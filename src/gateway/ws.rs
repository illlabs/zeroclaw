//! WebSocket agent chat handler.
//!
//! Protocol:
//! ```text
//! Client -> Server: {"type":"message","content":"Hello"}
//! Server -> Client: {"type":"chunk","content":"Hi! "}
//! Server -> Client: {"type":"tool_call","name":"shell","args":{...}}
//! Server -> Client: {"type":"tool_result","name":"shell","output":"..."}
//! Server -> Client: {"type":"done","full_response":"..."}
//! ```

use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use base64::{Engine as _, engine::general_purpose};
use super::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;

fn encrypt_payload(data: &str, key_b64: &str) -> Option<String> {
    let key_bytes = general_purpose::STANDARD.decode(key_b64).ok()?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).ok()?;
    let mut nonce_bytes = [0u8; 12];
    use rand::RngExt;
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes()).ok()?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    Some(general_purpose::STANDARD.encode(combined))
}

fn decrypt_payload(ciphertext_b64: &str, key_b64: &str) -> Option<String> {
    let key_bytes = general_purpose::STANDARD.decode(key_b64).ok()?;
    let ct_bytes = general_purpose::STANDARD.decode(ciphertext_b64).ok()?;
    if ct_bytes.len() < 12 { return None; }
    let (nonce_bytes, ciphertext) = ct_bytes.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).ok()?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

/// GET /ws/chat — WebSocket upgrade for agent chat
pub async fn handle_ws_chat(
    State(state): State<AppState>,
    Query(params): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Auth via query param (browser WebSocket limitation)
    if state.pairing.require_pairing() {
        let token = params.token.as_deref().unwrap_or("");
        if !state.pairing.is_authenticated(token) {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "Unauthorized — provide ?token=<bearer_token>",
            )
                .into_response();
        }
    }

    ws.on_upgrade(move |socket| handle_socket(socket, state))
        .into_response()
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(Message::Text(text)) => {
                let text_str = text.to_string();
                if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                    decrypt_payload(&text_str, secret).unwrap_or(text_str)
                } else {
                    text_str
                }
            },
            Ok(Message::Close(_)) | Err(_) => break,
            _ => continue,
        };

        // Parse incoming message
        let parsed: serde_json::Value = match serde_json::from_str(&msg) {
            Ok(v) => v,
            Err(_) => {
                let err = serde_json::json!({"type": "error", "message": "Invalid JSON"});
                let mut err_msg = err.to_string();
                if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                    if let Some(enc) = encrypt_payload(&err_msg, secret) {
                        err_msg = enc;
                    }
                }
                let _ = sender.send(Message::Text(err_msg.into())).await;
                continue;
            }
        };

        let msg_type = parsed["type"].as_str().unwrap_or("");
        if msg_type != "message" {
            continue;
        }

        let content = parsed["content"].as_str().unwrap_or("").to_string();
        if content.is_empty() {
            continue;
        }

        // Process message with the LLM provider
        let provider_label = state
            .config
            .lock()
            .default_provider
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        // Broadcast agent_start event
        let _ = state.event_tx.send(serde_json::json!({
            "type": "agent_start",
            "provider": provider_label,
            "model": state.model,
        }));

        // Simple single-turn chat (no streaming for now — use provider.chat_with_system)
        let system_prompt = {
            let config_guard = state.config.lock();
            crate::channels::build_system_prompt(
                &config_guard.workspace_dir,
                &state.model,
                &[],
                &[],
                Some(&config_guard.identity),
                None,
            )
        };

        let messages = vec![
            crate::providers::ChatMessage::system(system_prompt),
            crate::providers::ChatMessage::user(&content),
        ];

        let multimodal_config = state.config.lock().multimodal.clone();
        let prepared =
            match crate::multimodal::prepare_messages_for_provider(&messages, &multimodal_config)
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    let err = serde_json::json!({
                        "type": "error",
                        "message": format!("Multimodal prep failed: {e}")
                    });
                    let mut err_msg = err.to_string();
                    if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                        if let Some(enc) = encrypt_payload(&err_msg, secret) {
                            err_msg = enc;
                        }
                    }
                    let _ = sender.send(Message::Text(err_msg.into())).await;
                    continue;
                }
            };

        match state
            .provider
            .chat_with_history(&prepared.messages, &state.model, state.temperature)
            .await
        {
            Ok(response) => {
                // Send the full response as a done message
                let done = serde_json::json!({
                    "type": "done",
                    "full_response": response,
                });
                let mut done_msg = done.to_string();
                if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                    if let Some(enc) = encrypt_payload(&done_msg, secret) {
                        done_msg = enc;
                    }
                }
                let _ = sender.send(Message::Text(done_msg.into())).await;

                // Broadcast agent_end event
                let _ = state.event_tx.send(serde_json::json!({
                    "type": "agent_end",
                    "provider": provider_label,
                    "model": state.model,
                }));
            }
            Err(e) => {
                let sanitized = crate::providers::sanitize_api_error(&e.to_string());
                let err = serde_json::json!({
                    "type": "error",
                    "message": sanitized,
                });
                let mut err_msg = err.to_string();
                if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                    if let Some(enc) = encrypt_payload(&err_msg, secret) {
                        err_msg = enc;
                    }
                }
                let _ = sender.send(Message::Text(err_msg.into())).await;

                // Broadcast error event
                let _ = state.event_tx.send(serde_json::json!({
                    "type": "error",
                    "component": "ws_chat",
                    "message": sanitized,
                }));
            }
        }
    }
}

//! Server-Sent Events (SSE) stream for real-time event delivery.
//!
//! Wraps the broadcast channel in AppState to deliver events to web dashboard clients.

use super::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
};
use std::convert::Infallible;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use base64::{Engine as _, engine::general_purpose};

/// GET /api/events — SSE event stream
pub async fn handle_sse_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Auth check
    if state.pairing.require_pairing() {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .unwrap_or("");

        if !state.pairing.is_authenticated(token) {
            return (
                StatusCode::UNAUTHORIZED,
                "Unauthorized — provide Authorization: Bearer <token>",
            )
                .into_response();
        }
    }

    let rx = state.event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(
        move |result: Result<
            serde_json::Value,
            tokio_stream::wrappers::errors::BroadcastStreamRecvError,
        >| {
            match result {
                Ok(value) => {
                    let data = value.to_string();
                    let final_data = if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                        encrypt_payload(&data, secret).unwrap_or(data)
                    } else {
                        data
                    };
                    Some(Ok::<_, Infallible>(
                        Event::default().data(final_data),
                    ))
                }
                Err(_) => None, // Skip lagged messages
            }
        },
    );

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// GET /telemetry/stream — Secure SSE telemetry stream limited to 20 clients
pub async fn handle_telemetry_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Auth check
    if state.pairing.require_pairing() {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| auth.strip_prefix("Bearer "))
            .unwrap_or("");

        if !state.pairing.is_authenticated(token) {
            return (
                StatusCode::UNAUTHORIZED,
                "Unauthorized — provide Authorization: Bearer <token>",
            )
                .into_response();
        }
    }

    // Attempt to subscribe
    let rx = match crate::telemetry::TelemetryServer::get().subscribe() {
        Ok(receiver) => receiver,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Telemetry unavailable: {}", e),
            )
            .into_response();
        }
    };

    let server_ref = crate::telemetry::TelemetryServer::get().clone();
    
    let stream = BroadcastStream::new(rx).filter_map(
        move |result: Result<
            serde_json::Value,
            tokio_stream::wrappers::errors::BroadcastStreamRecvError,
        >| {
            match result {
                Ok(value) => {
                    let data = value.to_string();
                    let final_data = if let Some(ref secret) = state.config.lock().gateway.e2ee.shared_secret {
                        encrypt_payload(&data, secret).unwrap_or(data)
                    } else {
                        data
                    };
                    Some(Ok::<_, Infallible>(
                        Event::default().data(final_data),
                    ))
                }
                Err(_) => None, // Skip lagged messages
            }
        },
    );

    // On stream drop, connection is severed, we must decrement the subscriber count.
    // We achieve this by mapping the stream so we can hook the Drop semantics or just relying on a guard.
    // However, since Sse handles dropping the underlying stream, we can wrap the stream in a struct that implements Drop.
    struct UnsubscribeGuard {
        server: std::sync::Arc<crate::telemetry::TelemetryServer>,
    }
    impl Drop for UnsubscribeGuard {
        fn drop(&mut self) {
            self.server.unsubscribe();
        }
    }
    let guard = UnsubscribeGuard { server: server_ref };

    let mapped_stream = stream.map(move |item| {
        let _keep_guard = &guard;
        item
    });

    Sse::new(mapped_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Broadcast observer that forwards events to the SSE broadcast channel.
pub struct BroadcastObserver {
    inner: Box<dyn crate::observability::Observer>,
    tx: tokio::sync::broadcast::Sender<serde_json::Value>,
}

impl BroadcastObserver {
    pub fn new(
        inner: Box<dyn crate::observability::Observer>,
        tx: tokio::sync::broadcast::Sender<serde_json::Value>,
    ) -> Self {
        Self { inner, tx }
    }
}

impl crate::observability::Observer for BroadcastObserver {
    fn record_event(&self, event: &crate::observability::ObserverEvent) {
        // Forward to inner observer
        self.inner.record_event(event);

        // Broadcast to SSE subscribers
        let json = match event {
            crate::observability::ObserverEvent::LlmRequest {
                provider, model, ..
            } => serde_json::json!({
                "type": "llm_request",
                "provider": provider,
                "model": model,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
            crate::observability::ObserverEvent::ToolCall {
                tool,
                duration,
                success,
            } => serde_json::json!({
                "type": "tool_call",
                "tool": tool,
                "duration_ms": duration.as_millis(),
                "success": success,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
            crate::observability::ObserverEvent::ToolCallStart { tool } => serde_json::json!({
                "type": "tool_call_start",
                "tool": tool,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
            crate::observability::ObserverEvent::Error { component, message } => {
                serde_json::json!({
                    "type": "error",
                    "component": component,
                    "message": message,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                })
            }
            crate::observability::ObserverEvent::AgentStart { provider, model } => {
                serde_json::json!({
                    "type": "agent_start",
                    "provider": provider,
                    "model": model,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                })
            }
            crate::observability::ObserverEvent::AgentEnd {
                provider,
                model,
                duration,
                tokens_used,
                cost_usd,
            } => serde_json::json!({
                "type": "agent_end",
                "provider": provider,
                "model": model,
                "duration_ms": duration.as_millis(),
                "tokens_used": tokens_used,
                "cost_usd": cost_usd,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
            _ => return, // Skip events we don't broadcast
        };

        let _ = self.tx.send(json);
    }

    fn record_metric(&self, metric: &crate::observability::traits::ObserverMetric) {
        self.inner.record_metric(metric);
    }

    fn flush(&self) {
        self.inner.flush();
    }

    fn name(&self) -> &str {
        "broadcast"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn encrypt_payload(data: &str, key_b64: &str) -> Option<String> {
    let key_bytes = general_purpose::STANDARD.decode(key_b64).ok()?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes).ok()?;
    
    // In a real production system, we would use a counter or random nonce per message.
    // For this implementation, we use a random nonce and prepend it.
    let mut nonce_bytes = [0u8; 12];
    use rand::RngExt;
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data.as_bytes()).ok()?;
    
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    
    Some(general_purpose::STANDARD.encode(combined))
}

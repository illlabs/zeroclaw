use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tokio::io::AsyncWriteExt;
use std::path::Path;

pub struct TelemetryServer {
    tx: broadcast::Sender<Value>,
}

static TELEMETRY_SERVER: std::sync::OnceLock<Arc<TelemetryServer>> = std::sync::OnceLock::new();

impl TelemetryServer {
    pub fn get() -> Arc<Self> {
        TELEMETRY_SERVER.get_or_init(|| {
            let (tx, _) = broadcast::channel(100);
            Arc::new(Self { tx })
        }).clone()
    }

    pub fn broadcast(&self, value: Value) {
        let _ = self.tx.send(value);
    }

    pub async fn run(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            let _ = tokio::fs::remove_file(path).await;
        }

        let listener = UnixListener::bind(path)?;
        tracing::info!("📡 Telemetry server listening on {}", path.display());

        let tx = self.tx.clone();
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    let mut rx = tx.subscribe();
                    tokio::spawn(async move {
                        while let Ok(msg) = rx.recv().await {
                            let data = serde_json::to_vec(&msg).unwrap_or_default();
                            if stream.write_all(&data).await.is_err() {
                                break;
                            }
                            if stream.write_all(b"\n").await.is_err() {
                                break;
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Telemetry server accept error: {e}");
                }
            }
        }
    }
}

pub fn broadcast_health(snapshot: Value) {
    TelemetryServer::get().broadcast(snapshot);
}

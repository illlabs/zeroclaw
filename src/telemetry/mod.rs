use anyhow::Result;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct TelemetryServer {
    tx: broadcast::Sender<Value>,
    active_subscribers: AtomicUsize,
}

static TELEMETRY_SERVER: std::sync::OnceLock<Arc<TelemetryServer>> = std::sync::OnceLock::new();

pub const MAX_TELEMETRY_SUBSCRIBERS: usize = 20;

impl TelemetryServer {
    pub fn get() -> Arc<Self> {
        TELEMETRY_SERVER.get_or_init(|| {
            let (tx, _) = broadcast::channel(100);
            Arc::new(Self { 
                tx,
                active_subscribers: AtomicUsize::new(0),
            })
        }).clone()
    }

    pub fn broadcast(&self, value: Value) {
        // Only broadcast if there are active subscribers to save CPU cycles
        if self.active_subscribers.load(Ordering::Relaxed) > 0 {
            let _ = self.tx.send(value);
        }
    }

    /// Subscribes to the telemetry stream if the subscriber limit hasn't been reached.
    pub fn subscribe(&self) -> Result<broadcast::Receiver<Value>> {
        let current = self.active_subscribers.load(Ordering::SeqCst);
        if current >= MAX_TELEMETRY_SUBSCRIBERS {
            anyhow::bail!("Maximum telemetry subscribers reached ({})", MAX_TELEMETRY_SUBSCRIBERS);
        }
        
        self.active_subscribers.fetch_add(1, Ordering::SeqCst);
        Ok(self.tx.subscribe())
    }

    /// Decrement the active subscriber count when a client drops.
    pub fn unsubscribe(&self) {
        self.active_subscribers.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn broadcast_health(snapshot: Value) {
    TelemetryServer::get().broadcast(snapshot);
}

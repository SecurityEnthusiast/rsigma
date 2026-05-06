//! Background refresh scheduler for dynamic pipeline sources.
//!
//! Manages per-source refresh loops based on `RefreshPolicy`:
//! - `Interval(duration)`: re-fetches on a timer
//! - `Watch`: uses file system notifications (via `notify`)
//! - `Push`: receives updates from external triggers (NATS)
//! - `OnDemand`: only refreshes when explicitly triggered via API/signal

use std::collections::HashMap;
use std::sync::Arc;

use rsigma_eval::pipeline::sources::{DynamicSource, RefreshPolicy};
use tokio::sync::{mpsc, watch};

use super::{SourceResolver, resolve_all};

/// A message requesting source re-resolution.
#[derive(Debug, Clone)]
pub enum RefreshTrigger {
    /// Re-resolve all sources.
    All,
    /// Re-resolve a specific source by ID.
    Single(String),
}

/// Notification sent when sources have been refreshed.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    /// The newly resolved source data (source_id -> value).
    pub resolved: HashMap<String, serde_json::Value>,
}

/// Manages background refresh tasks for dynamic sources.
///
/// The scheduler spawns per-source tasks based on their refresh policy and
/// sends `RefreshResult` notifications whenever source data changes.
pub struct RefreshScheduler {
    /// Channel for on-demand refresh triggers (from API, SIGHUP, NATS control).
    trigger_tx: mpsc::Sender<RefreshTrigger>,
    /// Receiver for on-demand triggers (consumed by the run loop).
    trigger_rx: Option<mpsc::Receiver<RefreshTrigger>>,
    /// Watch channel sender for notifying consumers of updated source data.
    result_tx: watch::Sender<Option<RefreshResult>>,
    /// Watch channel receiver for consumers.
    result_rx: watch::Receiver<Option<RefreshResult>>,
}

impl RefreshScheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        let (trigger_tx, trigger_rx) = mpsc::channel(32);
        let (result_tx, result_rx) = watch::channel(None);
        Self {
            trigger_tx,
            trigger_rx: Some(trigger_rx),
            result_tx,
            result_rx,
        }
    }

    /// Get a sender for triggering on-demand resolution.
    pub fn trigger_sender(&self) -> mpsc::Sender<RefreshTrigger> {
        self.trigger_tx.clone()
    }

    /// Get a receiver that is notified when sources are refreshed.
    pub fn result_receiver(&self) -> watch::Receiver<Option<RefreshResult>> {
        self.result_rx.clone()
    }

    /// Start the scheduler background loop.
    ///
    /// Takes ownership of the trigger receiver and spawns per-source interval tasks.
    /// Returns a `JoinHandle` for the main coordination task.
    ///
    /// When a refresh occurs (via interval timer or on-demand trigger), all sources
    /// are re-resolved and the result is published on the watch channel.
    pub fn run(
        mut self,
        sources: Vec<DynamicSource>,
        resolver: Arc<dyn SourceResolver>,
    ) -> tokio::task::JoinHandle<()> {
        let trigger_rx = self
            .trigger_rx
            .take()
            .expect("run() can only be called once");

        tokio::spawn(async move {
            Self::run_loop(
                sources,
                resolver,
                trigger_rx,
                self.trigger_tx,
                self.result_tx,
            )
            .await;
        })
    }

    async fn run_loop(
        sources: Vec<DynamicSource>,
        resolver: Arc<dyn SourceResolver>,
        mut trigger_rx: mpsc::Receiver<RefreshTrigger>,
        trigger_tx: mpsc::Sender<RefreshTrigger>,
        result_tx: watch::Sender<Option<RefreshResult>>,
    ) {
        // Spawn interval timers that send triggers
        for source in &sources {
            if let RefreshPolicy::Interval(duration) = &source.refresh {
                let tx = trigger_tx.clone();
                let id = source.id.clone();
                let interval = *duration;
                tokio::spawn(async move {
                    let mut timer = tokio::time::interval(interval);
                    timer.tick().await; // skip immediate first tick
                    loop {
                        timer.tick().await;
                        if tx.send(RefreshTrigger::Single(id.clone())).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }

        // Main loop: wait for triggers and resolve
        while let Some(trigger) = trigger_rx.recv().await {
            let to_resolve: Vec<&DynamicSource> = match &trigger {
                RefreshTrigger::All => sources.iter().collect(),
                RefreshTrigger::Single(id) => sources.iter().filter(|s| s.id == *id).collect(),
            };

            if to_resolve.is_empty() {
                continue;
            }

            match resolve_all(
                resolver.as_ref(),
                &to_resolve.iter().map(|s| (*s).clone()).collect::<Vec<_>>(),
            )
            .await
            {
                Ok(resolved) => {
                    let _ = result_tx.send(Some(RefreshResult { resolved }));
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Background source refresh failed"
                    );
                }
            }
        }
    }
}

impl Default for RefreshScheduler {
    fn default() -> Self {
        Self::new()
    }
}

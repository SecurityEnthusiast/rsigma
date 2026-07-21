//! Exponential backoff retry policy.

use std::time::Duration;

/// Retry policy for transient TAXII transport failures.
#[derive(Clone, Debug, PartialEq)]
pub struct RetryPolicy {
    /// Maximum retry attempts after the initial request.
    pub max_attempts: u32,
    /// Initial backoff delay.
    pub initial_delay: Duration,
    /// Maximum backoff delay.
    pub max_delay: Duration,
    /// Multiplier applied after each attempt.
    pub multiplier: f64,
    /// Random jitter factor in `[0, jitter_factor]`.
    pub jitter_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
            jitter_factor: 0.1,
        }
    }
}

impl RetryPolicy {
    /// Delay before retry attempt `attempt` (1-based).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exp = self
            .multiplier
            .powi(i32::try_from(attempt.saturating_sub(1)).unwrap_or(0));
        let base_ms = self.initial_delay.as_millis() as f64 * exp;
        let capped = base_ms.min(self.max_delay.as_millis() as f64);
        let jitter = if self.jitter_factor > 0.0 {
            let frac = (attempt as f64 * 0.37).fract() * self.jitter_factor;
            capped * (1.0 + frac)
        } else {
            capped
        };
        Duration::from_millis(jitter.round() as u64)
    }
}

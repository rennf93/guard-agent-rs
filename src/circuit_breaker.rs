//! Client-side circuit breaker guarding the ingestion endpoint.
//!
//! Mirrors the Python agent's breaker: five consecutive non-permanent
//! failures open the circuit for a recovery window, after which a single
//! probe is admitted (half-open). Permanent client errors (400, 404, 413,
//! 422) are intentionally excluded by the caller and never count as
//! failures.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Number of consecutive failures that open the circuit.
pub const FAILURE_THRESHOLD: u32 = 5;

/// Recovery window after which a probe is admitted.
pub const RECOVERY_WINDOW: Duration = Duration::from_secs(60);

/// Current breaker position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Requests flow normally.
    Closed,
    /// Requests are short-circuited locally.
    Open,
    /// The recovery window elapsed and a probe was admitted.
    HalfOpen,
}

impl CircuitBreakerState {
    /// Returns the wire-compatible label used in agent stats.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Open => "OPEN",
            Self::HalfOpen => "HALF_OPEN",
        }
    }
}

#[derive(Debug)]
struct Inner {
    failures: u32,
    opened_at: Option<Instant>,
    half_open: bool,
}

/// Circuit breaker with a failure threshold and a recovery window.
#[derive(Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    recovery: Duration,
    inner: Mutex<Inner>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(FAILURE_THRESHOLD, RECOVERY_WINDOW)
    }
}

impl CircuitBreaker {
    /// Creates a breaker with the given threshold and recovery window.
    #[must_use]
    pub fn new(threshold: u32, recovery: Duration) -> Self {
        Self {
            threshold: threshold.max(1),
            recovery,
            inner: Mutex::new(Inner {
                failures: 0,
                opened_at: None,
                half_open: false,
            }),
        }
    }

    /// Returns `true` when a request may proceed.
    ///
    /// While open, the breaker denies requests until the recovery window
    /// elapses; the first request after that is admitted and the breaker
    /// moves to half-open.
    pub fn admit(&self) -> bool {
        let mut inner = self.inner.lock().expect("breaker mutex not poisoned");
        if let Some(opened_at) = inner.opened_at {
            if opened_at.elapsed() >= self.recovery {
                inner.half_open = true;
                return true;
            }
            return false;
        }
        true
    }

    /// Records a successful request, closing the circuit.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock().expect("breaker mutex not poisoned");
        inner.failures = 0;
        inner.opened_at = None;
        inner.half_open = false;
    }

    /// Records a failed request, possibly opening the circuit.
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock().expect("breaker mutex not poisoned");
        if inner.half_open {
            // A failed probe reopens the circuit with a fresh window.
            inner.half_open = false;
            inner.opened_at = Some(Instant::now());
            return;
        }
        inner.failures = inner.failures.saturating_add(1);
        if inner.failures >= self.threshold {
            inner.opened_at = Some(Instant::now());
        }
    }

    /// Returns the current breaker position.
    #[must_use]
    pub fn state(&self) -> CircuitBreakerState {
        let inner = self.inner.lock().expect("breaker mutex not poisoned");
        match (inner.opened_at, inner.half_open) {
            (None, _) => CircuitBreakerState::Closed,
            (Some(_), true) => CircuitBreakerState::HalfOpen,
            (Some(opened_at), false) => {
                if opened_at.elapsed() >= self.recovery {
                    CircuitBreakerState::HalfOpen
                } else {
                    CircuitBreakerState::Open
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_threshold_failures() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        assert!(breaker.admit());
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);

        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);

        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        assert!(!breaker.admit());
    }

    #[test]
    fn success_resets_the_failure_count() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(60));
        breaker.record_failure();
        breaker.record_failure();
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(
            breaker.state(),
            CircuitBreakerState::Closed,
            "count restarted"
        );
    }

    #[test]
    fn half_open_admits_one_probe_after_recovery() {
        let breaker = CircuitBreaker::new(1, Duration::from_millis(30));
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        assert!(!breaker.admit());

        std::thread::sleep(Duration::from_millis(40));
        assert!(breaker.admit(), "probe admitted after recovery window");
        assert_eq!(breaker.state(), CircuitBreakerState::HalfOpen);

        // A failed probe reopens the circuit.
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        assert!(!breaker.admit());
    }

    #[test]
    fn successful_probe_closes_the_circuit() {
        let breaker = CircuitBreaker::new(1, Duration::from_millis(30));
        breaker.record_failure();
        std::thread::sleep(Duration::from_millis(40));
        assert!(breaker.admit());
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
        assert!(breaker.admit());
    }

    #[test]
    fn state_labels_are_stable() {
        assert_eq!(CircuitBreakerState::Closed.as_str(), "CLOSED");
        assert_eq!(CircuitBreakerState::Open.as_str(), "OPEN");
        assert_eq!(CircuitBreakerState::HalfOpen.as_str(), "HALF_OPEN");
    }

    #[test]
    fn threshold_is_clamped_to_at_least_one() {
        let breaker = CircuitBreaker::new(0, Duration::from_secs(60));
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
    }
}

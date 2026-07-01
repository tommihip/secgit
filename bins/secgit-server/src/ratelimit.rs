//! Dependency-free abuse controls: a token-bucket rate limiter and a counting semaphore.
//!
//! No external crate is pulled onto the trust-critical serve path (the wedge is the
//! confidential layer, not a bespoke middleware stack). Both primitives are memory-bounded
//! by construction so the limiter itself cannot become a memory-exhaustion DoS.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// One token bucket: `tokens` refills at `refill`/sec up to `capacity`.
struct Bucket {
    tokens: f64,
    last: Instant,
}

struct Inner {
    buckets: HashMap<String, Bucket>,
    last_sweep: Instant,
}

/// A per-key token-bucket rate limiter. `check(key)` returns `true` if a token was
/// available (request allowed) and `false` otherwise (rate limited).
pub struct RateLimiter {
    capacity: f64,
    refill: f64,
    max_keys: usize,
    idle_evict: Duration,
    inner: Mutex<Inner>,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill: f64, max_keys: usize, idle_evict: Duration) -> Self {
        Self {
            capacity: capacity.max(1.0),
            refill: refill.max(0.0001),
            max_keys: max_keys.max(1),
            idle_evict,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Attempt to consume one token for `key`. Returns `true` if allowed.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();

        // Opportunistic sweep of idle buckets to bound memory.
        if now.duration_since(inner.last_sweep) >= self.idle_evict {
            let idle = self.idle_evict;
            inner
                .buckets
                .retain(|_, b| now.duration_since(b.last) < idle);
            inner.last_sweep = now;
        }

        // If the table is full and this is a new key, evict idle entries; if still full,
        // fail closed (rate-limit the new key) rather than grow unbounded.
        if !inner.buckets.contains_key(key) && inner.buckets.len() >= self.max_keys {
            let idle = self.idle_evict;
            inner
                .buckets
                .retain(|_, b| now.duration_since(b.last) < idle);
            if inner.buckets.len() >= self.max_keys {
                return false;
            }
        }

        let cap = self.capacity;
        let refill = self.refill;
        let bucket = inner.buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(cap);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A simple counting semaphore used to bound concurrency of expensive work (repo sealing),
/// so a burst of pushes cannot spawn unbounded simultaneous `git bundle` processes.
pub struct Semaphore {
    permits: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    pub fn new(permits: usize) -> Self {
        Self {
            permits: Mutex::new(permits.max(1)),
            cv: Condvar::new(),
        }
    }

    /// Acquire a permit, blocking until one is available. The returned guard releases it
    /// on drop.
    pub fn acquire(&self) -> SemaphoreGuard<'_> {
        let mut n = self.permits.lock().unwrap();
        while *n == 0 {
            n = self.cv.wait(n).unwrap();
        }
        *n -= 1;
        SemaphoreGuard { sem: self }
    }
}

pub struct SemaphoreGuard<'a> {
    sem: &'a Semaphore,
}

impl Drop for SemaphoreGuard<'_> {
    fn drop(&mut self) {
        let mut n = self.sem.permits.lock().unwrap();
        *n += 1;
        self.sem.cv.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_burst_then_limits() {
        let rl = RateLimiter::new(3.0, 0.0001, 100, Duration::from_secs(60));
        assert!(rl.check("ip1"));
        assert!(rl.check("ip1"));
        assert!(rl.check("ip1"));
        // Burst exhausted; refill is negligible over this instant.
        assert!(!rl.check("ip1"));
        // A different key has its own bucket.
        assert!(rl.check("ip2"));
    }

    #[test]
    fn refills_over_time() {
        let rl = RateLimiter::new(1.0, 1000.0, 100, Duration::from_secs(60));
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(rl.check("k"), "should refill quickly at 1000 tokens/sec");
    }

    #[test]
    fn max_keys_bounds_memory() {
        let rl = RateLimiter::new(1.0, 0.0001, 2, Duration::from_secs(3600));
        assert!(rl.check("a"));
        assert!(rl.check("b"));
        // Table full; a brand-new key is refused rather than growing the map.
        assert!(!rl.check("c"));
    }

    #[test]
    fn semaphore_bounds_concurrency() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let sem = Arc::new(Semaphore::new(2));
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        for _ in 0..8 {
            let sem = Arc::clone(&sem);
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            handles.push(std::thread::spawn(move || {
                let _g = sem.acquire();
                let cur = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(cur, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(10));
                live.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(
            peak.load(Ordering::SeqCst) <= 2,
            "concurrency exceeded permits"
        );
    }
}

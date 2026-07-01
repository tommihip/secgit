//! Content-free observability.
//!
//! The public instance still needs health/monitoring, but the operator is untrusted and
//! must never see repo content *or metadata*. This registry resolves that tension by being
//! **content-free by construction**: it holds only fixed, aggregate counters/gauges with a
//! hard-coded label set — no repo ids, paths, usernames, IPs, or per-repo sizes are ever
//! recorded. Nothing here can leak plaintext, and a leak-test (see `metrics_are_content_free`)
//! scans the rendered output to prove it.
//!
//! It is also telemetry-free: pull-only (Prometheus text), no outbound push, no telemetry
//! crate (those are banned in `deny.toml`) — preserving the no-plaintext-egress invariant.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Aggregate, content-free server metrics.
#[derive(Default)]
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub responses_2xx: AtomicU64,
    pub responses_3xx: AtomicU64,
    pub responses_4xx: AtomicU64,
    pub responses_5xx: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub body_rejected_total: AtomicU64,
    pub header_rejected_total: AtomicU64,
    pub conn_accepted_total: AtomicU64,
    pub conn_rejected_total: AtomicU64,
    pub active_connections: AtomicI64,
    pub ephemeral_created_total: AtomicU64,
    pub ephemeral_gc_total: AtomicU64,
    pub push_total: AtomicU64,
    pub push_rejected_total: AtomicU64,
    pub seal_total: AtomicU64,
    pub seal_millis_total: AtomicU64,
    pub pow_challenges_total: AtomicU64,
    pub pow_failures_total: AtomicU64,
    pub abuse_reports_total: AtomicU64,
    pub takedowns_total: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// Record an HTTP response status into the class counters.
    pub fn record_status(&self, status: u16) {
        Self::inc(&self.requests_total);
        match status / 100 {
            2 => Self::inc(&self.responses_2xx),
            3 => Self::inc(&self.responses_3xx),
            4 => Self::inc(&self.responses_4xx),
            _ => Self::inc(&self.responses_5xx),
        }
    }

    /// Render Prometheus text exposition format. Every emitted series is a static name with
    /// no dynamic labels, so the output carries zero confidential information.
    pub fn render(&self) -> String {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let gi = |a: &AtomicI64| a.load(Ordering::Relaxed);
        let mut s = String::new();
        let mut line = |name: &str, help: &str, ty: &str, val: String| {
            s.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {ty}\n{name} {val}\n"
            ));
        };
        line(
            "secgit_requests_total",
            "Total HTTP requests handled.",
            "counter",
            g(&self.requests_total).to_string(),
        );
        line(
            "secgit_responses_2xx_total",
            "Responses with a 2xx status.",
            "counter",
            g(&self.responses_2xx).to_string(),
        );
        line(
            "secgit_responses_3xx_total",
            "Responses with a 3xx status.",
            "counter",
            g(&self.responses_3xx).to_string(),
        );
        line(
            "secgit_responses_4xx_total",
            "Responses with a 4xx status.",
            "counter",
            g(&self.responses_4xx).to_string(),
        );
        line(
            "secgit_responses_5xx_total",
            "Responses with a 5xx status.",
            "counter",
            g(&self.responses_5xx).to_string(),
        );
        line(
            "secgit_rate_limited_total",
            "Requests rejected by a rate limiter.",
            "counter",
            g(&self.rate_limited_total).to_string(),
        );
        line(
            "secgit_body_rejected_total",
            "Requests rejected for exceeding the body size cap.",
            "counter",
            g(&self.body_rejected_total).to_string(),
        );
        line(
            "secgit_header_rejected_total",
            "Requests rejected for oversized/too-many headers.",
            "counter",
            g(&self.header_rejected_total).to_string(),
        );
        line(
            "secgit_connections_accepted_total",
            "TCP connections accepted for handling.",
            "counter",
            g(&self.conn_accepted_total).to_string(),
        );
        line(
            "secgit_connections_rejected_total",
            "TCP connections rejected by the connection cap.",
            "counter",
            g(&self.conn_rejected_total).to_string(),
        );
        line(
            "secgit_active_connections",
            "Connections currently being served.",
            "gauge",
            gi(&self.active_connections).to_string(),
        );
        line(
            "secgit_ephemeral_created_total",
            "Anonymous ephemeral repos created.",
            "counter",
            g(&self.ephemeral_created_total).to_string(),
        );
        line(
            "secgit_ephemeral_gc_total",
            "Expired ephemeral repos garbage-collected.",
            "counter",
            g(&self.ephemeral_gc_total).to_string(),
        );
        line(
            "secgit_push_total",
            "Successful git receive-pack (push) operations.",
            "counter",
            g(&self.push_total).to_string(),
        );
        line(
            "secgit_push_rejected_total",
            "Pushes rejected (quota/size/rate).",
            "counter",
            g(&self.push_rejected_total).to_string(),
        );
        line(
            "secgit_seal_total",
            "Repo seal (encrypt-to-store) operations.",
            "counter",
            g(&self.seal_total).to_string(),
        );
        line(
            "secgit_seal_millis_total",
            "Cumulative wall-clock spent sealing repos.",
            "counter",
            g(&self.seal_millis_total).to_string(),
        );
        line(
            "secgit_pow_challenges_total",
            "Proof-of-work challenges issued.",
            "counter",
            g(&self.pow_challenges_total).to_string(),
        );
        line(
            "secgit_pow_failures_total",
            "Proof-of-work verifications that failed.",
            "counter",
            g(&self.pow_failures_total).to_string(),
        );
        line(
            "secgit_abuse_reports_total",
            "Abuse reports received.",
            "counter",
            g(&self.abuse_reports_total).to_string(),
        );
        line(
            "secgit_takedowns_total",
            "Operator takedowns (force-delete by id).",
            "counter",
            g(&self.takedowns_total).to_string(),
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_content_free() {
        let m = Metrics::new();
        // Drive every counter, as if real (repo-bearing) traffic had flowed.
        m.record_status(200);
        m.record_status(429);
        m.record_status(500);
        Metrics::inc(&m.rate_limited_total);
        Metrics::inc(&m.ephemeral_created_total);
        Metrics::inc(&m.push_total);
        Metrics::inc(&m.abuse_reports_total);
        m.active_connections.fetch_add(3, Ordering::Relaxed);

        let out = m.render();

        // Leak-test: no canary-shaped content, and only fixed metric names may appear.
        let canary = secgit_leaktest::Canary::new("metrics");
        secgit_leaktest::assert_bytes_absent(out.as_bytes(), canary.as_bytes(), "metrics output");

        for line in out.lines() {
            if line.is_empty() || line.starts_with("# HELP ") || line.starts_with("# TYPE ") {
                continue;
            }
            // A data line must be "secgit_<name> <number>" — no slashes, no free-form text
            // (which could carry a repo id, path, or username).
            let (name, val) = line.split_once(' ').expect("metric line has a value");
            assert!(
                name.starts_with("secgit_")
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "unexpected metric name (possible label/content leak): {line}"
            );
            assert!(
                val.chars().all(|c| c.is_ascii_digit() || c == '-'),
                "metric value is not a bare number (possible content leak): {line}"
            );
        }
    }
}

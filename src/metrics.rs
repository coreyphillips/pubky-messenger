//! Request counters without message contents, destinations or credentials.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Counters for one HTTP method or directory-listing operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestCounts {
    pub attempts: u64,
    /// Body bytes offered to the HTTP client, including failed attempts.
    pub request_body_bytes: u64,
    /// Body bytes completely read from responses, including error responses.
    pub response_body_bytes: u64,
}

/// Cumulative counters since client creation. Snapshots do not reset counters.
///
/// Byte counts exclude HTTP headers, compression overhead and TLS. An interrupted upload
/// may send fewer bytes than were offered, and interrupted response bodies are not counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestStats {
    pub list: RequestCounts,
    pub get: RequestCounts,
    pub put: RequestCounts,
    pub delete: RequestCounts,
    pub session: RequestCounts,
    /// Additional attempts scheduled by the bounded request policy.
    pub retries: u64,
    pub timeouts: u64,
    /// Aggregate admission wait across attempts, including waits that were cancelled.
    pub queue_wait: Duration,
}

#[derive(Clone, Copy)]
pub(crate) enum RequestKind {
    List,
    Get,
    Put,
    Delete,
    Session,
}

#[derive(Default)]
struct Counters {
    attempts: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> RequestCounts {
        RequestCounts {
            attempts: self.attempts.load(Ordering::Relaxed),
            request_body_bytes: self.sent.load(Ordering::Relaxed),
            response_body_bytes: self.received.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub(crate) struct RequestMetrics {
    methods: [Counters; 5],
    retries: AtomicU64,
    timeouts: AtomicU64,
    queue_nanos: AtomicU64,
}

impl RequestMetrics {
    pub(crate) fn sent(&self, kind: RequestKind, bytes: usize) {
        let counters = &self.methods[kind as usize];
        counters.attempts.fetch_add(1, Ordering::Relaxed);
        counters.sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn received(&self, kind: RequestKind, bytes: usize) {
        self.methods[kind as usize]
            .received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn retried(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn timed_out(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn queued(&self, elapsed: Duration) {
        self.queue_nanos.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }
    pub(crate) fn snapshot(&self) -> RequestStats {
        RequestStats {
            list: self.methods[0].snapshot(),
            get: self.methods[1].snapshot(),
            put: self.methods[2].snapshot(),
            delete: self.methods[3].snapshot(),
            session: self.methods[4].snapshot(),
            retries: self.retries.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            queue_wait: Duration::from_nanos(self.queue_nanos.load(Ordering::Relaxed)),
        }
    }
}

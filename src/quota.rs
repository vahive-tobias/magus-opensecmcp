// src/quota.rs
//
// Local, in-process evaluation counter. Replaces the old Cloudflare-429-based
// kill switch entirely — there is no remote call in this path, which is the
// point: governance availability does not depend on a network round trip, and
// cannot be silently bypassed by a firewall the way a remote-telemetry-driven
// flag could be.
//
// v1 has one free tier and no license concept — this simply exists so the
// number is visible and the behavior (soft-warn, not hard-lock) is decided
// deliberately rather than left as an accidental permanent lockout.

use chrono::{Datelike, Utc};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub struct QuotaCounter {
    count_this_period: AtomicU32,
    /// Encoded as year * 100 + month, e.g. 202607 for July 2026.
    current_period: AtomicU64,
    limit: u32,
}

impl QuotaCounter {
    pub fn new(limit: u32) -> Self {
        Self {
            count_this_period: AtomicU32::new(0),
            current_period: AtomicU64::new(period_key()),
            limit,
        }
    }

    /// Records one evaluation and returns the count so far this period.
    /// Resets automatically the first time it's called after a real calendar
    /// month boundary — no restart required, unlike the daemon's rate_limited
    /// AtomicBool this replaces, which had no reset path at all.
    pub fn record_and_get_count(&self) -> u32 {
        let now_period = period_key();
        if now_period != self.current_period.load(Ordering::Relaxed) {
            self.current_period.store(now_period, Ordering::Relaxed);
            self.count_this_period.store(0, Ordering::Relaxed);
        }
        self.count_this_period.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn is_over_limit(&self) -> bool {
        let now_period = period_key();
        if now_period != self.current_period.load(Ordering::Relaxed) {
            return false; // new period hasn't been recorded into yet
        }
        self.count_this_period.load(Ordering::Relaxed) >= self.limit
    }

    #[allow(dead_code)]
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

fn period_key() -> u64 {
    let now = Utc::now();
    (now.year() as u64) * 100 + now.month() as u64
}

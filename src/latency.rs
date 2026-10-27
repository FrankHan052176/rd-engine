//! Decode-latency accounting for the presentation paths.
//!
//! The acceptance criterion this engine is built to is a per-frame decode cost
//! of **3 ms, excluding network time**. That number is only meaningful if it is
//! measured rather than asserted, so every presentation path records its own
//! decode cost here and the snapshot reports the distribution.
//!
//! The record is a fixed-size log2 histogram plus exact counters: no allocation,
//! no locking, and usable from a decoder worker thread. Percentiles are reported
//! as the bucket's upper bound, and are documented as such — a histogram cannot
//! produce an exact percentile and pretending otherwise would be the same class
//! of mistake as fabricating a latency number.

use std::fmt;

/// The per-frame decode budget. A frame at or above this is counted as over.
pub const DECODE_BUDGET_US: u32 = 3_000;

/// Buckets cover `[2^(k-1), 2^k)` microseconds for `k >= 1`; bucket 0 is exact
/// zeros and the last bucket also collects everything above it.
const BUCKETS: usize = 40;
/// Index of the bucket whose range contains the budget. Test-only: the budget
/// comparison itself uses exact microseconds, not the histogram.
#[cfg(test)]
const BUDGET_BUCKET: usize = 12; // [2048, 4096)

fn bucket_of(micros: u32) -> usize {
    if micros == 0 {
        return 0;
    }
    // floor(log2) + 1, so bucket k covers [2^(k-1), 2^k).
    (micros.ilog2() as usize + 1).min(BUCKETS - 1)
}

fn bucket_upper_bound(index: usize) -> u32 {
    match index {
        0 => 0,
        _ => {
            if index >= BUCKETS - 1 {
                u32::MAX
            } else {
                1u32 << index
            }
        }
    }
}

/// Exact counters plus a log2 histogram of decode times in microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeLatency {
    buckets: [u32; BUCKETS],
    count: u64,
    sum_us: u64,
    max_us: u32,
    over_budget: u64,
}

impl Default for DecodeLatency {
    fn default() -> Self {
        Self {
            buckets: [0; BUCKETS],
            count: 0,
            sum_us: 0,
            max_us: 0,
            over_budget: 0,
        }
    }
}

/// A flat, serialisable view of the distribution, for the snapshot and the HAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLatencySummary {
    pub frames: u64,
    pub average_us: u32,
    /// Upper bound of the bucket holding the median.
    pub p50_us: u32,
    /// Upper bound of the bucket holding the 99th percentile.
    pub p99_us: u32,
    pub max_us: u32,
    /// Frames that met or exceeded [`DECODE_BUDGET_US`].
    pub over_budget: u64,
    pub budget_us: u32,
}

impl DecodeLatency {
    /// Records one frame's decode cost. Saturating, so a counter can never wrap
    /// into a smaller number than it already reported.
    pub fn record(&mut self, micros: u32) {
        let index = bucket_of(micros);
        self.buckets[index] = self.buckets[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.sum_us = self.sum_us.saturating_add(u64::from(micros));
        self.max_us = self.max_us.max(micros);
        if micros >= DECODE_BUDGET_US {
            self.over_budget = self.over_budget.saturating_add(1);
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn max_us(&self) -> u32 {
        self.max_us
    }

    pub fn over_budget(&self) -> u64 {
        self.over_budget
    }

    /// Mean decode cost, truncated. Zero when nothing was recorded — a mean of
    /// no samples is not a latency, and reporting it as one would be a lie.
    pub fn average_us(&self) -> u32 {
        if self.count == 0 {
            return 0;
        }
        (self.sum_us / self.count).min(u64::from(u32::MAX)) as u32
    }

    /// Upper bound of the bucket holding the given quantile, or 0 with no
    /// samples. The value is an upper bound because the histogram is log2.
    pub fn percentile_us(&self, quantile: f64) -> u32 {
        if self.count == 0 {
            return 0;
        }
        let clamped = quantile.clamp(0.0, 1.0);
        // The rank of the sample we want, 1-based, never past the last one.
        let rank = ((clamped * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0u64;
        for (index, bucket) in self.buckets.iter().enumerate() {
            seen += u64::from(*bucket);
            if seen >= rank {
                return bucket_upper_bound(index);
            }
        }
        self.max_us
    }

    /// Whether every recorded frame met the budget. Vacuously true with no
    /// samples, which is why callers must check [`Self::count`] too.
    pub fn within_budget(&self) -> bool {
        self.over_budget == 0
    }

    pub fn summary(&self) -> DecodeLatencySummary {
        DecodeLatencySummary {
            frames: self.count,
            average_us: self.average_us(),
            p50_us: self.percentile_us(0.5),
            p99_us: self.percentile_us(0.99),
            max_us: self.max_us,
            over_budget: self.over_budget,
            budget_us: DECODE_BUDGET_US,
        }
    }

    /// Adds another record's samples. Used to fold per-session records together.
    pub fn merge(&mut self, other: &Self) {
        for (slot, add) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *slot = slot.saturating_add(*add);
        }
        self.count = self.count.saturating_add(other.count);
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        self.max_us = self.max_us.max(other.max_us);
        self.over_budget = self.over_budget.saturating_add(other.over_budget);
    }
}

impl fmt::Display for DecodeLatencySummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "frames={} avg={}us p50<={}us p99<={}us max={}us over_budget({}us)={}",
            self.frames,
            self.average_us,
            self.p50_us,
            self.p99_us,
            self.max_us,
            self.budget_us,
            self.over_budget
        )
    }
}

/// A monotonic timer for one decode operation.
///
/// The budget is about the decode itself, so a caller that also waits on the
/// network has to subtract that wait; [`Self::since`] reports what has already
/// been excluded.
#[derive(Debug, Clone, Copy)]
pub struct DecodeTimer {
    started: std::time::Instant,
    excluded: std::time::Duration,
}

impl DecodeTimer {
    pub fn start() -> Self {
        Self {
            started: std::time::Instant::now(),
            excluded: std::time::Duration::ZERO,
        }
    }

    /// Marks time inside this window that was not decode work.
    pub fn exclude(&mut self, duration: std::time::Duration) {
        self.excluded += duration;
    }

    /// Elapsed decode microseconds, saturating at `u32::MAX`.
    pub fn elapsed_us(&self) -> u32 {
        let total = self.started.elapsed().saturating_sub(self.excluded);
        total.as_micros().min(u128::from(u32::MAX)) as u32
    }

    /// Stops the timer and records the result.
    pub fn record_into(self, latency: &mut DecodeLatency) {
        latency.record(self.elapsed_us());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_record_reports_nothing_rather_than_zero_latency() {
        let latency = DecodeLatency::default();
        assert_eq!(latency.count(), 0);
        assert_eq!(latency.average_us(), 0, "a mean of no samples is not 0us");
        assert_eq!(latency.percentile_us(0.5), 0);
        assert_eq!(latency.max_us(), 0);
        // Vacuously within budget, which is why `count` has to be checked too.
        assert!(latency.within_budget());
    }

    #[test]
    fn the_exact_counters_track_every_sample() {
        let mut latency = DecodeLatency::default();
        for micros in [100u32, 200, 300, 400] {
            latency.record(micros);
        }
        assert_eq!(latency.count(), 4);
        assert_eq!(latency.average_us(), 250);
        assert_eq!(latency.max_us(), 400);
        assert_eq!(latency.over_budget(), 0);
        assert!(latency.within_budget());
    }

    #[test]
    fn the_budget_boundary_is_inclusive_of_the_budget_itself() {
        let mut latency = DecodeLatency::default();
        latency.record(DECODE_BUDGET_US - 1);
        assert_eq!(latency.over_budget(), 0, "just under the budget is inside");
        latency.record(DECODE_BUDGET_US);
        assert_eq!(latency.over_budget(), 1, "the budget itself is not inside");
        latency.record(DECODE_BUDGET_US + 1);
        assert_eq!(latency.over_budget(), 2);
        assert!(!latency.within_budget());
    }

    #[test]
    fn a_zero_length_decode_is_recorded_and_does_not_shift_the_median() {
        let mut latency = DecodeLatency::default();
        latency.record(0);
        assert_eq!(latency.count(), 1);
        assert_eq!(latency.average_us(), 0);
        assert_eq!(latency.percentile_us(0.5), 0, "the zero bucket is exact");
    }

    #[test]
    fn percentiles_are_upper_bounds_of_their_bucket() {
        let mut latency = DecodeLatency::default();
        // 100 samples, one microsecond apart. Buckets hold [2^(k-1), 2^k), so
        // the running total reaches 63 by [32, 64) and 100 by [64, 128).
        for micros in 1..=100u32 {
            latency.record(micros);
        }
        assert_eq!(latency.percentile_us(0.5), 64, "rank 50 lands in [32, 64)");
        assert_eq!(latency.percentile_us(0.99), 128, "rank 99 lands in [64, 128)");
        assert_eq!(latency.percentile_us(1.0), 128, "the last sample too");
        assert_eq!(latency.max_us(), 100, "the exact maximum is still exact");
    }

    #[test]
    fn a_slow_tail_lands_in_a_later_bucket_without_moving_the_median() {
        let mut latency = DecodeLatency::default();
        for _ in 0..99 {
            latency.record(500);
        }
        latency.record(40_000);
        assert_eq!(latency.percentile_us(0.5), 512, "the median ignores the tail");
        assert_eq!(latency.percentile_us(0.99), 512);
        assert_eq!(latency.percentile_us(1.0), 65_536, "[32768, 65536)");
        assert_eq!(latency.max_us(), 40_000);
        assert_eq!(latency.over_budget(), 1);
    }

    #[test]
    fn merging_folds_every_counter() {
        let mut first = DecodeLatency::default();
        first.record(1_000);
        let mut second = DecodeLatency::default();
        second.record(5_000);
        second.record(0);
        first.merge(&second);
        assert_eq!(first.count(), 3);
        assert_eq!(first.max_us(), 5_000);
        assert_eq!(first.over_budget(), 1);
        assert_eq!(first.average_us(), 2_000);
    }

    #[test]
    fn recording_saturates_instead_of_wrapping() {
        let mut latency = DecodeLatency::default();
        // The last bucket collects everything above the histogram's range.
        latency.record(u32::MAX);
        assert_eq!(latency.count(), 1);
        assert_eq!(latency.max_us(), u32::MAX);
        assert_eq!(latency.over_budget(), 1);
    }

    #[test]
    fn the_summary_names_the_budget_it_was_measured_against() {
        let mut latency = DecodeLatency::default();
        latency.record(100);
        let summary = latency.summary();
        assert_eq!(summary.frames, 1);
        assert_eq!(summary.budget_us, DECODE_BUDGET_US);
        assert_eq!(summary.over_budget, 0);
        let text = summary.to_string();
        assert!(text.contains("frames=1"), "{text}");
        assert!(text.contains("over_budget(3000us)=0"), "{text}");
    }

    #[test]
    fn a_timer_measures_a_real_wait_when_nothing_is_excluded() {
        let timer = DecodeTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(5));
        // A lower bound only: the scheduler may overshoot, never undershoot.
        assert!(
            timer.elapsed_us() >= 4_000,
            "a five millisecond wait must be visible: {}us",
            timer.elapsed_us()
        );
    }

    #[test]
    fn a_timer_that_excludes_the_whole_window_reports_no_decode_cost() {
        let mut timer = DecodeTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(5));
        // Excluding more than the window is the saturating case, and it is the
        // only form of this assertion that does not depend on how long the
        // sleep actually took under a loaded test runner.
        timer.exclude(std::time::Duration::from_secs(1));
        assert_eq!(
            timer.elapsed_us(),
            0,
            "excluded transport time must never be charged to decode"
        );
    }
}

/// The bucket index the budget falls in, for documentation and tests.
#[cfg(test)]
mod budget_bucket_test {
    use super::*;

    #[test]
    fn the_budget_bucket_actually_contains_the_budget() {
        assert_eq!(bucket_of(DECODE_BUDGET_US), BUDGET_BUCKET);
        assert!(bucket_upper_bound(BUDGET_BUCKET) > DECODE_BUDGET_US);
        assert!(bucket_upper_bound(BUDGET_BUCKET - 1) <= DECODE_BUDGET_US);
    }
}

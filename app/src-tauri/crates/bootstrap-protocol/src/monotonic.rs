use std::fmt;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonotonicClockError;

impl fmt::Display for MonotonicClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operating-system monotonic clock unavailable")
    }
}

impl std::error::Error for MonotonicClockError {}

/// Returns a boot-relative monotonic timestamp normalized to nanoseconds.
/// Linux and Windows processes on the same machine therefore share one
/// comparable time base without consulting the mutable wall clock.
#[cfg(target_os = "linux")]
pub fn monotonic_nanos() -> Result<u64, MonotonicClockError> {
    let mut sample = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut sample) } != 0 {
        return Err(MonotonicClockError);
    }
    normalized_seconds_nanos(sample.tv_sec, sample.tv_nsec).ok_or(MonotonicClockError)
}

#[cfg(target_os = "windows")]
pub fn monotonic_nanos() -> Result<u64, MonotonicClockError> {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };

    let mut counter = 0_i64;
    let mut frequency = 0_i64;
    if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
        || unsafe { QueryPerformanceCounter(&mut counter) } == 0
    {
        return Err(MonotonicClockError);
    }
    normalized_counter_nanos(counter, frequency).ok_or(MonotonicClockError)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn monotonic_nanos() -> Result<u64, MonotonicClockError> {
    Err(MonotonicClockError)
}

#[cfg(any(target_os = "linux", test))]
fn normalized_seconds_nanos(seconds: i64, nanos: i64) -> Option<u64> {
    let seconds = u128::try_from(seconds).ok()?;
    let nanos = u128::try_from(nanos).ok()?;
    if nanos >= NANOS_PER_SECOND {
        return None;
    }
    let normalized = seconds.checked_mul(NANOS_PER_SECOND)?.checked_add(nanos)?;
    u64::try_from(normalized).ok()
}

#[cfg(any(target_os = "windows", test))]
fn normalized_counter_nanos(counter: i64, frequency: i64) -> Option<u64> {
    let counter = u128::try_from(counter).ok()?;
    let frequency = u128::try_from(frequency).ok()?;
    if frequency == 0 {
        return None;
    }
    let normalized = counter
        .checked_mul(NANOS_PER_SECOND)?
        .checked_div(frequency)?;
    u64::try_from(normalized).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_values_are_normalized_without_wraparound() {
        assert_eq!(normalized_seconds_nanos(0, 0), Some(0));
        assert_eq!(normalized_seconds_nanos(12, 345), Some(12_000_000_345));
        assert_eq!(normalized_seconds_nanos(-1, 0), None);
        assert_eq!(normalized_seconds_nanos(0, 1_000_000_000), None);

        assert_eq!(normalized_counter_nanos(0, 10), Some(0));
        assert_eq!(normalized_counter_nanos(15, 10), Some(1_500_000_000));
        assert_eq!(normalized_counter_nanos(-1, 10), None);
        assert_eq!(normalized_counter_nanos(1, 0), None);
        assert_eq!(normalized_counter_nanos(i64::MAX, 1), None);
    }
}

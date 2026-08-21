//! The single name resolution of a personal access.
//!
//! A name is turned into addresses exactly once, before the user is shown
//! anything and long before the transport dials. That single call is the whole
//! point: what the native window displays and what the socket connects to come
//! from the same answer, so a name that later starts resolving elsewhere —
//! DNS rebinding — has nothing left to move.
//!
//! Two bounds guard the call itself. The resolver runs on its own thread and
//! is waited for under a deadline, because `getaddrinfo` has no cancellation
//! and a stalled resolver must never consume the session's whole lease. And no
//! more than [`MAX_COLLECTED_ADDRESSES`] answers are ever pulled out of the
//! iterator, so a hostile resolver cannot make this process allocate at will;
//! collecting one more than the accepted maximum is what lets
//! [`super::target::freeze`] refuse an oversized set instead of truncating it.

use std::{
    net::{IpAddr, ToSocketAddrs},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use super::target::MAX_TARGET_ADDRESSES;

/// Answers pulled out of one resolution. One more than the accepted maximum,
/// so an oversized set is observable and refusable rather than silently cut.
pub const MAX_COLLECTED_ADDRESSES: usize = MAX_TARGET_ADDRESSES + 1;

/// Longest a resolution may take on its own, whatever the session lease still
/// allows. A resolver that has not answered by then is treated as unavailable.
pub const MAX_RESOLUTION_WAIT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionRefusal {
    /// The name produced no address at all.
    NoAddress,
    /// The resolver failed, or the name does not exist.
    ResolverFailed,
    /// The resolver did not answer within the bound.
    TimedOut,
    /// The resolver thread could not be started.
    Unavailable,
}

/// Resolves `name` once, under a bound.
///
/// The returned addresses keep the resolver's order, which is the order the
/// user is shown and the order the transport tries.
pub fn resolve_once_bounded(
    name: &str,
    port: u16,
    deadline: Instant,
) -> Result<Vec<IpAddr>, ResolutionRefusal> {
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .min(MAX_RESOLUTION_WAIT);
    if wait.is_zero() {
        return Err(ResolutionRefusal::TimedOut);
    }

    let (sender, receiver) = mpsc::sync_channel(1);
    let query = (name.to_owned(), port);
    // The worker is deliberately detached rather than joined: `getaddrinfo`
    // cannot be cancelled, and waiting for a stalled resolver to notice would
    // hand it the very lease this bound exists to protect. The helper process
    // is short-lived and its exit reclaims the thread.
    thread::Builder::new()
        .name("personal-access-resolver".into())
        .spawn(move || {
            let _ = sender.send(resolve_once(&query.0, query.1));
        })
        .map_err(|_| ResolutionRefusal::Unavailable)?;

    match receiver.recv_timeout(wait) {
        Ok(resolved) => resolved,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(ResolutionRefusal::TimedOut),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(ResolutionRefusal::Unavailable),
    }
}

/// The one blocking call, isolated so the bounded wrapper above stays readable.
fn resolve_once(name: &str, port: u16) -> Result<Vec<IpAddr>, ResolutionRefusal> {
    let answers = (name, port)
        .to_socket_addrs()
        .map_err(|_| ResolutionRefusal::ResolverFailed)?;
    let addresses: Vec<IpAddr> = answers
        .take(MAX_COLLECTED_ADDRESSES)
        .map(|answer| answer.ip())
        .collect();
    if addresses.is_empty() {
        return Err(ResolutionRefusal::NoAddress);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A literal address is its own resolution: the call must not invent a
    /// second answer, and it must not need a network to succeed.
    #[test]
    fn a_literal_address_resolves_to_exactly_itself() {
        let resolved = resolve_once("192.0.2.10", 22).expect("a literal needs no resolver");
        assert_eq!(resolved, ["192.0.2.10".parse::<IpAddr>().unwrap()]);

        let resolved = resolve_once("2001:db8::1", 2222).expect("a literal needs no resolver");
        assert_eq!(resolved, ["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }

    /// The whole design rests on this: the answer is a value, and there is no
    /// way back from it to the resolver.
    #[test]
    fn a_resolution_result_carries_no_way_to_resolve_again() {
        let first = resolve_once("192.0.2.10", 22).expect("resolution");
        let second = resolve_once("192.0.2.10", 22).expect("resolution");
        assert_eq!(first, second);
        assert!(first.len() <= MAX_COLLECTED_ADDRESSES);
    }

    /// One more than the accepted maximum is collected on purpose, so an
    /// oversized set reaches `freeze` as a refusal instead of a silent cut.
    #[test]
    fn the_collected_bound_leaves_room_to_observe_an_oversized_set() {
        assert_eq!(MAX_COLLECTED_ADDRESSES, MAX_TARGET_ADDRESSES + 1);
    }

    #[test]
    fn an_elapsed_deadline_refuses_before_any_resolver_is_contacted() {
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            resolve_once_bounded("192.0.2.10", 22, past),
            Err(ResolutionRefusal::TimedOut),
            "an exhausted lease must never start a blocking resolution"
        );
    }

    #[test]
    fn a_bounded_resolution_of_a_literal_answers_within_its_lease() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let started = Instant::now();
        let resolved = resolve_once_bounded("192.0.2.10", 22, deadline).expect("literal");
        assert_eq!(resolved, ["192.0.2.10".parse::<IpAddr>().unwrap()]);
        assert!(
            started.elapsed() < MAX_RESOLUTION_WAIT,
            "the bound must not become the normal cost"
        );
    }

    /// The lease, not the fixed ceiling, is what caps a short session.
    #[test]
    fn the_wait_never_exceeds_the_remaining_lease() {
        let deadline = Instant::now() + Duration::from_millis(120);
        let started = Instant::now();
        let _ = resolve_once_bounded("invalid.invalid", 22, deadline);
        assert!(
            started.elapsed() < MAX_RESOLUTION_WAIT,
            "a short lease must cut the resolution before the fixed ceiling"
        );
    }
}

//! Real enumeration of the addresses this machine already holds.
//!
//! The guard that refuses to dial the administrator's own machine is only
//! worth what its input is worth. As long as the set of local addresses was a
//! plain slice, an empty one silently disabled the guard: nothing in the type
//! system distinguished "this machine holds no address" from "nobody looked".
//!
//! [`LocalAddresses`] is that missing witness. It can only be produced by an
//! enumeration that actually ran and actually observed something, so a caller
//! can no longer omit the observation by passing `&[]`. An enumeration that
//! fails, or that returns nothing at all, is a refusal rather than a permissive
//! empty set — even a machine with no network still holds a loopback address,
//! so an empty result means the observation is not trustworthy.

use std::net::IpAddr;

/// Largest accepted number of local addresses.
///
/// Refused rather than truncated: a truncated local set would silently make
/// one of this machine's own addresses dialable again.
pub const MAX_LOCAL_ADDRESSES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAddressRefusal {
    /// The operating system refused to enumerate the interfaces.
    EnumerationFailed,
    /// Nothing was observed at all, which no live machine ever reports.
    NothingObserved,
    TooManyAddresses,
    /// This platform has no enumeration wired up, so the guard cannot be honoured.
    Unsupported,
}

/// Proof that the local addresses of this machine were really enumerated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAddresses {
    addresses: Vec<IpAddr>,
}

impl LocalAddresses {
    /// The observed addresses, in enumeration order, deduplicated.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Builds the witness from an observation, enforcing the two properties
    /// that make it one: something was seen, and not unboundedly much.
    fn from_observation(observed: Vec<IpAddr>) -> Result<Self, LocalAddressRefusal> {
        if observed.is_empty() {
            return Err(LocalAddressRefusal::NothingObserved);
        }
        if observed.len() > MAX_LOCAL_ADDRESSES {
            return Err(LocalAddressRefusal::TooManyAddresses);
        }
        Ok(Self {
            addresses: observed,
        })
    }

    /// Enumerates every address currently configured on this machine.
    #[cfg(target_os = "linux")]
    pub fn observe() -> Result<Self, LocalAddressRefusal> {
        Self::from_observation(observe_interface_addresses()?)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn observe() -> Result<Self, LocalAddressRefusal> {
        // Failing closed keeps the Windows pass of this palier from believing
        // the guard is in force before its own enumeration exists.
        Err(LocalAddressRefusal::Unsupported)
    }

    /// Test-only witness. It is deliberately unavailable outside tests: a
    /// release build has exactly one way to obtain this value.
    #[cfg(test)]
    pub(crate) fn observed_for_test(observed: &[IpAddr]) -> Self {
        Self::from_observation(observed.to_vec()).expect("test observation")
    }
}

/// Walks the `getifaddrs` list once and keeps every IPv4 and IPv6 address.
///
/// Every address is kept, including loopback and link-local ones: the caller's
/// job is to refuse a target that matches any of them, and dropping a class
/// here would reopen exactly the case the guard exists for.
#[cfg(target_os = "linux")]
fn observe_interface_addresses() -> Result<Vec<IpAddr>, LocalAddressRefusal> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: head is valid output storage. The returned list is freed once,
    // unconditionally, before this function returns.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(LocalAddressRefusal::EnumerationFailed);
    }

    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor points at a live node of the list getifaddrs built,
        // which stays valid until freeifaddrs below.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points at a sockaddr whose family field is always
        // initialised by the kernel.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        let address = if family == libc::AF_INET as libc::sa_family_t {
            // SAFETY: AF_INET guarantees the storage is a sockaddr_in.
            let raw = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                raw.sin_addr.s_addr,
            ))))
        } else if family == libc::AF_INET6 as libc::sa_family_t {
            // SAFETY: AF_INET6 guarantees the storage is a sockaddr_in6.
            let raw = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)))
        } else {
            None
        };
        if let Some(address) = address {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        // Bounding inside the walk keeps a hostile interface count from
        // allocating without limit before the check below.
        if addresses.len() > MAX_LOCAL_ADDRESSES {
            break;
        }
    }

    // SAFETY: head is the exact pointer getifaddrs returned and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_live_machine_always_observes_at_least_its_loopback() {
        let local = LocalAddresses::observe().expect("this machine has interfaces");
        assert!(
            local
                .addresses()
                .iter()
                .any(|address| address.is_loopback()),
            "loopback must never be filtered out of the observation"
        );
        assert!(local.addresses().len() <= MAX_LOCAL_ADDRESSES);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_observation_is_deduplicated_and_reproducible() {
        let first = LocalAddresses::observe().expect("observation");
        let second = LocalAddresses::observe().expect("observation");
        assert_eq!(first, second);

        let mut seen: Vec<IpAddr> = Vec::new();
        for address in first.addresses() {
            assert!(!seen.contains(address), "{address} was reported twice");
            seen.push(*address);
        }
    }

    #[test]
    fn an_empty_or_oversized_observation_is_refused_rather_than_believed() {
        assert_eq!(
            LocalAddresses::from_observation(Vec::new()),
            Err(LocalAddressRefusal::NothingObserved),
            "no machine holds zero addresses: an empty result is untrustworthy"
        );
        let oversized: Vec<IpAddr> = (0..=MAX_LOCAL_ADDRESSES)
            .map(|index| {
                IpAddr::V4(std::net::Ipv4Addr::new(
                    10,
                    (index / 256) as u8,
                    (index % 256) as u8,
                    1,
                ))
            })
            .collect();
        assert_eq!(
            LocalAddresses::from_observation(oversized),
            Err(LocalAddressRefusal::TooManyAddresses)
        );
    }
}

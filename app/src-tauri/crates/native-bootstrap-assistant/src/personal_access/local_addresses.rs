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
//!
//! Two operating systems answer the question, through the primitive each of
//! them offers: `getifaddrs` on Linux, `GetAdaptersAddresses` on Windows. They
//! are two readings of the same fact and are held to the same rule — a call
//! that fails is [`LocalAddressRefusal::EnumerationFailed`], never an empty
//! observation quietly handed to [`LocalAddresses::from_observation`], which
//! would have turned a failure into a permissive answer one layer down.

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
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn observe() -> Result<Self, LocalAddressRefusal> {
        Self::from_observation(observe_interface_addresses()?)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn observe() -> Result<Self, LocalAddressRefusal> {
        // Failing closed keeps a platform with no enumeration of its own from
        // believing the guard is in force.
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

/// Smallest buffer `GetAdaptersAddresses` is offered. Microsoft's own guidance
/// is to start at fifteen kibibytes, which holds every ordinary machine in one
/// call; the growth below exists for the ones it does not.
#[cfg(target_os = "windows")]
const INITIAL_ADAPTER_BYTES: usize = 15 * 1024;

/// Largest buffer this module will ever hand the enumeration.
///
/// Refused rather than grown further: the size comes from the system, and a
/// bound is what keeps an implausible answer from becoming an allocation this
/// process makes on its behalf.
#[cfg(target_os = "windows")]
const MAX_ADAPTER_BYTES: usize = 4 * 1024 * 1024;

/// How many times the enumeration may be asked again for a larger buffer.
///
/// Adapters can appear between two calls, which is the whole reason the loop
/// exists; a loop that never gave up would hand a machine reconfiguring itself
/// an unbounded number of tries.
#[cfg(target_os = "windows")]
const MAX_ADAPTER_ATTEMPTS: usize = 4;

/// Walks the `GetAdaptersAddresses` list once and keeps every unicast IPv4 and
/// IPv6 address.
///
/// It is the Windows reading of what `getifaddrs` reads on Linux, and it keeps
/// exactly the same things for exactly the same reason: loopback and link-local
/// addresses are addresses this machine holds, and dropping a class here would
/// reopen the case the guard exists for. Anycast, multicast and the adapter's
/// DNS servers and friendly name are asked not to be built at all — the first
/// two are not addresses this machine answers on as itself, and the last two
/// are cost with no bearing on the question.
///
/// Adapters are enumerated whatever their operational state: an interface that
/// is down still holds its address, and a target matching it is still this
/// machine.
#[cfg(target_os = "windows")]
fn observe_interface_addresses() -> Result<Vec<IpAddr>, LocalAddressRefusal> {
    use std::{
        mem::size_of,
        net::{Ipv4Addr, Ipv6Addr},
        ptr::null,
    };

    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
    };

    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;

    let mut offered = INITIAL_ADAPTER_BYTES;
    let mut attempt = 0;
    // Held as words so the storage is aligned for the linked structures the
    // system writes into it.
    let storage: Vec<u64> = loop {
        let mut storage = vec![0_u64; offered.div_ceil(size_of::<u64>())];
        let mut size =
            u32::try_from(offered).map_err(|_| LocalAddressRefusal::EnumerationFailed)?;
        // SAFETY: storage is writable and aligned for the list the call builds,
        // size announces exactly its length, and the reserved argument is the
        // null pointer the call accepts.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                null(),
                storage.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status == ERROR_SUCCESS {
            break storage;
        }
        if status != ERROR_BUFFER_OVERFLOW {
            return Err(LocalAddressRefusal::EnumerationFailed);
        }
        let needed = usize::try_from(size).map_err(|_| LocalAddressRefusal::EnumerationFailed)?;
        attempt += 1;
        // A system that asks for no more than it was already given, for more
        // than this module will ever allocate, or once too often, has not
        // answered the question: that is a failed enumeration, not an empty one.
        if attempt >= MAX_ADAPTER_ATTEMPTS || needed <= offered || needed > MAX_ADAPTER_BYTES {
            return Err(LocalAddressRefusal::EnumerationFailed);
        }
        offered = needed;
    };

    let mut addresses: Vec<IpAddr> = Vec::new();
    let mut adapter: *const IP_ADAPTER_ADDRESSES_LH = storage.as_ptr().cast();
    while !adapter.is_null() {
        // SAFETY: adapter points at a live node of the list the call built,
        // which stays valid as long as storage does.
        let entry = unsafe { &*adapter };
        adapter = entry.Next;
        let mut unicast = entry.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: unicast points at a live node of the same list.
            let held = unsafe { &*unicast };
            unicast = held.Next;
            let socket_address = held.Address.lpSockaddr;
            if socket_address.is_null() {
                continue;
            }
            let length = usize::try_from(held.Address.iSockaddrLength).unwrap_or(0);
            // SAFETY: lpSockaddr points at a sockaddr whose family field the
            // system always initialises.
            let family = unsafe { (*socket_address).sa_family };
            // The announced length is checked against the storage each family
            // implies, so a truncated entry is skipped rather than read past.
            let address = if family == AF_INET && length >= size_of::<SOCKADDR_IN>() {
                // SAFETY: AF_INET and the length above guarantee a sockaddr_in.
                let raw = unsafe { &*socket_address.cast::<SOCKADDR_IN>() };
                // SAFETY: the union holds the address as its four bytes.
                let octets = unsafe { raw.sin_addr.S_un.S_addr };
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(octets))))
            } else if family == AF_INET6 && length >= size_of::<SOCKADDR_IN6>() {
                // SAFETY: AF_INET6 and the length above guarantee a sockaddr_in6.
                let raw = unsafe { &*socket_address.cast::<SOCKADDR_IN6>() };
                // SAFETY: the union holds the address as its sixteen bytes.
                let octets = unsafe { raw.sin6_addr.u.Byte };
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            } else {
                None
            };
            if let Some(address) = address {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
            // Bounding inside the walk keeps a hostile adapter count from
            // allocating without limit before the check the caller applies.
            if addresses.len() > MAX_LOCAL_ADDRESSES {
                return Ok(addresses);
            }
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both enumerations are held to this, on the machine running the test.
    /// It is what a platform guard used to hide: an `observe` that refuses by
    /// construction passes no assertion, it only skips them.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
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

    #[cfg(any(target_os = "linux", target_os = "windows"))]
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

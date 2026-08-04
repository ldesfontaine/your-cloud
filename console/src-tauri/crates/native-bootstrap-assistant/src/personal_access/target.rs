//! Frozen target set of the personal access.
//!
//! A name is resolved exactly once, before the user consents. What the native
//! window shows and what the transport later dials are the same frozen
//! addresses. Nothing re-resolves afterwards, so a name that starts answering
//! with a different address — DNS rebinding — cannot move the connection to a
//! host the user never approved.
//!
//! The refusal list is deliberately about *reachability class*, not about
//! public versus private: a Controller may legitimately live on a private
//! RFC1918 or ULA address, and a VPS on a public one. What must never be
//! dialled is an address that means "somewhere else than a real remote host":
//! the unspecified address, loopback, link-local — which carries the cloud
//! metadata endpoint `169.254.169.254` — multicast, broadcast, and any address
//! the administrator's own machine already holds.

use std::net::{IpAddr, Ipv6Addr};

use super::local_addresses::LocalAddresses;

/// Largest accepted number of distinct addresses behind one name.
pub const MAX_TARGET_ADDRESSES: usize = 8;

/// Largest accepted target name, in bytes.
pub const MAX_TARGET_NAME_BYTES: usize = 253;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetRefusal {
    EmptyName,
    NameTooLong,
    NameNotPrintableAscii,
    PortZero,
    NoAddress,
    TooManyAddresses,
    Unspecified,
    Loopback,
    LinkLocal,
    Multicast,
    Broadcast,
    LocalInterface,
}

/// A target the user has been shown and may consent to.
///
/// It owns its addresses. There is deliberately no constructor that takes a
/// name without addresses, and no method that resolves anything: holding this
/// value is the proof that resolution already happened, once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenTarget {
    name: String,
    port: u16,
    addresses: Vec<IpAddr>,
}

impl FrozenTarget {
    /// The displayed name. It never selects the peer: the addresses do.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The frozen numeric addresses, in resolution order, deduplicated.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// The only admissible question at connection time.
    pub fn allows(&self, candidate: IpAddr) -> bool {
        self.addresses.contains(&normalise(candidate))
    }
}

/// Freezes a resolution result into a consentable target.
///
/// `resolved` is what the single resolution returned, in order. `local` is the
/// witness that the administrator's own addresses were really enumerated; it
/// is a dedicated type rather than a slice precisely so that omitting the
/// observation is not expressible here.
pub fn freeze(
    name: &str,
    port: u16,
    resolved: &[IpAddr],
    local: &LocalAddresses,
) -> Result<FrozenTarget, TargetRefusal> {
    if name.is_empty() {
        return Err(TargetRefusal::EmptyName);
    }
    if name.len() > MAX_TARGET_NAME_BYTES {
        return Err(TargetRefusal::NameTooLong);
    }
    // The name is echoed into a native window. Restricting it to printable
    // ASCII keeps a control sequence or a homograph out of the surface the
    // user reads before consenting.
    if !name.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(TargetRefusal::NameNotPrintableAscii);
    }
    if port == 0 {
        return Err(TargetRefusal::PortZero);
    }
    if resolved.is_empty() {
        return Err(TargetRefusal::NoAddress);
    }

    let local: Vec<IpAddr> = local.addresses().iter().copied().map(normalise).collect();
    let mut addresses: Vec<IpAddr> = Vec::new();
    for candidate in resolved {
        let candidate = normalise(*candidate);
        check_reachability_class(candidate)?;
        if local.contains(&candidate) {
            return Err(TargetRefusal::LocalInterface);
        }
        if !addresses.contains(&candidate) {
            addresses.push(candidate);
        }
    }
    // Refused rather than truncated: silently dropping addresses would freeze
    // a set the user was never shown.
    if addresses.len() > MAX_TARGET_ADDRESSES {
        return Err(TargetRefusal::TooManyAddresses);
    }

    Ok(FrozenTarget {
        name: name.to_owned(),
        port,
        addresses,
    })
}

/// Collapses an IPv4-mapped IPv6 address onto its IPv4 form.
///
/// Without this, `::ffff:127.0.0.1` would pass an IPv6 check that only knows
/// about `::1` and reach loopback anyway.
fn normalise(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn check_reachability_class(address: IpAddr) -> Result<(), TargetRefusal> {
    match address {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err(TargetRefusal::Unspecified);
            }
            if v4.is_loopback() {
                return Err(TargetRefusal::Loopback);
            }
            if v4.is_link_local() {
                return Err(TargetRefusal::LinkLocal);
            }
            if v4.is_multicast() {
                return Err(TargetRefusal::Multicast);
            }
            if v4.is_broadcast() {
                return Err(TargetRefusal::Broadcast);
            }
            Ok(())
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err(TargetRefusal::Unspecified);
            }
            if v6.is_loopback() {
                return Err(TargetRefusal::Loopback);
            }
            if is_unicast_link_local(v6) {
                return Err(TargetRefusal::LinkLocal);
            }
            if v6.is_multicast() {
                return Err(TargetRefusal::Multicast);
            }
            Ok(())
        }
    }
}

/// `fe80::/10`. Written by hand because the standard predicate is still
/// unstable, and this palier pins its toolchain rather than tracking nightly.
fn is_unicast_link_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    /// An observation that really happened and that collides with no target
    /// used below. It replaces the former `&[]`, which could not tell an
    /// enumeration apart from its absence.
    fn elsewhere() -> LocalAddresses {
        LocalAddresses::observed_for_test(&[ip("203.0.113.9")])
    }

    #[test]
    fn private_unique_local_and_public_targets_stay_reachable() {
        for address in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.10",
            "fd00::1",
            "93.184.216.34",
            "2001:db8::1",
        ] {
            let target = freeze("target.lab", 22, &[ip(address)], &elsewhere())
                .unwrap_or_else(|error| panic!("{address} must stay reachable: {error:?}"));
            assert_eq!(target.addresses(), [ip(address)]);
        }
    }

    #[test]
    fn addresses_that_do_not_mean_a_remote_host_are_refused() {
        for (address, expected) in [
            ("0.0.0.0", TargetRefusal::Unspecified),
            ("::", TargetRefusal::Unspecified),
            ("127.0.0.1", TargetRefusal::Loopback),
            ("127.0.0.53", TargetRefusal::Loopback),
            ("::1", TargetRefusal::Loopback),
            ("169.254.1.1", TargetRefusal::LinkLocal),
            ("fe80::1", TargetRefusal::LinkLocal),
            ("224.0.0.1", TargetRefusal::Multicast),
            ("ff02::1", TargetRefusal::Multicast),
            ("255.255.255.255", TargetRefusal::Broadcast),
        ] {
            assert_eq!(
                freeze("target.lab", 22, &[ip(address)], &elsewhere()),
                Err(expected),
                "{address} must fail closed"
            );
        }
    }

    /// The cloud metadata endpoint is the reason link-local is refused rather
    /// than merely discouraged.
    #[test]
    fn the_cloud_metadata_endpoint_is_refused() {
        assert_eq!(
            freeze("metadata", 22, &[ip("169.254.169.254")], &elsewhere()),
            Err(TargetRefusal::LinkLocal)
        );
    }

    #[test]
    fn an_ipv4_mapped_address_cannot_smuggle_a_refused_class() {
        for (address, expected) in [
            ("::ffff:127.0.0.1", TargetRefusal::Loopback),
            ("::ffff:169.254.169.254", TargetRefusal::LinkLocal),
            ("::ffff:0.0.0.0", TargetRefusal::Unspecified),
            ("::ffff:255.255.255.255", TargetRefusal::Broadcast),
        ] {
            assert_eq!(
                freeze("target.lab", 22, &[ip(address)], &elsewhere()),
                Err(expected),
                "{address} must be normalised before it is judged"
            );
        }
    }

    #[test]
    fn an_address_the_local_machine_holds_is_refused() {
        let local = LocalAddresses::observed_for_test(&[ip("192.168.1.20"), ip("fd00::20")]);
        for address in ["192.168.1.20", "fd00::20", "::ffff:192.168.1.20"] {
            assert_eq!(
                freeze("target.lab", 22, &[ip(address)], &local),
                Err(TargetRefusal::LocalInterface),
                "{address} belongs to this machine"
            );
        }
        assert!(freeze("target.lab", 22, &[ip("192.168.1.21")], &local).is_ok());
    }

    /// The guard used to be optional by construction: passing an empty slice
    /// disabled it without any signal. The witness is now the only way in, and
    /// a real enumeration of this machine refuses this machine's own addresses.
    ///
    /// Only Linux enumerates. Elsewhere the witness cannot be produced at all,
    /// which the companion case below states as the refusal it is rather than
    /// leaving this one to fail as if the guard were broken.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_local_guard_cannot_be_disabled_by_omission() {
        let observed = LocalAddresses::observe().expect("this machine has interfaces");
        for address in observed.addresses() {
            // Loopback and link-local are already refused for their class; the
            // remaining ones exercise the local-interface refusal itself.
            let refusal = freeze("target.lab", 22, &[*address], &observed)
                .expect_err("no address of this machine may be dialled");
            assert!(
                matches!(
                    refusal,
                    TargetRefusal::LocalInterface
                        | TargetRefusal::Loopback
                        | TargetRefusal::LinkLocal
                        | TargetRefusal::Unspecified
                        | TargetRefusal::Multicast
                        | TargetRefusal::Broadcast
                ),
                "{address} is held by this machine yet produced {refusal:?}"
            );
        }
    }

    /// Off Linux the enumeration does not exist, and the witness it alone can
    /// produce is therefore unobtainable. That is the intended fail-closed
    /// behaviour and it is asserted here: a platform without enumeration must
    /// refuse to observe rather than hand back an empty set that would silently
    /// make every address of this machine dialable again.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_platform_without_enumeration_refuses_to_produce_the_witness() {
        assert_eq!(
            LocalAddresses::observe(),
            Err(crate::personal_access::local_addresses::LocalAddressRefusal::Unsupported)
        );
    }

    #[test]
    fn duplicates_collapse_while_preserving_resolution_order() {
        let resolved = [
            ip("192.168.1.10"),
            ip("10.0.0.1"),
            ip("192.168.1.10"),
            ip("::ffff:10.0.0.1"),
        ];
        let target = freeze("target.lab", 22, &resolved, &elsewhere()).expect("deduplicated");
        assert_eq!(target.addresses(), [ip("192.168.1.10"), ip("10.0.0.1")]);
    }

    #[test]
    fn more_than_eight_distinct_addresses_are_refused_rather_than_truncated() {
        let eight: Vec<IpAddr> = (1..=8)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 168, 1, last)))
            .collect();
        assert!(freeze("target.lab", 22, &eight, &elsewhere()).is_ok());

        let nine: Vec<IpAddr> = (1..=9)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 168, 1, last)))
            .collect();
        assert_eq!(
            freeze("target.lab", 22, &nine, &elsewhere()),
            Err(TargetRefusal::TooManyAddresses)
        );
    }

    #[test]
    fn a_name_or_port_that_cannot_be_displayed_or_dialled_is_refused() {
        assert_eq!(
            freeze("", 22, &[ip("10.0.0.1")], &elsewhere()),
            Err(TargetRefusal::EmptyName)
        );
        assert_eq!(
            freeze(
                &"a".repeat(MAX_TARGET_NAME_BYTES + 1),
                22,
                &[ip("10.0.0.1")],
                &elsewhere()
            ),
            Err(TargetRefusal::NameTooLong)
        );
        for hostile in ["tar\nget", "tar get", "targ\u{0}et", "tärget"] {
            assert_eq!(
                freeze(hostile, 22, &[ip("10.0.0.1")], &elsewhere()),
                Err(TargetRefusal::NameNotPrintableAscii),
                "{hostile:?} must never reach the native window"
            );
        }
        assert_eq!(
            freeze("target.lab", 0, &[ip("10.0.0.1")], &elsewhere()),
            Err(TargetRefusal::PortZero)
        );
        assert_eq!(
            freeze("target.lab", 22, &[], &elsewhere()),
            Err(TargetRefusal::NoAddress)
        );
    }

    #[test]
    fn a_frozen_target_only_ever_admits_its_own_addresses() {
        let target = freeze("target.lab", 22, &[ip("192.168.1.10")], &elsewhere()).expect("frozen");

        assert!(target.allows(ip("192.168.1.10")));
        assert!(
            target.allows(ip("::ffff:192.168.1.10")),
            "the same host in mapped form is the same peer"
        );
        // What a second resolution could have returned instead.
        for rebound in ["192.168.1.11", "127.0.0.1", "93.184.216.34"] {
            assert!(
                !target.allows(ip(rebound)),
                "{rebound} was never consented to"
            );
        }
    }

    #[test]
    fn a_frozen_target_exposes_no_way_to_resolve_again() {
        let target = freeze("target.lab", 2222, &[ip("10.0.0.1")], &elsewhere()).expect("frozen");
        assert_eq!(target.name(), "target.lab");
        assert_eq!(target.port(), 2222);
        // The displayed name is inert: only the frozen addresses select a peer.
        assert!(!target.allows(ip("10.0.0.2")));
        assert_eq!(
            target.addresses().len(),
            1,
            "the consented set never grows after freezing"
        );
    }

    #[test]
    fn unique_local_is_not_mistaken_for_link_local() {
        assert!(!is_unicast_link_local(
            "fd00::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(is_unicast_link_local(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(is_unicast_link_local(
            "febf::1".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_unicast_link_local(
            "fec0::1".parse::<Ipv6Addr>().unwrap()
        ));
    }
}

//! The plans of the public profile, of the private one and of the third door,
//! on the side that displays them.
//!
//! Schema 2 keeps every procedure of schema 1 — one bounded strict JSON
//! document, one domain-separated binary transcript, a rollback that is a
//! complete inverse document, a pair frozen by the Controller, a signature by
//! the Console, a re-verification by the Auxiliary — and describes the
//! operations of the public profile, of the private one and of the third door,
//! where a service is described by a definition its user wrote rather than by a
//! profile the product pins: six of them in three inverse pairs for the public
//! profile, six more in three pairs for the private one, a return whose undoing
//! is a document of its own operation, and two for the third door. Each carries
//! its own closed field list. Schema 1 is not reopened by any of it: a probe plan
//! decodes, hashes and verifies exactly as before, and a document of either
//! schema is refused by the decoder of the other.
//!
//! The third door is why this module reads the definition module, and it reads
//! it in one direction only: a plan names a definition by its slug and its
//! digest, so the grammar of those two values is stated where the definition owns
//! it rather than spelled a second time here. Nothing here reads a definition's
//! content — a plan pins bytes it never opens — and holding a plan against the
//! document it pins is not this side's act at all: see the note below the layout.
//!
//! **The operation is the discriminator.** It is read first, by a pass that
//! reads nothing else, and the document is then held against exactly the closed
//! field list that operation declares. A route document carrying an image digest
//! is therefore an unknown field of the route schema, refused before its value
//! is read, rather than retried as a service plan that happens to be missing a
//! port. Nothing is decided by that first pass: it selects a schema, and the
//! strict decoding that follows is the whole of the authority.
//!
//! **Nothing here signs, and nothing here encodes.** As for schema 1, the
//! Controller freezes the canonical bytes and transports them; this side
//! receives those exact bytes beside the digests they are claimed to have,
//! rebuilds the digest from the fields it parsed, and refuses the pair when the
//! two disagree.
//!
//! The transcript is laid out per operation group. The fields a group does not
//! have are simply not present rather than written empty — a field one group's
//! own documents may or may not carry is a different matter, stated below — and
//! the operation string inside the transcript is what tells the groups apart:
//!
//! ```text
//! domain  "your-cloud/oci-plan.v2\0"
//! then    schema_version                       on one byte
//!         infrastructure_id, machine_id, operation
//!                                     as uint32 big-endian length-prefixed fields
//! then, per operation:
//!   deploy_web_service / remove_web_service
//!         service_profile, image_reference     as prefixed fields
//!         image_digest (32 decoded bytes)      as a prefixed field
//!         local_port                           as a uint32 big-endian
//!   deploy_entrypoint / remove_entrypoint
//!         image_reference                      as a prefixed field
//!         image_digest (32 decoded bytes)      as a prefixed field
//!   publish_route / retire_route
//!         route_host                           as a prefixed field
//!         backend_port                         as a uint32 big-endian
//!   deploy_private_service / remove_private_service
//!         service_profile, image_reference     as prefixed fields
//!         image_digest (32 decoded bytes)      as a prefixed field
//!         local_port                           as a uint32 big-endian
//!         origin_host                          as a prefixed field
//!   publish_link_route / retire_link_route
//!         route_host                           as a prefixed field
//!         backend_port                         as a uint32 big-endian
//!   snapshot_service / discard_snapshot
//!         service_profile, snapshot_slot       as prefixed fields
//!   restore_service
//!         service_profile, snapshot_slot       as prefixed fields
//!   deploy_user_service / remove_user_service
//!         definition_slug                      as a prefixed field
//!         definition_digest (32 decoded bytes) as a prefixed field
//!         image_reference                      as a prefixed field
//!         image_digest (32 decoded bytes)      as a prefixed field
//!         local_port                           as a uint32 big-endian
//!         origin_host                          as a prefixed field, empty when absent
//! ```
//!
//! The layout is unambiguous across the groups without a group tag, because
//! everything before the operation is at a determined offset: the domain and the
//! version are fixed, and each of the two fields that follow announces its own
//! length. A reader that has consumed the operation therefore knows which of the
//! tails it is looking at, so no two documents of different groups can produce
//! the same bytes.
//!
//! Three pairs of groups carry the same tail shape — a route and a link route
//! name a host and a port, a snapshot and a restore name a profile and a slot —
//! and they are still six distinct digests, because the operation string is
//! inside the hashed bytes at a determined offset. That is exactly what the
//! operation is there for: two documents that describe different states never
//! hash the same, even when the values they carry are spelled identically. The
//! vectors below pin that property rather than leaving it to be read here.
//!
//! The user service group is the one group carrying a field that is present on
//! some of its documents and absent on others, and the layout writes it anyway:
//! `origin_host` is always a length-prefixed field, of length zero when the
//! definition does not interpolate the origin. Writing it always is what keeps
//! the tail unambiguous — a field the reader may or may not find would make the
//! end of the transcript depend on a rule the bytes do not carry — and it is the
//! decision the definition's own lists already took, where an empty list is
//! written as a count of zero rather than left out. The empty spelling is
//! unmistakable because no origin the contract accepts is the empty string: a
//! plan carrying no origin and a plan carrying an origin are two lengths and two
//! digests, never two readings of the same bytes. The canonical JSON follows the
//! same rule and always renders the field, so a document that omitted it and one
//! that spelled it empty are one plan with one digest — which is why this side
//! accepts both spellings and rebuilds the same transcript out of either.
//!
//! `definition_digest` travels as its 32 decoded bytes in a length-prefixed
//! field, as `image_digest` does. It is the digest of the frozen definition the
//! plan pins, taken over the definition's own transcript under its own domain, so
//! nothing of the two documents' bounds can ever be read through the other's. It
//! carries no `sha256:` prefix, and that is not an oversight beside the image
//! digest: an image digest is an OCI reference whose algorithm is part of the
//! value a registry answers to, while a definition digest is this product's own
//! SHA-256, spelled exactly as the approval envelope spells the digests it signs
//! — and it is read here by that very reader rather than by a second one.
//!
//! **Whether a plan agrees with the definition it pins is not decided here.**
//! Validating a plan is an offline act over one document: this side can say that
//! `origin_host` is a well-formed host or absent, and it cannot say whether the
//! pinned definition consumes one, because it holds no definition. That
//! cross-check — the digest re-derived from the definition's own bytes, the slug,
//! the repository, and the presence of the origin — is `RequireDefinitionAgreement`
//! on the Auxiliary side, held at construction by the Controller that has just
//! looked the definition up and re-held by the Auxiliary that receives the
//! definition beside the signed pair. The Console receives a frozen pair and no
//! definition, so a rule written here would be a rule with nothing to read.
//!
//! **The transcript is the counterpart of the one written on the Auxiliary
//! side.** The two are held against one another by deterministic vectors on both
//! sides rather than by reading. The eighteen vectors below are the very ones
//! pinned in `internal/plan/schema2_test.go`.

use crate::{
    approval::{append_field, canonical_machine_id, canonical_uuid_v4, decode_digest},
    plan::{
        decode_image_digest, encode_lower_hex, MAX_PLAN_DOCUMENT_BYTES, MAX_PLAN_LOCAL_PORT,
        MIN_PLAN_LOCAL_PORT, PLAN_DIGEST_BYTES,
    },
    service_definition::{canonical_definition_slug, canonical_image_repository},
    ProtocolError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The second plan version, and the only one that describes services,
/// entrypoints and routes.
pub const PLAN_V2_SCHEMA_VERSION: u8 = 2;

/// Domain separator of this transcript, terminated by a byte no textual field
/// may contain. It differs from the schema 1 separator by one byte on purpose:
/// the version is not a hint, it selects which closed contract a document is
/// held against, so a schema 2 digest can never be read as a schema 1 digest.
pub const PLAN_V2_TRANSCRIPT_DOMAIN: &[u8] = b"your-cloud/oci-plan.v2\0";

/// The one service profile of the stateless door.
///
/// The profile decides everything the plan does not state — account, unit file,
/// isolation headers — so an unknown profile is refused before the rest of the
/// document is read. Widening the list is a decision of a later palier, not a
/// generalisation of this one.
pub const SERVICE_PROFILE_BENTOPDF: &str = "bentopdf";

/// The one service profile of the private door: the first profile of the
/// product whose data outlives its container.
///
/// It decides its persistent volume, its closed environment lines and its egress
/// table, none of which any field of a plan can name or move. It is a second
/// door rather than a widening of the first, so the two lists of profiles are
/// closed against one another in both directions: a data-bearing service does
/// not pass through the stateless door, and a stateless service does not pass
/// through the private one.
pub const SERVICE_PROFILE_VAULTWARDEN: &str = "vaultwarden";

/// The one image the `bentopdf` profile may name, and the digest that is its
/// executable identity. The reference carries no tag: a tag is a human
/// indication, and an update is a new plan whose digest differs rather than a
/// silent mutation.
pub const BENTOPDF_IMAGE_REFERENCE: &str = "ghcr.io/alam00000/bentopdf";
pub const BENTOPDF_IMAGE_DIGEST: &str =
    "sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0";

/// The one image an entrypoint plan may name, under the same rule. There is one
/// entrypoint and one image for it, so it has no profile to choose from.
pub const ENTRYPOINT_IMAGE_REFERENCE: &str = "docker.io/library/traefik";
pub const ENTRYPOINT_IMAGE_DIGEST: &str =
    "sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac";

/// The one image the `vaultwarden` profile may name, under the same rule again.
///
/// The digest is the manifest list of the contract: it resolves to one image per
/// architecture, which is what lets a later proof change machine without
/// changing profile, and it is compared for equality rather than parsed into a
/// policy.
pub const VAULTWARDEN_IMAGE_REFERENCE: &str = "docker.io/vaultwarden/server";
pub const VAULTWARDEN_IMAGE_DIGEST: &str =
    "sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8";

/// The address a managed service listens on, and the address a route reaches its
/// backend at. It is a constant of the contract and not a field of any document:
/// no approvable value can expose a managed service beyond its own machine, so
/// the window that displays a plan reads the address from here.
pub const SERVICE_LOCAL_ADDRESS: &str = "127.0.0.1";

/// The two public ports of the entrypoint. They are constants of the contract
/// rather than fields, because an entrypoint has nothing approvable beyond its
/// existence and its image — but they are displayed, because what the human
/// approves is a machine that starts listening publicly.
pub const ENTRYPOINT_PUBLIC_HTTPS_PORT: u32 = 443;
pub const ENTRYPOINT_PUBLIC_HTTP_PORT: u32 = 80;

/// The one host-wide relaxation the entrypoint plan carries. It is a declared
/// effect of that plan, applied with it and removed with it, and it is written
/// in what the human approves rather than done in silence.
pub const ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL: &str = "net.ipv4.ip_unprivileged_port_start=80";

/// The isolation headers the route of the profile adds, as a named middleware of
/// its fragment. They condition `SharedArrayBuffer`, which the complete edition
/// exercises, so they are part of what a published name means and are displayed
/// beside it.
pub const ROUTE_ISOLATION_HEADERS: [&str; 2] = [
    "Cross-Origin-Opener-Policy: same-origin",
    "Cross-Origin-Embedder-Policy: require-corp",
];

/// Bounds of the declared name a route serves. There is no wildcard inside those
/// bounds: a route names one host, and a name nobody declared receives the
/// generic refusal of the entrypoint rather than an application route.
pub const MIN_ROUTE_HOST_BYTES: usize = 3;
pub const MAX_ROUTE_HOST_BYTES: usize = 253;

/// Bounds of the loopback port a route may name behind it. They repeat the range
/// of the service side, because a route may only name a port a managed service
/// of the same machine could be listening on.
pub const MIN_PLAN_BACKEND_PORT: u32 = MIN_PLAN_LOCAL_PORT;
pub const MAX_PLAN_BACKEND_PORT: u32 = MAX_PLAN_LOCAL_PORT;

/// The one durable write path of the private profile, and a constant of
/// placement rather than a field.
///
/// It is mounted on the `/data` the image declares, it lives under the home of
/// the profile's own account, and no field of any plan can describe another: the
/// rule of the stateless sheets is unchanged — no plan of this product describes
/// a path a machine will write to. It is displayed because a human who approved
/// a data-bearing service without reading where its data lands would have
/// approved a volume unread.
pub const PRIVATE_SERVICE_DATA_VOLUME: &str = "/var/lib/your-cloud-svc-vaultwarden/data";

/// The hardening lines of the private profile's environment. They are constants
/// of the profile, closed like everything else it decides, and displayed for the
/// same reason the volume is.
///
/// The fourth line of the sheet is the only approved value, `DOMAIN`, built from
/// the origin the document names — which is why it is not here: it is not a
/// constant, it is the one environment line a human chooses, and it is shown
/// beside these three.
pub const PRIVATE_SERVICE_ENVIRONMENT_HARDENING: [&str; 3] = [
    "SIGNUPS_ALLOWED=false",
    "INVITATIONS_ALLOWED=false",
    "SHOW_PASSWORD_HINT=false",
];

/// The environment variable the private profile's origin is written into, and
/// the scheme it is written under. The instance must know which name it answers
/// as, and a serious use of the vault demands a secure context, so the origin is
/// always an `https` one.
pub const PRIVATE_SERVICE_ORIGIN_VARIABLE: &str = "DOMAIN";
pub const PRIVATE_SERVICE_ORIGIN_SCHEME: &str = "https";

/// The egress table posed with a private service deployment and removed with it.
///
/// The service needs no outbound traffic at all, so every outbound flow emitted
/// by its account is refused, loopback and established replies aside. It is a
/// declared effect of the plan rather than a silent hardening, so it is
/// displayed beside what it confines.
pub const PRIVATE_SERVICE_EGRESS_TABLE: &str = "inet your-cloud-egress";

/// Bounds of the label one archive is named by.
///
/// The slot is the only part of an archive's path a human chooses, so it is
/// bounded to what a single directory entry can be: no separator, no dot, no
/// upper case, nothing that could climb out of the directory the profile owns.
pub const MIN_SNAPSHOT_SLOT_BYTES: usize = 1;
pub const MAX_SNAPSHOT_SLOT_BYTES: usize = 32;

/// The slot that belongs to the return mechanism and to nothing else.
///
/// A snapshot may not write it and a discard may not destroy it: it holds the
/// state a restore was about to replace, and it is the one slot the Auxiliary
/// itself is allowed to overwrite. It appears in exactly one document of the
/// product — the signed rollback of a restore — which is why a restore document
/// naming it is valid here while a snapshot or a discard naming it is not.
pub const RESERVED_SNAPSHOT_SLOT: &str = "previous";

/// Which of the closed field lists an operation carries.
///
/// It is the whole of the discriminator: an operation names exactly one group,
/// and a document decoded into one shape is refused when its operation belongs
/// to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanV2Group {
    WebService,
    Entrypoint,
    Route,
    PrivateService,
    LinkRoute,
    Snapshot,
    Restore,
    UserService,
}

/// The closed list of states this palier can describe.
///
/// Every member has an inverse that is itself a member and carries the same
/// closed field list, which is what makes an operation without an undoing
/// impossible to add here by accident: a rollback is a plan in its own right,
/// read, displayed, approved and verified like any other.
///
/// The restore is the one member that names itself, and it is the one this list
/// does not fully describe: what changes between a restore and its undoing is
/// the slot, not the operation. The undoing of [`RestorePlanDocumentV2`] states
/// that; this list says the only thing it can — that the document which returns
/// from a restore is a restore.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanV2Operation {
    /// One managed web service is present on exactly one machine, at exactly one
    /// loopback port, and its inverse asks for that exact instance to be absent.
    DeployWebService,
    RemoveWebService,
    /// The public entrypoint exists on this machine, and its inverse asks for it
    /// to be gone. Neither carries a port or a host.
    DeployEntrypoint,
    RemoveEntrypoint,
    /// One declared name reaches one managed service through the entrypoint, and
    /// its inverse asks for that name to stop being served. Retiring a route
    /// removes the route and nothing else: the service it named keeps running.
    PublishRoute,
    RetireRoute,
    /// One managed service whose data outlives its container is present on
    /// exactly one machine, at exactly one loopback port and under exactly one
    /// origin, and its inverse asks for that exact instance to be absent.
    DeployPrivateService,
    RemovePrivateService,
    /// One declared name reaches one managed service through the entrypoint and
    /// the private passage, and its inverse asks for that name to stop being
    /// served.
    ///
    /// It carries the fields of [`Self::PublishRoute`] and describes another
    /// state: the backend of a link route is the constant peer of the tunnel
    /// rather than this machine's own loopback, and its presence rule is a
    /// junction the passage bounds. The two are therefore never interchangeable,
    /// and their digests differ because the operation is inside the hashed bytes.
    PublishLinkRoute,
    RetireLinkRoute,
    /// The data of one private service is archived under exactly one named slot,
    /// and its inverse asks for that archive to be gone. A snapshot stops and
    /// restarts the service, so it mutates the machine as much as a deployment
    /// does.
    SnapshotService,
    DiscardSnapshot,
    /// The data of one private service becomes what one named slot holds. It is
    /// the one operation of this schema whose undoing is itself: the flow writes
    /// the current state into the reserved slot before replacing anything, so the
    /// document that returns is a restore naming that reserved slot.
    RestoreService,
    /// One service described by a definition its user wrote is present on
    /// exactly one machine, at exactly one loopback port, and its inverse asks
    /// for that exact instance to be absent.
    ///
    /// It is a third door rather than a widening of the second, for the reason
    /// the second was not a widening of the first: nothing about this service is
    /// a constant of the product. The account, the home, the volumes, the
    /// environment and the secret names are derived from a definition the
    /// Controller froze and the plan pins by digest, so the two documents name a
    /// definition where the other doors name a profile — and neither list of
    /// profiles can ever answer to a definition's slug, because those slugs are
    /// reserved against exactly the four names the product already owns.
    DeployUserService,
    RemoveUserService,
}

impl PlanV2Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeployWebService => "deploy_web_service",
            Self::RemoveWebService => "remove_web_service",
            Self::DeployEntrypoint => "deploy_entrypoint",
            Self::RemoveEntrypoint => "remove_entrypoint",
            Self::PublishRoute => "publish_route",
            Self::RetireRoute => "retire_route",
            Self::DeployPrivateService => "deploy_private_service",
            Self::RemovePrivateService => "remove_private_service",
            Self::PublishLinkRoute => "publish_link_route",
            Self::RetireLinkRoute => "retire_link_route",
            Self::SnapshotService => "snapshot_service",
            Self::DiscardSnapshot => "discard_snapshot",
            Self::RestoreService => "restore_service",
            Self::DeployUserService => "deploy_user_service",
            Self::RemoveUserService => "remove_user_service",
        }
    }

    /// The operation that undoes this one.
    ///
    /// The restore names itself, because what its undoing changes is the slot
    /// rather than the operation. An operation is therefore never the whole of an
    /// inverse document: the shapes below build one, and this is what they read
    /// for the part of it that is an operation.
    pub fn inverse(self) -> Self {
        match self {
            Self::DeployWebService => Self::RemoveWebService,
            Self::RemoveWebService => Self::DeployWebService,
            Self::DeployEntrypoint => Self::RemoveEntrypoint,
            Self::RemoveEntrypoint => Self::DeployEntrypoint,
            Self::PublishRoute => Self::RetireRoute,
            Self::RetireRoute => Self::PublishRoute,
            Self::DeployPrivateService => Self::RemovePrivateService,
            Self::RemovePrivateService => Self::DeployPrivateService,
            Self::PublishLinkRoute => Self::RetireLinkRoute,
            Self::RetireLinkRoute => Self::PublishLinkRoute,
            Self::SnapshotService => Self::DiscardSnapshot,
            Self::DiscardSnapshot => Self::SnapshotService,
            Self::RestoreService => Self::RestoreService,
            Self::DeployUserService => Self::RemoveUserService,
            Self::RemoveUserService => Self::DeployUserService,
        }
    }

    /// The closed field list this operation carries.
    pub fn group(self) -> PlanV2Group {
        match self {
            Self::DeployWebService | Self::RemoveWebService => PlanV2Group::WebService,
            Self::DeployEntrypoint | Self::RemoveEntrypoint => PlanV2Group::Entrypoint,
            Self::PublishRoute | Self::RetireRoute => PlanV2Group::Route,
            Self::DeployPrivateService | Self::RemovePrivateService => PlanV2Group::PrivateService,
            Self::PublishLinkRoute | Self::RetireLinkRoute => PlanV2Group::LinkRoute,
            Self::SnapshotService | Self::DiscardSnapshot => PlanV2Group::Snapshot,
            Self::RestoreService => PlanV2Group::Restore,
            Self::DeployUserService | Self::RemoveUserService => PlanV2Group::UserService,
        }
    }
}

/// One registry-qualified reference and the digest that is the executable
/// identity behind it. The two always travel together so that no declaration can
/// pin a digest for one repository and a reference for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinnedImage {
    reference: &'static str,
    digest: &'static str,
}

/// The single pin of the entrypoint.
const ENTRYPOINT_IMAGE: PinnedImage = PinnedImage {
    reference: ENTRYPOINT_IMAGE_REFERENCE,
    digest: ENTRYPOINT_IMAGE_DIGEST,
};

/// The closed list of service profiles of the stateless door, and the one image
/// each of them may name.
///
/// A profile this function does not hold is refused before its image is
/// compared, so an unknown profile can never borrow the pin of a known one.
///
/// It is one of two lookups rather than one lookup and a flag because the
/// refusal has to run in both directions: a data-bearing service does not pass
/// through the stateless door, and a stateless service does not pass through the
/// private one. A single list would make each of those a comparison someone has
/// to remember to write; two lists make them the same lookup that already
/// refuses an unknown name.
fn profile_image(service_profile: &str) -> Option<PinnedImage> {
    match service_profile {
        SERVICE_PROFILE_BENTOPDF => Some(PinnedImage {
            reference: BENTOPDF_IMAGE_REFERENCE,
            digest: BENTOPDF_IMAGE_DIGEST,
        }),
        _ => None,
    }
}

/// The closed list of service profiles of the private door, under the same rule.
fn private_profile_image(service_profile: &str) -> Option<PinnedImage> {
    match service_profile {
        SERVICE_PROFILE_VAULTWARDEN => Some(PinnedImage {
            reference: VAULTWARDEN_IMAGE_REFERENCE,
            digest: VAULTWARDEN_IMAGE_DIGEST,
        }),
        _ => None,
    }
}

/// Whether a name is one an archive operation may be filed under: a profile of
/// the private door's own closed list, or the slug of a user service definition.
///
/// The two readings share one field and stay unambiguous, because the four names
/// the product owns are exactly the four a definition may not take. A name is
/// therefore found in the closed list or it is a slug — never both, and never a
/// comparison someone has to remember to write.
///
/// A stateless profile is refused here and not merely unsupported: it is a
/// reserved name the closed list does not hold, so it is neither a data-bearing
/// profile nor a possible slug. It owns no persistent volume, an archive of it
/// would be an archive of nothing, and a plan that could ask for one would be a
/// plan whose report could never be honest.
///
/// What a slug is admitted as here is exactly a well-formed name, and nothing
/// more. This side reads no definition and no machine, so whether a service by
/// that name was ever deployed, and whether its definition declares a volume at
/// all, are facts the Auxiliary reads on the machine before any effect.
fn archives_data(service_profile: &str) -> bool {
    private_profile_image(service_profile).is_some() || canonical_definition_slug(service_profile)
}

/// The plan of one managed web service: one profile, the image that profile
/// pins, and one loopback port on one machine.
///
/// The declaration order below is the canonical encoding order and the
/// transcript order at once, and no field of a web service plan lives outside
/// it. There is deliberately no volume, no network, no container privilege, no
/// command and no variable: a document carrying one is an unknown field the
/// decoding refuses before reading its value.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebServicePlanDocumentV2 {
    pub schema_version: u8,
    /// The infrastructure this plan belongs to, as a canonical UUIDv4.
    pub infrastructure_id: String,
    /// The one machine this plan describes a state of.
    pub machine_id: String,
    pub operation: PlanV2Operation,
    /// The closed profile that decides everything this document does not state.
    pub service_profile: String,
    /// Registry and repository, without a tag.
    pub image_reference: String,
    /// `sha256:` followed by sixty-four lower-case hexadecimal characters.
    pub image_digest: String,
    /// The port the service listens on, on [`SERVICE_LOCAL_ADDRESS`] alone.
    pub local_port: u32,
}

/// The plan of the public entrypoint: its existence and its image, and
/// deliberately nothing else.
///
/// It carries neither port nor host. The public ports, the listening addresses
/// and the file provider directory are constants of the contract, so a field for
/// any of them would be an approvable value that decides nothing.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntrypointPlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    pub image_reference: String,
    pub image_digest: String,
}

/// The plan of one published name: the host the entrypoint serves and the
/// loopback port of the managed service behind it.
///
/// It carries no image. A route publishes a service that another plan deployed;
/// naming an image here would let a route describe a deployment nobody approved
/// as one.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    pub route_host: String,
    pub backend_port: u32,
}

/// The plan of one managed service whose data outlives its container: one
/// profile, the image that profile pins, one loopback port on one machine, and
/// the one origin the instance will answer under.
///
/// The origin is a field because it binds the service to the route that will
/// publish it: the instance only works correctly under that name, and the name is
/// therefore under the eyes of the human who approves the deployment. It is not a
/// route: publishing is a separate, optional plan, and a private service deployed
/// without one lives on its own machine's loopback for as long as its owner
/// wants.
///
/// The volume, the environment lines and the egress table have no field here and
/// none anywhere else. They are the profile's, exactly as the account and the
/// sheet are, and the rule of the stateless sheets is unchanged: no plan of this
/// product describes a path a machine will write to.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateServicePlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    /// The closed profile of the private door, which decides everything this
    /// document does not state.
    pub service_profile: String,
    pub image_reference: String,
    pub image_digest: String,
    /// The port the service listens on, on [`SERVICE_LOCAL_ADDRESS`] alone.
    pub local_port: u32,
    /// The exact origin the instance answers under, bounded as a route host is.
    pub origin_host: String,
}

/// The plan of one published name served through the private passage: the host
/// the entrypoint serves and the port the tunnel carries.
///
/// It carries the same two fields as a route of the public profile and describes
/// another state, which is why it is another shape rather than a flag on that
/// one. Its backend is the constant peer of the tunnel and never an address a
/// plan names, so there is no field for one; and the port it names is required,
/// on the machine that will act, to be the port an approved junction already
/// bounds.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRoutePlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    pub route_host: String,
    pub backend_port: u32,
}

/// The plan of one archive of one private service's data: which profile, and the
/// one named slot the archive is written to or destroyed from.
///
/// It carries no path and no digest. The directory belongs to the profile, the
/// file name is the slot, and the digest of the archive is a fact the report
/// carries afterwards rather than a value a human could approve in advance.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    pub service_profile: String,
    /// The one label this archive is named by, which is never the reserved slot.
    pub snapshot_slot: String,
}

/// The plan of one return: which profile, and the one named slot whose archive
/// becomes the service's data.
///
/// It carries exactly the fields a snapshot carries and it is a separate shape,
/// because what differs between the two is not a field but an undoing. A
/// snapshot is undone by destroying the archive it wrote; a restore is undone by
/// another restore, naming the reserved slot the flow has just written the
/// replaced state into. Two shapes is how that difference is stated once instead
/// of being decided by a branch every time an inverse is needed.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    pub service_profile: String,
    /// The one label whose archive becomes the data. It is the one field of the
    /// schema that may hold the reserved slot, because the signed rollback of a
    /// restore is a restore naming it.
    pub snapshot_slot: String,
}

/// The plan of one service the product does not know: the definition it runs,
/// the revision of that definition, the image of this instance, one loopback
/// port on one machine, and the origin the instance answers under when — and
/// only when — its definition consumes one.
///
/// It names a definition where the two other service shapes name a profile. A
/// profile decides everything its plan does not state and is a constant of the
/// product; a definition decides the same things and is a document its user
/// wrote, frozen by the Controller and pinned here by `definition_digest`. The
/// two are the same idea under two authorities, which is why this is a third
/// shape rather than a profile whose name happens to be free-form: the fields
/// differ, so the closed field lists differ.
///
/// `image_reference` is here and decides nothing. It must be exactly the
/// repository of the pinned definition — the human approves an origin and an
/// executable identity under their eyes — and `image_digest` is the identity of
/// this instance, which is the one thing about a user service that a revision
/// does not fix: an update is a new plan whose digest differs, never a silent
/// mutation.
///
/// `origin_host` is present exactly when the pinned definition interpolates it,
/// and this side accepts both of its forms because it holds no definition to
/// decide between them. That is not a weaker rule than the contract's, it is the
/// same rule read where it can be read: the agreement between a plan and the
/// definition it pins is held by the Controller that built the pair and again by
/// the Auxiliary that receives the definition beside it.
///
/// The volumes, the tmpfs, the environment lines, the secret names, the account
/// and the home have no field here and none anywhere else. They are the
/// definition's, and everything touching the machine is derived from its slug by
/// the Auxiliary: the rule of the delivered profiles, unchanged, over a document
/// whose author is the user rather than the product.
///
/// The declaration order below is the canonical encoding order and the
/// transcript order at once, and no field of a user service plan lives outside
/// it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserServicePlanDocumentV2 {
    pub schema_version: u8,
    pub infrastructure_id: String,
    pub machine_id: String,
    pub operation: PlanV2Operation,
    /// The name of the definition this instance runs, under the definition
    /// module's own grammar, reserved names refused.
    pub definition_slug: String,
    /// The revision pinned: sixty-four lower-case hexadecimal characters, bare.
    pub definition_digest: String,
    /// The repository the pinned definition names, without a tag.
    pub image_reference: String,
    /// `sha256:` followed by sixty-four lower-case hexadecimal characters.
    pub image_digest: String,
    /// The port the service listens on, on [`SERVICE_LOCAL_ADDRESS`] alone.
    pub local_port: u32,
    /// The exact origin the instance answers under, bounded as a route host is,
    /// and empty when the pinned definition consumes none.
    ///
    /// A document that leaves the field out altogether is the same plan under
    /// the same digest — an absent origin and an empty one are one value, and
    /// the transcript writes a length of zero for both. It is the same latitude
    /// the definition's own empty lists have, and it stops exactly there: the
    /// Controller emits one spelling, the one that renders the field.
    #[serde(default)]
    pub origin_host: String,
}

/// One plan of schema 2, whatever its operation group.
///
/// The list is closed to the eight shapes above: a ninth field list is a
/// decision taken here — beside the transcript it would need and beside the
/// inverse it must have — rather than a shape a caller could hand in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanDocumentV2 {
    WebService(WebServicePlanDocumentV2),
    Entrypoint(EntrypointPlanDocumentV2),
    Route(RoutePlanDocumentV2),
    PrivateService(PrivateServicePlanDocumentV2),
    LinkRoute(LinkRoutePlanDocumentV2),
    Snapshot(SnapshotPlanDocumentV2),
    Restore(RestorePlanDocumentV2),
    UserService(UserServicePlanDocumentV2),
}

impl WebServicePlanDocumentV2 {
    /// Holds a web service plan against the whole contract of the palier.
    ///
    /// The image is checked for equality against the pin of the declared profile
    /// rather than against a policy: a plan naming another registry, another
    /// repository or another digest is not a narrower or a wider plan, it is one
    /// this palier neither builds nor recognises.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::WebService,
        ) {
            return Err(ProtocolError::InvalidInput);
        }
        let Some(image) = profile_image(&self.service_profile) else {
            return Err(ProtocolError::InvalidInput);
        };
        if !pinned_image_matches(&self.image_reference, &self.image_digest, image)
            || !(MIN_PLAN_LOCAL_PORT..=MAX_PLAN_LOCAL_PORT).contains(&self.local_port)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a web service plan digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let image = decode_image_digest(&self.image_digest).ok_or(ProtocolError::InvalidInput)?;
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.service_profile.as_bytes())?;
        append_field(&mut transcript, self.image_reference.as_bytes())?;
        append_field(&mut transcript, &image)?;
        transcript.extend_from_slice(&self.local_port.to_be_bytes());
        Ok(transcript)
    }

    /// The document that undoes this one, which differs from it by its operation
    /// and by nothing else.
    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    ///
    /// The two documents are compared whole, so a rollback naming another
    /// machine, another port, another profile or another image is a second plan
    /// rather than an undoing, and is refused as one. Comparing the whole
    /// document rather than a list of fields is what keeps a field added later
    /// from silently falling outside the comparison.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl EntrypointPlanDocumentV2 {
    /// Holds an entrypoint plan against the whole contract of the palier.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::Entrypoint,
        ) || !pinned_image_matches(&self.image_reference, &self.image_digest, ENTRYPOINT_IMAGE)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes an entrypoint plan digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let image = decode_image_digest(&self.image_digest).ok_or(ProtocolError::InvalidInput)?;
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.image_reference.as_bytes())?;
        append_field(&mut transcript, &image)?;
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl RoutePlanDocumentV2 {
    /// Holds a route plan against the whole contract of the palier.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::Route,
        ) || !canonical_route_host(&self.route_host)
            || !(MIN_PLAN_BACKEND_PORT..=MAX_PLAN_BACKEND_PORT).contains(&self.backend_port)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a route plan digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.route_host.as_bytes())?;
        transcript.extend_from_slice(&self.backend_port.to_be_bytes());
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl PrivateServicePlanDocumentV2 {
    /// Holds a private service plan against the whole contract of the palier.
    ///
    /// The profile is looked up in the private door's own list, so the stateless
    /// profile of the previous palier is refused here exactly as an invented name
    /// would be: a service without persistent data has nothing to do behind a
    /// door whose sheet declares a volume, and the refusal happens before the
    /// image is even compared.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::PrivateService,
        ) {
            return Err(ProtocolError::InvalidInput);
        }
        let Some(image) = private_profile_image(&self.service_profile) else {
            return Err(ProtocolError::InvalidInput);
        };
        if !pinned_image_matches(&self.image_reference, &self.image_digest, image)
            || !(MIN_PLAN_LOCAL_PORT..=MAX_PLAN_LOCAL_PORT).contains(&self.local_port)
            || !canonical_route_host(&self.origin_host)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a private service plan digest is taken over.
    ///
    /// The origin follows the port rather than the profile: the layout is the
    /// stateless one with exactly one field appended, so a reader holds the two
    /// side by side and sees what the private door adds.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let image = decode_image_digest(&self.image_digest).ok_or(ProtocolError::InvalidInput)?;
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.service_profile.as_bytes())?;
        append_field(&mut transcript, self.image_reference.as_bytes())?;
        append_field(&mut transcript, &image)?;
        transcript.extend_from_slice(&self.local_port.to_be_bytes());
        append_field(&mut transcript, self.origin_host.as_bytes())?;
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl LinkRoutePlanDocumentV2 {
    /// Holds a link route plan against the whole contract of the palier.
    ///
    /// It is the route contract read again over the other operation: the bound of
    /// a name and the bound of a port do not change because the traffic behind
    /// them takes the passage.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::LinkRoute,
        ) || !canonical_route_host(&self.route_host)
            || !(MIN_PLAN_BACKEND_PORT..=MAX_PLAN_BACKEND_PORT).contains(&self.backend_port)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a link route plan digest is taken over.
    ///
    /// The tail is byte for byte the tail of a route of the public profile, and
    /// the two digests differ anyway, because the operation is inside the hashed
    /// bytes ahead of it. That is the whole reason the operation travels in the
    /// transcript at all.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.route_host.as_bytes())?;
        transcript.extend_from_slice(&self.backend_port.to_be_bytes());
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl SnapshotPlanDocumentV2 {
    /// Holds a snapshot plan against the whole contract of the palier.
    ///
    /// The reserved slot is refused here rather than only where documents are
    /// built, because a document is what a machine acts on: a snapshot writing
    /// over the return mechanism's slot, or a discard destroying it, would be a
    /// plan that removes the possibility of returning — and it must be refused
    /// whoever wrote the bytes.
    ///
    /// `service_profile` is the one field two doors share: it holds a profile of
    /// the private door or the slug of a user service definition, and
    /// [`archives_data`] is where the two readings stay one unambiguous lookup.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::Snapshot,
        ) || !archives_data(&self.service_profile)
            || !canonical_snapshot_slot(&self.snapshot_slot)
            || self.snapshot_slot == RESERVED_SNAPSHOT_SLOT
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a snapshot plan digest is taken over.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.service_profile.as_bytes())?;
        append_field(&mut transcript, self.snapshot_slot.as_bytes())?;
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl RestorePlanDocumentV2 {
    /// Holds a restore plan against the whole contract of the palier.
    ///
    /// It is the one place the reserved slot is accepted, and it has to be: the
    /// signed rollback of a restore is a restore naming that slot, and a rollback
    /// is a plan in its own right — displayed, hashed, transported and decoded
    /// like any other. What keeps a human from having one presented as a forward
    /// direction is that the Controller alone writes that document, and that a
    /// pair whose two documents are one is refused before anything is displayed.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::Restore,
        ) || !archives_data(&self.service_profile)
            || !canonical_snapshot_slot(&self.snapshot_slot)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a restore plan digest is taken over. It is the snapshot
    /// tail again, under the other operation.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.service_profile.as_bytes())?;
        append_field(&mut transcript, self.snapshot_slot.as_bytes())?;
        Ok(transcript)
    }

    /// The one undoing of this schema that moves a field instead of the
    /// operation.
    ///
    /// The document that returns from a restore is a restore of the reserved
    /// slot, because the flow writes the state it is about to replace there
    /// before replacing anything. That is why the reserved slot has to be a value
    /// this module accepts in a restore document and refuses everywhere else: it
    /// is not a slot a human names, it is the slot the mechanism owns.
    ///
    /// A restore already naming the reserved slot is its own undoing, which is
    /// honest — running it twice returns the machine where it started — and it is
    /// also why a pair whose two documents are one document is refused before
    /// being displayed.
    fn inverted(&self) -> Self {
        Self {
            snapshot_slot: RESERVED_SNAPSHOT_SLOT.to_owned(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl UserServicePlanDocumentV2 {
    /// Holds a user service plan against everything one document can be held
    /// against on its own.
    ///
    /// Three of its fields name a definition this module cannot read: the slug,
    /// the revision and the repository. What is required here is therefore their
    /// shape — the slug grammar the definition module owns, reserved names
    /// included, so a plan can never name a definition that could not exist; the
    /// one spelling of a revision's digest, read by the very reader an approval
    /// envelope reads its own digests with; and the repository rule, which is
    /// where the tag is refused on this side too.
    ///
    /// The shape of the image digest is required as it is everywhere else, so
    /// that the transcript may rely on decoding exactly thirty-two bytes out of
    /// the field. There is no pin to compare it to: which image runs is what a
    /// plan of this door says, and the definition only says where images come
    /// from.
    ///
    /// The origin is accepted in both of its forms and refused in neither.
    /// Presence is required exactly when the definition interpolates, and a
    /// document alone knows nothing of the definition; a pair reaching this side
    /// has been through the agreement check at the Controller that built it, and
    /// goes through it again at the Auxiliary that receives the definition beside
    /// it.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        if !valid_v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
            PlanV2Group::UserService,
        ) || !canonical_definition_slug(&self.definition_slug)
            || decode_digest(&self.definition_digest).is_none()
            || !canonical_image_repository(&self.image_reference)
            || decode_image_digest(&self.image_digest).is_none()
            || !(MIN_PLAN_LOCAL_PORT..=MAX_PLAN_LOCAL_PORT).contains(&self.local_port)
            || !canonical_user_service_origin(&self.origin_host)
        {
            return Err(ProtocolError::InvalidInput);
        }
        Ok(self)
    }

    /// The exact bytes a user service plan digest is taken over.
    ///
    /// The tail is the private door's with the profile replaced by the two fields
    /// that name a definition, so a reader holds the two side by side and sees
    /// what the third door changes: a plan of this door pins a document instead
    /// of naming a constant. The origin closes the tail as it does there, and it
    /// is written even when it is absent — a length of zero — so that the end of
    /// the transcript never depends on a rule the bytes do not carry.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        let definition =
            decode_digest(&self.definition_digest).ok_or(ProtocolError::InvalidInput)?;
        let image = decode_image_digest(&self.image_digest).ok_or(ProtocolError::InvalidInput)?;
        let mut transcript = v2_head(
            self.schema_version,
            &self.infrastructure_id,
            &self.machine_id,
            self.operation,
        )?;
        append_field(&mut transcript, self.definition_slug.as_bytes())?;
        append_field(&mut transcript, &definition)?;
        append_field(&mut transcript, self.image_reference.as_bytes())?;
        append_field(&mut transcript, &image)?;
        transcript.extend_from_slice(&self.local_port.to_be_bytes());
        append_field(&mut transcript, self.origin_host.as_bytes())?;
        Ok(transcript)
    }

    fn inverted(&self) -> Self {
        Self {
            operation: self.operation.inverse(),
            ..self.clone()
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    ///
    /// The two documents are compared whole, origin included and origin absent
    /// alike: a removal names the same instance as the deployment it undoes, or
    /// it is a second plan rather than an undoing.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        self.inverted() == *rollback
    }
}

impl PlanDocumentV2 {
    /// Holds the document against the whole contract of the palier, profile and
    /// pinned image included.
    pub fn validate(self) -> Result<Self, ProtocolError> {
        Ok(match self {
            Self::WebService(document) => Self::WebService(document.validate()?),
            Self::Entrypoint(document) => Self::Entrypoint(document.validate()?),
            Self::Route(document) => Self::Route(document.validate()?),
            Self::PrivateService(document) => Self::PrivateService(document.validate()?),
            Self::LinkRoute(document) => Self::LinkRoute(document.validate()?),
            Self::Snapshot(document) => Self::Snapshot(document.validate()?),
            Self::Restore(document) => Self::Restore(document.validate()?),
            Self::UserService(document) => Self::UserService(document.validate()?),
        })
    }

    /// The exact bytes this plan's digest is taken over.
    ///
    /// It is built from the parsed fields and never from a received document, so
    /// two implementations that read the same plan produce the same digest, a
    /// transport that reshapes the JSON transports the same plan, and a
    /// transport that changes one value transports a plan whose digest no longer
    /// matches the approval that named it.
    pub fn transcript(&self) -> Result<Vec<u8>, ProtocolError> {
        match self {
            Self::WebService(document) => document.transcript(),
            Self::Entrypoint(document) => document.transcript(),
            Self::Route(document) => document.transcript(),
            Self::PrivateService(document) => document.transcript(),
            Self::LinkRoute(document) => document.transcript(),
            Self::Snapshot(document) => document.transcript(),
            Self::Restore(document) => document.transcript(),
            Self::UserService(document) => document.transcript(),
        }
    }

    /// The raw digest of that transcript.
    pub fn digest(&self) -> Result<[u8; PLAN_DIGEST_BYTES], ProtocolError> {
        let mut digest = [0_u8; PLAN_DIGEST_BYTES];
        digest.copy_from_slice(Sha256::digest(self.transcript()?).as_slice());
        Ok(digest)
    }

    /// The lower-case hexadecimal value an envelope names as `plan_sha256` or
    /// `rollback_sha256`, in the exact spelling that envelope requires.
    pub fn sha256(&self) -> Result<String, ProtocolError> {
        Ok(encode_lower_hex(&self.digest()?))
    }

    pub fn operation(&self) -> PlanV2Operation {
        match self {
            Self::WebService(document) => document.operation,
            Self::Entrypoint(document) => document.operation,
            Self::Route(document) => document.operation,
            Self::PrivateService(document) => document.operation,
            Self::LinkRoute(document) => document.operation,
            Self::Snapshot(document) => document.operation,
            Self::Restore(document) => document.operation,
            Self::UserService(document) => document.operation,
        }
    }

    pub fn group(&self) -> PlanV2Group {
        self.operation().group()
    }

    pub fn infrastructure_id(&self) -> &str {
        match self {
            Self::WebService(document) => &document.infrastructure_id,
            Self::Entrypoint(document) => &document.infrastructure_id,
            Self::Route(document) => &document.infrastructure_id,
            Self::PrivateService(document) => &document.infrastructure_id,
            Self::LinkRoute(document) => &document.infrastructure_id,
            Self::Snapshot(document) => &document.infrastructure_id,
            Self::Restore(document) => &document.infrastructure_id,
            Self::UserService(document) => &document.infrastructure_id,
        }
    }

    pub fn machine_id(&self) -> &str {
        match self {
            Self::WebService(document) => &document.machine_id,
            Self::Entrypoint(document) => &document.machine_id,
            Self::Route(document) => &document.machine_id,
            Self::PrivateService(document) => &document.machine_id,
            Self::LinkRoute(document) => &document.machine_id,
            Self::Snapshot(document) => &document.machine_id,
            Self::Restore(document) => &document.machine_id,
            Self::UserService(document) => &document.machine_id,
        }
    }

    /// Whether `rollback` is the complete document that undoes this plan.
    ///
    /// A document of another operation group is never an undoing, whatever it
    /// names: the two are not the same plan written differently. A route and a
    /// link route carrying the same host and port fall under that rule, and so do
    /// a snapshot and a restore carrying the same profile and slot.
    pub fn is_undone_by(&self, rollback: &Self) -> bool {
        match (self, rollback) {
            (Self::WebService(plan), Self::WebService(inverse)) => plan.is_undone_by(inverse),
            (Self::Entrypoint(plan), Self::Entrypoint(inverse)) => plan.is_undone_by(inverse),
            (Self::Route(plan), Self::Route(inverse)) => plan.is_undone_by(inverse),
            (Self::PrivateService(plan), Self::PrivateService(inverse)) => {
                plan.is_undone_by(inverse)
            }
            (Self::LinkRoute(plan), Self::LinkRoute(inverse)) => plan.is_undone_by(inverse),
            (Self::Snapshot(plan), Self::Snapshot(inverse)) => plan.is_undone_by(inverse),
            (Self::Restore(plan), Self::Restore(inverse)) => plan.is_undone_by(inverse),
            (Self::UserService(plan), Self::UserService(inverse)) => plan.is_undone_by(inverse),
            _ => false,
        }
    }
}

/// Accepts one bounded, strict, fully validated schema 2 document.
///
/// It never returns a partially checked plan: a caller that holds one may assume
/// every field is inside the bounds of the contract, and that the fields it
/// holds are exactly the ones its operation declares — no more, and none
/// borrowed from another operation.
///
/// The bound is applied before parsing, exactly one JSON value is accepted, a
/// repeated key is a refusal, an undeclared field is a refusal, and every field
/// must appear under its exact canonical name.
pub fn decode_plan_v2_document(document: &[u8]) -> Result<PlanDocumentV2, ProtocolError> {
    if document.is_empty() || document.len() > MAX_PLAN_DOCUMENT_BYTES {
        return Err(ProtocolError::InvalidInput);
    }
    let parsed = match declared_operation(document)?.group() {
        PlanV2Group::WebService => PlanDocumentV2::WebService(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::Entrypoint => PlanDocumentV2::Entrypoint(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::Route => PlanDocumentV2::Route(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::PrivateService => PlanDocumentV2::PrivateService(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::LinkRoute => PlanDocumentV2::LinkRoute(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::Snapshot => PlanDocumentV2::Snapshot(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::Restore => PlanDocumentV2::Restore(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
        PlanV2Group::UserService => PlanDocumentV2::UserService(
            serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?,
        ),
    };
    parsed.validate()
}

/// Accepts one received document only if it is the plan its digest names.
///
/// This is the whole reason the documents travel as their exact canonical bytes
/// beside their digests: the digest is rebuilt here from the fields that were
/// parsed out of those very bytes, so the Controller can reindent what it
/// carries and can change nothing in it. A mismatch is refused before the
/// document reaches anything that would display it, because a plan nobody can
/// hold to a digest is a plan nobody can be shown.
pub fn verify_plan_v2_document(
    document: &[u8],
    expected_sha256: &str,
) -> Result<PlanDocumentV2, ProtocolError> {
    let expected = decode_digest(expected_sha256).ok_or(ProtocolError::InvalidInput)?;
    let parsed = decode_plan_v2_document(document)?;
    if parsed.digest()? != expected {
        return Err(ProtocolError::InvalidInput);
    }
    Ok(parsed)
}

/// The one field the first pass reads.
///
/// It deliberately does not deny unknown fields: this pass selects a schema and
/// decides nothing, and the strict decoding that follows is what refuses every
/// field the selected schema does not declare. A repeated `operation` is still a
/// refusal here, because two declarations of the shape a document claims are two
/// documents rather than one.
#[derive(Deserialize)]
struct DeclaredOperation {
    operation: PlanV2Operation,
}

/// Reads only the operation, and decides which closed schema the document will
/// be held against from it alone.
///
/// It is the same principle as the discriminator of the Auxiliary's input: the
/// shape is read in the document rather than guessed by trying each schema in
/// turn. That is what keeps the three field lists from covering for one another.
fn declared_operation(document: &[u8]) -> Result<PlanV2Operation, ProtocolError> {
    let declared: DeclaredOperation =
        serde_json::from_slice(document).map_err(|_| ProtocolError::InvalidInput)?;
    Ok(declared.operation)
}

/// The four fields every schema 2 document carries.
///
/// The last check is what makes the discriminator binding in both directions: a
/// document whose operation belongs to another group is refused even when a
/// caller built the value in Rust rather than decoding it.
fn valid_v2_head(
    schema_version: u8,
    infrastructure_id: &str,
    machine_id: &str,
    operation: PlanV2Operation,
    group: PlanV2Group,
) -> bool {
    schema_version == PLAN_V2_SCHEMA_VERSION
        && canonical_uuid_v4(infrastructure_id)
        && canonical_machine_id(machine_id)
        && operation.group() == group
}

/// The head of every schema 2 transcript, in the layout documented at the top of
/// this file.
fn v2_head(
    schema_version: u8,
    infrastructure_id: &str,
    machine_id: &str,
    operation: PlanV2Operation,
) -> Result<Vec<u8>, ProtocolError> {
    let mut transcript = Vec::with_capacity(PLAN_V2_TRANSCRIPT_DOMAIN.len() + 192);
    transcript.extend_from_slice(PLAN_V2_TRANSCRIPT_DOMAIN);
    transcript.extend_from_slice(&schema_version.to_be_bytes());
    append_field(&mut transcript, infrastructure_id.as_bytes())?;
    append_field(&mut transcript, machine_id.as_bytes())?;
    append_field(&mut transcript, operation.as_str().as_bytes())?;
    Ok(transcript)
}

/// Requires the exact couple the contract pins.
///
/// The shape of the digest is required before the pin so that the transcript may
/// rely on decoding exactly thirty-two bytes out of the field, and so that a
/// malformed digest and an unpinned one stay two distinct refusals.
fn pinned_image_matches(reference: &str, digest: &str, pinned: PinnedImage) -> bool {
    reference == pinned.reference
        && decode_image_digest(digest).is_some()
        && digest == pinned.digest
}

/// Bounds the one name a route serves: lower-case letters, digits, hyphens and
/// dots, three to two hundred fifty-three characters, opening and closing on a
/// letter or a digit, and no empty label.
///
/// The closed character set is what removes the wildcard, the upper-case
/// spelling and every separator a host name has no business carrying; the checks
/// around it remove the empty label and the name that opens or closes on a
/// separator. Consecutive hyphens stay accepted because a punycode label carries
/// them. A host outside these bounds never reaches a fragment of the entrypoint,
/// so the entrypoint never has to decide what such a name means.
fn canonical_route_host(host: &str) -> bool {
    let bytes = host.as_bytes();
    if bytes.len() < MIN_ROUTE_HOST_BYTES || bytes.len() > MAX_ROUTE_HOST_BYTES || !host.is_ascii()
    {
        return false;
    }
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) || host.contains("..") {
        return false;
    }
    bytes
        .iter()
        .all(|byte| alphanumeric(*byte) || *byte == b'-' || *byte == b'.')
}

/// Bounds the one label an archive is named by: lower-case letters, digits and
/// hyphens, one to thirty-two characters, opening on a letter or a digit.
///
/// The closed character set is what removes the separator, the dot, the
/// upper-case spelling and everything else a file name inside a directory the
/// profile owns has no business carrying: a slot cannot climb, cannot hide and
/// cannot be two spellings of the same archive. Whether the reserved slot is one
/// a given document may name is decided by that document's own group, not here.
/// The two forms the origin of a user service plan is accepted in, and no third.
///
/// A well-formed host is the origin the instance answers under; the empty string
/// is the absence of one, spelled the way the transcript spells it. No origin the
/// contract accepts is empty, so the two are never two readings of one value —
/// and which of the two a given plan must carry is decided by the definition it
/// pins, which this side does not hold.
fn canonical_user_service_origin(origin: &str) -> bool {
    origin.is_empty() || canonical_route_host(origin)
}

fn canonical_snapshot_slot(slot: &str) -> bool {
    let bytes = slot.as_bytes();
    if bytes.len() < MIN_SNAPSHOT_SLOT_BYTES || bytes.len() > MAX_SNAPSHOT_SLOT_BYTES {
        return false;
    }
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if !alphanumeric(bytes[0]) {
        return false;
    }
    bytes
        .iter()
        .all(|byte| alphanumeric(*byte) || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_definition::MAX_SERVICE_SLUG_CHARS;

    const INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2";
    const OTHER_INFRASTRUCTURE: &str = "8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c3";
    const MACHINE: &str = "lab-machine-1";
    const PORT: u32 = 8_080;
    const ROUTE_HOST: &str = "bentopdf.lab.your-cloud.test";

    /// The inputs of the private profile's vectors. The origin and the published
    /// name are the same string on purpose: that is what the contract describes —
    /// the service answers under the exact name the route serves — and a vector
    /// that used two names would prove the encoding without proving the shape of
    /// the scenario it encodes.
    const ORIGIN_HOST: &str = "vault.lab.your-cloud.test";
    const LINK_ROUTE_HOST: &str = "vault.lab.your-cloud.test";
    const SNAPSHOT_SLOT: &str = "nightly";

    /// The six canonical documents of the shared vectors, byte for byte. They
    /// are the bytes `internal/plan/schema2_test.go` pins as the ones the
    /// Controller emits, copied literally rather than rebuilt here.
    const WEB_SERVICE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_web_service","#,
        r#""service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf","#,
        r#""image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0","#,
        r#""local_port":8080}"#,
    );
    const WEB_SERVICE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_web_service","#,
        r#""service_profile":"bentopdf","image_reference":"ghcr.io/alam00000/bentopdf","#,
        r#""image_digest":"sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0","#,
        r#""local_port":8080}"#,
    );
    const ENTRYPOINT_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_entrypoint","#,
        r#""image_reference":"docker.io/library/traefik","#,
        r#""image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}"#,
    );
    const ENTRYPOINT_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_entrypoint","#,
        r#""image_reference":"docker.io/library/traefik","#,
        r#""image_digest":"sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac"}"#,
    );
    const ROUTE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"publish_route","#,
        r#""route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}"#,
    );
    const ROUTE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"retire_route","#,
        r#""route_host":"bentopdf.lab.your-cloud.test","backend_port":8080}"#,
    );

    /// The eight canonical documents of the private profile's vectors, byte for
    /// byte, under the same rule.
    ///
    /// The rollback of the restore is the one document of the product that names
    /// the reserved slot. It is pinned here for exactly that reason: it is built,
    /// signed, transported and decoded like any other plan, and this side has to
    /// read those bytes rather than a shape of its own.
    const PRIVATE_SERVICE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_private_service","#,
        r#""service_profile":"vaultwarden","image_reference":"docker.io/vaultwarden/server","#,
        r#""image_digest":"sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8","#,
        r#""local_port":8080,"origin_host":"vault.lab.your-cloud.test"}"#,
    );
    const PRIVATE_SERVICE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_private_service","#,
        r#""service_profile":"vaultwarden","image_reference":"docker.io/vaultwarden/server","#,
        r#""image_digest":"sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8","#,
        r#""local_port":8080,"origin_host":"vault.lab.your-cloud.test"}"#,
    );
    const LINK_ROUTE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"publish_link_route","#,
        r#""route_host":"vault.lab.your-cloud.test","backend_port":8080}"#,
    );
    const LINK_ROUTE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"retire_link_route","#,
        r#""route_host":"vault.lab.your-cloud.test","backend_port":8080}"#,
    );
    const SNAPSHOT_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"snapshot_service","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"nightly"}"#,
    );
    const SNAPSHOT_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"discard_snapshot","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"nightly"}"#,
    );
    const RESTORE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"restore_service","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"nightly"}"#,
    );
    const RESTORE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"restore_service","#,
        r#""service_profile":"vaultwarden","snapshot_slot":"previous"}"#,
    );

    /// The inputs of the third door's two vectors.
    ///
    /// They pin the two definitions the definition module pins as its own
    /// vectors — the reference one, which interpolates the origin, and the
    /// minimal one, which declares no environment at all — so that the slug, the
    /// repository and the digest of a plan are held against the very document
    /// that module froze rather than against a second invention. A drift in
    /// either fails on both sides rather than on neither.
    ///
    /// The two image digests are synthetic and deliberately look it: the third
    /// door pins no image, so there is no real digest to name here, and
    /// thirty-two bytes counting from one and from thirty-three are values a
    /// reader recognises as the test's own rather than mistaking for an identity
    /// of the product.
    const USER_SERVICE_SLUG: &str = "lab-notes";
    const USER_SERVICE_DEFINITION_DIGEST: &str =
        "c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce";
    const USER_SERVICE_IMAGE_REFERENCE: &str = "registry.lab.your-cloud.test/your-cloud/lab-notes";
    const USER_SERVICE_IMAGE_DIGEST: &str =
        "sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const USER_SERVICE_ORIGIN_HOST: &str = "notes.lab.your-cloud.test";
    const MINIMAL_SLUG: &str = "minimal";
    const MINIMAL_DEFINITION_DIGEST: &str =
        "faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c";
    const MINIMAL_IMAGE_REFERENCE: &str = "registry.lab.your-cloud.test/minimal";
    const MINIMAL_IMAGE_DIGEST: &str =
        "sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
    const MINIMAL_USER_PORT: u32 = 8_081;

    /// The two definitions the third door's vectors pin, as the exact canonical
    /// bytes the definition module froze them as.
    ///
    /// They are spelled here rather than built as values, because what the two
    /// contracts must agree on is bytes: a definition this test parses out of
    /// these strings is the definition whose digest the plans below pin, or the
    /// cross-check fails.
    const REFERENCE_DEFINITION_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"slug":"lab-notes","#,
        r#""image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
        r#""container_port":8080,"volumes":["/srv/notes","/var/lib/lab-notes"],"#,
        r#""tmpfs":["/tmp"],"environment":["LAB_NOTES_TITLE=Your Cloud lab notes","#,
        r#""LAB_NOTES_ORIGIN=https://{origin_host}/","LAB_NOTES_READ_ONLY=1"],"#,
        r#""secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}"#,
    );
    const MINIMAL_DEFINITION_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"slug":"minimal","#,
        r#""image_repository":"registry.lab.your-cloud.test/minimal","container_port":80,"#,
        r#""volumes":[],"tmpfs":[],"environment":[],"secret_keys":[]}"#,
    );

    /// The four canonical documents of the third door's vectors, byte for byte,
    /// under the same rule as every group before them.
    ///
    /// The minimal pair renders `"origin_host":""` rather than omitting the
    /// field. That is the canonical spelling of a plan whose definition does not
    /// consume an origin, and it is pinned here for exactly that reason: a
    /// document that left the field out and this one are the same plan with the
    /// same digest, and this is the one spelling they both freeze to.
    const USER_SERVICE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_user_service","#,
        r#""definition_slug":"lab-notes","#,
        r#""definition_digest":"c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce","#,
        r#""image_reference":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
        r#""image_digest":"sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","#,
        r#""local_port":8080,"origin_host":"notes.lab.your-cloud.test"}"#,
    );
    const USER_SERVICE_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_user_service","#,
        r#""definition_slug":"lab-notes","#,
        r#""definition_digest":"c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce","#,
        r#""image_reference":"registry.lab.your-cloud.test/your-cloud/lab-notes","#,
        r#""image_digest":"sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","#,
        r#""local_port":8080,"origin_host":"notes.lab.your-cloud.test"}"#,
    );
    const MINIMAL_USER_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_user_service","#,
        r#""definition_slug":"minimal","#,
        r#""definition_digest":"faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c","#,
        r#""image_reference":"registry.lab.your-cloud.test/minimal","#,
        r#""image_digest":"sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","#,
        r#""local_port":8081,"origin_host":""}"#,
    );
    const MINIMAL_USER_ROLLBACK_DOCUMENT: &str = concat!(
        r#"{"schema_version":2,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"remove_user_service","#,
        r#""definition_slug":"minimal","#,
        r#""definition_digest":"faf14b5c09ce83169466632fe2d37063453fe924154b6cc265b62fdd6aebd95c","#,
        r#""image_reference":"registry.lab.your-cloud.test/minimal","#,
        r#""image_digest":"sha256:2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","#,
        r#""local_port":8081,"origin_host":""}"#,
    );

    /// The six transcripts, byte for byte, copied literally from
    /// `internal/plan/schema2_test.go`. The Auxiliary side pins the very same
    /// values from its own encoder, so a single byte of drift in either
    /// implementation fails here rather than producing plans the other side
    /// hashes differently on a real machine.
    const WEB_SERVICE_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000126465706c6f795f7765625f",
        "736572766963650000000862656e746f7064660000001a676863722e696f2f61",
        "6c616d30303030302f62656e746f70646600000020a4ed090f29823da5e296e2",
        "c2f8603664da71676156ea47c3f186cc73eec38db000001f90",
    );
    const WEB_SERVICE_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000001272656d6f76655f7765625f",
        "736572766963650000000862656e746f7064660000001a676863722e696f2f61",
        "6c616d30303030302f62656e746f70646600000020a4ed090f29823da5e296e2",
        "c2f8603664da71676156ea47c3f186cc73eec38db000001f90",
    );
    const ENTRYPOINT_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000116465706c6f795f656e7472",
        "79706f696e7400000019646f636b65722e696f2f6c6962726172792f74726165",
        "66696b000000209c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab261",
        "4cbaf410dcb2ac",
    );
    const ENTRYPOINT_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000001172656d6f76655f656e7472",
        "79706f696e7400000019646f636b65722e696f2f6c6962726172792f74726165",
        "66696b000000209c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab261",
        "4cbaf410dcb2ac",
    );
    const ROUTE_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000d7075626c6973685f726f75",
        "74650000001c62656e746f7064662e6c61622e796f75722d636c6f75642e7465",
        "737400001f90",
    );
    const ROUTE_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000c7265746972655f726f7574",
        "650000001c62656e746f7064662e6c61622e796f75722d636c6f75642e746573",
        "7400001f90",
    );

    /// The eight transcripts of the private profile, byte for byte, under the
    /// same obligation.
    const PRIVATE_SERVICE_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000166465706c6f795f70726976",
        "6174655f736572766963650000000b7661756c7477617264656e0000001c646f",
        "636b65722e696f2f7661756c7477617264656e2f73657276657200000020ebdf",
        "e70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e80000",
        "1f90000000197661756c742e6c61622e796f75722d636c6f75642e74657374",
    );
    const PRIVATE_SERVICE_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000001672656d6f76655f70726976",
        "6174655f736572766963650000000b7661756c7477617264656e0000001c646f",
        "636b65722e696f2f7661756c7477617264656e2f73657276657200000020ebdf",
        "e70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e80000",
        "1f90000000197661756c742e6c61622e796f75722d636c6f75642e74657374",
    );
    const LINK_ROUTE_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000127075626c6973685f6c696e",
        "6b5f726f757465000000197661756c742e6c61622e796f75722d636c6f75642e",
        "7465737400001f90",
    );
    const LINK_ROUTE_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000117265746972655f6c696e6b",
        "5f726f757465000000197661756c742e6c61622e796f75722d636c6f75642e74",
        "65737400001f90",
    );
    const SNAPSHOT_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d3100000010736e617073686f745f7365",
        "72766963650000000b7661756c7477617264656e000000076e696768746c79",
    );
    const SNAPSHOT_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d3100000010646973636172645f736e61",
        "7073686f740000000b7661756c7477617264656e000000076e696768746c79",
    );
    const RESTORE_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000f726573746f72655f736572",
        "766963650000000b7661756c7477617264656e000000076e696768746c79",
    );
    const RESTORE_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000000f726573746f72655f736572",
        "766963650000000b7661756c7477617264656e0000000870726576696f7573",
    );

    /// The four transcripts of the third door, byte for byte, under the same
    /// obligation.
    ///
    /// The minimal pair closes on `00000000`: the origin is a length-prefixed
    /// field of length zero rather than an absence, which is what keeps the end
    /// of the tail from depending on a rule the bytes do not carry.
    const USER_SERVICE_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000136465706c6f795f75736572",
        "5f73657276696365000000096c61622d6e6f74657300000020c0f30d7c7f8635",
        "d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce00000031726567",
        "69737472792e6c61622e796f75722d636c6f75642e746573742f796f75722d63",
        "6c6f75642f6c61622d6e6f746573000000200102030405060708090a0b0c0d0e",
        "0f101112131415161718191a1b1c1d1e1f2000001f90000000196e6f7465732e",
        "6c61622e796f75722d636c6f75642e74657374",
    );
    const USER_SERVICE_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000001372656d6f76655f75736572",
        "5f73657276696365000000096c61622d6e6f74657300000020c0f30d7c7f8635",
        "d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce00000031726567",
        "69737472792e6c61622e796f75722d636c6f75642e746573742f796f75722d63",
        "6c6f75642f6c61622d6e6f746573000000200102030405060708090a0b0c0d0e",
        "0f101112131415161718191a1b1c1d1e1f2000001f90000000196e6f7465732e",
        "6c61622e796f75722d636c6f75642e74657374",
    );
    const MINIMAL_USER_PLAN_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d31000000136465706c6f795f75736572",
        "5f73657276696365000000076d696e696d616c00000020faf14b5c09ce831694",
        "66632fe2d37063453fe924154b6cc265b62fdd6aebd95c000000247265676973",
        "7472792e6c61622e796f75722d636c6f75642e746573742f6d696e696d616c00",
        "0000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d",
        "3e3f4000001f9100000000",
    );
    const MINIMAL_USER_ROLLBACK_TRANSCRIPT_HEX: &str = concat!(
        "796f75722d636c6f75642f6f63692d706c616e2e763200020000002438663134",
        "653435662d636565612d343136372d613862312d316637626430613066346332",
        "0000000d6c61622d6d616368696e652d310000001372656d6f76655f75736572",
        "5f73657276696365000000076d696e696d616c00000020faf14b5c09ce831694",
        "66632fe2d37063453fe924154b6cc265b62fdd6aebd95c000000247265676973",
        "7472792e6c61622e796f75722d636c6f75642e746573742f6d696e696d616c00",
        "0000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d",
        "3e3f4000001f9100000000",
    );

    /// The six digests an approval envelope of these vectors names as
    /// `plan_sha256` and `rollback_sha256`, in the exact spelling that envelope
    /// requires.
    const WEB_SERVICE_PLAN_SHA256: &str =
        "99f6e6401d74583f64e4200e6e47cd365ab299466eebe1c1a7210f260b0366ae";
    const WEB_SERVICE_ROLLBACK_SHA256: &str =
        "4e480f76a7247cde6c41990e941512dce70f0a272a17a2618211bd03230ced68";
    const ENTRYPOINT_PLAN_SHA256: &str =
        "fe15d468f77ed9ca6b54da9a63860278894be7db4b6d997898b55fcb602f3722";
    const ENTRYPOINT_ROLLBACK_SHA256: &str =
        "1b91a7fa77b7d02cc16ce5d694b1709f641a341c849b4459de0ee3960d1cfcd8";
    const ROUTE_PLAN_SHA256: &str =
        "3d92c310868a8ba98aca5501c069bd0e4674757f787c8095e7c39d65d8d20a89";
    const ROUTE_ROLLBACK_SHA256: &str =
        "93e844abe96e68f157eb715ace9ff423004b0c64c68536d4e79ebc8206da1324";

    /// The eight digests of the private profile, under the same rule.
    const PRIVATE_SERVICE_PLAN_SHA256: &str =
        "b4d69bc7fcd277a5c165cd9494f2a88cb3ea8acf06f66906a10f831292f03372";
    const PRIVATE_SERVICE_ROLLBACK_SHA256: &str =
        "c1650b0d359671aafc7fc19bc1d0f050bcf561558cfe3a82bfd897c16d0c7ba0";
    const LINK_ROUTE_PLAN_SHA256: &str =
        "384fe095408f815bcc6d9b0be5655eaadabefe01c1a717bd0ff641567a5f3fbd";
    const LINK_ROUTE_ROLLBACK_SHA256: &str =
        "c17842e513bd8af2da8cee699db20c24b59ae00d2fcfddfa0004caad1cc2d1db";
    const SNAPSHOT_PLAN_SHA256: &str =
        "3de5108f5e7f2934579128bcfa8a09b3a6bbb16739b37f53e61d941261c7c6e3";
    const SNAPSHOT_ROLLBACK_SHA256: &str =
        "0bedf38650c70b58a36e8a0a28944dd53bd9720bce77012be2227ffa85192cae";
    const RESTORE_PLAN_SHA256: &str =
        "6a6b71a15f969916a426fdfdcefca22ab670935a04459079eb724c18e180aebc";
    const RESTORE_ROLLBACK_SHA256: &str =
        "1be3be0186ff3be565e6c4df4fc5a864a8a28f1c3929d029b3ec6ecb38c11b5a";

    /// The four digests of the third door, under the same rule.
    const USER_SERVICE_PLAN_SHA256: &str =
        "604b9300bb6f321d53759365cc7064fed1fc9b794b8afdbe811a1742d8133a59";
    const USER_SERVICE_ROLLBACK_SHA256: &str =
        "b2737aba239eb3d43326c43e1508687b33ade43ed5fd62a97cfe0866b6deabc8";
    const MINIMAL_USER_PLAN_SHA256: &str =
        "305f7fac725f8c7cd0970cd4db3b92af60a339b1cd1fa569b61858865210a753";
    const MINIMAL_USER_ROLLBACK_SHA256: &str =
        "bb76c62b75d4fd70d7437e75d82396c5b9ae6df3ef6a65e881ac20a222bcc5d3";

    /// The two digests of a route of the public profile carrying exactly the
    /// host and the port of the link route vectors above.
    ///
    /// They exist so that the shared-tail property is pinned rather than merely
    /// computed: `publish_route` and `publish_link_route` describe two different
    /// states with identical field lists and identical values, and these are the
    /// bytes that prove the two never hash the same. The Auxiliary side pins them
    /// for the same reason.
    const SAME_FIELDS_ROUTE_SHA256: &str =
        "28513b85c3cb68488757f68009171820350d573efc10009eef0d540ffab193cf";
    const SAME_FIELDS_RETIRE_ROUTE_SHA256: &str =
        "cc1300fdc24448cb152cc9dbc42f8c9bcefe1f915012855d30abf8005cb15d57";

    /// A real digest of another image of the same palier. It is refused for the
    /// same reason a resolved architecture digest is: a plan names one pin, and
    /// nothing may stand in for it.
    const OTHER_PINNED_DIGEST: &str =
        "sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab";

    /// The schema 1 vector, kept here so that the two decoders can be held
    /// against one another without reopening the older contract.
    const PROBE_PLAN_DOCUMENT: &str = concat!(
        r#"{"schema_version":1,"infrastructure_id":"8f14e45f-ceea-4167-a8b1-1f7bd0a0f4c2","#,
        r#""machine_id":"lab-machine-1","operation":"deploy_oci_probe","#,
        r#""image_reference":"docker.io/traefik/whoami","#,
        r#""image_digest":"sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab","#,
        r#""local_port":8080}"#,
    );

    fn web_service() -> WebServicePlanDocumentV2 {
        WebServicePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::DeployWebService,
            service_profile: SERVICE_PROFILE_BENTOPDF.into(),
            image_reference: BENTOPDF_IMAGE_REFERENCE.into(),
            image_digest: BENTOPDF_IMAGE_DIGEST.into(),
            local_port: PORT,
        }
    }

    fn entrypoint() -> EntrypointPlanDocumentV2 {
        EntrypointPlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::DeployEntrypoint,
            image_reference: ENTRYPOINT_IMAGE_REFERENCE.into(),
            image_digest: ENTRYPOINT_IMAGE_DIGEST.into(),
        }
    }

    fn route() -> RoutePlanDocumentV2 {
        RoutePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::PublishRoute,
            route_host: ROUTE_HOST.into(),
            backend_port: PORT,
        }
    }

    fn private_service() -> PrivateServicePlanDocumentV2 {
        PrivateServicePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::DeployPrivateService,
            service_profile: SERVICE_PROFILE_VAULTWARDEN.into(),
            image_reference: VAULTWARDEN_IMAGE_REFERENCE.into(),
            image_digest: VAULTWARDEN_IMAGE_DIGEST.into(),
            local_port: PORT,
            origin_host: ORIGIN_HOST.into(),
        }
    }

    fn link_route() -> LinkRoutePlanDocumentV2 {
        LinkRoutePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::PublishLinkRoute,
            route_host: LINK_ROUTE_HOST.into(),
            backend_port: PORT,
        }
    }

    fn snapshot() -> SnapshotPlanDocumentV2 {
        SnapshotPlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::SnapshotService,
            service_profile: SERVICE_PROFILE_VAULTWARDEN.into(),
            snapshot_slot: SNAPSHOT_SLOT.into(),
        }
    }

    fn restore() -> RestorePlanDocumentV2 {
        RestorePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::RestoreService,
            service_profile: SERVICE_PROFILE_VAULTWARDEN.into(),
            snapshot_slot: SNAPSHOT_SLOT.into(),
        }
    }

    fn user_service() -> UserServicePlanDocumentV2 {
        UserServicePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::DeployUserService,
            definition_slug: USER_SERVICE_SLUG.into(),
            definition_digest: USER_SERVICE_DEFINITION_DIGEST.into(),
            image_reference: USER_SERVICE_IMAGE_REFERENCE.into(),
            image_digest: USER_SERVICE_IMAGE_DIGEST.into(),
            local_port: PORT,
            origin_host: USER_SERVICE_ORIGIN_HOST.into(),
        }
    }

    /// The same door over a definition that consumes no origin, which is the one
    /// document of the schema whose conditional field is empty.
    fn minimal_user_service() -> UserServicePlanDocumentV2 {
        UserServicePlanDocumentV2 {
            schema_version: PLAN_V2_SCHEMA_VERSION,
            infrastructure_id: INFRASTRUCTURE.into(),
            machine_id: MACHINE.into(),
            operation: PlanV2Operation::DeployUserService,
            definition_slug: MINIMAL_SLUG.into(),
            definition_digest: MINIMAL_DEFINITION_DIGEST.into(),
            image_reference: MINIMAL_IMAGE_REFERENCE.into(),
            image_digest: MINIMAL_IMAGE_DIGEST.into(),
            local_port: MINIMAL_USER_PORT,
            origin_host: String::new(),
        }
    }

    /// The fifteen operations this schema declares, in declaration order.
    ///
    /// Holding the list in one place is what keeps a registry from being
    /// half-extended: the exhaustive dispatch below counts its own table against
    /// this one, so an operation added to the enum without a canonical document
    /// fails on the count rather than on a machine.
    const DECLARED_OPERATIONS: [PlanV2Operation; 15] = [
        PlanV2Operation::DeployWebService,
        PlanV2Operation::RemoveWebService,
        PlanV2Operation::DeployEntrypoint,
        PlanV2Operation::RemoveEntrypoint,
        PlanV2Operation::PublishRoute,
        PlanV2Operation::RetireRoute,
        PlanV2Operation::DeployPrivateService,
        PlanV2Operation::RemovePrivateService,
        PlanV2Operation::PublishLinkRoute,
        PlanV2Operation::RetireLinkRoute,
        PlanV2Operation::SnapshotService,
        PlanV2Operation::DiscardSnapshot,
        PlanV2Operation::RestoreService,
        PlanV2Operation::DeployUserService,
        PlanV2Operation::RemoveUserService,
    ];

    /// The name of the shape a document decoded into.
    ///
    /// It is an exhaustive match rather than a comparison of debug strings, so a
    /// shape added to [`PlanDocumentV2`] without a line here does not compile.
    fn shape_name(document: &PlanDocumentV2) -> &'static str {
        match document {
            PlanDocumentV2::WebService(_) => "WebService",
            PlanDocumentV2::Entrypoint(_) => "Entrypoint",
            PlanDocumentV2::Route(_) => "Route",
            PlanDocumentV2::PrivateService(_) => "PrivateService",
            PlanDocumentV2::LinkRoute(_) => "LinkRoute",
            PlanDocumentV2::Snapshot(_) => "Snapshot",
            PlanDocumentV2::Restore(_) => "Restore",
            PlanDocumentV2::UserService(_) => "UserService",
        }
    }

    /// Encodes a document without validating it, which is what a hostile case
    /// needs: the refusal under test must come from the decoding rather than
    /// from something refusing to produce the bytes in the first place.
    fn hostile<T: Serialize>(document: &T) -> String {
        serde_json::to_string(document).expect("a plan is representable as JSON")
    }

    fn with_extra_member(document: &str, member: &str) -> String {
        format!("{},{member}}}", document.trim_end_matches('}'))
    }

    /// The interoperability proof of the schema 2 encoding, for each of the
    /// seven operation groups.
    ///
    /// Every transcript, every digest and every canonical document is pinned
    /// literally here and in `internal/plan/schema2_test.go`. Reading the two
    /// encoders against one another would not be a proof; producing the same
    /// bytes from both is.
    ///
    /// The rollback is required to undo the plan here, and only in that
    /// direction: the restore is the one group whose undoing is not mutual, and
    /// the test that reads rollbacks as plans states that asymmetry where it
    /// belongs rather than hiding it inside this table.
    #[test]
    fn the_deterministic_schema_two_vectors_are_held_with_the_auxiliary_side() {
        for (
            group,
            plan_document,
            rollback_document,
            plan_hex,
            rollback_hex,
            plan_sha,
            rollback_sha,
            length,
        ) in [
            (
                "web service",
                WEB_SERVICE_PLAN_DOCUMENT,
                WEB_SERVICE_ROLLBACK_DOCUMENT,
                WEB_SERVICE_PLAN_TRANSCRIPT_HEX,
                WEB_SERVICE_ROLLBACK_TRANSCRIPT_HEX,
                WEB_SERVICE_PLAN_SHA256,
                WEB_SERVICE_ROLLBACK_SHA256,
                185_usize,
            ),
            (
                "entrypoint",
                ENTRYPOINT_PLAN_DOCUMENT,
                ENTRYPOINT_ROLLBACK_DOCUMENT,
                ENTRYPOINT_PLAN_TRANSCRIPT_HEX,
                ENTRYPOINT_ROLLBACK_TRANSCRIPT_HEX,
                ENTRYPOINT_PLAN_SHA256,
                ENTRYPOINT_ROLLBACK_SHA256,
                167_usize,
            ),
            (
                "route",
                ROUTE_PLAN_DOCUMENT,
                ROUTE_ROLLBACK_DOCUMENT,
                ROUTE_PLAN_TRANSCRIPT_HEX,
                ROUTE_ROLLBACK_TRANSCRIPT_HEX,
                ROUTE_PLAN_SHA256,
                ROUTE_ROLLBACK_SHA256,
                134_usize,
            ),
            (
                "private service",
                PRIVATE_SERVICE_PLAN_DOCUMENT,
                PRIVATE_SERVICE_ROLLBACK_DOCUMENT,
                PRIVATE_SERVICE_PLAN_TRANSCRIPT_HEX,
                PRIVATE_SERVICE_ROLLBACK_TRANSCRIPT_HEX,
                PRIVATE_SERVICE_PLAN_SHA256,
                PRIVATE_SERVICE_ROLLBACK_SHA256,
                223_usize,
            ),
            (
                "link route",
                LINK_ROUTE_PLAN_DOCUMENT,
                LINK_ROUTE_ROLLBACK_DOCUMENT,
                LINK_ROUTE_PLAN_TRANSCRIPT_HEX,
                LINK_ROUTE_ROLLBACK_TRANSCRIPT_HEX,
                LINK_ROUTE_PLAN_SHA256,
                LINK_ROUTE_ROLLBACK_SHA256,
                136_usize,
            ),
            (
                "snapshot",
                SNAPSHOT_PLAN_DOCUMENT,
                SNAPSHOT_ROLLBACK_DOCUMENT,
                SNAPSHOT_PLAN_TRANSCRIPT_HEX,
                SNAPSHOT_ROLLBACK_TRANSCRIPT_HEX,
                SNAPSHOT_PLAN_SHA256,
                SNAPSHOT_ROLLBACK_SHA256,
                127_usize,
            ),
            (
                // The restore is the one group whose rollback is the same
                // operation on another slot, so its two vectors differ by that
                // slot alone — and the reserved one appears here, in the one
                // document of the product that names it.
                "restore",
                RESTORE_PLAN_DOCUMENT,
                RESTORE_ROLLBACK_DOCUMENT,
                RESTORE_PLAN_TRANSCRIPT_HEX,
                RESTORE_ROLLBACK_TRANSCRIPT_HEX,
                RESTORE_PLAN_SHA256,
                RESTORE_ROLLBACK_SHA256,
                126_usize,
            ),
            (
                // The third door, whose tail is the private one's with the
                // profile replaced by the two fields that name a definition.
                "user service",
                USER_SERVICE_PLAN_DOCUMENT,
                USER_SERVICE_ROLLBACK_DOCUMENT,
                USER_SERVICE_PLAN_TRANSCRIPT_HEX,
                USER_SERVICE_ROLLBACK_TRANSCRIPT_HEX,
                USER_SERVICE_PLAN_SHA256,
                USER_SERVICE_ROLLBACK_SHA256,
                275_usize,
            ),
            (
                // The same door over a definition that consumes no origin. Its
                // transcript is forty bytes shorter and closes on a length of
                // zero rather than on nothing, which is the whole of the
                // conditional field's encoding.
                "user service without an origin",
                MINIMAL_USER_PLAN_DOCUMENT,
                MINIMAL_USER_ROLLBACK_DOCUMENT,
                MINIMAL_USER_PLAN_TRANSCRIPT_HEX,
                MINIMAL_USER_ROLLBACK_TRANSCRIPT_HEX,
                MINIMAL_USER_PLAN_SHA256,
                MINIMAL_USER_ROLLBACK_SHA256,
                235_usize,
            ),
        ] {
            let plan = decode_plan_v2_document(plan_document.as_bytes())
                .unwrap_or_else(|_| panic!("{group}: the nominal document"));
            let rollback = decode_plan_v2_document(rollback_document.as_bytes())
                .unwrap_or_else(|_| panic!("{group}: the nominal rollback"));

            let transcript = plan.transcript().expect("the vector transcript");
            assert_eq!(
                transcript.len(),
                length,
                "{group} transcript length drifted"
            );
            assert!(
                transcript.starts_with(PLAN_V2_TRANSCRIPT_DOMAIN),
                "{group} transcript does not start with its own domain separator"
            );
            assert_eq!(
                encode_lower_hex(&transcript),
                plan_hex,
                "{group} plan transcript drifted from the shared vector"
            );
            assert_eq!(
                encode_lower_hex(&rollback.transcript().unwrap()),
                rollback_hex,
                "{group} rollback transcript drifted from the shared vector"
            );

            assert_eq!(plan.sha256().unwrap(), plan_sha, "{group} plan_sha256");
            assert_eq!(
                rollback.sha256().unwrap(),
                rollback_sha,
                "{group} rollback_sha256"
            );
            assert!(plan.is_undone_by(&rollback));
            assert_ne!(plan.sha256().unwrap(), rollback.sha256().unwrap());
        }
    }

    /// The declaration order of the fields is the canonical encoding order the
    /// Controller emits, and serde is held to it rather than trusted with it.
    ///
    /// It is asserted rather than relied upon, because this side must recognise
    /// those exact bytes and never has to produce them: a serialiser that sorted
    /// its keys would still read every plan correctly and would silently stop
    /// agreeing with the Auxiliary about what a canonical document is.
    #[test]
    fn the_canonical_serialisation_order_is_the_declaration_order() {
        assert_eq!(hostile(&web_service()), WEB_SERVICE_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&web_service().inverted()),
            WEB_SERVICE_ROLLBACK_DOCUMENT
        );
        assert_eq!(hostile(&entrypoint()), ENTRYPOINT_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&entrypoint().inverted()),
            ENTRYPOINT_ROLLBACK_DOCUMENT
        );
        assert_eq!(hostile(&route()), ROUTE_PLAN_DOCUMENT);
        assert_eq!(hostile(&route().inverted()), ROUTE_ROLLBACK_DOCUMENT);
        assert_eq!(hostile(&private_service()), PRIVATE_SERVICE_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&private_service().inverted()),
            PRIVATE_SERVICE_ROLLBACK_DOCUMENT
        );
        assert_eq!(hostile(&link_route()), LINK_ROUTE_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&link_route().inverted()),
            LINK_ROUTE_ROLLBACK_DOCUMENT
        );
        assert_eq!(hostile(&snapshot()), SNAPSHOT_PLAN_DOCUMENT);
        assert_eq!(hostile(&snapshot().inverted()), SNAPSHOT_ROLLBACK_DOCUMENT);
        assert_eq!(hostile(&restore()), RESTORE_PLAN_DOCUMENT);
        assert_eq!(hostile(&restore().inverted()), RESTORE_ROLLBACK_DOCUMENT);
        assert_eq!(hostile(&user_service()), USER_SERVICE_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&user_service().inverted()),
            USER_SERVICE_ROLLBACK_DOCUMENT
        );
        // The empty origin is rendered rather than skipped, which is what makes
        // the canonical spelling of a plan that carries none a fact of this side
        // too and not only of the Controller's encoder.
        assert_eq!(hostile(&minimal_user_service()), MINIMAL_USER_PLAN_DOCUMENT);
        assert_eq!(
            hostile(&minimal_user_service().inverted()),
            MINIMAL_USER_ROLLBACK_DOCUMENT
        );
    }

    /// No two of the fourteen vectors, nor the schema 1 vector, name the same
    /// digest.
    ///
    /// This is what makes the transcript layout unambiguous without a group tag:
    /// fourteen distinct documents produce fourteen distinct digests, and none of
    /// them is the schema 1 digest of anything.
    #[test]
    fn no_two_schema_two_digests_collide_across_operation_groups() {
        let mut seen: Vec<&str> = vec![
            // The two schema 1 digests of the probe vector.
            "2d50d2bc935ce6c56ef14fbfae93d670d5fdb9ca735315e5a26760d818dd5b0e",
            "e953fb5f9d8423be61cad4a06d571e200977dd183f53c12d5a897746ad80497a",
        ];
        for digest in [
            WEB_SERVICE_PLAN_SHA256,
            WEB_SERVICE_ROLLBACK_SHA256,
            ENTRYPOINT_PLAN_SHA256,
            ENTRYPOINT_ROLLBACK_SHA256,
            ROUTE_PLAN_SHA256,
            ROUTE_ROLLBACK_SHA256,
            PRIVATE_SERVICE_PLAN_SHA256,
            PRIVATE_SERVICE_ROLLBACK_SHA256,
            LINK_ROUTE_PLAN_SHA256,
            LINK_ROUTE_ROLLBACK_SHA256,
            SNAPSHOT_PLAN_SHA256,
            SNAPSHOT_ROLLBACK_SHA256,
            RESTORE_PLAN_SHA256,
            RESTORE_ROLLBACK_SHA256,
            // The third door's two pairs. The second of them carries no origin,
            // so it is also what proves that an absent field does not collapse
            // two documents into one digest: the same definition deployed with
            // and without an origin would be two states, and they are two
            // digests.
            USER_SERVICE_PLAN_SHA256,
            USER_SERVICE_ROLLBACK_SHA256,
            MINIMAL_USER_PLAN_SHA256,
            MINIMAL_USER_ROLLBACK_SHA256,
        ] {
            assert!(!seen.contains(&digest), "{digest} is named twice");
            seen.push(digest);
        }
    }

    /// The property the transcript layout rests on once two groups have the same
    /// tail.
    ///
    /// A route of the public profile and a route of the private passage name a
    /// host and a port and nothing else; a snapshot and a restore name a profile
    /// and a slot and nothing else. Their tails are byte for byte identical, and
    /// the four documents are four states: publishing a name to a loopback
    /// service is not publishing it through the tunnel, and archiving data is not
    /// replacing it. What keeps their digests apart is the operation string,
    /// hashed ahead of the tail at a determined offset.
    ///
    /// It is held against pinned vectors rather than against freshly built
    /// documents so that a failure names a value a reader can look up.
    #[test]
    fn two_operations_carrying_the_same_fields_still_carry_two_digests() {
        let same_fields_route = RoutePlanDocumentV2 {
            route_host: LINK_ROUTE_HOST.into(),
            ..route()
        };
        assert_eq!(
            same_fields_route.transcript().unwrap().len(),
            link_route().transcript().unwrap().len() - 5,
            "the two tails differ by the length of the operation alone"
        );
        assert_eq!(
            PlanDocumentV2::Route(same_fields_route.clone())
                .sha256()
                .unwrap(),
            SAME_FIELDS_ROUTE_SHA256
        );
        assert_eq!(
            PlanDocumentV2::Route(same_fields_route.inverted())
                .sha256()
                .unwrap(),
            SAME_FIELDS_RETIRE_ROUTE_SHA256
        );
        for (name, left, right) in [
            (
                "a public route and a link route carrying the same host and port",
                SAME_FIELDS_ROUTE_SHA256,
                LINK_ROUTE_PLAN_SHA256,
            ),
            (
                "their two retirements",
                SAME_FIELDS_RETIRE_ROUTE_SHA256,
                LINK_ROUTE_ROLLBACK_SHA256,
            ),
            (
                "a snapshot and a restore naming the same profile and slot",
                SNAPSHOT_PLAN_SHA256,
                RESTORE_PLAN_SHA256,
            ),
        ] {
            assert_ne!(left, right, "{name} share a digest");
        }

        // Rewriting the operation of one of these documents into the other's is
        // not a refusal and must not be: the result is a well-formed document of
        // the other group, describing another state. It is a second plan, and the
        // only thing that makes it one rather than the first plan reworded is
        // that its digest differs — so a transport that rewrote it carries a
        // document no approval names.
        for (name, document, from, to, digest) in [
            (
                "a route rewritten into a link route",
                ROUTE_PLAN_DOCUMENT,
                "publish_route",
                "publish_link_route",
                ROUTE_PLAN_SHA256,
            ),
            (
                "a snapshot rewritten into a restore",
                SNAPSHOT_PLAN_DOCUMENT,
                "snapshot_service",
                "restore_service",
                SNAPSHOT_PLAN_SHA256,
            ),
        ] {
            let rewritten = document.replace(&format!(r#""{from}""#), &format!(r#""{to}""#));
            let decoded = decode_plan_v2_document(rewritten.as_bytes())
                .unwrap_or_else(|_| panic!("{name}: the rewritten document"));
            assert_eq!(decoded.operation().as_str(), to, "{name}");
            assert_ne!(
                decoded.sha256().unwrap(),
                digest,
                "{name}: rewriting the operation left the digest where it was"
            );
        }
    }

    /// Every field of every schema 2 document is inside the hashed bytes.
    ///
    /// The test does not read the transcript builders: it changes one field at a
    /// time and requires the bytes to move. The wire documents are read back at
    /// the end, so a field added to a schema and forgotten in its transcript
    /// fails here rather than on a machine.
    #[test]
    fn changing_any_single_field_changes_the_schema_two_digest() {
        let reference = web_service().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                WebServicePlanDocumentV2 {
                    schema_version: 1,
                    ..web_service()
                },
            ),
            (
                "infrastructure_id",
                WebServicePlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..web_service()
                },
            ),
            (
                "machine_id",
                WebServicePlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..web_service()
                },
            ),
            (
                "operation",
                WebServicePlanDocumentV2 {
                    operation: PlanV2Operation::RemoveWebService,
                    ..web_service()
                },
            ),
            (
                "service_profile",
                WebServicePlanDocumentV2 {
                    service_profile: "bentopdf-simple".into(),
                    ..web_service()
                },
            ),
            (
                "image_reference",
                WebServicePlanDocumentV2 {
                    image_reference: "ghcr.io/attacker/bentopdf".into(),
                    ..web_service()
                },
            ),
            (
                "image_digest",
                WebServicePlanDocumentV2 {
                    image_digest: OTHER_PINNED_DIGEST.into(),
                    ..web_service()
                },
            ),
            (
                "local_port",
                WebServicePlanDocumentV2 {
                    local_port: PORT + 1,
                    ..web_service()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "web service {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&web_service()), &covered);

        let reference = entrypoint().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                EntrypointPlanDocumentV2 {
                    schema_version: 1,
                    ..entrypoint()
                },
            ),
            (
                "infrastructure_id",
                EntrypointPlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..entrypoint()
                },
            ),
            (
                "machine_id",
                EntrypointPlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..entrypoint()
                },
            ),
            (
                "operation",
                EntrypointPlanDocumentV2 {
                    operation: PlanV2Operation::RemoveEntrypoint,
                    ..entrypoint()
                },
            ),
            (
                "image_reference",
                EntrypointPlanDocumentV2 {
                    image_reference: "ghcr.io/attacker/traefik".into(),
                    ..entrypoint()
                },
            ),
            (
                "image_digest",
                EntrypointPlanDocumentV2 {
                    image_digest: OTHER_PINNED_DIGEST.into(),
                    ..entrypoint()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "entrypoint {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&entrypoint()), &covered);

        let reference = route().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                RoutePlanDocumentV2 {
                    schema_version: 1,
                    ..route()
                },
            ),
            (
                "infrastructure_id",
                RoutePlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..route()
                },
            ),
            (
                "machine_id",
                RoutePlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..route()
                },
            ),
            (
                "operation",
                RoutePlanDocumentV2 {
                    operation: PlanV2Operation::RetireRoute,
                    ..route()
                },
            ),
            (
                "route_host",
                RoutePlanDocumentV2 {
                    route_host: "other.lab.your-cloud.test".into(),
                    ..route()
                },
            ),
            (
                "backend_port",
                RoutePlanDocumentV2 {
                    backend_port: PORT + 1,
                    ..route()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "route {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&route()), &covered);

        let reference = private_service().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                PrivateServicePlanDocumentV2 {
                    schema_version: 1,
                    ..private_service()
                },
            ),
            (
                "infrastructure_id",
                PrivateServicePlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..private_service()
                },
            ),
            (
                "machine_id",
                PrivateServicePlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..private_service()
                },
            ),
            (
                "operation",
                PrivateServicePlanDocumentV2 {
                    operation: PlanV2Operation::RemovePrivateService,
                    ..private_service()
                },
            ),
            (
                "service_profile",
                PrivateServicePlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    ..private_service()
                },
            ),
            (
                "image_reference",
                PrivateServicePlanDocumentV2 {
                    image_reference: "ghcr.io/attacker/vaultwarden".into(),
                    ..private_service()
                },
            ),
            (
                "image_digest",
                PrivateServicePlanDocumentV2 {
                    image_digest: OTHER_PINNED_DIGEST.into(),
                    ..private_service()
                },
            ),
            (
                "local_port",
                PrivateServicePlanDocumentV2 {
                    local_port: PORT + 1,
                    ..private_service()
                },
            ),
            (
                "origin_host",
                PrivateServicePlanDocumentV2 {
                    origin_host: "other.lab.your-cloud.test".into(),
                    ..private_service()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "private service {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&private_service()), &covered);

        let reference = link_route().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                LinkRoutePlanDocumentV2 {
                    schema_version: 1,
                    ..link_route()
                },
            ),
            (
                "infrastructure_id",
                LinkRoutePlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..link_route()
                },
            ),
            (
                "machine_id",
                LinkRoutePlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..link_route()
                },
            ),
            (
                "operation",
                LinkRoutePlanDocumentV2 {
                    operation: PlanV2Operation::RetireLinkRoute,
                    ..link_route()
                },
            ),
            (
                "route_host",
                LinkRoutePlanDocumentV2 {
                    route_host: "other.lab.your-cloud.test".into(),
                    ..link_route()
                },
            ),
            (
                "backend_port",
                LinkRoutePlanDocumentV2 {
                    backend_port: PORT + 1,
                    ..link_route()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "link route {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&link_route()), &covered);

        let reference = snapshot().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                SnapshotPlanDocumentV2 {
                    schema_version: 1,
                    ..snapshot()
                },
            ),
            (
                "infrastructure_id",
                SnapshotPlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..snapshot()
                },
            ),
            (
                "machine_id",
                SnapshotPlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..snapshot()
                },
            ),
            (
                "operation",
                SnapshotPlanDocumentV2 {
                    operation: PlanV2Operation::DiscardSnapshot,
                    ..snapshot()
                },
            ),
            (
                "service_profile",
                SnapshotPlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    ..snapshot()
                },
            ),
            (
                "snapshot_slot",
                SnapshotPlanDocumentV2 {
                    snapshot_slot: "weekly".into(),
                    ..snapshot()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "snapshot {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&snapshot()), &covered);

        let reference = restore().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                RestorePlanDocumentV2 {
                    schema_version: 1,
                    ..restore()
                },
            ),
            (
                "infrastructure_id",
                RestorePlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..restore()
                },
            ),
            (
                "machine_id",
                RestorePlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..restore()
                },
            ),
            (
                "operation",
                RestorePlanDocumentV2 {
                    operation: PlanV2Operation::SnapshotService,
                    ..restore()
                },
            ),
            (
                "service_profile",
                RestorePlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    ..restore()
                },
            ),
            (
                // The reserved slot is the value the undoing of a restore moves
                // to, so the field it moves has to be inside the hashed bytes:
                // otherwise a return and the plan it returns from would be one
                // digest.
                "snapshot_slot",
                RestorePlanDocumentV2 {
                    snapshot_slot: RESERVED_SNAPSHOT_SLOT.into(),
                    ..restore()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "restore {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&restore()), &covered);

        let reference = user_service().transcript().unwrap();
        let mut covered: Vec<&str> = Vec::new();
        for (field, moved) in [
            (
                "schema_version",
                UserServicePlanDocumentV2 {
                    schema_version: 1,
                    ..user_service()
                },
            ),
            (
                "infrastructure_id",
                UserServicePlanDocumentV2 {
                    infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                    ..user_service()
                },
            ),
            (
                "machine_id",
                UserServicePlanDocumentV2 {
                    machine_id: "lab-machine-2".into(),
                    ..user_service()
                },
            ),
            (
                "operation",
                UserServicePlanDocumentV2 {
                    operation: PlanV2Operation::RemoveUserService,
                    ..user_service()
                },
            ),
            (
                "definition_slug",
                UserServicePlanDocumentV2 {
                    definition_slug: MINIMAL_SLUG.into(),
                    ..user_service()
                },
            ),
            (
                // The revision is the whole of what "this instance runs those
                // exact bytes" means, so it has to be inside the hashed bytes:
                // otherwise two revisions of one definition would be one plan.
                "definition_digest",
                UserServicePlanDocumentV2 {
                    definition_digest: MINIMAL_DEFINITION_DIGEST.into(),
                    ..user_service()
                },
            ),
            (
                "image_reference",
                UserServicePlanDocumentV2 {
                    image_reference: "ghcr.io/attacker/lab-notes".into(),
                    ..user_service()
                },
            ),
            (
                "image_digest",
                UserServicePlanDocumentV2 {
                    image_digest: OTHER_PINNED_DIGEST.into(),
                    ..user_service()
                },
            ),
            (
                "local_port",
                UserServicePlanDocumentV2 {
                    local_port: PORT + 1,
                    ..user_service()
                },
            ),
            (
                "origin_host",
                UserServicePlanDocumentV2 {
                    origin_host: "other.lab.your-cloud.test".into(),
                    ..user_service()
                },
            ),
        ] {
            assert_ne!(
                moved.transcript().unwrap(),
                reference,
                "user service {field} is outside the hashed bytes"
            );
            covered.push(field);
        }
        require_every_wire_field_is_held(&hostile(&user_service()), &covered);

        // Removing the origin altogether is the mutation this group has and no
        // other does, and it must move the digest as much as changing it does: a
        // service deployed under a name and the same service deployed under none
        // are two states, so they can never be one set of hashed bytes.
        assert_ne!(
            UserServicePlanDocumentV2 {
                origin_host: String::new(),
                ..user_service()
            }
            .transcript()
            .unwrap(),
            reference,
            "dropping the origin of a user service left the hashed bytes where they were"
        );
        // And the same in the other direction, from the vector that carries
        // none, so that the empty field is proven to be written rather than
        // skipped.
        let minimal_reference = minimal_user_service().transcript().unwrap();
        assert_ne!(
            UserServicePlanDocumentV2 {
                origin_host: USER_SERVICE_ORIGIN_HOST.into(),
                ..minimal_user_service()
            }
            .transcript()
            .unwrap(),
            minimal_reference,
            "adding an origin to a user service left the hashed bytes where they were"
        );
        require_every_wire_field_is_held(&hostile(&minimal_user_service()), &covered);
    }

    /// Every field the wire document carries is one of the ones that was moved.
    fn require_every_wire_field_is_held(document: &str, covered: &[&str]) {
        let wire: serde_json::Value = serde_json::from_str(document).unwrap();
        let mut names: Vec<String> = wire.as_object().unwrap().keys().cloned().collect();
        names.sort();
        let mut held: Vec<String> = covered.iter().map(|name| (*name).to_owned()).collect();
        held.sort();
        assert_eq!(
            names, held,
            "a field of the plan is never held against its digest"
        );
    }

    /// The hostile table of the service group.
    #[test]
    fn decoding_refuses_every_web_service_document_outside_the_contract() {
        assert!(decode_plan_v2_document(WEB_SERVICE_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(WEB_SERVICE_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        for (name, hostile_document) in [
            (
                "schema 1 version",
                WebServicePlanDocumentV2 {
                    schema_version: 1,
                    ..web_service()
                },
            ),
            (
                "absent schema",
                WebServicePlanDocumentV2 {
                    schema_version: 0,
                    ..web_service()
                },
            ),
            (
                "upper-case UUID",
                WebServicePlanDocumentV2 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..web_service()
                },
            ),
            (
                "empty infrastructure",
                WebServicePlanDocumentV2 {
                    infrastructure_id: String::new(),
                    ..web_service()
                },
            ),
            (
                "traversal machine",
                WebServicePlanDocumentV2 {
                    machine_id: "../../etc/shadow".into(),
                    ..web_service()
                },
            ),
            (
                "upper-case machine",
                WebServicePlanDocumentV2 {
                    machine_id: "LAB-MACHINE-1".into(),
                    ..web_service()
                },
            ),
            (
                "entrypoint operation",
                WebServicePlanDocumentV2 {
                    operation: PlanV2Operation::DeployEntrypoint,
                    ..web_service()
                },
            ),
            (
                "route operation",
                WebServicePlanDocumentV2 {
                    operation: PlanV2Operation::PublishRoute,
                    ..web_service()
                },
            ),
            (
                "unknown profile",
                WebServicePlanDocumentV2 {
                    service_profile: "bentopdf-simple".into(),
                    ..web_service()
                },
            ),
            (
                "upper-case profile",
                WebServicePlanDocumentV2 {
                    service_profile: "BentoPDF".into(),
                    ..web_service()
                },
            ),
            (
                "empty profile",
                WebServicePlanDocumentV2 {
                    service_profile: String::new(),
                    ..web_service()
                },
            ),
            (
                "other registry",
                WebServicePlanDocumentV2 {
                    image_reference: "docker.io/alam00000/bentopdf".into(),
                    ..web_service()
                },
            ),
            (
                "other repository",
                WebServicePlanDocumentV2 {
                    image_reference: "ghcr.io/attacker/bentopdf".into(),
                    ..web_service()
                },
            ),
            (
                "registry-less reference",
                WebServicePlanDocumentV2 {
                    image_reference: "alam00000/bentopdf".into(),
                    ..web_service()
                },
            ),
            (
                "tagged reference",
                WebServicePlanDocumentV2 {
                    image_reference: format!("{BENTOPDF_IMAGE_REFERENCE}:latest"),
                    ..web_service()
                },
            ),
            (
                "reference carrying its own digest",
                WebServicePlanDocumentV2 {
                    image_reference: format!("{BENTOPDF_IMAGE_REFERENCE}@{BENTOPDF_IMAGE_DIGEST}"),
                    ..web_service()
                },
            ),
            (
                "the entrypoint reference",
                WebServicePlanDocumentV2 {
                    image_reference: ENTRYPOINT_IMAGE_REFERENCE.into(),
                    ..web_service()
                },
            ),
            (
                "the entrypoint digest",
                WebServicePlanDocumentV2 {
                    image_digest: ENTRYPOINT_IMAGE_DIGEST.into(),
                    ..web_service()
                },
            ),
            (
                "another pinned digest",
                WebServicePlanDocumentV2 {
                    image_digest: OTHER_PINNED_DIGEST.into(),
                    ..web_service()
                },
            ),
            (
                "upper-case digest",
                WebServicePlanDocumentV2 {
                    image_digest: BENTOPDF_IMAGE_DIGEST.to_ascii_uppercase(),
                    ..web_service()
                },
            ),
            (
                "unprefixed digest",
                WebServicePlanDocumentV2 {
                    image_digest: BENTOPDF_IMAGE_DIGEST.trim_start_matches("sha256:").into(),
                    ..web_service()
                },
            ),
            (
                "other digest algorithm",
                WebServicePlanDocumentV2 {
                    image_digest: format!(
                        "sha512:{}",
                        BENTOPDF_IMAGE_DIGEST.trim_start_matches("sha256:")
                    ),
                    ..web_service()
                },
            ),
            (
                "short digest",
                WebServicePlanDocumentV2 {
                    image_digest: "sha256:a4ed".into(),
                    ..web_service()
                },
            ),
            (
                "port below the range",
                WebServicePlanDocumentV2 {
                    local_port: MIN_PLAN_LOCAL_PORT - 1,
                    ..web_service()
                },
            ),
            (
                "privileged port",
                WebServicePlanDocumentV2 {
                    local_port: 443,
                    ..web_service()
                },
            ),
            (
                "absent port",
                WebServicePlanDocumentV2 {
                    local_port: 0,
                    ..web_service()
                },
            ),
            (
                "port above the range",
                WebServicePlanDocumentV2 {
                    local_port: MAX_PLAN_LOCAL_PORT + 1,
                    ..web_service()
                },
            ),
            (
                "port beyond sixteen bits",
                WebServicePlanDocumentV2 {
                    local_port: 70_000,
                    ..web_service()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the entrypoint group. The entrypoint has the
    /// shortest field list of the palier, so most of its surface is what it must
    /// refuse to carry.
    #[test]
    fn decoding_refuses_every_entrypoint_document_outside_the_contract() {
        assert!(decode_plan_v2_document(ENTRYPOINT_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(ENTRYPOINT_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        for (name, hostile_document) in [
            (
                "schema 1 version",
                EntrypointPlanDocumentV2 {
                    schema_version: 1,
                    ..entrypoint()
                },
            ),
            (
                "non version 4 UUID",
                EntrypointPlanDocumentV2 {
                    infrastructure_id: "8f14e45f-ceea-1167-a8b1-1f7bd0a0f4c2".into(),
                    ..entrypoint()
                },
            ),
            (
                "too short machine",
                EntrypointPlanDocumentV2 {
                    machine_id: "ab".into(),
                    ..entrypoint()
                },
            ),
            (
                "service operation",
                EntrypointPlanDocumentV2 {
                    operation: PlanV2Operation::DeployWebService,
                    ..entrypoint()
                },
            ),
            (
                "route operation",
                EntrypointPlanDocumentV2 {
                    operation: PlanV2Operation::RetireRoute,
                    ..entrypoint()
                },
            ),
            (
                "the service reference",
                EntrypointPlanDocumentV2 {
                    image_reference: BENTOPDF_IMAGE_REFERENCE.into(),
                    ..entrypoint()
                },
            ),
            (
                "the service digest",
                EntrypointPlanDocumentV2 {
                    image_digest: BENTOPDF_IMAGE_DIGEST.into(),
                    ..entrypoint()
                },
            ),
            (
                "another pinned digest",
                EntrypointPlanDocumentV2 {
                    image_digest: OTHER_PINNED_DIGEST.into(),
                    ..entrypoint()
                },
            ),
            (
                "tagged reference",
                EntrypointPlanDocumentV2 {
                    image_reference: format!("{ENTRYPOINT_IMAGE_REFERENCE}:latest"),
                    ..entrypoint()
                },
            ),
            (
                "registry-less reference",
                EntrypointPlanDocumentV2 {
                    image_reference: "library/traefik".into(),
                    ..entrypoint()
                },
            ),
            (
                "unprefixed digest",
                EntrypointPlanDocumentV2 {
                    image_digest: ENTRYPOINT_IMAGE_DIGEST.trim_start_matches("sha256:").into(),
                    ..entrypoint()
                },
            ),
            (
                "upper-case digest algorithm",
                EntrypointPlanDocumentV2 {
                    image_digest: format!(
                        "SHA256:{}",
                        ENTRYPOINT_IMAGE_DIGEST.trim_start_matches("sha256:")
                    ),
                    ..entrypoint()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the route group, and the whole surface of
    /// `route_host`.
    ///
    /// A host outside these bounds never reaches a fragment of the entrypoint,
    /// which is why the bound is here and not in whatever writes the fragment.
    #[test]
    fn decoding_refuses_every_route_document_outside_the_contract() {
        assert!(decode_plan_v2_document(ROUTE_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(ROUTE_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        // The bounds themselves are accepted, so that the refusals below name a
        // malformation rather than an off-by-one.
        for (name, host) in [
            ("shortest accepted name", "abc".to_owned()),
            ("longest accepted name", format!("{}.test", "a".repeat(248))),
            (
                "punycode label",
                "xn--bcher-kva.lab.your-cloud.test".to_owned(),
            ),
            ("digits only", "127.0.0.1".to_owned()),
        ] {
            let accepted = RoutePlanDocumentV2 {
                route_host: host,
                ..route()
            };
            assert!(
                decode_plan_v2_document(hostile(&accepted).as_bytes()).is_ok(),
                "{name} was refused"
            );
        }
        for port in [MIN_PLAN_BACKEND_PORT, MAX_PLAN_BACKEND_PORT] {
            let accepted = RoutePlanDocumentV2 {
                backend_port: port,
                ..route()
            };
            assert!(
                decode_plan_v2_document(hostile(&accepted).as_bytes()).is_ok(),
                "the bound {port} of the backend range was refused"
            );
        }

        for (name, host) in [
            ("empty host", String::new()),
            ("host below the bound", "ab".to_owned()),
            ("host above the bound", format!("{}.test", "a".repeat(249))),
            ("wildcard host", "*.lab.your-cloud.test".to_owned()),
            ("bare wildcard", "*".to_owned()),
            ("upper-case host", "BentoPDF.lab.your-cloud.test".to_owned()),
            ("leading dot", ".lab.your-cloud.test".to_owned()),
            ("trailing dot", "bentopdf.lab.your-cloud.test.".to_owned()),
            ("leading hyphen", "-bentopdf.lab.your-cloud.test".to_owned()),
            (
                "trailing hyphen",
                "bentopdf.lab.your-cloud.test-".to_owned(),
            ),
            (
                "consecutive dots",
                "bentopdf..lab.your-cloud.test".to_owned(),
            ),
            ("empty label at the start", "..test".to_owned()),
            (
                "underscore host",
                "bento_pdf.lab.your-cloud.test".to_owned(),
            ),
            (
                "host carrying a port",
                "bentopdf.lab.your-cloud.test:443".to_owned(),
            ),
            (
                "host carrying a path",
                "bentopdf.lab.your-cloud.test/pdf".to_owned(),
            ),
            (
                "host carrying a routing rule",
                "bentopdf.lab.test`)||Host(`evil.test".to_owned(),
            ),
            (
                "host carrying a space",
                "bentopdf lab.your-cloud.test".to_owned(),
            ),
            (
                "host carrying a line break",
                "bentopdf.lab.test\nevil.test".to_owned(),
            ),
            ("non ASCII host", "bücher.lab.your-cloud.test".to_owned()),
            (
                "host carrying a trailing NUL",
                "bentopdf.lab.your-cloud.test\0".to_owned(),
            ),
        ] {
            let hostile_document = RoutePlanDocumentV2 {
                route_host: host,
                ..route()
            };
            assert_eq!(
                decode_plan_v2_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }

        for (name, hostile_document) in [
            (
                "schema 1 version",
                RoutePlanDocumentV2 {
                    schema_version: 1,
                    ..route()
                },
            ),
            (
                "upper-case UUID",
                RoutePlanDocumentV2 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..route()
                },
            ),
            (
                "machine opening on a hyphen",
                RoutePlanDocumentV2 {
                    machine_id: "-lab-machine-1".into(),
                    ..route()
                },
            ),
            (
                "service operation",
                RoutePlanDocumentV2 {
                    operation: PlanV2Operation::RemoveWebService,
                    ..route()
                },
            ),
            (
                "entrypoint operation",
                RoutePlanDocumentV2 {
                    operation: PlanV2Operation::RemoveEntrypoint,
                    ..route()
                },
            ),
            (
                "backend below the range",
                RoutePlanDocumentV2 {
                    backend_port: MIN_PLAN_BACKEND_PORT - 1,
                    ..route()
                },
            ),
            (
                "privileged backend",
                RoutePlanDocumentV2 {
                    backend_port: 443,
                    ..route()
                },
            ),
            (
                "absent backend",
                RoutePlanDocumentV2 {
                    backend_port: 0,
                    ..route()
                },
            ),
            (
                "backend above the range",
                RoutePlanDocumentV2 {
                    backend_port: MAX_PLAN_BACKEND_PORT + 1,
                    ..route()
                },
            ),
            (
                "backend beyond sixteen bits",
                RoutePlanDocumentV2 {
                    backend_port: 70_000,
                    ..route()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the private service group, and the whole of what
    /// the private door refuses.
    #[test]
    fn decoding_refuses_every_private_service_document_outside_the_contract() {
        assert!(decode_plan_v2_document(PRIVATE_SERVICE_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(PRIVATE_SERVICE_ROLLBACK_DOCUMENT.as_bytes()).is_ok());

        for (name, hostile_document) in [
            (
                "schema 1 version",
                PrivateServicePlanDocumentV2 {
                    schema_version: 1,
                    ..private_service()
                },
            ),
            (
                "upper-case UUID",
                PrivateServicePlanDocumentV2 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..private_service()
                },
            ),
            (
                "traversal machine",
                PrivateServicePlanDocumentV2 {
                    machine_id: "../../etc/shadow".into(),
                    ..private_service()
                },
            ),
            (
                "the stateless deployment operation",
                PrivateServicePlanDocumentV2 {
                    operation: PlanV2Operation::DeployWebService,
                    ..private_service()
                },
            ),
            (
                "a link route operation",
                PrivateServicePlanDocumentV2 {
                    operation: PlanV2Operation::PublishLinkRoute,
                    ..private_service()
                },
            ),
            (
                "the stateless profile",
                PrivateServicePlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    ..private_service()
                },
            ),
            (
                "unknown profile",
                PrivateServicePlanDocumentV2 {
                    service_profile: "vaultwarden-simple".into(),
                    ..private_service()
                },
            ),
            (
                "upper-case profile",
                PrivateServicePlanDocumentV2 {
                    service_profile: "Vaultwarden".into(),
                    ..private_service()
                },
            ),
            (
                "empty profile",
                PrivateServicePlanDocumentV2 {
                    service_profile: String::new(),
                    ..private_service()
                },
            ),
            (
                "the stateless image",
                PrivateServicePlanDocumentV2 {
                    image_reference: BENTOPDF_IMAGE_REFERENCE.into(),
                    ..private_service()
                },
            ),
            (
                "the stateless digest",
                PrivateServicePlanDocumentV2 {
                    image_digest: BENTOPDF_IMAGE_DIGEST.into(),
                    ..private_service()
                },
            ),
            (
                "another registry",
                PrivateServicePlanDocumentV2 {
                    image_reference: "ghcr.io/vaultwarden/server".into(),
                    ..private_service()
                },
            ),
            (
                "tagged reference",
                PrivateServicePlanDocumentV2 {
                    image_reference: format!("{VAULTWARDEN_IMAGE_REFERENCE}:latest"),
                    ..private_service()
                },
            ),
            (
                "reference carrying its own digest",
                PrivateServicePlanDocumentV2 {
                    image_reference: format!(
                        "{VAULTWARDEN_IMAGE_REFERENCE}@{VAULTWARDEN_IMAGE_DIGEST}"
                    ),
                    ..private_service()
                },
            ),
            (
                // The manifest list is what the contract pins. The image it
                // resolves to on one architecture is a real digest of the same
                // repository, and it is refused: a plan names one pin, and
                // nothing may stand in for it.
                "the resolved amd64 digest",
                PrivateServicePlanDocumentV2 {
                    image_digest:
                        "sha256:e9efdf001bf0d68c21f2cbfb8e1d9b5961a7ca9c85e0a7e58bf51a13b997d744"
                            .into(),
                    ..private_service()
                },
            ),
            (
                "upper-case digest",
                PrivateServicePlanDocumentV2 {
                    image_digest: VAULTWARDEN_IMAGE_DIGEST.to_ascii_uppercase(),
                    ..private_service()
                },
            ),
            (
                "unprefixed digest",
                PrivateServicePlanDocumentV2 {
                    image_digest: VAULTWARDEN_IMAGE_DIGEST
                        .trim_start_matches("sha256:")
                        .into(),
                    ..private_service()
                },
            ),
            (
                "privileged port",
                PrivateServicePlanDocumentV2 {
                    local_port: 443,
                    ..private_service()
                },
            ),
            (
                "absent port",
                PrivateServicePlanDocumentV2 {
                    local_port: 0,
                    ..private_service()
                },
            ),
            (
                "port above the range",
                PrivateServicePlanDocumentV2 {
                    local_port: MAX_PLAN_LOCAL_PORT + 1,
                    ..private_service()
                },
            ),
            (
                "empty origin",
                PrivateServicePlanDocumentV2 {
                    origin_host: String::new(),
                    ..private_service()
                },
            ),
            (
                "wildcard origin",
                PrivateServicePlanDocumentV2 {
                    origin_host: "*.lab.your-cloud.test".into(),
                    ..private_service()
                },
            ),
            (
                "upper-case origin",
                PrivateServicePlanDocumentV2 {
                    origin_host: "Vault.lab.your-cloud.test".into(),
                    ..private_service()
                },
            ),
            (
                "origin carrying a scheme",
                PrivateServicePlanDocumentV2 {
                    origin_host: "https://vault.lab.your-cloud.test".into(),
                    ..private_service()
                },
            ),
            (
                "origin carrying a port",
                PrivateServicePlanDocumentV2 {
                    origin_host: "vault.lab.your-cloud.test:443".into(),
                    ..private_service()
                },
            ),
            (
                "origin carrying a path",
                PrivateServicePlanDocumentV2 {
                    origin_host: "vault.lab.your-cloud.test/vault".into(),
                    ..private_service()
                },
            ),
            (
                "origin with consecutive dots",
                PrivateServicePlanDocumentV2 {
                    origin_host: "vault..lab.your-cloud.test".into(),
                    ..private_service()
                },
            ),
            (
                "origin above the bound",
                PrivateServicePlanDocumentV2 {
                    origin_host: format!("{}.test", "a".repeat(249)),
                    ..private_service()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the link route group.
    ///
    /// The bound of the name and the bound of the port are the ones a route of
    /// the public profile is held to — the same function, not a second one that
    /// agrees today — so what this table adds is the operation surface of the
    /// group and the two bounds read again through it.
    #[test]
    fn decoding_refuses_every_link_route_document_outside_the_contract() {
        assert!(decode_plan_v2_document(LINK_ROUTE_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(LINK_ROUTE_ROLLBACK_DOCUMENT.as_bytes()).is_ok());
        for port in [MIN_PLAN_BACKEND_PORT, MAX_PLAN_BACKEND_PORT] {
            let accepted = LinkRoutePlanDocumentV2 {
                backend_port: port,
                ..link_route()
            };
            assert!(
                decode_plan_v2_document(hostile(&accepted).as_bytes()).is_ok(),
                "the bound {port} of the backend range was refused"
            );
        }

        for (name, hostile_document) in [
            (
                "schema 1 version",
                LinkRoutePlanDocumentV2 {
                    schema_version: 1,
                    ..link_route()
                },
            ),
            // A link route carrying the public route's operation is
            // deliberately NOT in this table: the two groups share their
            // whole field list, so that document is a well-formed public
            // route of the other group — refusing it here would contradict
            // the schema, and the Go side asserts the acceptance. What keeps
            // the two apart is the digest, held by
            // two_operations_carrying_the_same_fields_still_carry_two_digests.
            (
                "a private service operation",
                LinkRoutePlanDocumentV2 {
                    operation: PlanV2Operation::DeployPrivateService,
                    ..link_route()
                },
            ),
            (
                "wildcard host",
                LinkRoutePlanDocumentV2 {
                    route_host: "*.lab.your-cloud.test".into(),
                    ..link_route()
                },
            ),
            (
                "host carrying a routing rule",
                LinkRoutePlanDocumentV2 {
                    route_host: "vault.lab.test`)||Host(`evil.test".into(),
                    ..link_route()
                },
            ),
            (
                "empty host",
                LinkRoutePlanDocumentV2 {
                    route_host: String::new(),
                    ..link_route()
                },
            ),
            (
                "privileged backend",
                LinkRoutePlanDocumentV2 {
                    backend_port: 443,
                    ..link_route()
                },
            ),
            (
                "absent backend",
                LinkRoutePlanDocumentV2 {
                    backend_port: 0,
                    ..link_route()
                },
            ),
            (
                "backend above the range",
                LinkRoutePlanDocumentV2 {
                    backend_port: MAX_PLAN_BACKEND_PORT + 1,
                    ..link_route()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile(&hostile_document).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The whole surface of `snapshot_slot`, held on both shapes that carry one.
    ///
    /// A slot is one name inside the directory its profile owns, so the corpus
    /// below is what a file name may never be: a path, a climb, a dot, an upper
    /// case, a second spelling of the same archive. The bounds themselves are
    /// accepted first, so that each refusal names a malformation rather than an
    /// off-by-one.
    #[test]
    fn decoding_bounds_the_slot_an_archive_is_named_by() {
        assert!(decode_plan_v2_document(SNAPSHOT_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(SNAPSHOT_ROLLBACK_DOCUMENT.as_bytes()).is_ok());
        assert!(decode_plan_v2_document(RESTORE_PLAN_DOCUMENT.as_bytes()).is_ok());

        for (name, slot) in [
            ("shortest accepted slot", "a".to_owned()),
            ("longest accepted slot", "a".repeat(MAX_SNAPSHOT_SLOT_BYTES)),
            ("digits only", "20260806".to_owned()),
            ("inner hyphens", "before-the-migration".to_owned()),
        ] {
            let accepted = SnapshotPlanDocumentV2 {
                snapshot_slot: slot,
                ..snapshot()
            };
            assert!(
                decode_plan_v2_document(hostile(&accepted).as_bytes()).is_ok(),
                "{name} was refused"
            );
        }

        for (name, slot) in [
            ("empty slot", String::new()),
            (
                "slot above the bound",
                "a".repeat(MAX_SNAPSHOT_SLOT_BYTES + 1),
            ),
            ("upper-case slot", "Nightly".to_owned()),
            ("leading hyphen", "-nightly".to_owned()),
            ("dotted slot", "nightly.tar.gz".to_owned()),
            ("hidden slot", ".nightly".to_owned()),
            ("current directory", ".".to_owned()),
            ("parent directory", "..".to_owned()),
            ("traversal slot", "../../etc/shadow".to_owned()),
            (
                "absolute slot",
                "/var/lib/your-cloud-svc-vaultwarden".to_owned(),
            ),
            ("slot carrying a separator", "nightly/data".to_owned()),
            ("underscore slot", "nightly_data".to_owned()),
            ("slot carrying a space", "last good".to_owned()),
            ("slot carrying a NUL", "nightly\0".to_owned()),
            ("non ASCII slot", "sauvegardé".to_owned()),
        ] {
            for hostile_document in [
                hostile(&SnapshotPlanDocumentV2 {
                    snapshot_slot: slot.clone(),
                    ..snapshot()
                }),
                hostile(&RestorePlanDocumentV2 {
                    snapshot_slot: slot.clone(),
                    ..restore()
                }),
            ] {
                assert_eq!(
                    decode_plan_v2_document(hostile_document.as_bytes()),
                    Err(ProtocolError::InvalidInput),
                    "{name} was accepted"
                );
            }
        }
    }

    /// The reserved slot belongs to the return mechanism, and the two shapes
    /// that name a slot do not agree about it.
    ///
    /// A snapshot writing over it, or a discard destroying it, would be a plan
    /// that removes the possibility of returning, so both are refused whoever
    /// wrote the bytes. A restore naming it is the signed rollback of a restore —
    /// a plan in its own right, displayed, hashed, transported and decoded like
    /// any other — so it is accepted, and it is the one document of the product
    /// where that slot appears.
    #[test]
    fn the_reserved_slot_is_refused_everywhere_but_inside_a_restore() {
        for hostile_document in [
            hostile(&SnapshotPlanDocumentV2 {
                snapshot_slot: RESERVED_SNAPSHOT_SLOT.into(),
                ..snapshot()
            }),
            hostile(&SnapshotPlanDocumentV2 {
                operation: PlanV2Operation::DiscardSnapshot,
                snapshot_slot: RESERVED_SNAPSHOT_SLOT.into(),
                ..snapshot()
            }),
            SNAPSHOT_PLAN_DOCUMENT.replace(
                &format!(r#""snapshot_slot":"{SNAPSHOT_SLOT}""#),
                &format!(r#""snapshot_slot":"{RESERVED_SNAPSHOT_SLOT}""#),
            ),
            SNAPSHOT_ROLLBACK_DOCUMENT.replace(
                &format!(r#""snapshot_slot":"{SNAPSHOT_SLOT}""#),
                &format!(r#""snapshot_slot":"{RESERVED_SNAPSHOT_SLOT}""#),
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile_document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "an archive named the slot of the return mechanism"
            );
        }

        // Bounded like any other slot, and refused by the snapshot shape for
        // being that one rather than for being malformed: the corpus above
        // already accepted names of the same shape.
        assert!(canonical_snapshot_slot(RESERVED_SNAPSHOT_SLOT));
        let returned = decode_plan_v2_document(RESTORE_ROLLBACK_DOCUMENT.as_bytes())
            .expect("the one document that names the reserved slot");
        assert_eq!(returned.sha256().unwrap(), RESTORE_ROLLBACK_SHA256);
        assert_eq!(returned.operation(), PlanV2Operation::RestoreService);
    }

    /// The undoing of a restore moves a field instead of the operation.
    ///
    /// The document that returns from a restore is a restore of the reserved
    /// slot, because the flow writes the state it is about to replace there
    /// before replacing anything. It is the one place in this schema where the
    /// operation of a rollback equals the operation of its plan, and the one
    /// place where the two documents are told apart by a value rather than by a
    /// verb — which is exactly why the slot is inside the hashed bytes.
    #[test]
    fn the_undoing_of_a_restore_moves_the_slot_rather_than_the_operation() {
        let plan = decode_plan_v2_document(RESTORE_PLAN_DOCUMENT.as_bytes()).unwrap();
        let rollback = decode_plan_v2_document(RESTORE_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        assert_eq!(plan.operation(), rollback.operation());
        assert_eq!(
            PlanV2Operation::RestoreService.inverse(),
            PlanV2Operation::RestoreService
        );
        assert!(plan.is_undone_by(&rollback));
        assert_ne!(plan.sha256().unwrap(), rollback.sha256().unwrap());

        // The undoing of the undoing is itself: running a return of the reserved
        // slot twice leaves the machine where it started. That is honest, and it
        // is why a pair of two identical documents is not a pair.
        assert!(rollback.is_undone_by(&rollback));
        assert!(!rollback.is_undone_by(&plan));

        // Nothing else undoes it: not another slot, not another instance, not the
        // snapshot that carries the very same fields.
        for forged in [
            RestorePlanDocumentV2 {
                snapshot_slot: "weekly".into(),
                ..restore()
            },
            RestorePlanDocumentV2 {
                machine_id: "lab-machine-2".into(),
                ..restore().inverted()
            },
            RestorePlanDocumentV2 {
                infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                ..restore().inverted()
            },
            RestorePlanDocumentV2 {
                service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                ..restore().inverted()
            },
        ] {
            assert!(
                !restore().is_undone_by(&forged),
                "a rollback that targets another instance is not a rollback"
            );
        }
        assert!(
            !PlanDocumentV2::Restore(restore()).is_undone_by(&PlanDocumentV2::Snapshot(
                SnapshotPlanDocumentV2 {
                    operation: PlanV2Operation::DiscardSnapshot,
                    ..snapshot()
                }
            ))
        );

        // A snapshot, by contrast, is undone by the operation and not by the
        // slot: its archive is destroyed where it was written.
        assert!(snapshot().is_undone_by(&SnapshotPlanDocumentV2 {
            operation: PlanV2Operation::DiscardSnapshot,
            ..snapshot()
        }));
        assert!(!snapshot().is_undone_by(&SnapshotPlanDocumentV2 {
            operation: PlanV2Operation::DiscardSnapshot,
            snapshot_slot: "weekly".into(),
            ..snapshot()
        }));
    }

    /// The two lists of profiles are closed against one another, in both
    /// directions.
    ///
    /// A data-bearing service does not pass through the stateless door, and a
    /// stateless service does not pass through the private one. Each refusal is a
    /// lookup that fails rather than a comparison someone has to remember to
    /// write, and the archives close on the private list for a third reason: a
    /// profile without a persistent volume has nothing to archive.
    #[test]
    fn the_two_doors_of_the_palier_refuse_one_another_s_profile() {
        assert!(profile_image(SERVICE_PROFILE_BENTOPDF).is_some());
        assert!(profile_image(SERVICE_PROFILE_VAULTWARDEN).is_none());
        assert!(private_profile_image(SERVICE_PROFILE_VAULTWARDEN).is_some());
        assert!(private_profile_image(SERVICE_PROFILE_BENTOPDF).is_none());
        for unknown in ["vaultwarden-simple", "Vaultwarden", "", "bitwarden"] {
            assert!(
                private_profile_image(unknown).is_none(),
                "{unknown} was pinned"
            );
        }

        for (name, document) in [
            (
                "a data-bearing profile at the stateless door",
                hostile(&WebServicePlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_VAULTWARDEN.into(),
                    image_reference: VAULTWARDEN_IMAGE_REFERENCE.into(),
                    image_digest: VAULTWARDEN_IMAGE_DIGEST.into(),
                    ..web_service()
                }),
            ),
            (
                "a stateless profile at the private door",
                hostile(&PrivateServicePlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    image_reference: BENTOPDF_IMAGE_REFERENCE.into(),
                    image_digest: BENTOPDF_IMAGE_DIGEST.into(),
                    ..private_service()
                }),
            ),
            (
                "an archive of a profile that holds no data",
                hostile(&SnapshotPlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    ..snapshot()
                }),
            ),
            (
                "a return of a profile that holds no data",
                hostile(&RestorePlanDocumentV2 {
                    service_profile: SERVICE_PROFILE_BENTOPDF.into(),
                    ..restore()
                }),
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// The hostile table of the third door.
    ///
    /// Three of its fields name a definition this module never reads, so what is
    /// proven here is exactly what a document can be held to alone: the slug
    /// grammar the definition module owns — reserved names and all — the one
    /// spelling of a revision's digest, and the repository rule that refuses a
    /// tag on this side too. The origin is the one field accepted in two forms,
    /// and both are exercised; the rule that decides between them needs the
    /// definition, which this side never holds.
    #[test]
    fn decoding_refuses_every_user_service_document_outside_the_contract() {
        for document in [
            USER_SERVICE_PLAN_DOCUMENT,
            USER_SERVICE_ROLLBACK_DOCUMENT,
            MINIMAL_USER_PLAN_DOCUMENT,
            MINIMAL_USER_ROLLBACK_DOCUMENT,
        ] {
            assert!(
                decode_plan_v2_document(document.as_bytes()).is_ok(),
                "a nominal document was refused"
            );
        }

        // A document that leaves the empty origin out entirely is the same plan
        // under the same digest. That is the whole latitude a transport has over
        // the conditional field.
        let omitted = MINIMAL_USER_PLAN_DOCUMENT.replace(r##","origin_host":"""##, "");
        let decoded = decode_plan_v2_document(omitted.as_bytes())
            .expect("a document omitting an empty origin is the same plan");
        assert_eq!(decoded.sha256().unwrap(), MINIMAL_USER_PLAN_SHA256);
        assert_eq!(
            decoded,
            decode_plan_v2_document(MINIMAL_USER_PLAN_DOCUMENT.as_bytes()).unwrap()
        );

        for port in [MIN_PLAN_LOCAL_PORT, MAX_PLAN_LOCAL_PORT] {
            let accepted = UserServicePlanDocumentV2 {
                local_port: port,
                ..user_service()
            };
            assert!(
                decode_plan_v2_document(hostile(&accepted).as_bytes()).is_ok(),
                "the bound {port} of the port range was refused"
            );
        }

        for (name, moved) in [
            (
                "schema 1 version",
                UserServicePlanDocumentV2 {
                    schema_version: 1,
                    ..user_service()
                },
            ),
            (
                "absent schema",
                UserServicePlanDocumentV2 {
                    schema_version: 0,
                    ..user_service()
                },
            ),
            (
                "upper-case UUID",
                UserServicePlanDocumentV2 {
                    infrastructure_id: INFRASTRUCTURE.to_ascii_uppercase(),
                    ..user_service()
                },
            ),
            (
                "traversal machine",
                UserServicePlanDocumentV2 {
                    machine_id: "../../etc/shadow".into(),
                    ..user_service()
                },
            ),
            (
                "a private operation",
                UserServicePlanDocumentV2 {
                    operation: PlanV2Operation::DeployPrivateService,
                    ..user_service()
                },
            ),
            (
                "a stateless operation",
                UserServicePlanDocumentV2 {
                    operation: PlanV2Operation::DeployWebService,
                    ..user_service()
                },
            ),
            (
                "a snapshot operation",
                UserServicePlanDocumentV2 {
                    operation: PlanV2Operation::SnapshotService,
                    ..user_service()
                },
            ),
            // The four reserved names are the whole of what keeps one name
            // designating one door, and a plan may not spell them here any more
            // than a definition may take them.
            (
                "the stateless profile as a slug",
                UserServicePlanDocumentV2 {
                    definition_slug: SERVICE_PROFILE_BENTOPDF.into(),
                    ..user_service()
                },
            ),
            (
                "the private profile as a slug",
                UserServicePlanDocumentV2 {
                    definition_slug: SERVICE_PROFILE_VAULTWARDEN.into(),
                    ..user_service()
                },
            ),
            (
                "the probe's reserved name",
                UserServicePlanDocumentV2 {
                    definition_slug: "probe".into(),
                    ..user_service()
                },
            ),
            (
                "the entry's reserved name",
                UserServicePlanDocumentV2 {
                    definition_slug: "entrypoint".into(),
                    ..user_service()
                },
            ),
            (
                "an empty slug",
                UserServicePlanDocumentV2 {
                    definition_slug: String::new(),
                    ..user_service()
                },
            ),
            (
                "an upper-case slug",
                UserServicePlanDocumentV2 {
                    definition_slug: "Lab-Notes".into(),
                    ..user_service()
                },
            ),
            (
                "a slug one character too long",
                UserServicePlanDocumentV2 {
                    definition_slug: "a".repeat(MAX_SERVICE_SLUG_CHARS + 1),
                    ..user_service()
                },
            ),
            (
                "a dotted slug",
                UserServicePlanDocumentV2 {
                    definition_slug: "lab.notes".into(),
                    ..user_service()
                },
            ),
            (
                "a traversal slug",
                UserServicePlanDocumentV2 {
                    definition_slug: "../../etc".into(),
                    ..user_service()
                },
            ),
            (
                "a slug opening on a hyphen",
                UserServicePlanDocumentV2 {
                    definition_slug: "-lab-notes".into(),
                    ..user_service()
                },
            ),
            (
                "an empty definition digest",
                UserServicePlanDocumentV2 {
                    definition_digest: String::new(),
                    ..user_service()
                },
            ),
            (
                "an upper-case digest",
                UserServicePlanDocumentV2 {
                    definition_digest: USER_SERVICE_DEFINITION_DIGEST.to_ascii_uppercase(),
                    ..user_service()
                },
            ),
            (
                "a truncated digest",
                UserServicePlanDocumentV2 {
                    definition_digest: USER_SERVICE_DEFINITION_DIGEST[..63].into(),
                    ..user_service()
                },
            ),
            (
                // The two spellings are two names for one revision, and every
                // freeze, plan and lookup is keyed on exactly one of them.
                "a digest spelled as an OCI one",
                UserServicePlanDocumentV2 {
                    definition_digest: format!("sha256:{USER_SERVICE_DEFINITION_DIGEST}"),
                    ..user_service()
                },
            ),
            (
                "a non hexadecimal digest",
                UserServicePlanDocumentV2 {
                    definition_digest: "z".repeat(64),
                    ..user_service()
                },
            ),
            (
                "an empty repository",
                UserServicePlanDocumentV2 {
                    image_reference: String::new(),
                    ..user_service()
                },
            ),
            (
                "a repository carrying a tag",
                UserServicePlanDocumentV2 {
                    image_reference: format!("{USER_SERVICE_IMAGE_REFERENCE}:latest"),
                    ..user_service()
                },
            ),
            (
                "a repository carrying a digest",
                UserServicePlanDocumentV2 {
                    image_reference: format!(
                        "{USER_SERVICE_IMAGE_REFERENCE}@{USER_SERVICE_IMAGE_DIGEST}"
                    ),
                    ..user_service()
                },
            ),
            (
                "a repository with no registry",
                UserServicePlanDocumentV2 {
                    image_reference: "lab-notes".into(),
                    ..user_service()
                },
            ),
            (
                "an upper-case repository",
                UserServicePlanDocumentV2 {
                    image_reference: "registry.lab.your-cloud.test/Lab-Notes".into(),
                    ..user_service()
                },
            ),
            (
                "an empty image digest",
                UserServicePlanDocumentV2 {
                    image_digest: String::new(),
                    ..user_service()
                },
            ),
            (
                "a bare image digest",
                UserServicePlanDocumentV2 {
                    image_digest: "a".repeat(64),
                    ..user_service()
                },
            ),
            (
                "an upper-case image digest",
                UserServicePlanDocumentV2 {
                    image_digest: format!("sha256:{}", "A".repeat(64)),
                    ..user_service()
                },
            ),
            (
                "another digest algorithm",
                UserServicePlanDocumentV2 {
                    image_digest: format!("sha512:{}", "a".repeat(64)),
                    ..user_service()
                },
            ),
            (
                "a truncated image digest",
                UserServicePlanDocumentV2 {
                    image_digest: format!("sha256:{}", "a".repeat(63)),
                    ..user_service()
                },
            ),
            (
                "a privileged port",
                UserServicePlanDocumentV2 {
                    local_port: 443,
                    ..user_service()
                },
            ),
            (
                "an absent port",
                UserServicePlanDocumentV2 {
                    local_port: 0,
                    ..user_service()
                },
            ),
            (
                "a port above the range",
                UserServicePlanDocumentV2 {
                    local_port: MAX_PLAN_LOCAL_PORT + 1,
                    ..user_service()
                },
            ),
            (
                "a port beyond a sixteen bit one",
                UserServicePlanDocumentV2 {
                    local_port: 70_000,
                    ..user_service()
                },
            ),
            (
                "a wildcard origin",
                UserServicePlanDocumentV2 {
                    origin_host: "*.lab.your-cloud.test".into(),
                    ..user_service()
                },
            ),
            (
                "an upper-case origin",
                UserServicePlanDocumentV2 {
                    origin_host: "Notes.lab.your-cloud.test".into(),
                    ..user_service()
                },
            ),
            (
                "an origin with a trailing dot",
                UserServicePlanDocumentV2 {
                    origin_host: "notes.lab.your-cloud.test.".into(),
                    ..user_service()
                },
            ),
            (
                "an origin with empty labels",
                UserServicePlanDocumentV2 {
                    origin_host: "notes..lab.your-cloud.test".into(),
                    ..user_service()
                },
            ),
            (
                "an origin carrying a port",
                UserServicePlanDocumentV2 {
                    origin_host: "notes.lab.your-cloud.test:443".into(),
                    ..user_service()
                },
            ),
            (
                "an origin carrying a routing rule",
                UserServicePlanDocumentV2 {
                    origin_host: "notes.lab.test`)||Host(`evil.test".into(),
                    ..user_service()
                },
            ),
            (
                "an origin carrying a line break",
                UserServicePlanDocumentV2 {
                    origin_host: "notes.lab.test\nevil.test".into(),
                    ..user_service()
                },
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(hostile(&moved).as_bytes()),
                Err(ProtocolError::InvalidInput),
                "a user service naming {name} was accepted"
            );
            // The same malformation in the other direction, so that the removal
            // is never the looser of the two readings. The cases that move the
            // operation itself are already in the other direction and are left
            // alone rather than overwritten into a valid document.
            if moved.operation == PlanV2Operation::DeployUserService {
                let removal = UserServicePlanDocumentV2 {
                    operation: PlanV2Operation::RemoveUserService,
                    ..moved
                };
                assert_eq!(
                    decode_plan_v2_document(hostile(&removal).as_bytes()),
                    Err(ProtocolError::InvalidInput),
                    "a user service removal naming {name} was accepted"
                );
            }
        }

        // The operation itself is read before any of the above, so a name this
        // schema does not declare selects no shape at all.
        for document in [
            r#"{"operation":"start_user_service"}"#,
            r#"{"operation":"deploy_user_services"}"#,
        ] {
            assert_eq!(
                decode_plan_v2_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput)
            );
        }
    }

    /// The revision a vector pins really is the digest of the definition it
    /// names, computed here rather than copied.
    ///
    /// It is what makes the two contracts one: the plan module pins a value, the
    /// definition module derives it from its own transcript, and a byte moved in
    /// either fails here rather than producing plans that pin a revision nobody
    /// can produce.
    #[test]
    fn the_revision_a_user_service_pins_is_the_digest_of_its_definition() {
        for (document, digest, repository, slug) in [
            (
                REFERENCE_DEFINITION_DOCUMENT,
                USER_SERVICE_DEFINITION_DIGEST,
                USER_SERVICE_IMAGE_REFERENCE,
                USER_SERVICE_SLUG,
            ),
            (
                MINIMAL_DEFINITION_DOCUMENT,
                MINIMAL_DEFINITION_DIGEST,
                MINIMAL_IMAGE_REFERENCE,
                MINIMAL_SLUG,
            ),
        ] {
            let definition =
                crate::service_definition::decode_service_definition_document(document.as_bytes())
                    .expect("the pinned definition is inside its own contract");
            assert_eq!(definition.sha256().unwrap(), digest);
            assert_eq!(definition.encode().unwrap(), document);
            assert_eq!(definition.slug, slug);
            assert_eq!(definition.image_repository, repository);
        }

        // And a revision that changes one byte is another revision, which is
        // what makes "each instance shows the exact revision it runs" a property
        // rather than a hope.
        let revised =
            MINIMAL_DEFINITION_DOCUMENT.replace(r#""container_port":80"#, r#""container_port":81"#);
        let revised =
            crate::service_definition::decode_service_definition_document(revised.as_bytes())
                .unwrap();
        assert_ne!(revised.sha256().unwrap(), MINIMAL_DEFINITION_DIGEST);
    }

    /// The three doors refuse one another in every direction.
    ///
    /// A definition passes through no door of the delivered profiles, and a
    /// delivered profile passes through no door of the definitions. The refusal
    /// is a lookup that fails rather than a comparison anyone had to write, and
    /// it is the reservation of the four names at the source that makes it so.
    #[test]
    fn the_three_doors_refuse_one_another_in_every_direction() {
        for slug in [USER_SERVICE_SLUG, MINIMAL_SLUG, "blog"] {
            for document in [
                hostile(&WebServicePlanDocumentV2 {
                    service_profile: slug.into(),
                    ..web_service()
                }),
                hostile(&PrivateServicePlanDocumentV2 {
                    service_profile: slug.into(),
                    ..private_service()
                }),
            ] {
                assert_eq!(
                    decode_plan_v2_document(document.as_bytes()),
                    Err(ProtocolError::InvalidInput),
                    "a delivered door accepted the definition {slug}"
                );
            }
            assert!(profile_image(slug).is_none(), "{slug} was pinned");
            assert!(private_profile_image(slug).is_none(), "{slug} was pinned");
        }
        for profile in [SERVICE_PROFILE_BENTOPDF, SERVICE_PROFILE_VAULTWARDEN] {
            assert_eq!(
                decode_plan_v2_document(
                    hostile(&UserServicePlanDocumentV2 {
                        definition_slug: profile.into(),
                        ..user_service()
                    })
                    .as_bytes()
                ),
                Err(ProtocolError::InvalidInput),
                "the third door accepted the delivered profile {profile}"
            );
            // And no definition can ever be written under that name, so no
            // frozen definition can carry it either.
            assert!(!canonical_definition_slug(profile));
        }
    }

    /// The archives open to the third door without changing shape.
    ///
    /// `service_profile` is the one field two doors share: it holds a profile of
    /// the private door's closed list or the slug of a user service definition,
    /// and the four reserved names are what keeps the two readings from ever
    /// naming the same thing. What a slug is admitted as here is a well-formed
    /// name and nothing more — whether a service by that name was ever deployed
    /// is a fact of a machine this side reads nowhere.
    #[test]
    fn an_archive_names_a_delivered_profile_or_a_definition_and_nothing_else() {
        for name in [USER_SERVICE_SLUG, MINIMAL_SLUG, "a", &"a".repeat(16)] {
            for document in [
                hostile(&SnapshotPlanDocumentV2 {
                    service_profile: name.into(),
                    ..snapshot()
                }),
                hostile(&SnapshotPlanDocumentV2 {
                    operation: PlanV2Operation::DiscardSnapshot,
                    service_profile: name.into(),
                    ..snapshot()
                }),
                hostile(&RestorePlanDocumentV2 {
                    service_profile: name.into(),
                    ..restore()
                }),
            ] {
                assert!(
                    decode_plan_v2_document(document.as_bytes()).is_ok(),
                    "an archive of the definition {name} was refused"
                );
            }
        }

        for name in [
            SERVICE_PROFILE_BENTOPDF,
            "probe",
            "entrypoint",
            "vaultwarden-lite-2",
            "Vaultwarden",
            "vault.warden",
            "../../etc",
            "",
        ] {
            for document in [
                hostile(&SnapshotPlanDocumentV2 {
                    service_profile: name.into(),
                    ..snapshot()
                }),
                hostile(&RestorePlanDocumentV2 {
                    service_profile: name.into(),
                    ..restore()
                }),
            ] {
                assert_eq!(
                    decode_plan_v2_document(document.as_bytes()),
                    Err(ProtocolError::InvalidInput),
                    "an archive named {name}"
                );
            }
        }

        // The existing vectors are untouched by the widening: a profile of the
        // private door is still found in the closed list rather than read as a
        // slug that happens to be spelled the same.
        assert!(archives_data(SERVICE_PROFILE_VAULTWARDEN));
        assert!(private_profile_image(SERVICE_PROFILE_VAULTWARDEN).is_some());
        assert_eq!(
            decode_plan_v2_document(SNAPSHOT_PLAN_DOCUMENT.as_bytes())
                .unwrap()
                .sha256()
                .unwrap(),
            SNAPSHOT_PLAN_SHA256
        );
    }

    /// Every operation of this schema decodes into its own shape, held against
    /// the declared list rather than against a table a reader has to keep in
    /// step with it.
    ///
    /// An operation added to [`DECLARED_OPERATIONS`] without a canonical
    /// document here fails on the count; one added without a decoding case falls
    /// through the decoder's own refusal; and one whose case builds the wrong
    /// shape fails on the assertion. The three failures are the three ways a
    /// closed registry can be left half-extended.
    #[test]
    fn every_schema_two_operation_decodes_into_its_own_shape() {
        let documents = [
            (
                PlanV2Operation::DeployWebService,
                WEB_SERVICE_PLAN_DOCUMENT,
                "WebService",
            ),
            (
                PlanV2Operation::RemoveWebService,
                WEB_SERVICE_ROLLBACK_DOCUMENT,
                "WebService",
            ),
            (
                PlanV2Operation::DeployEntrypoint,
                ENTRYPOINT_PLAN_DOCUMENT,
                "Entrypoint",
            ),
            (
                PlanV2Operation::RemoveEntrypoint,
                ENTRYPOINT_ROLLBACK_DOCUMENT,
                "Entrypoint",
            ),
            (PlanV2Operation::PublishRoute, ROUTE_PLAN_DOCUMENT, "Route"),
            (
                PlanV2Operation::RetireRoute,
                ROUTE_ROLLBACK_DOCUMENT,
                "Route",
            ),
            (
                PlanV2Operation::DeployPrivateService,
                PRIVATE_SERVICE_PLAN_DOCUMENT,
                "PrivateService",
            ),
            (
                PlanV2Operation::RemovePrivateService,
                PRIVATE_SERVICE_ROLLBACK_DOCUMENT,
                "PrivateService",
            ),
            (
                PlanV2Operation::PublishLinkRoute,
                LINK_ROUTE_PLAN_DOCUMENT,
                "LinkRoute",
            ),
            (
                PlanV2Operation::RetireLinkRoute,
                LINK_ROUTE_ROLLBACK_DOCUMENT,
                "LinkRoute",
            ),
            (
                PlanV2Operation::SnapshotService,
                SNAPSHOT_PLAN_DOCUMENT,
                "Snapshot",
            ),
            (
                PlanV2Operation::DiscardSnapshot,
                SNAPSHOT_ROLLBACK_DOCUMENT,
                "Snapshot",
            ),
            (
                PlanV2Operation::RestoreService,
                RESTORE_PLAN_DOCUMENT,
                "Restore",
            ),
            (
                PlanV2Operation::DeployUserService,
                USER_SERVICE_PLAN_DOCUMENT,
                "UserService",
            ),
            (
                PlanV2Operation::RemoveUserService,
                USER_SERVICE_ROLLBACK_DOCUMENT,
                "UserService",
            ),
        ];
        assert_eq!(
            documents.len(),
            DECLARED_OPERATIONS.len(),
            "this table covers {} operations and the schema declares {}",
            documents.len(),
            DECLARED_OPERATIONS.len()
        );
        for operation in DECLARED_OPERATIONS {
            let (_, document, shape) = documents
                .iter()
                .find(|(covered, _, _)| *covered == operation)
                .unwrap_or_else(|| {
                    panic!("operation {operation:?} has no canonical document in this table")
                });
            let decoded = decode_plan_v2_document(document.as_bytes())
                .unwrap_or_else(|_| panic!("operation {operation:?} does not decode"));
            assert_eq!(decoded.operation(), operation);
            assert_eq!(
                shape_name(&decoded),
                *shape,
                "operation {operation:?} decoded into another shape"
            );
            assert_eq!(decoded.group(), operation.group());
        }
    }

    /// What the discriminator exists for.
    ///
    /// The operation is read first, and the document is then held against
    /// exactly the closed field list that operation declares. A field belonging
    /// to another operation is an unknown field of the claimed schema, refused
    /// before its value is read — the strongest form the refusal can take, since
    /// it does not depend on understanding what was smuggled in.
    #[test]
    fn no_schema_two_document_borrows_a_field_of_another_operation() {
        for (name, document) in [
            (
                "a service plan carrying a route host",
                with_extra_member(WEB_SERVICE_PLAN_DOCUMENT, r#""route_host":"evil.test""#),
            ),
            (
                "a service plan carrying a backend port",
                with_extra_member(WEB_SERVICE_PLAN_DOCUMENT, r#""backend_port":9090"#),
            ),
            (
                "an entrypoint plan carrying a port",
                with_extra_member(ENTRYPOINT_PLAN_DOCUMENT, r#""local_port":8080"#),
            ),
            (
                "an entrypoint plan carrying a host",
                with_extra_member(ENTRYPOINT_PLAN_DOCUMENT, r#""route_host":"evil.test""#),
            ),
            (
                "an entrypoint plan carrying a profile",
                with_extra_member(ENTRYPOINT_PLAN_DOCUMENT, r#""service_profile":"bentopdf""#),
            ),
            (
                "a route plan carrying an image digest",
                with_extra_member(
                    ROUTE_PLAN_DOCUMENT,
                    &format!(r#""image_digest":"{BENTOPDF_IMAGE_DIGEST}""#),
                ),
            ),
            (
                "a route plan carrying an image",
                with_extra_member(
                    ROUTE_PLAN_DOCUMENT,
                    &format!(r#""image_reference":"{BENTOPDF_IMAGE_REFERENCE}""#),
                ),
            ),
            (
                "a route plan carrying a profile",
                with_extra_member(ROUTE_PLAN_DOCUMENT, r#""service_profile":"bentopdf""#),
            ),
            (
                "a route plan carrying a local port",
                with_extra_member(ROUTE_PLAN_DOCUMENT, r#""local_port":8080"#),
            ),
            (
                "a service plan claiming a route",
                WEB_SERVICE_PLAN_DOCUMENT.replace(r#""deploy_web_service""#, r#""publish_route""#),
            ),
            (
                "a route plan claiming a service",
                ROUTE_PLAN_DOCUMENT.replace(r#""publish_route""#, r#""deploy_web_service""#),
            ),
            (
                "an entrypoint plan claiming a service",
                ENTRYPOINT_PLAN_DOCUMENT
                    .replace(r#""deploy_entrypoint""#, r#""deploy_web_service""#),
            ),
            (
                "a service plan claiming an entrypoint",
                WEB_SERVICE_PLAN_DOCUMENT
                    .replace(r#""deploy_web_service""#, r#""deploy_entrypoint""#),
            ),
            (
                "a service plan without its profile",
                WEB_SERVICE_PLAN_DOCUMENT.replace(r#""service_profile":"bentopdf","#, ""),
            ),
            (
                "a service plan without its port",
                WEB_SERVICE_PLAN_DOCUMENT.replace(r#","local_port":8080"#, ""),
            ),
            (
                "a route plan without its host",
                ROUTE_PLAN_DOCUMENT.replace(r#""route_host":"bentopdf.lab.your-cloud.test","#, ""),
            ),
            (
                "an entrypoint plan without its image",
                ENTRYPOINT_PLAN_DOCUMENT
                    .replace(r#""image_reference":"docker.io/library/traefik","#, ""),
            ),
            (
                "a private service plan carrying a slot",
                with_extra_member(
                    PRIVATE_SERVICE_PLAN_DOCUMENT,
                    r#""snapshot_slot":"nightly""#,
                ),
            ),
            (
                "a private service plan carrying a volume",
                with_extra_member(
                    PRIVATE_SERVICE_PLAN_DOCUMENT,
                    r#""volumes":["/var/lib/evil:/data"]"#,
                ),
            ),
            (
                "a private service plan carrying environment lines",
                with_extra_member(
                    PRIVATE_SERVICE_PLAN_DOCUMENT,
                    r#""environment":["SIGNUPS_ALLOWED=true"]"#,
                ),
            ),
            (
                "a stateless plan carrying an origin",
                with_extra_member(
                    WEB_SERVICE_PLAN_DOCUMENT,
                    r#""origin_host":"vault.lab.your-cloud.test""#,
                ),
            ),
            (
                "a link route carrying a profile",
                with_extra_member(
                    LINK_ROUTE_PLAN_DOCUMENT,
                    r#""service_profile":"vaultwarden""#,
                ),
            ),
            (
                "a link route carrying a backend address",
                with_extra_member(
                    LINK_ROUTE_PLAN_DOCUMENT,
                    r#""backend_address":"10.66.66.2""#,
                ),
            ),
            (
                "a snapshot carrying an archive digest",
                with_extra_member(
                    SNAPSHOT_PLAN_DOCUMENT,
                    &format!(r#""archive_digest":"{OTHER_PINNED_DIGEST}""#),
                ),
            ),
            (
                "a snapshot carrying a path",
                with_extra_member(
                    SNAPSHOT_PLAN_DOCUMENT,
                    r#""snapshot_path":"/tmp/evil.tar.gz""#,
                ),
            ),
            (
                "a restore carrying a second direction",
                with_extra_member(RESTORE_PLAN_DOCUMENT, r#""forward":true"#),
            ),
            (
                "a private service plan without its origin",
                PRIVATE_SERVICE_PLAN_DOCUMENT
                    .replace(r#","origin_host":"vault.lab.your-cloud.test""#, ""),
            ),
            (
                "a snapshot without its slot",
                SNAPSHOT_PLAN_DOCUMENT.replace(r#","snapshot_slot":"nightly""#, ""),
            ),
            (
                "a restore without its profile",
                RESTORE_PLAN_DOCUMENT.replace(r#""service_profile":"vaultwarden","#, ""),
            ),
            (
                "a link route claiming a private deployment",
                LINK_ROUTE_PLAN_DOCUMENT
                    .replace(r#""publish_link_route""#, r#""deploy_private_service""#),
            ),
            (
                "a snapshot claiming a private deployment",
                SNAPSHOT_PLAN_DOCUMENT
                    .replace(r#""snapshot_service""#, r#""deploy_private_service""#),
            ),
            (
                "a private deployment claiming a snapshot",
                PRIVATE_SERVICE_PLAN_DOCUMENT
                    .replace(r#""deploy_private_service""#, r#""snapshot_service""#),
            ),
            ("a schema 1 probe plan", PROBE_PLAN_DOCUMENT.to_owned()),
            (
                "a document with no operation",
                ROUTE_PLAN_DOCUMENT.replace(r#""operation":"publish_route","#, ""),
            ),
            (
                "a document naming a number as its operation",
                ROUTE_PLAN_DOCUMENT.replace(r#""operation":"publish_route""#, r#""operation":2"#),
            ),
            (
                "a document naming null as its operation",
                ROUTE_PLAN_DOCUMENT
                    .replace(r#""operation":"publish_route""#, r#""operation":null"#),
            ),
            (
                "a document naming an object as its operation",
                ROUTE_PLAN_DOCUMENT.replace(
                    r#""operation":"publish_route""#,
                    r#""operation":{"name":"publish_route"}"#,
                ),
            ),
            (
                "a document naming an upper-case operation",
                ROUTE_PLAN_DOCUMENT.replace(
                    r#""operation":"publish_route""#,
                    r#""operation":"PUBLISH_ROUTE""#,
                ),
            ),
            (
                "a document naming an unknown operation",
                ROUTE_PLAN_DOCUMENT.replace(
                    r#""operation":"publish_route""#,
                    r#""operation":"publish_ingress""#,
                ),
            ),
            (
                "a document repeating its operation",
                with_extra_member(ROUTE_PLAN_DOCUMENT, r#""operation":"retire_route""#),
            ),
            (
                "a document repeating a bounded field",
                with_extra_member(ROUTE_PLAN_DOCUMENT, r#""backend_port":9090"#),
            ),
            (
                "a document with a non-canonical field name",
                ROUTE_PLAN_DOCUMENT.replace(r#""route_host""#, r#""Route_Host""#),
            ),
            (
                "a document with a camel-case field name",
                ROUTE_PLAN_DOCUMENT.replace(r#""backend_port""#, r#""backendPort""#),
            ),
            (
                "a document with a stringified port",
                ROUTE_PLAN_DOCUMENT.replace(r#""backend_port":8080"#, r#""backend_port":"8080""#),
            ),
            (
                "a document with a fractional port",
                ROUTE_PLAN_DOCUMENT.replace(r#""backend_port":8080"#, r#""backend_port":8080.5"#),
            ),
            (
                "a document with an exponent port",
                ROUTE_PLAN_DOCUMENT.replace(r#""backend_port":8080"#, r#""backend_port":8.08e3"#),
            ),
            (
                "a document with a negative port",
                ROUTE_PLAN_DOCUMENT.replace(r#""backend_port":8080"#, r#""backend_port":-1"#),
            ),
            (
                "a document carrying a command",
                with_extra_member(WEB_SERVICE_PLAN_DOCUMENT, r#""command":"/bin/sh""#),
            ),
            (
                "a document carrying a volume",
                with_extra_member(WEB_SERVICE_PLAN_DOCUMENT, r#""volumes":["/etc:/etc"]"#),
            ),
            (
                "a document carrying a privilege",
                with_extra_member(ENTRYPOINT_PLAN_DOCUMENT, r#""privileged":true"#),
            ),
            (
                "a document carrying a tag",
                with_extra_member(ENTRYPOINT_PLAN_DOCUMENT, r#""tag":"latest""#),
            ),
            (
                "a document carrying middleware headers",
                with_extra_member(
                    ROUTE_PLAN_DOCUMENT,
                    r#""headers":{"X-Forwarded-For":"1.2.3.4"}"#,
                ),
            ),
            (
                "a document carrying a TLS certificate",
                with_extra_member(
                    ROUTE_PLAN_DOCUMENT,
                    r#""tls_certificate":"-----BEGIN CERTIFICATE-----""#,
                ),
            ),
            // The third door names a definition where the two others name a
            // profile, so a field of either vocabulary crossing into the other
            // is the whole of what this group has to refuse — and it is refused
            // as an unknown field of the shape the operation selected, before
            // its value is read.
            (
                "a user service carrying a profile",
                with_extra_member(
                    USER_SERVICE_PLAN_DOCUMENT,
                    r#""service_profile":"vaultwarden""#,
                ),
            ),
            (
                "a user service carrying a slot",
                with_extra_member(USER_SERVICE_PLAN_DOCUMENT, r#""snapshot_slot":"nightly""#),
            ),
            (
                "a user service carrying a route host",
                with_extra_member(USER_SERVICE_PLAN_DOCUMENT, r#""route_host":"evil.test""#),
            ),
            (
                "a user service carrying a volume",
                with_extra_member(USER_SERVICE_PLAN_DOCUMENT, r#""volumes":["/srv/notes"]"#),
            ),
            (
                "a user service carrying environment",
                with_extra_member(
                    USER_SERVICE_PLAN_DOCUMENT,
                    r#""environment":["LAB_NOTES_TITLE=x"]"#,
                ),
            ),
            (
                "a user service carrying a secret",
                with_extra_member(
                    USER_SERVICE_PLAN_DOCUMENT,
                    r#""secrets":{"LAB_NOTES_ADMIN_TOKEN":"hunter2"}"#,
                ),
            ),
            (
                "a user service carrying a host path",
                with_extra_member(
                    USER_SERVICE_PLAN_DOCUMENT,
                    r#""home":"/var/lib/your-cloud-user-lab-notes""#,
                ),
            ),
            (
                "a user service carrying an account",
                with_extra_member(USER_SERVICE_PLAN_DOCUMENT, r#""account":"root""#),
            ),
            (
                "a user service carrying the definition itself",
                with_extra_member(USER_SERVICE_PLAN_DOCUMENT, r#""definition_document":"{}""#),
            ),
            (
                "a user service repeating its origin",
                with_extra_member(USER_SERVICE_PLAN_DOCUMENT, r#""origin_host":"evil.test""#),
            ),
            (
                "a user service repeating its revision",
                with_extra_member(
                    USER_SERVICE_PLAN_DOCUMENT,
                    &format!(r#""definition_digest":"{MINIMAL_DEFINITION_DIGEST}""#),
                ),
            ),
            (
                "a user service without its slug",
                USER_SERVICE_PLAN_DOCUMENT
                    .replace(&format!(r#""definition_slug":"{USER_SERVICE_SLUG}","#), ""),
            ),
            (
                "a user service without its revision",
                USER_SERVICE_PLAN_DOCUMENT.replace(
                    &format!(r#""definition_digest":"{USER_SERVICE_DEFINITION_DIGEST}","#),
                    "",
                ),
            ),
            (
                "a user service without its image",
                USER_SERVICE_PLAN_DOCUMENT.replace(
                    &format!(r#""image_reference":"{USER_SERVICE_IMAGE_REFERENCE}","#),
                    "",
                ),
            ),
            (
                "a user service claiming the private door",
                USER_SERVICE_PLAN_DOCUMENT
                    .replace(r#""deploy_user_service""#, r#""deploy_private_service""#),
            ),
            (
                "a private service claiming the third door",
                PRIVATE_SERVICE_PLAN_DOCUMENT
                    .replace(r#""deploy_private_service""#, r#""deploy_user_service""#),
            ),
            (
                "a snapshot claiming the third door",
                SNAPSHOT_PLAN_DOCUMENT.replace(r#""snapshot_service""#, r#""deploy_user_service""#),
            ),
            (
                "an oversized user service origin",
                USER_SERVICE_PLAN_DOCUMENT.replace(
                    USER_SERVICE_ORIGIN_HOST,
                    &"a".repeat(MAX_PLAN_DOCUMENT_BYTES),
                ),
            ),
            ("an empty document", String::new()),
            ("two values", format!("{ROUTE_PLAN_DOCUMENT}{{}}")),
            ("an array of documents", format!("[{ROUTE_PLAN_DOCUMENT}]")),
            (
                "a truncated document",
                ROUTE_PLAN_DOCUMENT.trim_end_matches('}').to_owned(),
            ),
            (
                "an oversized document",
                ROUTE_PLAN_DOCUMENT.replace(ROUTE_HOST, &"a".repeat(MAX_PLAN_DOCUMENT_BYTES)),
            ),
            (
                "a document that is only its operation",
                r#"{"operation":"publish_route"}"#.to_owned(),
            ),
            (
                "a document whose operation belongs to schema 1",
                r#"{"operation":"deploy_oci_probe"}"#.to_owned(),
            ),
        ] {
            assert_eq!(
                decode_plan_v2_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }
    }

    /// Schema 1 stays exactly where it was.
    ///
    /// A probe plan decodes and hashes as it always did, and neither decoder
    /// accepts a document of the other schema: the version is not a hint, it
    /// selects which closed contract the document is held against.
    #[test]
    fn schema_one_and_schema_two_refuse_one_another() {
        for document in [
            WEB_SERVICE_PLAN_DOCUMENT,
            ENTRYPOINT_PLAN_DOCUMENT,
            ROUTE_PLAN_DOCUMENT,
            PRIVATE_SERVICE_PLAN_DOCUMENT,
            LINK_ROUTE_PLAN_DOCUMENT,
            SNAPSHOT_PLAN_DOCUMENT,
            RESTORE_PLAN_DOCUMENT,
            USER_SERVICE_PLAN_DOCUMENT,
        ] {
            assert_eq!(
                crate::plan::decode_plan_document(document.as_bytes()),
                Err(ProtocolError::InvalidInput),
                "the schema 1 decoder accepted a schema 2 document"
            );
        }
        assert!(crate::plan::decode_plan_document(PROBE_PLAN_DOCUMENT.as_bytes()).is_ok());
        assert_eq!(
            decode_plan_v2_document(PROBE_PLAN_DOCUMENT.as_bytes()),
            Err(ProtocolError::InvalidInput)
        );
        assert_ne!(
            PLAN_V2_TRANSCRIPT_DOMAIN,
            crate::plan::PLAN_TRANSCRIPT_DOMAIN
        );
        assert_ne!(PLAN_V2_SCHEMA_VERSION, crate::plan::PLAN_SCHEMA_VERSION);
    }

    /// The exact limit of what a transport may do: reshape the JSON, and only
    /// that. The digest is rebuilt from the fields, so a reindented, reordered
    /// document is the same plan, and a document with one value changed is not.
    #[test]
    fn a_reindented_document_is_the_same_plan() {
        for (reshaped, digest) in [
            (
                format!(
                    "{{\n  \"local_port\": {PORT},\n  \"image_digest\": \"{BENTOPDF_IMAGE_DIGEST}\",\n  \
                     \"image_reference\": \"{BENTOPDF_IMAGE_REFERENCE}\",\n  \
                     \"service_profile\": \"{SERVICE_PROFILE_BENTOPDF}\",\n  \
                     \"operation\": \"deploy_web_service\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                WEB_SERVICE_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"image_digest\": \"{ENTRYPOINT_IMAGE_DIGEST}\",\n  \
                     \"image_reference\": \"{ENTRYPOINT_IMAGE_REFERENCE}\",\n  \
                     \"operation\": \"deploy_entrypoint\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                ENTRYPOINT_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"backend_port\": {PORT},\n  \"route_host\": \"{ROUTE_HOST}\",\n  \
                     \"operation\": \"publish_route\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                ROUTE_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"origin_host\": \"{ORIGIN_HOST}\",\n  \"local_port\": {PORT},\n  \
                     \"image_digest\": \"{VAULTWARDEN_IMAGE_DIGEST}\",\n  \
                     \"image_reference\": \"{VAULTWARDEN_IMAGE_REFERENCE}\",\n  \
                     \"service_profile\": \"{SERVICE_PROFILE_VAULTWARDEN}\",\n  \
                     \"operation\": \"deploy_private_service\",\n  \
                     \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                PRIVATE_SERVICE_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"backend_port\": {PORT},\n  \"route_host\": \"{LINK_ROUTE_HOST}\",\n  \
                     \"operation\": \"publish_link_route\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                LINK_ROUTE_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"snapshot_slot\": \"{SNAPSHOT_SLOT}\",\n  \
                     \"service_profile\": \"{SERVICE_PROFILE_VAULTWARDEN}\",\n  \
                     \"operation\": \"snapshot_service\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                SNAPSHOT_PLAN_SHA256,
            ),
            (
                format!(
                    "{{\n  \"snapshot_slot\": \"{RESERVED_SNAPSHOT_SLOT}\",\n  \
                     \"service_profile\": \"{SERVICE_PROFILE_VAULTWARDEN}\",\n  \
                     \"operation\": \"restore_service\",\n  \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                RESTORE_ROLLBACK_SHA256,
            ),
            (
                format!(
                    "{{\n  \"origin_host\": \"{USER_SERVICE_ORIGIN_HOST}\",\n  \
                     \"local_port\": {PORT},\n  \
                     \"image_digest\": \"{USER_SERVICE_IMAGE_DIGEST}\",\n  \
                     \"image_reference\": \"{USER_SERVICE_IMAGE_REFERENCE}\",\n  \
                     \"definition_digest\": \"{USER_SERVICE_DEFINITION_DIGEST}\",\n  \
                     \"definition_slug\": \"{USER_SERVICE_SLUG}\",\n  \
                     \"operation\": \"deploy_user_service\",\n  \
                     \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                USER_SERVICE_PLAN_SHA256,
            ),
            (
                // A definition that consumes no origin leaves the field empty,
                // and a transport that drops it altogether carries the same
                // plan: the digest is rebuilt from the fields, and an absent
                // origin and an empty one are one value.
                format!(
                    "{{\n  \"local_port\": {MINIMAL_USER_PORT},\n  \
                     \"image_digest\": \"{MINIMAL_IMAGE_DIGEST}\",\n  \
                     \"image_reference\": \"{MINIMAL_IMAGE_REFERENCE}\",\n  \
                     \"definition_digest\": \"{MINIMAL_DEFINITION_DIGEST}\",\n  \
                     \"definition_slug\": \"{MINIMAL_SLUG}\",\n  \
                     \"operation\": \"deploy_user_service\",\n  \
                     \"machine_id\": \"{MACHINE}\",\n  \
                     \"infrastructure_id\": \"{INFRASTRUCTURE}\",\n  \"schema_version\": 2\n}}"
                ),
                MINIMAL_USER_PLAN_SHA256,
            ),
        ] {
            let reordered = decode_plan_v2_document(reshaped.as_bytes())
                .expect("a reindented document is the same plan");
            assert_eq!(reordered.sha256().unwrap(), digest);
            assert_eq!(
                verify_plan_v2_document(reshaped.as_bytes(), digest).unwrap(),
                reordered
            );
        }
    }

    /// A plan is only ever accepted beside the digest it really has.
    #[test]
    fn verification_refuses_a_document_its_digest_does_not_name() {
        assert_eq!(
            verify_plan_v2_document(ROUTE_PLAN_DOCUMENT.as_bytes(), ROUTE_PLAN_SHA256).unwrap(),
            decode_plan_v2_document(ROUTE_PLAN_DOCUMENT.as_bytes()).unwrap()
        );
        assert_eq!(
            verify_plan_v2_document(
                ENTRYPOINT_ROLLBACK_DOCUMENT.as_bytes(),
                ENTRYPOINT_ROLLBACK_SHA256
            )
            .unwrap()
            .operation(),
            PlanV2Operation::RemoveEntrypoint
        );

        let upper_case_digest = WEB_SERVICE_PLAN_SHA256.to_ascii_uppercase();
        for (name, document, expected) in [
            (
                "the rollback presented under the plan digest",
                WEB_SERVICE_ROLLBACK_DOCUMENT,
                WEB_SERVICE_PLAN_SHA256,
            ),
            (
                "the plan presented under the rollback digest",
                WEB_SERVICE_PLAN_DOCUMENT,
                WEB_SERVICE_ROLLBACK_SHA256,
            ),
            (
                "a plan presented under the digest of another group",
                WEB_SERVICE_PLAN_DOCUMENT,
                ROUTE_PLAN_SHA256,
            ),
            (
                "an upper-case digest",
                WEB_SERVICE_PLAN_DOCUMENT,
                upper_case_digest.as_str(),
            ),
            ("a truncated digest", WEB_SERVICE_PLAN_DOCUMENT, "99f6"),
            ("an empty digest", WEB_SERVICE_PLAN_DOCUMENT, ""),
            (
                "a user service presented under the digest of its removal",
                USER_SERVICE_PLAN_DOCUMENT,
                USER_SERVICE_ROLLBACK_SHA256,
            ),
            (
                "a user service presented under the digest of another instance",
                USER_SERVICE_PLAN_DOCUMENT,
                MINIMAL_USER_PLAN_SHA256,
            ),
        ] {
            assert_eq!(
                verify_plan_v2_document(document.as_bytes(), expected),
                Err(ProtocolError::InvalidInput),
                "{name} was accepted"
            );
        }

        // One byte moved inside a document is another plan, and no longer the
        // one its escort claims. The alteration below is a single character of
        // the origin — the smallest change a transport can make that a reader
        // would never notice — and it is refused before anything displays it.
        let mut altered = USER_SERVICE_PLAN_DOCUMENT.as_bytes().to_vec();
        let index = USER_SERVICE_PLAN_DOCUMENT
            .find(USER_SERVICE_ORIGIN_HOST)
            .expect("the vector carries its origin");
        altered[index] = b'm';
        assert_eq!(
            verify_plan_v2_document(&altered, USER_SERVICE_PLAN_SHA256),
            Err(ProtocolError::InvalidInput)
        );
        // It is still a well-formed plan on its own, which is exactly why the
        // digest and not the grammar is what refuses it.
        assert_ne!(
            decode_plan_v2_document(&altered)
                .expect("the altered document is a plan of its own")
                .sha256()
                .unwrap(),
            USER_SERVICE_PLAN_SHA256
        );
    }

    /// What makes a rollback a plan rather than a promise, in each of the three
    /// groups: removal for a deployment, redeployment for a removal,
    /// `retire_route` for `publish_route`.
    #[test]
    fn a_rollback_is_recognised_only_when_it_undoes_exactly_the_plan() {
        let service = decode_plan_v2_document(WEB_SERVICE_PLAN_DOCUMENT.as_bytes()).unwrap();
        let service_rollback =
            decode_plan_v2_document(WEB_SERVICE_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        let entrypoint_plan = decode_plan_v2_document(ENTRYPOINT_PLAN_DOCUMENT.as_bytes()).unwrap();
        let entrypoint_rollback =
            decode_plan_v2_document(ENTRYPOINT_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        let route_plan = decode_plan_v2_document(ROUTE_PLAN_DOCUMENT.as_bytes()).unwrap();
        let route_rollback = decode_plan_v2_document(ROUTE_ROLLBACK_DOCUMENT.as_bytes()).unwrap();

        let private_plan =
            decode_plan_v2_document(PRIVATE_SERVICE_PLAN_DOCUMENT.as_bytes()).unwrap();
        let private_rollback =
            decode_plan_v2_document(PRIVATE_SERVICE_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        let link_plan = decode_plan_v2_document(LINK_ROUTE_PLAN_DOCUMENT.as_bytes()).unwrap();
        let link_rollback =
            decode_plan_v2_document(LINK_ROUTE_ROLLBACK_DOCUMENT.as_bytes()).unwrap();
        let snapshot_plan = decode_plan_v2_document(SNAPSHOT_PLAN_DOCUMENT.as_bytes()).unwrap();
        let snapshot_rollback =
            decode_plan_v2_document(SNAPSHOT_ROLLBACK_DOCUMENT.as_bytes()).unwrap();

        for (plan, rollback) in [
            (&service, &service_rollback),
            (&entrypoint_plan, &entrypoint_rollback),
            (&route_plan, &route_rollback),
            (&private_plan, &private_rollback),
            (&link_plan, &link_rollback),
            (&snapshot_plan, &snapshot_rollback),
        ] {
            assert!(plan.is_undone_by(rollback));
            assert!(rollback.is_undone_by(plan));
            assert_ne!(plan.sha256().unwrap(), rollback.sha256().unwrap());
            // A second copy of the plan undoes nothing.
            assert!(!plan.is_undone_by(plan));
        }

        // A document of another operation group is never an undoing, whatever it
        // names: the two are not the same plan written differently.
        assert!(!route_rollback.is_undone_by(&service));
        assert!(!service_rollback.is_undone_by(&route_plan));
        assert!(!entrypoint_rollback.is_undone_by(&service));

        // The two couples that carry identical fields under two operations are
        // the sharpest case of that rule: retiring a public route does not undo
        // publishing a link route, and discarding an archive does not undo a
        // return, however identically the two documents are spelled.
        assert!(!link_plan.is_undone_by(
            &decode_plan_v2_document(
                ROUTE_ROLLBACK_DOCUMENT
                    .replace(ROUTE_HOST, LINK_ROUTE_HOST)
                    .as_bytes()
            )
            .unwrap()
        ));
        assert!(!snapshot_plan
            .is_undone_by(&decode_plan_v2_document(RESTORE_PLAN_DOCUMENT.as_bytes()).unwrap()));

        for forged in [
            PrivateServicePlanDocumentV2 {
                origin_host: "other.lab.your-cloud.test".into(),
                ..private_service().inverted()
            },
            PrivateServicePlanDocumentV2 {
                local_port: PORT + 1,
                ..private_service().inverted()
            },
            PrivateServicePlanDocumentV2 {
                operation: PlanV2Operation::DeployPrivateService,
                ..private_service().inverted()
            },
        ] {
            assert!(
                !private_service().is_undone_by(&forged),
                "a rollback that targets another instance is not a rollback"
            );
        }

        for forged in [
            LinkRoutePlanDocumentV2 {
                route_host: "other.lab.your-cloud.test".into(),
                ..link_route().inverted()
            },
            LinkRoutePlanDocumentV2 {
                backend_port: PORT + 1,
                ..link_route().inverted()
            },
        ] {
            assert!(
                !link_route().is_undone_by(&forged),
                "a rollback that targets another name is not a rollback"
            );
        }

        for forged in [
            WebServicePlanDocumentV2 {
                machine_id: "lab-machine-2".into(),
                ..web_service().inverted()
            },
            WebServicePlanDocumentV2 {
                infrastructure_id: OTHER_INFRASTRUCTURE.into(),
                ..web_service().inverted()
            },
            WebServicePlanDocumentV2 {
                local_port: PORT + 1,
                ..web_service().inverted()
            },
            WebServicePlanDocumentV2 {
                service_profile: "bentopdf-simple".into(),
                ..web_service().inverted()
            },
            WebServicePlanDocumentV2 {
                image_reference: ENTRYPOINT_IMAGE_REFERENCE.into(),
                ..web_service().inverted()
            },
            WebServicePlanDocumentV2 {
                image_digest: OTHER_PINNED_DIGEST.into(),
                ..web_service().inverted()
            },
            WebServicePlanDocumentV2 {
                operation: PlanV2Operation::DeployWebService,
                ..web_service().inverted()
            },
        ] {
            assert!(
                !web_service().is_undone_by(&forged),
                "a rollback that targets another instance is not a rollback"
            );
        }

        for forged in [
            RoutePlanDocumentV2 {
                route_host: "other.lab.your-cloud.test".into(),
                ..route().inverted()
            },
            RoutePlanDocumentV2 {
                backend_port: PORT + 1,
                ..route().inverted()
            },
            RoutePlanDocumentV2 {
                operation: PlanV2Operation::PublishRoute,
                ..route().inverted()
            },
        ] {
            assert!(
                !route().is_undone_by(&forged),
                "a rollback that targets another name is not a rollback"
            );
        }

        assert!(!entrypoint().is_undone_by(&EntrypointPlanDocumentV2 {
            machine_id: "lab-machine-2".into(),
            ..entrypoint().inverted()
        }));

        // The third door, in both directions and over both of its vectors: the
        // removal names the same instance as the deployment it undoes, origin
        // included and origin absent alike.
        for (plan, rollback) in [
            (USER_SERVICE_PLAN_DOCUMENT, USER_SERVICE_ROLLBACK_DOCUMENT),
            (MINIMAL_USER_PLAN_DOCUMENT, MINIMAL_USER_ROLLBACK_DOCUMENT),
        ] {
            let plan = decode_plan_v2_document(plan.as_bytes()).unwrap();
            let rollback = decode_plan_v2_document(rollback.as_bytes()).unwrap();
            assert!(plan.is_undone_by(&rollback));
            assert!(rollback.is_undone_by(&plan));
            assert!(!plan.is_undone_by(&plan));
            assert_ne!(plan.sha256().unwrap(), rollback.sha256().unwrap());
        }
        // And the two instances never undo one another, however alike the two
        // documents are shaped.
        assert!(
            !decode_plan_v2_document(USER_SERVICE_PLAN_DOCUMENT.as_bytes())
                .unwrap()
                .is_undone_by(
                    &decode_plan_v2_document(MINIMAL_USER_ROLLBACK_DOCUMENT.as_bytes()).unwrap()
                )
        );

        for forged in [
            UserServicePlanDocumentV2 {
                definition_digest: MINIMAL_DEFINITION_DIGEST.into(),
                ..user_service().inverted()
            },
            UserServicePlanDocumentV2 {
                definition_slug: MINIMAL_SLUG.into(),
                ..user_service().inverted()
            },
            UserServicePlanDocumentV2 {
                image_digest: OTHER_PINNED_DIGEST.into(),
                ..user_service().inverted()
            },
            UserServicePlanDocumentV2 {
                origin_host: String::new(),
                ..user_service().inverted()
            },
            UserServicePlanDocumentV2 {
                local_port: PORT + 1,
                ..user_service().inverted()
            },
            UserServicePlanDocumentV2 {
                operation: PlanV2Operation::DeployUserService,
                ..user_service().inverted()
            },
        ] {
            assert!(
                !user_service().is_undone_by(&forged),
                "a rollback that targets another instance is not a rollback"
            );
        }
        assert!(
            !minimal_user_service().is_undone_by(&UserServicePlanDocumentV2 {
                origin_host: USER_SERVICE_ORIGIN_HOST.into(),
                ..minimal_user_service().inverted()
            })
        );
    }

    /// The decisions of the contract, kept testable rather than merely written:
    /// one profile, one image per pinned role, no second truth beside a digest,
    /// and an undoing for every operation that carries the same fields.
    ///
    /// The human versions of these images — the tags a release note names —
    /// appear nowhere in this module on purpose. A tag in the source would be a
    /// second, movable identity beside the digest, and the digest is the
    /// identity.
    #[test]
    fn the_images_of_this_palier_are_pinned_by_digest_alone() {
        for reference in [
            BENTOPDF_IMAGE_REFERENCE,
            ENTRYPOINT_IMAGE_REFERENCE,
            VAULTWARDEN_IMAGE_REFERENCE,
        ] {
            assert!(!reference.contains(':'), "{reference} carries a tag");
            assert!(!reference.contains('@'), "{reference} carries a digest");
            assert!(reference.contains('/'), "{reference} names no registry");
        }
        let mut pinned: Vec<&str> = Vec::new();
        for digest in [
            BENTOPDF_IMAGE_DIGEST,
            ENTRYPOINT_IMAGE_DIGEST,
            VAULTWARDEN_IMAGE_DIGEST,
        ] {
            assert!(decode_image_digest(digest).is_some(), "{digest}");
            assert!(!pinned.contains(&digest), "{digest} pins two roles");
            pinned.push(digest);
        }
        assert_eq!(SERVICE_LOCAL_ADDRESS, "127.0.0.1");
        assert_eq!(ENTRYPOINT_PUBLIC_HTTPS_PORT, 443);
        assert_eq!(ENTRYPOINT_PUBLIC_HTTP_PORT, 80);
        assert_eq!(
            ENTRYPOINT_UNPRIVILEGED_PORT_SYSCTL,
            "net.ipv4.ip_unprivileged_port_start=80"
        );
        assert_eq!(
            ROUTE_ISOLATION_HEADERS,
            [
                "Cross-Origin-Opener-Policy: same-origin",
                "Cross-Origin-Embedder-Policy: require-corp",
            ]
        );

        // The constants of the private profile: displayed by the window that
        // asks for consent, and named by no field of any document.
        assert_eq!(
            PRIVATE_SERVICE_DATA_VOLUME,
            "/var/lib/your-cloud-svc-vaultwarden/data"
        );
        assert_eq!(
            PRIVATE_SERVICE_ENVIRONMENT_HARDENING,
            [
                "SIGNUPS_ALLOWED=false",
                "INVITATIONS_ALLOWED=false",
                "SHOW_PASSWORD_HINT=false",
            ]
        );
        assert_eq!(PRIVATE_SERVICE_ORIGIN_VARIABLE, "DOMAIN");
        assert_eq!(PRIVATE_SERVICE_ORIGIN_SCHEME, "https");
        assert_eq!(PRIVATE_SERVICE_EGRESS_TABLE, "inet your-cloud-egress");
        assert_eq!(RESERVED_SNAPSHOT_SLOT, "previous");
        assert_eq!(MIN_SNAPSHOT_SLOT_BYTES, 1);
        assert_eq!(MAX_SNAPSHOT_SLOT_BYTES, 32);

        // The one profile of each door is the one it names, and an unknown
        // profile can never borrow the pin of a known one.
        assert!(profile_image(SERVICE_PROFILE_BENTOPDF).is_some());
        for unknown in ["bentopdf-simple", "BentoPDF", "", "traefik"] {
            assert!(profile_image(unknown).is_none(), "{unknown} was pinned");
        }
        assert!(private_profile_image(SERVICE_PROFILE_VAULTWARDEN).is_some());

        let mut names: Vec<&str> = Vec::new();
        for operation in DECLARED_OPERATIONS {
            assert_eq!(operation.inverse().inverse(), operation);
            // The restore is the one operation whose undoing is itself, because
            // what its undoing moves is the slot rather than the verb. Every
            // other operation names another one, and none of them changes group.
            if operation == PlanV2Operation::RestoreService {
                assert_eq!(operation.inverse(), operation);
            } else {
                assert_ne!(operation.inverse(), operation);
            }
            assert_eq!(
                operation.inverse().group(),
                operation.group(),
                "{operation:?} and its undoing do not carry the same fields"
            );
            assert_eq!(
                serde_json::to_value(operation).unwrap(),
                serde_json::json!(operation.as_str())
            );
            assert!(!names.contains(&operation.as_str()));
            names.push(operation.as_str());
        }
        assert_eq!(
            names,
            [
                "deploy_web_service",
                "remove_web_service",
                "deploy_entrypoint",
                "remove_entrypoint",
                "publish_route",
                "retire_route",
                "deploy_private_service",
                "remove_private_service",
                "publish_link_route",
                "retire_link_route",
                "snapshot_service",
                "discard_snapshot",
                "restore_service",
                "deploy_user_service",
                "remove_user_service",
            ]
        );
    }
}

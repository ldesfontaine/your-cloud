//! The ordered installation, and the witnesses it may not be built without.
//!
//! This module decides nothing that another module already decided. That the
//! placement is private, approved and normally powered on is
//! [`ApprovedPlacement`]'s statement, made by `placement::propose` on facts
//! `audit` read; that root was really reached is [`Elevation`]'s; that the
//! bundle is the bundle is [`VerifiedBundle`]'s; that every endpoint answered
//! the Controller is [`PreflightCleared`]'s. [`authorize`] asks for them by type
//! and re-derives none of them. Re-checking "is this endpoint private" here
//! would give the property two homes and, eventually, two answers.
//!
//! **Combien de témoins dépend de la provenance, et c'est un fait sur le monde
//! plutôt qu'un réglage.** Remplacer un Controller peut s'appuyer sur le prévol
//! d'un Controller qui vit déjà ; en créer un ne le peut pas, puisque la
//! machine qui devrait jouer ce prévol est celle qu'on installe. [`Origin`]
//! porte cette différence par type, et le prévol reste dans tous les cas la
//! dernière étape de [`STEPS`] — ce que ce module a toujours dit de lui.
//!
//! **What this palier installs, it installs on one machine.** The scope of #38
//! stops before the other machines are touched, and that is visible in
//! [`Step`]: there is no step that mutates a target. The preflight is the last
//! thing the plan does, which is what makes "if a preflight fails, no other
//! machine is modified" a property of the shape of the sequence rather than of
//! a check somebody remembered to write.
//!
//! **The isolation is a set of constants, not a set of parameters.** Account
//! names, directories, unit names and budgets below are fixed. An installation
//! that could be pointed at another account or another directory would be an
//! installation whose blast radius is decided by its caller, and the LAB proof
//! could then only speak about the invocation it happened to run.

use crate::installation::bundle::VerifiedBundle;
use crate::installation::preflight::PreflightCleared;
use crate::personal_access::audit::Role;
use crate::personal_access::elevation::Elevation;
use crate::personal_access::placement::ApprovedPlacement;
use your_cloud_bootstrap_protocol::BootstrapAction;

/// Where the package puts what it owns. These are the paths of the bounded
/// distribution this palier fixes, not the `/usr/local` paths the earlier
/// paliers' proofs used.
pub const PACKAGE_DIRECTORY: &str = "/usr/lib/your-cloud";
pub const PACKAGE_BINARY: &str = "/usr/lib/your-cloud/your-cloud";
pub const PACKAGE_UNIT_DIRECTORY: &str = "/usr/lib/systemd/system";

/// The three units the package delivers, and the only three. The package
/// installs them inactive; enabling one is the Assistant's typed operation, not
/// a maintainer script's side effect.
pub const DELIVERED_UNITS: [&str; 3] = [
    "your-cloud-controller.service",
    "your-cloud-daemon.service",
    "your-cloud-relay.service",
];

/// The unit this palier is allowed to enable. The Daemon and the Relay are
/// delivered by the same package and left alone: installing a Controller is not
/// a reason to start anything else on the machine.
pub const CONTROLLER_UNIT: &str = "your-cloud-controller.service";

/// The account the Controller service runs as, distinct from the Daemon's and
/// the Relay's. It is a systemd *dynamic* user: the unit names it, systemd
/// allocates it for the lifetime of the service and no persistent account with
/// a shell, a password or a home ever exists. Compromising one role's account
/// does not hand over another's, and there is no account left to attack when
/// the service is stopped.
pub const CONTROLLER_ACCOUNT: &str = "your-cloud-controller";

/// The Controller's private state, as systemd owns it under a dynamic user.
/// `dpkg` inventories the package's files and never this one: the state is the
/// Assistant's, managed separately, exactly as the distribution contract
/// requires.
pub const CONTROLLER_STATE_DIRECTORY: &str = "/var/lib/private/your-cloud-controller";

/// The machine-specific, non-secret configuration the unit reads. The package
/// never carries it — that is the whole point of the distribution contract —
/// and the Assistant writes it as a file `dpkg` does not inventory.
pub const MACHINE_CONFIGURATION: &str = "/etc/your-cloud/controller.env";

/// Where the root-owned credential sources live. They are readable by `root`
/// alone; systemd exposes them to the one service at start, which is what keeps
/// the operational keys out of the command line and out of the environment.
pub const CREDENTIAL_SOURCE_DIRECTORY: &str = "/etc/your-cloud/controller-credentials";

/// Les trois répertoires du motif-répertoire de l'unité, créés VIDES à la
/// création : leur contenu appartient à d'autres moments consentis —
/// l'enrôlement pour les deux premiers, le parcours qui posera un Relay pour
/// le troisième (décision du 20 août 2026, aucun placeholder).
pub const COMMAND_IDENTITY_DIRECTORY: &str = "/etc/your-cloud/command-identities";
pub const COMMAND_ENDPOINT_DIRECTORY: &str = "/etc/your-cloud/command-endpoints";
pub const RELAY_ANCHOR_DIRECTORY: &str = "/etc/your-cloud/relay-anchor";

/// Les deux fichiers de la paire du lecteur, nés sur la cible par la frappe.
pub const READER_CERTIFICATE: &str = "/etc/your-cloud/controller-credentials/controller-reader.crt";
pub const READER_KEY: &str = "/etc/your-cloud/controller-credentials/controller-reader.key";

/// Ce que l'init laisse dans l'état privé : l'autorité du Controller. Nommé
/// pour le registre — un retour à l'état d'avant doit savoir le retirer.
pub const AUTHORITY_FILE: &str = "/var/lib/private/your-cloud-controller/authority.json";

/// The budgets the Controller unit is confined by. They are named here so the
/// LAB can assert the running service really carries them, rather than assert
/// that the file mentioned them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    pub tasks_max: u32,
    pub memory_max_mib: u32,
}

pub const CONTROLLER_BUDGETS: Budgets = Budgets {
    tasks_max: 128,
    memory_max_mib: 384,
};

/// One step of the installation, in the order the architecture fixes.
///
/// Each step names the item it will record in the rollback ledger, so a failure
/// at step *n* has an unambiguous list of what steps 1..n created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Le lot judged voyage vers la cible, sous le seul accès personnel, et son
    /// empreinte y est relue. Un fichier de six mégaoctets qui apparaît sur une
    /// machine est un effet : il naît donc d'un plan approuvé et visible, comme
    /// tous les autres. C'est la seule étape qui ne dépense aucun privilège —
    /// voir [`FIRST_ELEVATED_STEP`].
    TransferBundle,
    /// `dpkg` installs the judged artefact. It is the first privileged act of
    /// the whole palier, and it happens after [`VerifiedBundle`] exists.
    InstallPackage,
    /// The machine-specific configuration the package deliberately does not
    /// carry: the exact addresses this Controller listens on and answers to.
    WriteMachineConfiguration,
    /// The private state directory, and the Controller's own identity in it.
    /// There is no account step beside it: the unit's dynamic user is allocated
    /// by systemd at start and no persistent account is ever created.
    CreateState,
    /// The root-owned credential sources the unit will be given : le
    /// répertoire des credentials du Controller, et les trois répertoires du
    /// motif-répertoire de l'unité — identités de commandement, feuilles
    /// d'endpoints, ancre du Relay — créés VIDES, parce que leur contenu
    /// appartient à d'autres moments consentis : l'enrôlement machine par
    /// machine, et le parcours qui posera un Relay (décision du 20 août 2026).
    InstallCredentialSources,
    /// `controller init` : les identifiants immuables naissent sous l'acte
    /// consenti — imprimés, jugés, constatés au registre — jamais dans l'ombre
    /// d'un premier démarrage. Mesuré le 19 août 2026 : `serve` ne
    /// s'auto-initialise pas, et la fixture du palier antérieur jouait cet
    /// acte que le plan réel ne jouait nulle part.
    InitialiseController,
    /// `controller mint-reader` : la paire du lecteur naît chez celui qu'elle
    /// identifie et ne voyage jamais — l'empreinte publique est jugée sur la
    /// sortie de l'acte et constatée au registre, le précédent de la clé
    /// d'hôte. Après l'init (l'URI porte les identifiants), avant la première
    /// activation (`LoadCredential=` est une contrainte de forme, pas
    /// d'autorité).
    MintReaderIdentity,
    /// Enabling and starting the one unit this palier activates.
    ActivateController,
    /// Binding this Console to this Controller, freshly and for this
    /// infrastructure only.
    AssociateConsole,
    /// The Controller reaches every declared endpoint. Nothing follows it in
    /// this palier.
    Preflight,
}

/// The fixed sequence. It is a constant rather than a builder because an
/// installation whose order could be chosen is an installation whose ordering
/// guarantees are the caller's problem.
pub const STEPS: [Step; 10] = [
    Step::TransferBundle,
    Step::InstallPackage,
    Step::WriteMachineConfiguration,
    Step::CreateState,
    Step::InstallCredentialSources,
    Step::InitialiseController,
    Step::MintReaderIdentity,
    Step::ActivateController,
    Step::AssociateConsole,
    Step::Preflight,
];

/// La première étape qui dépense l'élévation prouvée.
///
/// Tout ce qui la précède dans [`STEPS`] agit sous le seul accès personnel. Ce
/// n'est pas une annotation de confort : c'est la frontière que le contrat
/// d'architecture nomme — `dpkg` est le premier acte privilégié du palier — et
/// un test la tient, pour qu'une étape glissée avant elle ne puisse pas
/// prétendre au privilège sans que la porte le dise.
pub const FIRST_ELEVATED_STEP: Step = Step::InstallPackage;

/// La tranche contiguë de [`STEPS`] que chaque action du protocole approuve.
///
/// C'est ici que « une session ne peut pas produire un acte d'une autre
/// action » cesse d'être une intention : l'exécutant du palier recevra une
/// action et n'aura à sa main que la tranche qu'elle nomme, rendue par une
/// fonction totale — une action ajoutée sans sa tranche ne compile pas.
/// L'audit ne couvre rien : une session d'audit n'installe pas, et le dire
/// par une tranche vide vaut mieux que de ne pas être appelable.
///
/// Les deux tranches d'installation séparent l'inerte de l'actif, exactement
/// comme le contrat les approuve : poser s'arrête avant la première unité en
/// écoute, activer commence à elle. Leur concaténation est [`STEPS`] dans son
/// ordre — un test le tient, pour qu'aucune étape ne puisse être orpheline ou
/// couverte deux fois.
pub const fn authorized_steps(action: BootstrapAction) -> &'static [Step] {
    match action {
        BootstrapAction::AuditTargetReadOnly => &[],
        BootstrapAction::InstallServerBundle => &[
            Step::TransferBundle,
            Step::InstallPackage,
            Step::WriteMachineConfiguration,
            Step::CreateState,
            Step::InstallCredentialSources,
            Step::InitialiseController,
            Step::MintReaderIdentity,
        ],
        BootstrapAction::ActivateApprovedController => &[
            Step::ActivateController,
            Step::AssociateConsole,
            Step::Preflight,
        ],
    }
}

/// Why an installation was not authorised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanRefusal {
    /// The approved placement is not a Controller placement. A Relay approval,
    /// or an Agent's, does not authorise this.
    NotAControllerPlacement { role: &'static str },
    /// The preflight cleared a set that does not contain the machine the
    /// placement names. Clearing other endpoints is not clearing this one.
    PlacementNotCleared { endpoint: String },
    /// The bundle is not the one this Assistant may install.
    BundleNotForThisTarget { target: String },
}

/// One authorised installation of one Controller on one machine.
///
/// It cannot be built by naming its fields and [`authorize`] is the only
/// function that returns one. Holding it is what a caller must be able to show
/// before it runs a single privileged command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPlan {
    endpoint: String,
    version: String,
}

impl InstallPlan {
    /// The machine this plan installs on — the one the user approved, taken
    /// from the witness rather than from any later argument.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The bundle version this plan installs, taken from the verified manifest.
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn steps(&self) -> &'static [Step] {
        &STEPS
    }
}

/// D'où vient cette installation, et ce que cette provenance peut prouver.
///
/// **Amendement du 16 août 2026.** Ce module exigeait un [`PreflightCleared`]
/// de toute installation, sans distinguer les deux provenances. C'était juste
/// pour celle que `#38` avait sous les yeux — remplacer un Controller — et
/// **inapplicable** à celle que ce palier installe : en création, le prévol ne
/// peut avoir été joué par personne, puisque la machine qui doit le jouer est
/// celle qu'on installe. La contradiction n'était pas visible parce que
/// `authorize` n'était appelé par aucun code de production ; elle est apparue
/// à la ligne où il allait enfin l'être.
///
/// Le prévol ne disparaît pas : il **redevient ce que `STEPS` dit déjà qu'il
/// est**, la dernière étape de la séquence, constatée à la fin plutôt
/// qu'exigée au début. Ce qui change est qu'on cesse de demander comme
/// précondition une observation que seule la conséquence peut produire.
pub enum Origin<'a> {
    /// Une infrastructure qui n'existe pas encore. Rien n'a pu joindre les
    /// endpoints depuis un Controller, et ce qui répond de la machine est
    /// l'audit : sa clé d'hôte confirmée, son placement approuvé — ce que
    /// [`ApprovedPlacement`] porte déjà.
    Creation,
    /// Un Controller vit déjà et a joint chaque endpoint déclaré **avant**
    /// qu'on touche à quoi que ce soit. C'est la provenance de `#38`, et elle
    /// garde son quatrième témoin entier.
    Replacement(&'a PreflightCleared),
}

/// The one gate. Nothing else in this crate builds an [`InstallPlan`].
///
/// The `Elevation` parameter is taken by value-like reference and never read:
/// it is a proof obligation, not an input. Asking for it by type is what makes
/// "could this run without root having been really reached" answerable by
/// looking at one signature.
///
/// La provenance est un **témoin de plus, pas un réglage de moins** : elle est
/// exigée par type comme les trois autres, et la variante qui remplace porte le
/// prévol qu'elle prouve. Un appelant ne peut donc pas se dispenser du prévol
/// en mode remplacement — il n'a pas de variante pour le dire.
pub fn authorize(
    bundle: &VerifiedBundle,
    placement: &ApprovedPlacement,
    _elevation: &Elevation,
    origin: Origin<'_>,
) -> Result<InstallPlan, PlanRefusal> {
    if placement.role() != Role::Controller {
        return Err(PlanRefusal::NotAControllerPlacement {
            role: placement.role().as_str(),
        });
    }
    if bundle.target() != crate::installation::bundle::SUPPORTED_TARGET {
        return Err(PlanRefusal::BundleNotForThisTarget {
            target: bundle.target().to_owned(),
        });
    }
    // Le prévol répond de la machine **quand quelqu'un a pu le jouer**. En
    // création, personne ne l'a pu, et exiger ici une observation que seule
    // l'installation rendra possible ferait de cette porte une porte
    // infranchissable — ce qu'elle a été jusqu'ici sans que rien ne le dise.
    if let Origin::Replacement(cleared) = origin {
        if !cleared.covers(placement.endpoint()) {
            return Err(PlanRefusal::PlacementNotCleared {
                endpoint: placement.endpoint().to_owned(),
            });
        }
    }
    Ok(InstallPlan {
        endpoint: placement.endpoint().to_owned(),
        version: bundle.version().to_owned(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::installation::bundle;
    use crate::installation::preflight::{self, EndpointAttempt, Observation};
    use crate::personal_access::audit::{
        Architecture, CgroupHierarchy, Distribution, InitSystem, Installation, Observed,
        ObservedMachine, SUPPORTED_DISTRIBUTION_ID, SUPPORTED_DISTRIBUTION_VERSION,
    };
    use crate::personal_access::elevation;
    use crate::personal_access::placement::{
        self, Approval, Availability, DeclaredEndpoint, Exposure, PlacementRefusal,
    };
    use ed25519_dalek::{Signer, SigningKey};

    /// Exposés au crate pour la même raison que [`plan_for_tests`] : les suites
    /// de l'ordonnanceur font réellement traverser ces octets, et une seconde
    /// définition du lot de référence donnerait deux lots là où la propriété
    /// tient précisément à ce qu'il n'y en ait qu'un.
    pub(crate) const ARTIFACT: &[u8] = b"the exact bytes of the embedded server bundle";
    const KEY: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// A real [`VerifiedBundle`], obtained the only way one can be obtained.
    pub(crate) fn verified_bundle() -> bundle::VerifiedBundle {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let digest: String = <sha2::Sha256 as sha2::Digest>::digest(ARTIFACT)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let manifest = format!(
            concat!(
                "{{\"schema_version\":1,\"kind\":\"{}\",\"version\":\"0.0.3\",",
                "\"target\":\"{}\",\"size\":{},\"sha256\":\"{}\"}}"
            ),
            bundle::BUNDLE_KIND,
            bundle::SUPPORTED_TARGET,
            ARTIFACT.len(),
            digest,
        );
        let signature = key.sign(manifest.as_bytes());
        bundle::verify(
            &key.verifying_key().to_bytes(),
            manifest.as_bytes(),
            &signature.to_bytes(),
            "0.0.3",
            ARTIFACT,
        )
        .expect("the bundle fixture must verify")
    }

    /// Un plan réel, obtenu par la seule porte qui en rend un.
    ///
    /// Il est exposé au crate pour que les suites de l'ordonnanceur exercent
    /// une séquence sans reconstruire les quatre témoins : ce que ce plan
    /// prouve est déjà prouvé ici, et le dupliquer ailleurs donnerait deux
    /// endroits où la même obligation pourrait diverger.
    pub(crate) fn plan_for_tests() -> InstallPlan {
        let endpoint = private_endpoint();
        authorize(
            &verified_bundle(),
            &approved_placement(&endpoint),
            &elevation(),
            // Le palier de ce plan de référence est une création : aucun
            // Controller n'a pu jouer de prévol, puisque c'est lui qu'il
            // installe.
            Origin::Creation,
        )
        .expect("le plan de référence doit être autorisé")
    }

    /// A real [`Elevation`], obtained the only way one can be obtained.
    fn elevation() -> elevation::Elevation {
        elevation::elevated(0, b"0\n", b"").expect("the elevation fixture must be granted")
    }

    fn compatible_machine() -> ObservedMachine {
        ObservedMachine {
            uid: Observed::Known(1001),
            hostname: Observed::Known("machine-1".into()),
            distribution: Observed::Known(Distribution {
                id: SUPPORTED_DISTRIBUTION_ID.into(),
                version_id: SUPPORTED_DISTRIBUTION_VERSION.into(),
            }),
            architecture: Observed::Known(Architecture::Amd64),
            init: Observed::Known(InitSystem::Systemd),
            cgroup: Observed::Known(CgroupHierarchy::V2),
            memory_kib: Observed::Known(991_164),
            processors: Observed::Known(1),
            free_disk_kib: Observed::Known(8_388_996),
            installation: Observed::Known(Installation::NotDeclared),
        }
    }

    fn private_endpoint() -> DeclaredEndpoint {
        DeclaredEndpoint {
            name: "machine-1".into(),
            port: 22,
            exposure: Exposure::Private,
            availability: Availability::NormallyOn,
            relay_candidate: false,
        }
    }

    /// A real [`ApprovedPlacement`], obtained the only way one can be obtained:
    /// through `propose` on observed facts, then `approve`.
    fn approved_placement(endpoint: &DeclaredEndpoint) -> ApprovedPlacement {
        let proposal = placement::propose(Role::Controller, endpoint, &compatible_machine())
            .expect("the placement fixture must be proposable");
        placement::approve(
            &proposal,
            &Approval {
                role: Role::Controller,
                endpoint: endpoint.name.clone(),
            },
        )
        .expect("the placement fixture must be approvable")
    }

    fn cleared(names: &[&str]) -> preflight::PreflightCleared {
        let attempts: Vec<EndpointAttempt> = names
            .iter()
            .map(|name| EndpointAttempt {
                name: (*name).into(),
                confirmed_fingerprint: KEY.into(),
                observed: Observation::Presented {
                    fingerprint: KEY.into(),
                },
            })
            .collect();
        preflight::clear(&attempts).expect("the preflight fixture must clear")
    }

    /// The positive control: four genuine witnesses authorise one plan.
    #[test]
    fn four_witnesses_authorise_one_controller_installation() {
        let plan = authorize(
            &verified_bundle(),
            &approved_placement(&private_endpoint()),
            &elevation(),
            Origin::Replacement(&cleared(&["machine-1"])),
        )
        .expect("the positive control must authorise");

        assert_eq!(plan.endpoint(), "machine-1");
        assert_eq!(plan.version(), "0.0.3");
        assert_eq!(plan.steps(), STEPS);
    }

    /// **Une création autorise sans prévol, et c'est une décision plutôt qu'un
    /// oubli.**
    ///
    /// La machine qui devrait jouer le prévol est celle qu'on installe. Exiger
    /// ici son observation faisait de cette porte une porte que rien ne pouvait
    /// franchir en création — ce qui ne se voyait pas tant qu'aucun code de
    /// production ne l'appelait, et se voit à la ligne où il l'appelle enfin.
    ///
    /// Ce que la création rend n'est pas un plan au rabais : c'est le **même**
    /// plan, les mêmes étapes dans le même ordre, prévol compris — il y est
    /// comme dernière étape, à constater à la fin.
    #[test]
    fn a_creation_authorises_without_a_preflight_nobody_could_have_played() {
        let plan = authorize(
            &verified_bundle(),
            &approved_placement(&private_endpoint()),
            &elevation(),
            Origin::Creation,
        )
        .expect("une création doit être autorisable");

        assert_eq!(plan.endpoint(), "machine-1");
        assert_eq!(plan.steps(), STEPS);
        assert_eq!(plan.steps().last(), Some(&Step::Preflight));
    }

    /// The scope of #38 is visible in the sequence itself: the preflight is the
    /// last step, so no step of this palier can mutate another machine, and
    /// "a failed preflight modifies no other machine" is a property of the
    /// shape rather than of a check.
    #[test]
    fn the_sequence_ends_at_the_preflight_and_touches_no_target() {
        assert_eq!(STEPS.last(), Some(&Step::Preflight));
        // La séquence commence au transfert, pas à `dpkg` : le lot est un effet
        // que le plan nomme. Que le premier acte *privilégié* reste `dpkg` est
        // la propriété voisine, tenue par `FIRST_ELEVATED_STEP` et son propre
        // test plutôt que répétée ici.
        assert_eq!(STEPS[0], Step::TransferBundle);
        // Exactly one unit is ever activated by this palier, and it is the
        // Controller's; the Daemon and the Relay travel in the same package
        // and are left inactive.
        assert!(DELIVERED_UNITS.contains(&CONTROLLER_UNIT));
        assert_eq!(DELIVERED_UNITS.len(), 3);
    }

    /// The placement half of the contract is #36's decision, and this test
    /// walks the whole chain rather than restating it: an exposed endpoint
    /// never yields a proposal, so it never yields an approval, so there is
    /// nothing `authorize` could be handed.
    #[test]
    fn an_exposed_endpoint_never_reaches_this_module_at_all() {
        let mut exposed = private_endpoint();
        exposed.exposure = Exposure::Exposed;

        assert_eq!(
            placement::propose(Role::Controller, &exposed, &compatible_machine()),
            Err(PlacementRefusal::ControllerOnExposedEndpoint)
        );

        let mut intermittent = private_endpoint();
        intermittent.availability = Availability::Intermittent;
        assert_eq!(
            placement::propose(Role::Controller, &intermittent, &compatible_machine()),
            Err(PlacementRefusal::ControllerOnIntermittentEndpoint)
        );
    }

    /// Clearing other endpoints is not clearing this one.
    #[test]
    fn a_preflight_that_cleared_another_machine_does_not_authorise_this_one() {
        assert_eq!(
            authorize(
                &verified_bundle(),
                &approved_placement(&private_endpoint()),
                &elevation(),
                Origin::Replacement(&cleared(&["machine-2", "machine-3"])),
            ),
            Err(PlanRefusal::PlacementNotCleared {
                endpoint: "machine-1".into()
            })
        );
    }

    /// A Relay approval does not authorise installing a Controller.
    #[test]
    fn an_approval_for_another_role_does_not_authorise_a_controller() {
        let endpoint = DeclaredEndpoint {
            relay_candidate: true,
            ..private_endpoint()
        };
        let proposal = placement::propose(Role::Relay, &endpoint, &compatible_machine())
            .expect("a relay candidate must be proposable");
        let relay = placement::approve(
            &proposal,
            &Approval {
                role: Role::Relay,
                endpoint: endpoint.name.clone(),
            },
        )
        .expect("the relay approval must be approvable");

        // Quelle que soit la provenance. Retirer le prévol des préconditions
        // d'une création ne retire rien d'autre : ce qu'un Relay ne peut pas
        // autoriser, il ne le peut pas davantage parce que personne n'a joué
        // de prévol.
        let cleared = cleared(&["machine-1"]);
        for origin in [Origin::Creation, Origin::Replacement(&cleared)] {
            assert_eq!(
                authorize(&verified_bundle(), &relay, &elevation(), origin),
                Err(PlanRefusal::NotAControllerPlacement {
                    role: Role::Relay.as_str()
                })
            );
        }
    }

    /// The isolation constants are the ones the architecture fixes, and the
    /// Controller's account, state and credentials are its own.
    #[test]
    fn the_controller_is_isolated_by_account_state_credentials_and_budget() {
        assert_eq!(PACKAGE_BINARY, "/usr/lib/your-cloud/your-cloud");
        assert_eq!(PACKAGE_UNIT_DIRECTORY, "/usr/lib/systemd/system");
        // These are not the /usr/local paths of the earlier proofs.
        assert!(!PACKAGE_DIRECTORY.starts_with("/usr/local"));
        assert!(!PACKAGE_UNIT_DIRECTORY.starts_with("/etc"));
        // Nothing the Controller owns is shared with the other two roles.
        assert!(CONTROLLER_ACCOUNT.ends_with("controller"));
        assert!(CONTROLLER_STATE_DIRECTORY.ends_with("controller"));
        assert!(CREDENTIAL_SOURCE_DIRECTORY.contains("controller"));
        assert!(CONTROLLER_BUDGETS.tasks_max > 0 && CONTROLLER_BUDGETS.memory_max_mib > 0);
    }

    /// Les deux tranches d'installation, mises bout à bout, sont exactement
    /// [`STEPS`] dans son ordre : aucune étape orpheline, aucune couverte deux
    /// fois, et la coupure tombe exactement entre l'inerte et l'actif. L'audit
    /// ne couvre rien.
    #[test]
    fn the_action_slices_cover_the_plan_exactly_once_and_split_inert_from_active() {
        assert_eq!(
            authorized_steps(BootstrapAction::AuditTargetReadOnly),
            &[] as &[Step]
        );

        let install = authorized_steps(BootstrapAction::InstallServerBundle);
        let activate = authorized_steps(BootstrapAction::ActivateApprovedController);
        let concatenated: Vec<Step> = install.iter().chain(activate).copied().collect();
        assert_eq!(concatenated, STEPS);

        // La coupure : poser s'arrête avant la première unité en écoute —
        // la frappe du lecteur est le dernier acte de la pose, parce que
        // `LoadCredential=` exige l'identité AVANT le premier démarrage —
        // et activer commence à l'unité.
        assert_eq!(install.last(), Some(&Step::MintReaderIdentity));
        assert_eq!(activate.first(), Some(&Step::ActivateController));
    }

    /// Le lot arrive sur la cible avant qu'aucun privilège ne soit dépensé, et
    /// c'est la seule étape dans ce cas.
    ///
    /// La propriété se lit sur la forme de la séquence : tout ce qui précède
    /// [`FIRST_ELEVATED_STEP`] est le transfert, et rien d'autre. Une étape
    /// glissée avant `dpkg` fait rougir ce test plutôt que d'hériter
    /// silencieusement de l'élévation que le plan tient.
    #[test]
    fn the_bundle_reaches_the_target_before_any_privilege_is_spent() {
        let elevated_at = STEPS
            .iter()
            .position(|step| *step == FIRST_ELEVATED_STEP)
            .expect("la première étape élevée appartient à la séquence");

        assert_eq!(&STEPS[..elevated_at], &[Step::TransferBundle]);
        assert_eq!(STEPS[elevated_at], Step::InstallPackage);
    }
}

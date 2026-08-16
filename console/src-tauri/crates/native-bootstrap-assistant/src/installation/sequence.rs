//! L'ordonnanceur : il enchaîne, il n'invente rien.
//!
//! Toutes les décisions de ce palier appartiennent aux modules voisins — le lot
//! est jugé par [`super::bundle`], son dépôt par [`super::transfer`], l'état du
//! paquet par [`super::package`], celui de l'unité par [`super::unit`], celui
//! des nœuds par [`super::nodes`], et ce qui peut courir en `root` par
//! [`super::acts`]. Ce module ne fait que porter des octets entre une commande
//! fixe et un juge, dans l'ordre que [`super::plan`] fixe, en tenant le
//! registre de ce qu'il a réellement fait.
//!
//! **Il ne juge rien, donc il ne peut pas se tromper de verdict.** Tout refus
//! qu'il rend vient d'un module déjà éprouvé ; ce qui lui appartient en propre
//! est l'ordre, le budget et la destruction du secret.
//!
//! ## Ce que le canal est, et pourquoi c'est une couture
//!
//! [`Channel`] est le seul point par lequel cette séquence touche une machine.
//! C'est un trait plutôt qu'un type concret pour la même raison que les juges
//! reçoivent des octets plutôt que d'ouvrir des fichiers : la séquence entière
//! — l'ordre, le budget, le registre, la destruction du secret — devient
//! exerçable par une suite, sans transport et sans machine. La preuve LAB
//! branche le canal réel ; aucune fixture ne remplace pour autant un composant
//! du produit, puisque ce qui décide est ailleurs et reste le même.
//!
//! ## Le secret, et la seule promesse qui compte
//!
//! Quand la politique attestée exige un mot de passe, chaque acte le présente —
//! jamais l'horodatage de `sudo`, que chaque acte jette avant de courir. Le
//! secret vit donc le temps de la séquence, et [`Sequence`] le détruit sur
//! **tout** chemin de sortie : réussite, refus d'un juge, échec de canal,
//! annulation, expiration. Ce n'est pas « quand le processus se termine » : la
//! destruction est un acte de cette séquence, pas une conséquence de sa mort.

use super::acts::{self, ElevatedAct};
use super::bundle::VerifiedBundle;
use super::configuration::MachineConfiguration;
use super::plan::{InstallPlan, Step};
use super::rollback::{ItemKind, Ledger, Provenance};
use super::transfer::{self, TransferReadings};
use crate::personal_access::elevation::FixedCommand;
use your_cloud_bootstrap_protocol::BootstrapAction;

/// Ce qu'une machine a répondu à une commande.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub exit_status: u32,
    pub stdout: Vec<u8>,
}

/// La seule voie par laquelle cette séquence atteint une machine.
///
/// Une implémentation réelle porte la session d'accès personnel ; une
/// implémentation de suite rend des réponses écrites. Les deux voient
/// exactement la même séquence, ce qui est le point.
pub trait Channel {
    /// Exécute une commande fixe, en lui donnant éventuellement une entrée.
    ///
    /// L'entrée est ce qui permet au lot de traverser sans shell ni
    /// redirection : elle est donnée à `dd`, et à lui seul.
    fn run(&mut self, command: FixedCommand, input: Option<&[u8]>) -> Result<Answer, ChannelError>;

    /// Adopte le budget que la séquence a dérivé de ses étapes, avant tout
    /// canal. Une implémentation qui n'en tient pas rend `Ok(())`.
    fn adopt_budget(&mut self, budget: usize) -> Result<(), ChannelError>;
}

/// Pourquoi un canal n'a pas répondu. Ce n'est jamais un verdict sur la
/// machine : c'est l'absence de verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelError;

/// Pourquoi une séquence s'est arrêtée.
///
/// Aucun de ces refus n'est inventé ici : chacun porte celui du module qui l'a
/// prononcé, ou dit que la machine n'a pas répondu du tout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SequenceStop {
    /// Le budget dérivé n'a pas pu être adopté avant le premier canal.
    BudgetRefused,
    /// La machine n'a pas répondu à cette étape. On ne sait donc rien de ce
    /// qu'elle a fait, et le registre le porte comme tel.
    Unanswered { step: Step },
    /// Un acte n'a pas rendu zéro. Ce n'est pas encore un constat : c'est la
    /// commande qui s'est plainte, et la séquence s'arrête avant de constater.
    ActFailed { step: Step, exit_status: u32 },
    /// Un juge a refusé ce que la machine a répondu. Le refus est le sien,
    /// rendu par son propre nom — cette séquence n'en invente aucun.
    Refused { step: Step, reason: String },
}

/// Ce qu'une séquence a fait, quoi qu'il lui soit arrivé.
///
/// Elle est rendue **dans les deux cas**, succès comme arrêt : un appelant qui
/// ne recevrait le registre qu'en cas de succès n'aurait rien à défaire au
/// moment précis où il en a besoin.
#[derive(Debug)]
pub struct SequenceOutcome {
    pub ledger: Ledger,
    pub stopped: Option<SequenceStop>,
}

impl SequenceOutcome {
    pub fn succeeded(&self) -> bool {
        self.stopped.is_none()
    }
}

/// Le secret que la séquence dépense, et qu'elle détruit en la quittant.
///
/// Il est pris par valeur et jamais rendu : la seule façon de le faire sortir
/// d'ici est de le détruire. C'est ce qui rend la borne tenable — il n'existe
/// aucun chemin où un appelant repartirait avec.
pub struct SpentSecret<S> {
    secret: Option<S>,
}

impl<S> SpentSecret<S> {
    pub fn holding(secret: S) -> Self {
        Self {
            secret: Some(secret),
        }
    }

    pub fn none() -> Self {
        Self { secret: None }
    }

    fn bytes<'a>(&'a self, borrow: impl Fn(&'a S) -> &'a [u8]) -> Option<&'a [u8]> {
        self.secret.as_ref().map(borrow)
    }

    /// La destruction, explicite et idempotente.
    ///
    /// Elle est appelée sur chaque chemin de sortie de [`Sequence::run`] — y
    /// compris les chemins d'erreur — plutôt que laissée au `Drop` du
    /// processus : une borne qui dépendrait de la fin du processus ne serait
    /// pas la borne annoncée.
    pub fn destroy(&mut self) {
        self.secret = None;
    }

    #[cfg(test)]
    fn is_destroyed(&self) -> bool {
        self.secret.is_none()
    }
}

/// Ce que la séquence dépose sur la cible, et que des juges locaux ont déjà
/// arrêté.
///
/// Les trois membres sont pris ensemble parce qu'ils partent ensemble : sans
/// eux, aucun lot n'arrive sur la machine et `dpkg` n'aurait rien à installer.
/// Ils sont exigés même par l'action qui n'en dépose aucun — un appelant qui ne
/// les aurait pas ne pourrait de toute façon pas tenir d'[`InstallPlan`], que
/// `plan::authorize` ne rend que contre un [`VerifiedBundle`].
///
/// **L'artefact et son témoin sont deux valeurs, et la liaison est prouvée
/// ailleurs.** Des octets qui ne seraient pas ceux que le manifeste signé lie
/// traversent quand même, puis sont refusés par l'empreinte relue **sur la
/// cible** — `StagedDigestMismatch`, avant tout privilège. C'est précisément la
/// propriété pour laquelle le transfert mesure après la traversée plutôt que de
/// se fier à ce que l'expéditeur croyait envoyer.
pub struct InstallPayload<'a> {
    /// Le lot que `bundle::verify` a jugé : ce qui est attendu sur la cible.
    pub bundle: &'a VerifiedBundle,
    /// Les octets exacts qui traversent, donnés à `dd` et à lui seul.
    pub artifact: &'a [u8],
    /// La configuration composée localement, avec l'empreinte que le plan
    /// nomme et que l'humain a vue avant de consentir.
    pub configuration: &'a MachineConfiguration,
}

/// Une séquence d'installation, du budget adopté au secret détruit.
pub struct Sequence<'a, C: Channel> {
    channel: &'a mut C,
    action: BootstrapAction,
    password_required: bool,
    /// Le refus qu'un juge vient de prononcer, conservé le temps de le porter
    /// à l'appelant sous son propre nom.
    last_refusal: String,
}

impl<'a, C: Channel> Sequence<'a, C> {
    /// Prépare la séquence d'une action approuvée.
    ///
    /// `password_required` vient de l'attestation de politique et de rien
    /// d'autre : c'est elle qui a lu le listing distant.
    pub fn new(channel: &'a mut C, action: BootstrapAction, password_required: bool) -> Self {
        Self {
            channel,
            action,
            password_required,
            last_refusal: String::new(),
        }
    }

    /// Déroule les actes que l'action autorise, en tenant le registre.
    ///
    /// Le budget est dérivé et adopté **avant le premier canal**. Le secret est
    /// détruit avant de rendre, sur chaque chemin — c'est la raison pour
    /// laquelle cette fonction a un seul point de sortie et non cinq.
    pub fn run<S>(
        mut self,
        plan: &InstallPlan,
        payload: &InstallPayload<'_>,
        secret: &mut SpentSecret<S>,
        borrow: impl Fn(&S) -> &[u8] + Copy,
    ) -> SequenceOutcome {
        let mut ledger = Ledger::new();
        // Les étapes dont l'effet est posé mais qu'aucun constat n'a encore
        // établi. Elles vivent ici, et non dans la boucle, précisément pour que
        // **tout** arrêt les inscrive : un effet posé que personne n'a établi
        // doit être visible au déroulé, sans quoi il resterait sur la machine
        // sans que rien ne le connaisse.
        let mut pending: Vec<Step> = Vec::new();
        let outcome = self.drive(plan, payload, secret, borrow, &mut ledger, &mut pending);
        for step in pending {
            record_step(&mut ledger, step, Provenance::Unknown);
        }
        // Sur **tout** chemin : réussite, refus d'un juge, canal muet.
        secret.destroy();
        // Ce que `sudo` garde de nous ne survit pas non plus, et ce geste ne
        // dépend d'aucune issue.
        let _ = self.channel.run(acts::DROP_CREDENTIAL, None);
        SequenceOutcome {
            ledger,
            stopped: outcome.err(),
        }
    }

    fn drive<S>(
        &mut self,
        plan: &InstallPlan,
        payload: &InstallPayload<'_>,
        secret: &SpentSecret<S>,
        borrow: impl Fn(&S) -> &[u8] + Copy,
        ledger: &mut Ledger,
        pending: &mut Vec<Step>,
    ) -> Result<(), SequenceStop> {
        let budget = acts::channel_budget(self.action);
        self.channel
            .adopt_budget(budget)
            .map_err(|_| SequenceStop::BudgetRefused)?;

        for step in super::plan::authorized_steps(self.action) {
            // Ce que l'étape fait traverser, avant tout privilège. L'ordre est
            // une propriété et non une commodité : `dpkg` installe le lot que
            // la cible détient déjà, donc le dépôt précède l'acte, et l'acte
            // qui met la configuration en place déplace un fichier dont
            // l'empreinte a été relue là-bas.
            self.deposit(*step, payload, ledger)?;

            let mut ran_an_act = false;
            for act in ElevatedAct::authorised_for(plan, *step) {
                ran_an_act = true;
                let command = act.command(self.password_required);
                let input = if self.password_required {
                    secret.bytes(borrow)
                } else {
                    None
                };
                let answer = self
                    .channel
                    .run(command, input)
                    .map_err(|_| SequenceStop::Unanswered { step: *step })?;
                // Ce que l'acte a touché entre au registre avec la provenance
                // que la machine a rendue : `Created` sur un zéro constaté,
                // `Unknown` sinon — jamais `Created` sur une supposition.
                if answer.exit_status != 0 {
                    // L'acte s'est plaint : rien n'est constaté, donc cette
                    // étape et toutes celles qui attendaient encore entrent en
                    // `Unknown` — leurs effets sont peut-être sur la machine et
                    // personne ne les a établis, ce que le déroulé doit voir.
                    pending.push(*step);
                    return Err(SequenceStop::ActFailed {
                        step: *step,
                        exit_status: answer.exit_status,
                    });
                }
            }

            // Une étape n'attend un constat que si elle a **réellement** couru
            // un acte. Le transfert n'en court aucun : ce qu'il pose est établi
            // sur-le-champ par l'empreinte relue, donc il s'inscrit lui-même et
            // n'a rien à attendre. L'inscrire ici ferait porter au registre un
            // inconnu qui n'existe pas, et un déroulé qui nomme un inconnu
            // imaginaire est aussi faux qu'un déroulé qui en oublie un.
            if ran_an_act {
                // Un `stat` mesurant les trois nœuds d'un coup, plusieurs
                // étapes peuvent attendre le même constat.
                pending.push(*step);
            }

            // Le constat, et lui seul, donne sa provenance au registre. Un code
            // de sortie dit qu'un programme s'est terminé sans se plaindre ;
            // seul le constat dit ce que la machine est devenue.
            match self.constate(*step, plan)? {
                Some(true) => {
                    // Le constat établit toutes les étapes qu'il couvre, et
                    // celles-là seulement.
                    let covered = acts::covered_by(
                        acts::constat_for(*step).expect("un constat a répondu pour cette étape"),
                    );
                    pending.retain(|waiting| {
                        if covered.contains(waiting) {
                            record_step(ledger, *waiting, Provenance::Created);
                            false
                        } else {
                            true
                        }
                    });
                }
                Some(false) => {
                    return Err(SequenceStop::Refused {
                        step: *step,
                        reason: self.last_refusal.clone(),
                    });
                }
                // Aucun constat ici : l'étape reste en attente de celui qui la
                // couvrira, et sera portée `Unknown` si la séquence s'arrête
                // avant lui.
                None => {}
            }
        }
        Ok(())
    }

    /// Joue la chaîne de dépôt que l'étape exige, et inscrit ce qu'elle pose.
    ///
    /// C'est la seule partie de la séquence dont le constat est **immédiat** :
    /// la machine relit elle-même la taille et l'empreinte de ce qu'elle vient
    /// de recevoir, et le juge du transfert les confronte à ce que
    /// l'expéditeur tenait déjà. Rien n'y est différé, donc rien n'y passe par
    /// les étapes en attente — ce qui est posé entre au registre à la ligne où
    /// il est établi.
    ///
    /// Les étapes qui ne déposent rien rendent `Ok(())` sans ouvrir de canal,
    /// et c'est ce qui laisse cette fonction s'appeler à chaque tour de boucle
    /// sans que l'ordonnanceur ait à savoir laquelle dépose.
    fn deposit(
        &mut self,
        step: Step,
        payload: &InstallPayload<'_>,
        ledger: &mut Ledger,
    ) -> Result<(), SequenceStop> {
        match step {
            Step::TransferBundle => {
                // La porte d'abord, et **avant que le premier octet parte** :
                // déposer dans un répertoire que cette exécution n'a pas créé
                // écrirait le lot là où un tiers tient la porte, et le refuser
                // ensuite ne le reprendrait pas.
                let created = self
                    .channel
                    .run(transfer::CREATE_STAGING, None)
                    .map_err(|_| SequenceStop::Unanswered { step })?;
                if let Err(refusal) = transfer::staging_created(created.exit_status) {
                    return Err(SequenceStop::Refused {
                        step,
                        reason: format!("{refusal:?}"),
                    });
                }
                // Le répertoire est nôtre, et il entre au registre avant que
                // quoi que ce soit y soit écrit : un arrêt à la ligne suivante
                // doit le rendre retirable, faute de quoi il resterait sur la
                // machine et ferait refuser la prochaine installation.
                ledger.record(
                    ItemKind::Directory,
                    transfer::STAGING_DIRECTORY,
                    Provenance::Created,
                );

                let (deposited, size, digest) = self.deposit_and_measure(
                    step,
                    transfer::DEPOSIT_BUNDLE,
                    payload.artifact,
                    transfer::MEASURE_STAGED_SIZE,
                    transfer::MEASURE_STAGED,
                )?;
                let verdict =
                    transfer::staged(payload.bundle, &readings_of(&deposited, &size, &digest));
                self.record_deposit(ledger, step, transfer::STAGED_ARTIFACT_SUFFIX, verdict)
            }
            Step::WriteMachineConfiguration => {
                // Aucun répertoire à créer : c'est celui que le transfert a
                // posé, et une seconde création le refuserait à juste titre.
                let (deposited, size, digest) = self.deposit_and_measure(
                    step,
                    super::configuration::DEPOSIT_CONFIGURATION,
                    payload.configuration.bytes(),
                    super::configuration::MEASURE_CONFIGURATION_SIZE,
                    super::configuration::MEASURE_CONFIGURATION,
                )?;
                let verdict = super::configuration::staged(
                    payload.configuration,
                    &readings_of(&deposited, &size, &digest),
                );
                self.record_deposit(
                    ledger,
                    step,
                    super::configuration::STAGED_CONFIGURATION_SUFFIX,
                    verdict,
                )
            }
            Step::InstallPackage
            | Step::CreateState
            | Step::InstallCredentialSources
            | Step::ActivateController
            | Step::AssociateConsole
            | Step::Preflight => Ok(()),
        }
    }

    /// Dépose des octets, puis fait relire à la machine ce qu'elle a écrit.
    ///
    /// Les trois commandes courent dans l'ordre que le transfert fixe — écrire,
    /// la taille, l'empreinte — et **toutes les trois**, même quand l'une se
    /// plaint. Ce n'est pas cette fonction qui décide : le juge veut les trois
    /// réponses, et c'est lui qui dit laquelle a arrêté l'étape. S'arrêter au
    /// premier statut non nul reviendrait à trancher ici, dans le seul module
    /// du palier qui n'a le droit de trancher rien.
    fn deposit_and_measure(
        &mut self,
        step: Step,
        deposit: FixedCommand,
        bytes: &[u8],
        size: FixedCommand,
        digest: FixedCommand,
    ) -> Result<(Answer, Answer, Answer), SequenceStop> {
        // Les octets ne passent que par l'entrée, et seul un dépôt en reçoit :
        // c'est ce qui les fait traverser sans shell ni redirection.
        let deposited = self
            .channel
            .run(deposit, Some(bytes))
            .map_err(|_| SequenceStop::Unanswered { step })?;
        let size = self
            .channel
            .run(size, None)
            .map_err(|_| SequenceStop::Unanswered { step })?;
        let digest = self
            .channel
            .run(digest, None)
            .map_err(|_| SequenceStop::Unanswered { step })?;
        Ok((deposited, size, digest))
    }

    /// Inscrit le fichier qu'un dépôt a posé, sous la provenance que son juge a
    /// rendue.
    ///
    /// `dd` a couru : un fichier peut exister à ce chemin quel que soit le
    /// verdict, y compris tronqué. Il entre donc au registre **dans les deux
    /// cas** — `Created` quand l'empreinte relue l'établit, `Unknown` sinon, ce
    /// qui interdit de le retirer et le rend visible au déroulé plutôt que de
    /// le laisser sur la machine sans que personne ne le connaisse.
    fn record_deposit(
        &mut self,
        ledger: &mut Ledger,
        step: Step,
        name: &str,
        verdict: Result<super::transfer::StagedFile, super::transfer::TransferRefusal>,
    ) -> Result<(), SequenceStop> {
        match verdict {
            Ok(_) => {
                ledger.record(ItemKind::File, name, Provenance::Created);
                Ok(())
            }
            Err(refusal) => {
                ledger.record(ItemKind::File, name, Provenance::Unknown);
                Err(SequenceStop::Refused {
                    step,
                    reason: format!("{refusal:?}"),
                })
            }
        }
    }

    /// Interroge la machine et fait juger sa réponse par le module qui décide.
    ///
    /// Rien n'est jugé ici : la réponse est portée telle quelle au juge, et
    /// c'est son verdict qui revient. Un refus est donc toujours celui d'un
    /// module éprouvé, jamais une conclusion de l'ordonnanceur.
    fn constate(&mut self, step: Step, plan: &InstallPlan) -> Result<Option<bool>, SequenceStop> {
        let Some(constat) = acts::constat_for(step) else {
            return Ok(None);
        };
        let answer = self
            .channel
            .run(constat.command(), None)
            .map_err(|_| SequenceStop::Unanswered { step })?;

        let verdict = match constat {
            acts::Constat::Package => super::package::read(answer.exit_status, &answer.stdout)
                .map_err(|refusal| format!("{refusal:?}"))
                .and_then(|state| {
                    super::package::posed(&state, plan.version())
                        .map(|_| ())
                        .map_err(|refusal| format!("{refusal:?}"))
                }),
            acts::Constat::Unit => super::unit::running(answer.exit_status, &answer.stdout)
                .map(|_| ())
                .map_err(|refusal| format!("{refusal:?}")),
            acts::Constat::Nodes => super::nodes::owned(&answer.stdout)
                .map(|_| ())
                .map_err(|refusal| format!("{refusal:?}")),
        };

        match verdict {
            Ok(()) => Ok(Some(true)),
            Err(reason) => {
                self.last_refusal = reason;
                Ok(Some(false))
            }
        }
    }
}

/// Les trois réponses d'un dépôt, dans la forme que le juge attend.
///
/// Elle ne conclut rien : chaque statut et chaque sortie passe tel quel, et ce
/// qui reste à l'ordonnanceur est de les avoir mises dans le bon ordre.
fn readings_of<'a>(
    deposited: &Answer,
    size: &'a Answer,
    digest: &'a Answer,
) -> TransferReadings<'a> {
    TransferReadings {
        deposit_status: deposited.exit_status,
        size_status: size.exit_status,
        size_stdout: &size.stdout,
        digest_status: digest.exit_status,
        digest_stdout: &digest.stdout,
    }
}

/// Ce qu'une étape inscrit au registre, et sous quelle provenance.
///
/// La provenance ne vient **jamais** d'un code de sortie : elle vient du
/// constat que l'étape a obtenu. `Created` dit que la machine a été vue dans
/// l'état annoncé, donc que cette exécution peut le défaire ; `Unknown` dit
/// qu'on n'a pas pu l'établir — le déroulé refusera alors de retirer et
/// dégradera l'ensemble en `Incomplete`, ce que le contrat exige d'un état que
/// personne n'a constaté.
fn record_step(ledger: &mut Ledger, step: Step, provenance: Provenance) {
    match step {
        Step::InstallPackage => {
            ledger.record(ItemKind::Package, super::package::PACKAGE_NAME, provenance)
        }
        Step::CreateState => ledger.record(
            ItemKind::Directory,
            super::plan::CONTROLLER_STATE_DIRECTORY,
            provenance,
        ),
        Step::InstallCredentialSources => ledger.record(
            ItemKind::CredentialSource,
            super::plan::CREDENTIAL_SOURCE_DIRECTORY,
            provenance,
        ),
        Step::ActivateController => ledger.record(
            ItemKind::UnitState,
            super::plan::CONTROLLER_UNIT,
            provenance,
        ),
        Step::WriteMachineConfiguration => ledger.record(
            ItemKind::File,
            super::plan::MACHINE_CONFIGURATION,
            provenance,
        ),
        // Le transfert s'inscrit lui-même, au fur et à mesure : son répertoire
        // dès qu'il est créé, son fichier dès que l'empreinte relue l'établit
        // ou le laisse inconnu. Il n'entre donc jamais dans les étapes en
        // attente, et le nommer ici donnerait au registre une seconde manière
        // d'écrire ce qu'il a déjà écrit.
        Step::TransferBundle => {}
        Step::AssociateConsole | Step::Preflight => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Un canal écrit qui répond **comme une machine dans un état**, plutôt
    /// que comme une file de statuts.
    ///
    /// C'est ce que le câblage des juges impose : une séquence ne peut plus
    /// « réussir » sans que la machine rende des constats qu'un juge accepte.
    /// Un canal qui ne rendrait que des codes de sortie ferait passer des
    /// séquences que le produit refuse — et c'est précisément le défaut que ce
    /// câblage a corrigé.
    struct ScriptedChannel {
        /// Le statut que rendent les actes. Un seul suffit : la séquence
        /// s'arrête au premier qui se plaint.
        act_status: u32,
        /// Le statut que rend la création du répertoire d'attente.
        ///
        /// Il est distinct d'[`Self::act_status`] parce que ce n'est pas un
        /// acte : il ne dépense aucun privilège, et son statut **est** le
        /// constat que `mkdir` sans `-p` rend. Une machine dont les actes
        /// privilégiés se plaignent n'est pas une machine dont le foyer refuse
        /// d'écrire, et confondre les deux ferait jouer un scénario pour un
        /// autre.
        staging_status: u32,
        /// Ce qu'un dépôt fait subir aux octets qu'il reçoit, avant que la
        /// machine ne les remesure. L'identité par défaut.
        alter: fn(Vec<u8>) -> Vec<u8>,
        /// L'état que la machine dit d'elle-même, par constat.
        package: Vec<u8>,
        unit: Vec<u8>,
        nodes: Vec<u8>,
        /// Ce que la machine a **réellement reçu** par l'entrée de chaque
        /// dépôt, et qu'elle remesurera elle-même.
        ///
        /// C'est ce qui distingue ce canal d'une file de réponses écrites : la
        /// taille et l'empreinte qu'il rend sont celles des octets qui ont
        /// traversé, jamais des constantes recopiées. Un ordonnanceur qui
        /// enverrait autre chose — ou rien — verrait donc son propre juge le
        /// refuser, ce qu'une fixture complaisante n'aurait jamais montré.
        received: RefCell<Vec<(String, Vec<u8>)>>,
        mute: bool,
        /// Les octets exacts que la machine refusera. Vide : tout réussit.
        /// Le canal ne connaît pas les étapes, seulement des commandes — c'est
        /// à l'appelant de dériver du plan celles qu'il veut voir échouer.
        failing: Vec<String>,
        /// Chaque commande vue, et l'entrée exacte qu'elle a reçue.
        seen: RefCell<Vec<(String, Option<Vec<u8>>)>>,
        adopted: RefCell<Option<usize>>,
    }

    impl ScriptedChannel {
        /// Une machine qui répond exactement ce que les juges attendent.
        fn in_the_announced_state() -> Self {
            Self {
                act_status: 0,
                staging_status: 0,
                alter: |bytes| bytes,
                package: format!(
                    "{} install ok installed 0.0.3\n",
                    super::super::package::PACKAGE_NAME
                )
                .into_bytes(),
                unit: unit_reading(),
                nodes: nodes_reading(),
                received: RefCell::new(Vec::new()),
                mute: false,
                failing: Vec::new(),
                seen: RefCell::new(Vec::new()),
                adopted: RefCell::new(None),
            }
        }

        /// Ce que la machine détient à un chemin donné, si un dépôt l'y a
        /// écrit.
        fn held(&self, suffix: &str) -> Option<Vec<u8>> {
            self.received
                .borrow()
                .iter()
                .find(|(path, _)| path == suffix)
                .map(|(_, bytes)| bytes.clone())
        }

        fn failing_acts() -> Self {
            Self {
                act_status: 1,
                ..Self::in_the_announced_state()
            }
        }

        fn mute() -> Self {
            Self {
                mute: true,
                ..Self::in_the_announced_state()
            }
        }
    }

    /// Le foyer du compte personnel, tel que la cible le développe. Les
    /// commandes portent `$HOME` ; ce que `sha256sum` imprime est un chemin
    /// absolu, et c'est celui-là que le juge confronte à son suffixe.
    const HOME: &str = "/home/ycoperator";

    /// Les dépôts du palier, et le chemin que chacun écrit. La table est celle
    /// des modules qui les déclarent : un dépôt ajouté sans son entrée ici ne
    /// serait pas relu, et le test le verrait avant une machine.
    const DEPOSITS: [(FixedCommand, &str); 2] = [
        (
            super::super::transfer::DEPOSIT_BUNDLE,
            super::super::transfer::STAGED_ARTIFACT_SUFFIX,
        ),
        (
            super::super::configuration::DEPOSIT_CONFIGURATION,
            super::super::configuration::STAGED_CONFIGURATION_SUFFIX,
        ),
    ];

    /// Les deux mesures de chaque dépôt, rattachées au chemin qu'elles lisent.
    const MEASUREMENTS: [(FixedCommand, FixedCommand, &str); 2] = [
        (
            super::super::transfer::MEASURE_STAGED_SIZE,
            super::super::transfer::MEASURE_STAGED,
            super::super::transfer::STAGED_ARTIFACT_SUFFIX,
        ),
        (
            super::super::configuration::MEASURE_CONFIGURATION_SIZE,
            super::super::configuration::MEASURE_CONFIGURATION,
            super::super::configuration::STAGED_CONFIGURATION_SUFFIX,
        ),
    ];

    fn hex_digest(bytes: &[u8]) -> String {
        <sha2::Sha256 as sha2::Digest>::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// La configuration de référence, composée par la seule porte qui en rend
    /// une.
    fn configuration() -> super::super::configuration::MachineConfiguration {
        super::super::configuration::compose(
            "192.168.240.115:9443",
            "192.168.240.0/24",
            "192.168.240.9:9444",
        )
        .expect("la configuration de référence doit se composer")
    }

    /// Ce qu'une unité réellement confinée répond, dérivé des mêmes valeurs que
    /// le juge attend — jamais recopié, sans quoi deux définitions du
    /// confinement coexisteraient.
    fn unit_reading() -> Vec<u8> {
        let mut lines = vec![
            "ActiveState=active".to_owned(),
            "SubState=running".to_owned(),
        ];
        for (name, value) in super::super::unit::expected_isolation() {
            lines.push(format!("{name}={value}"));
        }
        format!("{}\n", lines.join("\n")).into_bytes()
    }

    /// Ce qu'une machine dont les nœuds sont posés répond, dérivé de la table
    /// que le juge tient.
    fn nodes_reading() -> Vec<u8> {
        let lines: Vec<String> = super::super::nodes::EXPECTED_NODES
            .iter()
            .map(|node| format!("{} 0 0 {} {}", node.path, node.mode, node.kind))
            .collect();
        format!("{}\n", lines.join("\n")).into_bytes()
    }

    impl Channel for ScriptedChannel {
        fn run(
            &mut self,
            command: FixedCommand,
            input: Option<&[u8]>,
        ) -> Result<Answer, ChannelError> {
            // L'entrée est conservée telle quelle, et non réduite à « il y en
            // avait une » : depuis que le transfert passe par ce canal, une
            // entrée est tantôt le secret, tantôt six mégaoctets de lot, et
            // confondre les deux laisserait passer le secret présenté à un
            // `dd`.
            self.seen
                .borrow_mut()
                .push((command.as_str().to_owned(), input.map(<[u8]>::to_vec)));
            if self.mute {
                return Err(ChannelError);
            }
            let bytes = command.as_str();
            // Le répertoire d'attente : son statut est son propre constat.
            if bytes == super::super::transfer::CREATE_STAGING.as_str() {
                return Ok(Answer {
                    exit_status: self.staging_status,
                    stdout: Vec::new(),
                });
            }
            // Un dépôt écrit ce qu'on lui donne là où son chemin le dit. La
            // machine garde les octets : ce sont eux, et eux seuls, que les
            // deux mesures suivantes rendront.
            for (deposit, suffix) in DEPOSITS {
                if bytes == deposit.as_str() {
                    let refused = self.failing.iter().any(|command| command == bytes);
                    if !refused {
                        let written = (self.alter)(input.unwrap_or_default().to_vec());
                        self.received
                            .borrow_mut()
                            .push((suffix.to_owned(), written));
                    }
                    return Ok(Answer {
                        exit_status: if refused { 1 } else { 0 },
                        stdout: Vec::new(),
                    });
                }
            }
            // Les mesures relisent ce que la machine détient réellement. Un
            // fichier qu'aucun dépôt n'a écrit fait échouer `stat` et
            // `sha256sum` comme sur une vraie machine, plutôt que de rendre la
            // ligne d'un fichier absent.
            for (size, digest, suffix) in MEASUREMENTS {
                if bytes == size.as_str() || bytes == digest.as_str() {
                    let Some(held) = self.held(suffix) else {
                        return Ok(Answer {
                            exit_status: 1,
                            stdout: Vec::new(),
                        });
                    };
                    let stdout = if bytes == size.as_str() {
                        format!("{}\n", held.len()).into_bytes()
                    } else {
                        format!("{}  {HOME}{suffix}\n", hex_digest(&held)).into_bytes()
                    };
                    return Ok(Answer {
                        exit_status: 0,
                        stdout,
                    });
                }
            }
            // Les constats répondent l'état ; tout le reste est un acte.
            let stdout = if bytes == super::super::package::QUERY_PACKAGE.as_str() {
                self.package.clone()
            } else if bytes == super::super::unit::SHOW_CONTROLLER.as_str() {
                self.unit.clone()
            } else if bytes == super::super::nodes::STAT_OWNED.as_str() {
                self.nodes.clone()
            } else {
                let refused = self.failing.iter().any(|command| command == bytes);
                return Ok(Answer {
                    exit_status: if refused { 1 } else { self.act_status },
                    stdout: Vec::new(),
                });
            };
            Ok(Answer {
                exit_status: 0,
                stdout,
            })
        }

        fn adopt_budget(&mut self, budget: usize) -> Result<(), ChannelError> {
            *self.adopted.borrow_mut() = Some(budget);
            Ok(())
        }
    }

    fn plan() -> InstallPlan {
        super::super::plan::tests::plan_for_tests()
    }

    /// Ce que l'appelant tient pendant une séquence.
    ///
    /// Les témoins vivent chez lui et la charge n'est qu'une vue empruntée sur
    /// eux — c'est la forme réelle : l'Assistant tient le lot qu'il embarque et
    /// la configuration qu'il vient de composer, et n'en donne à la séquence
    /// que le droit de les lire.
    ///
    /// Les deux sortent des portes du produit — `bundle::verify` et
    /// `configuration::compose` — et d'aucune constante recopiée : une suite
    /// qui fabriquerait sa propre charge exercerait un transfert que le produit
    /// ne peut pas produire.
    struct Held {
        bundle: VerifiedBundle,
        configuration: MachineConfiguration,
    }

    impl Held {
        fn new() -> Self {
            Self {
                bundle: super::super::plan::tests::verified_bundle(),
                configuration: configuration(),
            }
        }

        fn payload(&self) -> InstallPayload<'_> {
            InstallPayload {
                bundle: &self.bundle,
                artifact: super::super::plan::tests::ARTIFACT,
                configuration: &self.configuration,
            }
        }
    }

    /// Le secret meurt sur une séquence **réussie**.
    #[test]
    fn the_secret_dies_after_a_sequence_that_succeeded() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        let mut secret = SpentSecret::holding(b"phrase".to_vec());

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held| held.as_slice(),
        );

        assert!(outcome.succeeded());
        assert!(secret.is_destroyed(), "le secret survit à une réussite");
    }

    /// Le secret meurt sur une séquence **échouée**.
    #[test]
    fn the_secret_dies_after_a_sequence_that_failed() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::failing_acts();
        let mut secret = SpentSecret::holding(b"phrase".to_vec());

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held| held.as_slice(),
        );

        assert!(!outcome.succeeded());
        assert!(secret.is_destroyed(), "le secret survit à un échec");
    }

    /// Le secret meurt quand la machine **ne répond pas du tout**.
    ///
    /// C'est le chemin le plus facile à oublier : il n'y a pas de verdict, donc
    /// rien qui ressemble à une fin de séquence.
    #[test]
    fn the_secret_dies_when_the_machine_never_answered() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::mute();
        let mut secret = SpentSecret::holding(b"phrase".to_vec());

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held| held.as_slice(),
        );

        assert!(matches!(
            outcome.stopped,
            Some(SequenceStop::Unanswered { .. })
        ));
        assert!(secret.is_destroyed(), "le secret survit à un canal muet");
    }

    /// La destruction est prouvée **en mémoire**, pas seulement en logique.
    ///
    /// Le canari de `#45` observe l'allocation protégée au moment où elle est
    /// rendue : il voit ce que le processus laisse derrière lui. Les cas
    /// précédents disent « la séquence ne tient plus le secret » ; celui-ci dit
    /// « les octets ne sont plus là ». Ce sont deux affirmations différentes,
    /// et seule la seconde est celle que le contrat promet.
    ///
    /// Le canari est réutilisé plutôt qu'inventé : un second observateur
    /// donnerait une seconde définition de ce que « effacé » veut dire.
    #[test]
    fn the_secret_is_wiped_in_memory_and_not_merely_dropped() {
        let carried = Held::new();
        use crate::secret::ProtectedSecret;
        use std::sync::{Arc, Mutex};

        for failing in [false, true] {
            let seen: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
            let recorder = Arc::clone(&seen);

            let mut protected = ProtectedSecret::new().expect("une allocation protégée");
            protected
                .copy_from(b"phrase-de-passe")
                .expect("le secret tient dans l'allocation");
            protected.observe_wipe_for_test(move |wiped| {
                *recorder.lock().expect("le canari est seul") =
                    Some(wiped.iter().all(|byte| *byte == 0));
            });

            let mut channel = if failing {
                ScriptedChannel::failing_acts()
            } else {
                ScriptedChannel::in_the_announced_state()
            };
            let mut secret = SpentSecret::holding(protected);
            Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
                &plan(),
                &carried.payload(),
                &mut secret,
                |held: &ProtectedSecret| held.bytes(),
            );

            assert_eq!(
                *seen.lock().expect("le canari a rendu la main"),
                Some(true),
                "l'allocation n'a pas été rendue effacée (actes en échec : {failing})"
            );
        }
    }

    /// Le budget est adopté avant le premier canal, et c'est celui que les
    /// étapes ont produit.
    #[test]
    fn the_derived_budget_is_adopted_before_anything_is_run() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        assert_eq!(
            *channel.adopted.borrow(),
            Some(acts::channel_budget(BootstrapAction::InstallServerBundle))
        );
    }

    /// Toute séquence se termine en jetant ce que `sudo` garde d'elle, quelle
    /// que soit son issue.
    #[test]
    fn every_sequence_closes_by_dropping_the_credential() {
        let carried = Held::new();
        for failing in [false, true] {
            let mut channel = if failing {
                ScriptedChannel::failing_acts()
            } else {
                ScriptedChannel::in_the_announced_state()
            };
            let mut secret = SpentSecret::<Vec<u8>>::none();

            Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
                &plan(),
                &carried.payload(),
                &mut secret,
                |held: &Vec<u8>| held.as_slice(),
            );

            let seen = channel.seen.borrow();
            assert_eq!(
                seen.last().map(|(command, _)| command.as_str()),
                Some(acts::DROP_CREDENTIAL.as_str()),
                "la séquence ne s'est pas fermée sur le rejet de credential"
            );
        }
    }

    /// Le secret voyage avec chaque **acte privilégié** quand la politique
    /// l'exige — et avec rien d'autre, jamais.
    ///
    /// La distinction n'est pas cosmétique : lire l'état d'une machine ne
    /// demande aucun privilège, et déposer un fichier dans le foyer du compte
    /// personnel non plus. Une commande qui présenterait le secret sans en
    /// avoir besoin le dépenserait pour rien et l'exposerait une fois de plus
    /// par séquence.
    ///
    /// **La famille testée est celle que la table des actes déclare**, et non
    /// une liste de constats tenue à côté. C'est ce qui a changé quand le
    /// transfert a été câblé : les commandes qui ne portent pas de secret ne
    /// sont plus seulement les trois constats, ce sont aussi la création du
    /// répertoire d'attente, les deux dépôts et leurs quatre mesures. Une
    /// liste tenue à la main aurait dû être allongée à chaque câblage ; dérivée
    /// des actes, elle est juste par construction.
    ///
    /// L'entrée est confrontée **par ses octets**. Depuis que le lot traverse
    /// par ce canal, « il y avait une entrée » ne dit plus si c'était le secret
    /// ou six mégaoctets de paquet — et c'est exactement la confusion qui
    /// laisserait un secret partir dans un `dd`.
    #[test]
    fn the_secret_travels_with_every_privileged_act_and_with_nothing_else() {
        let carried = Held::new();
        const SECRET: &[u8] = b"phrase";
        let privileged: Vec<String> =
            super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle)
                .iter()
                .flat_map(|step| acts::ElevatedAct::authorised_for(&plan(), *step))
                .map(|act| act.command(true).as_str().to_owned())
                .collect();

        let mut with = ScriptedChannel::in_the_announced_state();
        let mut held = SpentSecret::holding(SECRET.to_vec());
        Sequence::new(&mut with, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &carried.payload(),
            &mut held,
            |held| held.as_slice(),
        );

        let seen = with.seen.borrow();
        let (elevated, unprivileged): (Vec<_>, Vec<_>) = seen
            .iter()
            .filter(|(command, _)| command != acts::DROP_CREDENTIAL.as_str())
            .partition(|(command, _)| privileged.contains(command));

        assert!(!elevated.is_empty(), "aucun acte privilégié n'a couru");
        assert!(
            elevated
                .iter()
                .all(|(_, input)| input.as_deref() == Some(SECRET)),
            "un acte a couru sans présenter le secret que la politique exige"
        );
        assert!(
            !unprivileged.is_empty(),
            "aucune commande non privilégiée n'a couru"
        );
        assert!(
            unprivileged
                .iter()
                .all(|(_, input)| input.as_deref() != Some(SECRET)),
            "le secret a été présenté à une commande qui ne dépense aucun privilège"
        );

        // Et sans politique de mot de passe, aucune commande ne reçoit le
        // secret — pas même les dépôts, qui reçoivent pourtant une entrée.
        let mut without = ScriptedChannel::in_the_announced_state();
        let mut none = SpentSecret::<Vec<u8>>::none();
        Sequence::new(&mut without, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut none,
            |held: &Vec<u8>| held.as_slice(),
        );
        assert!(without
            .seen
            .borrow()
            .iter()
            .all(|(_, input)| input.as_deref() != Some(SECRET)));
    }

    /// Le constat, et lui seul, donne sa provenance au registre.
    ///
    /// C'est la propriété que le câblage des juges existe pour tenir : une
    /// machine dont les actes rendent zéro mais dont l'état dément l'annonce
    /// **refuse**, là où un ordonnanceur qui lirait des codes de sortie aurait
    /// inscrit `Created` et se serait déclaré satisfait.
    #[test]
    fn a_machine_whose_state_denies_the_announcement_is_refused_though_every_act_returned_zero() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        // Le paquet répond « à demi configuré » : chaque acte a rendu zéro, et
        // l'état dit autre chose.
        channel.package = format!(
            "{} install ok half-configured 0.0.3\n",
            super::super::package::PACKAGE_NAME
        )
        .into_bytes();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        let Some(SequenceStop::Refused { step, reason }) = outcome.stopped else {
            panic!("un état qui dément l'annonce doit refuser : {outcome:?}");
        };
        assert_eq!(step, Step::InstallPackage);
        assert!(
            reason.contains("HalfConfigured"),
            "le refus doit porter le nom du juge : {reason}"
        );
    }

    /// L'arrêt **à chaque étape nommée** rend un déroulé exact.
    ///
    /// La séquence est arrêtée successivement à chacune des étapes qui portent
    /// un acte, et le registre rendu est confronté à chaque fois : les étapes
    /// franchies avant l'arrêt sont `Created` — elles ont été constatées, donc
    /// cette exécution peut les défaire — et l'étape interrompue est `Unknown`,
    /// ce qui dégrade l'ensemble en `Incomplete`.
    ///
    /// Un registre qui, arrêté à l'étape *n*, ne rendrait pas exactement ce que
    /// les *n* premières ont posé est un registre sur lequel un rollback ne
    /// peut pas s'appuyer : il retirerait trop, ou pas assez.
    ///
    /// **Le compte se fait en items, pas en étapes**, et c'est le câblage du
    /// transfert qui l'a imposé : deux étapes en posent deux chacune. Le
    /// transfert crée un répertoire d'attente *puis* y écrit le lot ; la
    /// configuration laisse un résidu dans ce répertoire *puis* un fichier en
    /// place. Compter par l'index supposerait qu'une étape ne touche jamais
    /// qu'une chose, ce que la machine dément — et c'est justement le résidu
    /// qu'un compte par étape aurait laissé derrière lui.
    #[test]
    fn stopping_at_each_named_step_yields_an_exact_unwind() {
        let carried = Held::new();
        use super::super::rollback::Unwind;

        /// Ce que chaque étape laisse au registre une fois qu'elle a couru.
        fn recorded_by(step: Step) -> usize {
            match step {
                // Le répertoire d'attente, puis le lot qui y est déposé.
                Step::TransferBundle => 2,
                // Le résidu déposé, puis le fichier mis en place.
                Step::WriteMachineConfiguration => 2,
                Step::InstallPackage
                | Step::CreateState
                | Step::InstallCredentialSources
                | Step::ActivateController => 1,
                // Elles ne parlent pas à la machine par ce canal.
                Step::AssociateConsole | Step::Preflight => 0,
            }
        }

        /// Le **dernier** geste d'une étape que la machine peut refuser.
        ///
        /// C'est lui, et non le premier, qu'il faut faire échouer pour arrêter
        /// une étape qui a posé tout ce qu'elle pose : refuser plus tôt
        /// mesurerait un arrêt à mi-étape, qui est un autre cas.
        ///
        /// Le transfert y figure par son dépôt. Il ne porte aucun acte
        /// privilégié — c'est précisément sa propriété — mais il pose désormais
        /// des effets, donc « chaque étape nommée » le comprend. Le filtrer sur
        /// les actes, comme ce test le faisait, laissait hors du déroulé la
        /// seule étape que personne n'appelait.
        fn last_refusable(step: Step) -> Option<String> {
            let act = acts::ElevatedAct::authorised_for(&plan(), step)
                .last()
                .map(|act| act.command(false).as_str().to_owned());
            act.or(match step {
                Step::TransferBundle => {
                    Some(super::super::transfer::DEPOSIT_BUNDLE.as_str().to_owned())
                }
                _ => None,
            })
        }

        let stepped: Vec<Step> =
            super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle)
                .iter()
                .filter(|step| last_refusable(**step).is_some())
                .copied()
                .collect();
        assert_eq!(
            stepped.len(),
            super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle).len(),
            "une étape de la tranche ne peut être arrêtée par aucun refus : {stepped:?}"
        );

        for stop_at in stepped.iter() {
            let mut channel = ScriptedChannel::in_the_announced_state();
            channel.failing = vec![last_refusable(*stop_at).expect("l'étape a un geste refusable")];
            let mut secret = SpentSecret::<Vec<u8>>::none();

            let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false)
                .run(
                    &plan(),
                    &carried.payload(),
                    &mut secret,
                    |held: &Vec<u8>| held.as_slice(),
                );

            assert!(
                !outcome.succeeded(),
                "l'arrêt à {stop_at:?} devait interrompre la séquence"
            );
            // Les étapes franchies sont retirables ; l'interrompue ne l'est pas.
            let Unwind::Incomplete { removals, unknown } = outcome.ledger.unwind() else {
                panic!("un arrêt doit dégrader le déroulé : {:?}", outcome.ledger);
            };
            // L'exactitude n'est pas un compte fixe : elle est que **tout ce
            // qui a couru est rendu, et rien d'autre**. Une étape constatée est
            // retirable ; une étape posée dont le constat était différé à
            // l'étape qui vient d'échouer reste inconnue — c'est le cas de
            // `CreateState`, dont le `stat` est porté par
            // `InstallCredentialSources`.
            let steps = super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle);
            let ran = steps
                .iter()
                .position(|step| step == stop_at)
                .expect("l'étape arrêtée appartient à la tranche")
                + 1;
            let expected: usize = steps[..ran].iter().map(|step| recorded_by(*step)).sum();
            assert_eq!(
                removals.len() + unknown.len(),
                expected,
                "arrêt à {stop_at:?} : {expected} effets ont été posés, le registre en rend {}",
                removals.len() + unknown.len()
            );
            assert!(
                !unknown.is_empty(),
                "arrêt à {stop_at:?} : l'étape interrompue doit rester inconnue"
            );
            // Rien de retirable ne peut venir d'une étape non encore atteinte.
            assert!(
                removals.len() < expected,
                "arrêt à {stop_at:?} : une étape non atteinte est déclarée retirable"
            );
        }
    }

    /// Un acte qui échoue laisse sa trace en `Unknown` : le déroulé refusera de
    /// la retirer et dégradera l'ensemble, ce qui est le comportement que le
    /// contrat exige d'un état que personne n'a pu établir.
    #[test]
    fn a_failed_act_is_recorded_unknown_and_degrades_the_unwind() {
        let carried = Held::new();
        use super::super::rollback::Unwind;

        let mut channel = ScriptedChannel::failing_acts();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        assert!(matches!(outcome.ledger.unwind(), Unwind::Incomplete { .. }));
    }

    /// **Le lot arrive réellement sur la machine, et `dpkg` vient après lui.**
    ///
    /// C'est la propriété que ce module existe pour tenir et que rien
    /// n'exerçait : `CREATE_STAGING`, `DEPOSIT_BUNDLE` et ses deux mesures
    /// étaient justes, prouvés, éprouvés par mutation — et personne ne les
    /// appelait. Un ordonnanceur qui ne les joue pas laisse `dpkg --install`
    /// porter sur un fichier qui n'existe pas, sans qu'aucune suite du palier
    /// ne s'en aperçoive.
    ///
    /// Le test dit trois choses d'un coup : les octets qui traversent sont
    /// **exactement** ceux du lot jugé, la chaîne court dans son ordre, et le
    /// premier acte privilégié ne part qu'après elle.
    #[test]
    fn the_bundle_reaches_the_machine_before_any_privileged_act() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );
        assert!(
            outcome.succeeded(),
            "la séquence a été arrêtée : {outcome:?}"
        );

        // Les octets déposés sont ceux du lot, et non une approximation.
        assert_eq!(
            channel
                .held(super::super::transfer::STAGED_ARTIFACT_SUFFIX)
                .as_deref(),
            Some(super::super::plan::tests::ARTIFACT),
            "la machine ne détient pas les octets du lot jugé"
        );

        let seen = channel.seen.borrow();
        let position = |command: FixedCommand| {
            seen.iter()
                .position(|(vu, _)| vu == command.as_str())
                .unwrap_or_else(|| panic!("commande jamais jouée : {}", command.as_str()))
        };
        let staging = position(super::super::transfer::CREATE_STAGING);
        let deposit = position(super::super::transfer::DEPOSIT_BUNDLE);
        let size = position(super::super::transfer::MEASURE_STAGED_SIZE);
        let digest = position(super::super::transfer::MEASURE_STAGED);
        assert!(
            staging < deposit && deposit < size && size < digest,
            "la chaîne du transfert n'a pas couru dans son ordre"
        );

        // `dpkg` installe le lot que la cible détient déjà : il vient après que
        // l'empreinte a été relue là-bas, jamais avant.
        let first_privileged = acts::ElevatedAct::authorised_for(&plan(), Step::InstallPackage)
            .first()
            .expect("l'étape du paquet porte un acte")
            .command(false);
        assert!(
            digest < position(first_privileged),
            "un acte privilégié a couru avant que le lot soit relu sur la cible"
        );
    }

    /// **Un répertoire d'attente que cette exécution n'a pas créé arrête tout
    /// avant que le premier octet parte.**
    ///
    /// La propriété ne se lit pas dans le verdict mais dans ce qui n'a pas eu
    /// lieu : aucun dépôt n'a été tenté. Un ordonnanceur qui déposerait d'abord
    /// et refuserait ensuite aurait déjà écrit le lot dans un répertoire dont
    /// un tiers tient la porte, et le refus ne le reprendrait pas.
    #[test]
    fn a_staging_directory_that_is_not_ours_stops_everything_before_the_first_byte() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        channel.staging_status = 1;
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        let Some(SequenceStop::Refused { step, reason }) = &outcome.stopped else {
            panic!("un répertoire qui n'est pas le nôtre doit refuser : {outcome:?}");
        };
        assert_eq!(*step, Step::TransferBundle);
        assert!(
            reason.contains("StagingNotFresh"),
            "le refus doit porter le nom du juge : {reason}"
        );
        assert!(
            channel.received.borrow().is_empty(),
            "des octets sont partis vers un répertoire que cette exécution n'a pas créé"
        );
        // Rien n'a été touché, donc rien n'entre au registre : nommer un
        // inconnu ici dégraderait un déroulé qui n'a rien à défaire.
        assert!(
            outcome.ledger.items().is_empty(),
            "un registre nomme un effet qu'aucune commande n'a posé : {:?}",
            outcome.ledger
        );
    }

    /// **Un lot qui arrive altéré est refusé avant tout privilège, et le résidu
    /// reste visible.**
    ///
    /// C'est la raison d'être de la mesure après traversée. La machine écrit un
    /// octet de travers ; l'empreinte relue là-bas le dit ; aucun `dpkg` ne
    /// part. Et le fichier partiellement écrit entre au registre en `Unknown` —
    /// il est sur la machine, personne ne l'a établi, donc rien ne le retirera
    /// en aveugle et le déroulé le nomme.
    #[test]
    fn a_bundle_that_arrived_altered_is_refused_and_leaves_a_visible_residue() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        channel.alter = |mut bytes| {
            bytes.push(b'!');
            bytes
        };
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        let Some(SequenceStop::Refused { step, reason }) = &outcome.stopped else {
            panic!("un lot altéré doit refuser : {outcome:?}");
        };
        assert_eq!(*step, Step::TransferBundle);
        // La taille l'attrape avant l'empreinte : c'est l'ordre que le juge
        // tient, et le refus le nomme.
        assert!(
            reason.contains("StagedSizeMismatch"),
            "le refus doit porter le nom du juge : {reason}"
        );

        let seen = channel.seen.borrow();
        for step in super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle) {
            for act in acts::ElevatedAct::authorised_for(&plan(), *step) {
                assert!(
                    !seen.iter().any(|(vu, _)| vu == act.command(false).as_str()),
                    "un acte privilégié a couru sur un lot que la cible n'a pas confirmé"
                );
            }
        }

        let residue = outcome
            .ledger
            .items()
            .iter()
            .find(|item| item.name == super::super::transfer::STAGED_ARTIFACT_SUFFIX)
            .expect("le fichier que `dd` a écrit doit entrer au registre");
        assert_eq!(residue.provenance, Provenance::Unknown);
    }

    /// **La configuration machine traverse elle aussi, et l'acte qui la met en
    /// place ne part qu'après que la cible l'a confirmée.**
    ///
    /// C'est la seconde moitié du câblage. Les octets sont ceux que `compose` a
    /// produits — donc ceux dont l'humain a vu l'empreinte — et l'`install`
    /// privilégié ne déplace qu'un fichier déjà relu sur la machine.
    #[test]
    fn the_machine_configuration_travels_and_is_confirmed_before_it_is_put_in_place() {
        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );
        assert!(
            outcome.succeeded(),
            "la séquence a été arrêtée : {outcome:?}"
        );

        assert_eq!(
            channel
                .held(super::super::configuration::STAGED_CONFIGURATION_SUFFIX)
                .as_deref(),
            Some(configuration().bytes()),
            "la machine ne détient pas les octets composés ici"
        );

        let seen = channel.seen.borrow();
        let position = |command: FixedCommand| {
            seen.iter()
                .position(|(vu, _)| vu == command.as_str())
                .unwrap_or_else(|| panic!("commande jamais jouée : {}", command.as_str()))
        };
        let digest = position(super::super::configuration::MEASURE_CONFIGURATION);
        let install = position(
            acts::ElevatedAct::authorised_for(&plan(), Step::WriteMachineConfiguration)
                .first()
                .expect("l'étape de la configuration porte un acte")
                .command(false),
        );
        assert!(
            digest < install,
            "la configuration a été mise en place avant d'être relue sur la cible"
        );

        // Le résidu et le fichier en place sont deux entrées distinctes : le
        // premier est dans le répertoire d'attente et doit être retiré avec
        // lui, le second est l'effet que l'installation laisse.
        for name in [
            super::super::configuration::STAGED_CONFIGURATION_SUFFIX,
            super::super::plan::MACHINE_CONFIGURATION,
        ] {
            let item = outcome
                .ledger
                .items()
                .iter()
                .find(|item| item.name == name)
                .unwrap_or_else(|| panic!("le registre ne nomme pas {name}"));
            assert_eq!(item.provenance, Provenance::Created);
        }
    }

    /// Le répertoire d'attente est retiré **après** ce qu'il contient.
    ///
    /// Le déroulé rend ses retraits en ordre inverse de création ; encore
    /// faut-il que le répertoire ait été inscrit avant les fichiers qu'il
    /// reçoit. Un registre qui l'inscrirait après demanderait de retirer un
    /// répertoire non vide, c'est-à-dire un retrait qui échoue.
    #[test]
    fn the_staging_directory_is_taken_back_after_what_it_holds() {
        use super::super::rollback::Unwind;

        let carried = Held::new();
        let mut channel = ScriptedChannel::in_the_announced_state();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &carried.payload(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        let Unwind::Complete(removals) = outcome.ledger.unwind() else {
            panic!("une séquence entièrement constatée doit rendre un déroulé complet");
        };
        let position = |name: &str| {
            removals
                .iter()
                .position(|removal| removal.name == name)
                .unwrap_or_else(|| panic!("le déroulé ne retire pas {name}"))
        };
        let directory = position(super::super::transfer::STAGING_DIRECTORY);
        for held in [
            super::super::transfer::STAGED_ARTIFACT_SUFFIX,
            super::super::configuration::STAGED_CONFIGURATION_SUFFIX,
        ] {
            assert!(
                position(held) < directory,
                "le répertoire d'attente serait retiré avant {held}"
            );
        }
    }
}

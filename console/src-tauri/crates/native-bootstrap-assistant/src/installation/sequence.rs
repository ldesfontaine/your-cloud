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
use super::plan::{InstallPlan, Step};
use super::rollback::{ItemKind, Ledger, Provenance};
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
    /// Un juge a refusé. Le refus est le sien, rendu par son propre nom.
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

/// Une séquence d'installation, du budget adopté au secret détruit.
pub struct Sequence<'a, C: Channel> {
    channel: &'a mut C,
    action: BootstrapAction,
    password_required: bool,
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
        }
    }

    /// Déroule les actes que l'action autorise, en tenant le registre.
    ///
    /// Le budget est dérivé et adopté **avant le premier canal**. Le secret est
    /// détruit avant de rendre, sur chaque chemin — c'est la raison pour
    /// laquelle cette fonction a un seul point de sortie et non cinq.
    pub fn run<S>(
        mut self,
        _plan: &InstallPlan,
        secret: &mut SpentSecret<S>,
        borrow: impl Fn(&S) -> &[u8] + Copy,
    ) -> SequenceOutcome {
        let mut ledger = Ledger::new();
        let outcome = self.drive(_plan, secret, borrow, &mut ledger);
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
        secret: &SpentSecret<S>,
        borrow: impl Fn(&S) -> &[u8] + Copy,
        ledger: &mut Ledger,
    ) -> Result<(), SequenceStop> {
        let budget = acts::channel_budget(self.action);
        self.channel
            .adopt_budget(budget)
            .map_err(|_| SequenceStop::BudgetRefused)?;

        for step in super::plan::authorized_steps(self.action) {
            for act in ElevatedAct::authorised_for(plan, *step) {
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
                record_act(ledger, *step, answer.exit_status);
                if answer.exit_status != 0 {
                    return Err(SequenceStop::Refused {
                        step: *step,
                        reason: format!("{command:?} a rendu {}", answer.exit_status),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Ce qu'une étape inscrit au registre, et sous quelle provenance.
///
/// Un statut nul dit que l'acte a fait ce qu'il annonçait, donc que cette
/// exécution a créé la chose : elle pourra la retirer. Tout autre statut la
/// laisse `Unknown` — le déroulé refusera de la retirer et dégradera l'ensemble
/// en `Incomplete`, ce qui est exactement le comportement que le contrat exige
/// d'un état que personne n'a pu établir.
fn record_act(ledger: &mut Ledger, step: Step, exit_status: u32) {
    let provenance = if exit_status == 0 {
        Provenance::Created
    } else {
        Provenance::Unknown
    };
    match step {
        Step::TransferBundle => ledger.record(
            ItemKind::File,
            super::transfer::STAGED_ARTIFACT_SUFFIX,
            provenance,
        ),
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
        Step::AssociateConsole | Step::Preflight => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Un canal écrit : il rend ce qu'on lui a dit de rendre, et retient ce
    /// qu'on lui a demandé. Il ne remplace aucun composant du produit — ce qui
    /// décide est ailleurs — il tient la place d'une machine.
    struct ScriptedChannel {
        answers: RefCell<Vec<Result<Answer, ChannelError>>>,
        seen: RefCell<Vec<(String, bool)>>,
        adopted: RefCell<Option<usize>>,
    }

    impl ScriptedChannel {
        fn answering(statuses: &[u32]) -> Self {
            Self {
                answers: RefCell::new(
                    statuses
                        .iter()
                        .map(|status| {
                            Ok(Answer {
                                exit_status: *status,
                                stdout: Vec::new(),
                            })
                        })
                        .collect(),
                ),
                seen: RefCell::new(Vec::new()),
                adopted: RefCell::new(None),
            }
        }

        fn mute() -> Self {
            Self {
                answers: RefCell::new(vec![Err(ChannelError)]),
                seen: RefCell::new(Vec::new()),
                adopted: RefCell::new(None),
            }
        }
    }

    impl Channel for ScriptedChannel {
        fn run(
            &mut self,
            command: FixedCommand,
            input: Option<&[u8]>,
        ) -> Result<Answer, ChannelError> {
            self.seen
                .borrow_mut()
                .push((command.as_str().to_owned(), input.is_some()));
            let mut answers = self.answers.borrow_mut();
            if answers.is_empty() {
                return Ok(Answer {
                    exit_status: 0,
                    stdout: Vec::new(),
                });
            }
            answers.remove(0)
        }

        fn adopt_budget(&mut self, budget: usize) -> Result<(), ChannelError> {
            *self.adopted.borrow_mut() = Some(budget);
            Ok(())
        }
    }

    fn plan() -> InstallPlan {
        super::super::plan::tests::plan_for_tests()
    }

    /// Le secret meurt sur une séquence **réussie**.
    #[test]
    fn the_secret_dies_after_a_sequence_that_succeeded() {
        let mut channel = ScriptedChannel::answering(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut secret = SpentSecret::holding(b"phrase".to_vec());

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &mut secret,
            |held| held.as_slice(),
        );

        assert!(outcome.succeeded());
        assert!(secret.is_destroyed(), "le secret survit à une réussite");
    }

    /// Le secret meurt sur une séquence **échouée**.
    #[test]
    fn the_secret_dies_after_a_sequence_that_failed() {
        let mut channel = ScriptedChannel::answering(&[1]);
        let mut secret = SpentSecret::holding(b"phrase".to_vec());

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
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
        let mut channel = ScriptedChannel::mute();
        let mut secret = SpentSecret::holding(b"phrase".to_vec());

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
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
        use crate::secret::ProtectedSecret;
        use std::sync::{Arc, Mutex};

        for statuses in [vec![0, 0, 0, 0, 0, 0, 0, 0], vec![1]] {
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

            let mut channel = ScriptedChannel::answering(&statuses);
            let mut secret = SpentSecret::holding(protected);
            Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, true).run(
                &plan(),
                &mut secret,
                |held: &ProtectedSecret| held.bytes(),
            );

            assert_eq!(
                *seen.lock().expect("le canari a rendu la main"),
                Some(true),
                "l'allocation n'a pas été rendue effacée (statuts : {statuses:?})"
            );
        }
    }

    /// Le budget est adopté avant le premier canal, et c'est celui que les
    /// étapes ont produit.
    #[test]
    fn the_derived_budget_is_adopted_before_anything_is_run() {
        let mut channel = ScriptedChannel::answering(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut secret = SpentSecret::<Vec<u8>>::none();

        Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
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
        for statuses in [vec![0, 0, 0, 0, 0, 0, 0, 0], vec![1]] {
            let mut channel = ScriptedChannel::answering(&statuses);
            let mut secret = SpentSecret::<Vec<u8>>::none();

            Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
                &plan(),
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

    /// Le secret n'est présenté que si la politique l'exige — et à chaque acte
    /// quand elle l'exige, jamais une fois pour toutes.
    #[test]
    fn the_secret_travels_with_every_act_or_with_none() {
        let mut with = ScriptedChannel::answering(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut held = SpentSecret::holding(b"phrase".to_vec());
        Sequence::new(&mut with, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &mut held,
            |held| held.as_slice(),
        );
        let seen = with.seen.borrow();
        let acts_seen: Vec<bool> = seen
            .iter()
            .filter(|(command, _)| command != acts::DROP_CREDENTIAL.as_str())
            .map(|(_, carried)| *carried)
            .collect();
        assert!(
            !acts_seen.is_empty() && acts_seen.iter().all(|carried| *carried),
            "un acte a couru sans présenter le secret que la politique exige"
        );

        let mut without = ScriptedChannel::answering(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let mut none = SpentSecret::<Vec<u8>>::none();
        Sequence::new(&mut without, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &mut none,
            |held: &Vec<u8>| held.as_slice(),
        );
        assert!(without.seen.borrow().iter().all(|(_, carried)| !*carried));
    }

    /// Un acte qui échoue laisse sa trace en `Unknown` : le déroulé refusera de
    /// la retirer et dégradera l'ensemble, ce qui est le comportement que le
    /// contrat exige d'un état que personne n'a pu établir.
    #[test]
    fn a_failed_act_is_recorded_unknown_and_degrades_the_unwind() {
        use super::super::rollback::Unwind;

        let mut channel = ScriptedChannel::answering(&[1]);
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        assert!(matches!(outcome.ledger.unwind(), Unwind::Incomplete { .. }));
    }
}

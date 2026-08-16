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
        _plan: &InstallPlan,
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
        let outcome = self.drive(_plan, secret, borrow, &mut ledger, &mut pending);
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
            // quelque chose. Le transfert, dont la chaîne n'est pas encore
            // jouée par cet ordonnanceur, ne pose aucun effet ici : l'inscrire
            // en attente ferait porter au registre un inconnu qui n'existe pas,
            // et un déroulé qui nomme un inconnu imaginaire est aussi faux
            // qu'un déroulé qui en oublie un.
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
        /// L'état que la machine dit d'elle-même, par constat.
        package: Vec<u8>,
        unit: Vec<u8>,
        nodes: Vec<u8>,
        mute: bool,
        /// Les octets exacts que la machine refusera. Vide : tout réussit.
        /// Le canal ne connaît pas les étapes, seulement des commandes — c'est
        /// à l'appelant de dériver du plan celles qu'il veut voir échouer.
        failing: Vec<String>,
        seen: RefCell<Vec<(String, bool)>>,
        adopted: RefCell<Option<usize>>,
    }

    impl ScriptedChannel {
        /// Une machine qui répond exactement ce que les juges attendent.
        fn in_the_announced_state() -> Self {
            Self {
                act_status: 0,
                package: format!(
                    "{} install ok installed 0.0.3\n",
                    super::super::package::PACKAGE_NAME
                )
                .into_bytes(),
                unit: unit_reading(),
                nodes: nodes_reading(),
                mute: false,
                failing: Vec::new(),
                seen: RefCell::new(Vec::new()),
                adopted: RefCell::new(None),
            }
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
            self.seen
                .borrow_mut()
                .push((command.as_str().to_owned(), input.is_some()));
            if self.mute {
                return Err(ChannelError);
            }
            let bytes = command.as_str();
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

    /// Le secret meurt sur une séquence **réussie**.
    #[test]
    fn the_secret_dies_after_a_sequence_that_succeeded() {
        let mut channel = ScriptedChannel::in_the_announced_state();
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
        let mut channel = ScriptedChannel::failing_acts();
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
        let mut channel = ScriptedChannel::in_the_announced_state();
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
        for failing in [false, true] {
            let mut channel = if failing {
                ScriptedChannel::failing_acts()
            } else {
                ScriptedChannel::in_the_announced_state()
            };
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

    /// Le secret voyage avec chaque **acte** quand la politique l'exige — et
    /// avec aucun **constat**, jamais.
    ///
    /// La distinction n'est pas cosmétique : lire l'état d'une machine ne
    /// demande aucun privilège, donc un constat qui présenterait le secret le
    /// dépenserait pour rien et l'exposerait une fois de plus par séquence.
    /// C'est ce test qui a attrapé la confusion quand les juges ont été
    /// câblés : il exigeait que *toute* commande porte le secret, ce qui
    /// n'était vrai que tant que la séquence ne constatait rien.
    #[test]
    fn the_secret_travels_with_every_act_and_with_no_constat() {
        let constats: Vec<&str> = vec![
            super::super::package::QUERY_PACKAGE.as_str(),
            super::super::unit::SHOW_CONTROLLER.as_str(),
            super::super::nodes::STAT_OWNED.as_str(),
        ];

        let mut with = ScriptedChannel::in_the_announced_state();
        let mut held = SpentSecret::holding(b"phrase".to_vec());
        Sequence::new(&mut with, BootstrapAction::InstallServerBundle, true).run(
            &plan(),
            &mut held,
            |held| held.as_slice(),
        );

        let seen = with.seen.borrow();
        let (constats_seen, acts_seen): (Vec<_>, Vec<_>) = seen
            .iter()
            .filter(|(command, _)| command != acts::DROP_CREDENTIAL.as_str())
            .partition(|(command, _)| constats.contains(&command.as_str()));

        assert!(!acts_seen.is_empty(), "aucun acte n'a couru");
        assert!(
            acts_seen.iter().all(|(_, carried)| *carried),
            "un acte a couru sans présenter le secret que la politique exige"
        );
        assert!(!constats_seen.is_empty(), "aucun constat n'a été demandé");
        assert!(
            constats_seen.iter().all(|(_, carried)| !*carried),
            "un constat a dépensé le secret pour lire un état qui ne l'exige pas"
        );

        // Et sans politique de mot de passe, rien ne porte jamais rien.
        let mut without = ScriptedChannel::in_the_announced_state();
        let mut none = SpentSecret::<Vec<u8>>::none();
        Sequence::new(&mut without, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &mut none,
            |held: &Vec<u8>| held.as_slice(),
        );
        assert!(without.seen.borrow().iter().all(|(_, carried)| !*carried));
    }

    /// Le constat, et lui seul, donne sa provenance au registre.
    ///
    /// C'est la propriété que le câblage des juges existe pour tenir : une
    /// machine dont les actes rendent zéro mais dont l'état dément l'annonce
    /// **refuse**, là où un ordonnanceur qui lirait des codes de sortie aurait
    /// inscrit `Created` et se serait déclaré satisfait.
    #[test]
    fn a_machine_whose_state_denies_the_announcement_is_refused_though_every_act_returned_zero() {
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
    /// Un registre qui, arrêté à l'étape *n*, ne rendrait pas exactement les
    /// *n* premières entrées est un registre sur lequel un rollback ne peut pas
    /// s'appuyer : il retirerait trop, ou pas assez.
    #[test]
    fn stopping_at_each_named_step_yields_an_exact_unwind() {
        use super::super::rollback::Unwind;

        let stepped: Vec<Step> =
            super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle)
                .iter()
                .filter(|step| acts::ElevatedAct::authorised_for(&plan(), **step).len() > 0)
                .copied()
                .collect();
        assert!(!stepped.is_empty(), "aucune étape ne porte d'acte");

        for (index, stop_at) in stepped.iter().enumerate() {
            let mut channel = ScriptedChannel::in_the_announced_state();
            channel.failing = acts::ElevatedAct::authorised_for(&plan(), *stop_at)
                .iter()
                .map(|act| act.command(false).as_str().to_owned())
                .collect();
            let mut secret = SpentSecret::<Vec<u8>>::none();

            let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false)
                .run(&plan(), &mut secret, |held: &Vec<u8>| held.as_slice());

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
            // `InstallCredentialSources`. Compter par l'index supposerait qu'un
            // constat suit chaque étape, ce que la table de couverture dément.
            assert_eq!(
                removals.len() + unknown.len(),
                index + 1,
                "arrêt à {stop_at:?} : {} étapes ont couru, le registre en rend {}",
                index + 1,
                removals.len() + unknown.len()
            );
            assert!(
                !unknown.is_empty(),
                "arrêt à {stop_at:?} : l'étape interrompue doit rester inconnue"
            );
            // Rien de retirable ne peut venir d'une étape non encore atteinte.
            assert!(
                removals.len() <= index,
                "arrêt à {stop_at:?} : une étape non atteinte est déclarée retirable"
            );
        }
    }

    /// Un acte qui échoue laisse sa trace en `Unknown` : le déroulé refusera de
    /// la retirer et dégradera l'ensemble, ce qui est le comportement que le
    /// contrat exige d'un état que personne n'a pu établir.
    #[test]
    fn a_failed_act_is_recorded_unknown_and_degrades_the_unwind() {
        use super::super::rollback::Unwind;

        let mut channel = ScriptedChannel::failing_acts();
        let mut secret = SpentSecret::<Vec<u8>>::none();

        let outcome = Sequence::new(&mut channel, BootstrapAction::InstallServerBundle, false).run(
            &plan(),
            &mut secret,
            |held: &Vec<u8>| held.as_slice(),
        );

        assert!(matches!(outcome.ledger.unwind(), Unwind::Incomplete { .. }));
    }
}

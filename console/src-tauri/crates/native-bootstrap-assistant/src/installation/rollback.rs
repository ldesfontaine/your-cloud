//! What a failed installation may take back, and what it must leave visible.
//!
//! This module is the deciding half of the rollback. It performs no removal: it
//! records what each step was about to create, what the machine answered
//! afterwards, and it turns that history into the exact list of removals a
//! failure is allowed to perform — or into a refusal to remove anything at all.
//!
//! **Only what this run created is ever removed.** A directory, an account or a
//! unit that was already there when the step looked is [`Provenance::Found`],
//! and no failure of ours is a reason to take away something we did not put
//! there. This is the difference between undoing an installation and damaging a
//! machine that merely happened to fail one.
//!
//! **An unknown outcome removes nothing and hides nothing.** When a step could
//! not observe what it did — a cut connection, a command that answered neither
//! success nor failure — the item is [`Provenance::Unknown`]. The architecture
//! contract is explicit that a half-configured package, a cut or an unknown
//! state stays visible and forbids any blind removal or replay, so an unknown
//! item is never removed, and its presence downgrades the whole unwind to
//! [`Unwind::Incomplete`] rather than letting a partial success be reported as
//! a clean rollback.
//!
//! **After the authority is transferred, this module stops answering.** Once the
//! Controller holds the infrastructure, undoing is no longer a local matter of
//! files this run created; it belongs to the explicit, machine-by-machine
//! operation that knows which authority is live. [`Ledger::unwind`] therefore
//! refuses outright rather than offering a rollback that would be wrong.

/// What a step was acting on. The kind is carried so a report can say what is
/// being left behind, and so the ordering of removals is legible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    /// The Debian package itself.
    Package,
    /// A locked technical account the installation creates.
    Account,
    /// A directory the Assistant owns, outside the package inventory.
    Directory,
    /// A file the Assistant generated: never a file `dpkg` inventories.
    File,
    /// A systemd unit state the Assistant changed — enabling or starting one
    /// the package delivered inactive.
    UnitState,
    /// A root-owned credential source read by one service.
    CredentialSource,
    /// The Console–Controller association.
    Association,
}

/// What the machine answered when the step looked.
///
/// It is recorded from an observation, never assumed: a step that did not look
/// records [`Provenance::Unknown`], which is honest, rather than
/// [`Provenance::Created`], which would authorise a removal nothing observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// The item was absent before the step and present after it. This run made
    /// it, and this run may take it back.
    Created,
    /// The item was already there. Nothing here will remove it.
    Found,
    /// The step could not establish which of the two it is. Nothing here will
    /// remove it either, and the unwind will say so.
    Unknown,
}

/// One thing an installation step touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub kind: ItemKind,
    /// What names the item on the machine: a path, an account name, a unit
    /// name. It is carried verbatim into the removal list and into the report.
    pub name: String,
    pub provenance: Provenance,
}

/// One removal a failure is allowed to perform.
///
/// It is a distinct type from [`Item`] on purpose: an `Item` is a thing that was
/// touched, a `Removal` is a thing that may be taken back, and only
/// [`Ledger::unwind`] turns one into the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    pub kind: ItemKind,
    pub name: String,
}

/// What a failure may do, given everything the run recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unwind {
    /// Every item is accounted for. Performing these removals, in this order,
    /// returns the machine to the state the run found.
    Complete(Vec<Removal>),
    /// Some item's fate could not be established. The removals listed are still
    /// safe and may be performed, but the machine does not return to its
    /// initial state by them alone, and `unknown` names exactly what a human
    /// or a later explicit operation has to look at.
    ///
    /// A caller that reports this variant as a successful rollback is reporting
    /// a partial success as a success, which is the one thing the contract
    /// forbids.
    Incomplete {
        removals: Vec<Removal>,
        unknown: Vec<String>,
    },
    /// The authority has been transferred. Nothing is undone here.
    AfterTransfer,
}

/// Everything one installation run touched, in the order it touched it.
///
/// The ledger is append-only by construction: there is no method that edits or
/// forgets an entry, because a rollback that could be made to forget an item is
/// a rollback that can be made to remove the wrong thing — or to hide one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    items: Vec<Item>,
    authority_transferred: bool,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what one step observed. Called once per item, after the step
    /// looked at the machine.
    pub fn record(&mut self, kind: ItemKind, name: &str, provenance: Provenance) {
        self.items.push(Item {
            kind,
            name: name.to_owned(),
            provenance,
        });
    }

    /// Marks the point past which this module no longer answers.
    ///
    /// It is one-way. There is no method that takes it back, because a rollback
    /// that could be re-enabled after the transfer is exactly the blind replay
    /// the contract forbids.
    pub fn authority_transferred(&mut self) {
        self.authority_transferred = true;
    }

    /// Le déroulé sous la forme que le protocole transporte — même
    /// vocabulaire, mot pour mot, parce que deux vocabulaires qui
    /// divergeraient rendraient le déroulé intraduisible au moment où
    /// l'humain en a besoin. Aucune coupe, aucun tri : ce qui est au registre
    /// est ce qui voyage, et un registre plus long que la borne du protocole
    /// est refusé à la trame plutôt que raccourci ici en silence.
    pub fn to_protocol(&self) -> Vec<your_cloud_bootstrap_protocol::LedgerItemV1> {
        use your_cloud_bootstrap_protocol::{LedgerItemKind, LedgerItemV1, LedgerProvenance};
        self.items
            .iter()
            .map(|item| LedgerItemV1 {
                kind: match item.kind {
                    ItemKind::Package => LedgerItemKind::Package,
                    ItemKind::Account => LedgerItemKind::Account,
                    ItemKind::Directory => LedgerItemKind::Directory,
                    ItemKind::File => LedgerItemKind::File,
                    ItemKind::UnitState => LedgerItemKind::UnitState,
                    ItemKind::CredentialSource => LedgerItemKind::CredentialSource,
                    ItemKind::Association => LedgerItemKind::Association,
                },
                name: item.name.clone(),
                provenance: match item.provenance {
                    Provenance::Created => LedgerProvenance::Created,
                    Provenance::Found => LedgerProvenance::Found,
                    Provenance::Unknown => LedgerProvenance::Unknown,
                },
            })
            .collect()
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Turns the history into what a failure may take back.
    ///
    /// Removals come back in reverse order of creation: a directory is taken
    /// away after the files inside it, an account after what it owns. Only
    /// [`Provenance::Created`] items are listed — [`Provenance::Found`] items
    /// are silently kept because they are not ours, and [`Provenance::Unknown`]
    /// items are kept *and named*, because those are the ones somebody has to
    /// see.
    pub fn unwind(&self) -> Unwind {
        if self.authority_transferred {
            return Unwind::AfterTransfer;
        }
        let removals: Vec<Removal> = self
            .items
            .iter()
            .rev()
            .filter(|item| item.provenance == Provenance::Created)
            .map(|item| Removal {
                kind: item.kind,
                name: item.name.clone(),
            })
            .collect();
        let unknown: Vec<String> = self
            .items
            .iter()
            .filter(|item| item.provenance == Provenance::Unknown)
            .map(|item| item.name.clone())
            .collect();
        if unknown.is_empty() {
            return Unwind::Complete(removals);
        }
        Unwind::Incomplete { removals, unknown }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nominal failure: three things created, three things taken back, in
    /// the reverse of the order they appeared.
    #[test]
    fn a_failure_takes_back_exactly_what_this_run_created_in_reverse_order() {
        let mut ledger = Ledger::new();
        ledger.record(ItemKind::Package, "your-cloud-server", Provenance::Created);
        ledger.record(ItemKind::Account, CONTROLLER, Provenance::Created);
        ledger.record(ItemKind::Directory, STATE, Provenance::Created);

        let Unwind::Complete(removals) = ledger.unwind() else {
            panic!("a fully observed run must unwind completely");
        };
        assert_eq!(
            removals
                .iter()
                .map(|removal| removal.name.as_str())
                .collect::<Vec<_>>(),
            [STATE, CONTROLLER, "your-cloud-server"]
        );
    }

    const CONTROLLER: &str = "your-cloud-controller";
    const STATE: &str = "/var/lib/your-cloud-controller";

    /// The property that separates undoing an installation from damaging a
    /// machine: what was already there is never taken away.
    #[test]
    fn what_was_already_there_is_never_removed() {
        let mut ledger = Ledger::new();
        ledger.record(ItemKind::Account, CONTROLLER, Provenance::Found);
        ledger.record(ItemKind::Directory, STATE, Provenance::Created);

        let Unwind::Complete(removals) = ledger.unwind() else {
            panic!("a run that found something is still fully observed");
        };
        assert_eq!(removals.len(), 1);
        assert_eq!(removals[0].name, STATE);
    }

    /// The central rollback property of the issue: an unknown outcome is never
    /// removed, it is named, and the unwind refuses to call itself complete.
    #[test]
    fn an_unknown_outcome_removes_nothing_of_itself_and_downgrades_the_unwind() {
        let mut ledger = Ledger::new();
        ledger.record(ItemKind::Package, "your-cloud-server", Provenance::Created);
        ledger.record(
            ItemKind::UnitState,
            "your-cloud-controller.service",
            Provenance::Unknown,
        );
        ledger.record(ItemKind::Directory, STATE, Provenance::Created);

        let Unwind::Incomplete { removals, unknown } = ledger.unwind() else {
            panic!("an unknown item must not produce a complete unwind");
        };
        assert_eq!(unknown, ["your-cloud-controller.service"]);
        // The safe removals are still offered — leaving them would be its own
        // kind of dishonesty — but the unknown one is not among them.
        assert_eq!(
            removals
                .iter()
                .map(|removal| removal.name.as_str())
                .collect::<Vec<_>>(),
            [STATE, "your-cloud-server"]
        );
        assert!(!removals
            .iter()
            .any(|removal| removal.name == "your-cloud-controller.service"));
    }

    /// A run that observed nothing at all still refuses to remove blindly.
    #[test]
    fn a_run_that_observed_nothing_removes_nothing() {
        let mut ledger = Ledger::new();
        ledger.record(ItemKind::Package, "your-cloud-server", Provenance::Unknown);

        let Unwind::Incomplete { removals, unknown } = ledger.unwind() else {
            panic!("an unobserved run must not report a complete unwind");
        };
        assert!(removals.is_empty());
        assert_eq!(unknown, ["your-cloud-server"]);
    }

    /// Past the transfer this module stops answering, and it does not resume.
    #[test]
    fn nothing_is_undone_after_the_authority_is_transferred() {
        let mut ledger = Ledger::new();
        ledger.record(ItemKind::Directory, STATE, Provenance::Created);
        assert!(matches!(ledger.unwind(), Unwind::Complete(_)));

        ledger.authority_transferred();
        assert_eq!(ledger.unwind(), Unwind::AfterTransfer);

        // And it stays that way: recording more does not reopen the door.
        ledger.record(
            ItemKind::File,
            "/var/lib/your-cloud-controller/identity",
            Provenance::Created,
        );
        assert_eq!(ledger.unwind(), Unwind::AfterTransfer);
    }

    /// An empty run unwinds to nothing, and says so as a completion rather than
    /// as an incompletion: there was nothing to be unsure about.
    #[test]
    fn a_run_that_created_nothing_unwinds_to_nothing() {
        assert_eq!(Ledger::new().unwind(), Unwind::Complete(Vec::new()));
    }

    /// La garde de la tranche registre : le déroulé traverse vers le protocole
    /// mot pour mot — chaque nature, chaque provenance, dans l'ordre du
    /// registre, sans coupe. Une torsion de ce passage rendrait à l'humain un
    /// déroulé qui ment sur ce qui a été rendu et sur ce qui reste.
    #[test]
    fn the_ledger_crosses_into_the_protocol_word_for_word() {
        use your_cloud_bootstrap_protocol::{LedgerItemKind, LedgerProvenance};

        let mut ledger = Ledger::new();
        ledger.record(ItemKind::Package, "your-cloud-server", Provenance::Created);
        ledger.record(ItemKind::Account, CONTROLLER, Provenance::Found);
        ledger.record(ItemKind::Directory, STATE, Provenance::Created);
        ledger.record(
            ItemKind::File,
            "/etc/your-cloud/controller.yaml",
            Provenance::Created,
        );
        ledger.record(
            ItemKind::UnitState,
            "your-cloud-controller.service",
            Provenance::Unknown,
        );
        ledger.record(
            ItemKind::CredentialSource,
            "/etc/your-cloud/relay-anchor",
            Provenance::Created,
        );
        ledger.record(
            ItemKind::Association,
            "controller sur sa machine",
            Provenance::Found,
        );

        let crossed = ledger.to_protocol();
        assert_eq!(
            crossed
                .iter()
                .map(|item| (item.kind, item.name.as_str(), item.provenance))
                .collect::<Vec<_>>(),
            [
                (
                    LedgerItemKind::Package,
                    "your-cloud-server",
                    LedgerProvenance::Created
                ),
                (LedgerItemKind::Account, CONTROLLER, LedgerProvenance::Found),
                (LedgerItemKind::Directory, STATE, LedgerProvenance::Created),
                (
                    LedgerItemKind::File,
                    "/etc/your-cloud/controller.yaml",
                    LedgerProvenance::Created
                ),
                (
                    LedgerItemKind::UnitState,
                    "your-cloud-controller.service",
                    LedgerProvenance::Unknown
                ),
                (
                    LedgerItemKind::CredentialSource,
                    "/etc/your-cloud/relay-anchor",
                    LedgerProvenance::Created
                ),
                (
                    LedgerItemKind::Association,
                    "controller sur sa machine",
                    LedgerProvenance::Found
                ),
            ]
        );
    }
}

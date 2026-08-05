//! Who may rewrite the key file, its parents and the binary.
//!
//! A forced command is only as forced as the file that declares it. If the
//! technical account can write its own `authorized_keys`, it chooses its own
//! command; if it can write any directory on the way to that file, it replaces
//! the file; if it can write the binary the command names, it chooses what root
//! runs. The architecture therefore puts the key file outside anything the
//! account can modify and requires the whole chain — file *and* parents — to be
//! owned by `root` and writable by nobody else.
//!
//! **The chain is checked as a chain.** Judging the file alone would accept a
//! `0600 root` file inside a directory the account owns, which is a file the
//! account can replace by replacing its parent. [`judge`] therefore requires
//! each observation to be the parent of the next, starting at `/`, and refuses
//! a set of paths that does not form one descent.
//!
//! **A symbolic link anywhere is a refusal, not a hop.** Following one would
//! mean judging a path that is not the path the enrolment named, and the last
//! component being a link is how a writable target hides behind a root-owned
//! name.
//!
//! Nothing here reads a file. It judges what `stat` answered on the machine,
//! which is the only version of these facts that is worth having.

use crate::machine_identity::account::LockedAccount;

/// What one path is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    Directory,
    File,
    /// Anything that is not one of the two above — a symbolic link, a socket, a
    /// device. It is a single variant because none of them may appear in the
    /// chain, and distinguishing them further would only invite a caller to
    /// accept one.
    Other,
}

/// One path as `stat` described it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedPath {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    /// The permission bits *and* the set-user and set-group bits, as `stat -c
    /// %a` prints them.
    pub mode: u32,
    pub kind: PathKind,
}

/// Why a chain was refused. Every variant names the path it fired on, so a
/// report says which component is wrong rather than that something is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustodyRefusal {
    /// Nothing was observed. An empty chain is refused rather than judged
    /// vacuously.
    NothingObserved,
    /// The chain does not start at the root directory.
    NotRootedAtSlash { path: String },
    /// One observation is not the parent of the next, so the paths judged are
    /// not the descent to the leaf.
    NotTheParentChain { path: String },
    /// A path that is not absolute or not canonical. `..` in a chain would let
    /// the leaf be somewhere the parents never described.
    NotCanonical { path: String },
    /// A component that is neither a directory nor the final file.
    NotADirectory { path: String },
    /// The leaf is not a regular file.
    NotAFile { path: String },
    /// A symbolic link in the chain.
    SymbolicLink { path: String },
    /// A path `root` does not own.
    NotRootOwned { path: String, uid: u32 },
    /// A path the technical account itself may write. It is the refusal the
    /// architecture is really about, and it is named separately from the two
    /// below so a proof can say the account was the one who could write.
    WritableByTheAccount { path: String },
    /// A path any member of its group may write.
    GroupWritable { path: String },
    /// A path anybody may write.
    WorldWritable { path: String },
    /// A set-user or set-group bit. On the binary it would make the elevation
    /// rule beside the point.
    SetUserOrGroup { path: String },
}

/// One chain that only `root` can rewrite.
///
/// It cannot be built by naming its fields, and [`judge`] is the only function
/// that returns one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custody {
    leaf: String,
}

impl Custody {
    /// The path the chain descends to.
    pub fn leaf(&self) -> &str {
        &self.leaf
    }
}

/// The one gate. Nothing else in this crate builds a [`Custody`].
///
/// `chain` is `/`, then every directory down to the leaf, then the leaf itself.
/// `account` is the locked account of [`super::account`]: it is what makes
/// "writable by the account" a refusal with a name rather than an inference the
/// reader has to make from ownership and mode.
pub fn judge(chain: &[ObservedPath], account: &LockedAccount) -> Result<Custody, CustodyRefusal> {
    let Some((leaf, ancestors)) = chain.split_last() else {
        return Err(CustodyRefusal::NothingObserved);
    };
    if chain[0].path != "/" {
        return Err(CustodyRefusal::NotRootedAtSlash {
            path: chain[0].path.clone(),
        });
    }
    for window in chain.windows(2) {
        let (parent, child) = (&window[0], &window[1]);
        if !is_child_of(&parent.path, &child.path) {
            return Err(CustodyRefusal::NotTheParentChain {
                path: child.path.clone(),
            });
        }
    }
    for observed in ancestors {
        if observed.kind != PathKind::Directory {
            return Err(match observed.kind {
                PathKind::Other => CustodyRefusal::SymbolicLink {
                    path: observed.path.clone(),
                },
                _ => CustodyRefusal::NotADirectory {
                    path: observed.path.clone(),
                },
            });
        }
    }
    match leaf.kind {
        PathKind::File => {}
        PathKind::Other => {
            return Err(CustodyRefusal::SymbolicLink {
                path: leaf.path.clone(),
            })
        }
        PathKind::Directory => {
            return Err(CustodyRefusal::NotAFile {
                path: leaf.path.clone(),
            })
        }
    }
    for observed in chain {
        judge_one(observed, account)?;
    }
    Ok(Custody {
        leaf: leaf.path.clone(),
    })
}

fn judge_one(observed: &ObservedPath, account: &LockedAccount) -> Result<(), CustodyRefusal> {
    let path = observed.path.clone();
    if !observed.path.starts_with('/')
        || observed.path.contains("/..")
        || observed.path.contains("/./")
        || (observed.path.len() > 1 && observed.path.ends_with('/'))
    {
        return Err(CustodyRefusal::NotCanonical { path });
    }
    if observed.mode & 0o6000 != 0 {
        return Err(CustodyRefusal::SetUserOrGroup { path });
    }
    if observed.uid == account.uid() && observed.mode & 0o200 != 0 {
        return Err(CustodyRefusal::WritableByTheAccount { path });
    }
    if observed.gid == account.gid() && observed.mode & 0o020 != 0 {
        return Err(CustodyRefusal::WritableByTheAccount { path });
    }
    if observed.mode & 0o002 != 0 {
        return Err(CustodyRefusal::WorldWritable { path });
    }
    if observed.uid != 0 {
        return Err(CustodyRefusal::NotRootOwned {
            path,
            uid: observed.uid,
        });
    }
    if observed.mode & 0o020 != 0 {
        return Err(CustodyRefusal::GroupWritable { path });
    }
    Ok(())
}

/// Whether `child` is exactly one component below `parent`.
fn is_child_of(parent: &str, child: &str) -> bool {
    let prefix = if parent == "/" {
        "/".to_owned()
    } else {
        format!("{parent}/")
    };
    let Some(remainder) = child.strip_prefix(&prefix) else {
        return false;
    };
    !remainder.is_empty() && !remainder.contains('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine_identity::account::{
        self, ObservedAccount, AUXILIARY_ACCOUNT, REQUIRED_HOME, REQUIRED_SHELL,
    };

    fn account() -> LockedAccount {
        account::judge(&ObservedAccount {
            name: AUXILIARY_ACCOUNT.into(),
            uid: 991,
            gid: 991,
            shell: REQUIRED_SHELL.into(),
            home: REQUIRED_HOME.into(),
            password_field: "!".into(),
            supplementary_groups: Vec::new(),
        })
        .expect("the account fixture must be accepted")
    }

    fn directory(path: &str, mode: u32) -> ObservedPath {
        ObservedPath {
            path: path.into(),
            uid: 0,
            gid: 0,
            mode,
            kind: PathKind::Directory,
        }
    }

    fn file(path: &str, mode: u32) -> ObservedPath {
        ObservedPath {
            path: path.into(),
            uid: 0,
            gid: 0,
            mode,
            kind: PathKind::File,
        }
    }

    /// The key file as the enrolment installs it: root-owned all the way down,
    /// and outside anything the account can modify.
    fn key_chain() -> Vec<ObservedPath> {
        vec![
            directory("/", 0o755),
            directory("/etc", 0o755),
            directory("/etc/your-cloud", 0o755),
            directory("/etc/your-cloud/authorized-keys", 0o755),
            file(
                "/etc/your-cloud/authorized-keys/your-cloud-auxiliary",
                0o644,
            ),
        ]
    }

    /// The binary the forced command names.
    fn binary_chain() -> Vec<ObservedPath> {
        vec![
            directory("/", 0o755),
            directory("/usr", 0o755),
            directory("/usr/lib", 0o755),
            directory("/usr/lib/your-cloud", 0o755),
            file("/usr/lib/your-cloud/your-cloud", 0o755),
        ]
    }

    /// The positive control, on both chains the palier cares about.
    #[test]
    fn the_key_file_and_the_binary_are_root_owned_all_the_way_down() {
        assert_eq!(
            judge(&key_chain(), &account())
                .expect("the key chain must be accepted")
                .leaf(),
            "/etc/your-cloud/authorized-keys/your-cloud-auxiliary"
        );
        assert_eq!(
            judge(&binary_chain(), &account())
                .expect("the binary chain must be accepted")
                .leaf(),
            "/usr/lib/your-cloud/your-cloud"
        );
    }

    /// A writable component anywhere on the chain is refused, and the refusal
    /// names the component rather than the leaf.
    #[test]
    fn a_writable_component_anywhere_on_the_chain_is_refused_by_its_own_path() {
        for index in 0..key_chain().len() {
            let mut chain = key_chain();
            chain[index].mode |= 0o002;
            assert_eq!(
                judge(&chain, &account()),
                Err(CustodyRefusal::WorldWritable {
                    path: chain[index].path.clone()
                }),
                "a world-writable {} must be refused",
                chain[index].path
            );

            let mut chain = key_chain();
            chain[index].mode |= 0o020;
            assert_eq!(
                judge(&chain, &account()),
                Err(CustodyRefusal::GroupWritable {
                    path: chain[index].path.clone()
                })
            );
        }
    }

    /// The refusal the architecture is really about: a component the technical
    /// account itself can write, by owning it or by its group.
    #[test]
    fn a_component_the_account_can_write_is_refused_by_its_own_name() {
        let mut owned = key_chain();
        let last = owned.len() - 1;
        owned[last].uid = account().uid();
        assert_eq!(
            judge(&owned, &account()),
            Err(CustodyRefusal::WritableByTheAccount {
                path: owned[last].path.clone()
            })
        );

        let mut grouped = key_chain();
        grouped[last].gid = account().gid();
        grouped[last].mode = 0o664;
        assert_eq!(
            judge(&grouped, &account()),
            Err(CustodyRefusal::WritableByTheAccount {
                path: grouped[last].path.clone()
            })
        );
    }

    /// A component `root` does not own is refused even when nobody else can
    /// write it: the enrolment installed a root-owned chain, and anything else
    /// is a chain it did not install.
    #[test]
    fn a_component_root_does_not_own_is_refused_even_when_it_is_not_writable() {
        let mut chain = key_chain();
        chain[2].uid = 1000;
        chain[2].mode = 0o555;
        assert_eq!(
            judge(&chain, &account()),
            Err(CustodyRefusal::NotRootOwned {
                path: "/etc/your-cloud".into(),
                uid: 1000
            })
        );
    }

    /// A set-user bit on the binary would make the elevation rule beside the
    /// point, so it is refused before anything else about the binary is judged.
    #[test]
    fn a_setuid_binary_is_refused() {
        let mut chain = binary_chain();
        let last = chain.len() - 1;
        chain[last].mode = 0o4755;
        assert_eq!(
            judge(&chain, &account()),
            Err(CustodyRefusal::SetUserOrGroup {
                path: "/usr/lib/your-cloud/your-cloud".into()
            })
        );
    }

    /// A symbolic link is refused wherever it appears, rather than followed.
    #[test]
    fn a_symbolic_link_is_refused_rather_than_followed() {
        for index in 0..key_chain().len() {
            let mut chain = key_chain();
            chain[index].kind = PathKind::Other;
            assert_eq!(
                judge(&chain, &account()),
                Err(CustodyRefusal::SymbolicLink {
                    path: chain[index].path.clone()
                })
            );
        }
    }

    /// A set of root-owned paths that is not the descent to the leaf proves
    /// nothing about the leaf, and is refused as such.
    #[test]
    fn paths_that_are_not_the_descent_to_the_leaf_are_refused() {
        let mut chain = key_chain();
        chain.remove(2);
        assert_eq!(
            judge(&chain, &account()),
            Err(CustodyRefusal::NotTheParentChain {
                path: "/etc/your-cloud/authorized-keys".into()
            })
        );

        let elsewhere = vec![
            directory("/", 0o755),
            directory("/tmp", 0o1777),
            file("/tmp/authorized_keys", 0o644),
        ];
        assert_eq!(
            judge(&elsewhere, &account()),
            Err(CustodyRefusal::WorldWritable {
                path: "/tmp".into()
            })
        );
    }

    /// A chain that does not start at the root directory has parents nobody
    /// looked at.
    #[test]
    fn a_chain_that_does_not_start_at_the_root_directory_is_refused() {
        let mut chain = key_chain();
        chain.remove(0);
        assert_eq!(
            judge(&chain, &account()),
            Err(CustodyRefusal::NotRootedAtSlash {
                path: "/etc".into()
            })
        );
        assert_eq!(judge(&[], &account()), Err(CustodyRefusal::NothingObserved));
    }

    /// The leaf is a file and the components above it are directories; a
    /// directory presented as the leaf is refused rather than judged.
    #[test]
    fn the_leaf_is_a_file_and_everything_above_it_is_a_directory() {
        let mut chain = key_chain();
        let last = chain.len() - 1;
        chain[last].kind = PathKind::Directory;
        assert_eq!(
            judge(&chain, &account()),
            Err(CustodyRefusal::NotAFile {
                path: chain[last].path.clone()
            })
        );

        let mut chain = key_chain();
        chain[3].kind = PathKind::File;
        assert_eq!(
            judge(&chain, &account()),
            Err(CustodyRefusal::NotADirectory {
                path: "/etc/your-cloud/authorized-keys".into()
            })
        );
    }
}

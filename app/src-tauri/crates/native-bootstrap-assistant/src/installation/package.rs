//! Ce que la machine dit du paquet — avant l'acte, et après lui.
//!
//! Le contrat d'amorçage demande deux choses de ce module et rien d'autre.
//! Avant un changement, distinguer **l'absence, une version antérieure exacte
//! et un état ambigu** : ce sont trois situations dont chacune commande un
//! rollback différent, et les confondre reviendrait à promettre un retour que
//! personne ne pourrait tenir. Après la pose, dire si le paquet est
//! **réellement installé à la version que le manifeste signé lie** — l'état
//! constaté, jamais le code de sortie d'un `dpkg` qu'on aurait cru sur parole.
//!
//! **Un paquet à demi configuré n'est pas un échec parmi d'autres.** `dpkg`
//! connaît des états intermédiaires — dépaqueté sans configuration, à demi
//! installé, retiré avec ses fichiers de configuration — et le contrat
//! d'architecture est explicite : ils restent **visibles** et interdisent tout
//! retrait ou rejeu aveugle. Ce module les nomme donc au lieu de les ranger
//! sous « pas installé », précisément pour que la moitié qui agit n'ait aucun
//! moyen de les traiter comme une absence.
//!
//! Ce module est la moitié qui décide : ses entrées sont ce que la machine a
//! répondu, il n'exécute rien, et il ne connaît d'un paquet que ce que la
//! ligne interrogée en dit.

use crate::personal_access::elevation::FixedCommand;

/// Le paquet que ce palier installe, et le seul que ce module interroge.
pub const PACKAGE_NAME: &str = "your-cloud-server";

/// Interroge l'état du paquet. Le format est fixe et explicite : le nom, les
/// trois mots d'état de `dpkg` et la version, séparés par une espace.
///
/// `-f` fige le rendu, ce qui évite d'analyser une sortie destinée aux humains,
/// et `LC_ALL=C` vit dans les octets de la commande — ce sont eux qui sont
/// approuvés et comparés, jamais un environnement posé à côté.
///
/// **Le format est entre apostrophes, et ce n'est pas un ornement.** Ces octets
/// traversent le shell de la machine cible avant d'atteindre `dpkg-query` :
/// sans apostrophes, ce shell développerait `${Package}`, `${Status}` et
/// `${Version}` comme ses propres variables — vides — et la commande
/// demanderait un format vide. Elle ne rendrait pas une erreur : elle rendrait
/// des lignes vides, que ce module lirait comme illisibles sans jamais dire
/// pourquoi. Une garde de ce module tient les apostrophes.
pub const QUERY_PACKAGE: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/dpkg-query -W -f='${Package} ${Status} ${Version}\\n' your-cloud-server",
);

/// Une ligne d'état est courte. Tout ce qui dépasse est refusé avant lecture.
pub const MAX_READING_BYTES: usize = 4096;

/// Le statut, et le seul, d'un paquet réellement installé et configuré.
const INSTALLED_STATUS: &str = "install ok installed";

/// Le code que `dpkg-query` rend lorsqu'aucun paquet ne correspond. C'est sa
/// réponse documentée pour « ce paquet n'est pas connu », et non une panne :
/// tout autre code non nul en est une, et se nomme autrement.
const NO_PACKAGE_MATCHED: u32 = 1;

/// Pourquoi l'état du paquet n'a pas pu être lu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadingRefusal {
    /// La sortie dépasse ce qu'une ligne d'état peut faire.
    ReadingTooLarge,
    /// La commande a échoué autrement qu'en ne trouvant pas le paquet. On ne
    /// sait donc rien, et « on ne sait rien » n'est pas « absent ».
    QueryFailed,
    /// La sortie n'a pas la forme que le format demandé impose.
    ReadingUnreadable,
    /// La ligne parle d'un autre paquet que celui qui a été interrogé.
    ForeignPackageNamed,
}

/// L'état du paquet sur la machine, tel que `dpkg` le connaît.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackageState {
    /// `dpkg` ne connaît pas ce paquet.
    Absent,
    /// Installé **et** configuré, à cette version exacte.
    Installed { version: String },
    /// Connu de `dpkg` dans un état qui n'est ni l'absence ni une installation
    /// aboutie : dépaqueté, à demi configuré, retiré avec ses fichiers de
    /// configuration. Le statut est conservé mot pour mot, parce qu'un rapport
    /// qui dit « ambigu » sans dire lequel ne dit rien à qui devra regarder.
    Ambiguous { status: String, version: String },
}

/// Ce qu'une installation s'apprête à changer, une fois l'état lu.
///
/// C'est cette valeur qui décide de ce qu'un échec devra rendre : l'absence
/// initiale, ou la version antérieure exacte. Le contrat approuve le rollback
/// en même temps que le plan, et il ne peut le faire que parce que cette
/// distinction est établie **avant** le premier acte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Rien n'est là. Un échec devra rendre l'absence.
    FromAbsence,
    /// Une version antérieure exacte est là. Un échec devra la rendre.
    FromVersion { version: String },
    /// La version visée est déjà installée. Il n'y a rien à poser.
    AlreadyAtThisVersion,
    /// L'état est ambigu. Le contrat interdit d'installer par-dessus : ni
    /// retrait, ni rejeu, ni pose aveugle — la machine reste telle quelle et
    /// un humain regarde.
    RefusedAmbiguousState { status: String },
}

/// La preuve que le paquet est posé, à la version exacte que le lot liait.
///
/// Comme les autres témoins de ce crate, il ne peut pas être construit en
/// nommant ses champs, et [`posed`] est la seule fonction qui en rend un.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PosedPackage {
    version: String,
}

impl PosedPackage {
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// Pourquoi la pose n'a pas été constatée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoseRefusal {
    /// `dpkg` a rendu ce qu'il voulait : le paquet n'est pas là.
    NotInstalled,
    /// Le paquet est là, dans un état intermédiaire. Rien n'est retiré, rien
    /// n'est rejoué, et cet état est nommé.
    HalfConfigured { status: String },
    /// Le paquet est installé, mais pas à la version que le lot liait.
    UnexpectedVersion { version: String },
}

/// Lit ce que la machine a répondu, et rien de plus.
///
/// L'absence est la réponse documentée de `dpkg-query` pour un paquet inconnu,
/// et elle est reconnue à son code exact plutôt qu'à « un code non nul » : une
/// commande qui échoue pour une autre raison ne prouve pas une absence, et la
/// prendre pour telle ferait installer par-dessus un état que personne n'a lu.
pub fn read(exit_status: u32, stdout: &[u8]) -> Result<PackageState, ReadingRefusal> {
    if stdout.len() > MAX_READING_BYTES {
        return Err(ReadingRefusal::ReadingTooLarge);
    }
    if exit_status != 0 {
        return if exit_status == NO_PACKAGE_MATCHED && stdout.is_empty() {
            Ok(PackageState::Absent)
        } else {
            Err(ReadingRefusal::QueryFailed)
        };
    }

    let line = std::str::from_utf8(stdout)
        .map_err(|_| ReadingRefusal::ReadingUnreadable)?
        .strip_suffix('\n')
        .ok_or(ReadingRefusal::ReadingUnreadable)?;
    let fields: Vec<&str> = line.split(' ').collect();
    // Le nom, les trois mots d'état, la version : le format demandé en produit
    // exactement cinq, et une ligne qui en compte un autre nombre n'est pas la
    // réponse à la question posée.
    let [package, want, flag, status, version] = fields.as_slice() else {
        return Err(ReadingRefusal::ReadingUnreadable);
    };
    if *package != PACKAGE_NAME {
        return Err(ReadingRefusal::ForeignPackageNamed);
    }
    if version.is_empty() {
        return Err(ReadingRefusal::ReadingUnreadable);
    }

    let status_words = format!("{want} {flag} {status}");
    if status_words == INSTALLED_STATUS {
        Ok(PackageState::Installed {
            version: (*version).to_owned(),
        })
    } else {
        Ok(PackageState::Ambiguous {
            status: status_words,
            version: (*version).to_owned(),
        })
    }
}

/// Ce qu'une installation de `expected_version` changerait, vu l'état lu.
pub fn change(state: &PackageState, expected_version: &str) -> Change {
    match state {
        PackageState::Absent => Change::FromAbsence,
        PackageState::Installed { version } if version == expected_version => {
            Change::AlreadyAtThisVersion
        }
        PackageState::Installed { version } => Change::FromVersion {
            version: version.clone(),
        },
        PackageState::Ambiguous { status, .. } => Change::RefusedAmbiguousState {
            status: status.clone(),
        },
    }
}

/// Constate la pose : le paquet est-il **réellement** installé, à la version
/// exacte que le manifeste signé liait ?
///
/// C'est ici que « vérification après pose » cesse d'être une intention. Un
/// `dpkg --install` qui rend zéro n'a pas prouvé l'état de la machine ; cette
/// fonction ne lit que ce que la machine dit d'elle-même ensuite.
pub fn posed(state: &PackageState, bound_version: &str) -> Result<PosedPackage, PoseRefusal> {
    match state {
        PackageState::Absent => Err(PoseRefusal::NotInstalled),
        PackageState::Ambiguous { status, .. } => Err(PoseRefusal::HalfConfigured {
            status: status.clone(),
        }),
        PackageState::Installed { version } if version == bound_version => Ok(PosedPackage {
            version: version.clone(),
        }),
        PackageState::Installed { version } => Err(PoseRefusal::UnexpectedVersion {
            version: version.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(status: &str, version: &str) -> Vec<u8> {
        format!("{PACKAGE_NAME} {status} {version}\n").into_bytes()
    }

    /// Le contrôle positif : un paquet installé et configuré est lu comme tel,
    /// avec sa version exacte.
    #[test]
    fn an_installed_package_is_read_with_its_exact_version() {
        assert_eq!(
            read(0, &reading(INSTALLED_STATUS, "0.1.0")),
            Ok(PackageState::Installed {
                version: "0.1.0".into()
            })
        );
    }

    /// La réponse documentée de `dpkg-query` pour un paquet inconnu est une
    /// absence ; toute autre panne n'en est pas une, et se nomme.
    #[test]
    fn only_the_documented_answer_for_an_unknown_package_reads_as_absence() {
        assert_eq!(read(NO_PACKAGE_MATCHED, b""), Ok(PackageState::Absent));
        // Un autre code : on ne sait rien, et « on ne sait rien » n'est pas
        // « absent » — c'est la confusion qui ferait poser par-dessus un état
        // que personne n'a lu.
        assert_eq!(read(2, b""), Err(ReadingRefusal::QueryFailed));
        assert_eq!(read(127, b""), Err(ReadingRefusal::QueryFailed));
        // Le code de l'absence, mais avec une sortie : la réponse ne
        // correspond pas à son propre code.
        assert_eq!(
            read(NO_PACKAGE_MATCHED, &reading(INSTALLED_STATUS, "0.1.0")),
            Err(ReadingRefusal::QueryFailed)
        );
    }

    /// Chaque état intermédiaire de `dpkg` est nommé plutôt que rangé sous
    /// « pas installé » : c'est ce qui empêche la moitié qui agit de les
    /// traiter comme une absence.
    #[test]
    fn every_intermediate_dpkg_state_is_named_rather_than_flattened() {
        for status in [
            "install ok half-configured",
            "install ok unpacked",
            "install ok half-installed",
            "deinstall ok config-files",
            "hold ok installed",
        ] {
            assert_eq!(
                read(0, &reading(status, "0.1.0")),
                Ok(PackageState::Ambiguous {
                    status: status.into(),
                    version: "0.1.0".into()
                }),
                "l'état était : {status}"
            );
        }
    }

    /// Les trois situations que le contrat exige de distinguer avant un
    /// changement, et la quatrième qu'il interdit de franchir.
    #[test]
    fn the_three_states_before_a_change_are_distinguished_and_the_ambiguous_one_refused() {
        assert_eq!(change(&PackageState::Absent, "0.1.0"), Change::FromAbsence);
        assert_eq!(
            change(
                &PackageState::Installed {
                    version: "0.0.3".into()
                },
                "0.1.0"
            ),
            Change::FromVersion {
                version: "0.0.3".into()
            }
        );
        assert_eq!(
            change(
                &PackageState::Installed {
                    version: "0.1.0".into()
                },
                "0.1.0"
            ),
            Change::AlreadyAtThisVersion
        );
        assert_eq!(
            change(
                &PackageState::Ambiguous {
                    status: "install ok half-configured".into(),
                    version: "0.1.0".into()
                },
                "0.1.0"
            ),
            Change::RefusedAmbiguousState {
                status: "install ok half-configured".into()
            }
        );
    }

    /// La pose n'est constatée que sur l'état réel, et à la version exacte.
    #[test]
    fn the_pose_is_constated_on_the_state_and_on_the_exact_version() {
        let installed = PackageState::Installed {
            version: "0.1.0".into(),
        };
        assert_eq!(
            posed(&installed, "0.1.0").map(|posed| posed.version().to_owned()),
            Ok("0.1.0".into())
        );
        assert_eq!(
            posed(&installed, "0.1.1"),
            Err(PoseRefusal::UnexpectedVersion {
                version: "0.1.0".into()
            })
        );
        assert_eq!(
            posed(&PackageState::Absent, "0.1.0"),
            Err(PoseRefusal::NotInstalled)
        );
        assert_eq!(
            posed(
                &PackageState::Ambiguous {
                    status: "install ok half-configured".into(),
                    version: "0.1.0".into()
                },
                "0.1.0"
            ),
            Err(PoseRefusal::HalfConfigured {
                status: "install ok half-configured".into()
            })
        );
    }

    /// Une ligne qui n'est pas la réponse à la question posée est refusée par
    /// sa propre raison.
    #[test]
    fn a_reading_that_is_not_the_answer_is_refused_by_its_own_reason() {
        let cases: [(Vec<u8>, ReadingRefusal); 5] = [
            (
                format!("autre-paquet {INSTALLED_STATUS} 0.1.0\n").into_bytes(),
                ReadingRefusal::ForeignPackageNamed,
            ),
            (
                // Quatre champs : pas le format demandé.
                format!("{PACKAGE_NAME} install ok installed\n").into_bytes(),
                ReadingRefusal::ReadingUnreadable,
            ),
            (
                // Sans saut de ligne final : une sortie tronquée.
                format!("{PACKAGE_NAME} {INSTALLED_STATUS} 0.1.0").into_bytes(),
                ReadingRefusal::ReadingUnreadable,
            ),
            (
                b"\xff\xfe pas de l'UTF-8\n".to_vec(),
                ReadingRefusal::ReadingUnreadable,
            ),
            (
                vec![b'a'; MAX_READING_BYTES + 1],
                ReadingRefusal::ReadingTooLarge,
            ),
        ];

        for (stdout, expected) in cases {
            assert_eq!(read(0, &stdout), Err(expected));
        }
    }

    /// La commande porte sa locale et son format dans ses propres octets, et
    /// n'interroge que le paquet de ce palier.
    ///
    /// La garde des apostrophes est la plus importante de ce test : ces octets
    /// traversent le shell de la cible, et un format non protégé s'y
    /// développerait en vide. Le défaut serait silencieux — des lignes vides
    /// lues comme illisibles — donc il est attrapé ici, sur les octets, plutôt
    /// que sur une machine.
    #[test]
    fn the_query_carries_its_locale_its_quoted_format_and_one_package_name() {
        let command = QUERY_PACKAGE.as_str();
        assert!(command.starts_with("/usr/bin/env LC_ALL=C "));
        assert!(command.ends_with(PACKAGE_NAME));
        assert!(command.contains("-f='${Package} ${Status} ${Version}\\n'"));
        // Aucune référence de variable ne reste hors des apostrophes.
        let (_, after_format) = command
            .split_once("-f='")
            .expect("le format est introduit par une apostrophe");
        let (quoted, tail) = after_format
            .split_once('\'')
            .expect("le format est refermé par une apostrophe");
        assert!(quoted.contains("${Package}"));
        assert!(!tail.contains('$'));
    }
}

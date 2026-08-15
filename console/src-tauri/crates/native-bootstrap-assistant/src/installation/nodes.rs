//! Ce que la machine dit des fichiers que l'Assistant a posés.
//!
//! `dpkg` inventorie ce que le paquet possède ; ces nœuds-ci n'y sont pas, par
//! décision du contrat de distribution — la configuration propre à une machine,
//! l'état privé et les sources de credentials sont générés par l'Assistant et
//! gérés séparément par lui. Personne d'autre ne les constate donc, et un
//! `install` qui a rendu zéro n'a rien prouvé de leurs droits.
//!
//! **Le mode est une propriété de sécurité, pas un détail d'écriture.** Les
//! sources de credentials reçoivent les moitiés privées des identités de
//! commande : `0600 root:root` est ce que la preuve `#38` a relevé sur la
//! machine, et c'est ce que ce constat exige. Un fichier posé `0644` par une
//! ombrelle mal réglée resterait fonctionnel — le service démarrerait, la
//! preuve serait verte, et le secret serait lisible par tout compte de la
//! machine. C'est exactement le genre de divergence qu'un constat d'état
//! attrape et qu'un code de sortie ne voit pas.
//!
//! Ce module est la moitié qui décide : ses entrées sont ce que la machine a
//! répondu, il n'écrit rien et n'ouvre rien.

use super::plan::{CONTROLLER_STATE_DIRECTORY, CREDENTIAL_SOURCE_DIRECTORY, MACHINE_CONFIGURATION};
use crate::personal_access::elevation::FixedCommand;

/// Interroge d'un coup les nœuds que l'Assistant possède.
///
/// Le format est fixe et sans ambiguïté : le chemin, le propriétaire et le
/// groupe **numériques** — un nom d'utilisateur dépendrait de la base de
/// comptes de la machine là où `0` est `root` partout — le mode en octal, et le
/// genre du nœud. `LC_ALL=C` vit dans les octets, comme partout ailleurs.
///
/// **Le format est entre apostrophes, et ce n'est pas un ornement.** Ces octets
/// traversent le shell de la cible : sans apostrophes, il découperait
/// `%n %u %g %a %F` en cinq mots, `stat` prendrait `%n` pour format et
/// `%u`, `%g`, `%a`, `%F` pour des **noms de fichiers**. La commande ne serait
/// pas rejetée — elle rendrait des lignes sur des fichiers inexistants, que ce
/// module lirait comme illisibles sans jamais dire pourquoi. Une garde de ce
/// module tient les apostrophes, comme pour l'interrogation du paquet.
pub const STAT_OWNED: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/stat -c '%n %u %g %a %F' -- \
     /etc/your-cloud/controller.env \
     /var/lib/private/your-cloud-controller \
     /etc/your-cloud/controller-credentials",
);

/// Quatre lignes courtes. Au-delà, la sortie n'est pas celle qui a été demandée.
pub const MAX_READING_BYTES: usize = 4096;

/// L'uid et le gid de `root`, numériques : le seul propriétaire que ces nœuds
/// peuvent avoir.
const ROOT_ID: &str = "0";

/// Ce qu'un nœud posé doit être.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expectation {
    pub path: &'static str,
    /// Le genre exact, tel que `stat -c %F` le nomme.
    pub kind: &'static str,
    /// Le mode octal, tel que `stat -c %a` le rend — sans zéro de tête.
    pub mode: &'static str,
}

/// Les nœuds que l'Assistant pose, et ce que chacun doit être.
///
/// Deux origines, distinguées parce qu'elles n'ont pas la même autorité :
///
/// - `0600` sur les sources de credentials et `0700` sur l'état privé sont des
///   valeurs **mesurées** par la preuve `#38` sur une machine réelle ;
/// - `0600` sur la configuration de machine est une **décision de ce contrat**
///   qu'aucune preuve n'a encore constatée. Elle ne porte pas de secret, mais
///   rien n'exige qu'une topologie privée soit lisible par tout compte de la
///   machine, et la même posture pour tout ce que l'Assistant écrit sous
///   `/etc/your-cloud` évite d'avoir à se demander, fichier par fichier, si
///   celui-ci méritait d'être plus lâche.
pub const EXPECTED_NODES: [Expectation; 3] = [
    Expectation {
        path: MACHINE_CONFIGURATION,
        kind: "regular file",
        mode: "600",
    },
    Expectation {
        path: CONTROLLER_STATE_DIRECTORY,
        kind: "directory",
        mode: "700",
    },
    Expectation {
        path: CREDENTIAL_SOURCE_DIRECTORY,
        kind: "directory",
        mode: "700",
    },
];

/// Pourquoi les nœuds posés n'ont pas été constatés conformes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeRefusal {
    /// La sortie dépasse ce que ces lignes peuvent faire.
    ReadingTooLarge,
    /// La sortie n'est pas une suite de lignes de `stat`, ou elle est vide —
    /// une sortie vide ne dit pas « tout est absent », elle dit que la commande
    /// n'a rien répondu, ce qui n'est pas la même chose.
    ReadingUnreadable,
    /// Une ligne nomme un chemin qui n'a pas été demandé.
    ForeignPathReported { path: String },
    /// Un nœud attendu manque à la réponse. `stat` nomme sur sa sortie d'erreur
    /// ceux qu'il n'a pas pu lire, et leur ligne manque ici.
    Missing { path: &'static str },
    /// Le nœud existe mais n'est pas du genre attendu — un fichier là où un
    /// répertoire est requis, ou un lien à la place de l'un des deux.
    WrongKind {
        path: &'static str,
        observed: String,
    },
    /// Le nœud n'appartient pas à `root`.
    WrongOwner {
        path: &'static str,
        uid: String,
        gid: String,
    },
    /// Le nœud est plus ouvert — ou plus fermé — que ce que le contrat exige.
    WrongMode {
        path: &'static str,
        observed: String,
    },
}

/// La preuve que les nœuds de l'Assistant sont posés comme le contrat les veut.
///
/// Comme les autres témoins de ce crate, elle ne peut pas être construite en
/// nommant ses champs, et [`owned`] est la seule fonction qui en rend une.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedNodes {
    count: usize,
}

impl OwnedNodes {
    /// Combien de nœuds ont été constatés. C'est toujours la totalité de
    /// [`EXPECTED_NODES`] : un manquant refuse au lieu de réduire ce nombre.
    pub fn count(&self) -> usize {
        self.count
    }
}

/// Constate chaque nœud attendu : présent, du bon genre, à `root`, au bon mode.
///
/// Le code de sortie n'est **pas** la porte, et c'est une propriété de `stat` :
/// un opérande illisible le fait terminer non nul tout en imprimant les lignes
/// des autres. Gater là-dessus perdrait l'information la plus utile — lequel
/// manque — au profit d'un « quelque chose a échoué ». Ce sont donc les lignes
/// qui répondent, et une sortie vide est refusée comme illisible plutôt que lue
/// comme une absence générale.
pub fn owned(stdout: &[u8]) -> Result<OwnedNodes, NodeRefusal> {
    if stdout.len() > MAX_READING_BYTES {
        return Err(NodeRefusal::ReadingTooLarge);
    }
    let text = std::str::from_utf8(stdout).map_err(|_| NodeRefusal::ReadingUnreadable)?;
    let mut readings = Vec::new();
    for line in text.lines() {
        let mut fields = line.splitn(5, ' ');
        let (Some(path), Some(uid), Some(gid), Some(mode), Some(kind)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(NodeRefusal::ReadingUnreadable);
        };
        readings.push((path, uid, gid, mode, kind));
    }
    if readings.is_empty() {
        return Err(NodeRefusal::ReadingUnreadable);
    }
    for (path, ..) in &readings {
        if !EXPECTED_NODES.iter().any(|node| node.path == *path) {
            return Err(NodeRefusal::ForeignPathReported {
                path: (*path).to_owned(),
            });
        }
    }

    for node in EXPECTED_NODES {
        let (_, uid, gid, mode, kind) = readings
            .iter()
            .find(|(path, ..)| *path == node.path)
            .ok_or(NodeRefusal::Missing { path: node.path })?;
        if *kind != node.kind {
            return Err(NodeRefusal::WrongKind {
                path: node.path,
                observed: (*kind).to_owned(),
            });
        }
        if *uid != ROOT_ID || *gid != ROOT_ID {
            return Err(NodeRefusal::WrongOwner {
                path: node.path,
                uid: (*uid).to_owned(),
                gid: (*gid).to_owned(),
            });
        }
        if *mode != node.mode {
            return Err(NodeRefusal::WrongMode {
                path: node.path,
                observed: (*mode).to_owned(),
            });
        }
    }

    Ok(OwnedNodes {
        count: EXPECTED_NODES.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(node: &Expectation) -> String {
        format!("{} 0 0 {} {}", node.path, node.mode, node.kind)
    }

    fn nominal() -> Vec<u8> {
        let lines: Vec<String> = EXPECTED_NODES.iter().map(line).collect();
        format!("{}\n", lines.join("\n")).into_bytes()
    }

    fn with(path: &str, replacement: &str) -> Vec<u8> {
        let nominal = String::from_utf8(nominal()).unwrap();
        let lines: Vec<String> = nominal
            .lines()
            .map(|existing| {
                if existing.starts_with(&format!("{path} ")) {
                    replacement.to_owned()
                } else {
                    existing.to_owned()
                }
            })
            .collect();
        format!("{}\n", lines.join("\n")).into_bytes()
    }

    /// Le contrôle positif. Tout ce qui suit est celui-ci, moins une chose.
    #[test]
    fn every_node_the_assistant_places_is_constated() {
        let constated = owned(&nominal()).expect("le contrôle positif doit être constaté");
        assert_eq!(constated.count(), EXPECTED_NODES.len());
    }

    /// La propriété que ce module existe pour tenir : un mode plus ouvert que
    /// le contrat est refusé, alors que la machine fonctionnerait très bien
    /// avec — le service démarrerait, et le secret serait lisible par tout
    /// compte de la machine.
    #[test]
    fn a_node_left_more_open_than_the_contract_is_refused_though_it_would_work() {
        for (node, loosened) in [
            (&EXPECTED_NODES[0], "644"),
            (&EXPECTED_NODES[1], "755"),
            (&EXPECTED_NODES[2], "755"),
        ] {
            let reading = with(
                node.path,
                &format!("{} 0 0 {} {}", node.path, loosened, node.kind),
            );

            assert_eq!(
                owned(&reading),
                Err(NodeRefusal::WrongMode {
                    path: node.path,
                    observed: loosened.to_owned()
                }),
                "le nœud était : {}",
                node.path
            );
        }
    }

    /// Un nœud qui n'appartient pas à `root` est refusé, et les deux
    /// identifiants sont conservés : un mauvais groupe et un mauvais
    /// propriétaire ne demandent pas le même geste.
    #[test]
    fn a_node_that_root_does_not_own_is_refused_with_both_identifiers() {
        let node = &EXPECTED_NODES[2];
        let reading = with(
            node.path,
            &format!("{} 1000 1000 {} {}", node.path, node.mode, node.kind),
        );

        assert_eq!(
            owned(&reading),
            Err(NodeRefusal::WrongOwner {
                path: node.path,
                uid: "1000".into(),
                gid: "1000".into()
            })
        );
    }

    /// Un genre inattendu est refusé : un lien symbolique posé à la place d'un
    /// répertoire de credentials pointerait ailleurs sans rien casser.
    #[test]
    fn a_node_of_another_kind_is_refused() {
        let node = &EXPECTED_NODES[2];
        let reading = with(
            node.path,
            &format!("{} 0 0 {} symbolic link", node.path, node.mode),
        );

        assert_eq!(
            owned(&reading),
            Err(NodeRefusal::WrongKind {
                path: node.path,
                observed: "symbolic link".into()
            })
        );
    }

    /// `stat` nomme sur sa sortie d'erreur ce qu'il n'a pas pu lire : la ligne
    /// manque, et l'absence se nomme par le chemin qui manque.
    #[test]
    fn a_node_whose_line_is_absent_is_named_missing() {
        let nominal = String::from_utf8(nominal()).unwrap();
        for node in EXPECTED_NODES {
            let kept: Vec<&str> = nominal
                .lines()
                .filter(|line| !line.starts_with(&format!("{} ", node.path)))
                .collect();

            assert_eq!(
                owned(format!("{}\n", kept.join("\n")).as_bytes()),
                Err(NodeRefusal::Missing { path: node.path })
            );
        }
    }

    /// Une sortie vide ne dit pas « tout est absent » : elle dit que la
    /// commande n'a rien répondu, et les deux ne se confondent pas.
    #[test]
    fn an_empty_reading_is_unreadable_rather_than_a_general_absence() {
        assert_eq!(owned(b""), Err(NodeRefusal::ReadingUnreadable));
        assert_eq!(owned(b"\n"), Err(NodeRefusal::ReadingUnreadable));
    }

    /// Une ligne qui parle d'un chemin non demandé est refusée : la réponse ne
    /// correspond pas à la question.
    #[test]
    fn a_line_about_a_path_nobody_asked_for_is_refused() {
        let mut reading = String::from_utf8(nominal()).unwrap();
        reading.push_str("/etc/shadow 0 0 640 regular file\n");

        assert_eq!(
            owned(reading.as_bytes()),
            Err(NodeRefusal::ForeignPathReported {
                path: "/etc/shadow".into()
            })
        );
    }

    /// Ce qui n'est pas une ligne de `stat` est refusé avant interprétation.
    #[test]
    fn a_reading_that_is_not_a_stat_line_is_refused() {
        assert_eq!(
            owned(b"trois champs seulement\n"),
            Err(NodeRefusal::ReadingUnreadable)
        );
        assert_eq!(
            owned(&vec![b'a'; MAX_READING_BYTES + 1]),
            Err(NodeRefusal::ReadingTooLarge)
        );
    }

    /// La commande porte sa locale, son format numérique, et n'interroge que
    /// les nœuds que ce module juge.
    #[test]
    fn the_command_asks_for_exactly_the_nodes_this_module_judges() {
        let command = STAT_OWNED.as_str();
        assert!(command.starts_with("/usr/bin/env LC_ALL=C "));
        // Le format est protégé du découpage en mots : sans apostrophes, le
        // shell de la cible en ferait cinq arguments et `stat` chercherait des
        // fichiers nommés `%u`, `%g`, `%a` et `%F`.
        assert!(command.contains("-c '%n %u %g %a %F' --"));
        // Les identifiants sont demandés numériques : `%u`/`%g`, jamais
        // `%U`/`%G` qui dépendraient de la base de comptes de la machine.
        assert!(!command.contains("%U") && !command.contains("%G"));
        assert!(!command.contains("  "));
        // Aucun blanc hors apostrophes ne sépare les jetons du format.
        let (_, after_format) = command
            .split_once("-c '")
            .expect("le format est introduit par une apostrophe");
        let (quoted, tail) = after_format
            .split_once('\'')
            .expect("le format est refermé par une apostrophe");
        assert_eq!(quoted, "%n %u %g %a %F");
        assert!(!tail.contains('%'));
        for node in EXPECTED_NODES {
            assert!(
                command.contains(node.path),
                "nœud non demandé : {}",
                node.path
            );
        }
    }
}

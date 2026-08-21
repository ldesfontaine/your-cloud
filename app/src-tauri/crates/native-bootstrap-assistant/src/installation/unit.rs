//! Ce que la machine dit de l'unité activée : elle tourne, et elle est confinée.
//!
//! La preuve `#38` relevait ces valeurs **au harnais** — `systemctl show` lancé
//! par le pilote, comparé par le pilote. Un harnais qui mesure l'isolation du
//! produit prouve que le harnais sait la lire, pas que le produit la constate.
//! Ce module déplace ce relevé dans le produit : c'est l'Assistant qui demande,
//! l'Assistant qui juge, et la preuve LAB confronte ensuite son verdict à un
//! relevé indépendant.
//!
//! **Un service actif n'est pas un service confiné.** `ActiveState=active`
//! répond « il tourne » et rien d'autre : un Controller qui tournerait en
//! `root`, sans budget et sans bornes de capacités serait actif tout autant.
//! Les deux questions sont donc posées ensemble, et une divergence d'isolation
//! refuse comme un service mort — parce qu'un service dont le confinement a
//! glissé est un service que personne n'a approuvé.
//!
//! Les valeurs attendues ne sont pas écrites ici : elles sont dérivées des
//! constantes de [`super::plan`], seule source du compte, de l'unité et des
//! budgets. Une constante changée au plan fait rougir ce constat plutôt que de
//! le laisser mesurer une isolation périmée.

use super::plan::{CONTROLLER_ACCOUNT, CONTROLLER_BUDGETS, CONTROLLER_UNIT};
use crate::personal_access::elevation::FixedCommand;

/// Interroge l'état et le confinement de l'unité, en une fois.
///
/// Les propriétés sont demandées nommément : `systemctl show` sans `-p` rend
/// des centaines de lignes, et un constat qui lirait tout serait un constat
/// dont la surface d'analyse dépend de la version de systemd installée.
/// `--no-pager` interdit qu'un terminal s'invite dans une sortie lue par un
/// programme, et `LC_ALL=C` vit dans les octets, comme partout ailleurs.
pub const SHOW_CONTROLLER: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/systemctl show --no-pager \
     -p ActiveState,SubState,DynamicUser,User,TasksMax,MemoryMax,NoNewPrivileges,ProtectSystem,CapabilityBoundingSet \
     -- your-cloud-controller.service",
);

/// Neuf propriétés courtes. Au-delà, la sortie n'est pas celle qui a été
/// demandée et elle est refusée avant d'être lue.
pub const MAX_READING_BYTES: usize = 8192;

/// Les propriétés d'isolation, et la valeur que chacune doit porter.
///
/// `MemoryMax` est en octets là où le plan borne en mébioctets : la conversion
/// est faite ici, à partir de la constante du plan, plutôt qu'écrite en dur —
/// un budget changé au plan reste tenu par ce constat.
#[cfg(not(test))]
fn expected_isolation() -> [(&'static str, String); 7] {
    isolation()
}

/// Exposée aux suites du crate pour qu'un canal écrit puisse répondre comme une
/// machine réellement confinée, sans recopier ces valeurs ailleurs — deux
/// copies donneraient deux définitions du confinement attendu.
#[cfg(test)]
pub(crate) fn expected_isolation() -> [(&'static str, String); 7] {
    isolation()
}

fn isolation() -> [(&'static str, String); 7] {
    [
        ("DynamicUser", "yes".to_owned()),
        ("User", CONTROLLER_ACCOUNT.to_owned()),
        ("TasksMax", CONTROLLER_BUDGETS.tasks_max.to_string()),
        (
            "MemoryMax",
            (u64::from(CONTROLLER_BUDGETS.memory_max_mib) * 1024 * 1024).to_string(),
        ),
        ("NoNewPrivileges", "yes".to_owned()),
        ("ProtectSystem", "strict".to_owned()),
        // Vide, et c'est la valeur attendue : l'unité ne conserve aucune
        // capacité. Une chaîne vide est une réponse, pas une absence.
        ("CapabilityBoundingSet", String::new()),
    ]
}

/// Pourquoi l'unité n'a pas été constatée en état d'être approuvée.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitRefusal {
    /// La sortie dépasse ce que neuf propriétés peuvent faire.
    ReadingTooLarge,
    /// La sortie n'est pas une suite de lignes `Propriété=valeur`.
    ReadingUnreadable,
    /// Une propriété demandée manque à la réponse. On ne sait donc pas ce
    /// qu'elle vaut, et ne pas savoir n'est pas une conformité.
    PropertyMissing { property: &'static str },
    /// L'unité ne tourne pas. Les deux mots sont conservés : `failed` et
    /// `inactive` ne demandent pas le même geste.
    NotRunning {
        active_state: String,
        sub_state: String,
    },
    /// L'unité tourne, mais son confinement n'est pas celui que le plan borne.
    /// Un service dont l'isolation a glissé est un service que personne n'a
    /// approuvé.
    IsolationDiverged {
        property: &'static str,
        observed: String,
    },
}

/// La preuve que l'unité approuvée tourne, confinée comme le plan la borne.
///
/// Comme les autres témoins de ce crate, elle ne peut pas être construite en
/// nommant ses champs, et [`running`] est la seule fonction qui en rend une.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningController {
    account: String,
}

impl RunningController {
    /// Le compte que systemd a réellement alloué à l'unité.
    pub fn account(&self) -> &str {
        &self.account
    }

    /// L'unité constatée. Il n'y en a qu'une, et c'est celle du plan.
    pub fn unit(&self) -> &'static str {
        CONTROLLER_UNIT
    }
}

/// Constate l'unité : elle tourne **et** elle est confinée.
///
/// L'ordre des deux questions n'est pas indifférent. L'état vient d'abord
/// parce qu'un service mort rend des valeurs d'isolation qui ne décrivent
/// rien ; le confinement ensuite, propriété par propriété, chacune nommée dans
/// son refus.
pub fn running(exit_status: u32, stdout: &[u8]) -> Result<RunningController, UnitRefusal> {
    if stdout.len() > MAX_READING_BYTES {
        return Err(UnitRefusal::ReadingTooLarge);
    }
    if exit_status != 0 {
        return Err(UnitRefusal::ReadingUnreadable);
    }
    let properties = read_properties(stdout)?;

    let active_state = property(&properties, "ActiveState")?;
    let sub_state = property(&properties, "SubState")?;
    if active_state != "active" || sub_state != "running" {
        return Err(UnitRefusal::NotRunning {
            active_state: active_state.to_owned(),
            sub_state: sub_state.to_owned(),
        });
    }

    for (name, expected) in expected_isolation() {
        let observed = property(&properties, name)?;
        if observed != expected {
            return Err(UnitRefusal::IsolationDiverged {
                property: name,
                observed: observed.to_owned(),
            });
        }
    }

    Ok(RunningController {
        account: property(&properties, "User")?.to_owned(),
    })
}

/// Lit les lignes `Propriété=valeur` que `systemctl show` rend, sans supposer
/// leur ordre : systemd choisit le sien, et un constat qui dépendrait de cet
/// ordre dépendrait d'une version de systemd.
fn read_properties(stdout: &[u8]) -> Result<Vec<(&str, &str)>, UnitRefusal> {
    let text = std::str::from_utf8(stdout).map_err(|_| UnitRefusal::ReadingUnreadable)?;
    let mut properties = Vec::new();
    for line in text.lines() {
        let (name, value) = line.split_once('=').ok_or(UnitRefusal::ReadingUnreadable)?;
        if name.is_empty() {
            return Err(UnitRefusal::ReadingUnreadable);
        }
        properties.push((name, value));
    }
    if properties.is_empty() {
        return Err(UnitRefusal::ReadingUnreadable);
    }
    Ok(properties)
}

fn property<'a>(
    properties: &[(&'a str, &'a str)],
    name: &'static str,
) -> Result<&'a str, UnitRefusal> {
    properties
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, value)| *value)
        .ok_or(UnitRefusal::PropertyMissing { property: name })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La réponse d'une unité qui tourne et qui est confinée exactement comme
    /// le plan la borne. Les valeurs sont celles que la preuve `#38` a relevées
    /// sur la machine, y compris `MemoryMax` en octets.
    fn nominal() -> Vec<u8> {
        let mut lines = vec![
            "ActiveState=active".to_owned(),
            "SubState=running".to_owned(),
        ];
        for (name, value) in expected_isolation() {
            lines.push(format!("{name}={value}"));
        }
        format!("{}\n", lines.join("\n")).into_bytes()
    }

    fn without(property: &str) -> Vec<u8> {
        let nominal = String::from_utf8(nominal()).unwrap();
        let kept: Vec<&str> = nominal
            .lines()
            .filter(|line| !line.starts_with(&format!("{property}=")))
            .collect();
        format!("{}\n", kept.join("\n")).into_bytes()
    }

    fn with(property: &str, value: &str) -> Vec<u8> {
        let nominal = String::from_utf8(nominal()).unwrap();
        let changed: Vec<String> = nominal
            .lines()
            .map(|line| {
                if line.starts_with(&format!("{property}=")) {
                    format!("{property}={value}")
                } else {
                    line.to_owned()
                }
            })
            .collect();
        format!("{}\n", changed.join("\n")).into_bytes()
    }

    /// Le contrôle positif. Tout ce qui suit est celui-ci, moins une chose.
    #[test]
    fn a_running_and_confined_controller_is_constated() {
        let controller = running(0, &nominal()).expect("le contrôle positif doit être constaté");

        assert_eq!(controller.account(), CONTROLLER_ACCOUNT);
        assert_eq!(controller.unit(), CONTROLLER_UNIT);
    }

    /// Un service qui ne tourne pas est refusé, et les deux mots de son état
    /// sont conservés : `failed` et `inactive` ne demandent pas le même geste.
    #[test]
    fn a_controller_that_does_not_run_is_refused_with_both_words_of_its_state() {
        for (active_state, sub_state) in [
            ("inactive", "dead"),
            ("failed", "failed"),
            ("activating", "start"),
        ] {
            let reading = with("SubState", sub_state);
            let reading = String::from_utf8(reading)
                .unwrap()
                .replace("ActiveState=active", &format!("ActiveState={active_state}"));

            assert_eq!(
                running(0, reading.as_bytes()),
                Err(UnitRefusal::NotRunning {
                    active_state: active_state.to_owned(),
                    sub_state: sub_state.to_owned(),
                })
            );
        }
    }

    /// La propriété que ce module existe pour tenir : un service **actif**
    /// dont le confinement a glissé est refusé, propriété par propriété et
    /// chacune nommée. Un constat qui n'aurait regardé que `ActiveState`
    /// aurait accepté chacun de ces cas.
    #[test]
    fn an_active_controller_whose_confinement_slipped_is_refused_by_the_property_that_slipped() {
        let cases: [(&str, &str); 6] = [
            ("DynamicUser", "no"),
            ("User", "root"),
            ("TasksMax", "infinity"),
            ("MemoryMax", "infinity"),
            ("NoNewPrivileges", "no"),
            ("ProtectSystem", "no"),
        ];

        for (property, observed) in cases {
            assert_eq!(
                running(0, &with(property, observed)),
                Err(UnitRefusal::IsolationDiverged {
                    property,
                    observed: observed.to_owned()
                }),
                "la propriété était : {property}"
            );
        }

        // Une capacité conservée : la valeur attendue est vide, donc toute
        // valeur est une divergence.
        assert_eq!(
            running(0, &with("CapabilityBoundingSet", "cap_net_bind_service")),
            Err(UnitRefusal::IsolationDiverged {
                property: "CapabilityBoundingSet",
                observed: "cap_net_bind_service".to_owned()
            })
        );
    }

    /// Une propriété absente n'est pas une conformité : ne pas savoir ce
    /// qu'elle vaut est refusé par son propre nom.
    #[test]
    fn a_missing_property_is_refused_rather_than_assumed_conforming() {
        for property in ["ActiveState", "DynamicUser", "MemoryMax", "ProtectSystem"] {
            let refusal = running(0, &without(property)).expect_err("une absence doit refuser");
            assert!(
                matches!(refusal, UnitRefusal::PropertyMissing { property: missing } if missing == property),
                "la propriété retirée était {property}, le refus était {refusal:?}"
            );
        }
    }

    /// L'ordre des lignes appartient à systemd, pas à ce module : la même
    /// réponse dans un autre ordre rend le même verdict.
    #[test]
    fn the_order_of_the_lines_belongs_to_systemd_and_changes_nothing() {
        let nominal = String::from_utf8(nominal()).unwrap();
        let mut reversed: Vec<&str> = nominal.lines().collect();
        reversed.reverse();

        let controller = running(0, format!("{}\n", reversed.join("\n")).as_bytes())
            .expect("l'ordre ne fait pas le verdict");
        assert_eq!(controller.account(), CONTROLLER_ACCOUNT);
    }

    /// Ce qui n'est pas une réponse est refusé avant d'être interprété.
    #[test]
    fn a_reading_that_is_not_a_property_list_is_refused() {
        assert_eq!(running(1, &nominal()), Err(UnitRefusal::ReadingUnreadable));
        assert_eq!(running(0, b""), Err(UnitRefusal::ReadingUnreadable));
        assert_eq!(
            running(0, b"pas de signe egal\n"),
            Err(UnitRefusal::ReadingUnreadable)
        );
        assert_eq!(
            running(0, b"=sans nom\n"),
            Err(UnitRefusal::ReadingUnreadable)
        );
        assert_eq!(
            running(0, &vec![b'a'; MAX_READING_BYTES + 1]),
            Err(UnitRefusal::ReadingTooLarge)
        );
    }

    /// La commande demande nommément ses propriétés, porte sa locale et
    /// n'interroge que l'unité du plan.
    #[test]
    fn the_command_names_its_properties_its_locale_and_one_unit() {
        let command = SHOW_CONTROLLER.as_str();
        assert!(command.starts_with("/usr/bin/env LC_ALL=C "));
        assert!(command.ends_with(CONTROLLER_UNIT));
        // Les séparateurs exacts, et pas seulement la présence des mots : ces
        // octets sont écrits sur plusieurs lignes de source, et une
        // continuation Rust mange le saut de ligne **et** l'indentation qui
        // suit. Une espace oubliée avant la barre obliquerait collé
        // `--no-pager` à `-p`, et la commande serait refusée par la machine
        // plutôt que par une suite.
        assert!(command.contains(" --no-pager -p "));
        assert!(command.contains(" -- your-cloud-controller.service"));
        assert!(!command.contains("  "));
        // Chaque propriété jugée est réellement demandée : un constat qui
        // jugerait une propriété qu'il n'a pas demandée la trouverait toujours
        // absente.
        for (name, _) in expected_isolation() {
            assert!(command.contains(name), "propriété non demandée : {name}");
        }
        for name in ["ActiveState", "SubState"] {
            assert!(command.contains(name), "propriété non demandée : {name}");
        }
    }
}

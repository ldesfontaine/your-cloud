//! La configuration propre à la machine, produite ici et jugée comme le lot.
//!
//! C'est le seul contenu de ce palier dont les octets ne sont pas une
//! constante : ils dépendent de la machine que l'humain a approuvée. Le risque
//! est donc nommé plutôt que contourné — **des octets choisis ailleurs
//! entreraient dans un acte privilégié**, ce qui n'arrive nulle part ailleurs
//! dans cette installation.
//!
//! La réponse ne lui invente aucune forme : elle réutilise, telle quelle, la
//! chaîne que le lot a déjà prouvée.
//!
//! 1. **Le contenu est produit localement**, depuis le placement approuvé et
//!    les endpoints déclarés. Rien n'est composé sur la cible.
//! 2. **Son empreinte est calculée ici et nommée dans le plan** que l'humain
//!    approuve. C'est ce qui transforme « des octets choisis ailleurs » en
//!    « des octets dont l'humain a vu l'empreinte avant de consentir » — la
//!    même bascule que l'ancre scellée opère pour le lot.
//! 3. **Le dépôt est celui du lot** : `dd` sans privilège, dans le même
//!    répertoire propre à l'opération, jugé statut → taille → empreinte, et le
//!    fichier déposé est un résidu que le registre nomme et retire.
//! 4. **Un acte fixe l'installe en place.** Le privilège ne voit donc toujours
//!    que des octets fixes : `install` copie d'un chemin constant vers un
//!    chemin constant, et ce qui varie a déjà été relu et confronté à
//!    l'empreinte que le plan portait.
//!
//! Ce que la configuration contient a été **mesuré** avant d'être figé :
//! l'unité du Controller ne consomme d'elle que trois variables, toutes des
//! adresses non secrètes. Elle se réduit donc à un fichier déposé, et rien
//! n'exige de la composer sur la machine.

use super::plan::MACHINE_CONFIGURATION;
use crate::personal_access::elevation::FixedCommand;
use sha2::{Digest, Sha256};

/// Le nom du fichier déposé, dans le répertoire d'attente du transfert.
pub const STAGED_CONFIGURATION_SUFFIX: &str = "/.your-cloud-bootstrap/controller.env";

/// Les trois variables que l'unité du Controller lit, et les seules.
///
/// Elles sont relevées de `packaging/server-bundle/units/your-cloud-controller.service` :
/// `ExecStart` ne développe qu'elles, et `EnvironmentFile` ne sert qu'à les
/// fournir. Une quatrième ligne serait donc du contenu que rien ne lit — et ce
/// module refuse d'en écrire, parce qu'un fichier qui dit plus que ce qui est
/// lu est un fichier dont personne ne relit la part inutile.
pub const CONFIGURATION_KEYS: [&str; 3] = [
    "CONTROLLER_LISTEN",
    "CONTROLLER_ALLOWED_SOURCE",
    "CONTROLLER_RELAY_ENDPOINT",
];

/// Dépose la configuration produite, sans privilège, par le même `dd` que le
/// lot et dans le même répertoire propre à l'opération.
pub const DEPOSIT_CONFIGURATION: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/dd of=$HOME/.your-cloud-bootstrap/controller.env \
     bs=4096 conv=fsync status=none",
);

/// Relit la taille du fichier déposé, avant son empreinte — le même ordre, pour
/// la même raison : `dd` tronque sans crier.
pub const MEASURE_CONFIGURATION_SIZE: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/stat -c %s -- $HOME/.your-cloud-bootstrap/controller.env",
);

/// Relit l'empreinte du fichier déposé, sur la cible.
pub const MEASURE_CONFIGURATION: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/sha256sum -- $HOME/.your-cloud-bootstrap/controller.env",
);

/// L'acte privilégié qui met le fichier en place, **d'un chemin constant vers
/// un chemin constant**.
///
/// C'est ce qui garde le privilège aveugle au contenu : `install` ne compose
/// rien, ne lit aucun champ et ne connaît aucune adresse. Les octets qu'il
/// déplace ont été relus et confrontés à l'empreinte que le plan nommait, avant
/// que le moindre privilège soit dépensé sur eux. Le mode et le propriétaire
/// sont posés par l'appel qui installe, jamais par un `chmod` qui suivrait.
pub const INSTALL_CONFIGURATION: ActPair = ActPair {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/install -o root -g root -m 0600 \
         -- $HOME/.your-cloud-bootstrap/controller.env /etc/your-cloud/controller.env",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/install -o root -g root -m 0600 -- \
         $HOME/.your-cloud-bootstrap/controller.env /etc/your-cloud/controller.env",
    ),
};

/// Les deux orthographes d'un acte, comme [`super::acts::ActCommands`] les
/// déclare. Elle est répétée ici plutôt qu'importée pour que ce module reste
/// lisible seul ; les suites tiennent l'égalité de forme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActPair {
    pub without_password: FixedCommand,
    pub with_password: FixedCommand,
}

/// La configuration produite localement, avec l'empreinte que le plan nommera.
///
/// Elle ne peut pas être construite en nommant ses champs : [`compose`] est la
/// seule fonction qui en rend une, et elle n'accepte que des valeurs qu'un
/// placement approuvé et des endpoints déclarés ont produites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineConfiguration {
    bytes: Vec<u8>,
    sha256: String,
}

impl MachineConfiguration {
    /// Les octets exacts qui seront déposés, et dont l'empreinte est celle-ci.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// L'empreinte que le plan nomme et que la cible devra rendre.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// Pourquoi une configuration n'a pas été composée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationRefusal {
    /// Une valeur est vide : une adresse absente donnerait une unité qui
    /// démarre sur une variable vide plutôt qu'une installation qui refuse.
    EmptyValue { key: &'static str },
    /// Une valeur porte un caractère qu'un fichier d'environnement ne peut pas
    /// transporter sans changer de sens.
    UnrepresentableValue { key: &'static str },
}

/// Compose la configuration, et refuse tout ce qui ne s'écrit pas tel quel.
///
/// Les trois valeurs viennent du placement approuvé et des endpoints déclarés.
/// Elles sont refusées vides, et refusées si elles portent un saut de ligne, un
/// caractère de contrôle ou un `=` — un fichier d'environnement n'a aucun
/// échappement, donc une valeur qui en contiendrait ne serait pas transportée,
/// elle serait **réinterprétée**. Refuser vaut mieux qu'échapper : il n'y a
/// alors aucune règle d'échappement dont la cible et nous pourrions différer.
pub fn compose(
    listen: &str,
    allowed_source: &str,
    relay_endpoint: &str,
) -> Result<MachineConfiguration, ConfigurationRefusal> {
    let values = [listen, allowed_source, relay_endpoint];
    for (key, value) in CONFIGURATION_KEYS.iter().zip(values) {
        if value.is_empty() {
            return Err(ConfigurationRefusal::EmptyValue { key });
        }
        if value
            .chars()
            .any(|character| character.is_control() || character == '=')
        {
            return Err(ConfigurationRefusal::UnrepresentableValue { key });
        }
    }

    let mut bytes = Vec::new();
    for (key, value) in CONFIGURATION_KEYS.iter().zip(values) {
        bytes.extend_from_slice(format!("{key}={value}\n").as_bytes());
    }
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    Ok(MachineConfiguration { bytes, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nominal() -> MachineConfiguration {
        compose(
            "192.168.240.115:9443",
            "192.168.240.0/24",
            "192.168.240.9:9444",
        )
        .expect("le contrôle positif doit se composer")
    }

    /// Le contrôle positif : trois lignes, dans l'ordre des clés que l'unité
    /// lit, et une empreinte qui est celle de ces octets exacts.
    #[test]
    fn the_configuration_is_the_three_lines_the_unit_reads() {
        let composed = nominal();

        assert_eq!(
            std::str::from_utf8(composed.bytes()).unwrap(),
            "CONTROLLER_LISTEN=192.168.240.115:9443\n\
             CONTROLLER_ALLOWED_SOURCE=192.168.240.0/24\n\
             CONTROLLER_RELAY_ENDPOINT=192.168.240.9:9444\n"
        );
        assert_eq!(composed.size(), composed.bytes().len() as u64);
        assert_eq!(composed.sha256().len(), 64);
    }

    /// Ce qui ne s'écrit pas tel quel est refusé plutôt qu'échappé.
    ///
    /// Un fichier d'environnement n'a aucun échappement : une valeur portant un
    /// saut de ligne ne serait pas transportée, elle serait réinterprétée — la
    /// ligne suivante deviendrait une variable que personne n'a approuvée.
    /// Refuser ne laisse aucune règle d'échappement sur laquelle la cible et
    /// nous pourrions différer.
    #[test]
    fn a_value_that_would_be_reinterpreted_is_refused_rather_than_escaped() {
        for hostile in [
            "192.168.1.1\nCONTROLLER_ALLOWED_SOURCE=0.0.0.0/0",
            "192.168.1.1\r",
            "192.168.1.1\0",
            "a=b",
        ] {
            assert_eq!(
                compose(hostile, "192.168.240.0/24", "192.168.240.9:9444"),
                Err(ConfigurationRefusal::UnrepresentableValue {
                    key: "CONTROLLER_LISTEN"
                }),
                "la valeur était : {hostile:?}"
            );
        }
    }

    /// Une valeur vide est refusée : elle donnerait une unité qui démarre sur
    /// une variable vide plutôt qu'une installation qui refuse.
    #[test]
    fn an_empty_value_is_refused_by_the_key_that_is_missing() {
        assert_eq!(
            compose("", "192.168.240.0/24", "192.168.240.9:9444"),
            Err(ConfigurationRefusal::EmptyValue {
                key: "CONTROLLER_LISTEN"
            })
        );
        assert_eq!(
            compose("192.168.240.115:9443", "", "192.168.240.9:9444"),
            Err(ConfigurationRefusal::EmptyValue {
                key: "CONTROLLER_ALLOWED_SOURCE"
            })
        );
        assert_eq!(
            compose("192.168.240.115:9443", "192.168.240.0/24", ""),
            Err(ConfigurationRefusal::EmptyValue {
                key: "CONTROLLER_RELAY_ENDPOINT"
            })
        );
    }

    /// L'empreinte est celle des octets déposés, et rien d'autre : deux
    /// configurations qui diffèrent d'un caractère ont deux empreintes.
    ///
    /// C'est ce qui donne son sens à « nommée dans le plan » — une empreinte
    /// qui ne bougerait pas avec le contenu ne dirait rien de ce que l'humain
    /// approuve.
    #[test]
    fn the_digest_names_these_bytes_and_no_others() {
        let composed = nominal();
        let other = compose(
            "192.168.240.116:9443",
            "192.168.240.0/24",
            "192.168.240.9:9444",
        )
        .expect("une seconde configuration valable");

        assert_ne!(composed.sha256(), other.sha256());
        assert_ne!(composed.bytes(), other.bytes());
    }

    /// Le privilège ne voit que des octets fixes : l'acte d'installation ne
    /// porte aucune adresse, aucun champ, rien qui vienne du contenu.
    #[test]
    fn the_privileged_act_carries_no_byte_of_the_content() {
        for command in [
            INSTALL_CONFIGURATION.without_password,
            INSTALL_CONFIGURATION.with_password,
        ] {
            let bytes = command.as_str();
            assert!(bytes.contains("/usr/bin/install -o root -g root -m 0600"));
            assert!(bytes.ends_with(MACHINE_CONFIGURATION));
            assert!(bytes.starts_with("/usr/bin/sudo -k "));
            // Aucune des clés, donc aucune valeur, n'entre dans l'acte.
            for key in CONFIGURATION_KEYS {
                assert!(!bytes.contains(key));
            }
            assert!(!bytes.contains("chmod"));
            for forbidden in ["$(", "`", "&&", "||", ";", "|", ">", "~"] {
                assert!(!bytes.contains(forbidden), "acte composé : {bytes}");
            }
        }
    }

    /// Le dépôt emprunte la chaîne du lot, sans en inventer une seconde.
    #[test]
    fn the_deposit_reuses_the_chain_the_bundle_already_proved() {
        for command in [
            DEPOSIT_CONFIGURATION,
            MEASURE_CONFIGURATION_SIZE,
            MEASURE_CONFIGURATION,
        ] {
            let bytes = command.as_str();
            assert!(bytes.starts_with("/usr/bin/env LC_ALL=C "));
            // Le même répertoire propre à l'opération que le lot, donc la même
            // fermeture de course, sans second raisonnement à tenir.
            assert!(bytes.contains("$HOME/.your-cloud-bootstrap/controller.env"));
            assert!(!bytes.contains('~'));
            assert!(
                !bytes.contains("sudo"),
                "le dépôt ne dépense aucun privilège"
            );
        }
        assert!(DEPOSIT_CONFIGURATION.as_str().contains("conv=fsync"));
    }
}

//! Les octets de ce qui **agit**, et le témoin sans lequel aucun ne part.
//!
//! Les cinq modules voisins jugent : ils reçoivent ce que la machine a répondu
//! et rendent un verdict. Celui-ci est leur symétrique — il ne juge rien, il
//! déclare **exactement** ce que l'Assistant est autorisé à exécuter, sous
//! forme d'octets fixes, et refuse par construction qu'un acte privilégié
//! existe hors de cette liste.
//!
//! **Un acte privilégié ne se compose pas.** Chaque commande est une constante
//! de [`FixedCommand`], dont le constructeur est interne au crate : rien
//! d'assemblé depuis un document, un champ du protocole ou une réponse de
//! machine ne peut devenir une commande. C'est la discipline de
//! `personal_access::elevation`, étendue à l'installation, et c'est ce qui rend
//! la question « que peut lancer cet Assistant en root » lisible en une page.
//!
//! **Aucun ne part sans le plan.** [`ElevatedAct`] ne se construit qu'en
//! présentant un [`InstallPlan`], que seul `plan::authorize` rend contre les
//! quatre témoins. La question « un `dpkg` peut-il partir sans que le lot ait
//! été jugé, le placement approuvé, root réellement atteint et chaque endpoint
//! entendu » se répond donc en lisant une signature, pas en auditant des sites
//! d'appel.
//!
//! **Chaque acte connaît l'étape qu'il sert**, et l'ordonnanceur ne peut lui en
//! faire servir une autre : l'appariement est déclaré ici, une fois.

use super::plan::{InstallPlan, Step};
use crate::personal_access::elevation::FixedCommand;

/// Les deux orthographes d'un même acte, choisies par la politique attestée.
///
/// Ce n'est pas un réglage : ce sont deux commandes constantes, comme
/// `ELEVATE_WITH_PASSWORD` et `ELEVATE_WITHOUT_PASSWORD` le sont déjà pour
/// l'élévation. Une politique sans mot de passe emprunte la forme `-n`, qui
/// interdit tout prompt et **ne retient aucun secret** ; une politique qui en
/// demande un emprunte la forme `-S`, qui lit le secret sur le canal.
///
/// **`-k` est sur chaque acte, et c'est la condition qui compte.** Il jette
/// l'horodatage avant de courir, donc chaque acte s'authentifie réellement au
/// lieu de profiter du précédent. Sans lui, l'installation dépendrait de
/// `timestamp_timeout` — un réglage invisible dont l'expiration au milieu de la
/// séquence redemanderait un mot de passe que personne n'attend, c'est-à-dire
/// exactement le mur que ce palier élimine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActCommands {
    /// La forme empruntée quand la politique attestée n'exige aucun secret.
    pub without_password: FixedCommand,
    /// La forme empruntée quand elle en exige un. Le secret est présenté à
    /// chaque acte, jamais supposé encore valide.
    pub with_password: FixedCommand,
}

/// `dpkg` installe le lot que la cible détient déjà, à l'emplacement que le
/// transfert a posé et dont l'empreinte a été relue là-bas.
///
/// `--install` et rien d'autre : ni `--force-*`, qui passerait outre les refus
/// de `dpkg` lui-même, ni `--unpack`, qui laisserait précisément l'état à demi
/// configuré que le constat du paquet existe pour nommer.
pub const INSTALL_PACKAGE: ActCommands = ActCommands {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/dpkg --install -- \
         $HOME/.your-cloud-bootstrap/your-cloud-server.deb",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/dpkg --install -- $HOME/.your-cloud-bootstrap/your-cloud-server.deb",
    ),
};

/// Relit les unités que le paquet vient de poser.
///
/// C'est un acte et non un constat : il ne dit rien de l'état, il demande à
/// systemd de relire ce que `dpkg` a écrit. Sans lui, l'activation porterait sur
/// la version en mémoire de systemd plutôt que sur les fichiers installés.
pub const RELOAD_UNITS: ActCommands = ActCommands {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/systemctl daemon-reload",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/systemctl daemon-reload",
    ),
};

/// Active la seule unité que le plan nomme, et la démarre.
///
/// `--now` fait les deux d'un geste parce que les séparer laisserait une fenêtre
/// où l'unité est activée sans tourner — un état que rien n'approuverait et que
/// le registre devrait pourtant porter.
pub const ACTIVATE_CONTROLLER: ActCommands = ActCommands {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/systemctl enable --now -- \
         your-cloud-controller.service",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/systemctl enable --now -- your-cloud-controller.service",
    ),
};

/// Crée l'état privé du Controller, droits posés dans l'appel qui crée.
///
/// `install -d` fixe le mode à la création même, là où un `mkdir` suivi d'un
/// `chmod` laisserait un intervalle pendant lequel le répertoire existerait plus
/// ouvert qu'il ne doit l'être.
pub const CREATE_STATE: ActCommands = ActCommands {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/install -d -o root -g root \
         -m 0700 -- /var/lib/private/your-cloud-controller",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/install -d -o root -g root -m 0700 -- /var/lib/private/your-cloud-controller",
    ),
};

/// Crée le répertoire des sources de credentials, mêmes droits, même raison.
pub const CREATE_CREDENTIAL_SOURCES: ActCommands = ActCommands {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/install -d -o root -g root \
         -m 0700 -- /etc/your-cloud/controller-credentials",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/install -d -o root -g root -m 0700 -- /etc/your-cloud/controller-credentials",
    ),
};

/// Le dernier geste de toute séquence : jeter ce que `sudo` garde de nous.
///
/// Il court quelle que soit l'issue — succès, échec, annulation — parce que ce
/// qu'il retire n'appartient pas à la réussite : c'est l'horodatage qui
/// permettrait à un acte ultérieur de s'élever sans présenter de secret. Il ne
/// demande rien et ne peut donc pas échouer faute d'authentification.
pub const DROP_CREDENTIAL: FixedCommand = FixedCommand::fixed("/usr/bin/sudo -k");

/// Chaque acte privilégié de ce palier, et l'étape qu'il sert.
///
/// La table est close et constante : un acte qui n'y figure pas n'a aucun moyen
/// d'atteindre un canal, et un acte ne peut pas être présenté pour une étape qui
/// n'est pas la sienne. Elle se lit comme la réponse complète à « que lance cet
/// Assistant en root ».
///
/// `WriteMachineConfiguration` n'y est pas, et c'est une absence délibérée :
/// écrire un fichier dont le contenu dépend de la machine n'est pas une commande
/// fixe, et le faire passer pour telle serait le seul endroit du palier où des
/// octets choisis ailleurs entreraient dans un acte privilégié. Cette étape aura
/// sa propre forme — un dépôt de contenu borné, jugé comme le lot l'a été — et
/// la déclarer ici l'aurait dissimulée.
pub const ACTS: [(Step, ActCommands); 5] = [
    (Step::InstallPackage, INSTALL_PACKAGE),
    (Step::InstallPackage, RELOAD_UNITS),
    (Step::CreateState, CREATE_STATE),
    (Step::InstallCredentialSources, CREATE_CREDENTIAL_SOURCES),
    (Step::ActivateController, ACTIVATE_CONTROLLER),
];

/// Un acte privilégié qu'un plan autorise, et la seule forme sous laquelle un
/// exécutant en reçoit un.
///
/// Il ne porte aucune donnée du plan : il n'est pas un moyen de lire le plan,
/// il est la preuve qu'un plan existait au moment où cet acte a été choisi. Le
/// témoin est passé par référence et n'est jamais lu, exactement comme
/// `plan::authorize` traite l'élévation — c'est une obligation de preuve, pas
/// une entrée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElevatedAct {
    step: Step,
    commands: ActCommands,
}

impl ElevatedAct {
    /// Les actes que cette étape autorise, dans leur ordre, contre un plan.
    ///
    /// Rien d'autre dans ce crate ne construit un [`ElevatedAct`]. Une étape
    /// sans acte — le transfert, qui ne dépense aucun privilège, ou la
    /// configuration machine dont la forme est autre — rend une liste vide, ce
    /// qui est une réponse et non une absence de réponse.
    pub fn authorised_for(_plan: &InstallPlan, step: Step) -> Vec<Self> {
        ACTS.iter()
            .filter(|(candidate, _)| *candidate == step)
            .map(|(step, commands)| Self {
                step: *step,
                commands: *commands,
            })
            .collect()
    }

    pub fn step(&self) -> Step {
        self.step
    }

    /// Les octets exacts à exécuter, dans la forme que la politique attestée
    /// impose. Ils sortent d'une constante de ce module et de nulle part
    /// ailleurs.
    ///
    /// `password_required` vient de l'attestation de politique et de rien
    /// d'autre : c'est elle qui a lu le listing, et un appelant qui choisirait
    /// la forme `-n` sur une politique qui exige un secret verrait `sudo`
    /// refuser plutôt que de s'élever sans l'avoir présenté.
    pub fn command(&self, password_required: bool) -> FixedCommand {
        if password_required {
            self.commands.with_password
        } else {
            self.commands.without_password
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spellings() -> Vec<(Step, FixedCommand)> {
        ACTS.iter()
            .flat_map(|(step, commands)| {
                [
                    (*step, commands.without_password),
                    (*step, commands.with_password),
                ]
            })
            .collect()
    }

    /// Chaque orthographe porte sa locale et ne compose rien : ce sont des
    /// octets figés, relus ici pour qu'un changement se voie.
    #[test]
    fn every_act_is_fixed_bytes_carrying_its_own_locale() {
        for (_, command) in spellings() {
            let bytes = command.as_str();
            assert!(
                bytes.contains("/usr/bin/env LC_ALL=C "),
                "acte sans locale : {bytes}"
            );
            assert!(!bytes.contains("  "), "acte à double espace : {bytes}");
            for forbidden in ["$(", "`", "&&", "||", ";", "|"] {
                assert!(
                    !bytes.contains(forbidden),
                    "acte composé ({forbidden}) : {bytes}"
                );
            }
        }
    }

    /// La condition qui tient la borne du secret : **chaque** acte jette
    /// l'horodatage avant de courir.
    ///
    /// Sans `-k`, un acte pourrait s'élever en profitant de l'authentification
    /// du précédent, et l'installation dépendrait alors de `timestamp_timeout`
    /// — un réglage invisible dont l'expiration au milieu de la séquence
    /// redemanderait un mot de passe que personne n'attend. La séquence
    /// présente donc son secret à chaque acte, ou n'en présente aucun.
    #[test]
    fn every_act_drops_the_timestamp_and_never_relies_on_the_previous_one() {
        for (_, command) in spellings() {
            let bytes = command.as_str();
            assert!(
                bytes.starts_with("/usr/bin/sudo -k "),
                "acte qui ne jette pas l'horodatage : {bytes}"
            );
        }
        for (_, commands) in ACTS {
            // La forme sans secret interdit tout prompt ; la forme avec secret
            // le lit sur le canal, sous le prompt sentinelle qui rend tout
            // autre prompt reconnaissable.
            assert!(commands.without_password.as_str().contains(" -k -n -- "));
            assert!(commands
                .with_password
                .as_str()
                .contains(" -k -S -p your-cloud-sudo-prompt: -- "));
        }
    }

    /// Le dernier geste ne demande rien et ne dépend d'aucune issue.
    #[test]
    fn the_closing_act_drops_what_sudo_kept_of_us() {
        assert_eq!(DROP_CREDENTIAL.as_str(), "/usr/bin/sudo -k");
        assert!(!DROP_CREDENTIAL.as_str().contains("-S"));
    }

    /// `dpkg` n'est jamais forcé, et n'est jamais un simple dépaquetage.
    ///
    /// `--force-*` passerait outre les refus de `dpkg` lui-même ; `--unpack`
    /// laisserait l'état à demi configuré que le constat du paquet existe pour
    /// nommer. La porte refuserait ensuite cet état — mais l'acte ne doit pas
    /// pouvoir le produire délibérément.
    #[test]
    fn the_package_is_installed_never_forced_and_never_merely_unpacked() {
        for bytes in [
            INSTALL_PACKAGE.without_password.as_str(),
            INSTALL_PACKAGE.with_password.as_str(),
        ] {
            assert!(bytes.contains("--install"));
            assert!(!bytes.contains("--force"));
            assert!(!bytes.contains("--unpack"));
            assert!(!bytes.contains("--auto-deconfigure"));
        }
    }

    /// Les deux répertoires posent leurs droits dans l'appel qui les crée.
    #[test]
    fn the_directories_carry_their_mode_in_the_call_that_creates_them() {
        for commands in [CREATE_STATE, CREATE_CREDENTIAL_SOURCES] {
            for bytes in [
                commands.without_password.as_str(),
                commands.with_password.as_str(),
            ] {
                assert!(bytes.contains("install -d"));
                assert!(bytes.contains("-m 0700"));
                assert!(bytes.contains("-o root -g root"));
                assert!(!bytes.contains("chmod"));
            }
        }
    }

    /// L'unité activée est celle du plan, démarrée du même geste, et les deux
    /// autres que le paquet livre ne sont nommées par aucun acte.
    #[test]
    fn exactly_one_unit_is_activated_and_started_together() {
        for bytes in [
            ACTIVATE_CONTROLLER.without_password.as_str(),
            ACTIVATE_CONTROLLER.with_password.as_str(),
        ] {
            assert!(bytes.ends_with(super::super::plan::CONTROLLER_UNIT));
            assert!(bytes.contains("enable --now"));
        }
        for (_, command) in spellings() {
            for untouched in ["your-cloud-daemon.service", "your-cloud-relay.service"] {
                assert!(
                    !command.as_str().contains(untouched),
                    "un acte nomme une unité que ce palier n'active pas : {untouched}"
                );
            }
        }
    }

    /// Les étapes sans acte rendent une liste vide, et c'est une réponse.
    #[test]
    fn the_steps_without_an_act_answer_with_an_empty_list() {
        for step in [
            Step::TransferBundle,
            Step::WriteMachineConfiguration,
            Step::AssociateConsole,
            Step::Preflight,
        ] {
            assert!(
                !ACTS.iter().any(|(candidate, _)| *candidate == step),
                "cette étape ne doit porter aucun acte fixe : {step:?}"
            );
        }
    }

    /// Chaque acte sert une étape que le plan connaît.
    #[test]
    fn every_act_serves_a_step_the_plan_knows() {
        for (step, _) in ACTS {
            assert!(
                super::super::plan::STEPS.contains(&step),
                "acte rattaché à une étape hors du plan : {step:?}"
            );
        }
    }
}

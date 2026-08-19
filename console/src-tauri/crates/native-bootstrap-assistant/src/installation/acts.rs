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
    ///
    /// Les deux champs sont privés, et les constantes qui les portent aussi :
    /// un acte privilégié n'est joignable que par [`ElevatedAct`], donc en
    /// présentant un [`InstallPlan`]. Sans cela, « aucun acte privilégié n'est
    /// joignable sans plan » resterait une intention — il aurait suffi de lire
    /// la constante et de la passer à un canal.
    without_password: FixedCommand,
    /// La forme empruntée quand elle en exige un. Le secret est présenté à
    /// chaque acte, jamais supposé encore valide.
    with_password: FixedCommand,
}

/// `dpkg` installe le lot que la cible détient déjà, à l'emplacement que le
/// transfert a posé et dont l'empreinte a été relue là-bas.
///
/// `--install` et rien d'autre : ni `--force-*`, qui passerait outre les refus
/// de `dpkg` lui-même, ni `--unpack`, qui laisserait précisément l'état à demi
/// configuré que le constat du paquet existe pour nommer.
const INSTALL_PACKAGE: ActCommands = ActCommands {
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
const RELOAD_UNITS: ActCommands = ActCommands {
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
const ACTIVATE_CONTROLLER: ActCommands = ActCommands {
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
const CREATE_STATE: ActCommands = ActCommands {
    without_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -n -- /usr/bin/env LC_ALL=C /usr/bin/install -d -o root -g root \
         -m 0700 -- /var/lib/private/your-cloud-controller",
    ),
    with_password: FixedCommand::fixed(
        "/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/env LC_ALL=C \
         /usr/bin/install -d -o root -g root -m 0700 -- /var/lib/private/your-cloud-controller",
    ),
};

/// Met la configuration machine en place, **d'un chemin constant vers un chemin
/// constant**.
///
/// C'est ce qui garde le privilège aveugle au contenu : `install` ne compose
/// rien, ne lit aucun champ et ne connaît aucune adresse. Les octets qu'il
/// déplace ont voyagé sans privilège, ont été relus sur la cible et confrontés
/// à l'empreinte que le plan nommait, **avant** que le moindre privilège soit
/// dépensé sur eux. Le mode et le propriétaire sont posés par l'appel qui
/// installe, jamais par un `chmod` qui suivrait.
const INSTALL_CONFIGURATION: ActCommands = ActCommands {
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

/// Crée le répertoire des sources de credentials, mêmes droits, même raison.
const CREATE_CREDENTIAL_SOURCES: ActCommands = ActCommands {
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
/// **Amendement.** `WriteMachineConfiguration` en a longtemps été absente, et
/// cette absence disait alors la vérité : sa forme n'était pas décidée, et
/// écrire un fichier dont le contenu dépend de la machine n'est pas une
/// commande fixe. Sa forme existe désormais — [`super::configuration`] compose
/// les octets localement, les fait voyager **sans privilège** et les fait relire
/// sur la cible — et ce qui reste à faire en `root` est un `install` d'un chemin
/// constant vers un chemin constant, qui ne porte aucun octet du contenu. C'est
/// donc un acte fixe comme les quatre autres, et le tenir hors de cette table
/// décrirait moins bien la réalité qu'elle : il serait le seul acte privilégié
/// du palier joignable sans présenter de plan.
const ACTS: [(Step, ActCommands); 6] = [
    (Step::InstallPackage, INSTALL_PACKAGE),
    (Step::InstallPackage, RELOAD_UNITS),
    (Step::WriteMachineConfiguration, INSTALL_CONFIGURATION),
    (Step::CreateState, CREATE_STATE),
    (Step::InstallCredentialSources, CREATE_CREDENTIAL_SOURCES),
    (Step::ActivateController, ACTIVATE_CONTROLLER),
];

/// Combien de canaux une étape ouvre sur la cible.
///
/// Ce n'est pas une estimation : chaque nombre est la somme de ce que les
/// tables de ce palier déclarent — les actes de [`ACTS`] pour cette étape, plus
/// les constats que son verdict exige. Un test tient l'égalité avec `ACTS`,
/// pour qu'un acte ajouté sans son canal fasse rougir au lieu de faire heurter
/// un budget en cours de séquence.
pub const fn channels_for(step: Step) -> usize {
    match step {
        // Créer le répertoire d'attente, déposer les octets, relire la taille,
        // relire l'empreinte. Aucun n'est privilégié.
        Step::TransferBundle => 4,
        // `dpkg --install`, `daemon-reload`, puis le constat du paquet.
        Step::InstallPackage => 3,
        // La même chaîne que le lot, moins le répertoire d'attente que le
        // transfert a déjà créé : déposer les octets, relire la taille, relire
        // l'empreinte — puis l'`install` qui met le fichier en place. Le constat
        // n'en ouvre pas un cinquième : le `stat` des nœuds le mesure avec les
        // deux répertoires, et il est compté à la dernière étape qu'il couvre.
        Step::WriteMachineConfiguration => 4,
        // Un `install -d` chacune. Le constat des nœuds les mesure toutes les
        // trois d'un seul `stat`, compté à la dernière d'entre elles.
        Step::CreateState => 1,
        Step::InstallCredentialSources => 2,
        // `systemctl enable --now`, puis le constat de l'unité.
        Step::ActivateController => 2,
        // L'association ne parle pas à la cible par ce canal, et le prévol est
        // collecté par le Controller lui-même.
        Step::AssociateConsole | Step::Preflight => 0,
    }
}

/// Le budget de canaux d'une **session**, dérivé et jamais choisi.
///
/// La propriété que `#54` a conquise est conservée mot pour mot — le budget est
/// compté avant l'ouverture du premier canal, jamais réapprovisionné, et une
/// demande au-delà est refusée plutôt que négociée. Ce qui change est qu'il
/// cesse d'être la **même constante** pour deux conversations différentes :
/// une installation déclare exactement ce que ses étapes ouvrent.
///
/// Le canal de fermeture est compté une fois : toute séquence qui a dépensé du
/// privilège se termine par [`DROP_CREDENTIAL`], quelle que soit son issue.
///
/// **Amendement du 16 août 2026 — le budget est celui de la session, pas celui
/// du plan seul.** Ce texte disait que « l'élévation seule garde les trois
/// canaux qui sont toute sa conversation, et une installation déclare ce que
/// ses étapes ouvrent », comme s'il s'agissait de deux conversations. C'est
/// inexact, et le câblage l'a mesuré : **la même session porte les deux**. Elle
/// dépense d'abord la sonde d'identité, le listing de politique et l'unique
/// élévation — les trois canaux exacts que [`MAX_EXEC_CHANNELS`] borne — puis
/// les étapes du plan. Un budget qui ne compterait que les secondes serait
/// épuisé avant la première : la garde d'adoption exige `channels_spent == 0`,
/// et une séquence branchée sur la session réelle se voyait donc refuser son
/// budget **à tous les coups**.
///
/// Le terme ajouté n'est pas un nombre choisi : c'est la constante que la
/// session elle-même publie, lue ici plutôt que recopiée — deux définitions de
/// « ce que l'accès personnel dépense » finiraient par diverger. Rien n'est
/// allégé : l'adoption reste unique, antérieure au premier canal, et une
/// demande au-delà reste refusée.
pub fn channel_budget(action: your_cloud_bootstrap_protocol::BootstrapAction) -> usize {
    let opened: usize = super::plan::authorized_steps(action)
        .iter()
        .map(|step| channels_for(*step))
        .sum();
    if opened == 0 {
        // L'audit n'installe rien : sa conversation est exactement celle de
        // l'accès personnel, que la session porte déjà. Zéro dit « rien à
        // substituer », et non « aucun canal » — la nuance est ce qui empêche
        // une session d'audit de se retrouver sans budget du tout.
        0
    } else {
        // Une action qui installe juge un placement, et un placement se juge
        // sur des faits que l'Assistant observe LUI-MÊME dans cette session —
        // jamais depuis un champ qu'une Console affirmerait. Les canaux de
        // cette observation sont donc dans la conversation, et leur nombre
        // vient de la constante que l'audit publie à côté de ses commandes,
        // jamais recopié.
        crate::personal_access::session::MAX_EXEC_CHANNELS
            + crate::personal_access::audit::OBSERVATION_CHANNELS
            + opened
            + 1
    }
}

/// Le constat qu'une étape doit obtenir **après** ses actes, et le juge qui le
/// prononce.
///
/// C'est ce qui sépare « la commande a rendu zéro » de « la machine est dans
/// l'état annoncé ». Un code de sortie dit qu'un programme s'est terminé sans
/// se plaindre ; seul le constat dit ce que la machine est devenue, et c'est
/// lui qui donne sa provenance au registre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Constat {
    /// `dpkg-query` : le paquet est-il installé, à la version du lot ?
    Package,
    /// `systemctl show` : l'unité tourne-t-elle, et confinée ?
    Unit,
    /// `stat` : les nœuds de l'Assistant sont-ils posés comme le contrat veut ?
    Nodes,
}

impl Constat {
    /// La commande qui l'obtient — non privilégiée partout où lire ne demande
    /// rien, élevée là où la cible réserve la lecture à `root`.
    ///
    /// La règle d'hier — « une lecture élevée serait du privilège dépensé pour
    /// rien » — tient pour le paquet et l'unité, et sa PRÉMISSE est tombée
    /// pour les nœuds : `/var/lib/private` est `0700 root` par construction
    /// systemd, et la première pose réelle a été refusée par un juge qui ne
    /// pouvait pas lire ce qu'il jugeait (19 août 2026 ; le double des suites
    /// rendait les lignes écrites sans les permissions du parent — la même
    /// couture que le transport). Le privilège n'est pas dépensé pour rien :
    /// il est la seule voie de cette lecture.
    pub fn command(self, password_required: bool) -> FixedCommand {
        match self {
            Self::Package => super::package::QUERY_PACKAGE,
            Self::Unit => super::unit::SHOW_CONTROLLER,
            Self::Nodes if password_required => super::nodes::STAT_OWNED_WITH_PASSWORD,
            Self::Nodes => super::nodes::STAT_OWNED,
        }
    }

    /// Ce constat dépense-t-il l'élévation — et donc présente-t-il le secret
    /// quand la politique en exige un, exactement comme un acte.
    pub fn elevated(self) -> bool {
        matches!(self, Self::Nodes)
    }
}

/// Les étapes qu'un constat couvre.
///
/// Un `stat` mesure les trois nœuds d'un coup : le constat des nœuds répond
/// donc pour trois étapes, pas une. Déclarer cette couverture est ce qui
/// permet au registre de savoir **quelles** étapes un constat vient
/// d'établir — sans quoi une étape dont le constat est différé n'entrerait
/// jamais au registre, et son effet resterait sur la machine sans que le
/// déroulé le connaisse.
pub const fn covered_by(constat: Constat) -> &'static [Step] {
    match constat {
        Constat::Package => &[Step::InstallPackage],
        Constat::Nodes => &[
            Step::WriteMachineConfiguration,
            Step::CreateState,
            Step::InstallCredentialSources,
        ],
        Constat::Unit => &[Step::ActivateController],
    }
}

/// Ce que chaque étape doit constater une fois ses actes passés.
///
/// Une étape sans constat rend `None`, et c'est une déclaration : le transfert
/// a le sien dans son propre module, l'association et le prévol ne touchent pas
/// cette machine. Le constat des nœuds est rattaché à la dernière étape qui en
/// pose un, puisqu'un seul `stat` les mesure tous les trois.
pub const fn constat_for(step: Step) -> Option<Constat> {
    match step {
        Step::InstallPackage => Some(Constat::Package),
        Step::InstallCredentialSources => Some(Constat::Nodes),
        Step::ActivateController => Some(Constat::Unit),
        Step::TransferBundle
        | Step::WriteMachineConfiguration
        | Step::CreateState
        | Step::AssociateConsole
        | Step::Preflight => None,
    }
}

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

    /// Le constat des nœuds dépense l'élévation, et lui seul — mesuré, pas
    /// choisi : `/var/lib/private` réserve cette lecture à `root`.
    ///
    /// La garde existe parce que la mutation qui rendrait `elevated()` faux
    /// survivrait aux autres suites : le `-S` partirait sans secret, et
    /// `sudo` attendrait sur une machine réelle une réponse qu'aucune suite ne
    /// peut voir manquer. Ici, elle rougit.
    #[test]
    fn the_nodes_constat_alone_spends_the_elevation() {
        assert!(Constat::Nodes.elevated());
        assert!(!Constat::Package.elevated());
        assert!(!Constat::Unit.elevated());
        // Et ses deux formes portent réellement l'élévation qu'il déclare.
        assert!(Constat::Nodes
            .command(false)
            .as_str()
            .starts_with("/usr/bin/sudo -k -n -- "));
        assert!(Constat::Nodes
            .command(true)
            .as_str()
            .starts_with("/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- "));
    }

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

    /// Le privilège ne voit que des octets fixes : l'acte qui met la
    /// configuration en place ne porte aucune adresse, aucun champ, rien qui
    /// vienne du contenu.
    ///
    /// C'est la condition qui permet à cette étape d'être un acte comme les
    /// autres. Si l'acte portait la moindre valeur composée, il n'aurait pas sa
    /// place dans cette table et le contenu variable entrerait dans le
    /// privilège — ce qui n'arrive nulle part dans ce palier.
    #[test]
    fn the_configuration_act_carries_no_byte_of_the_content() {
        for command in [
            INSTALL_CONFIGURATION.without_password,
            INSTALL_CONFIGURATION.with_password,
        ] {
            let bytes = command.as_str();
            assert!(bytes.contains("/usr/bin/install -o root -g root -m 0600"));
            assert!(bytes.ends_with(super::super::plan::MACHINE_CONFIGURATION));
            // Aucune des clés, donc aucune valeur, n'entre dans l'acte.
            for key in super::super::configuration::CONFIGURATION_KEYS {
                assert!(!bytes.contains(key));
            }
            assert!(!bytes.contains("chmod"));
            for forbidden in [">", "~"] {
                assert!(!bytes.contains(forbidden), "acte composé : {bytes}");
            }
        }
    }

    /// Les étapes sans acte rendent une liste vide, et c'est une réponse.
    #[test]
    fn the_steps_without_an_act_answer_with_an_empty_list() {
        for step in [
            Step::TransferBundle,
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

    /// Le budget est une somme de ce que les tables déclarent, jamais un nombre
    /// rond posé à la main.
    ///
    /// L'audit n'ouvre aucun canal d'installation : son budget est nul, ce qui
    /// dit « rien à substituer » et laisse la session porter la conversation de
    /// l'accès personnel telle quelle.
    ///
    /// **Amendement du 16 août 2026.** Ce test asserte désormais `MAX + étapes
    /// + 1` là où il assertait `étapes + 1`, parce que le terme manquant était
    /// un défaut et non une convention : la même session dépense la
    /// conversation de l'accès personnel avant les étapes du plan. Ce qu'il
    /// tient en propre reste ce qu'il tenait — **le canal de fermeture est
    /// compté une fois, et une seule** — et cette part-là n'a pas bougé.
    #[test]
    fn the_budget_is_derived_from_the_steps_and_never_chosen() {
        use crate::personal_access::audit::OBSERVATION_CHANNELS;
        use crate::personal_access::session::MAX_EXEC_CHANNELS;
        use your_cloud_bootstrap_protocol::BootstrapAction;

        assert_eq!(channel_budget(BootstrapAction::AuditTargetReadOnly), 0);

        let install: usize =
            super::super::plan::authorized_steps(BootstrapAction::InstallServerBundle)
                .iter()
                .map(|step| channels_for(*step))
                .sum();
        assert_eq!(
            channel_budget(BootstrapAction::InstallServerBundle),
            MAX_EXEC_CHANNELS + OBSERVATION_CHANNELS + install + 1,
            "le canal de fermeture est compté une fois, et une seule"
        );

        let activate: usize =
            super::super::plan::authorized_steps(BootstrapAction::ActivateApprovedController)
                .iter()
                .map(|step| channels_for(*step))
                .sum();
        assert_eq!(
            channel_budget(BootstrapAction::ActivateApprovedController),
            MAX_EXEC_CHANNELS + OBSERVATION_CHANNELS + activate + 1
        );
    }

    /// **Le budget d'une action qui installe couvre la session entière**, et
    /// non ses seules étapes.
    ///
    /// C'est la propriété que le câblage du canal réel a imposée, et le test
    /// qui manquait : la même session dépense d'abord la conversation de
    /// l'accès personnel — sonde, listing, élévation — puis les étapes du plan.
    /// La garde d'adoption n'accepte un budget qu'avant le **premier** canal de
    /// la session ; un budget qui ne compterait que les étapes serait donc
    /// adopté avant la sonde, puis épuisé au milieu de l'installation.
    ///
    /// Mesuré avant correction : `channel_budget(InstallServerBundle)` rendait
    /// 15, la session en dépensait 3 pour s'élever, et la séquence branchée sur
    /// elle s'arrêtait sur `BudgetRefused` à tous les coups.
    #[test]
    fn an_installing_action_budgets_the_whole_session_and_not_only_its_steps() {
        use crate::personal_access::audit::OBSERVATION_CHANNELS;
        use crate::personal_access::session::MAX_EXEC_CHANNELS;
        use your_cloud_bootstrap_protocol::BootstrapAction;

        for action in [
            BootstrapAction::InstallServerBundle,
            BootstrapAction::ActivateApprovedController,
        ] {
            let opened: usize = super::super::plan::authorized_steps(action)
                .iter()
                .map(|step| channels_for(*step))
                .sum();
            assert_eq!(
                channel_budget(action),
                MAX_EXEC_CHANNELS + OBSERVATION_CHANNELS + opened + 1,
                "le budget de {action:?} n'ouvre pas la conversation de la session entière"
            );
            // La forme faible que ce test existe pour interdire : un budget qui
            // ne dépasserait pas ce que l'accès personnel a déjà dépensé
            // laisserait la séquence sans un seul canal.
            assert!(
                channel_budget(action) > MAX_EXEC_CHANNELS,
                "{action:?} n'a aucun canal une fois l'élévation prouvée"
            );
        }

        // L'audit ne substitue rien : sa conversation est déjà celle que la
        // session porte, et lui donner un budget serait lui en donner un second.
        assert_eq!(channel_budget(BootstrapAction::AuditTargetReadOnly), 0);
    }

    /// Chaque acte déclaré tient dans le budget de son étape.
    ///
    /// C'est l'égalité qui empêche un acte ajouté sans son canal de heurter le
    /// budget au milieu d'une séquence : il fait rougir ici, avant d'exister
    /// sur une machine.
    #[test]
    fn every_step_budgets_at_least_the_acts_it_declares() {
        for step in super::super::plan::STEPS {
            let declared = ACTS
                .iter()
                .filter(|(candidate, _)| *candidate == step)
                .count();
            assert!(
                channels_for(step) >= declared,
                "l'étape {step:?} déclare {declared} actes pour {} canaux",
                channels_for(step)
            );
        }
    }
}

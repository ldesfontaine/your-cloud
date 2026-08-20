//! What a personal session must observe before an access may be called
//! verified, and the single place that verdict can be reached.
//!
//! The deciding half of the `sudo` policy already exists: [`super::sudo_policy`]
//! reads a listing and answers whether a password may travel at all. This
//! module is the half that *acts* on that answer. It owns the three fixed
//! commands the session may ever run, reads what they answered, and holds the
//! one gate that turns those answers into an [`Elevation`].
//!
//! Three rules shape everything below.
//!
//! The commands are constants. Not one of them is assembled from a name, a
//! path, a fingerprint or anything else that crossed a process boundary, and
//! [`FixedCommand`] cannot be built outside this crate, so a command that is
//! not one of these constants has no way of reaching a channel. The read-only
//! audit declares its own three constants of the same type, in
//! [`super::audit`]: what [`CHANNEL_COMMANDS`] lists is every command an
//! *elevation* may run, not every command that type has values for.
//!
//! The verdict is a pair. An exit status of zero and a uid of `0` are read
//! together, in [`elevated`], and neither is ever enough on its own. The case
//! that looks harmless — a uid of zero printed under a failing status, or a
//! successful status over an unreadable uid — is refused exactly like the case
//! that looks hostile, because a client that trusted either would be trusting
//! output it could not correlate with an outcome.
//!
//! Everything doubtful fails closed. An unattestable listing, two sudoers
//! entries, a command the policy does not name, a prompt this palier never
//! asked for, a terminal requirement, an oversized stream, a uid that is not a
//! plain decimal number: each of them ends the elevation with its own reason
//! and none of them is retried.

use super::sudo_policy::{self, SudoRefusal, MAX_PREFLIGHT_OUTPUT_BYTES};
use your_cloud_bootstrap_protocol::BootstrapAction;

/// One of the fixed commands a personal session may run, and nothing else.
///
/// The inner string is private and the constructor is crate-internal, so every
/// value that exists is one of the constants declared in this module. A caller
/// outside the crate — the contract suite included — can name them and compare
/// them, and cannot invent a fourth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedCommand(&'static str);

impl FixedCommand {
    pub(crate) const fn fixed(command: &'static str) -> Self {
        Self(command)
    }

    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// The prompt `sudo` is told to print, and the only one this palier accepts.
///
/// It carries no `%` escape, no space and no shell metacharacter: `sudo`
/// expands the former, and the remote login shell that receives the `exec`
/// request would split or interpret the latter.
pub const PROMPT_SENTINEL: &str = "your-cloud-sudo-prompt:";

/// The single elevated action, and the only program the remote policy has to
/// authorise. It is the probe of #52 run as `root`, so what proves the
/// elevation is the very command that proved the identity.
const ELEVATED_ACTION: &str = super::session::PROBE_COMMAND;

/// The absolute path the listing must authorise, without its argument.
const AUTHORISED_PROGRAM: &str = "/usr/bin/id";

/// `sudo` entry that authorises every command. It is not a divergence: it
/// names the one this palier runs, among others.
const ANY_COMMAND: &str = "ALL";

/// The uid an elevation must reach, and the uid the administrator route must
/// not already hold.
pub const ROOT_UID: u32 = 0;

/// Longest decimal uid a probe may print. `u32::MAX` is ten digits.
const MAX_UID_DIGITS: usize = 10;

/// The identity probe. It is [`super::session::PROBE_COMMAND`], named here as a
/// channel so the three commands of a session are read as one list.
pub const IDENTITY: FixedCommand = FixedCommand::fixed(ELEVATED_ACTION);

/// The policy preflight of #51. `-N` leaves the timestamp untouched, `-n`
/// forbids any prompt, `-ll` asks for the long listing — the argument vector
/// that module fixed, spelled here as the command a channel runs.
pub const PREFLIGHT: FixedCommand = FixedCommand::fixed("/usr/bin/sudo -N -n -l -l");

/// The elevation of an account the attested policy says needs no password. It
/// stays `-n`: a policy that turned out to want one after all must fail rather
/// than wait for a prompt nobody will answer.
pub const ELEVATE_WITHOUT_PASSWORD: FixedCommand =
    FixedCommand::fixed("/usr/bin/sudo -N -n -- /usr/bin/id -u");

/// The elevation that spends the one password. `-k` drops any cached
/// credential, so the password is really required and a session that reused
/// somebody else's timestamp could not pass for one that authenticated; `-S`
/// reads it from the channel rather than from a terminal; `-p` replaces the
/// prompt with the sentinel above, which is what makes any other prompt
/// recognisable as unexpected.
pub const ELEVATE_WITH_PASSWORD: FixedCommand =
    FixedCommand::fixed("/usr/bin/sudo -k -S -p your-cloud-sudo-prompt: -- /usr/bin/id -u");

/// Every command a personal session may ever run, in the order it may run them.
pub const CHANNEL_COMMANDS: [FixedCommand; 4] = [
    IDENTITY,
    PREFLIGHT,
    ELEVATE_WITHOUT_PASSWORD,
    ELEVATE_WITH_PASSWORD,
];

/// The two routes to a proven access. They are separate values, not a flag,
/// because they consent to different things and share no step after the
/// identity probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessRoute {
    /// A non-root account whose elevation the remote policy authorises.
    Administrator,
    /// A `root` account lent for this operation, and consented to on its own.
    Root,
}

/// Ce que l'entrée sudoers doit autoriser pour l'action que l'humain approuve.
///
/// Les deux valeurs ne sont pas deux niveaux d'une même échelle, ce sont deux
/// questions différentes. L'audit exécute **une** sonde nommée, donc une entrée
/// qui ne nomme qu'elle suffit — et c'est la bonne asymétrie : auditer ne doit
/// pas coûter plus de privilège qu'auditer n'en demande.
///
/// Installer exige [`RequiredScope::EveryCommand`], et la raison est écrite au
/// contrat d'architecture parce qu'elle se laisse mal deviner : **une liste
/// exacte contenant `dpkg --install` n'est pas du moindre privilège, c'en est
/// l'apparence.** Un `.deb` exécute ses scripts de mainteneur en `root` —
/// autoriser `dpkg`, c'est autoriser l'exécution arbitraire en `root` — et
/// `systemctl` y ajoute le démarrage de n'importe quelle unité. Une liste
/// étroite serait donc équivalente à `ALL` en pouvoir réel, tout en coûtant à
/// l'humain un sudoers écrit à la main avant son premier lancement et en
/// devenant une surface publique du contrat qui dériverait à chaque étape
/// ajoutée au plan.
///
/// Ce qui borne réellement cette élévation existe déjà et n'est pas une liste :
/// le **temps** — elle meurt avec la session —, le **consentement** — chaque
/// acte est approuvé —, et la **nature** de cet accès, celui du mainteneur,
/// prêté et conservé, jamais détenu par le produit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredScope {
    /// L'entrée doit nommer la sonde d'identité, ou tout autoriser.
    IdentityProbe,
    /// L'entrée doit tout autoriser.
    EveryCommand,
}

impl RequiredScope {
    /// Ce que l'action approuvée exige de la politique distante.
    ///
    /// La correspondance vit ici plutôt que dans le module d'installation pour
    /// une raison de compilation et non de sens : ce module est bâti sur toutes
    /// les cibles, `installation` seulement sur les deux que le palier vise, et
    /// l'appelant qui dérive ce champ est bâti partout.
    pub const fn for_action(action: BootstrapAction) -> Self {
        match action {
            BootstrapAction::AuditTargetReadOnly => Self::IdentityProbe,
            BootstrapAction::InstallServerBundle | BootstrapAction::ActivateApprovedController => {
                Self::EveryCommand
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElevationRefusal {
    /// The listing itself could not be attested. It carries #51's own reason.
    Policy(SudoRefusal),
    /// L'entrée n'autorise que des programmes nommés là où l'action approuvée
    /// exige toute commande.
    ///
    /// Elle porte **ce que l'entrée permet aujourd'hui**, parce qu'un refus qui
    /// ne dirait que « non » laisserait l'humain deviner : il y a deux issues,
    /// autoriser `ALL` ou prêter un accès `root` direct — que le contrat
    /// d'amorçage accepte déjà comme sa seconde route — et nommer l'existant
    /// est ce qui rend le choix possible. Personne n'est contraint d'élargir
    /// son sudoers ; c'est une décision nommée, prise avant toute fenêtre.
    NarrowerThanTheActionRequires { permits: String },
    /// No sudoers entry, or more than one: which of them applies to the action
    /// cannot be told, and guessing is not a bound.
    ///
    /// Elle porte **les entrées vues**, pour la même raison que le refus
    /// d'entrée trop étroite porte ce que l'entrée permet : le geste qui la
    /// lève — retirer le compte du groupe qui lui donne sa seconde entrée —
    /// ne peut se choisir qu'en voyant lesquelles s'empilent (#157).
    AmbiguousPolicy { entries: String },
    /// The listing authorises another program, another target user, or negates
    /// the one this palier runs.
    DivergentCommand,
    /// A prompt this palier never asked for, or its own sentinel a second
    /// time — which is `sudo` asking again, and there is no second answer.
    UnexpectedPrompt,
    /// The policy wants a terminal. This session allocates none, on purpose.
    TerminalRequired,
    /// A stream exceeded the bound its reader holds.
    OutputTooLarge,
    /// The output is not a single plain decimal uid.
    UnreadableUid,
    /// The administrator route reached an account that is already `root`.
    /// `root` has its own consent and is never arrived at by accident.
    AlreadyRoot,
    /// The root route reached an account that is not `root`.
    NotRoot,
    /// The elevated command failed, and said so consistently.
    NotElevated,
    /// The exit status and the uid disagree. Refused whichever way round.
    DivergentOutcome,
}

impl From<SudoRefusal> for ElevationRefusal {
    fn from(refusal: SudoRefusal) -> Self {
        Self::Policy(refusal)
    }
}

/// The proof that an elevation really happened.
///
/// It is a witness, not a report: it carries no output, it cannot be built by
/// naming its fields, and [`elevated`] is the only function in this crate that
/// returns one. Whatever publishes `access_verified` must hold one, so the
/// question "could that event be published without the elevation" has one
/// answer to look at rather than one per call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elevation {
    route: AccessRoute,
}

impl Elevation {
    pub fn route(self) -> AccessRoute {
        self.route
    }
}

/// What the attested listing says about the one action this palier runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedPolicy {
    /// Which of the two elevation commands the session may run next.
    pub command: FixedCommand,
    /// True when that command is the one carrying a password. Kept beside the
    /// command rather than derived from it at each call site, so "a password
    /// travels" is one decision taken once.
    pub password_required: bool,
    /// Ce que la même entrée permettrait à une INSTALLATION — jugé ici, sur le
    /// même listing, par le même juge, quel que soit le scope de l'action en
    /// cours. C'est ce que la route d'audit exporte pour que le refus d'une
    /// pose tombe avant toute fenêtre (constat n°10 de #143, arbitrage du
    /// 19 août 2026) : une seconde lecture ailleurs serait une seconde
    /// autorité, et les deux finiraient par différer.
    pub installation: InstallationScope,
}

/// Ce que l'entrée sudoers attestée permet face à ce qu'installer exige.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationScope {
    /// L'entrée autorise toute commande — ce que les actions d'installation
    /// exigent, pour la raison écrite à la décision tranchée du contrat.
    pub suffices: bool,
    /// Ce que l'entrée permet aujourd'hui, mot pour mot depuis le listing —
    /// renseigné exactement quand `suffices` est faux, parce que c'est le
    /// refus qui a besoin de nommer, et lui seul.
    pub permits: String,
}

/// Reads the identity probe of the route, and refuses the two accounts that
/// have no business being on it.
///
/// The administrator route refuses `root` outright: an account that is already
/// `root` would make the elevation trivially true and would reach root
/// privileges under the personal access consent alone, which is exactly the
/// implicit root attempt this palier forbids. The root route refuses everything
/// that is not `root`, for the symmetric reason.
pub fn attest_identity(
    route: AccessRoute,
    exit_status: u32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<u32, ElevationRefusal> {
    bounded(stderr)?;
    if exit_status != 0 {
        return Err(ElevationRefusal::NotElevated);
    }
    let uid = read_uid(stdout)?;
    match (route, uid == ROOT_UID) {
        (AccessRoute::Administrator, true) => Err(ElevationRefusal::AlreadyRoot),
        (AccessRoute::Root, false) => Err(ElevationRefusal::NotRoot),
        _ => Ok(uid),
    }
}

/// The root route ends where it started: the session authenticated as `root`,
/// the fixed probe answered `0`, and its own native consent was given.
///
/// `consented` is not a courtesy argument. It is the caller's own statement
/// that a second, dedicated window was answered, and there is no default: a
/// caller that forgot it refuses instead of eliding it.
pub fn root_access(
    consented: bool,
    exit_status: u32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Elevation, ElevationRefusal> {
    if !consented {
        return Err(ElevationRefusal::NotRoot);
    }
    attest_identity(AccessRoute::Root, exit_status, stdout, stderr)?;
    verified_pair(AccessRoute::Root, exit_status, ROOT_UID)
}

/// Decides, from the preflight the second channel captured, which single
/// elevation command the third may run — or that there will be none.
///
/// The listing is first handed to #51 unchanged, so the reason a password may
/// never travel is that module's and not a second opinion. Only a listing that
/// module accepted is then read for what this one needs: that exactly one entry
/// applies, that it runs as `root`, that it names the program this palier runs,
/// and whether answering it costs a password.
pub fn attest_policy(
    succeeded: bool,
    output: &[u8],
    truncated: bool,
    scope: RequiredScope,
) -> Result<AttestedPolicy, ElevationRefusal> {
    let decision = sudo_policy::evaluate(succeeded, output, truncated)?;
    debug_assert!(decision.password_may_be_sent);
    debug_assert!(!decision.relies_on_sudo_redaction);

    // `evaluate` already refused anything that is not ASCII, and anything past
    // the bound, so the listing is text from here on.
    let text = std::str::from_utf8(output)
        .map_err(|_| ElevationRefusal::Policy(SudoRefusal::OutputNotAscii))?;
    let entry = single_entry(text)?;
    if !runs_as_root(&entry) {
        return Err(ElevationRefusal::DivergentCommand);
    }
    if !authorises_the_action(&entry) {
        return Err(ElevationRefusal::DivergentCommand);
    }
    // La portée d'installation est jugée sur CHAQUE attestation, pas seulement
    // quand l'action l'exige : c'est elle que la route d'audit exporte, et un
    // jugement qui n'existerait que sur la route d'installation ne pourrait
    // jamais faire tomber le refus avant la fenêtre de cette route-là.
    let suffices = authorises_every_command(&entry);
    let installation = InstallationScope {
        permits: if suffices {
            String::new()
        } else {
            entry.commands.join(", ")
        },
        suffices,
    };
    // Le durcissement de portée vient **après** la divergence et non à sa
    // place : une entrée qui nomme un autre programme reste `DivergentCommand`,
    // et seule une entrée par ailleurs valable mais trop étroite pour l'action
    // reçoit le refus qui nomme ce qu'elle permet. Les deux ne demandent pas le
    // même geste à l'humain.
    if scope == RequiredScope::EveryCommand && !installation.suffices {
        return Err(ElevationRefusal::NarrowerThanTheActionRequires {
            permits: installation.permits,
        });
    }

    let password_required = !entry.authentication_waived;
    Ok(AttestedPolicy {
        command: if password_required {
            ELEVATE_WITH_PASSWORD
        } else {
            ELEVATE_WITHOUT_PASSWORD
        },
        password_required,
        installation,
    })
}

/// The one gate. Nothing else in this crate builds an [`Elevation`].
///
/// Both halves are read here, from the same channel, and both must hold: the
/// elevated command exited zero *and* printed root's uid. The streams are
/// examined before either, because a prompt or a terminal requirement means the
/// answer is not an answer at all.
pub fn elevated(
    exit_status: u32,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Elevation, ElevationRefusal> {
    prompt_free(stderr)?;
    let uid = read_uid(stdout)?;
    verified_pair(AccessRoute::Administrator, exit_status, uid)
}

/// The pair itself, isolated so both routes reach it through the same two
/// lines and neither can weaken its own copy.
fn verified_pair(
    route: AccessRoute,
    exit_status: u32,
    uid: u32,
) -> Result<Elevation, ElevationRefusal> {
    match (exit_status == 0, uid == ROOT_UID) {
        (true, true) => Ok(Elevation { route }),
        // A command that failed and did not reach root is the ordinary
        // refusal; anything else is the two halves disagreeing.
        (false, false) => Err(ElevationRefusal::NotElevated),
        _ => Err(ElevationRefusal::DivergentOutcome),
    }
}

/// One sudoers entry of the long listing, reduced to what this module judges.
struct Entry {
    run_as_users: Option<String>,
    /// True when the matching policy states that answering it needs no
    /// authentication.
    authentication_waived: bool,
    commands: Vec<String>,
}

/// Extracts the single applicable entry, refusing zero and refusing two.
///
/// The long listing prints one `Sudoers entry:` block per matching rule. A
/// listing with several of them may well be answerable, but which rule the
/// action falls under is decided by `sudo`'s own ordering and not by anything
/// observable here, so it is refused rather than guessed.
fn single_entry(text: &str) -> Result<Entry, ElevationRefusal> {
    // Les entrées telles que le listing les nomme, dans son ordre : c'est ce
    // que le refus rendra à l'humain s'il y en a plusieurs. La borne du nom
    // exporté s'applique au moment de l'export, pas ici.
    let named: Vec<&str> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("Sudoers entry"))
        .map(str::trim)
        .collect();
    let ambiguous = || ElevationRefusal::AmbiguousPolicy {
        entries: named.join(" ; "),
    };
    let mut starts = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with("Sudoers entry"))
        .map(|(index, _)| index);
    let start = starts.next().ok_or_else(ambiguous)?;
    if starts.next().is_some() {
        return Err(ambiguous());
    }

    let mut entry = Entry {
        run_as_users: None,
        authentication_waived: false,
        commands: Vec::new(),
    };
    let mut in_commands = false;
    for line in text.lines().skip(start + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(users) = trimmed.strip_prefix("RunAsUsers:") {
            in_commands = false;
            entry.run_as_users = Some(users.trim().to_owned());
        } else if let Some(options) = trimmed.strip_prefix("Options:") {
            in_commands = false;
            entry.authentication_waived = options
                .split(',')
                .any(|option| option.trim() == "!authenticate");
        } else if trimmed.starts_with("Commands:") {
            in_commands = true;
        } else if trimmed.ends_with(':') && !trimmed.starts_with('/') {
            // Any other heading of the block — `RunAsGroups:`, `Options:` of a
            // later form — ends the command list rather than joining it.
            in_commands = false;
        } else if in_commands {
            entry.commands.push(trimmed.to_owned());
        }
    }
    Ok(entry)
}

/// The elevation must run as `root` and as nothing else. `ALL` names root among
/// others and is accepted; a list is not, because this palier asks for one
/// target user and a list means the entry was written for something wider.
fn runs_as_root(entry: &Entry) -> bool {
    matches!(
        entry.run_as_users.as_deref(),
        Some("root") | Some(ANY_COMMAND)
    )
}

/// The listing must name the exact program the elevation runs, or authorise
/// every program. A negated command anywhere in the entry refuses the whole
/// entry: `sudo` reads those in order and this module does not.
fn authorises_the_action(entry: &Entry) -> bool {
    if entry
        .commands
        .iter()
        .any(|command| command.starts_with('!'))
    {
        return false;
    }
    entry.commands.iter().any(|command| {
        let mut words = command.split_whitespace();
        matches!(words.next(), Some(AUTHORISED_PROGRAM) | Some(ANY_COMMAND))
    })
}

/// L'entrée autorise-t-elle **toute** commande ?
///
/// Rien d'autre que `ALL` ne répond oui. Une liste de programmes, si longue
/// soit-elle, ne vaut pas `ALL` ici — non parce qu'elle serait moins puissante,
/// mais parce que le contrat refuse de faire croire à un moindre privilège que
/// `dpkg` et `systemctl` démentiraient. La négation reste éliminatoire, comme
/// pour [`authorises_the_action`].
fn authorises_every_command(entry: &Entry) -> bool {
    if entry
        .commands
        .iter()
        .any(|command| command.starts_with('!'))
    {
        return false;
    }
    entry
        .commands
        .iter()
        .any(|command| command.split_whitespace().next() == Some(ANY_COMMAND))
}

/// Refuses a stream past the bound its reader holds, and anything that is not
/// ASCII — under `LC_ALL=C` the far side answers ASCII, and a stream that does
/// not means the locale never applied, so nothing in it can be recognised.
fn bounded(stream: &[u8]) -> Result<&str, ElevationRefusal> {
    if stream.len() > MAX_PREFLIGHT_OUTPUT_BYTES {
        return Err(ElevationRefusal::OutputTooLarge);
    }
    if !stream.is_ascii() {
        return Err(ElevationRefusal::UnexpectedPrompt);
    }
    std::str::from_utf8(stream).map_err(|_| ElevationRefusal::UnexpectedPrompt)
}

/// Everything the standard error of an elevation may not contain.
///
/// The sentinel may appear once: that is `sudo` asking for the one password
/// this session sends. A second occurrence is `sudo` asking again, which is the
/// retry this palier does not have. `sudo`'s own default prompt means the fixed
/// `-p` never took effect, so the client is no longer reading the conversation
/// it started.
fn prompt_free(stderr: &[u8]) -> Result<(), ElevationRefusal> {
    let text = bounded(stderr)?;
    let lowered = text.to_ascii_lowercase();
    for marker in TERMINAL_MARKERS {
        if lowered.contains(marker) {
            return Err(ElevationRefusal::TerminalRequired);
        }
    }
    if text.matches(PROMPT_SENTINEL).count() > 1 {
        return Err(ElevationRefusal::UnexpectedPrompt);
    }
    for marker in FOREIGN_PROMPT_MARKERS {
        if lowered.contains(marker) {
            return Err(ElevationRefusal::UnexpectedPrompt);
        }
    }
    Ok(())
}

/// What `sudo` says when the policy wants a terminal this session never
/// allocates. `requiretty` produces the first two; the third is what a policy
/// with no askpass answers.
const TERMINAL_MARKERS: [&str; 3] = [
    "a terminal is required",
    "sorry, you must have a tty",
    "no tty present",
];

/// Answers that are not this palier's own prompt.
///
/// The first three are `sudo`'s default prompt in its usual spellings, and
/// seeing one means the fixed `-p` never took effect, so the client is no
/// longer reading the conversation it started. The fourth is what a
/// passwordless elevation is told when the attested policy turned out to want a
/// password after all: there is no second decision to take and no answer to
/// give, so it is refused here rather than left to the exit status.
const FOREIGN_PROMPT_MARKERS: [&str; 4] = [
    "[sudo]",
    "password for",
    "password:",
    "a password is required",
];

/// Reads exactly one plain decimal uid, and refuses everything else.
///
/// A single trailing newline belongs to the command, not to the number.
/// Anything beyond it — a second line, a sign, a leading zero, padding — means
/// the output is not the one `/usr/bin/id -u` produces, and an output this
/// client cannot recognise is never interpreted generously.
fn read_uid(stdout: &[u8]) -> Result<u32, ElevationRefusal> {
    let text = bounded(stdout).map_err(|_| ElevationRefusal::UnreadableUid)?;
    let digits = text.strip_suffix('\n').unwrap_or(text);
    if digits.is_empty()
        || digits.len() > MAX_UID_DIGITS
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(ElevationRefusal::UnreadableUid);
    }
    digits
        .parse::<u32>()
        .map_err(|_| ElevationRefusal::UnreadableUid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A long listing in the shape `sudo 1.9.16p2` really writes it, with the
    /// options and the command list the caller asks for.
    fn listing(options: &str, commands: &str) -> String {
        let options = if options.is_empty() {
            String::new()
        } else {
            format!("    Options: {options}\n")
        };
        format!(
            "Matching Defaults entries for operator on target:\n    \
             env_reset, mail_badpass, secure_path=/usr/bin\n\n\
             User operator may run the following commands on target:\n\n\
             Sudoers entry: /etc/sudoers.d/90-operator\n    \
             RunAsUsers: root\n{options}    Commands:\n\t{commands}\n"
        )
    }

    #[test]
    fn every_command_is_an_absolute_constant_with_no_shell_in_it() {
        for command in CHANNEL_COMMANDS {
            let text = command.as_str();
            assert!(text.starts_with('/'), "{text} is not an absolute path");
            for forbidden in [
                ';', '&', '|', '\n', '\r', '`', '$', '<', '>', '(', ')', '\'', '"', '*', '?', '\\',
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{text} carries the shell character {forbidden:?}"
                );
            }
        }
        assert_eq!(IDENTITY.as_str(), ELEVATED_ACTION);
        assert!(ELEVATE_WITH_PASSWORD.as_str().contains(PROMPT_SENTINEL));
        assert!(
            !PROMPT_SENTINEL.contains('%') && !PROMPT_SENTINEL.contains(' '),
            "the sentinel must survive sudo's own expansion and the remote shell's word splitting"
        );
        // Both elevated commands run the very action the identity probe ran.
        for elevated in [ELEVATE_WITHOUT_PASSWORD, ELEVATE_WITH_PASSWORD] {
            assert!(elevated
                .as_str()
                .ends_with(&format!("-- {ELEVATED_ACTION}")));
        }
        // Only one of the four ever carries a password, and only that one asks
        // `sudo` to read the channel.
        assert_eq!(
            CHANNEL_COMMANDS
                .iter()
                .filter(|command| command.as_str().contains(" -S "))
                .count(),
            1
        );
    }

    /// The property `access_verified` rests on: neither half of the pair is
    /// ever enough, and the two disagreeing is its own refusal.
    #[test]
    fn the_exit_status_and_the_uid_are_read_as_one_indissociable_pair() {
        assert!(elevated(0, b"0\n", b"").is_ok());

        assert_eq!(
            elevated(1, b"0\n", b""),
            Err(ElevationRefusal::DivergentOutcome),
            "root's uid under a failing status must never pass"
        );
        assert_eq!(
            elevated(0, b"1000\n", b""),
            Err(ElevationRefusal::DivergentOutcome),
            "a successful status over another uid must never pass"
        );
        assert_eq!(
            elevated(1, b"1000\n", b""),
            Err(ElevationRefusal::NotElevated)
        );
        assert_eq!(elevated(0, b"", b""), Err(ElevationRefusal::UnreadableUid));
    }

    #[test]
    fn only_a_plain_decimal_uid_is_read() {
        assert_eq!(read_uid(b"0\n"), Ok(0));
        assert_eq!(read_uid(b"0"), Ok(0));
        assert_eq!(read_uid(b"4294967295\n"), Ok(u32::MAX));
        for hostile in [
            &b""[..],
            b"\n",
            b"00\n",
            b"+0\n",
            b"-0\n",
            b" 0\n",
            b"0 \n",
            b"0\n0\n",
            b"0\n\n",
            b"0x0\n",
            b"root\n",
            b"4294967296\n",
            b"00000000000\n",
        ] {
            assert_eq!(
                read_uid(hostile),
                Err(ElevationRefusal::UnreadableUid),
                "{:?} is not one plain uid",
                String::from_utf8_lossy(hostile)
            );
        }
    }

    #[test]
    fn an_administrator_route_never_arrives_at_root_and_a_root_route_never_leaves_it() {
        assert_eq!(
            attest_identity(AccessRoute::Administrator, 0, b"1000\n", b""),
            Ok(1000)
        );
        assert_eq!(
            attest_identity(AccessRoute::Administrator, 0, b"0\n", b""),
            Err(ElevationRefusal::AlreadyRoot),
            "an account that is already root must never be elevated implicitly"
        );
        assert_eq!(attest_identity(AccessRoute::Root, 0, b"0\n", b""), Ok(0));
        assert_eq!(
            attest_identity(AccessRoute::Root, 0, b"1000\n", b""),
            Err(ElevationRefusal::NotRoot)
        );
    }

    #[test]
    fn the_root_route_demands_its_own_consent_before_anything_else() {
        assert_eq!(
            root_access(true, 0, b"0\n", b"").map(Elevation::route),
            Ok(AccessRoute::Root)
        );
        assert_eq!(
            root_access(false, 0, b"0\n", b""),
            Err(ElevationRefusal::NotRoot),
            "a root access without its own consent is not an access"
        );
        assert_eq!(
            root_access(true, 1, b"0\n", b""),
            Err(ElevationRefusal::NotElevated)
        );
    }

    #[test]
    fn an_attestable_policy_chooses_exactly_one_elevation_command() {
        let with_password = attest_policy(
            true,
            listing("", "/usr/bin/id").as_bytes(),
            false,
            RequiredScope::IdentityProbe,
        )
        .expect("an attestable policy");
        assert!(with_password.password_required);
        assert_eq!(with_password.command, ELEVATE_WITH_PASSWORD);

        let waived = attest_policy(
            true,
            listing("!authenticate", "/usr/bin/id").as_bytes(),
            false,
            RequiredScope::IdentityProbe,
        )
        .expect("an attestable policy");
        assert!(!waived.password_required);
        assert_eq!(waived.command, ELEVATE_WITHOUT_PASSWORD);

        let wide = attest_policy(
            true,
            listing("", "ALL").as_bytes(),
            false,
            RequiredScope::IdentityProbe,
        )
        .expect("ALL names the action among others");
        assert_eq!(wide.command, ELEVATE_WITH_PASSWORD);
    }

    /// Chaque attestation juge aussi ce que l'entrée permettrait à une
    /// installation — c'est la portée que la route d'audit exporte.
    ///
    /// Le refus d'une pose ne peut tomber avant sa fenêtre que si un jugement
    /// antérieur, rendu sous un consentement antérieur, a déjà dit ce que
    /// l'entrée permet (arbitrage du 19 août 2026, constat n°10 de #143). Ce
    /// cas tient les deux moitiés de la paire : `suffices` sans nom, ou le nom
    /// exact sans `suffices` — une portée qui dirait « non » sans nommer
    /// laisserait l'humain deviner, et c'est ce que le contrat refuse.
    #[test]
    fn every_attestation_judges_what_the_entry_would_permit_an_installation() {
        // L'entrée étroite, attestée pour un AUDIT : la politique passe —
        // c'est l'asymétrie — et la portée dit déjà ce qu'un refus de pose
        // devra nommer, mot pour mot depuis le listing.
        let narrow = attest_policy(
            true,
            listing("", "/usr/bin/id").as_bytes(),
            false,
            RequiredScope::IdentityProbe,
        )
        .expect("la sonde nommée suffit à l'audit");
        assert!(!narrow.installation.suffices);
        assert_eq!(narrow.installation.permits, "/usr/bin/id");

        // L'entrée qui autorise tout : la portée suffit et ne nomme rien —
        // c'est le refus qui a besoin de nommer, et lui seul.
        let wide = attest_policy(
            true,
            listing("", "ALL").as_bytes(),
            false,
            RequiredScope::IdentityProbe,
        )
        .expect("ALL satisfait toute action");
        assert!(wide.installation.suffices);
        assert!(wide.installation.permits.is_empty());
    }

    /// Le point d'autorité de l'installation : une entrée qui ne nomme que la
    /// sonde suffit pour auditer et **ne suffit pas** pour installer.
    ///
    /// C'est le cas exact que ce durcissement existe pour empêcher. Sans lui,
    /// l'Assistant prouverait l'élévation, ouvrirait la fenêtre, obtiendrait le
    /// consentement — puis heurterait un mur au premier `dpkg`, machine intacte
    /// et parcours mort. Ici le refus tombe **avant** la fenêtre, et il nomme ce
    /// que l'entrée permet aujourd'hui pour que l'humain puisse choisir entre
    /// ses deux issues plutôt que deviner.
    #[test]
    fn an_entry_that_only_names_the_probe_audits_but_never_installs() {
        let narrow = listing("", "/usr/bin/id");

        // L'asymétrie voulue : auditer ne coûte pas plus de privilège
        // qu'auditer n'en demande.
        attest_policy(true, narrow.as_bytes(), false, RequiredScope::IdentityProbe)
            .expect("la sonde nommée suffit à l'audit");

        for scope_action in [
            BootstrapAction::InstallServerBundle,
            BootstrapAction::ActivateApprovedController,
        ] {
            assert_eq!(
                attest_policy(
                    true,
                    narrow.as_bytes(),
                    false,
                    RequiredScope::for_action(scope_action),
                ),
                Err(ElevationRefusal::NarrowerThanTheActionRequires {
                    permits: "/usr/bin/id".into()
                }),
                "l'action était : {scope_action:?}"
            );
        }

        // La même entrée élargie passe : c'est la première des deux issues que
        // le refus nomme. La seconde — prêter un accès root direct — est l'autre
        // route du contrat d'amorçage et ne passe pas par cette porte.
        attest_policy(
            true,
            listing("", "ALL").as_bytes(),
            false,
            RequiredScope::EveryCommand,
        )
        .expect("une entrée qui autorise tout satisfait une installation");
    }

    /// Une liste de programmes, si longue soit-elle, ne vaut pas `ALL` pour une
    /// installation — et le refus la nomme entière.
    ///
    /// La liste nomme ici la sonde **et** les programmes de l'installation :
    /// c'est le cas de l'opérateur soigneux, le seul qui atteigne cette porte.
    /// Une liste qui omettrait la sonde serait refusée bien avant, par
    /// `DivergentCommand`, puisque l'élévation ne pourrait pas même se prouver.
    ///
    /// Le contrat le dit et ce test le tient : autoriser `dpkg` revient à
    /// autoriser l'exécution arbitraire en `root`, donc une liste qui le
    /// contient n'est pas un moindre privilège mais son apparence. La porte
    /// refuse l'apparence.
    #[test]
    fn a_list_of_programs_however_long_is_not_every_command() {
        let listed = listing("", "/usr/bin/id\n\t/usr/bin/dpkg\n\t/usr/bin/systemctl");

        assert_eq!(
            attest_policy(true, listed.as_bytes(), false, RequiredScope::EveryCommand,),
            Err(ElevationRefusal::NarrowerThanTheActionRequires {
                permits: "/usr/bin/id, /usr/bin/dpkg, /usr/bin/systemctl".into()
            })
        );
    }

    /// Une entrée qui autorise tout **mais nie** une commande n'autorise pas
    /// tout : la négation reste éliminatoire, comme pour l'audit.
    #[test]
    fn a_negated_command_defeats_every_command_too() {
        let negated = listing("", "ALL\n\t!/usr/bin/dpkg");

        assert!(matches!(
            attest_policy(true, negated.as_bytes(), false, RequiredScope::EveryCommand,),
            Err(ElevationRefusal::DivergentCommand)
        ));
    }

    #[test]
    fn a_policy_that_names_another_command_or_another_user_fails_closed() {
        for divergent in [
            listing("", "/usr/bin/systemctl"),
            listing("", "!/usr/bin/id"),
            listing("", "/usr/local/bin/id"),
            listing("", "/usr/bin/idle"),
        ] {
            assert_eq!(
                attest_policy(
                    true,
                    divergent.as_bytes(),
                    false,
                    RequiredScope::IdentityProbe
                ),
                Err(ElevationRefusal::DivergentCommand),
                "a divergent command must fail closed: {divergent}"
            );
        }

        let other_user =
            listing("", "/usr/bin/id").replace("RunAsUsers: root", "RunAsUsers: nobody");
        assert_eq!(
            attest_policy(
                true,
                other_user.as_bytes(),
                false,
                RequiredScope::IdentityProbe
            ),
            Err(ElevationRefusal::DivergentCommand)
        );
    }

    #[test]
    fn a_listing_with_no_entry_or_several_is_refused_rather_than_guessed() {
        let none = "Matching Defaults entries for operator on target:\n    env_reset\n\n\
                    User operator may run the following commands on target:\n\n";
        assert_eq!(
            attest_policy(true, none.as_bytes(), false, RequiredScope::IdentityProbe),
            Err(ElevationRefusal::AmbiguousPolicy {
                entries: String::new()
            }),
            "aucune entrée : il n'y a rien à nommer, et le refus le dit ainsi"
        );

        let two = format!(
            "{}\nSudoers entry: /etc/sudoers.d/91-other\n    RunAsUsers: root\n    Commands:\n\t/usr/bin/id\n",
            listing("", "/usr/bin/id")
        );
        // Les DEUX entrées sont nommées, dans l'ordre du listing : c'est ce
        // que l'humain doit voir pour choisir laquelle retirer (#157).
        assert_eq!(
            attest_policy(true, two.as_bytes(), false, RequiredScope::IdentityProbe),
            Err(ElevationRefusal::AmbiguousPolicy {
                entries: "Sudoers entry: /etc/sudoers.d/90-operator ; Sudoers entry: /etc/sudoers.d/91-other"
                    .into()
            }),
            "two entries mean sudo's own ordering decides, and this module does not read it"
        );
    }

    /// #51's refusals reach the caller unchanged rather than being restated.
    #[test]
    fn an_unattestable_listing_carries_the_policy_refusal_it_earned() {
        assert_eq!(
            attest_policy(
                false,
                b"sudo: a password is required\n",
                false,
                RequiredScope::IdentityProbe
            ),
            Err(ElevationRefusal::Policy(
                SudoRefusal::AuthenticationRequired
            ))
        );
        assert_eq!(
            attest_policy(
                true,
                listing("", "/usr/bin/id")
                    .replace("env_reset,", "env_reset, log_input,")
                    .as_bytes(),
                false,
                RequiredScope::IdentityProbe
            ),
            Err(ElevationRefusal::Policy(SudoRefusal::InputLoggingActive))
        );
        assert_eq!(
            attest_policy(
                true,
                listing("", "/usr/bin/id").as_bytes(),
                true,
                RequiredScope::IdentityProbe
            ),
            Err(ElevationRefusal::Policy(SudoRefusal::OutputTooLarge))
        );
    }

    #[test]
    fn an_unexpected_prompt_a_second_sentinel_or_a_terminal_requirement_fails_closed() {
        assert_eq!(
            elevated(0, b"0\n", PROMPT_SENTINEL.as_bytes()).map(Elevation::route),
            Ok(AccessRoute::Administrator)
        );

        let twice = format!("{PROMPT_SENTINEL}{PROMPT_SENTINEL}");
        assert_eq!(
            elevated(0, b"0\n", twice.as_bytes()),
            Err(ElevationRefusal::UnexpectedPrompt),
            "a second sentinel is sudo asking again, and there is no second answer"
        );
        for foreign in [
            &b"[sudo] password for operator: "[..],
            b"Password:",
            b"sudo: a password is required\n",
        ] {
            assert_eq!(
                elevated(0, b"0\n", foreign),
                Err(ElevationRefusal::UnexpectedPrompt),
                "{:?} is not the prompt this palier asked for",
                String::from_utf8_lossy(foreign)
            );
        }
        for terminal in [
            &b"sudo: a terminal is required to read the password"[..],
            b"sudo: sorry, you must have a tty to run sudo",
            b"sudo: no tty present and no askpass program specified",
        ] {
            assert_eq!(
                elevated(0, b"0\n", terminal),
                Err(ElevationRefusal::TerminalRequired)
            );
        }
    }

    #[test]
    fn a_stream_past_the_bound_is_refused_before_it_is_read() {
        let oversized = vec![b'x'; MAX_PREFLIGHT_OUTPUT_BYTES + 1];
        assert_eq!(
            elevated(0, b"0\n", &oversized),
            Err(ElevationRefusal::OutputTooLarge)
        );
        assert_eq!(
            elevated(0, &oversized, b""),
            Err(ElevationRefusal::UnreadableUid)
        );
    }

    /// The capture taken from the LAB's own synthetic account, so the parsing
    /// is pinned to what `sudo` really writes rather than to what a manual page
    /// suggests: wrapped Defaults, a tab-indented command, and the `Options`
    /// line that waives authentication.
    #[test]
    fn a_real_debian_13_listing_is_read_as_written() {
        const REAL: &str = "Matching Defaults entries for ycoperator on lab-console:\n    env_reset, mail_badpass,\n    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin,\n    use_pty\n\nUser ycoperator may run the following commands on lab-console:\n\nSudoers entry: /etc/sudoers.d/90-lab-ycoperator\n    RunAsUsers: root\n    Options: !authenticate\n    Commands:\n\t/usr/bin/id\n";

        let attested = attest_policy(true, REAL.as_bytes(), false, RequiredScope::IdentityProbe)
            .expect("a real listing");
        assert!(!attested.password_required);
        assert_eq!(attested.command, ELEVATE_WITHOUT_PASSWORD);

        let authenticating = REAL.replace("    Options: !authenticate\n", "");
        let attested = attest_policy(
            true,
            authenticating.as_bytes(),
            false,
            RequiredScope::IdentityProbe,
        )
        .expect("a real listing");
        assert!(attested.password_required);
        assert_eq!(attested.command, ELEVATE_WITH_PASSWORD);
    }
}

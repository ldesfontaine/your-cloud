//! The one document of this product a user writes, on the side that helps write
//! it: bounded review, derived consequences, and a paste that can only prefill.
//!
//! Three things live here and nothing else.
//!
//! **The review.** A draft becomes a definition through
//! `your_cloud_bootstrap_protocol::ServiceDefinitionDocument` and through
//! nothing else: the grammars, the bounds, the reserved names, the overlap rule
//! and the one interpolation are read from the mirror the Controller is held
//! against, so a definition this Console accepts is a definition that Controller
//! freezes. Nothing here re-reads a grammar, and a refusal displayed to a human
//! is a refusal the mirror named.
//!
//! **The consequences.** A definition is inert, and freezing one has no effect —
//! but everything a later deployment will do to a machine is already decided by
//! the slug and by the lists, so it is displayed before the freeze rather than
//! discovered after it. The lines follow the pattern the approval windows of the
//! product use: sentences a human approves as consequences, never fields they
//! approve as intentions. The derivation they describe is the contract's
//! (`docs/architecture/SERVICE-UTILISATEUR.md`) and the Auxiliary's; this module
//! decides none of it and re-derives it locally only to say it out loud.
//!
//! **The paste.** A `docker run` command or a `docker-compose.yml` fills the
//! form and does nothing else. The parser is local and pure — it opens no
//! socket, runs no process, reads no file and submits nothing — and its whole
//! output is a draft plus named notes about what it dropped. Every field it
//! produces is then held against the mirror exactly as a field a human typed is:
//! a paste is a keyboard, not an authority.
//!
//! What is deliberately absent is a signature. Freezing a definition is not
//! approving a plan: no envelope is built here, no native window is reached, and
//! the freeze travels by the ordinary session of the Console. The consent frame
//! of the assistant is not on this path at all.

use serde::{Deserialize, Serialize};
use your_cloud_bootstrap_protocol::{
    ServiceDefinitionDocument, ServiceDefinitionField, ServiceDefinitionFieldRefusal,
    ServiceDefinitionRefusal, MAX_SERVICE_DEFINITION_BYTES, ORIGIN_HOST_PLACEHOLDER,
    PRIVATE_SERVICE_EGRESS_TABLE, SERVICE_DEFINITION_SCHEMA_VERSION, SERVICE_LOCAL_ADDRESS,
};

/// The prefix of the account a slug derives, spelled here so the Console can
/// display the name before anything creates it.
///
/// It is the contract's derivation and the Auxiliary's, mirrored for display
/// only: this Console never sends an account name anywhere, no request of the
/// product carries one, and the machine re-derives it from the slug it verified.
/// A drift here would show a human the wrong name and could move nothing.
const USER_SERVICE_ACCOUNT_PREFIX: &str = "your-cloud-user-";
const USER_SERVICE_HOME_ROOT: &str = "/var/lib/";
const USER_SERVICE_VOLUMES_DIRECTORY: &str = "volumes";
const USER_SERVICE_SNAPSHOTS_DIRECTORY: &str = "snapshots";
const USER_SERVICE_SECRETS_DIRECTORY: &str = "secrets";
const USER_SERVICE_SECRETS_FILE: &str = "secrets.env";

/// The sysctl the sheet carries exactly when the image listens below this port,
/// and the port itself. The rule stopped being a constant per profile and became
/// a function of the document, so the Console reads it off the very field a
/// human is filling in.
const FIRST_UNPRIVILEGED_PORT: u32 = 1024;
const LOW_PORT_SYSCTL: &str = "Sysctl=net.ipv4.ip_unprivileged_port_start=0";

/// The egress table every confined account of a machine joins. It is a constant
/// of the palier and there is no field of any document that could turn it off.
///
/// It is the very constant the private profile named, because the table is one
/// table: the palier that added a second confined account made it multi-account
/// rather than adding a second table beside it.
const USER_SERVICE_EGRESS_TABLE: &str = PRIVATE_SERVICE_EGRESS_TABLE;

/// Bounds one paste before it is looked at.
///
/// It is twice the bound of a definition, because a compose document carries
/// several services and a definition carries one: a paste large enough to hold
/// what a human copied, and small enough that no parser here walks an
/// unbounded input. A larger paste is refused as a whole rather than truncated,
/// because a truncated compose document prefills a form from half a service.
const MAX_PASTE_BYTES: usize = 2 * MAX_SERVICE_DEFINITION_BYTES;

/// Bounds how many lines and how many tokens one paste may carry, so that every
/// walk below terminates on the input rather than on its own care.
const MAX_PASTE_LINES: usize = 512;
const MAX_PASTE_TOKENS: usize = 512;

/// Bounds how many names one note may carry back. A note that listed everything
/// would be a second document rather than a sentence.
const MAX_NOTE_SUBJECTS: usize = 8;

/// What a human filled in, before it is a definition.
///
/// It carries no `schema_version`: a Console writes the one version it knows,
/// and a draft that could name another would be a draft able to ask for a
/// document this palier does not read. Everything else is exactly the fields of
/// the contract, in its order, and nothing that touches a machine appears —
/// there is no account, no host path, no secret value and no infrastructure
/// here, because none of them is a field of the document either.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceDefinitionDraft {
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub image_repository: String,
    #[serde(default)]
    pub container_port: u32,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub tmpfs: Vec<String>,
    #[serde(default)]
    pub environment: Vec<String>,
    #[serde(default)]
    pub secret_keys: Vec<String>,
}

impl ServiceDefinitionDraft {
    /// The one place a draft becomes the document of the contract.
    fn document(&self) -> ServiceDefinitionDocument {
        ServiceDefinitionDocument {
            schema_version: SERVICE_DEFINITION_SCHEMA_VERSION,
            slug: self.slug.clone(),
            image_repository: self.image_repository.clone(),
            container_port: self.container_port,
            volumes: self.volumes.clone(),
            tmpfs: self.tmpfs.clone(),
            environment: self.environment.clone(),
            secret_keys: self.secret_keys.clone(),
        }
    }
}

/// What a review answers, in the two states a draft can be in.
///
/// It is an enumeration rather than a record with empty fields, so that a
/// caller cannot reach a document, a digest or a consequence line for a draft
/// the contract refuses: the freeze of this Console is written against the
/// ready form alone, and there is no shape in which a refused draft carries
/// something to submit.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum ServiceDefinitionReview {
    /// The draft is outside the contract, and every way it is, named on the
    /// field it belongs to.
    Refused {
        schema_version: u8,
        refusals: Vec<ServiceDefinitionFieldRefusal>,
    },
    /// The draft is a definition. What is carried is what would be frozen — the
    /// exact canonical bytes and their digest — and what a machine would later
    /// receive, in sentences.
    Ready {
        schema_version: u8,
        slug: String,
        definition_document: String,
        definition_sha256: String,
        /// Whether a deployment of this revision will require approving a name.
        interpolates_origin_host: bool,
        confirmation_lines: Vec<String>,
    },
}

/// Reads one draft against the contract, and says what freezing it would mean.
///
/// It contacts nothing and it freezes nothing: a review is a function of the
/// draft, and calling it twice on the same draft answers twice the same thing.
pub(crate) fn review_service_definition(draft: &ServiceDefinitionDraft) -> ServiceDefinitionReview {
    let document = draft.document();
    let refusals = document.refusals();
    if !refusals.is_empty() {
        return ServiceDefinitionReview::Refused {
            schema_version: 1,
            refusals,
        };
    }
    // The bytes and the digest come from the mirror, never from a rendering of
    // the form: what a human is shown, what would be frozen and what a digest
    // was taken over are one thing. The unreachable branch is written as the
    // refusal it would be rather than as a panic, because the one way it could
    // be reached is a document the mirror already names.
    let (Ok(definition_document), Ok(definition_sha256)) = (document.encode(), document.sha256())
    else {
        return ServiceDefinitionReview::Refused {
            schema_version: 1,
            refusals: vec![ServiceDefinitionFieldRefusal {
                field: ServiceDefinitionField::Document,
                entry: None,
                refusal: ServiceDefinitionRefusal::DocumentTooLarge,
            }],
        };
    };
    ServiceDefinitionReview::Ready {
        schema_version: 1,
        slug: document.slug.clone(),
        confirmation_lines: confirmation_lines(&document, &definition_sha256),
        interpolates_origin_host: document.interpolates_origin_host(),
        definition_document,
        definition_sha256,
    }
}

/// What the machine will receive, in the sentences a human approves.
///
/// It is the pattern of the approval windows of this product, applied to a
/// document that approves nothing yet: each line is a consequence rather than a
/// field, and the whole panel is reached before a freeze rather than after it.
/// The order is the order of the contract — what freezing does, then the
/// identity the slug derives, then the host paths, then the sheet, then the
/// egress, then what an archive of this service would hold — because that is the
/// order in which a reader learns that they decided none of it.
///
/// Two values are named as absent rather than left out: the digest of the image
/// and the local port belong to a plan and not to a definition, and a panel that
/// showed neither would let a reader believe a definition pins an image.
fn confirmation_lines(document: &ServiceDefinitionDocument, digest: &str) -> Vec<String> {
    let account = format!("{USER_SERVICE_ACCOUNT_PREFIX}{}", document.slug);
    let home = format!("{USER_SERVICE_HOME_ROOT}{account}");
    let data_root = format!("{home}/{USER_SERVICE_VOLUMES_DIRECTORY}");
    let mut lines = vec![
        format!("Service défini : {}", document.slug),
        format!("Révision à geler : {digest}"),
        "Ce que geler fait : le Controller garde ces octets sous cette empreinte. Aucun compte, \
         aucun répertoire, aucune fiche et aucun plan ne naît de ce gel, et aucune machine n’est \
         contactée."
            .to_owned(),
        "Ce que geler ne fait pas : déployer. Poser ce service sur une machine reste un plan \
         approuvé et signé à part, qui épingle cette révision par son empreinte."
            .to_owned(),
        format!(
            "Compte dérivé sur la machine : {account}, créé le jour où un plan de déploiement \
             approuvé pose ce service"
        ),
        format!("Foyer dérivé : {home}/"),
        format!("Dépôt d’image : {}", document.image_repository),
        format!(
            "Image exécutée : {}@<empreinte choisie par un plan> — une définition dit d’où les \
             images viennent, jamais laquelle",
            document.image_repository
        ),
    ];

    // The two lists of paths, each said as the mount it becomes. A volume is
    // named with the host directory it lands in, because that directory is the
    // whole of what survives the container; a tmpfs is named with what it loses.
    if document.volumes.is_empty() {
        lines.push(
            "Volumes : aucun. Ce service ne garde rien : ce qu’il écrit hors tmpfs disparaît avec \
             son conteneur, et il n’y a rien à archiver."
                .to_owned(),
        );
    } else {
        for path in &document.volumes {
            lines.push(format!(
                "Volume durable : {path} dans le conteneur, tenu sur la machine dans \
                 {data_root}{path}"
            ));
        }
    }
    for path in &document.tmpfs {
        lines.push(format!(
            "Brouillon en mémoire : {path}, monté en tmpfs et perdu à chaque arrêt du conteneur"
        ));
    }

    // The sheet, line for line as the machine writes it. The four hardening
    // lines are constants of the product rather than choices of the document,
    // and they are displayed for that very reason: a human must be able to read
    // that they were not asked.
    lines.push(format!(
        "Ligne de la fiche : PublishPort={SERVICE_LOCAL_ADDRESS}:<port local choisi par un \
         plan>:{} — le service n’écoute que sur la boucle locale de sa machine",
        document.container_port
    ));
    for hardening in [
        "Pull=never",
        "ReadOnly=true",
        "NoNewPrivileges=true",
        "DropCapability=ALL",
    ] {
        lines.push(format!("Ligne de la fiche : {hardening}"));
    }
    for line in &document.environment {
        lines.push(format!("Ligne de la fiche : Environment={line}"));
    }
    for path in &document.tmpfs {
        lines.push(format!("Ligne de la fiche : Tmpfs={path}:rw,mode=1777"));
    }
    if !document.secret_keys.is_empty() {
        lines.push(format!(
            "Ligne de la fiche : EnvironmentFile={home}/{USER_SERVICE_SECRETS_FILE}"
        ));
    }
    if document.container_port < FIRST_UNPRIVILEGED_PORT {
        lines.push(format!(
            "Ligne de la fiche : {LOW_PORT_SYSCTL} — le port déclaré est inférieur à \
             {FIRST_UNPRIVILEGED_PORT}, et le contrôle est borné à l’espace de noms du conteneur"
        ));
    }

    // The origin is a presence rather than a value at this stage, and saying so
    // here is what keeps the later approval from being a surprise.
    if document.interpolates_origin_host() {
        lines.push(format!(
            "Origine : une ligne au moins nomme {ORIGIN_HOST_PLACEHOLDER}. Le plan qui déploiera \
             cette révision devra porter un nom, et ce nom sera sous vos yeux avant d’être approuvé."
        ));
    } else {
        lines.push(format!(
            "Origine : aucune ligne ne nomme {ORIGIN_HOST_PLACEHOLDER}. Un plan qui porterait \
             malgré tout une origine serait refusé, parce qu’aucune ligne ne la consommerait."
        ));
    }

    // The secrets, said as names and never as values, and said with what a
    // redeployment does to them — which is the question a human actually has.
    if document.secret_keys.is_empty() {
        lines.push(
            "Secrets : aucun. La machine ne génère aucune valeur pour ce service.".to_owned(),
        );
    } else {
        for key in &document.secret_keys {
            lines.push(format!(
                "Secret généré sur la machine : {key}, écrit dans \
                 {home}/{USER_SERVICE_SECRETS_DIRECTORY}/{key} en 0600. La valeur ne quitte jamais \
                 la machine et n’entre dans aucun document."
            ));
        }
        lines.push(
            "Redéploiement : une clé dont le fichier existe garde sa valeur ; seule une clé \
             nouvelle en reçoit une. Rien ne détruit une valeur générée."
                .to_owned(),
        );
    }

    lines.push(format!(
        "Confinement de sortie : le compte rejoint la table {USER_SERVICE_EGRESS_TABLE}. Ce \
         service ne parle à personne : sortie refusée hors boucle locale et réponses établies, et \
         aucun champ d’aucun document ne peut y percer un trou."
    ));

    // What a future archive would hold, said now rather than at the moment an
    // archive is approved: the volumes root entire, the secrets outside it.
    if document.volumes.is_empty() {
        lines.push(
            "Instantané futur : rien à archiver. Une définition sans volume n’a pas de racine de \
             données, et une opération d’archive qui la nommerait serait refusée sur la machine."
                .to_owned(),
        );
    } else {
        lines.push(format!(
            "Instantané futur : {data_root}/ entier, en une seule archive cohérente prise service \
             arrêté, déposée dans {home}/{USER_SERVICE_SNAPSHOTS_DIRECTORY}/ que root seul détient."
        ));
        lines.push(
            "Ce qu’un instantané ne contient pas : les secrets générés. Ils vivent à côté de la \
             racine archivée, et un retour ne les touche pas."
                .to_owned(),
        );
    }

    // The one consequence of a revision that surprises, said before it can.
    lines.push(
        "Révision suivante : renommer un chemin conteneur monte un répertoire neuf et vide. \
         L’ancien sous-arbre survit sous le foyer ; le déplacer vous appartient, et ce produit ne \
         l’infère jamais."
            .to_owned(),
    );
    lines.push(format!("Empreinte de la définition : {digest}"));
    lines
}

// --------------------------------------------------------------------------
// The paste, which can only prefill.

/// What a paste was read as. `Unrecognised` is a state and not an error: the
/// form keeps whatever it already held, and nothing is prefilled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PasteSource {
    ContainerCommand,
    ComposeDocument,
    Unrecognised,
}

/// Why a paste did not carry something into the form, as a closed list of named
/// notes.
///
/// A closed list rather than a message, for the reason the refusals of the
/// mirror are one: the sentence a human reads is written where this product
/// speaks to humans, and a name without its sentence is a hole a caller can be
/// held against.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PasteNoteName {
    /// Neither a container command nor a compose document.
    NothingRecognised,
    /// Above the paste bound, refused whole rather than read in part.
    PasteTooLarge,
    /// A compose document declared several services; one prefilled the form and
    /// the others are named.
    SingleServiceOnly,
    /// A tag or a digest was dropped from the repository: a definition says
    /// where images come from, a plan says which one runs.
    ImagePinDropped,
    /// Host paths and host ports were dropped: the machine derives the first
    /// and a plan decides the second.
    HostSideDropped,
    /// Directives a definition has no field for were dropped, and named.
    UnsupportedDirectiveDropped,
    /// Environment entries the definition's grammar cannot carry were dropped,
    /// and named.
    EnvironmentEntryDropped,
    /// No image was found, so the field a definition cannot do without is empty.
    NoImageFound,
}

/// One note, and the names it is about.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PasteNote {
    pub note: PasteNoteName,
    pub subjects: Vec<String>,
}

/// What a paste answers: a draft to review, and what was dropped on the way.
///
/// There is deliberately no digest, no document and no freeze here. A paste
/// produces a draft and a draft is reviewed by the same function a typed one is;
/// nothing in this answer can be submitted, and the frontend has nothing to
/// submit it with.
#[derive(Debug, Serialize)]
pub(crate) struct ServiceDefinitionPaste {
    pub schema_version: u8,
    pub source: PasteSource,
    pub draft: ServiceDefinitionDraft,
    pub notes: Vec<PasteNote>,
}

/// Reads one paste into a draft, locally and purely.
///
/// It opens nothing, runs nothing and writes nothing. Every value it produces is
/// held against the mirror afterwards, exactly as a value a human typed is:
/// this function is a keyboard.
pub(crate) fn parse_service_definition_paste(pasted: &str) -> ServiceDefinitionPaste {
    let mut notes = Notes::default();
    if pasted.len() > MAX_PASTE_BYTES || pasted.lines().count() > MAX_PASTE_LINES {
        notes.add(PasteNoteName::PasteTooLarge, None);
        return unrecognised(notes);
    }
    if let Some(paste) = parse_compose_document(pasted, &mut notes) {
        return paste;
    }
    if let Some(paste) = parse_container_command(pasted, &mut notes) {
        return paste;
    }
    notes.add(PasteNoteName::NothingRecognised, None);
    unrecognised(notes)
}

fn unrecognised(notes: Notes) -> ServiceDefinitionPaste {
    ServiceDefinitionPaste {
        schema_version: 1,
        source: PasteSource::Unrecognised,
        draft: ServiceDefinitionDraft::default(),
        notes: notes.into_vec(),
    }
}

/// Collects the notes of one paste, one entry per name, with its subjects.
#[derive(Default)]
struct Notes {
    entries: Vec<PasteNote>,
}

impl Notes {
    fn add(&mut self, note: PasteNoteName, subject: Option<&str>) {
        let entry = match self.entries.iter_mut().find(|entry| entry.note == note) {
            Some(entry) => entry,
            None => {
                self.entries.push(PasteNote {
                    note,
                    subjects: Vec::new(),
                });
                self.entries.last_mut().expect("a note was just pushed")
            }
        };
        let Some(subject) = subject else { return };
        let subject = bounded_subject(subject);
        if entry.subjects.len() < MAX_NOTE_SUBJECTS && !entry.subjects.contains(&subject) {
            entry.subjects.push(subject);
        }
    }

    fn into_vec(self) -> Vec<PasteNote> {
        self.entries
    }
}

/// Bounds one name a note carries back, because a subject is a word of the
/// paste and a paste is a third party's bytes.
fn bounded_subject(subject: &str) -> String {
    subject.chars().take(64).collect()
}

// --------------------------------------------------------------------------
// A container command.

/// The long options of `docker run` and `podman run` that consume the token
/// after them. It exists so that the image is the first token that is really
/// positional: an option whose value looked like an image would otherwise
/// prefill the field a definition cannot do without.
const VALUE_TAKING_OPTIONS: [&str; 30] = [
    "--publish",
    "--expose",
    "--volume",
    "--mount",
    "--tmpfs",
    "--env",
    "--env-file",
    "--name",
    "--network",
    "--restart",
    "--user",
    "--workdir",
    "--entrypoint",
    "--hostname",
    "--label",
    "--memory",
    "--cpus",
    "--device",
    "--sysctl",
    "--ulimit",
    "--cap-add",
    "--cap-drop",
    "--security-opt",
    "--pull",
    "--platform",
    "--add-host",
    "--dns",
    "--log-driver",
    "--health-cmd",
    "--volumes-from",
];

/// The short options that consume the token after them.
const VALUE_TAKING_SHORT_OPTIONS: [&str; 7] = ["-p", "-v", "-e", "-w", "-h", "-m", "-u"];

/// The options that change what a service is allowed to do and have no field in
/// a definition. They are named back rather than dropped in silence, because a
/// human who pasted `--network host` must not believe it was carried.
const REFUSED_OPTIONS: [&str; 12] = [
    "--network",
    "--restart",
    "--privileged",
    "--cap-add",
    "--device",
    "--sysctl",
    "--user",
    "--entrypoint",
    "--add-host",
    "--dns",
    "--security-opt",
    "--volumes-from",
];

fn parse_container_command(pasted: &str, notes: &mut Notes) -> Option<ServiceDefinitionPaste> {
    let tokens = tokenise_command(pasted)?;
    let mut index = position_of_run(&tokens)? + 1;
    let mut draft = ServiceDefinitionDraft::default();
    let mut name: Option<String> = None;
    let mut published: Option<u32> = None;
    let mut exposed: Option<u32> = None;

    while index < tokens.len() {
        let token = tokens[index].clone();
        index += 1;
        if !token.starts_with('-') {
            // The first positional token is the image; everything after it is
            // the command the image would run, which a definition cannot carry.
            let (repository, pinned) = repository_of(&token);
            draft.image_repository = repository;
            if pinned {
                notes.add(PasteNoteName::ImagePinDropped, Some(&token));
            }
            if index < tokens.len() {
                notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some("command"));
            }
            break;
        }
        let (option, inline) = match token.split_once('=') {
            Some((option, value)) if option.starts_with("--") => {
                (option.to_owned(), Some(value.to_owned()))
            }
            _ => (token.clone(), None),
        };
        let value = match inline {
            Some(value) => Some(value),
            None if VALUE_TAKING_OPTIONS.contains(&option.as_str())
                || VALUE_TAKING_SHORT_OPTIONS.contains(&option.as_str()) =>
            {
                let value = tokens.get(index).cloned();
                index += 1;
                value
            }
            None => None,
        };
        if REFUSED_OPTIONS.contains(&option.as_str()) {
            notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some(&option));
            continue;
        }
        let Some(value) = value else { continue };
        match option.as_str() {
            "-p" | "--publish" => {
                if let Some(port) = container_port_of_mapping(&value) {
                    published = Some(port);
                    if value.contains(':') {
                        notes.add(PasteNoteName::HostSideDropped, Some(&value));
                    }
                }
            }
            "--expose" => exposed = exposed.or_else(|| container_port_of_mapping(&value)),
            "-v" | "--volume" => match container_path_of_mount(&value) {
                Some(path) => {
                    if value.contains(':') {
                        notes.add(PasteNoteName::HostSideDropped, Some(&value));
                    }
                    draft.volumes.push(path);
                }
                None => notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some(&value)),
            },
            "--mount" => notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some("--mount")),
            "--tmpfs" => match container_path_of_mount(&value) {
                Some(path) => draft.tmpfs.push(path),
                None => notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some(&value)),
            },
            "-e" | "--env" => {
                if value.contains('=') {
                    draft.environment.push(value);
                } else {
                    // `-e KEY` asks the daemon to copy a value out of the shell
                    // that ran the command. There is no such value here, and
                    // inventing one would be inventing configuration.
                    notes.add(PasteNoteName::EnvironmentEntryDropped, Some(&value));
                }
            }
            "--env-file" => notes.add(PasteNoteName::EnvironmentEntryDropped, Some(&value)),
            "--name" => name = Some(value),
            _ => {}
        }
    }

    if draft.image_repository.is_empty() {
        notes.add(PasteNoteName::NoImageFound, None);
    }
    draft.container_port = published.or(exposed).unwrap_or_default();
    draft.slug = suggested_slug(name.as_deref(), &draft.image_repository);
    Some(ServiceDefinitionPaste {
        schema_version: 1,
        source: PasteSource::ContainerCommand,
        draft,
        notes: std::mem::take(notes).into_vec(),
    })
}

/// Splits a pasted command into tokens, honouring the three things a human
/// really copies: line continuations, single quotes and double quotes.
///
/// It is a splitter and never an evaluator: no substitution, no expansion, no
/// escape beyond a backslash before a newline, and an unterminated quote ends
/// the token at the end of the paste rather than reaching for more input.
fn tokenise_command(pasted: &str) -> Option<Vec<String>> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut characters = pasted.chars().peekable();
    while let Some(character) = characters.next() {
        if tokens.len() > MAX_PASTE_TOKENS {
            return None;
        }
        match character {
            '\\' if quote.is_none() => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                } else if let Some(escaped) = characters.next() {
                    current.push(escaped);
                }
            }
            '\'' | '"' if quote.is_none() => quote = Some(character),
            character if Some(character) == quote => quote = None,
            character if quote.is_none() && character.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Some(tokens)
}

/// Finds the `run` of a container command, and refuses everything else.
///
/// A paste is read as a command only when a container engine is named and asked
/// to run something. `docker build`, `kubectl apply` and a line of prose are all
/// answered by the same "nothing recognised" rather than by a form filled from
/// half a guess.
fn position_of_run(tokens: &[String]) -> Option<usize> {
    tokens
        .iter()
        .position(|token| token == "run" || token == "create")
        .filter(|position| {
            tokens[..*position]
                .iter()
                .any(|token| matches!(token.as_str(), "docker" | "podman" | "nerdctl"))
        })
}

/// The container side of a published port, in the three spellings that exist.
///
/// `8080`, `8080:80` and `127.0.0.1:8080:80` all name one container port — the
/// last field — and a protocol suffix is dropped because a definition declares a
/// port and not a protocol.
fn container_port_of_mapping(mapping: &str) -> Option<u32> {
    let last = mapping.rsplit(':').next()?;
    let port = last.split('/').next()?;
    port.parse::<u32>().ok().filter(|port| *port > 0)
}

/// The container side of a mount, which is the only side a definition has.
///
/// `/srv/data`, `./data:/srv/data` and `notes:/srv/data:rw` all name one
/// container path. A host path is dropped rather than carried: the machine
/// derives where the data lives, and no field of a definition could move it.
fn container_path_of_mount(mount: &str) -> Option<String> {
    let fields: Vec<&str> = mount.split(':').collect();
    let candidate = match fields.len() {
        1 => fields[0],
        _ => fields[1],
    };
    candidate
        .starts_with('/')
        .then(|| candidate.trim_end_matches('/').to_owned())
        .filter(|path| path.len() > 1)
}

/// Where the images come from, out of a reference that names which one.
///
/// The tag and the digest are removed here rather than refused, because
/// removing them is exactly what turns a reference a human pulls with into the
/// repository a definition declares — and the note says it happened.
fn repository_of(reference: &str) -> (String, bool) {
    let without_digest = reference.split_once('@').map(|(head, _)| head);
    let pinned_by_digest = without_digest.is_some();
    let reference = without_digest.unwrap_or(reference);
    let (head, last) = match reference.rsplit_once('/') {
        Some((head, last)) => (Some(head), last),
        None => (None, reference),
    };
    let (last, pinned_by_tag) = match last.split_once(':') {
        Some((last, _)) => (last, true),
        None => (last, false),
    };
    let repository = match head {
        Some(head) => format!("{head}/{last}"),
        None => last.to_owned(),
    };
    (repository, pinned_by_digest || pinned_by_tag)
}

/// A slug the form opens on, out of the name a paste gave or out of the
/// repository it named.
///
/// It is a suggestion and never a verdict: the mirror decides whether it is a
/// slug, the human decides whether it is the right one, and a suggestion that
/// the grammar refuses is displayed as refused like any other.
fn suggested_slug(name: Option<&str>, repository: &str) -> String {
    let source = name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| repository.rsplit('/').next().unwrap_or_default());
    let mut slug = String::new();
    for character in source.chars() {
        if slug.len() == 16 {
            break;
        }
        let character = character.to_ascii_lowercase();
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            slug.push(character);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_end_matches('-').to_owned()
}

// --------------------------------------------------------------------------
// A compose document.

/// The keys of one compose service this reader carries into a draft. Every
/// other key is named back as a directive a definition has no field for.
const COMPOSE_CARRIED_KEYS: [&str; 6] = [
    "image",
    "ports",
    "expose",
    "volumes",
    "tmpfs",
    "environment",
];

/// The keys of one compose service this reader drops without a word, because
/// they say nothing about what the service is: they are the shape of a compose
/// file rather than a property of the application.
const COMPOSE_SILENT_KEYS: [&str; 5] = [
    "container_name",
    "restart",
    "depends_on",
    "healthcheck",
    "labels",
];

/// Reads the subset of a compose document a definition can hold.
///
/// It is a bounded reader of an indented mapping and never a YAML
/// implementation: anchors, aliases, multi-line scalars, flow mappings and tabs
/// are not read, and a document that needs one of them is answered by the notes
/// rather than by a guess. What it does read is what a human really pastes — a
/// `services:` mapping with an image, ports, volumes, tmpfs and environment.
///
/// **One service prefills the form, and the reader says so.** The contract names
/// "un conteneur par service" as a limit of the palier, so a multi-service
/// compose is not an error: it is a document from which exactly one service can
/// be carried, and the others are named back.
fn parse_compose_document(pasted: &str, notes: &mut Notes) -> Option<ServiceDefinitionPaste> {
    let lines = compose_lines(pasted)?;
    let services_at = lines
        .iter()
        .position(|line| line.indent == 0 && line.key.as_deref() == Some("services"))?;
    let service_indent = lines
        .get(services_at + 1)
        .filter(|line| line.indent > 0)?
        .indent;
    let mut names: Vec<(usize, String)> = Vec::new();
    for (position, line) in lines.iter().enumerate().skip(services_at + 1) {
        if line.indent == 0 {
            break;
        }
        if line.indent == service_indent {
            if let Some(key) = &line.key {
                names.push((position, key.clone()));
            }
        }
    }
    let (first_at, first_name) = names.first().cloned()?;
    for (_, ignored) in names.iter().skip(1) {
        notes.add(PasteNoteName::SingleServiceOnly, Some(ignored));
    }
    if names.len() > 1 {
        notes.add(PasteNoteName::SingleServiceOnly, Some(&first_name));
    }

    let end = names
        .get(1)
        .map(|(position, _)| *position)
        .unwrap_or(lines.len());
    let body = &lines[first_at + 1..end];
    let mut draft = ServiceDefinitionDraft::default();
    let mut published: Option<u32> = None;
    let mut exposed: Option<u32> = None;
    let key_indent = body.first().map(|line| line.indent).unwrap_or(usize::MAX);

    for (position, line) in body.iter().enumerate() {
        if line.indent != key_indent {
            continue;
        }
        let Some(key) = line.key.clone() else {
            continue;
        };
        if COMPOSE_SILENT_KEYS.contains(&key.as_str()) {
            continue;
        }
        if !COMPOSE_CARRIED_KEYS.contains(&key.as_str()) {
            notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some(&key));
            continue;
        }
        let values = compose_values(body, position, key_indent, line.value.as_deref());
        match key.as_str() {
            "image" => {
                if let Some(reference) = values.first() {
                    let (repository, pinned) = repository_of(reference);
                    draft.image_repository = repository;
                    if pinned {
                        notes.add(PasteNoteName::ImagePinDropped, Some(reference));
                    }
                }
            }
            "ports" => {
                for value in &values {
                    if let Some(port) = container_port_of_mapping(value) {
                        published = published.or(Some(port));
                        if value.contains(':') {
                            notes.add(PasteNoteName::HostSideDropped, Some(value));
                        }
                    }
                }
            }
            "expose" => {
                for value in &values {
                    exposed = exposed.or_else(|| container_port_of_mapping(value));
                }
            }
            "volumes" => {
                for value in &values {
                    match container_path_of_mount(value) {
                        Some(path) => {
                            if value.contains(':') {
                                notes.add(PasteNoteName::HostSideDropped, Some(value));
                            }
                            draft.volumes.push(path);
                        }
                        None => {
                            notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some(value));
                        }
                    }
                }
            }
            "tmpfs" => {
                for value in &values {
                    match container_path_of_mount(value) {
                        Some(path) => draft.tmpfs.push(path),
                        None => notes.add(PasteNoteName::UnsupportedDirectiveDropped, Some(value)),
                    }
                }
            }
            "environment" => {
                for value in &values {
                    if value.contains('=') {
                        draft.environment.push(value.clone());
                    } else {
                        notes.add(PasteNoteName::EnvironmentEntryDropped, Some(value));
                    }
                }
            }
            _ => {}
        }
    }

    if draft.image_repository.is_empty() {
        notes.add(PasteNoteName::NoImageFound, None);
    }
    draft.container_port = published.or(exposed).unwrap_or_default();
    draft.slug = suggested_slug(Some(&first_name), &draft.image_repository);
    Some(ServiceDefinitionPaste {
        schema_version: 1,
        source: PasteSource::ComposeDocument,
        draft,
        notes: std::mem::take(notes).into_vec(),
    })
}

/// One significant line of a compose document, reduced to what this reader
/// understands: how deep it sits, the key it opens if it opens one, and the
/// scalar or list item it carries.
struct ComposeLine {
    indent: usize,
    key: Option<String>,
    value: Option<String>,
    item: Option<String>,
}

/// Splits a compose document into those lines, and refuses the shapes this
/// reader does not read rather than misreading them.
///
/// A tab in the indentation is refused outright: YAML forbids it, and a reader
/// that guessed a width would be inventing a structure. Comments and blank
/// lines are dropped, and a trailing comment is not: a `#` inside a value is a
/// legitimate byte of that value.
fn compose_lines(pasted: &str) -> Option<Vec<ComposeLine>> {
    let mut lines = Vec::new();
    for raw in pasted.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if raw[..indent].contains('\t') {
            return None;
        }
        if let Some(item) = trimmed.strip_prefix("- ") {
            lines.push(ComposeLine {
                indent,
                key: None,
                value: None,
                item: Some(unquoted(item).to_owned()),
            });
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            return None;
        };
        let value = value.trim();
        lines.push(ComposeLine {
            indent,
            key: Some(key.trim().to_owned()),
            value: (!value.is_empty()).then(|| unquoted(value).to_owned()),
            item: None,
        });
    }
    (!lines.is_empty()).then_some(lines)
}

/// The values one key carries: its inline scalar, or the list items and mapping
/// entries indented beneath it.
///
/// An environment written as a mapping (`KEY: value`) and an environment written
/// as a list (`- KEY=value`) describe the same thing, so both are returned in
/// the one spelling a definition has.
fn compose_values(
    body: &[ComposeLine],
    position: usize,
    key_indent: usize,
    inline: Option<&str>,
) -> Vec<String> {
    if let Some(inline) = inline {
        return vec![inline.to_owned()];
    }
    let mut values = Vec::new();
    for line in body.iter().skip(position + 1) {
        if line.indent <= key_indent {
            break;
        }
        if let Some(item) = &line.item {
            values.push(item.clone());
        } else if let Some(key) = &line.key {
            match &line.value {
                Some(value) => values.push(format!("{key}={value}")),
                None => values.push(key.clone()),
            }
        }
    }
    values
}

/// Removes the one pair of quotes a compose scalar may carry, and nothing else.
fn unquoted(value: &str) -> &str {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// Reads one document back from the bytes a Controller returned, and refuses
/// bytes that are not the definition their digest names.
///
/// It is the mirror's own verification rather than a second reading of it, and
/// it is applied to every entry of every listing: what a human is shown is a
/// definition this Console rehashed, so a Controller that altered one byte of a
/// frozen revision is caught by the Console before it is displayed and not only
/// by the Auxiliary the day a plan pins it.
pub(crate) fn displayable_definition(
    document: &str,
    digest: &str,
) -> Option<ServiceDefinitionDocument> {
    your_cloud_bootstrap_protocol::verify_service_definition_document(document.as_bytes(), digest)
        .ok()
        .filter(|parsed| parsed.encode().is_ok_and(|canonical| canonical == document))
}

/// One frozen revision as the Console displays it: the bytes, the digest, the
/// date, and the fields those bytes parse to.
///
/// The fields are parsed here rather than in the frontend, and that is a
/// decision rather than a convenience: the canonical document is the object a
/// digest was taken over, so a second parser — in another language, with another
/// notion of what a duplicate key or a trailing byte is — would be a second
/// reading of the one thing this product hashes. What the frontend renders is
/// what the mirror read.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct FrozenDefinitionView {
    pub slug: String,
    pub definition_sha256: String,
    pub frozen_at: String,
    pub definition_document: String,
    pub document: ServiceDefinitionDocument,
    pub interpolates_origin_host: bool,
}

/// Projects one frozen entry, and refuses one whose bytes are not the definition
/// its digest names.
pub(crate) fn frozen_definition_view(
    slug: &str,
    document: &str,
    digest: &str,
    frozen_at: &str,
) -> Option<FrozenDefinitionView> {
    let parsed = displayable_definition(document, digest)?;
    if parsed.slug != slug {
        return None;
    }
    Some(FrozenDefinitionView {
        slug: parsed.slug.clone(),
        definition_sha256: digest.to_owned(),
        frozen_at: frozen_at.to_owned(),
        definition_document: document.to_owned(),
        interpolates_origin_host: parsed.interpolates_origin_host(),
        document: parsed,
    })
}

/// The frozen definitions of one infrastructure, as one view.
///
/// There is no instance here, and the absence is the state of the product rather
/// than an omission of this projection: nothing between the Controller and this
/// Console projects which machine runs which revision, so a field for it would
/// be a field nothing could fill honestly.
#[derive(Debug, Serialize)]
pub(crate) struct ServiceDefinitionsProjection {
    pub schema_version: u8,
    pub definition_revision: u64,
    pub definitions: Vec<FrozenDefinitionView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_draft() -> ServiceDefinitionDraft {
        ServiceDefinitionDraft {
            slug: "lab-notes".into(),
            image_repository: "registry.lab.your-cloud.test/your-cloud/lab-notes".into(),
            container_port: 8_080,
            volumes: vec!["/srv/notes".into(), "/var/lib/lab-notes".into()],
            tmpfs: vec!["/tmp".into()],
            environment: vec![
                "LAB_NOTES_TITLE=Your Cloud lab notes".into(),
                "LAB_NOTES_ORIGIN=https://{origin_host}/".into(),
            ],
            secret_keys: vec!["LAB_NOTES_ADMIN_TOKEN".into()],
        }
    }

    fn ready_lines(draft: &ServiceDefinitionDraft) -> Vec<String> {
        match review_service_definition(draft) {
            ServiceDefinitionReview::Ready {
                confirmation_lines, ..
            } => confirmation_lines,
            other => panic!("the draft was refused: {other:?}"),
        }
    }

    /// A review is the mirror's verdict, and the bytes it carries are the
    /// mirror's bytes.
    ///
    /// The digest is held against the deterministic vector the two
    /// implementations of the encoding pin, so a Console that displayed one
    /// spelling and froze another fails here rather than on a machine.
    #[test]
    fn a_ready_review_carries_the_exact_bytes_a_freeze_would_send() {
        let draft = ServiceDefinitionDraft {
            environment: vec![
                "LAB_NOTES_TITLE=Your Cloud lab notes".into(),
                "LAB_NOTES_ORIGIN=https://{origin_host}/".into(),
                "LAB_NOTES_READ_ONLY=1".into(),
            ],
            ..reference_draft()
        };
        let ServiceDefinitionReview::Ready {
            definition_document,
            definition_sha256,
            interpolates_origin_host,
            slug,
            ..
        } = review_service_definition(&draft)
        else {
            panic!("the reference definition is inside the contract")
        };
        assert_eq!(slug, "lab-notes");
        assert!(interpolates_origin_host);
        assert_eq!(
            definition_sha256,
            "c0f30d7c7f8635d2fb56445d7b75c6523b440d35de8e1867444c788e4b30f3ce"
        );
        assert!(definition_document.starts_with(r#"{"schema_version":1,"slug":"lab-notes""#));
        // And the bytes a freeze would send are bytes the mirror verifies under
        // the digest that was displayed beside them.
        assert!(displayable_definition(&definition_document, &definition_sha256).is_some());
    }

    /// A draft outside the contract carries no document, no digest and no
    /// consequence line — there is no shape in which it could.
    #[test]
    fn a_refused_review_carries_nothing_that_could_be_frozen() {
        let refused = review_service_definition(&ServiceDefinitionDraft {
            slug: "vaultwarden".into(),
            ..reference_draft()
        });
        let ServiceDefinitionReview::Refused { refusals, .. } = refused else {
            panic!("a reserved slug is refused")
        };
        assert_eq!(refusals.len(), 1);
        assert_eq!(
            refusals[0].refusal,
            your_cloud_bootstrap_protocol::ServiceDefinitionRefusal::SlugReserved
        );
    }

    /// The panel names every consequence the contract derives from the slug and
    /// from the lists, and names the two values a definition does not decide.
    #[test]
    fn the_panel_names_what_the_machine_will_receive() {
        let lines = ready_lines(&reference_draft()).join("\n");
        for expected in [
            "Compte dérivé sur la machine : your-cloud-user-lab-notes",
            "Foyer dérivé : /var/lib/your-cloud-user-lab-notes/",
            "Volume durable : /srv/notes dans le conteneur, tenu sur la machine dans \
             /var/lib/your-cloud-user-lab-notes/volumes/srv/notes",
            "Volume durable : /var/lib/lab-notes dans le conteneur, tenu sur la machine dans \
             /var/lib/your-cloud-user-lab-notes/volumes/var/lib/lab-notes",
            "Brouillon en mémoire : /tmp",
            "Ligne de la fiche : Pull=never",
            "Ligne de la fiche : ReadOnly=true",
            "Ligne de la fiche : NoNewPrivileges=true",
            "Ligne de la fiche : DropCapability=ALL",
            "Ligne de la fiche : Tmpfs=/tmp:rw,mode=1777",
            "Ligne de la fiche : EnvironmentFile=/var/lib/your-cloud-user-lab-notes/secrets.env",
            "Secret généré sur la machine : LAB_NOTES_ADMIN_TOKEN",
            "table inet your-cloud-egress",
            "Instantané futur : /var/lib/your-cloud-user-lab-notes/volumes/ entier",
            "Ce qu’un instantané ne contient pas : les secrets générés",
        ] {
            assert!(lines.contains(expected), "the panel never says: {expected}");
        }
        // The two values a plan decides are named as belonging to a plan, and
        // the panel never invents one.
        assert!(lines.contains("<empreinte choisie par un plan>"));
        assert!(lines.contains("<port local choisi par un plan>"));
        // A port above the bound carries no sysctl at all: a control that grants
        // nothing reads as a control that was needed.
        assert!(!lines.contains(LOW_PORT_SYSCTL));
    }

    /// The three shapes the panel changes for, said rather than left out.
    #[test]
    fn the_panel_says_the_absences_as_plainly_as_the_presences() {
        let bare = ready_lines(&ServiceDefinitionDraft {
            container_port: 80,
            volumes: Vec::new(),
            tmpfs: Vec::new(),
            environment: Vec::new(),
            secret_keys: Vec::new(),
            ..reference_draft()
        })
        .join("\n");
        assert!(bare.contains("Volumes : aucun"));
        assert!(bare.contains("Instantané futur : rien à archiver"));
        assert!(bare.contains("Secrets : aucun"));
        assert!(bare.contains(LOW_PORT_SYSCTL));
        assert!(!bare.contains("EnvironmentFile="));
        assert!(bare.contains(&format!(
            "Origine : aucune ligne ne nomme {ORIGIN_HOST_PLACEHOLDER}"
        )));

        let interpolating = ready_lines(&reference_draft()).join("\n");
        assert!(interpolating.contains("Le plan qui déploiera cette révision devra porter un nom"));
    }

    /// A paste prefills and does nothing else: what comes back is a draft, and a
    /// draft has to be reviewed like any other.
    #[test]
    fn a_container_command_prefills_the_form_and_names_what_it_dropped() {
        let paste = parse_service_definition_paste(
            "docker run -d --name lab-notes \\\n  -p 127.0.0.1:8080:8080 \\\n  \
             -v /opt/data:/srv/notes \\\n  --tmpfs /tmp \\\n  -e LAB_NOTES_TITLE=Notes \\\n  \
             -e SHELL_VALUE \\\n  --network host \\\n  \
             registry.lab.your-cloud.test/your-cloud/lab-notes:1.4",
        );
        assert_eq!(paste.source, PasteSource::ContainerCommand);
        assert_eq!(paste.draft.slug, "lab-notes");
        assert_eq!(
            paste.draft.image_repository,
            "registry.lab.your-cloud.test/your-cloud/lab-notes"
        );
        assert_eq!(paste.draft.container_port, 8_080);
        assert_eq!(paste.draft.volumes, vec!["/srv/notes".to_owned()]);
        assert_eq!(paste.draft.tmpfs, vec!["/tmp".to_owned()]);
        assert_eq!(
            paste.draft.environment,
            vec!["LAB_NOTES_TITLE=Notes".to_owned()]
        );
        // Nothing is generated for a secret: a definition names keys, and a
        // paste has no way of naming one.
        assert!(paste.draft.secret_keys.is_empty());
        let names: Vec<PasteNoteName> = paste.notes.iter().map(|note| note.note).collect();
        for expected in [
            PasteNoteName::ImagePinDropped,
            PasteNoteName::HostSideDropped,
            PasteNoteName::UnsupportedDirectiveDropped,
            PasteNoteName::EnvironmentEntryDropped,
        ] {
            assert!(names.contains(&expected), "{expected:?} was never named");
        }
        assert!(paste
            .notes
            .iter()
            .find(|note| note.note == PasteNoteName::UnsupportedDirectiveDropped)
            .is_some_and(|note| note.subjects.contains(&"--network".to_owned())));
    }

    /// A compose document with several services prefills from one and says so.
    #[test]
    fn a_compose_document_prefills_from_one_service_and_names_the_others() {
        let paste = parse_service_definition_paste(
            "version: \"3\"\nservices:\n  web:\n    image: \
             registry.lab.your-cloud.test/your-cloud/lab-notes:1.4\n    ports:\n      \
             - \"8080:8080\"\n    volumes:\n      - notes:/srv/notes\n    tmpfs:\n      \
             - /tmp\n    environment:\n      LAB_NOTES_TITLE: Notes\n    restart: always\n    \
             networks:\n      - back\n  db:\n    image: registry.lab.your-cloud.test/postgres\n",
        );
        assert_eq!(paste.source, PasteSource::ComposeDocument);
        assert_eq!(paste.draft.slug, "web");
        assert_eq!(
            paste.draft.image_repository,
            "registry.lab.your-cloud.test/your-cloud/lab-notes"
        );
        assert_eq!(paste.draft.container_port, 8_080);
        assert_eq!(paste.draft.volumes, vec!["/srv/notes".to_owned()]);
        assert_eq!(paste.draft.tmpfs, vec!["/tmp".to_owned()]);
        assert_eq!(
            paste.draft.environment,
            vec!["LAB_NOTES_TITLE=Notes".to_owned()]
        );
        let single = paste
            .notes
            .iter()
            .find(|note| note.note == PasteNoteName::SingleServiceOnly)
            .expect("a multi-service document says only one service prefilled");
        assert!(single.subjects.contains(&"db".to_owned()));
        assert!(single.subjects.contains(&"web".to_owned()));
        assert!(paste
            .notes
            .iter()
            .find(|note| note.note == PasteNoteName::UnsupportedDirectiveDropped)
            .is_some_and(|note| note.subjects.contains(&"networks".to_owned())));
    }

    /// Everything else is recognised as nothing, and prefills nothing.
    #[test]
    fn a_paste_that_is_not_one_of_the_two_shapes_fills_nothing() {
        for (name, pasted) in [
            ("prose", "Bonjour, voici mon application préférée."),
            ("another command", "kubectl apply -f deployment.yaml"),
            ("a build", "docker build -t lab-notes ."),
            ("an empty paste", ""),
            (
                "a compose document indented with tabs",
                "services:\n\tweb:\n\t\timage: registry.test/lab-notes\n",
            ),
        ] {
            let paste = parse_service_definition_paste(pasted);
            assert_eq!(paste.source, PasteSource::Unrecognised, "{name} was read");
            assert_eq!(paste.draft, ServiceDefinitionDraft::default());
            assert!(paste
                .notes
                .iter()
                .any(|note| note.note == PasteNoteName::NothingRecognised));
        }

        // A paste above its bound is refused whole rather than read in part: a
        // truncated compose document would prefill a form from half a service.
        let oversized = format!(
            "services:\n  web:\n    image: registry.test/{}\n",
            "a".repeat(MAX_PASTE_BYTES)
        );
        let paste = parse_service_definition_paste(&oversized);
        assert_eq!(paste.source, PasteSource::Unrecognised);
        assert!(paste
            .notes
            .iter()
            .any(|note| note.note == PasteNoteName::PasteTooLarge));
    }

    /// The property the whole paste rests on: it can only prefill.
    ///
    /// Whatever a paste produces is a draft, and a draft reaches the Controller
    /// only through a review a human read and a freeze a human clicked. The
    /// statement made here is the one a reader needs: a paste of an application
    /// that is not eligible produces a draft the contract refuses, and the
    /// refusal is the ordinary one.
    #[test]
    fn a_paste_can_never_produce_something_that_is_frozen_by_itself() {
        let paste = parse_service_definition_paste(
            "docker run --name Vaultwarden -p 80:80 -v /data:/data docker.io/vaultwarden/server",
        );
        assert_eq!(paste.source, PasteSource::ContainerCommand);
        // The suggestion is lower-cased by the suggestion itself, and it lands
        // on one of the four reserved names — which the mirror refuses, exactly
        // as it refuses one a human typed.
        assert_eq!(paste.draft.slug, "vaultwarden");
        let review = review_service_definition(&paste.draft);
        let ServiceDefinitionReview::Refused { refusals, .. } = review else {
            panic!("a reserved slug is refused")
        };
        assert!(refusals.iter().any(|refusal| refusal.refusal
            == your_cloud_bootstrap_protocol::ServiceDefinitionRefusal::SlugReserved));
    }

    /// A frozen document is displayed only if it is the definition its digest
    /// names, and only in its canonical spelling.
    #[test]
    fn a_frozen_definition_is_rehashed_before_it_is_displayed() {
        let ServiceDefinitionReview::Ready {
            definition_document,
            definition_sha256,
            ..
        } = review_service_definition(&reference_draft())
        else {
            panic!("the reference definition is inside the contract")
        };
        assert!(displayable_definition(&definition_document, &definition_sha256).is_some());
        assert!(displayable_definition(
            &definition_document.replace("lab-notes", "lab-notez"),
            &definition_sha256
        )
        .is_none());
        // A reindented document carries the same definition and is refused all
        // the same: what is displayed is the exact bytes that were frozen.
        assert!(
            displayable_definition(&format!(" {definition_document}"), &definition_sha256)
                .is_none()
        );
    }
}

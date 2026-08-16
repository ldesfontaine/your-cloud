//! Le lot, posé sur la cible — l'étape que le plan nomme avant tout privilège.
//!
//! Un fichier de six mégaoctets qui apparaît sur une machine est un **effet**,
//! et tout effet de ce produit naît d'un plan approuvé et visible. Le transfert
//! est donc une étape du plan et non une commodité du prévol : la faire
//! précéder le plan créerait le premier effet qu'aucun plan ne nomme, et ce
//! précédent-là ne se rattrape pas.
//!
//! **Elle ne dépense aucun privilège.** Le lot voyage sous le seul accès
//! personnel, vers le foyer du compte qui l'a prêté ; l'élévation reste intacte
//! pour [`super::plan::Step::InstallPackage`], qui demeure le premier acte
//! privilégié du palier. Un retrait n'en demande pas davantage : le registre de
//! démontage sait déjà retirer un fichier et un répertoire que cette exécution
//! a créés, donc le rollback de cette étape est celui qui existe, sans une
//! ligne de plus.
//!
//! **Son verdict est l'empreinte relue sur la cible.** Ce module est la moitié
//! qui décide : ses entrées sont ce que la machine a répondu, et sa sortie est
//! un [`StagedFile`] ou un refus nommé. Il n'ouvre aucun fichier, n'ouvre
//! aucun transport et ne copie rien — la moitié qui agit lui apporte les octets
//! observés. Confronter l'empreinte **après** la traversée est ce qui distingue
//! « le lot a été envoyé » de « le lot est sur la cible » : un transport qui
//! tronque, une écriture qui échoue à mi-course ou un fichier qu'un tiers a
//! remplacé donnent chacun leur refus plutôt qu'un `dpkg` sur des octets que
//! personne n'a relus.
//!
//! **Il prononce deux verdicts, et leur séparation est l'ordre lui-même.**
//! [`staging_created`] répond du répertoire d'attente, [`deposited`] du fichier
//! qui y est déposé. Les réunir en un seul appel obligerait l'exécutant à avoir
//! déjà déposé pour apprendre que le répertoire n'était pas le sien — c'est-à-
//! dire à écrire six mégaoctets dans un répertoire dont un tiers tient la
//! porte, quitte à le refuser après coup. Le refus doit tomber **avant** que le
//! premier octet parte, donc la porte est une fonction distincte, appelée en
//! premier.
//!
//! **La chaîne sert aussi ce qui n'est pas le lot.** [`deposited`] reçoit la
//! taille, l'empreinte et le suffixe attendus plutôt que de les lire d'un
//! [`VerifiedBundle`] : la configuration machine de [`super::configuration`]
//! est déposée par le même `dd`, mesurée par les mêmes deux commandes et jugée
//! par ce même corps. Un second juge écrit à côté aurait donné deux définitions
//! de « le fichier est celui qu'on a envoyé », et c'est exactement ce qu'un
//! duplicata finit par produire.

use super::bundle::VerifiedBundle;
use crate::personal_access::elevation::FixedCommand;

/// Le répertoire d'attente, dans le foyer du compte personnel, et le lot qu'il
/// reçoit.
///
/// Les deux chemins sont relatifs au foyer parce que l'étape n'a que l'accès
/// personnel : elle écrit là où ce compte est chez lui, jamais dans un
/// répertoire partagé où un tiers aurait pu poser un lien avant elle. C'est
/// aussi pourquoi la création refuse un répertoire déjà présent au lieu de le
/// réutiliser — la même discipline que le `O_EXCL` des clés de lien.
pub const STAGING_DIRECTORY: &str = "$HOME/.your-cloud-bootstrap";
/// Le suffixe que le chemin mesuré doit porter, foyer non compris.
pub const STAGED_ARTIFACT_SUFFIX: &str = "/.your-cloud-bootstrap/your-cloud-server.deb";

/// Crée le répertoire d'attente, et refuse s'il existe déjà.
///
/// `mkdir` sans `-p` échoue sur un répertoire présent : c'est la porte, et non
/// une vérification séparée qui laisserait une fenêtre entre le regard et
/// l'écriture. `-m 0700` fixe les droits à la création même, jamais après.
///
/// `LC_ALL=C` est dans les **octets de la commande**, jamais dans un
/// environnement qu'un appelant poserait : ce sont ces octets-ci que l'humain
/// approuve et que la preuve compare, et une locale posée à côté d'eux ne
/// serait ni approuvée ni comparée. Sans elle, un message de diagnostic traduit
/// ferait de tout lecteur de constat un lecteur de traductions.
pub const CREATE_STAGING: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/mkdir -m 0700 -- $HOME/.your-cloud-bootstrap",
);

/// Dépose les octets du lot sur la cible, par l'entrée standard du canal.
///
/// `dd of=<chemin>` écrit ce qu'on lui donne à l'endroit nommé, **sans shell,
/// sans redirection et sans sous-système de transfert** : il n'y a ni `>` que
/// le shell interpréterait, ni SFTP dont la surface dépasse de loin le dépôt
/// d'un fichier. Les octets de la commande restent fixes ; ce qui varie est ce
/// qui passe par l'entrée, et c'est précisément ce que le manifeste signé a
/// déjà borné.
///
/// **La borne d'écriture est dérivée, jamais choisie.** Ce qui est envoyé est
/// l'artefact que [`super::bundle::verify`] a jugé : sa longueur a été
/// confrontée à celle que le manifeste lie, et le manifeste lui-même a été
/// refusé au-delà de [`super::bundle::MAX_ARTIFACT_BYTES`] **avant** toute
/// signature. Un manifeste hostile ou malformé ne peut donc pas faire écrire un
/// fichier sans limite : il ne franchit pas la porte locale.
///
/// `conv=fsync` fait rendre la main à `dd` une fois les octets sur le disque,
/// pour que la mesure qui suit porte sur un fichier écrit et non sur une
/// promesse. `status=none` tait le compte-rendu que `dd` écrit sur sa sortie
/// d'erreur : ce n'est pas lui qui décide, ce sont les deux mesures suivantes.
pub const DEPOSIT_BUNDLE: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/dd of=$HOME/.your-cloud-bootstrap/your-cloud-server.deb \
     bs=65536 conv=fsync status=none",
);

/// Relit la **taille** du lot déposé, avant d'en relire l'empreinte.
///
/// L'ordre n'est pas une commodité : `dd` peut tronquer sans crier — un disque
/// plein, une entrée coupée — et la taille est la mesure la moins chère qui
/// l'attrape. La confronter d'abord évite de hacher six mégaoctets pour
/// apprendre ce qu'un entier disait déjà.
pub const MEASURE_STAGED_SIZE: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/stat -c %s -- \
     $HOME/.your-cloud-bootstrap/your-cloud-server.deb",
);

/// Relit l'empreinte du lot **sur la cible**, après la traversée.
pub const MEASURE_STAGED: FixedCommand = FixedCommand::fixed(
    "/usr/bin/env LC_ALL=C /usr/bin/sha256sum -- $HOME/.your-cloud-bootstrap/your-cloud-server.deb",
);

/// Une ligne de `sha256sum` est courte et fixe. Tout ce qui dépasse est refusé
/// avant d'être lu, comme partout ailleurs dans ce module d'installation.
pub const MAX_MEASUREMENT_BYTES: usize = 4096;

/// Longueur d'une empreinte SHA-256 en hexadécimal minuscule.
const DIGEST_ENCODED_BYTES: usize = 64;

/// Le séparateur exact que `sha256sum` écrit entre l'empreinte et le chemin en
/// mode texte : deux espaces. Le mode binaire écrirait `" *"`, et un constat
/// qui accepterait les deux lirait une sortie qu'il n'a pas demandée.
const MEASUREMENT_SEPARATOR: &str = "  ";

/// Pourquoi le lot n'a pas été jugé posé.
///
/// Il n'y a pas de refus générique : la preuve LAB asserte chaque cas par son
/// nom, jamais par un code de sortie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferRefusal {
    /// Le répertoire d'attente n'a pas pu être créé — il existait déjà, ou le
    /// foyer refuse l'écriture. Rien n'a été transféré.
    ///
    /// C'est aussi la porte qui ferme la seule vraie faille de ce mécanisme :
    /// un répertoire partagé et inscriptible laisserait un utilisateur local
    /// gagner la course entre le dépôt et la vérification, donc faire installer
    /// d'autres octets que ceux qui ont été relus. Le répertoire est propre à
    /// l'opération, en `0700`, et sa création **refuse** l'existant au lieu de
    /// le réutiliser : la course n'a pas de fenêtre où se glisser.
    StagingNotFresh,
    /// `dd` n'a pas rendu zéro : les octets ne sont pas tous arrivés.
    DepositFailed,
    /// La taille relue n'est pas lisible comme un entier décimal.
    SizeUnreadable,
    /// La taille sur la cible n'est pas celle que le manifeste signé lie.
    /// `dd` tronque sans crier ; c'est ici que la troncature se voit.
    StagedSizeMismatch,
    /// La mesure a répondu autre chose que zéro. Le lot n'est pas relu.
    MeasurementFailed,
    /// La sortie de la mesure est plus longue qu'une ligne d'empreinte.
    MeasurementTooLarge,
    /// La sortie n'a pas la forme exacte d'une ligne de `sha256sum`.
    MeasurementUnreadable,
    /// La ligne mesure un autre fichier que le lot posé.
    ForeignPathMeasured,
    /// Le lot présent sur la cible n'est pas celui que le manifeste signé lie.
    StagedDigestMismatch,
}

/// La preuve qu'un fichier exactement jugé est sur la cible, à l'emplacement
/// connu — le lot, ou la configuration que le plan nomme.
///
/// Comme les autres témoins de ce crate, il ne peut pas être construit en
/// nommant ses champs et [`deposited`] est la seule fonction qui en rend un. Il
/// n'autorise rien par lui-même : il dit seulement que les octets qu'un juge
/// local avait déjà arrêtés sont ceux que la cible détient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFile {
    path: String,
    sha256: String,
}

impl StagedFile {
    /// Le chemin absolu du lot sur la cible, tel que la machine l'a nommé.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Ce que la machine a répondu aux trois commandes d'un dépôt.
///
/// Chaque champ est un statut ou des octets bruts : rien n'y est une conclusion
/// tirée par l'appelant. C'est la forme de `elevation::elevated`, appliquée à
/// une étape qui parle trois fois au lieu d'une. Le statut du répertoire
/// d'attente n'y est pas : il a son propre verdict, prononcé avant que ces
/// trois commandes existent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferReadings<'a> {
    /// Statut de [`DEPOSIT_BUNDLE`] ou de son équivalent.
    pub deposit_status: u32,
    /// Statut et sortie de [`MEASURE_STAGED_SIZE`].
    pub size_status: u32,
    pub size_stdout: &'a [u8],
    /// Statut et sortie de [`MEASURE_STAGED`].
    pub digest_status: u32,
    pub digest_stdout: &'a [u8],
}

/// La porte du répertoire d'attente, prononcée **avant** que le moindre octet
/// parte.
///
/// `mkdir` sans `-p` échoue sur un répertoire présent, donc ce statut n'est pas
/// un code de sortie parmi d'autres : c'est le constat lui-même. Zéro dit que
/// le répertoire n'existait pas et que cette exécution l'a créé — donc qu'elle
/// pourra le retirer ; non nul dit qu'elle n'en est pas propriétaire, et rien
/// n'y sera écrit.
pub fn staging_created(status: u32) -> Result<(), TransferRefusal> {
    if status == 0 {
        Ok(())
    } else {
        Err(TransferRefusal::StagingNotFresh)
    }
}

/// La taille relue sur la cible, confrontée à celle que l'expéditeur tenait.
fn read_size(expected: u64, readings: &TransferReadings<'_>) -> Result<(), TransferRefusal> {
    if readings.size_stdout.len() > MAX_MEASUREMENT_BYTES {
        return Err(TransferRefusal::MeasurementTooLarge);
    }
    if readings.size_status != 0 {
        return Err(TransferRefusal::MeasurementFailed);
    }
    let observed: u64 = std::str::from_utf8(readings.size_stdout)
        .map_err(|_| TransferRefusal::SizeUnreadable)?
        .strip_suffix('\n')
        .ok_or(TransferRefusal::SizeUnreadable)?
        .parse()
        .map_err(|_| TransferRefusal::SizeUnreadable)?;
    // La taille attendue vient d'un témoin que l'appelant détenait déjà — le
    // manifeste signé pour le lot, les octets composés pour la configuration —
    // jamais d'un nombre choisi au moment de la comparaison.
    if observed == expected {
        Ok(())
    } else {
        Err(TransferRefusal::StagedSizeMismatch)
    }
}

/// La porte d'un dépôt. Rien d'autre dans ce crate ne construit un
/// [`StagedFile`].
///
/// Les entrées sont ce que la **machine a répondu**, jamais ce qu'un appelant
/// en a conclu : chaque statut est rendu tel quel — un booléen aurait laissé la
/// conclusion à celui qui la rapporte, et c'est précisément ce que la forme de
/// `elevation::elevated` refuse de faire.
///
/// Les trois attentes ne sont pas des réglages : elles viennent d'un témoin que
/// l'appelant tenait **avant** le départ — le manifeste signé pour le lot, les
/// octets composés pour la configuration. Un appelant qui les choisirait ne
/// pourrait rien prouver de plus qu'en n'appelant pas cette fonction.
///
/// La sortie d'erreur n'entre pas dans le verdict, et c'est délibéré : ce qui
/// est jugé est l'empreinte que la cible a calculée sur son propre fichier. Une
/// commande qui aurait écrit un avertissement sur `stderr` tout en rendant zéro
/// et la ligne exacte a mesuré le fichier quand même, et refuser là-dessus
/// ferait dépendre une porte de sécurité du bavardage d'un système.
pub fn deposited(
    expected_size: u64,
    expected_sha256: &str,
    expected_suffix: &str,
    readings: &TransferReadings<'_>,
) -> Result<StagedFile, TransferRefusal> {
    // L'ordre va du moins cher au plus cher, et chaque marche a son nom : le
    // statut du dépôt, puis la taille — que `dd` peut tronquer sans crier —,
    // puis seulement l'empreinte, qui coûte de hacher tout le fichier.
    if readings.deposit_status != 0 {
        return Err(TransferRefusal::DepositFailed);
    }
    read_size(expected_size, readings)?;
    let stdout = readings.digest_stdout;
    if stdout.len() > MAX_MEASUREMENT_BYTES {
        return Err(TransferRefusal::MeasurementTooLarge);
    }
    if readings.digest_status != 0 {
        return Err(TransferRefusal::MeasurementFailed);
    }

    let line = std::str::from_utf8(stdout)
        .map_err(|_| TransferRefusal::MeasurementUnreadable)?
        .strip_suffix('\n')
        .ok_or(TransferRefusal::MeasurementUnreadable)?;
    let (digest, path) = line
        .split_once(MEASUREMENT_SEPARATOR)
        .ok_or(TransferRefusal::MeasurementUnreadable)?;
    if digest.len() != DIGEST_ENCODED_BYTES
        || !digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(TransferRefusal::MeasurementUnreadable);
    }
    // Le chemin imprimé est l'écho de l'argument fixe. Il est confronté à ce
    // que cet argument désigne : une ligne qui nommerait un autre fichier ne
    // répond pas à la commande qui a été approuvée.
    if !path.ends_with(expected_suffix) || path.starts_with(' ') {
        return Err(TransferRefusal::ForeignPathMeasured);
    }
    // L'empreinte que l'expéditeur tenait, relue sur la machine qui détient
    // désormais le fichier. La taille n'est pas reconfrontée ici : elle l'a été
    // à la marche précédente, et une troncature en chemin change l'empreinte.
    if digest != expected_sha256 {
        return Err(TransferRefusal::StagedDigestMismatch);
    }

    Ok(StagedFile {
        path: path.to_owned(),
        sha256: digest.to_owned(),
    })
}

/// Le dépôt du **lot**, jugé contre ce que le manifeste signé lie.
///
/// Elle ne fait que nommer les trois attentes du lot, une fois, pour qu'aucun
/// exécutant n'ait à les porter lui-même : la taille et l'empreinte sortent du
/// [`VerifiedBundle`], le suffixe est la constante de ce module.
pub fn staged(
    bundle: &VerifiedBundle,
    readings: &TransferReadings<'_>,
) -> Result<StagedFile, TransferRefusal> {
    deposited(
        bundle.size(),
        bundle.sha256(),
        STAGED_ARTIFACT_SUFFIX,
        readings,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    const ARTIFACT: &[u8] = b"not a real .deb, but exactly these bytes";
    const HOME_PATH: &str = "/home/ycoperator/.your-cloud-bootstrap/your-cloud-server.deb";

    fn hex_digest(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Un lot réellement jugé par la porte du produit : ce module n'accepte
    /// qu'un [`VerifiedBundle`], et les suites ne peuvent pas en fabriquer un
    /// autrement que par elle.
    fn verified() -> VerifiedBundle {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = format!(
            concat!(
                "{{\"schema_version\":1,\"kind\":\"your-cloud-server-bundle\",",
                "\"version\":\"0.1.0\",\"target\":\"debian-13-amd64\",",
                "\"size\":{},\"sha256\":\"{}\"}}"
            ),
            ARTIFACT.len(),
            hex_digest(ARTIFACT),
        );
        let signature = key.sign(manifest.as_bytes());
        super::super::bundle::verify(
            &key.verifying_key().to_bytes(),
            manifest.as_bytes(),
            &signature.to_bytes(),
            "0.1.0",
            ARTIFACT,
        )
        .expect("le contrôle positif du lot doit être jugé")
    }

    fn readings<'a>(size: &'a [u8], digest: &'a [u8]) -> TransferReadings<'a> {
        TransferReadings {
            deposit_status: 0,
            size_status: 0,
            size_stdout: size,
            digest_status: 0,
            digest_stdout: digest,
        }
    }

    fn size_line(bytes: usize) -> Vec<u8> {
        format!("{bytes}\n").into_bytes()
    }

    fn nominal_size() -> Vec<u8> {
        size_line(ARTIFACT.len())
    }

    fn measurement(digest: &str, path: &str) -> Vec<u8> {
        format!("{digest}  {path}\n").into_bytes()
    }

    /// Le contrôle positif. Tout ce qui suit est celui-ci, moins une chose.
    #[test]
    fn the_bundle_the_target_holds_is_the_one_the_manifest_binds() {
        let bundle = verified();
        let staged = staged(
            &bundle,
            &readings(
                &nominal_size(),
                &measurement(&hex_digest(ARTIFACT), HOME_PATH),
            ),
        )
        .expect("le contrôle positif doit être jugé posé");

        assert_eq!(staged.path(), HOME_PATH);
        assert_eq!(staged.sha256(), hex_digest(ARTIFACT));
    }

    /// La propriété que l'étape existe pour obtenir : des octets arrivés
    /// différents sont refusés, et rien de privilégié ne les touchera.
    #[test]
    fn a_bundle_that_travelled_badly_is_refused_before_any_privilege() {
        let bundle = verified();
        let mut altered = ARTIFACT.to_vec();
        altered[0] ^= 0x01;

        assert_eq!(
            staged(
                &bundle,
                &readings(
                    &nominal_size(),
                    &measurement(&hex_digest(&altered), HOME_PATH)
                )
            ),
            Err(TransferRefusal::StagedDigestMismatch)
        );
    }

    /// Un répertoire d'attente qui existait déjà arrête l'étape **avant tout
    /// dépôt** : cette exécution n'a pas créé ce qu'elle s'apprêtait à remplir,
    /// donc elle ne le remplit pas et ne pourra pas le retirer.
    ///
    /// Le verdict est séparé de celui du dépôt pour cette raison exacte. S'il
    /// vivait dans [`deposited`], l'exécutant devrait avoir déjà écrit six
    /// mégaoctets dans un répertoire dont un tiers tient la porte pour
    /// apprendre qu'il n'avait pas le droit de l'écrire.
    #[test]
    fn a_staging_directory_this_run_did_not_create_stops_the_step() {
        assert_eq!(staging_created(0), Ok(()));
        for refused in [1u32, 2, 127] {
            assert_eq!(
                staging_created(refused),
                Err(TransferRefusal::StagingNotFresh)
            );
        }
    }

    /// Chaque forme de sortie que la mesure ne doit pas accepter, refusée par
    /// son propre nom.
    #[test]
    fn every_measurement_that_is_not_one_is_refused_by_its_own_reason() {
        let bundle = verified();
        let digest = hex_digest(ARTIFACT);
        let cases: [(Vec<u8>, TransferRefusal); 7] = [
            (
                measurement(&digest, "/home/ycoperator/other.deb"),
                TransferRefusal::ForeignPathMeasured,
            ),
            (
                measurement(&digest.to_uppercase(), HOME_PATH),
                TransferRefusal::MeasurementUnreadable,
            ),
            (
                measurement(&digest[..63], HOME_PATH),
                TransferRefusal::MeasurementUnreadable,
            ),
            (
                // Un seul espace : la forme du mode binaire, jamais demandée.
                format!("{digest} {HOME_PATH}\n").into_bytes(),
                TransferRefusal::MeasurementUnreadable,
            ),
            (
                // Sans saut de ligne final : une sortie tronquée en vol.
                format!("{digest}  {HOME_PATH}").into_bytes(),
                TransferRefusal::MeasurementUnreadable,
            ),
            (
                b"\xff\xfe pas de l'UTF-8\n".to_vec(),
                TransferRefusal::MeasurementUnreadable,
            ),
            (
                vec![b'a'; MAX_MEASUREMENT_BYTES + 1],
                TransferRefusal::MeasurementTooLarge,
            ),
        ];

        for (stdout, expected) in cases {
            assert_eq!(
                staged(&bundle, &readings(&nominal_size(), &stdout)),
                Err(expected)
            );
        }
    }

    /// Une mesure qui a échoué n'est pas une mesure : même une ligne
    /// parfaitement formée ne rachète pas un statut non nul.
    #[test]
    fn a_failed_measurement_is_refused_however_well_formed_its_output() {
        let bundle = verified();

        assert_eq!(
            staged(
                &bundle,
                &TransferReadings {
                    digest_status: 1,
                    ..readings(
                        &nominal_size(),
                        &measurement(&hex_digest(ARTIFACT), HOME_PATH)
                    )
                }
            ),
            Err(TransferRefusal::MeasurementFailed)
        );
    }

    /// L'ordre des marches, et chacune par son nom.
    ///
    /// Du moins cher au plus cher : le statut du dépôt, puis la taille — que
    /// `dd` peut tronquer sans crier —, puis l'empreinte. Un lot tronqué
    /// s'arrête donc à la taille sans qu'on ait haché six mégaoctets pour
    /// apprendre ce qu'un entier disait déjà.
    #[test]
    fn the_transfer_is_judged_from_the_cheapest_reading_to_the_costliest() {
        let bundle = verified();
        let intact = measurement(&hex_digest(ARTIFACT), HOME_PATH);

        // `dd` a échoué : rien d'autre n'est même regardé.
        assert_eq!(
            staged(
                &bundle,
                &TransferReadings {
                    deposit_status: 1,
                    ..readings(&nominal_size(), &intact)
                }
            ),
            Err(TransferRefusal::DepositFailed)
        );

        // Tronqué d'un octet : la taille l'attrape, et le nom le dit.
        assert_eq!(
            staged(&bundle, &readings(&size_line(ARTIFACT.len() - 1), &intact)),
            Err(TransferRefusal::StagedSizeMismatch)
        );

        // Une taille illisible n'est pas une taille.
        for unreadable in [&b"pas un nombre\n"[..], &b"12"[..], &b"-1\n"[..]] {
            assert_eq!(
                staged(&bundle, &readings(unreadable, &intact)),
                Err(TransferRefusal::SizeUnreadable)
            );
        }

        // La mesure de taille qui échoue se nomme comme telle.
        assert_eq!(
            staged(
                &bundle,
                &TransferReadings {
                    size_status: 1,
                    ..readings(&nominal_size(), &intact)
                }
            ),
            Err(TransferRefusal::MeasurementFailed)
        );
    }

    /// Le dépôt ne passe ni par un shell, ni par une redirection, ni par un
    /// sous-système : `dd` écrit là où on le lui dit, et rien d'autre ne
    /// traverse.
    #[test]
    fn the_deposit_uses_no_shell_no_redirection_and_no_subsystem() {
        let bytes = DEPOSIT_BUNDLE.as_str();
        assert!(bytes.contains("/usr/bin/dd of=$HOME/.your-cloud-bootstrap/your-cloud-server.deb"));
        assert!(bytes.contains("conv=fsync"));
        for forbidden in [">", "<", "|", "&&", ";", "sftp", "scp", "sh -c", "~"] {
            assert!(
                !bytes.contains(forbidden),
                "dépôt composé ({forbidden}) : {bytes}"
            );
        }
    }

    /// Les octets des deux commandes portent leur locale eux-mêmes, et
    /// désignent le foyer du compte plutôt qu'un répertoire partagé. Ce test
    /// fige ce qui est approuvé et comparé.
    #[test]
    fn the_fixed_commands_carry_their_own_locale_and_stay_in_the_account_home() {
        for command in [CREATE_STAGING, MEASURE_STAGED] {
            assert!(command.as_str().starts_with("/usr/bin/env LC_ALL=C "));
            assert!(command.as_str().contains("$HOME/.your-cloud-bootstrap"));
            // Jamais `~` : l'expansion du tilde après un `=` n'est pas POSIX,
            // et `dash` ne la fait pas. Un chemin de sécurité ne dépend pas
            // du shell que la cible se trouve avoir.
            assert!(!command.as_str().contains('~'));
            assert!(!command.as_str().contains("/tmp"));
        }
        // La création refuse un répertoire présent : pas de `-p`, et les droits
        // sont posés à la création même.
        assert!(!CREATE_STAGING.as_str().contains(" -p"));
        assert!(CREATE_STAGING.as_str().contains("-m 0700"));
    }
}

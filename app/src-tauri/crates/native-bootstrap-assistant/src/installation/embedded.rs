//! La résolution du lot embarqué, depuis la position attestée et depuis rien
//! d'autre.
//!
//! Ce module fournit des valeurs, [`super::bundle`] juge — la séparation de
//! [`super::anchor`], reprise à l'identique. Ce qu'il fournit : l'emplacement
//! des trois fichiers du lot serveur que le paquet de l'App livre, puis
//! leurs octets. L'emplacement est **dérivé** de la position du binaire en
//! cours d'exécution telle que le noyau la rapporte (`/proc/self/exe`) —
//! jamais d'un argument, jamais d'une variable d'environnement, jamais d'un
//! chemin qu'un parent aurait choisi. C'est la propriété du refus d'être
//! enrobé, prolongée au lot : un binaire recopié ailleurs ne trouve pas un
//! autre lot, il ne trouve rien, et il le dit par son nom.
//!
//! La dérivation n'est pas une confiance. Quel que soit le chemin résolu, la
//! seule autorité sur le lot reste [`super::bundle::verify`] contre l'ancre de
//! [`super::anchor`] : ce module ne parse pas un octet du manifeste et ne
//! connaît pas l'ancre. Il borne seulement ce qu'il accepte de lire, aux
//! limites que `bundle` refuse déjà, pour qu'aucun fichier démesuré ne soit
//! chargé en mémoire avant d'être refusé.
//!
//! Les trois fichiers portent des noms fixes plutôt que versionnés : l'identité
//! d'un lot est son manifeste signé, jamais son nom de fichier, et un nom qui
//! changerait à chaque version ferait de la configuration d'empaquetage un
//! document à réviser à chaque release.

use std::path::{Path, PathBuf};

/// Le sous-arbre du préfixe d'installation (`/usr`) où le paquet de l'App
/// livre le lot. `usr/lib/<binaire principal>` est l'emplacement que
/// l'empaquetage Debian de Tauri donne aux fichiers déclarés, et
/// `server-bundle` est le répertoire que la déclaration du paquet nomme.
const CARRIED_DIRECTORY_UNDER_PREFIX: &str = "lib/your-cloud-app/server-bundle";

/// Les noms fixes des trois fichiers, exactement ceux que la préparation du
/// paquet de l'App dépose.
pub const CARRIED_MANIFEST_FILE_NAME: &str = "bundle-manifest.json";
pub const CARRIED_SIGNATURE_FILE_NAME: &str = "bundle-manifest.sig";
pub const CARRIED_ARTIFACT_FILE_NAME: &str = "your-cloud-server.deb";

/// Lequel des trois fichiers un refus de lecture nomme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarriedFile {
    Manifest,
    Signature,
    Artifact,
}

/// Pourquoi la résolution n'a pas rendu de lot.
///
/// Comme pour [`super::bundle::BundleRefusal`], il n'y a pas de refus générique :
/// la preuve LAB asserte chacun par son nom, jamais par un code de sortie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbeddedRefusal {
    /// Le processus ne peut attester aucune position : la plateforme n'offre
    /// pas `/proc/self/exe`, ou sa lecture a échoué.
    PositionNotAttestable,
    /// La position attestée n'est pas le chemin installé de l'Assistant. Un
    /// binaire recopié ou lancé depuis un arbre de travail reçoit ce refus,
    /// et c'est le comportement voulu.
    OutsideAttestedPosition,
    /// Un des trois fichiers du lot manque à l'arborescence installée.
    NotCarried(CarriedFile),
    /// Un des trois fichiers existe mais n'a pas pu être lu.
    Unreadable(CarriedFile),
}

/// L'emplacement résolu des trois fichiers du lot.
///
/// Comme les témoins de ce crate, il ne peut pas être construit en nommant ses
/// champs : [`locate`] est la seule fonction qui en rend un, et elle ne le rend
/// que pour la position attestée exacte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarriedBundleLocation {
    manifest: PathBuf,
    signature: PathBuf,
    artifact: PathBuf,
}

impl CarriedBundleLocation {
    pub fn manifest(&self) -> &Path {
        &self.manifest
    }

    pub fn signature(&self) -> &Path {
        &self.signature
    }

    pub fn artifact(&self) -> &Path {
        &self.artifact
    }

    /// Uniquement pour les suites : un emplacement pointant un répertoire
    /// arbitraire, afin d'exercer [`read`] sans écrire sous `/usr`. Le produit
    /// n'a aucun moyen d'en construire un ainsi.
    #[cfg(test)]
    fn rooted_for_tests(directory: &Path) -> Self {
        Self {
            manifest: directory.join(CARRIED_MANIFEST_FILE_NAME),
            signature: directory.join(CARRIED_SIGNATURE_FILE_NAME),
            artifact: directory.join(CARRIED_ARTIFACT_FILE_NAME),
        }
    }
}

/// Les octets des trois fichiers, lus mais **jamais jugés** : seul
/// [`super::bundle::verify`] dit ce qu'ils valent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarriedBundle {
    pub manifest: Vec<u8>,
    pub signature: Vec<u8>,
    pub artifact: Vec<u8>,
}

/// Dérive l'emplacement du lot de la position attestée, et d'elle seule.
///
/// La position doit être exactement le chemin installé de l'Assistant ; tout
/// autre chemin — copie, arbre de travail, répertoire temporaire — est refusé
/// par [`EmbeddedRefusal::OutsideAttestedPosition`]. La dérivation remonte
/// ensuite structurellement du binaire à son préfixe (`/usr/bin/… → /usr`)
/// puis descend vers le sous-arbre que le paquet livre : le chemin du lot est
/// une conséquence de la position, pas une seconde constante qu'un oubli
/// pourrait désynchroniser.
pub fn locate(attested_executable: &Path) -> Result<CarriedBundleLocation, EmbeddedRefusal> {
    if attested_executable != Path::new(crate::parent::LINUX_HELPER_PATH) {
        return Err(EmbeddedRefusal::OutsideAttestedPosition);
    }
    let prefix = attested_executable
        .parent()
        .and_then(Path::parent)
        .ok_or(EmbeddedRefusal::OutsideAttestedPosition)?;
    let directory = prefix.join(CARRIED_DIRECTORY_UNDER_PREFIX);
    Ok(CarriedBundleLocation {
        manifest: directory.join(CARRIED_MANIFEST_FILE_NAME),
        signature: directory.join(CARRIED_SIGNATURE_FILE_NAME),
        artifact: directory.join(CARRIED_ARTIFACT_FILE_NAME),
    })
}

/// Atteste la position de ce processus auprès du noyau, puis dérive.
///
/// `/proc/self/exe` est la seule entrée : ni `argv[0]`, ni le répertoire
/// courant, ni l'environnement n'y participent. Sur les plateformes qui ne
/// l'offrent pas, la position n'est pas attestable et le refus le dit.
#[cfg(target_os = "linux")]
pub fn from_attested_position() -> Result<CarriedBundleLocation, EmbeddedRefusal> {
    let attested =
        std::fs::read_link("/proc/self/exe").map_err(|_| EmbeddedRefusal::PositionNotAttestable)?;
    locate(&attested)
}

#[cfg(not(target_os = "linux"))]
pub fn from_attested_position() -> Result<CarriedBundleLocation, EmbeddedRefusal> {
    Err(EmbeddedRefusal::PositionNotAttestable)
}

/// Lit les trois fichiers, chacun borné à la limite que `bundle` refuse.
///
/// Les bornes de lecture dépassent d'un octet celles de [`super::bundle`] :
/// un fichier trop long est ainsi tronqué à « trop long d'exactement un » et
/// c'est la porte qui prononce `ManifestTooLarge` ou `ArtifactTooLarge` — la
/// lecture ne juge pas, elle empêche seulement qu'un fichier démesuré occupe
/// la mémoire avant que la porte ait parlé.
pub fn read(location: &CarriedBundleLocation) -> Result<CarriedBundle, EmbeddedRefusal> {
    Ok(CarriedBundle {
        manifest: bounded(
            &location.manifest,
            super::bundle::MAX_MANIFEST_BYTES + 1,
            CarriedFile::Manifest,
        )?,
        signature: bounded(
            &location.signature,
            super::bundle::SIGNATURE_BYTES + 1,
            CarriedFile::Signature,
        )?,
        artifact: bounded(
            &location.artifact,
            super::bundle::MAX_ARTIFACT_BYTES + 1,
            CarriedFile::Artifact,
        )?,
    })
}

fn bounded(path: &Path, limit: usize, which: CarriedFile) -> Result<Vec<u8>, EmbeddedRefusal> {
    use std::io::Read;

    let file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            EmbeddedRefusal::NotCarried(which)
        } else {
            EmbeddedRefusal::Unreadable(which)
        }
    })?;
    let mut bytes = Vec::new();
    file.take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| EmbeddedRefusal::Unreadable(which))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le contrôle positif : la position attestée exacte rend l'emplacement
    /// dérivé, et chaque fichier porte son nom fixe sous le sous-arbre du
    /// paquet.
    #[test]
    fn the_attested_position_yields_the_carried_tree() {
        let location = locate(Path::new("/usr/bin/your-cloud-native-bootstrap-assistant"))
            .expect("la position attestée doit résoudre");

        assert_eq!(
            location.manifest(),
            Path::new("/usr/lib/your-cloud-app/server-bundle/bundle-manifest.json")
        );
        assert_eq!(
            location.signature(),
            Path::new("/usr/lib/your-cloud-app/server-bundle/bundle-manifest.sig")
        );
        assert_eq!(
            location.artifact(),
            Path::new("/usr/lib/your-cloud-app/server-bundle/your-cloud-server.deb")
        );
    }

    /// Chacune de ces positions est plausible pour un binaire recopié ou
    /// enrobé, et chacune est refusée par le même nom. Le nom du fichier ne
    /// suffit pas : c'est la position entière qui atteste.
    #[test]
    fn every_other_position_is_refused_by_its_name() {
        let outside = [
            "/tmp/your-cloud-native-bootstrap-assistant",
            "/usr/local/bin/your-cloud-native-bootstrap-assistant",
            "/usr/bin/your-cloud-app",
            "/home/operator/your-cloud-native-bootstrap-assistant",
            "your-cloud-native-bootstrap-assistant",
            "/usr/bin/",
        ];

        for position in outside {
            assert_eq!(
                locate(Path::new(position)),
                Err(EmbeddedRefusal::OutsideAttestedPosition),
                "la position était : {position}"
            );
        }
    }

    /// Un lot absent se nomme fichier par fichier : la preuve LAB asserte le
    /// manifeste manquant et l'artefact manquant comme deux faits distincts.
    #[test]
    fn a_missing_file_is_named_not_carried() {
        let directory = test_directory("missing");
        let location = CarriedBundleLocation::rooted_for_tests(&directory);

        assert_eq!(
            read(&location),
            Err(EmbeddedRefusal::NotCarried(CarriedFile::Manifest))
        );

        std::fs::write(location.manifest(), b"{}").expect("write manifest");
        assert_eq!(
            read(&location),
            Err(EmbeddedRefusal::NotCarried(CarriedFile::Signature))
        );

        std::fs::write(location.signature(), [0u8; 64]).expect("write signature");
        assert_eq!(
            read(&location),
            Err(EmbeddedRefusal::NotCarried(CarriedFile::Artifact))
        );

        std::fs::remove_dir_all(&directory).expect("cleanup");
    }

    /// La lecture rend les octets tels quels et ne juge rien : des contenus
    /// qui feraient refuser la porte sont rendus sans un mot. C'est `bundle`
    /// qui parlera.
    #[test]
    fn read_returns_bytes_verbatim_and_judges_nothing() {
        let directory = test_directory("verbatim");
        let location = CarriedBundleLocation::rooted_for_tests(&directory);
        std::fs::write(location.manifest(), b"not even json").expect("write manifest");
        std::fs::write(location.signature(), b"short").expect("write signature");
        std::fs::write(location.artifact(), b"not a deb").expect("write artifact");

        let carried = read(&location).expect("trois fichiers présents doivent se lire");
        assert_eq!(carried.manifest, b"not even json");
        assert_eq!(carried.signature, b"short");
        assert_eq!(carried.artifact, b"not a deb");

        std::fs::remove_dir_all(&directory).expect("cleanup");
    }

    /// La lecture tronque à « une de trop » et laisse la porte prononcer le
    /// refus de taille : le manifeste ci-dessous dépasse la borne, et c'est
    /// bien `ManifestTooLarge` que `verify` rend sur les octets lus.
    #[test]
    fn an_oversized_manifest_is_truncated_for_the_gate_to_refuse() {
        let directory = test_directory("oversized");
        let location = CarriedBundleLocation::rooted_for_tests(&directory);
        std::fs::write(
            location.manifest(),
            vec![b'{'; super::super::bundle::MAX_MANIFEST_BYTES + 17],
        )
        .expect("write manifest");
        std::fs::write(location.signature(), [0u8; 64]).expect("write signature");
        std::fs::write(location.artifact(), b"artifact").expect("write artifact");

        let carried = read(&location).expect("des fichiers présents doivent se lire");
        assert_eq!(
            carried.manifest.len(),
            super::super::bundle::MAX_MANIFEST_BYTES + 1
        );
        assert_eq!(
            super::super::bundle::verify(
                &[0u8; 32],
                &carried.manifest,
                &carried.signature,
                "0.0.0",
                &carried.artifact,
            ),
            Err(super::super::bundle::BundleRefusal::ManifestTooLarge)
        );

        std::fs::remove_dir_all(&directory).expect("cleanup");
    }

    fn test_directory(label: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "your-cloud-embedded-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("create test directory");
        directory
    }
}

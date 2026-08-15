//! L'ancre de release, scellée dans ce binaire à la compilation.
//!
//! Elle est ici et pas dans [`super::bundle`] pour une raison de forme :
//! `bundle` est la moitié qui **décide**, et ses entrées sont des octets déjà
//! en main. Lui donner une ancre en dur ferait d'une fonction pure une fonction
//! qui connaît une identité, et retirerait aux suites la possibilité de
//! l'exercer contre une ancre à elles. La séparation est la même que partout
//! ailleurs dans ce crate : ce module fournit une valeur, `bundle` juge.
//!
//! **Elle est scellée, et c'est ce que « scellée » veut dire.** Les octets sont
//! inclus à la compilation depuis un fichier des sources : ils font partie du
//! binaire que l'humain a installé lui-même, et rien ne peut les joindre après
//! coup — ni le réseau, ni un fichier de configuration, ni une variable
//! d'environnement. C'est la propriété qui rend l'embarquement du lot utile :
//! un lot vérifié contre une ancre qu'un tiers pourrait remplacer ne serait
//! vérifié contre rien.
//!
//! **Il n'y a pas de révocation, et c'est délibéré.** Une ancre scellée dans un
//! binaire déjà posé ne peut pas être révoquée à distance — donc elle ne peut
//! pas l'être par quelqu'un d'autre. Une nouvelle ancre est une nouvelle
//! release, et les installations existantes continuent de faire confiance à
//! l'ancienne jusqu'à ce que leur humain installe la nouvelle Console. La
//! procédure de rotation est au dossier de release.
//!
//! La moitié privée correspondante n'existe ni dans ce dépôt, ni dans une
//! machine du LAB, ni dans une porte d'intégration continue : elle est détenue
//! hors ligne par le mainteneur, et la signature détachée est son geste à
//! chaque release.

use super::bundle::ANCHOR_PUBLIC_KEY_BYTES;

/// Les 32 octets bruts de la clé publique Ed25519 qui répond des lots que ce
/// binaire acceptera d'installer.
///
/// Le fichier ne porte que la clé — pas d'enveloppe DER, pas d'en-tête PEM, pas
/// de saut de ligne final — parce que c'est exactement ce que
/// [`super::bundle::verify`] attend. Une enveloppe ici demanderait un analyseur
/// avant l'authentification qu'il sert, et l'ordre de ce crate est l'inverse.
pub const RELEASE_ANCHOR: &[u8; ANCHOR_PUBLIC_KEY_BYTES] =
    include_bytes!("../../anchor/release-anchor.pub");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installation::bundle::{self, BundleRefusal};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    /// Le message public sur lequel le mainteneur a prouvé qu'il détient la
    /// moitié privée de l'ancre. Ses octets exacts, sans saut de ligne final.
    const ANCHOR_PROOF_MESSAGE: &[u8] = b"your-cloud release anchor proof";

    /// La signature qu'il a produite une fois, hors ligne, sur ce message.
    const ANCHOR_PROOF_SIGNATURE: [u8; 64] = [
        0x90, 0xb0, 0x54, 0x87, 0x98, 0x27, 0xea, 0xd1, 0x4b, 0x1d, 0x0e, 0xbe, 0x83, 0x18, 0xf6,
        0xea, 0xca, 0x4c, 0x75, 0xda, 0x10, 0x88, 0x37, 0x5b, 0x43, 0x63, 0x89, 0xb9, 0x7b, 0x28,
        0x94, 0x18, 0x43, 0x65, 0x9a, 0x6e, 0xb8, 0xfe, 0xcf, 0x47, 0x4c, 0xf8, 0xb1, 0xdc, 0x1c,
        0xa8, 0x75, 0x4a, 0x31, 0xd7, 0x5b, 0xee, 0xa3, 0x3d, 0x48, 0x63, 0x95, 0xef, 0x2c, 0x0f,
        0x20, 0x0e, 0xfe, 0x09,
    ];

    /// L'ancre scellée est celle dont le mainteneur détient la moitié privée.
    ///
    /// Le contrôle de forme ci-dessous ne dit que « ces trente-deux octets
    /// décodent en un point de la courbe » — ce qu'une empreinte SHA-256 fait
    /// une fois sur deux. Il scellerait sans bruit une clé dont personne ne
    /// détient la moitié privée, et le produit ne l'apprendrait qu'à la
    /// première release, sur un `SignatureNotByAnchor` que rien n'expliquerait.
    ///
    /// Cette signature-ci est le seul lien vérifiable entre l'ancre committée
    /// et la clé hors ligne. Elle a été produite une fois, sur un message
    /// public, et rien d'autre n'a besoin d'exister pour la relire. Une ancre
    /// remplacée par une autre clé valide — accident de copie ou geste
    /// délibéré — fait rougir ce test là où la forme la laisserait passer.
    #[test]
    fn the_sealed_anchor_is_the_one_its_holder_proved() {
        let key = VerifyingKey::from_bytes(RELEASE_ANCHOR)
            .expect("l'ancre scellée doit être une clé Ed25519");
        key.verify(
            ANCHOR_PROOF_MESSAGE,
            &Signature::from_bytes(&ANCHOR_PROOF_SIGNATURE),
        )
        .expect("l'ancre scellée n'est pas celle dont la preuve de possession a été produite");
    }

    /// L'ancre scellée est une clé, et le seul moyen de le dire est de la
    /// donner à la fonction qui refuse ce qui n'en est pas une.
    ///
    /// Un fichier de 32 octets n'est pas une clé Ed25519 : la moitié des
    /// suites de 32 octets ne décodent en aucun point de la courbe. Une ancre
    /// tronquée, recopiée de travers ou remplacée par une empreinte passerait
    /// la vérification de longueur et échouerait ici — au moment de la
    /// compilation des suites plutôt qu'au premier amorçage d'un humain.
    #[test]
    fn the_sealed_anchor_is_a_key() {
        // Une signature vide suffit à prouver le point : `verify` lit l'ancre
        // avant la signature, donc une ancre invalide se nomme avant elle.
        let refusal = bundle::verify(RELEASE_ANCHOR, b"{}", &[0_u8; 64], "0.1.0", b"")
            .expect_err("aucun lot n'est signé par une signature nulle");
        assert_ne!(
            refusal,
            BundleRefusal::AnchorNotAKey,
            "l'ancre scellée n'est pas une clé Ed25519 valide"
        );
    }
}

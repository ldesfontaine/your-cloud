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

//! Les juges des deux actes d'identité — l'init et la frappe du lecteur.
//!
//! Un code de sortie dit qu'un programme s'est terminé sans se plaindre ; ces
//! deux actes disent PLUS : des identifiants immuables et des empreintes sont
//! nés, et la séquence n'a le droit de continuer que si la sortie les porte
//! sous leur forme canonique exacte. Un init silencieusement partiel, une
//! frappe qui rendrait autre chose que deux identifiants et deux empreintes,
//! laisseraient un `serve` mourir plus tard sous un nom qui ne désignerait pas
//! la cause — le motif exact que les gardes d'octets de ce palier existent
//! pour fermer.
//!
//! Les juges sont purs, exprès : la preuve LAB branche le canal réel, les
//! suites écrivent des sorties — et une mutation qui relâcherait une forme
//! rougit ici, sans machine.

/// La sortie exacte de `controller init` : une ligne, deux identifiants
/// canoniques. C'est la forme que `cmd/your-cloud` imprime, et les deux
/// documents doivent s'accorder — un test d'octets tient la ligne.
pub fn initialised(stdout: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "init output is not UTF-8".to_owned())?;
    let line = single_line(text)?;
    let (controller, infrastructure) = line
        .strip_prefix("controller_id=")
        .and_then(|rest| rest.split_once(" infrastructure_id="))
        .ok_or_else(|| format!("init line has the wrong shape: {line:?}"))?;
    canonical_uuid(controller).map_err(|why| format!("controller_id {why}"))?;
    canonical_uuid(infrastructure).map_err(|why| format!("infrastructure_id {why}"))?;
    Ok(())
}

/// La sortie exacte de `controller mint-reader` : quatre lignes, dans cet
/// ordre — les deux identifiants, la série canonique, l'empreinte du DER.
/// Rien d'autre ne peut quitter cette machine, et rien d'autre n'est accepté.
pub fn minted_reader(stdout: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "mint output is not UTF-8".to_owned())?;
    let mut lines = text.lines();
    let mut expect = |prefix: &str| -> Result<String, String> {
        let line = lines
            .next()
            .ok_or_else(|| format!("mint output ends before {prefix}"))?;
        line.strip_prefix(prefix)
            .map(str::to_owned)
            .ok_or_else(|| format!("mint line has the wrong shape: {line:?}"))
    };
    let controller = expect("controller_id=")?;
    let infrastructure = expect("infrastructure_id=")?;
    let serial = expect("reader_serial=")?;
    let digest = expect("reader_sha256=")?;
    if lines.next().is_some() {
        return Err("mint output carries more than its four lines".to_owned());
    }
    canonical_uuid(&controller).map_err(|why| format!("controller_id {why}"))?;
    canonical_uuid(&infrastructure).map_err(|why| format!("infrastructure_id {why}"))?;
    // La série : le canon de l'autorisation côté Relay — hexadécimal
    // minuscule, strictement positif, sans zéro de tête ni enveloppe.
    if serial.is_empty()
        || serial.len() > 32
        || serial.starts_with('0')
        || !serial
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("reader_serial is not canonical: {serial:?}"));
    }
    // L'empreinte : SHA-256 du DER, hexadécimal minuscule, 64 exactement.
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "reader_sha256 is not a canonical digest: {digest:?}"
        ));
    }
    Ok(())
}

fn single_line(text: &str) -> Result<&str, String> {
    let mut lines = text.lines();
    let line = lines.next().ok_or_else(|| "output is empty".to_owned())?;
    if lines.next().is_some() {
        return Err("output carries more than its one line".to_owned());
    }
    Ok(line)
}

/// Un UUID canonique tel que le Controller les imprime : minuscule,
/// 8-4-4-4-12. La version n'est pas re-jugée ici — c'est l'autorité du
/// Controller qui la tient — mais la FORME l'est entièrement : un identifiant
/// qui voyagerait sous une autre écriture divergerait un jour de celui que le
/// manifeste du Relay épinglera.
fn canonical_uuid(candidate: &str) -> Result<(), String> {
    let groups: Vec<&str> = candidate.split('-').collect();
    let sizes = [8usize, 4, 4, 4, 12];
    if groups.len() != sizes.len() {
        return Err(format!("is not a canonical uuid: {candidate:?}"));
    }
    for (group, size) in groups.iter().zip(sizes) {
        if group.len() != size
            || !group
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!("is not a canonical uuid: {candidate:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    const INFRASTRUCTURE: &str = "f0e1d2c3-b4a5-4968-8776-655443322110";

    /// La boucle nominale des deux juges, sur les formes exactes que
    /// `cmd/your-cloud` imprime — et rien d'autre : une ligne de trop, un
    /// préfixe déplacé, une casse changée rougissent.
    #[test]
    fn the_two_judges_accept_exactly_what_the_controller_prints() {
        let init = format!("controller_id={CONTROLLER} infrastructure_id={INFRASTRUCTURE}\n");
        initialised(init.as_bytes()).expect("l'init canonique passe");

        let mint = format!(
            "controller_id={CONTROLLER}\ninfrastructure_id={INFRASTRUCTURE}\n\
             reader_serial=9f3ac2\nreader_sha256={}\n",
            "ab".repeat(32)
        );
        minted_reader(mint.as_bytes()).expect("la frappe canonique passe");
    }

    /// Chaque forme relâchée est un refus nommé — les mutations qui
    /// affaibliraient un juge rougissent une par une.
    #[test]
    fn every_loosened_shape_is_refused_by_name() {
        assert!(initialised(b"").is_err());
        assert!(initialised(b"controller_id=abc infrastructure_id=def\n").is_err());
        assert!(initialised(
            format!("controller_id={CONTROLLER} infrastructure_id={INFRASTRUCTURE}\nextra\n")
                .as_bytes()
        )
        .is_err());
        // Majuscule : la forme canonique est minuscule, et la divergence de
        // casse est exactement ce qui casserait l'épinglage du manifeste.
        assert!(initialised(
            format!(
                "controller_id={} infrastructure_id={INFRASTRUCTURE}\n",
                CONTROLLER.to_uppercase()
            )
            .as_bytes()
        )
        .is_err());

        let digest = "ab".repeat(32);
        for hostile in [
            String::new(),
            format!("controller_id={CONTROLLER}\ninfrastructure_id={INFRASTRUCTURE}\n"),
            format!(
                "controller_id={CONTROLLER}\ninfrastructure_id={INFRASTRUCTURE}\n\
                 reader_serial=0abc\nreader_sha256={digest}\n"
            ),
            format!(
                "controller_id={CONTROLLER}\ninfrastructure_id={INFRASTRUCTURE}\n\
                 reader_serial=9f3ac2\nreader_sha256={}\n",
                "AB".repeat(32)
            ),
            format!(
                "controller_id={CONTROLLER}\ninfrastructure_id={INFRASTRUCTURE}\n\
                 reader_serial=9f3ac2\nreader_sha256={digest}\nextra\n"
            ),
        ] {
            assert!(
                minted_reader(hostile.as_bytes()).is_err(),
                "accepté à tort : {hostile:?}"
            );
        }
    }
}

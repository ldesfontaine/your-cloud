#!/usr/bin/env python3
"""Prouve que `tools/check-docs` refuse — un contrôle qui ne peut pas rougir n'en est pas un.

Chaque cas construit un **arbre-fixture** minimal dans un répertoire temporaire
et y injecte un défaut. Aucun test ne mute l'arbre réel : un échec en cours de
route y laisserait le dépôt sale, et un plantage un `docs/` amputé.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_check_docs():
    """Charge `tools/check-docs`, qui n'a pas de suffixe `.py`."""

    spec = importlib.util.spec_from_loader(
        "check_docs",
        importlib.machinery.SourceFileLoader("check_docs", str(ROOT / "tools/check-docs")),
    )
    module = importlib.util.module_from_spec(spec)
    # le module doit être enregistré AVANT son exécution : ses `@dataclass`
    # résolvent leurs annotations via `sys.modules`.
    sys.modules["check_docs"] = module
    spec.loader.exec_module(module)
    return module


def build_tree(base: Path) -> Path:
    """Construit l'arbre minimal qu'un contrôle sain doit accepter."""

    root = base / "arbre"
    (root / "docs/projet").mkdir(parents=True)
    (root / "docs/architecture").mkdir(parents=True)

    (root / "README.md").write_text("# Racine\n", encoding="utf-8")
    (root / "CONTEXT.md").write_text(
        "# Contexte\n\n<!-- coherence: EXEMPLE:start -->\n**Terme**:\nUne définition.\n"
        "<!-- coherence: EXEMPLE:end -->\n",
        encoding="utf-8",
    )
    (root / "docs/README.md").write_text(
        "# Documentation\n\n| Besoin | Source |\n|---|---|\n"
        "| Lire la frontière | [`architecture/FRONTIERE.md`](architecture/FRONTIERE.md) |\n"
        "| Propager | [`projet/COHERENCE.md`](projet/COHERENCE.md) |\n",
        encoding="utf-8",
    )
    (root / "docs/architecture/FRONTIERE.md").write_text(
        "# Frontière\n\n<!-- coherence: EXEMPLE:start -->\n## La frontière\n\nTexte.\n"
        "<!-- coherence: EXEMPLE:end -->\n",
        encoding="utf-8",
    )
    (root / "docs/projet/COHERENCE.md").write_text(
        "# Cohérence\n\n<!-- coherence-registry:start -->\n"
        "| Identifiant | Frontière suivie | Source canonique | Projections obligatoires |\n"
        "|---|---|---|---|\n"
        "| `EXEMPLE` | Une frontière d'exemple | `docs/architecture/FRONTIERE.md` | `CONTEXT.md` |\n"
        "<!-- coherence-registry:end -->\n",
        encoding="utf-8",
    )
    return root


def run(module, root: Path) -> int:
    """Exécute le contrôle en absorbant sa sortie : seul son verdict compte ici."""

    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return module.main(root)


def expect(name: str, module, root: Path, attendu: int) -> bool:
    obtenu = run(module, root)
    ok = obtenu == attendu
    verdict = "OK " if ok else "ÉCHEC"
    mot = "rouge" if attendu else "vert"
    print(f"  [{verdict}] {name} — attendu {mot}, obtenu {'rouge' if obtenu else 'vert'}")
    return ok


def main() -> int:
    module = load_check_docs()
    # les contrôles de fichiers requis visent le vrai dépôt : on les neutralise
    # pour l'arbre-fixture, qui n'a pas vocation à porter toute la carte.
    module.REQUIRED_FILES = ()
    module.HTML_MIRRORS = {}

    resultats: list[bool] = []
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)

        sain = build_tree(base / "sain")
        resultats.append(expect("arbre sain", module, sain, 0))

        # cas hostile 1 — un document qu'aucun index ne nomme
        orphelin = build_tree(base / "orphelin")
        (orphelin / "docs/architecture/PERDU.md").write_text("# Perdu\n", encoding="utf-8")
        resultats.append(expect("orphelin: document non indexé", module, orphelin, 1))

        # cas hostile 2 — une archive que le registre nomme encore
        archive = build_tree(base / "archive")
        cible = archive / "docs/architecture/FRONTIERE.md"
        cible.write_text("# Frontière\n\n" + module.ARCHIVE_MARK + "\n\n" + cible.read_text(encoding="utf-8").split("\n", 1)[1], encoding="utf-8")
        resultats.append(expect("archive: gelée mais nommée par le registre", module, archive, 1))

        # cas hostile 3 — un marqueur orphelin, le refus qui nous a rattrapés
        orphan_marker = build_tree(base / "marqueur")
        p = orphan_marker / "CONTEXT.md"
        p.write_text(p.read_text(encoding="utf-8").replace("EXEMPLE", "INCONNU"), encoding="utf-8")
        resultats.append(expect("marqueur: identifiant inconnu du registre", module, orphan_marker, 1))

    print()
    if all(resultats):
        print(f"check-docs: PASS — {len(resultats)} cas, dont {len(resultats)-1} refus prouvés")
        return 0
    print("check-docs: FAIL — un contrôle n'a pas rendu le verdict attendu", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

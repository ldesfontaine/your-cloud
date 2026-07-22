# Sorties générées

Un artefact produit est un binaire, un paquet ou un installateur destiné à être
installé. Un artefact de preuve est une sortie d’exécution : résultat structuré,
rapport, journal expurgé ou capture.

| Chemin | Contenu | Durée de vie | Versionné |
|---|---|---|---|
| `dist/` | exécutables et paquets construits dans un runner | transitoire | non |
| `artifacts/proofs/<preuve>/<run>/` | résultats, rapports et captures d’un run identifié | audit local ou publication CI sélectionnée | non |
| `artifacts/README.md` | cette convention | durable | oui |

Les vraies sorties CI peuvent être publiées par GitHub, mais le dossier local
reste utile aux preuves LAB qui doivent rapatrier un résultat structuré. Dans
les deux cas, la sortie n’est jamais une dépendance du produit en exécution.

Les fichiers générés sont ignorés par Git. Une publication durable copie un lot
explicitement sélectionné vers le stockage d’artefacts du runner avec ses
empreintes et sa provenance ; elle ne versionne pas silencieusement tout le
dossier.

`build/` est un ancien chemin inutilisé, gardé uniquement dans les règles
d’exclusion afin d’empêcher sa réintroduction accidentelle.

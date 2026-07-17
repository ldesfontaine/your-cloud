# Artefacts générés

Dans ce dossier, un **artefact de preuve** est une sortie produite par une
exécution : résultat structuré, rapport ou capture. Ce n'est pas l'artefact
produit, c'est-à-dire le binaire `your-cloud` déployé sur les VM.

Les emplacements ont des rôles distincts :

| Chemin | Contenu | Durée de vie | Versionné |
|---|---|---|---|
| `dist/` | binaire `your-cloud` compilé dans le runner LAB | transitoire pendant le build et le transfert | non |
| `artifacts/proofs/v0.0.1/<run>/` | toujours `result.json` ; résultat P2, rapports et capture seulement après P1 vert | conservé localement pour l'audit | non |
| `artifacts/proofs/ci/<run>/` | rapports Plumber nominal et hostile validés d'une simulation CI générique | conservés localement pour l'audit | non |
| `artifacts/README.md` | cette convention | durable | oui |

Les sorties générées sont ignorées par Git afin d'éviter d'alourdir le dépôt ou
de confondre code et exécution. Une publication durable devra copier un lot
explicitement sélectionné vers un stockage d'artefacts de CI ; elle ne doit pas
versionner silencieusement tout le dossier.

`build/` est un ancien chemin, désormais inutilisé. Les outils du projet ne
doivent ni le créer ni y publier de sortie ; il reste uniquement ignoré par Git
afin d'éviter de réintroduire accidentellement son ancien contenu.

## Références historiques exécutées pendant la réorganisation

La dernière preuve propre précédant la nouvelle arborescence est le run
`20260717T093905Z-1478107` :

```text
source_lot_sha256=8e2ff3331d58cd5798d425a473bca0fd2682172ef8c83a7831ea65df9a22127c
artifact_sha256=4d58798e7c0f1440af22f631b24f6b99c34491765bb41d1c6fc1f46c365f0d41
result_sha256=0e912eb429da16fa21f53b3d2bf063a142c6bf822cb132207568b88e7482915f
render_result_sha256=28b202ce5569d5c309368c53931ee889604cf76d25c93721653d18e2b76afb89
capture_sha256=9b37f8858e44ed62a649e0de41803ea36882fda384275d2d9e57a051e81da8c1
```

Le run post-réorganisation `20260717T100150Z-1543398` a ensuite réussi depuis
les nouveaux chemins, avant les derniers durcissements du banc et de la CI :

```text
source_lot_sha256=ae7ba5d37158a5fdc100e7e37c45048a654b500b4dd836bb133f5f348b833923
artifact_sha256=4d58798e7c0f1440af22f631b24f6b99c34491765bb41d1c6fc1f46c365f0d41
result_sha256=7f0d62b5db78082d9556b96f477b0e1d85a993e17e34c1c6355e00071a23f1c1
render_result_sha256=1107e4a17b6cd5c1547714e74f7c5732643ebfbbbce0dd0a5eb0b3cccadf9171
capture_sha256=2f2234618dc21871d99c1e58dfbda8b408c58127012cb7cb75f11e0ce41fad05
```

La simulation CI générique historique `20260717T103459Z-1580819` a exécuté le
contrôle source et Plumber sous l'UID `65534`, avant la liaison finale des deux
rapports au lot et leur publication atomique. Son lot source vaut
`a6d558affe8fffc102cc91d06a4084767dec8feed335b84f7e39e2ea1a8f1255`
et son rapport validé
`54f537331b0e403ccd08048e5b42666cc126977594e843cdab31d583c8d4552a`.

`result.json` et les assertions machine restent l'autorité. La page et la
capture ne prouvent que leur rendu ; le score Plumber ne remplace pas le garde
structuré ni les autres tests. Chaque nouveau gel conserve ses identifiants
exhaustifs dans le répertoire de run non versionné afin d'éviter d'auto-référencer
son propre hash dans les sources qu'il mesure.

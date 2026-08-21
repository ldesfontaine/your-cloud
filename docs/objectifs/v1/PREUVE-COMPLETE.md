# Preuve complète de `v0.1.0` : ce qui est rejoué, ce qui est produit

> Statut : proposition de contrat pour le palier `#19`, suivie par `#110`.
> Il fixe ce que « rejouer le scénario entier depuis une base propre »
> signifie exactement, la liste close des artefacts et ce que chacun atteste,
> la règle qui rend une capacité non prouvée bloquante, et la frontière entre
> ce qu'une preuve LAB établit et ce qu'une distribution publique exige. Rien
> ici n'est implémenté tant que ce contrat n'est pas validé.

## Ce que ce palier prouve, et ce qu'il ne peut pas prouver seul

La preuve complète rejoue les capacités que les paliers ont établies une à
une, **dans la même exécution et depuis une topologie réellement détruite
puis recréée**. Ce qu'elle ajoute aux preuves de palier n'est pas une
capacité de plus : c'est la démonstration qu'elles tiennent ensemble, dans
l'ordre, sur des machines qui ne gardaient rien.

Elle ne peut pas, à elle seule, fermer `v0.1.0`. Trois exigences nomment un
**SHA attesté par la porte hébergée** — les issues de palier toutes fermées,
les artefacts correspondant à la révision annoncée, le tag désignant le SHA
de la matrice finale. Aucune exécution locale ne produit cette attestation,
et le contrat le dit ici plutôt que de le laisser découvrir : la preuve
complète est **nécessaire et non suffisante**.

## Depuis une base propre : ce que « propre » veut dire

`Propre` n'est pas « les harnais ont nettoyé derrière eux ». C'est :

```text
tools/labctl topology destroy quick     la topologie cesse d'exister
tools/labctl topology create quick      les machines renaissent de l'image de base
tools/provision-lab all                 le sol est reposé par la recette
```

La destruction précède la première étape et n'est pas supposée : une machine
qui aurait gardé un compte, une plage subordonnée, une table ou une clé d'une
exécution antérieure rendrait la preuve muette sur ce qui la fonde. Les
harnais de palier savent déjà se démonter ; ce que cette preuve ajoute est de
ne pas leur faire confiance sur ce point.

## L'ordre du scénario

Chaque harnais existant est **rejoué tel quel**, jamais réécrit : un harnais
modifié pour cette occasion prouverait autre chose que ce que son palier a
fermé. L'orchestrateur les enchaîne dans l'ordre du produit :

```text
1. amorçage et identités          les preuves du palier #13 disponibles sans porte
2. plan contrôlé et sonde OCI     #14 — le mécanisme, prouvé avant toute charge
3. profil public et entrée        #15 — HTTPS constaté depuis l'extérieur
4. passage privé borné            #16 — le tunnel et ses refus, machine hostile comprise
5. profil privé et sauvegardes    #17 — les deux noms, les données, le retour
6. responsabilité externe         #18 — représenter sans posséder
7. artefacts et rapport           la révision, ses empreintes, ses limites
8. assert-clean                   la topologie ne garde rien
```

Un harnais qui échoue arrête la séquence : la preuve complète n'annonce
jamais un succès partiel, règle que l'orchestrateur du LAB applique déjà.

## Les artefacts : liste close, et ce que chacun atteste

| Artefact | Ce qu'il atteste | Ce qu'il n'atteste pas |
|---|---|---|
| `manifest.json` | la révision exacte, la propreté de l'arbre, la liste des artefacts et leurs empreintes | que cette révision a été attestée par une porte |
| `checksums.txt` | l'empreinte de chaque fichier produit, recalculable depuis le dépôt seul | l'origine des octets d'un tiers |
| `sbom.json` | les composants du produit et leurs versions épinglées, résolus depuis les verrous du dépôt | l'absence de faille dans ces composants |
| `provenance.json` | qui a produit quoi, où, à partir de quelle révision et avec quels outils | une identité reconnue publiquement |
| `report.txt` | ce qui a été constaté sur des machines, avec ses dates et ses limites | ce que le produit ferait sur une infrastructure réelle |

Décisions portées par cette liste :

- **Deux exécutions sur la même révision produisent les mêmes octets.** Une
  date d'exécution ou un chemin de travail dans un artefact rendrait la
  vérification impossible pour un tiers ; ce qui varie appartient au rapport,
  pas au manifeste.
- **Un arbre sale est nommé dans l'artefact, jamais tu.** Le produit sait
  déjà écrire `<sha>+worktree` dans ses rapports de preuve ; un manifeste qui
  tairait cette différence attesterait une révision qui n'existe nulle part.
- **La provenance ne prétend pas à une identité.** Elle dit d'où viennent les
  octets, pas qui en répond ; ce que dit une identité reconnue relève de la
  signature, et la signature publique Windows est encore bloquée.
- **Aucune signature n'entre dans cette liste tant que `#12` n'a pas
  conclu.** Une signature synthétique prouve une mécanique et jamais une
  confiance : la faire figurer parmi les artefacts de release ferait lire
  comme distribuée une chose qui ne l'est pas.

## L'outil qui produit ces artefacts, et comment un tiers le vérifie

[`tools/release-artifacts`](../../../tools/release-artifacts) écrit quatre des
cinq artefacts depuis l'état courant du dépôt — `manifest.json`,
`checksums.txt`, `sbom.json` et `provenance.json`. Le cinquième, `report.txt`,
appartient à la preuve complète : il porte des dates, des machines et des
limites, c'est-à-dire exactement ce que deux exécutions sur une même révision
ne peuvent pas rendre identique. Le manifeste le nomme donc dans la liste close
sans l'empreindre, et dit pourquoi, plutôt que de laisser un lecteur croire la
liste couverte en entier.

```text
tools/release-artifacts produce <répertoire>     écrit les quatre fichiers
tools/release-artifacts check-determinism        produit deux fois et compare
```

Trois propriétés sont tenues par l'outil et non par une intention :

- **Le déterminisme est une commande, pas une promesse.**
  `check-determinism` produit deux fois dans deux répertoires distincts,
  compare octet pour octet et échoue si un seul octet diffère. Aucun horodatage,
  aucun chemin de travail, aucun nom de machine n'entre dans un artefact ; le
  numéro de série du SBOM est dérivé de la révision, jamais tiré au hasard.
- **La vérification n'a besoin de rien de nous.** `checksums.txt` est au format
  exact de `sha256sum`, sans entête ni commentaire :
  `sha256sum -c checksums.txt`, exécuté dans le répertoire, suffit à un tiers.
- **Le refus précède l'écriture.** Un répertoire non vide sans `--force`, un
  dépôt illisible, une chaîne d'outils absente, un verrou absent ou illisible
  arrêtent la production avant qu'un octet soit écrit. Une chaîne d'outils
  manquante est nommée ; elle n'est jamais consignée comme `unknown`.

Le SBOM est un document **CycloneDX 1.6 JSON** : un schéma publié qu'un
validateur du commerce applique sans rien de nous, des consommateurs qui le
lisent déjà, et un document licite sans horodatage — là où un SPDX minimal
impose une date de création, donc deux exécutions qui ne rendent pas les mêmes
octets. Ses composants sont résolus depuis les verrous versionnés — `go.mod` et
`go.sum`, `app/src-tauri/Cargo.lock`, `app/package-lock.json` — et
depuis les images OCI épinglées, relues dans `internal/plan` plutôt que
redites ici. Aucun registre n'est interrogé à la production.

Ce que cet outil ne couvre pas, et le manifeste l'écrit : les charges
distribuables. Le `.deb` serveur Debian 13 `amd64` et les installateurs App
sont construits ailleurs et liés par leur propre manifeste signé ; ce jeu
d'artefacts n'en porte aucun octet.

### Le rapport est nommé par le manifeste et scellé par sa propre course

Un lecteur attentif verra que `report.txt` figure dans la liste close sans
empreinte au manifeste, et la question mérite mieux qu'un silence : sans
rien pour le sceller, un rapport se réécrit.

La réponse tient à ce que chaque document atteste. Les quatre premiers
artefacts parlent d'une **révision** : mêmes octets, deux fois, sur la même
révision, c'est ce qui les rend vérifiables par un tiers qui ne détient que
le dépôt. Le rapport parle d'une **course** : ses dates, ses machines et ses
limites sont précisément ce que deux exécutions ne peuvent pas rendre
identique. Mettre son empreinte dans le manifeste ferait varier le manifeste
d'une course à l'autre et détruirait la propriété qui fonde les quatre
autres.

La preuve complète écrit donc, à côté de son rapport, un
`proof-checksum.txt` au même format que `checksums.txt`, couvrant le seul
rapport. Un tiers vérifie alors deux choses distinctes avec le même outil du
système : que les quatre artefacts sont ceux de cette révision, et que le
rapport qu'il lit est celui que cette course a produit. Deux portées, deux
fichiers, aucune des deux ne prétendant à l'autre.

## La procédure de tag : relier version, SHA et artefacts, dans cet ordre

Le tag `v0.1.0` est le dernier geste, jamais un geste préparatoire, et il est
préparé ici pour n'être improvisé nulle part (`#55`). L'identité de release a
une source unique — `app/package.json` — que le contrat des sources
App fait rayonner sur les manifestes, les verrous, la constante
d'observation du Daemon et les artefacts ; le tag ne fait que la relier au
SHA que la matrice hébergée a attesté.

Préconditions, toutes vérifiées sur le même SHA candidat :

1. la matrice native `workflow_dispatch` est entièrement verte sur ce SHA
   exact ; `tools/ci-usage --guard 100` la précède toujours, mais depuis le
   passage du dépôt en public il **enregistre** la consommation au lieu de la
   borner ([contrat de CI](../../contribution/CI.md)) ;
2. la preuve complète est verte sur ce SHA, arbre propre, et ses artefacts
   portent `release.version` égal à la version de `app/package.json` ;
3. les issues de palier requises sont fermées, et le suivi le montre.

Le geste, alors :

```text
git rev-parse HEAD                        le SHA local est le SHA attesté
git status --porcelain                    l'arbre est propre, rien d'autre
git tag -a v0.1.0 -m "Your Cloud 0.1.0" <sha-atteste>
git rev-parse 'v0.1.0^{commit}'           le tag déréférencé rend le même SHA
git push origin v0.1.0                    l'unique écriture, après accord
```

Deux règles ferment la procédure : un tag publié ne bouge jamais — une erreur
découverte après le push reçoit un numéro suivant, jamais un re-tag — et
aucune preuve antérieure n'est réattribuée au tag d'un autre SHA. La
vérification d'un tiers reste celle des artefacts : `sha256sum -c` dans le
répertoire publié, puis le rapprochement du champ `release.version` du
manifeste, du tag et du SHA qu'il déréférence.

## La règle de blocage, sans exception implicite

**Toute capacité que la preuve complète n'établit pas est annoncée comme non
prouvée, et empêche la release.** La règle n'admet ni « prouvé ailleurs », ni
« prouvé en unitaire », ni « prouvé à un palier précédent » comme substitut
silencieux : ce qui est prouvé autrement est nommé avec la forme exacte de sa
preuve, et cette forme est lisible dans le rapport.

Sont déjà connues, et le rapport les portera :

- l'App n'est pas exercée par les harnais LAB ; sa surface est prouvée
  par sa propre suite, et la fenêtre native de consentement n'est pas câblée ;
- les signatures des preuves passent par des fixtures synthétiques, la
  App ne signant pas dans ces exécutions ;
- le TLS des preuves est une autorité synthétique du run ;
- aucune de ces exécutions n'a vu de porte hébergée ;
- `arm64` n'est pas prouvé ;
- la distribution publique Windows reste bloquée.

## Ce que le rapport doit dire de la topologie

Le rapport nomme la topologie **scénario LAB de référence** et jamais
infrastructure imposée. Les profils y sont écrits comme des charges
explicitement sélectionnées, et la phrase que chaque contrat de profil porte
déjà — rien n'est créé sans déclaration, placement, plan et approbation — est
celle que le rapport final reprend. Un lecteur qui découvrirait le produit par
ce rapport doit en sortir sachant ce qu'il peut choisir, pas ce qu'il devra
subir.

## Ce que la preuve devra constater

1. la topologie a été détruite puis recréée, et le rapport le montre ;
2. chaque harnais de palier passe dans la même exécution, sans modification ;
3. les artefacts sont produits, rattachés à la révision, et deux exécutions
   sur la même révision les rendent identiques ;
4. chaque empreinte est recalculable depuis le dépôt seul ;
5. les limites ci-dessus figurent nommément dans le rapport ;
6. `tools/labctl assert-clean` est vert à la fin, sans exception ajoutée à la
   main.

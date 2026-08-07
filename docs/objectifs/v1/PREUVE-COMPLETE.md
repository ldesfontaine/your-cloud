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

## La règle de blocage, sans exception implicite

**Toute capacité que la preuve complète n'établit pas est annoncée comme non
prouvée, et empêche la release.** La règle n'admet ni « prouvé ailleurs », ni
« prouvé en unitaire », ni « prouvé à un palier précédent » comme substitut
silencieux : ce qui est prouvé autrement est nommé avec la forme exacte de sa
preuve, et cette forme est lisible dans le rapport.

Sont déjà connues, et le rapport les portera :

- la Console n'est pas exercée par les harnais LAB ; sa surface est prouvée
  par sa propre suite, et la fenêtre native de consentement n'est pas câblée ;
- les signatures des preuves passent par des fixtures synthétiques, la
  Console ne signant pas dans ces exécutions ;
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

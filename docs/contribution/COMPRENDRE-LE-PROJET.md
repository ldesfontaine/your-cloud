# Comprendre le projet avant d'agir

## Ce que ce document rend visible

Ce document expose la méthode de qualification d'un travail sur Your Cloud :
quelles sources sont lues, dans quel ordre, pourquoi elles le sont et quels
contrôles précèdent une modification. Il permet de reproduire l'analyse à
partir des mêmes faits et de challenger ses hypothèses.

## Ordre de lecture

### 1. Préserver l'état réel

La première lecture porte sur Git : branche, état du worktree, fichiers non
suivis et diff des sources susceptibles d'être touchées. Cette étape empêche de
prendre une ancienne version pour l'état courant ou d'écraser un travail déjà
présent.

Les changements existants sont présumés en cours et restent préservés tant que
leur origine et leur périmètre ne permettent pas de les intégrer sans conflit.

### 2. Router par la carte documentaire

[`docs/README.md`](../README.md) est ouvert avant les documents métier. Il dit
où se trouve l'autorité de chaque sujet et évite deux erreurs symétriques : lire
tout le dépôt sans hiérarchie ou choisir un fichier familier qui n'est pas la
source du sujet.

### 3. Charger le socle correspondant à la tâche

| Question posée | Source lue | Pourquoi |
|---|---|---|
| Que signifie un terme ou une relation ? | [`CONTEXT.md`](../../CONTEXT.md) | Fixer le vocabulaire sans en déduire une implémentation |
| Quelle est la destination durable ? | [`projet/CAP.md`](../projet/CAP.md) | Distinguer le cap des limites d'un palier courant |
| Qu'est-ce qui ferme `v0.1.0` ? | [`objectifs/v1/README.md`](../objectifs/v1/README.md) | Lire les conditions de réussite avant la liste des travaux |
| Dans quel ordre avancer ? | [`objectifs/v1/ROADMAP.md`](../objectifs/v1/ROADMAP.md) | Identifier le palier ouvert, ses dépendances et son état décidé, implémenté ou prouvé |
| Quel comportement exact doit être livré ? | Le contrat du palier sous `docs/objectifs/` | Borner entrées, sorties, refus et preuve avant le code |
| Où vivent les composants et autorités ? | [`architecture/ANATOMIE.md`](../architecture/ANATOMIE.md), puis la fiche d'architecture concernée | Vérifier les frontières et les flux sans inventer une autorité |
| Comment contribuer ou modifier du code ? | [`contribution/README.md`](README.md), puis [`QUALITE.md`](QUALITE.md) | Appliquer les règles de changement minimal, de qualité et de sécurité |
| Comment tester ou prouver ? | [`TESTS.md`](TESTS.md), puis [`lab/README.md`](../lab/README.md) | Distinguer un contrôle planifié d'une preuve exécutée et choisir le bon environnement |
| Comment changer une décision transverse ? | [`projet/COHERENCE.md`](../projet/COHERENCE.md) | Modifier d'abord la source canonique puis toutes ses projections |
| Comment modifier GitHub Actions ? | [`CI.md`](CI.md), puis `.github/workflows/` et leurs gardes | Préserver permissions, menaces, checks requis et assertions de sécurité |
| Comment ouvrir le travail ? | [`ISSUES.md`](ISSUES.md) | Transformer seulement un résultat décidé en contrat d'exécution |

Seules les lignes utiles à la demande sont chargées. Une architecture complète
n'est pas relue pour corriger un libellé local, mais une décision transverse
impose la source et toutes les projections déclarées.

### 4. Confronter la documentation au réel

Après le contrat, la lecture cible le code, les tests, les scripts et les
workflows qui réalisent ou prétendent réaliser ce contrat. Une recherche par
terme et par chemin précède la lecture détaillée. Les dépendances proches sont
ouvertes seulement lorsqu'elles influencent le résultat.

Une capture, une proposition externe ou un exemple trouvé ailleurs fournit une
hypothèse de conception. Elle n'établit pas l'état du dépôt. L'analyse vérifie
d'abord si le mécanisme existe déjà, quel problème concret subsiste et quelles
protections seraient affectées par le changement.

### 5. Séparer les niveaux de vérité

Chaque conclusion distingue au minimum :

- **documenté** : une source canonique l'affirme ;
- **implémenté** : du code ou une configuration matérialise le contrat ;
- **exécuté** : le comportement a réellement tourné dans l'environnement nommé ;
- **prouvé** : les assertions annoncées ont réussi et leurs limites sont
  conservées.

Un blocage de preuve n'est pas automatiquement un blocage de documentation ou
de conception. Inversement, un document cohérent n'est pas une preuve runtime.

### 6. Décider avant d'élargir

Les ambiguïtés levables dans le dépôt sont investiguées. S'il reste plusieurs
interprétations qui changent l'objectif, la sécurité, l'autorité ou un effet
sensible, elles sont présentées avec leur compromis et une décision est
demandée. Une hypothèse sûre et réversible peut permettre de continuer si elle
ne change pas le sens du travail ; elle est alors annoncée.

Une idée voisine utile est notée comme hors périmètre ou future issue. Elle ne
devient pas une fonctionnalité, une abstraction ou une refactorisation cachée.

### 7. Vérifier et rendre compte

Chaque changement se termine par le contrôle automatisé proportionné, la
relecture du diff et la vérification que chaque ligne se rattache à la demande.
Une décision documentaire propagée passe par `tools/check-docs`. Les contrôles
statiques peuvent s'exécuter sur le poste ; produit, tests, builds et preuves
s'exécutent uniquement dans le LAB ou un runner isolé autorisé.

Le compte rendu final nomme : résultat, fichiers modifiés, preuves exécutées,
limites et prochaine étape sûre. Il ne transforme pas un contrôle plus faible
en affirmation plus forte.

## Exemple : évolution de la CI et du suivi des travaux

Pour évaluer un graphe GitHub Actions et faire évoluer le suivi de `v0.1.0` par issues,
le jeu de lecture minimal est :

1. Git et le diff, pour préserver le travail en cours ;
2. la carte documentaire et les règles de contribution ;
3. `CI.md` et `.github/workflows/ci.yml`, pour comparer l'image au découpage
   réellement implémenté et à ses gardes ;
4. la roadmap de `v0.1.0`, pour ne pas confondre ordre produit et file d'exécution ;
5. `COHERENCE.md`, pour savoir où propager la pratique validée ;
6. les sources officielles GitHub utiles, car les comportements des relances,
   checks requis et issues évoluent hors du dépôt.

Cette lecture permet de conclure séparément sur ce qui existe déjà, ce qui peut
être amélioré et ce qui mérite une issue autonome avant toute modification de
la CI.

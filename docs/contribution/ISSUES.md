# Piloter le travail avec GitHub Issues

## Rôle des issues

La roadmap V1 reste la source canonique de l'ordre des preuves et des limites du
produit. Une issue GitHub est un **contrat d'exécution** : elle transforme une
partie suffisamment décidée de cette roadmap en travail borné, attribuable et
vérifiable. Fermer une issue ne modifie pas à lui seul l'état documenté,
implémenté ou prouvé du projet.

Les issues servent à savoir quoi attaquer maintenant, à rattacher les branches,
pull requests et preuves, et à conserver les blocages visibles. Elles ne servent
ni à décider silencieusement le produit, ni à dupliquer toute la roadmap.

## Niveau de découpage

Le suivi jusqu'à la V1 utilise cette hiérarchie :

1. la [roadmap V1](../objectifs/v1/ROADMAP.md) fixe l'ordre canonique ;
2. l'[issue de suivi V1](https://github.com/ldesfontaine/your-cloud/issues/20)
   relie les paliers qui contribuent réellement à cette ligne d'arrivée ;
3. chaque palier ou étape décidé possède une issue de suivi ;
4. une issue parente représente ce palier lorsqu'il exige plusieurs
   résultats indépendants ;
5. une sous-issue représente un résultat qui peut être réalisé et vérifié sans
   fermer artificiellement tout le palier ;
6. une pull request livre par défaut une seule issue et la relie explicitement.

Un tableau GitHub Project peut être ajouté si le volume rend la liste d'issues
difficile à lire. Il reste une vue : ni ses colonnes, ni un milestone, ni une
issue parente ne deviennent une nouvelle source produit.

Inscrire un palier décidé dans la roadmap implique donc de créer ou relier son
issue dans le même travail. Un palier futur peut rester une issue de suivi
macroscopique. Avant de commencer son implémentation, il est découpé en
sous-issues actionnables dont chacune connaît les quatre éléments suivants :

- un résultat observable ;
- un périmètre et un hors-périmètre ;
- des critères d'acceptation ;
- une preuve proportionnée et son environnement d'exécution.

Une incertitude qui doit être levée avant ce découpage reçoit une issue de
décision séparée. Elle annonce la question à trancher et ne mélange pas étude et
implémentation.

## Milestone active du palier #13

Le palier d'amorçage et de remplacement du Controller utilise la milestone
[V1 — Amorçage et remplacement du Controller](https://github.com/ldesfontaine/your-cloud/milestone/1)
comme vue de suivi. Elle regroupe l'issue parente
[#13](https://github.com/ldesfontaine/your-cloud/issues/13), la décision #34,
les contrats exécutables #35 à #40 et la preuve globale #41. Le suivi transversal
de toute la V1 reste porté par [#20](https://github.com/ldesfontaine/your-cloud/issues/20),
hors de cette milestone.

Aucune date d'échéance arbitraire ne lui est attachée. Elle n'est fermée qu'après
la preuve globale #41, la propagation documentaire et la fermeture de #13 ; sa
fermeture ne prouve rien de plus que les preuves reliées par ces issues. Elle
termine ce palier d'amorçage et permet d'ouvrir #14 ; elle ne ferme ni le suivi
#20, ni la V1 complète.

## Convention de titre

Le titre reprend la grammaire des commits sans prétendre étendre la
spécification Conventional Commits aux issues :

```text
type(scope): résultat observable
```

Types usuels :

- `feat` pour une capacité produit ;
- `fix` pour un comportement incorrect ;
- `docs` pour une source documentaire ;
- `test` pour une preuve ou un refus hostile ;
- `ci` pour l'automatisation et les runners ;
- `refactor` pour une transformation sans changement de contrat ;
- `chore` pour un travail d'entretien borné.

Le `scope` nomme le domaine stable le plus étroit, par exemple `console`,
`controller`, `agent`, `relay`, `lab` ou `ci`. Le reste du titre décrit le
résultat, pas l'action vague « travailler sur ».

Exemples :

```text
ci(console): router les contrôles selon les chemins modifiés
test(windows): prouver le lancement du MSI sans listener local
docs(v1): propager le contrat d'amorçage dans la roadmap
```

## Contenu obligatoire

Le modèle [`.github/ISSUE_TEMPLATE/01-travail.md`](../../.github/ISSUE_TEMPLATE/01-travail.md)
demande :

- les sources canoniques et le contexte factuel ;
- le résultat observable ;
- le périmètre et le hors-périmètre ;
- les critères d'acceptation ;
- les preuves attendues, avec leur environnement ;
- les dépendances, blocages et décisions encore ouvertes.

Les critères décrivent ce qui doit être vrai. La section de preuve indique
comment l'observer. Une liste d'étapes d'implémentation ne remplace aucun des
deux.

## Ouverture, branche et pull request

L'auteur visible d'une issue est le compte GitHub authentifié qui l'ouvre. Toute
ouverture automatisée doit être explicitement autorisée et interrompue si
l'identité authentifiée n'est pas celle du mainteneur attendu. Le contenu public
ne reçoit ni signature d'outil, ni mention décorative sans rapport avec le
travail.

Une ouverture groupée définit au préalable les titres, relations parent-enfant,
dépendances et milestone. Elle ne publie ni données personnelles, ni secrets,
ni chemins locaux, ni notes de réflexion : seulement les faits et contrats
nécessaires à un développeur pour réaliser le travail.

Par défaut :

- la branche se nomme `type/numero-resume-court` ;
- les commits gardent la forme `type(scope): action` ;
- la pull request référence l'issue et utilise `Closes #numero` seulement si
  elle satisfait réellement tous ses critères ;
- un nouveau besoin hors périmètre devient une autre issue au lieu d'élargir la
  pull request en silence.

## Fermeture

Une issue est fermée lorsque ses critères sont satisfaits, les vérifications
annoncées sont exécutées, les limites restantes sont nommées et les documents
canoniques concernés sont propagés. Une preuve manuelle indique ses
préconditions, son action, son résultat attendu et son résultat observé.

Un blocage externe ne transforme pas un travail non prouvé en travail terminé.
L'issue reste ouverte ou porte explicitement son blocage et la prochaine action
sûre. Une issue parente n'est fermée que lorsque toutes les sous-issues exigées
par son résultat le sont et que la preuve globale du palier existe.

## Références

- [GitHub — planifier et suivre le travail](https://docs.github.com/en/issues/tracking-your-work-with-issues/learning-about-issues/planning-and-tracking-work-for-your-team-or-project) ;
- [GitHub — issues, sous-issues, dépendances et métadonnées](https://docs.github.com/en/issues/tracking-your-work-with-issues/learning-about-issues/about-issues) ;
- [GitHub — modèles et formulaires d'issue](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates).

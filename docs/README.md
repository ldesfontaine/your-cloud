# Documentation

Cette page est l'entrée unique de la documentation active de Your Cloud. Elle
indique où lire une information et évite de charger tout le dépôt pour répondre
à une question précise.

## Lire selon le besoin

| Besoin | Source à ouvrir |
|---|---|
| Comprendre les termes du produit | [`CONTEXT.md`](../CONTEXT.md) |
| Comprendre la destination à long terme | [`projet/CAP.md`](projet/CAP.md) |
| Savoir dans quel ordre le produit avance | [`projet/DIRECTION.md`](projet/DIRECTION.md) |
| Relire ce qui devait être vrai pour `v0.1.0` — **objectif atteint** | [`objectifs/v1/README.md`](objectifs/v1/README.md) |
| Relire l'ordre des preuves qui a mené à `v0.1.0` — **objectif atteint** | [`objectifs/v1/ROADMAP.md`](objectifs/v1/ROADMAP.md) |
| Relire le contrat de l'App cliente et du Controller de lecture `v0.0.3` — **archive datée** | [`objectifs/v1/CONTRAT-V0.0.3.md`](objectifs/v1/CONTRAT-V0.0.3.md) |
| Comprendre les machines, composants et flux | [`architecture/ANATOMIE.md`](architecture/ANATOMIE.md) |
| Comprendre l'amorçage et le remplacement du Controller | [`architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md`](architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md) |
| Connaître la frontière de la chaîne d'observation, puis ses appels, données et états | [`architecture/CHAINE-D-OBSERVATION.md`](architecture/CHAINE-D-OBSERVATION.md) |
| Savoir ce que Your Cloud peut faire d'un service, et pourquoi | [`architecture/SERVICES-DECOUVERTE-ET-REPRISE.md`](architecture/SERVICES-DECOUVERTE-ET-REPRISE.md) |
| Connaître la frontière du réseau interne : qui parle à qui, et sous quelle autorisation | [`architecture/RESEAU.md`](architecture/RESEAU.md) |
| Connaître la frontière de l'exposition publique et le sort des identités présentées | [`architecture/POINT-D-ENTREE.md`](architecture/POINT-D-ENTREE.md) |
| Savoir ce que Your Cloud pose quand un service exige une connexion | [`architecture/PROFIL-AUTHELIA.md`](architecture/PROFIL-AUTHELIA.md) |
| Comprendre comment déployer, publier ou migrer un service | [`architecture/CYCLE-DE-VIE-DES-SERVICES.md`](architecture/CYCLE-DE-VIE-DES-SERVICES.md) |
| Savoir comment une version est vue, choisie, gelée et remplacée | [`architecture/VERSIONS-ET-MISES-A-JOUR.md`](architecture/VERSIONS-ET-MISES-A-JOUR.md) |
| Contribuer ou travailler avec un agent | [`contribution/README.md`](contribution/README.md) |
| Comprendre comment le dépôt est lu avant d'agir | [`contribution/COMPRENDRE-LE-PROJET.md`](contribution/COMPRENDRE-LE-PROJET.md) |
| Organiser la roadmap en issues exécutables | [`contribution/ISSUES.md`](contribution/ISSUES.md) |
| Lire les exigences de qualité | [`contribution/QUALITE.md`](contribution/QUALITE.md) |
| Consulter la stratégie et le registre d'automatisation | [`contribution/TESTS.md`](contribution/TESTS.md) |
| Comprendre la CI, ses permissions et ses limites | [`contribution/CI.md`](contribution/CI.md) |
| Préparer ou vérifier une preuve LAB | [`lab/README.md`](lab/README.md) |
| Propager une décision validée | [`projet/COHERENCE.md`](projet/COHERENCE.md) |
| Ouvrir la documentation visuelle | [`html/index.html`](html/index.html) |

Un objectif marqué **atteint** se relit comme un récit : il dit ce que le
produit devait rendre et l'a rendu, pas ce qu'il vise maintenant. La
destination à long terme se lit dans [`projet/CAP.md`](projet/CAP.md).

## Organisation

```text
docs/
|- projet/          cap, direction et cohérence des sources
|- objectifs/
|  `- v1/           objectif ATTEINT : ligne d'arrivée et roadmap de v0.1.0
|- architecture/    placements, autorités et futurs sujets techniques
|- contribution/    manière de travailler et qualité
|- lab/             règles et preuves réellement exécutées
`- html/            vues visuelles dérivées des sources Markdown
```

Un sujet d'architecture obtient son propre fichier seulement lorsqu'il possède
un contrat autonome. Un sous-répertoire n'est créé que lorsque ce sujet exige
plusieurs documents. Cette création reste paresseuse afin d'éviter les fichiers
vides et les sources concurrentes.

Les ADR seront créés sous `docs/adr/` uniquement lorsqu'une décision est à la
fois difficile à renverser, surprenante sans son contexte et issue d'un
véritable compromis. Aucun répertoire vide ni ADR de rangement n'est créé à
l'avance.

## Sources et vues

Le Markdown est la source éditoriale. Les pages de `html/` sont des vues
visuelles dérivées : elles doivent évoluer avec leur source, mais ne décident
jamais seules du produit.

Après une décision transverse ou un déplacement documentaire :

```text
tools/check-docs
```

Ce contrôle vérifie la carte documentaire, les projections déclarées et les
liens. Une relecture humaine reste nécessaire pour valider le sens.

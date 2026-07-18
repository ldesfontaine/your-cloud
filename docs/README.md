# Documentation

Cette page est l'entrée unique de la documentation active de Your Cloud. Elle
indique où lire une information et évite de charger tout le dépôt pour répondre
à une question précise.

## Lire selon le besoin

| Besoin | Source à ouvrir |
|---|---|
| Comprendre les termes du produit | [`CONTEXT.md`](../CONTEXT.md) |
| Comprendre la destination à long terme | [`projet/CAP.md`](projet/CAP.md) |
| Savoir ce qui doit être vrai pour la V1 | [`objectifs/v1/README.md`](objectifs/v1/README.md) |
| Voir l'ordre des preuves jusqu'à la V1 | [`objectifs/v1/ROADMAP.md`](objectifs/v1/ROADMAP.md) |
| Comprendre les machines, composants et flux | [`architecture/ANATOMIE.md`](architecture/ANATOMIE.md) |
| Comprendre les appels, données, états et protections de la chaîne d'observation | [`architecture/CHAINE-D-OBSERVATION.md`](architecture/CHAINE-D-OBSERVATION.md) |
| Comprendre comment déployer, publier ou migrer un service | [`architecture/CYCLE-DE-VIE-DES-SERVICES.md`](architecture/CYCLE-DE-VIE-DES-SERVICES.md) |
| Contribuer ou travailler avec un agent | [`contribution/README.md`](contribution/README.md) |
| Lire les exigences de qualité | [`contribution/QUALITE.md`](contribution/QUALITE.md) |
| Consulter la stratégie et le registre d'automatisation | [`contribution/TESTS.md`](contribution/TESTS.md) |
| Comprendre la CI, ses permissions et ses limites | [`contribution/CI.md`](contribution/CI.md) |
| Préparer ou vérifier une preuve LAB | [`lab/README.md`](lab/README.md) |
| Propager une décision validée | [`projet/COHERENCE.md`](projet/COHERENCE.md) |
| Ouvrir la documentation visuelle | [`html/index.html`](html/index.html) |

## Organisation

```text
docs/
|- projet/          cap et cohérence des sources
|- objectifs/
|  `- v1/           ligne d'arrivée et roadmap de la V1
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

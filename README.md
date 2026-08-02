# Your Cloud

Your Cloud permet de représenter une infrastructure, d'observer ses machines et
de déployer des services depuis une interface compréhensible, sans masquer les
opérations réellement exécutées.

## Construction vérifiable

Chaque capacité est d'abord définie, puis implémentée et enfin prouvée dans un
environnement isolé. La documentation distingue explicitement ces trois états.

[`tools/labctl`](tools/labctl) contrôle les machines du LAB. Sa
présence ne prouve aucune capacité du produit.

## Sources actives

- [Carte documentaire](docs/README.md) : le point d'entrée et le chemin de
  lecture selon le sujet.
- [Cap du projet](docs/projet/CAP.md) : la destination à long terme et les
  limites durables.
- [Objectif `v0.1.0`](docs/objectifs/v1/README.md) : la première ligne d'arrivée
  concrète.
- [Roadmap `v0.1.0`](docs/objectifs/v1/ROADMAP.md) : l'ordre des preuves nécessaires
  pour atteindre cette ligne d'arrivée, sans planifier les versions postérieures.
- [Contexte](CONTEXT.md) : le petit glossaire commun.
- [Qualité du code](docs/contribution/QUALITE.md) : les règles appliquées à
  chaque changement.
- [Cohérence documentaire](docs/projet/COHERENCE.md) : le rôle de chaque
  source et la propagation des décisions transverses.
- [Anatomie du projet](docs/architecture/ANATOMIE.md) : le placement, les flux
  et leur [vue HTML visuelle](docs/html/anatomie.html), mis à jour au fil du
  développement.
- [Amorçage et remplacement du Controller](docs/architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md) :
  l'autorité SSH initiale, l'approbation des actions, son transfert et le
  parcours de remplacement décidé pour `v0.1.0`.
- [Documentation visuelle](docs/html/index.html) : l'entrée vers toutes les
  éditions HTML.
- [LAB](docs/lab/README.md) : le contrôleur et ses gardes.

Après toute modification d'une décision transverse, le contrôle statique est :

```text
tools/check-docs
```

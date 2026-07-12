# Projet de console d’infrastructure

> Le nom du produit reste à choisir. Le dépôt emploie temporairement une
> description fonctionnelle afin de ne pas transformer un nom de travail en
> décision de marque.

Ce projet construit une console souveraine qui enrôle, observe et fait évoluer
des infrastructures Linux sans donner au chemin de télémétrie une autorité
d’administration et sans rendre les services dépendants du pilotage.

La V1 repose sur trois composants :

- une console Python sur le poste Linux approuvé de l’opérateur ;
- un daemon Go léger et en lecture seule sur chaque machine gérée ;
- un coordinateur Go remplaçable qui conserve uniquement la télémétrie.

Le chemin de changement reste séparé : la console présente un plan puis atteint
directement les machines par SSH et Ansible après approbation.

## Comprendre le fonctionnement pas à pas

L'[Anatomie du projet](docs/ANATOMIE-DU-PROJET.md) suit le code depuis le
premier audit SSH jusqu'à la publication mTLS, la seconde vérification des
signatures et la reprise après coupure. Une
[édition HTML interactive](docs/anatomie-du-projet.html) permet d'explorer les
flux installation, publication, lecture et panne.

## Lire le projet

- [Anatomie technique](docs/ANATOMIE-DU-PROJET.md)
- [Vision](docs/VISION.md)
- [Guide du bâtisseur](docs/GUIDE-DU-BATISSEUR.md)
- [Scénario simple VPS + mini-PC](docs/SCENARIO-VPS-MINI-PC.md)
- [Installation et premier audit](docs/INSTALLATION.md)
- [Roadmap](docs/ROADMAP.md)
- [Contrat des releases](docs/RELEASES.md)
- [Vocabulaire partagé](CONTEXT.md)
- [Registre des décisions](docs/adr/REGISTRE.md)
- [Spécifications](docs/specifications/README.md)
- [Laboratoire](docs/lab/README.md)

Le développement suit la roadmap par paliers. Aucun code de l’ancienne lignée
n’est repris par défaut ; son archive reste séparée de ce produit.

## Arborescence de construction

Les frontières de P0 accueillent progressivement le code des paliers :

```text
console/       console Python, audit, enrôlement et inspection signée
daemon/        daemon Go d’observation sans port entrant
coordinateur/  coordinateur Go de télémétrie
protocole/     contrats Protobuf et sorties générées versionnées
engine/        contenu Ansible exécuté depuis la console dans le LAB
tools/         contrôleurs d’atelier, distincts du produit
```

Le coordinateur local, le transport mTLS et la reprise après coupure sont
implémentés depuis P4. P5 ajoute le même point en mode distant, la migration par
pilote avec ancien endpoint conservé, son retrait séparé et le LAB réseau
complet. Les preuves exécutées vivent dans `docs/lab/`.

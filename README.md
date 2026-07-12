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

## Lire le projet

- [Vision](docs/VISION.md)
- [Guide du bâtisseur](docs/GUIDE-DU-BATISSEUR.md)
- [Roadmap](docs/ROADMAP.md)
- [Contrat des releases](docs/RELEASES.md)
- [Vocabulaire partagé](CONTEXT.md)
- [Registre des décisions](docs/adr/REGISTRE.md)
- [Spécifications](docs/specifications/README.md)
- [Laboratoire](docs/lab/README.md)

Le développement suit la roadmap par paliers. Aucun code de l’ancien wrapper
Ansible/k3s n’est repris par défaut ; son histoire reste disponible sur la
branche `old-project`.

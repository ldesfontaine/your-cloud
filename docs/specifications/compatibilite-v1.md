# Compatibilité V1

> État : cible de construction P0, non encore prouvée.

La V1 prend officiellement en charge Debian 13 `trixie` sur amd64 uniquement.
Une cible différente est refusée avant toute mutation ou enrôlement partiel.

Cette limite s’applique ensemble :

- aux machines gérées ;
- aux gabarits du LAB ;
- aux rôles Ansible ;
- aux paquets, binaires et unités systemd installés ;
- aux preuves de release.

Debian 12 et ARM64 pourront être étudiés après la première release stable. Le
code évite les dépendances inutiles à amd64, mais aucune compatibilité n’est
annoncée sans environnement réel de test et sans coût de maintenance accepté.

Les images, dépendances et outils sont toujours épinglés à une version ou à un
artefact vérifiable ; `latest` n’est jamais une version admissible.

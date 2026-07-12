# Exécuter le développement exclusivement dans un LAB isolé

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

Le laptop de développement détient des autorités d’administration. Exécuter un
playbook, un binaire en construction ou des tests ayant des effets système sur
ce poste confondrait environnement de contrôle et cible.

## Décision

- Le laptop sert à l’édition, Git, l’inspection, aux validations statiques sans
  import du projet et au contrôle de `labctl`.
- Aucun binaire, test, build, serveur, playbook, dépendance ou import exécutable
  du projet n’y est lancé.
- La console de développement, les composants Go, Ansible et les scénarios
  tournent dans des VM KVM/libvirt ou un runner distant d’isolation équivalente.
- Le LAB rapide couvre les boucles quotidiennes ; le LAB complet reproduit les
  frontières opérateur, public simulé et site privé pour l’intégration.
- Les VM utilisent uniquement des secrets synthétiques et aucune adresse de
  production comme cible de test.
- `labctl` reste le contrôleur du LAB, distinct du produit testé.

## Conséquences

Les validations sont plus coûteuses qu’une exécution locale mais reproduisent
Linux, systemd, Ansible et les frontières réseau sans exposer le poste
d’autorité. Cette règle d’atelier n’interdit pas qu’une console publiée soit un
jour installée sur un poste Linux explicitement approuvé.

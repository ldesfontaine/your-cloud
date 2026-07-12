# Réemploi de l’ancienne lignée

> État : audit statique P0 du 2026-07-12. Aucun code de `old-project` n’a été
> exécuté et aucun secret historique n’a été lu.

## Décision

Le nouveau `main` ne reprend aucun composant applicatif de l’ancien wrapper.
L’histoire complète reste consultable sur `old-project`, ce qui permet de
réexaminer une pièce précise sans transporter son architecture dans la V1.

Un seul outil est adapté dès P0 : `labctl`. Sa nouvelle version conserve les
mécanismes libvirt déjà éprouvés — absence de `sudo`, volumes gérés par l’API,
image datée vérifiée par SHA512, seed NoCloud, snapshots et validation des
noms — mais remplace ses gabarits, réseaux, métadonnées et commandes de
topologie. Il s’agit d’une adaptation relue, pas d’une copie déclarée compatible.

## Inventaire examiné

| Ensemble historique | Décision P0 | Motif |
|---|---|---|
| `src/infractl/` | ne pas reprendre | La CLI et l’orchestrateur pilotent un moteur Ansible local sur la cible et portent le parcours k3s de l’ancien produit. |
| `src/infractl/engine/` | ne pas reprendre | Les rôles mêlent durcissement, WireGuard, k3s, IAM et applications, alors que la nouvelle V1 sépare le profil Linux de toute génération de services. |
| `spikes/` et `drill/` | conserver sur `old-project` | Ce sont des preuves historiques liées à Debian 12 et à l’ancienne topologie, pas des tests de la nouvelle lignée. |
| `tests/` | ne pas reprendre | Ils vérifient les contrats et modules de l’ancien wrapper ; les déplacer donnerait une fausse impression de couverture. |
| `pyproject.toml` | repartir à P1 | Le nom, les points d’entrée et les dépendances `ansible-core`, PyYAML et pytest appartiennent à l’ancien paquet. Les pins de la nouvelle console seront choisis avec son premier squelette. |
| anciens ADR et runbooks | conserver sur `old-project` | Leur valeur est historique. Les décisions qui gouvernent le nouveau produit sont reformulées dans le registre courant. |
| `tools/labctl` | adapter | Le contrôleur est extérieur au produit et ses gardes libvirt restent utiles ; Debian 12, le réseau unique et les gabarits historiques sont retirés. |

## Règle pour la suite

Une pièce historique n’entre dans `main` que pour un besoin du palier courant,
après comparaison avec le contrat actif et réécriture de ses hypothèses. Une
ressemblance de fonction ou un gain de temps supposé ne suffit pas. Les leçons
peuvent être reprises ; la preuve doit être reconstruite dans le LAB V1.

## État de sortie P0

- le dépôt GitHub `ldesfontaine/yourcloud` est privé et utilise `main` par
  défaut ;
- `old-project` conserve la tête de l’ancien wrapper et `main` sa nouvelle
  lignée documentaire ;
- `main` ne contient aucun ancien composant applicatif ;
- les frontières `console`, `daemon`, `coordinateur`, `protocole` et `engine`
  sont réservées sans squelette exécutable ;
- le contrôleur LAB Debian 13 et ses deux topologies sont implémentés, mais leur
  création réelle reste à attester dans libvirt ;
- les ADR 0001 à 0011 ont été relus et ratifiés à la fermeture de P0.

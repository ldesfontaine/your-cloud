# Registre des décisions

Ce registre appartient uniquement à la nouvelle lignée. Les ADR de l’ancien
wrapper Ansible/k3s restent consultables sur la branche `old-project` et ne
gouvernent pas ce `main`.

Une décision reçoit un ADR lorsqu’elle est difficile à renverser, surprenante
et issue d’un compromis réel. Les seuils, champs, commandes et contrats précis
vivent dans les spécifications liées.

| ADR | Décision | Statut |
|---|---|---|
| [0001](0001-separation-des-autorites.md) | Séparer strictement observation et administration | proposé |
| [0002](0002-declaration-et-etat-runtime.md) | Séparer déclaration versionnable et état runtime | proposé |
| [0003](0003-secrets-et-recuperation-console.md) | Séparer les secrets et le kit de récupération | proposé |
| [0004](0004-identites-et-confiance.md) | Utiliser des identités individuelles sans secret de flotte | proposé |
| [0005](0005-telemetrie-et-persistance.md) | Conserver une télémétrie minimale dans SQLite | proposé |
| [0006](0006-protocole-de-telemetrie.md) | Utiliser Protobuf sur HTTPS/mTLS sans gRPC | proposé |
| [0007](0007-mutation-linux-sure.md) | Séparer bootstrap, administration et mutation risquée | proposé |
| [0008](0008-profil-linux-et-autorites.md) | Refuser les autorités concurrentes dans le profil Linux | proposé |
| [0009](0009-coordinateur-local-et-distant.md) | Employer le même coordinateur en mode local et distant | proposé |
| [0010](0010-cycle-de-vie-progressif.md) | Piloter mises à jour et bascules progressivement | proposé |
| [0011](0011-execution-developpement-en-lab.md) | Exécuter le développement exclusivement dans un LAB isolé | proposé |

Le statut « proposé » reste volontaire tant que cette consolidation P0 n’a pas
été relue et ratifiée. Il ne remet pas en cause la Vision ou la Roadmap ; il
évite de présenter le nouveau découpage comme approuvé avant review.

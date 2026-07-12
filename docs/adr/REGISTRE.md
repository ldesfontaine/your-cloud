# Registre des décisions

Ce registre appartient uniquement à la nouvelle lignée. Les ADR de l’ancien
wrapper Ansible/k3s restent consultables sur la branche `old-project` et ne
gouvernent pas ce `main`.

Une décision reçoit un ADR lorsqu’elle est difficile à renverser, surprenante
et issue d’un compromis réel. Les seuils, champs, commandes et contrats précis
vivent dans les spécifications liées.

| ADR | Décision | Statut |
|---|---|---|
| [0001](0001-separation-des-autorites.md) | Séparer strictement observation et administration | accepté |
| [0002](0002-declaration-et-etat-runtime.md) | Séparer déclaration versionnable et état runtime | accepté |
| [0003](0003-secrets-et-recuperation-console.md) | Séparer les secrets et le kit de récupération | accepté |
| [0004](0004-identites-et-confiance.md) | Utiliser des identités individuelles sans secret de flotte | accepté |
| [0005](0005-telemetrie-et-persistance.md) | Conserver une télémétrie minimale dans SQLite | accepté |
| [0006](0006-protocole-de-telemetrie.md) | Utiliser Protobuf sur HTTPS/mTLS sans gRPC | accepté |
| [0007](0007-mutation-linux-sure.md) | Séparer bootstrap, administration et mutation risquée | accepté |
| [0008](0008-profil-linux-et-autorites.md) | Refuser les autorités concurrentes dans le profil Linux | accepté |
| [0009](0009-coordinateur-local-et-distant.md) | Employer le même coordinateur en mode local et distant | accepté |
| [0010](0010-cycle-de-vie-progressif.md) | Piloter mises à jour et bascules progressivement | accepté |
| [0011](0011-execution-developpement-en-lab.md) | Exécuter le développement exclusivement dans un LAB isolé | accepté |

Ces décisions ont été relues ensemble et ratifiées à la fermeture de P0 le
2026-07-12. Les paramètres réversibles et les seuils mesurables continuent de
vivre dans les spécifications associées.

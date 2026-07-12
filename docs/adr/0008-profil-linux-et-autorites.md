# Refuser les autorités concurrentes dans le profil Linux

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

Fusionner automatiquement une configuration SSH, nftables ou `sysctl` inconnue
peut interrompre un service ou supprimer un accès légitime. Une confirmation
« machine dédiée » ne prouve pas à elle seule que le système est simple.

## Décision

- Le profil exige une machine déclarée dédiée et un audit technique concluant.
- Un gestionnaire ou une configuration concurrente sur une politique visée
  refuse le profil complet avant toute mutation.
- Le produit ne fusionne, ne vide, ne traduit ou ne remplace jamais
  silencieusement une politique qu’il ne possède pas.
- Le pare-feu V1 nftables couvre IPv4 et IPv6, ferme par défaut les nouveaux
  flux entrants et le forwarding, puis laisse les sorties ouvertes.
- SSH est limité au chemin d’administration prouvé. Aucun port applicatif
  n’appartient au profil générique.
- Les réglages `sysctl` sont minimaux, justifiés individuellement et prouvés ;
  aucune checklist historique n’est reprise en bloc.
- Une dérive est visible et sa correction nécessite un nouveau plan. Une
  provenance ambiguë interdit l’écrasement.

## Conséquences

La V1 préfère un refus explicite à une compatibilité dangereusement
approximative. Les machines complexes restent observables mais peuvent ne pas
être sécurisables avant un futur plan d’adoption. Les détails de configuration
et les preuves dual-stack vivent dans la spécification du profil Linux.

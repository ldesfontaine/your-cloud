# Conserver une télémétrie minimale dans SQLite

Statut : accepté · ratification P0 du 2026-07-12

## Contexte

L’observation doit survivre aux coupures sans imposer une plateforme de
métriques ou un service de base de données supplémentaire. Une file de fichiers
maison et une base différente côté serveur multiplieraient les mécanismes de
durabilité.

## Décision

- La V1 collecte un état système minimal et des unités systemd sélectionnées,
  jamais un inventaire intrusif ou des journaux complets.
- Le daemon possède une base SQLite locale bornée pour sa file de reprise.
- Le coordinateur possède une base SQLite distincte pour le dernier état et un
  historique borné d’événements significatifs.
- Le daemon publie d’abord l’état actuel après une coupure, puis ce qui subsiste
  du journal. Un débordement produit une lacune explicite.
- Une donnée n’est purgée localement qu’après un accusé authentifié émis après
  validation de la transaction du coordinateur.
- La présence de plusieurs coordinateurs préautorisés ne reçoit le nom de haute
  disponibilité qu’après preuve de réplication, reprise et domaines de panne.

## Conséquences

Le projet maintient un seul modèle transactionnel embarqué et aucun daemon de
base supplémentaire. La perte d’une base peut faire perdre de la télémétrie,
jamais une déclaration ou une autorité. Les limites, rythmes et rétentions
restent dans la spécification de télémétrie et doivent être mesurés en LAB.

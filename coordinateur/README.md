# Coordinateur

Le coordinateur Go termine lui-même le mTLS, valide la signature et l'identité
de chaque machine, conserve l'enveloppe Protobuf originale dans SQLite, puis
émet un accusé seulement après validation de la transaction.

Il sert l'état courant et des pages bornées d'événements à une identité de
console en lecture seule. Son compte, ses certificats, sa base limitée à
64 Mio et ses ressources systemd restent séparés du daemon lorsqu'ils sont
colocalisés. Il ne détient aucun secret d'administration.

Voir l'[Anatomie du projet](../docs/ANATOMIE-DU-PROJET.md) pour les routes,
messages, rôles mTLS, transactions et vérifications de bout en bout.

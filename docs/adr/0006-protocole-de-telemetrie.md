# Utiliser Protobuf sur HTTPS/mTLS sans gRPC

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

Les échanges sont des publications et accusés bornés entre composants Go et
Python. Un framework RPC avec streaming permanent ajouterait des dépendances et
des garanties inutiles sur des réseaux domestiques ou derrière NAT.

## Décision

- Le daemon initie des requêtes HTTPS/mTLS ordinaires ; aucune connexion
  entrante ou session permanente n’est requise.
- Le coordinateur termine lui-même le mTLS et n’exige ni reverse proxy, ni
  ingress, ni runtime de conteneurs.
- Des messages Protobuf versionnés constituent l’unique contrat réseau V1.
- Chaque payload de daemon est signé sur ses octets exacts avec séparation de
  domaine. Le coordinateur conserve l’enveloppe originale et la console vérifie
  à nouveau sa provenance.
- Les échanges, ressources serveur et diagnostics publics sont strictement
  bornés. Les diagnostics détaillés restent locaux.
- Les accusés sont durables et les retransmissions idempotentes par identité,
  flux et séquence.
- Les compilateurs et générateurs épinglés s’exécutent uniquement dans le LAB ;
  le code généré est versionné.

## Conséquences

Le protocole reste compact, typé et simple à reprendre après une coupure. Il
supporte moins d’outillage automatique que gRPC et demande une génération de
code, mais évite streaming, découverte de service et canonicalisation JSON pour
les signatures.

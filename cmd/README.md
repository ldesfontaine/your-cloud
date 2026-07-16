# Exécutable du produit

`your-cloud/` est le point de démarrage du seul artefact Go de `v0.0.1` :

- `your-cloud daemon` valide sa configuration puis envoie les présences ;
- `your-cloud relay` vérifie d'abord le manifeste candidat local, puis assemble
  le stockage mémoire et les routes HTTP.

Ces modes partagent des octets, pas un processus, un compte ou une
configuration. Les fichiers de `cmd/` restent courts : le comportement métier
vit dans [`internal/`](../internal/). `cmd/` ne contient pas des commandes de
test LAB.

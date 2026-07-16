# Cœur du produit

Ce dossier contient la logique réelle de `v0.0.1` : contrat du signal,
validation, envoi par le Daemon, réception et calcul d'état par le Relay.

`internal` possède aussi un sens précis en Go : aucun autre module ne peut
importer directement ces packages. Les exécutables publics du dépôt les
assemblent depuis [`cmd/`](../cmd/).

Ce dossier ne contient ni scénario LAB, ni script d'installation, ni futur
palier préparé à l'avance.

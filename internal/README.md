# Cœur du produit

Ce dossier contient la logique métier réellement appelée par l'exécutable.
Les packages historiques de `v0.0.1` restent présents pour conserver sa preuve
rejouable ; `v0.0.2` ajoute l'identité machine, les credentials stricts, le
profil d'observation fixe, le tampon durable, le transport mTLS, l'enrôlement,
la révocation et le stockage durable du Relay.

`internal` possède aussi un sens précis en Go : aucun autre module ne peut
importer directement ces packages. Les exécutables publics du dépôt les
assemblent depuis [`cmd/`](../cmd/).

Ce dossier ne contient ni scénario LAB, ni script d'installation, ni futur
palier préparé à l'avance.

La carte des appels, des états et des protections se trouve dans
[`CHAINE-D-OBSERVATION.md`](../docs/architecture/CHAINE-D-OBSERVATION.md).

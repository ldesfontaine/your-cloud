# Outils de pilotage

Ce dossier contient le petit **plan de contrôle** du projet : des commandes qui
inspectent ou pilotent l'environnement, mais aucun composant du produit et
aucun scénario de test.

- [`labctl`](labctl) crée, inspecte et commande les VM KVM/libvirt du LAB. Il
  reste utile depuis le poste de développement pour une preuve autorisée et
  depuis un futur runner CI dédié ; il n'est donc pas réservé à la CI. Sa
  commande `assert-clean`, sans mutation, rend bloquante toute VM ou tout réseau
  LAB encore persistant à la clôture.
- [`check-docs`](check-docs) vérifie la structure et les liens de la
  documentation sans lancer le produit.
- [`release-artifacts`](release-artifacts) produit les artefacts vérifiables de
  la révision courante — manifeste, sommes, SBOM CycloneDX et provenance — sans
  réseau, sans horodatage et sans nom de machine, de sorte que deux exécutions
  sur une même révision rendent les mêmes octets. Sa commande
  `check-determinism` le prouve en produisant deux fois, et un tiers vérifie le
  résultat avec `sha256sum -c checksums.txt`. Il ne construit rien et ne signe
  rien.
- [`ci-usage`](ci-usage) mesure les minutes GitHub Actions réellement
  facturées du cycle courant, en appliquant le facteur de plateforme, et sert
  de garde avant une matrice native : `tools/ci-usage --guard 100` échoue
  lorsque la marge restante est insuffisante. Il interroge l'API en lecture
  seule et n'exécute rien.

Une image CI ordinaire fournit un système de fichiers et des dépendances
préinstallées, pas automatiquement la topologie multi-VM `v1-full` ni l'accès
libvirt nécessaire à `labctl`. Les contrôles réutilisables vivent sous
[`tests/checks/`](../tests/checks/) ; la preuve qui a besoin de vraies VM vit
sous [`tests/lab/`](../tests/lab/).

Le laptop reste limité à Git, l'édition, l'empaquetage non sensible et le
pilotage de `labctl`. Tout test, build, serveur ou binaire du projet s'exécute
dans un runner isolé conforme aux [règles LAB](../docs/lab/README.md).

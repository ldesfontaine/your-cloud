# Tests et preuves

Ce dossier sépare deux notions qui répondent à des questions différentes.

Un **contrôle générique** vérifie une propriété des sources ou d'un outil sans
dépendre de la topologie métier complète. Une **preuve LAB** exécute le produit
sur les VM identifiées, observe ses frontières réelles et conserve un résultat
relié au lot exact qui a été exécuté.

| Couche | Contenu | Runner attendu | Autorité |
|---|---|---|---|
| [`checks/`](checks/) | format, syntaxe, documentation, tests Go, build, contrat `labctl list` et schéma de restitution | runner isolé, actuellement `lab-console` pour le palier complet | codes de sortie et assertions |
| [`lab/v0.0.1/`](lab/v0.0.1/) | préparation, déploiement, scénarios hostiles multi-VM, nettoyage et restitution P2 | topologie KVM/libvirt `v1-full` pilotée par `labctl` | `result.json` et assertions machine |

Cette séparation prépare une CI propre sans prétendre qu'un conteneur standard
équivaut au LAB :

1. une CI courante peut exécuter les contrôles génériques dans une image
   isolée qui possède les dépendances attendues ;
2. la preuve multi-VM demande un runner dédié, sans charge de production, avec
   libvirt et les gabarits `labctl` ;
3. ce runner doit commencer par l'inventaire en lecture seule, borner ses
   délais, publier les résultats puis vérifier le nettoyage même en cas
   d'échec.

L'entrée [`checks/source-v0.0.1`](checks/source-v0.0.1) rend le placement
explicite : le mode `lab` exige `lab-console` et root isolé pour produire
`dist/your-cloud`, tandis que le mode `ci` exige un runner distant déclaré et
non privilégié, puis construit dans un répertoire temporaire. Aucun mode
n'autorise l'exécution sur le laptop.

Les contrôles sont maintenus avec le code : tout défaut corrigé reçoit le cas
hostile proportionné dans la couche la plus petite capable de le reproduire,
puis une preuve LAB seulement lorsque la frontière réelle est nécessaire. Une
capture ou une page HTML ne remplace jamais une assertion machine.

Le registre détaillé reste
[`docs/contribution/TESTS.md`](../docs/contribution/TESTS.md). Le placement, les
permissions et les limites de la couche distante sont fixés par le
[`contrat CI`](../docs/contribution/CI.md).

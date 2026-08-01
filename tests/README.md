# Tests et preuves

Ce dossier sépare trois notions qui répondent à des questions différentes.

Un **contrôle générique** vérifie une propriété des sources ou d'un outil sans
dépendre de la topologie métier complète. Un **contrôle natif** construit,
installe et lance l'application sur le système ciblé sans inventer son
infrastructure. Une **preuve LAB** exécute le produit sur les VM identifiées,
observe ses frontières réelles et conserve un résultat relié au lot exact qui
a été exécuté.

| Couche | Contenu | Runner attendu | Autorité |
|---|---|---|---|
| porte rapide sous [`checks/`](checks/) | format, syntaxe, contrat PowerShell de nettoyage, documentation, tests Go, build temporaire, contrats `labctl list`/`assert-clean` et politique CI | runner GitHub Linux jetable sur chaque pull request | codes de sortie et assertions |
| matrice native sous [`checks/`](checks/) | tests frontend et Rust, paquets `.deb`/`.msi`, signature Authenticode synthétique Windows, installation, lancement, absence de listener et smoke de la WebView installée | runners GitHub Linux et Windows jetables, déclenchés manuellement sur le candidat exact | codes de sortie, journaux et smoke borné |
| [`lab/v0.0.1/`](lab/v0.0.1/) | préparation, déploiement, scénarios hostiles multi-VM, nettoyage et restitution P2 | topologie KVM/libvirt `v1-full` pilotée par `labctl` | `result.json` et assertions machine |

Cette séparation prépare une CI propre sans prétendre qu'un conteneur standard
équivaut au LAB :

1. une pull request exécute automatiquement les contrôles génériques et la
   politique CI dans une image isolée ;
2. le candidat final exécute manuellement les différences natives Linux et
   Windows sans Controller, Relay, Daemon ou topologie simulée ;
3. la preuve multi-VM demande un runner dédié, sans charge de production, avec
   libvirt et les gabarits `labctl` ;
4. ce runner doit commencer par l'inventaire en lecture seule, borner ses
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

# Console Your Cloud

La Console est l'application cliente installée de `v0.0.3`. React rend le
frontend embarqué ; le cœur Rust Tauri porte seul le réseau, le coffre et les
identités. Aucun Controller ne fournit de frontend et aucun serveur local ne
sert l'interface.

Le dossier suit trois frontières explicites :

- `src/design/` contient les tokens et composants visuels communs ;
- `src/product/` contient les sept vues et leur état sans accès réseau direct ;
- `src-tauri/` contient les seules opérations natives autorisées au frontend.

Les dépendances, tests et builds s'exécutent exclusivement dans le LAB. Le
laptop peut seulement éditer ces fichiers et exécuter les contrôles statiques
documentaires autorisés par le projet.

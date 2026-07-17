# Déploiement minimal

Ce dossier contient uniquement ce qui installe, active ou retire le palier sur
une machine cible. Il ne contient plus les assertions ni les pilotes de preuve.

[`v0.0.1/`](v0.0.1/) regroupe :

- `install-agent`, qui installe l'unique exécutable et active le Daemon ;
- `enable-relay` et `disable-relay`, qui gèrent séparément la candidature
  Relay ;
- `remove-agent`, qui retire tous les rôles et l'artefact commun ;
- les deux modèles d'unité systemd.

Ce dossier ne contient pas la logique métier du produit : elle vit dans
[`internal/`](../internal/), puis l'exécutable est assemblé depuis
[`cmd/`](../cmd/). Les scripts ne sont pas un second composant à maintenir sur
une machine : ils servent à installer ou retirer les unités, puis peuvent
disparaître de la cible.

Les contrôles génériques sont sous [`tests/checks/`](../tests/checks/) et la
preuve multi-VM sous [`tests/lab/v0.0.1/`](../tests/lab/v0.0.1/). Le binaire
compilé n'est pas versionné dans `deploy/` : il est produit temporairement dans
`dist/` à l'intérieur du runner LAB.

# Déploiement minimal

Ce dossier contient uniquement ce qui installe, active ou retire le palier sur
une machine cible. Il ne contient plus les assertions ni les pilotes de preuve.

[`v0.0.1/`](v0.0.1/) regroupe :

- `install-agent`, qui installe l'unique exécutable et active le Daemon ;
- `enable-relay` et `disable-relay`, qui gèrent séparément la candidature
  Relay ;
- `remove-agent`, qui retire tous les rôles et l'artefact commun ;
- les deux modèles d'unité systemd.

[`v0.0.2/`](v0.0.2/) ajoute séparément le Daemon d'observation authentifiée et
le Relay mTLS, toujours avec systemd uniquement et sans moteur de déploiement.

[`v0.0.3/`](v0.0.3/) ajoute l'unité du Controller privé en lecture seule, sous
utilisateur dynamique et sans capacité Linux. Elle ne déploie ni la Console ni
un frontend sur le Controller.

Ce dossier ne contient pas la logique métier du produit : elle vit dans
[`internal/`](../internal/), puis l'exécutable est assemblé depuis
[`cmd/`](../cmd/). Les scripts ne sont pas un second composant à maintenir sur
une machine : ils servent à installer ou retirer les unités, puis peuvent
disparaître de la cible.

Les contrôles génériques sont sous [`tests/checks/`](../tests/checks/).
[`tests/lab/v0.0.1/`](../tests/lab/v0.0.1/) porte son orchestrateur multi-VM ;
[`tests/lab/v0.0.2/`](../tests/lab/v0.0.2/) contient seulement les auxiliaires
de sa preuve encore assistée. Le binaire compilé n'est pas versionné dans
`deploy/` : il est produit temporairement dans `dist/` à l'intérieur du runner
LAB.

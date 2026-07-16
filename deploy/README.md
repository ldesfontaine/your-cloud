# Installation et preuve

`v0.0.1/` contient deux familles de fichiers :

- `install-agent` installe l'unique exécutable et active le Daemon ;
  `enable-relay` / `disable-relay` gèrent séparément la candidature Relay, et
  `remove-agent` retire tous les rôles et l'artefact commun ;
- `prove-hostile-relay` est uniquement un pilote de preuve dans le LAB.

Ce dossier ne contient pas la logique métier du produit : elle vit dans
[`internal/`](../internal/), puis l'exécutable est assemblé depuis
[`cmd/`](../cmd/). Les scripts ne sont pas un second composant à maintenir sur
une machine : ils servent à installer ou retirer les unités, puis peuvent
disparaître de la cible.

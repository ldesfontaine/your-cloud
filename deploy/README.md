# Installation des rôles

`deploy/` contient les fichiers minimaux qui installent, activent ou retirent
un rôle sur une machine cible : unités systemd, comptes, répertoires et garde de
configuration. Il ne contient ni logique métier, ni scénario de test.

Ce n’est pas un faux déploiement réservé au développement. Ce sont les
primitives d’installation réellement exercées dans le LAB. Elles restent
volontairement simples et bornées ; l’interface ou un futur moteur d’action
pourra les piloter seulement après avoir produit et fait approuver un plan
exact. Elles ne deviennent pas pour autant une seconde implémentation du
Daemon, du Relay ou du Controller.

Les répertoires numérotés identifient le contrat sous lequel un lot
d’installation a été prouvé. Ils ne sont pas le numéro d’une API à remplacer
globalement : leur nom reste stable afin qu’une preuve passée désigne toujours
les mêmes entrées. Le code produit courant évolue dans `cmd/` et `internal/` ;
une capacité n’y est pas recopiée à chaque palier.

- `v0.0.1/` conserve le lot de présence synthétique et son retrait ;
- `v0.0.2/` installe le Daemon d’observation et le Relay authentifié ;
- `v0.0.3/` ajoute le Controller et le lecteur privé du Relay.

Les assertions et pilotes vivent sous [`tests/`](../tests/). Les exécutables et
paquets compilés restent temporaires sous `dist/` ou dans le stockage du runner ;
ils ne sont pas versionnés dans `deploy/`.

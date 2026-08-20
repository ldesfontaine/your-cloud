# Your Cloud

> ## ⚠️ Pré-version — en cours de développement.
>
> **Une pre-release existe** ([Releases](https://github.com/ldesfontaine/your-cloud/releases)) :
> elle installe et active un Controller sur une machine Debian 13 `amd64`, par
> le parcours prouvé du palier `v0.1.3` — audit, pose, activation, chaque issue
> en phrase. **Elle n'héberge encore aucun service : ne pas lui confier de
> données réelles.**

## Objectif

Héberger soi-même demande aujourd'hui de tenir dans sa tête ce que font une
douzaine d'outils. Your Cloud vise l'inverse : déclarer ses machines, les voir
rapporter leur état, choisir un service, lire en phrases ce que la machine
recevra, approuver, et regarder le résultat que la machine a réellement
rapporté.

Ce que l'écran affiche est ce qui s'est produit, pas une promesse d'interface :
jamais un bouton qui cache ce qu'il déclenche.

C'est un projet pour qui veut héberger ses propres services — un serveur loué,
un mini-PC, une machine au grenier — et refuse d'échanger la simplicité contre
l'opacité.

## Ce qui existe

Chaque capacité listée ci-dessous est prouvée par des tests exécutés sur de
vraies machines — les [rapports de preuve](docs/lab/README.md) le documentent.

- **Amorçage et enrôlement** — permet d'installer le Controller, d'enrôler une
  machine et de remplacer le Controller sans perdre le parc.
- **Observation du parc** — permet de voir ce que chaque machine rapporte
  réellement, ancienneté affichée.
- **Déploiement par plans signés** — permet de déployer les profils de
  référence après lecture et approbation de ce que la machine recevra.
- **Services utilisateur** — permet de déclarer sa propre application (image,
  volumes, secrets) et de la déployer comme un profil.
- **Publication HTTPS** — permet d'exposer un service par un point d'entrée
  Traefik.
- **Passage privé WireGuard** — permet de relier deux machines par un lien
  chiffré sans rien publier.
- **Commandes depuis la Console** — permet d'approuver un plan dans une fenêtre
  native, de le signer, de le lancer par SSH et de lire le rapport de la
  machine.
- **Instantanés et restauration** — permet de sauvegarder et de restaurer les
  volumes d'un service sur sa machine.
- **Mode externe** — permet de déclarer un service existant sans le confier à
  Your Cloud.

## Prochaines versions

- Approbation des plans depuis la Console Windows, mise en page au zoom
  texte 200 % sous Windows, signature Windows publiquement reconnue.
- Gestion DNS Cloudflare : à partir de la v0.1.3.
- Sauvegardes gérées : v0.2.0.

## Limites

- La Console Windows observe et lit un plan ; approuver se fait depuis Linux.
- Les sauvegardes restent locales et à la demande — aucune copie hors machine.
- DNS et certificats TLS publics restent manuels.
- Debian 13 sur `amd64` seulement.

## Pour lire plus loin

La [carte documentaire](docs/README.md) est le point d'entrée : elle donne le
chemin de lecture selon le sujet — le [cap du projet](docs/projet/CAP.md) et ses
limites durables, l'[anatomie](docs/architecture/ANATOMIE.md) du placement et des
flux, les [rapports de preuve](docs/lab/README.md), et les
[règles de qualité](docs/contribution/QUALITE.md) appliquées à chaque changement.

[`tools/labctl`](tools/labctl) contrôle les machines de l'environnement isolé.
Sa présence ne prouve aucune capacité du produit.

## Licence

Your Cloud est distribué sous licence
[GNU Affero General Public License, version 3](LICENSE), et sous elle seule.

Le copyleft réseau est un choix de destination plutôt qu'une préférence :
ce produit sert à héberger soi-même, et l'AGPL est la licence qui garde ce
sens quand quelqu'un d'autre en fait un service — celui qui propose Your
Cloud à des tiers par un réseau doit leur en offrir la source, modifications
comprises. Une licence permissive aurait laissé refermer ce que ce dépôt
ouvre.

Les profils de service que la `v0.1.0` prend en charge sont eux-mêmes sous
AGPL — BentoPDF, Vaultwarden — et ne sont ni redistribués, ni modifiés, ni
liés par ce dépôt : Your Cloud les déploie par leur image officielle
épinglée, ce que le contrat de chaque profil écrit.

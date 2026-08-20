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

## Installer (Linux)

Debian 13 `amd64`. Chaque commande ci-dessous a été exécutée sur une machine
nue, et le [rapport de preuve](docs/lab/v0.1.3-from-releases.md) dit combien
de temps chacune a pris.

**1. Télécharger le paquet et son empreinte.** Les deux sont sur la page
[Releases](https://github.com/ldesfontaine/your-cloud/releases). Vérifiez
l'empreinte avant d'installer : c'est le seul contrôle qui vous appartient
entièrement.

```bash
sha256sum your-cloud_0.1.3_amd64.deb
```

Elle doit être exactement celle que les notes de la release affichent. Si elle
diffère, n'installez pas.

**2. Installer.**

```bash
sudo apt update
sudo apt install ./your-cloud_0.1.3_amd64.deb
```

Le `./` n'est pas décoratif : il dit à `apt` d'installer ce fichier plutôt que
de chercher ce nom dans les dépôts. `sudo dpkg -i` seul ne suffit pas — il ne
résout pas les dépendances (`libwebkit2gtk-4.1-0`, `libgtk-3-0`) et laisse le
paquet non configuré. Comptez quelques minutes : ces dépendances pèsent
environ 200 Mio.

**3. Vérifier que le paquet contient bien ce qu'il annonce.**

```bash
/usr/bin/your-cloud-native-bootstrap-assistant --verify-embedded-server-bundle
```

La réponse doit commencer par `VERIFIED`. L'Assistant vient de confronter le
lot serveur qu'il transporte à son manifeste signé, contre une ancre scellée
dans son propre binaire. Un refus se nomme (`DigestMismatch`,
`SignatureNotByAnchor`, `UnexpectedVersion`) plutôt que de se taire.

**4. Lancer la Console.** Elle apparaît dans le menu des applications sous
**Your Cloud**. Depuis un terminal : `your-cloud-console`.

### Préparer la machine que vous voulez installer

Le parcours « Créer une infrastructure » demande une machine cible, un compte
sur cette machine, et l'empreinte de sa clé d'hôte.

**Le compte prêté.** Aujourd'hui, il doit satisfaire deux conditions
précises — et ce ne sont pas celles d'un compte administrateur Debian
ordinaire :

- il porte **une seule** entrée sudoers, qui autorise toute commande sans mot
  de passe ;
- il n'appartient **pas** au groupe `sudo` — sans quoi il en porterait deux, et
  l'Assistant refuse un listing ambigu.

```bash
sudo deluser <compte> sudo
echo '<compte> ALL=(ALL:ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-<compte>
sudo chmod 0440 /etc/sudoers.d/90-<compte>
sudo visudo -c
```

C'est une exigence que nous ne trouvons pas satisfaisante, et elle est
ouverte : le contrat d'amorçage promet de s'adapter à la posture de la machine
plutôt que d'en imposer une, et le produit ne tient pas encore cette promesse
pour un compte à mot de passe. Voir
[l'issue 158](https://github.com/ldesfontaine/your-cloud/issues/158). En
attendant, l'Assistant vous dit lequel des deux cas vous êtes et quel geste le
lève.

**L'empreinte de la clé d'hôte.** Relevez-la **sur la machine cible**, jamais
en acceptant ce qu'une première connexion propose :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Le formulaire attend la partie `SHA256:…`. C'est la clé `ed25519` qui compte :
c'est l'algorithme que l'Assistant négocie en premier.

**Les trois adresses.** L'écoute du Controller est une adresse IPv4 privée
exacte sur le port `9443` ; la source autorisée est **une** adresse en `/32`,
jamais une plage ; le rendez-vous du Relay est une adresse IPv4 privée exacte
sur le port `8444`.

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

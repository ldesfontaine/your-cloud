# Your Cloud

Héberger ses propres services sur ses propres machines, sans avoir à tenir
dans sa tête ce que font une douzaine d'outils. Ce que l'écran affiche est ce
qui s'est produit : jamais un bouton qui cache ce qu'il déclenche.

> ## ⚠️ Pré-version — en cours de développement.
>
> **Une pre-release existe** ([Releases](https://github.com/ldesfontaine/your-cloud/releases)) :
> la `v0.1.4` installe et met en service un Controller — le programme qui
> pilotera vos machines — sur une machine Debian 13 `amd64`. Chaque étape est
> approuvée dans une fenêtre, chaque issue est une phrase, chaque refus dit sa
> cause. **Elle n'héberge encore aucun service : ne lui confiez pas de données
> réelles.**

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

## Installer (Linux)

Il vous faut deux machines : celle où vous travaillez, sous Debian 13
(`amd64`), et celle que vous voulez faire piloter — un serveur loué, un
mini-PC, une machine au grenier.

Les commandes ci-dessous se tapent dans un terminal, l'une après l'autre.
Chacune a été jouée telle quelle sur une machine neuve.

**1. Télécharger le fichier.** Sur la page
[Releases](https://github.com/ldesfontaine/your-cloud/releases), prenez le
fichier dont le nom se termine par `.deb`. Il arrive en général dans votre
dossier « Téléchargements » : ouvrez un terminal dans ce dossier.

**2. Vérifier que le fichier reçu est bien celui qui a été publié.** La
commande ci-dessous calcule une empreinte du fichier — une longue suite de
chiffres et de lettres qui change entièrement si un seul caractère du fichier
a été modifié en route.

```bash
sha256sum your-cloud_0.1.4_amd64.deb
```

Comparez ce qu'elle affiche à l'empreinte donnée sur la page de la release.
Les deux doivent être identiques. Si elles diffèrent, arrêtez-vous : n'ouvrez
pas ce fichier et ne l'installez pas.

**3. Installer l'application.** La première commande met à jour la liste des
logiciels disponibles ; la seconde installe le fichier que vous venez de
vérifier, en ajoutant au passage les composants dont il a besoin pour
fonctionner. Votre mot de passe vous sera demandé, puis une confirmation.

```bash
sudo apt update
sudo apt install ./your-cloud_0.1.4_amd64.deb
```

Comptez quelques minutes : les composants à télécharger pèsent environ
200 Mio. Le `./` devant le nom du fichier compte : sans lui, votre machine
irait chercher ce nom sur Internet au lieu d'installer le fichier que vous
avez sous la main.

**4. Vérifier que l'application n'a pas été altérée.** Elle transporte avec
elle le programme qu'elle posera sur votre serveur ; cette commande lui
demande de le vérifier elle-même, avant que vous vous en serviez.

```bash
/usr/bin/your-cloud-native-bootstrap-assistant --verify-embedded-server-bundle
```

La réponse doit commencer par `VERIFIED`. Toute autre réponse est un refus :
n'allez pas plus loin.

**5. Ouvrir l'application.** Elle s'appelle **Your Cloud** dans le menu des
applications.

### Préparer la machine que vous voulez installer

L'application vous demandera trois choses au sujet de cette machine : un
compte pour s'y connecter, son empreinte, et trois adresses.

**Le compte.** L'application se connecte à votre serveur avec un compte que
vous lui prêtez, et ce compte doit pouvoir y installer des logiciels. Il doit
aujourd'hui remplir deux conditions précises, qui ne sont pas celles d'un
compte d'administrateur habituel :

- pouvoir tout faire sans qu'on lui redemande son mot de passe ;
- ne pas appartenir au groupe `sudo` — sinon il reçoit deux autorisations
  différentes, et l'application ne sait pas laquelle s'applique.

Les commandes ci-dessous mettent le compte dans cette forme. Elles se tapent
**sur la machine que vous voulez installer**, et vous y remplacez `<compte>`
par le nom du compte, partout où il apparaît.

```bash
sudo deluser <compte> sudo
echo '<compte> ALL=(ALL:ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/90-<compte>
sudo chmod 0440 /etc/sudoers.d/90-<compte>
sudo visudo -c
```

La dernière ligne relit ce qui vient d'être écrit et doit répondre
`parsed OK` : c'est ce qui vous protège d'une faute de frappe.

Cette exigence ne nous satisfait pas et elle est ouverte — voir
[l'issue 158](https://github.com/ldesfontaine/your-cloud/issues/158). Si vous
vous trompez, rien n'est posé sur votre serveur, et l'application vous dit
laquelle des deux conditions manque et quelle commande la corrige.

**L'empreinte de la machine.** Elle permet à l'application de reconnaître
votre serveur, et de refuser de parler à une autre machine qui prendrait sa
place. Relevez-la **sur le serveur lui-même**, jamais en acceptant ce qu'une
première connexion vous propose :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Recopiez la partie qui commence par `SHA256:`.

**Les trois adresses.** L'application vous demandera ensuite :

- l'adresse de votre serveur suivie de `:9443` — c'est là qu'il répondra ;
- l'adresse de la seule machine autorisée à lui parler, suivie de `/32` : une
  machine précise, jamais un réseau entier ;
- l'adresse du point de rendez-vous — le champ « Relay » du formulaire —
  suivie de `:8444`.

## Limites

- La Console Windows observe et lit un plan ; approuver se fait depuis Linux.
- Les sauvegardes restent locales et à la demande — aucune copie hors machine.
- DNS et certificats TLS publics restent manuels.
- Debian 13 sur `amd64` seulement.

## Licence

Your Cloud est distribué sous licence
[GNU Affero General Public License, version 3](LICENSE), et sous elle seule.

Le copyleft réseau est un choix de destination plutôt qu'une préférence :
ce produit sert à héberger soi-même, et l'AGPL est la licence qui garde ce
sens quand quelqu'un d'autre en fait un service — celui qui propose Your
Cloud à des tiers par un réseau doit leur en offrir la source, modifications
comprises. Une licence permissive aurait laissé refermer ce que ce dépôt
ouvre.

Les profils de service que ce dépôt prend en charge sont eux-mêmes sous
AGPL — BentoPDF, Vaultwarden — et ne sont ni redistribués, ni modifiés, ni
liés par ce dépôt : Your Cloud les déploie par leur image officielle
épinglée, ce que le contrat de chaque profil écrit.

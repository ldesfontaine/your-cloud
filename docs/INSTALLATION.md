# Installer your-cloud 1.0.0

> Cette procédure part uniquement du lot stable `1.0.0`. Le dépôt source n'est
> jamais nécessaire sur la console de l'opérateur.

La V1 cible Debian 13 `trixie` sur amd64. Les artefacts ne doivent jamais être
choisis par un alias `latest` : l'opérateur sélectionne une version exacte et
vérifie sa provenance avant installation.

Après publication, la release GitHub `v1.0.0` fournit une archive unique pour
Debian 13 amd64 et trois fichiers permettant de la vérifier. Les archives du
code source ajoutées automatiquement par GitHub ne sont pas le paquet
d'installation. Avant publication, le responsable de la preuve remet
exactement ces quatre fichiers à l'opérateur.

## Vérifier le lot

Télécharger uniquement :

- `your-cloud_1.0.0_linux_amd64.tar.gz`, le lot installable ;
- `SHA256SUMS`, son empreinte ;
- `SHA256SUMS.sig`, la signature de cette empreinte ;
- `release-signing-public.pem`, la clé publique de vérification.

Le lot installable contient les binaires observer et coordinateur, le wheel de
la console, l'archive versionnée de l'engine Ansible, les unités systemd, cette
documentation et `RELEASE-METADATA.json`.

Dans les commandes suivantes, partir d'un répertoire contenant les quatre
fichiers téléchargés ou remis pour la preuve :

```text
cd "$HOME/Downloads"
openssl pkeyutl -verify -rawin -pubin \
  -inkey release-signing-public.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check SHA256SUMS
tar -xzf your-cloud_1.0.0_linux_amd64.tar.gz
export RELEASE_DIR="$HOME/Downloads/your-cloud-1.0.0"
```

Une clé publique téléchargée depuis la même release prouve la cohérence interne
du lot, pas à elle seule l'identité de son auteur. Pour une release publique,
son empreinte doit être publiée par un canal indépendant approuvé par
l'opérateur.

## Installer la console

La console de l'opérateur et les machines gérées doivent utiliser Debian 13
amd64 pour cette V1. Sur la console, installer d'abord le module venv prouvé,
puis créer un environnement Python 3.13 dédié et installer le nom exact du
wheel :

```text
sudo apt-get update
sudo apt-get install python3.13-venv=3.13.5-2+deb13u3
python3 -m venv ~/.local/share/your-cloud/venv
~/.local/share/your-cloud/venv/bin/pip install \
  "$RELEASE_DIR/your_cloud_console-1.0.0-py3-none-any.whl"
source ~/.local/share/your-cloud/venv/bin/activate
your-cloud --help
```

Dans un nouveau terminal, réactiver le venv et redéfinir `RELEASE_DIR` avant
de reprendre les commandes. `ENGINE_DIR` et `OBSERVER` seront définis plus bas
et doivent eux aussi être redéfinis après une nouvelle connexion.

Les dépendances transitives sont épinglées par le projet, mais `pip` les
télécharge depuis son index configuré : la V1 n'est pas un lot
d'installation hors ligne. La console conserve sa déclaration sous
`~/.config/your-cloud/` et son état privé sous `~/.local/state/your-cloud/` sauf
chemins explicitement fournis.

Cette installation minimale suffit pour initialiser la console, déclarer des
machines et les auditer en lecture seule. Une console qui doit enrôler,
sécuriser ou mettre à jour une machine installe l'extra d'automatisation du
même wheel vérifié :

```text
pip install \
  "$RELEASE_DIR/your_cloud_console-1.0.0-py3-none-any.whl[automation]"
ansible-playbook --version
```

Les versions Ansible et Python sont ainsi épinglées dans le même artefact.
Le fichier `console/requirements-lab.txt` reste réservé au développement du
projet et n'est plus une condition cachée pour l'utilisateur.

## Premier audit en lecture seule

Avant de lancer la console, l'opérateur dispose déjà d'un accès SSH par clé à
la machine. La clé est fournie par l'hébergeur, installée physiquement ou par
un autre canal d'administration ; your-cloud ne peut pas inventer ce premier
accès. Le compte peut être `root` pour un bootstrap fournisseur ou un compte
normal capable d'exécuter `sudo -n` sans demander de mot de passe. La V1 ne sait
pas répondre à une invite interactive de mot de passe SSH ou sudo.

Le parcours minimal crée une infrastructure, déclare une machine puis effectue
un audit sans la modifier :

```text
your-cloud init
your-cloud infrastructure add homelab --name "Mon homelab"
your-cloud machine add mini-pc \
  --address 192.0.2.10 \
  --user mon-compte \
  --identity-file ~/.ssh/mini-pc \
  --infrastructure homelab
your-cloud machine audit mini-pc --accept-host-key
```

`--accept-host-key` effectue un premier enregistrement TOFU visible. Lorsqu'une
empreinte fournisseur ou obtenue hors bande existe, utiliser plutôt
`--host-fingerprint SHA256:...`. Une différence ultérieure est refusée.

TOFU signifie que la première clé d'hôte observée est affichée puis acceptée
explicitement. Pour une preuve plus forte, l'hébergeur fournit l'empreinte
`SHA256:...` dans son interface ou par un autre canal ; elle doit correspondre
exactement au format affiché par OpenSSH.

Un audit réussi se termine par `Décision : eligible`, `Mutation distante : 0`
et aucun refus. `ineligible` signifie que la cible ou l'accès ne satisfait pas
les prérequis ; il ne faut alors pas tenter de forcer l'enrôlement.

## Enrôler la première machine

L'engine est l'ensemble des playbooks Ansible utilisés par la console. Il reste
un artefact séparé afin que son contenu soit inspectable avant exécution.
Extraire son archive dans un répertoire privé :

```text
install -d -m 0700 "$HOME/.local/share/your-cloud/releases/1.0.0"
tar -xzf "$RELEASE_DIR/your-cloud-engine_1.0.0.tar.gz" \
  -C "$HOME/.local/share/your-cloud/releases/1.0.0"
export ENGINE_DIR="$HOME/.local/share/your-cloud/releases/1.0.0/engine"
export OBSERVER="$RELEASE_DIR/your-cloud-observer_1.0.0_linux_amd64"
```

La première commande affiche seulement le plan. Elle n'installe rien :

```text
your-cloud machine enroll mini-pc \
  --daemon-binary "$OBSERVER" \
  --engine-dir "$ENGINE_DIR" \
  --unit ssh.service
```

`--unit ssh.service` demande au daemon d'observer explicitement l'état du
service SSH. Cette unité existe sur la Debian 13 cible prouvée. On peut omettre
ce paramètre pour commencer sans unité particulière, ou le répéter avec le nom
exact d'une autre unité systemd que l'on veut suivre. Le daemon n'inventorie
jamais automatiquement tous les services.

Lire le plan, puis relancer exactement la même commande avec l'approbation :

```text
your-cloud machine enroll mini-pc \
  --daemon-binary "$OBSERVER" \
  --engine-dir "$ENGINE_DIR" \
  --unit ssh.service \
  --approve
```

La console lance elle-même `ansible-playbook --syntax-check` avant le playbook
réel. Un succès se termine par `Enrôlement vérifié`, l'identité publique du
daemon et la séquence du premier état signé. La clé privée du daemon reste sur
la machine.

Vérifier ensuite l'état courant, puis relancer l'enrôlement approuvé. Le second
passage doit rester idempotent et le récapitulatif Ansible doit indiquer
`changed=0` :

```text
your-cloud machine inspect mini-pc
your-cloud machine enroll mini-pc \
  --daemon-binary "$OBSERVER" \
  --engine-dir "$ENGINE_DIR" \
  --unit ssh.service \
  --approve
```

Un état « signé » signifie que la console vérifie qu'il provient de l'identité
Ed25519 approuvée pour cette machine et qu'il ne s'agit pas d'un rejeu. Cela ne
donne au daemon aucun droit d'administration.

Ce premier état ne passe pas encore par un coordinateur : la console le lit
directement par le même accès SSH strict que l'audit. Le coordinateur devient
utile plus tard pour conserver l'observation lorsque la console est éteinte.

## Refus courants

- `Permission denied (publickey)` : la clé passée à `--identity-file` ou le
  compte SSH ne correspond pas à la cible ; corriger l'accès fournisseur, sans
  remplacer automatiquement la clé d'hôte ;
- `sudo` ou `become` refusé : le compte ne satisfait pas `sudo -n` ; utiliser
  un accès bootstrap autorisé ou préparer cette délégation hors de your-cloud ;
- `playbook ou binaire du daemon absent` : vérifier `ENGINE_DIR`, `OBSERVER` et
  le niveau d'extraction de l'archive ;
- unité inconnue : retirer le `--unit` concerné ou confirmer son nom avec
  `systemctl status NOM.service` sur la cible ;
- version incompatible : ne pas renommer un artefact et ne pas mélanger les
  fichiers de deux releases ; revérifier `SHA256SUMS` ;
- clé d'hôte différente : arrêter le parcours et vérifier la machine par le
  fournisseur ou un canal hors bande avant toute rotation.

## Installer ou mettre à jour les composants natifs

Ne pas copier manuellement un binaire sur une flotte. La console reçoit le
chemin exact, sa somme SHA-256 et sa version, met d'abord à jour un coordinateur,
puis un daemon pilote par site. Elle conserve le binaire précédent et arrête la
propagation au premier échec.

L'installation d'un coordinateur local ou distant vient seulement après cette
première machine observable. Elle n'appartient pas au parcours de démarrage
minimal ci-dessus ; son tutoriel complet doit être validé avant la promotion
stable. Un coordinateur local reste limité au LAN ou au réseau
d'administration. Un coordinateur distant est joignable par plusieurs sites,
par exemple sur un VPS, sans recevoir de clé SSH d'administration.

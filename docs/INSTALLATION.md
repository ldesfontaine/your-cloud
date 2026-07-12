# Installer la release candidate V1

> La candidate courante est `1.0.0-rc.2`. Elle corrige le premier essai
> d'adoption de `rc.1` en rendant les dépendances d'automatisation installables
> depuis le wheel, sans copie du dépôt source.

La V1 cible Debian 13 `trixie` sur amd64. Les artefacts ne doivent jamais être
choisis par un alias `latest` : l'opérateur sélectionne une version exacte et
vérifie sa provenance avant installation.

## Vérifier le lot

Le lot RC contient les binaires observer et coordinateur, le wheel de la
console, l'archive versionnée de l'engine Ansible, les unités systemd,
`RELEASE-METADATA.json`, `SHA256SUMS`, sa signature et la clé publique de la
preuve.

Depuis le répertoire des artefacts :

```text
openssl pkeyutl -verify -rawin -pubin \
  -inkey release-signing-public.pem \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check SHA256SUMS
```

Une clé publique livrée dans le même lot prouve la cohérence interne de la
preuve LAB, pas encore la confiance d'une release publique. Pour une vraie
release, son empreinte doit être publiée par un canal indépendant approuvé par
l'opérateur.

## Installer la console

Sur Debian 13, installer d'abord le module venv prouvé, puis créer un
environnement Python 3.13 dédié et installer le nom exact du wheel :

```text
apt-get update
apt-get install python3.13-venv=3.13.5-2+deb13u3
python3 -m venv ~/.local/share/your-cloud/venv
~/.local/share/your-cloud/venv/bin/pip install \
  ./your_cloud_console-1.0.0rc2-py3-none-any.whl
~/.local/share/your-cloud/venv/bin/your-cloud --help
```

Les dépendances transitives sont épinglées par le projet. La console conserve
sa déclaration sous `~/.config/your-cloud/` et son état privé sous
`~/.local/state/your-cloud/` sauf chemins explicitement fournis.

Cette installation minimale suffit pour initialiser la console, déclarer des
machines et les auditer en lecture seule. Une console qui doit enrôler,
sécuriser ou mettre à jour une machine installe l'extra d'automatisation du
même wheel vérifié :

```text
~/.local/share/your-cloud/venv/bin/pip install \
  './your_cloud_console-1.0.0rc2-py3-none-any.whl[automation]'
~/.local/share/your-cloud/venv/bin/ansible-playbook --version
```

Les versions Ansible et Python sont ainsi épinglées dans le même artefact.
Le fichier `console/requirements-lab.txt` reste réservé au développement du
projet et n'est plus une condition cachée pour l'utilisateur.

## Premier audit en lecture seule

Avant de lancer la console, l'opérateur dispose déjà d'un accès SSH par clé à
la machine. La clé est fournie par l'hébergeur, installée physiquement ou par
un autre canal d'administration ; your-cloud ne peut pas inventer ce premier
accès.

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

## Installer ou mettre à jour les composants natifs

Ne pas copier manuellement un binaire sur une flotte. La console reçoit le
chemin exact, sa somme SHA-256 et sa version, met d'abord à jour un coordinateur,
puis un daemon pilote par site. Elle conserve le binaire précédent et arrête la
propagation au premier échec.

Le premier parcours utilise les commandes guidées `machine enroll`,
`coordination install-local` ou `coordination install-distant`. Une installation
existante utilise `component update --pilot --approve`. Les playbooks exécutent
leur `--syntax-check` avant mutation et le re-run attendu vaut `changed=0`.

Extraire `your-cloud-engine_1.0.0-rc.2.tar.gz` dans un répertoire privé du
runner, puis passer son dossier `engine/` à `--engine-dir`. L'archive appartient
au même manifeste signé que la console et les binaires.

# Preuve LAB de `v0.1.1`

Ce dossier contient les harnais LAB de la milestone `v0.1.1` « Services
utilisateur ». Il ne prépare aucune capacité d'un autre palier, ne remplace aucun
contrôle générique et ne rejoue pas les paliers de `v0.1.0`, dont les preuves
restent sous [`../v0.1.0/`](../v0.1.0/).

Il n'y a **pas d'orchestrateur de milestone** ici, et c'est une décision plutôt
qu'un manque : `v0.1.1` ferme une seule preuve LAB, celle de `#121`, et un
orchestrateur qui n'ordonnancerait qu'un passage serait un second fichier
pouvant diverger de celui qu'il appelle. La séquence, l'ordre et la fermeture
sont dans l'entrée du harnais lui-même.

## [`user-service/`](user-service/) — le moteur de la troisième porte, prouvé une fois

La milestone renverse la charge du catalogue : le moteur que `#14` à `#17` ont
prouvé devient paramétrable par un document que l'utilisateur rédige. Ce que
`#121` prouve est donc le **moteur**, une seule fois, et jamais une application :
la dixième application d'un utilisateur ne doit coûter ni un contrat ni une
preuve nouvelle.

- [`prove`](user-service/prove) est l'entrée unique, exécutée depuis le poste de
  pilotage. Elle commence par la garde d'inventaire obligatoire
  (`tools/labctl list --format=tsv`), refuse une origine, une topologie, un état
  ou une adresse inattendus, puis enchaîne cinq sous-commandes également
  utilisables seules : `setup`, `run`, `verify`, `dismantle` et `remove`. Sans
  argument, elle fait les cinq dans l'ordre, démonte même lorsqu'une étape
  échoue, et publie son rapport sous
  `tests/artifacts/proofs/user-service/<run>/`.
- [`_app/main.go`](user-service/_app/main.go) est l'**application synthétique**.
  Elle n'existe que pour tenir, phrase par phrase, le contrat d'éligibilité :
  rootless, un seul port lu dans une ligne d'environnement inerte, ses données
  durables sous les seuls chemins déclarés en volumes, un `tmpfs` sans lequel
  elle refuse de démarrer plutôt que de se dégrader, aucune sortie réseau, une
  configuration inerte et un secret reçu par une clé générée sur la machine.
  Elle ne sert jamais la valeur de ce secret : elle en sert une attestation à
  clé sur un message fixe, que la fixture recalcule côté machine.
- [`_fixture/main.go`](user-service/_fixture/main.go) tient les quatre autorités
  que le palier sépare et n'en détient aucune pour de vrai : le Controller — dont
  le gel et la relecture passent par `internal/controller` et non par une
  seconde orthographe —, la Console, l'autorité de certification, et
  l'**origine de l'image**, qui est la seule que ce palier ne pouvait emprunter
  nulle part.
- [`common`](user-service/common) est le vocabulaire partagé, repris de
  [`../v0.1.0/private-service/common`](../v0.1.0/private-service/common) avec la
  troisième porte ajoutée et rien des deux autres retiré : c'est ce qui fait de
  « les fiches des profils livrés ne bougent pas d'un octet » une comparaison
  contre le texte du palier précédent plutôt qu'une affirmation.

### Ce que ce harnais installe et retire

Aucune image tierce n'entre dans la preuve : seules l'application synthétique et
les images produit épinglées — Traefik et Vaultwarden — sont tirées. L'image de
l'application est construite sur les machines, servie depuis `lab-console` par
la moitié en lecture de l'API de distribution OCI, en TLS sous l'autorité de la
course, et **uniquement par digest**.

Trois actes sortent d'un plan approuvé et se nomment dans le journal : l'autorité
de la course placée dans le magasin de confiance et le nom de l'origine dans le
fichier `hosts` ; les certificats des deux noms déclarés ; et le retrait puis la
plantation d'une valeur générée, qui produisent les deux phrases de l'addendum
`#119` sur les secrets. Le démontage défait chacun des trois et relit la machine.

### Limites

- **Une jonction borne exactement un port.** Le coffre et le service utilisateur
  ne peuvent donc pas être publiés par le même passage en même temps : le coffre
  est déployé, confiné et jamais publié ici, et le second nom de la course est le
  second service utilisateur, publié par une route locale sur l'autre machine.
- **La surface HTTP du Controller n'est pas montée** : le gel, la relecture et la
  construction des paires passent par les paquets du produit, jamais par une
  session ni par un certificat client.
- **Les machines ne sont pas redémarrées.** Que le confinement et le passage
  reviennent par leurs unités de démarrage est ce que la preuve `#104` a établi
  sur ces mêmes machines.
- **L'origine est un arbre statique** derrière un serveur HTTPS du harnais, pas
  une implémentation de registre.

Le détail, les verdicts et les défauts produits que cette preuve a trouvés vivent
dans son rapport :
[`docs/lab/v0.1.1-user-service.md`](../../../docs/lab/v0.1.1-user-service.md).

### Usage

```text
tests/lab/v0.1.1/user-service/prove              # montage, scénario, démontage
tests/lab/v0.1.1/user-service/prove setup
tests/lab/v0.1.1/user-service/prove run
tests/lab/v0.1.1/user-service/prove verify
tests/lab/v0.1.1/user-service/prove dismantle
tests/lab/v0.1.1/user-service/prove remove
```

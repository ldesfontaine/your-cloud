# Preuve LAB de `v0.1.0`

Ce dossier contient les harnais LAB du palier `v0.1.0`. Il ne prépare aucune
capacité d'un autre palier et ne remplace aucun contrôle générique.

## [`prove`](prove) — l'orchestrateur du palier

[`prove`](prove) ne prouve rien par lui-même. Chaque verdict du palier sort de
l'un des harnais ci-dessous, qui monte son propre périmètre, juge à travers le
produit compilé et retire ce qu'il a monté. Ce que l'orchestrateur ajoute, ce
sont les trois choses que la preuve globale de #41 exige et qu'aucun passage
isolé ne peut donner : **une révision** nommée une fois et portée par tous les
passages, **un ordre** — les passages partagent deux VM et ne peuvent donc
jamais tourner ensemble — et **une fermeture** qui détruit la topologie que ce
passage possède au lieu de la laisser à la vigilance d'un humain.

```text
tests/lab/v0.1.0/prove                    # garde, les cinq passages, fermeture
tests/lab/v0.1.0/prove guard
tests/lab/v0.1.0/prove run [passe...]
tests/lab/v0.1.0/prove close
```

L'ordre est celui des dépendances de #13 : `personal-access` (#51, #52),
`signed-approval` (#37), `controller-install` (#38), `machine-identity` (#39),
`enrolment-bounds` (#41), puis `controller-replacement` (#40).

- **Le premier rouge est conservé.** Le passage qui échoue arrête la séquence,
  son journal est retenu entier, les passages suivants sont enregistrés
  `not_run` — jamais `passed` — et la fermeture a quand même lieu.
- **Les délais sont bornés.** Chaque passage porte un plafond d'horloge, et
  chaque appel au LAB aussi. Un passage tué sur sa borne est ensuite forcé à
  travers son propre `remove` : une borne qui laisse un périmètre monté est pire
  que pas de borne du tout.
- **Aucun faux succès global.** `PROVE_V0_1_0_OK` n'est écrit que par un
  passage qui a gardé, joué **tous** les passages et fermé. Une phase seule rend
  `PROVE_V0_1_0_PHASE_OK`, un sous-ensemble rend `PROVE_V0_1_0_PARTIAL_OK`, et
  le résultat structuré porte `complete: false` dans les deux cas.
- **Le résultat est structuré et expurgé.** Chaque passage écrit
  `tests/artifacts/proofs/v0.1.0/<run>/result.json` et le journal de chaque
  passe à côté, les chemins du poste de pilotage remplacés. La matière du LAB
  est synthétique par construction : elle est frappée au montage et détruite au
  démontage.
- **La révision est nommée honnêtement.** Un arbre modifié rend
  `<sha>+worktree`, et l'orchestrateur annonce alors que #41 demande un SHA
  exact et qu'un tel passage ne ferme aucune ligne du palier.

### Limites

- `windows-helper` **ne fait pas partie de la séquence** : sa machine
  d'évaluation vit hors de `labctl` et hors de cette topologie. Elle est
  enregistrée `not_run`, jamais `passed`. La moitié Windows du palier reste non
  prouvée tant que cette machine ne la joue pas.
- `oci-plan` **n'en fait pas partie non plus**, pour une autre raison : il rend
  le palier du plan OCI contrôlé (#14, preuve #86) et non l'amorçage et le
  remplacement que cette séquence prouve. Il partage `lab-machine-1` avec ces
  passages et ne tourne donc jamais à côté d'eux, mais son verdict appartient à
  son palier ; il est enregistré `not_run` ici et possède sa propre entrée.
- **La fermeture relit la garde et nomme ce qui reste**, au lieu d'appeler le
  LAB propre. Si l'un des résidus appartenait à la topologie détruite, c'est un
  échec de nettoyage et la fermeture rougit ; s'il lui préexistait, il est
  nommé comme conservation et non tu. Le critère de #41 qui demande un
  `assert-clean` vert est atteignable depuis que la VM Windows manuelle a
  quitté le préfixe `lab-*` — elle s'appelait `lab-windows`, et sous ce nom la
  garde la retenait indéfiniment, ce qui rendait le critère impossible à
  satisfaire quoi que fasse un passage.
- **Démarrer une VM arrêtée est la seule mutation** que l'orchestrateur fait
  hors d'un passage, et c'est elle qui rend la topologie sienne à fermer. Il
  remonte alors le swapfile, que `labctl start` laisse présent mais inutilisé :
  plusieurs passages compilent le crate de la Console, et cette compilation est
  tuée par l'OOM sans lui. C'est un fait de provisionnement du LAB, pas un
  comportement du produit — un passage qui meurt d'un swapfile absent n'a
  mesuré que le swapfile.
- **La fermeture coûte un reprovisionnement.** `topology destroy` emporte la
  chaîne d'outils, les paquets et le cache de compilation de `lab-console` ;
  seul `labctl stop` les conserve. Une passe complète est donc jouable une
  fois, puis le LAB doit être reprovisionné avant la suivante — par
  [`tools/provision-lab`](../../../tools/provision-lab), qui lit les versions
  épinglées dans le workflow de la porte hébergée. C'est le prix du critère qui
  exige une fermeture, et il se paie en une commande.

## [`enrolment-bounds/`](enrolment-bounds/) — la borne des soixante-quatre

Ce harnais prouve l'**échelle**, et rien d'autre. Que chaque machine n'admette
que son identité est la propriété de #39, éprouvée là-bas contre une vraie
commande forcée ; la rejuger ici lui donnerait un second domicile. Ce que ce
passage ajoute et qui n'existe nulle part ailleurs est triple : le parc entier
de soixante-quatre identités frappé d'un coup par la porte compilée avec de
vraies clés, la soixante-cinquième refusée par son nom, et l'**accord** entre
ce que la porte décide et ce qu'un vrai `sshd` fait là où une machine existe.

- [`prove`](enrolment-bounds/prove) est l'entrée unique. Elle commence par la
  garde d'inventaire obligatoire, puis enchaîne sept sous-commandes :
  `artifact`, `setup`, `estate`, `refuse`, `agree`, `mutate` et `remove`. Sans
  argument, elle fait les sept dans l'ordre et démonte même lorsqu'une étape
  échoue.
- [`mount-machine`](enrolment-bounds/mount-machine) monte un compte synthétique
  détenant exactement une clé publique, et **imprime sa provenance** plutôt que
  de la supposer. Il n'installe ni commande forcée, ni règle d'élévation, ni
  ancre : ce sont les propriétés de #39.
- [`remove-machine`](enrolment-bounds/remove-machine) ne retire un compte que si
  ce harnais l'a créé, la provenance étant celle que le montage a imprimée et
  que le pilote lui rend. Un compte trouvé en place est laissé en place.

`estate` imprime `MINTED count=64 bound=64` — les deux nombres sortant de la
porte, jamais du harnais. `refuse` prend la soixante-cinquième
(`TooManyMachines { count: 65 }`) et les deux collisions qui doivent encore être
attrapées **à** la borne, identité partagée et machine déclarée deux fois.
`agree` confronte le verdict de la porte à quatre vraies tentatives SSH.
`mutate` porte la borne à soixante-cinq dans les sources, reconstruit, montre
que la suite rougit, puis restaure et vérifie son propre point d'application.

### Représentativité

**Soixante-quatre machines ne sont pas prouvées.** Deux identités sur
soixante-quatre sont détenues par une vraie machine de la topologie ; les
soixante-deux autres sont de vraies clés Ed25519 que personne ne détient. Le
harnais imprime cette proportion à chaque passage, parce qu'un rapport qui la
tairait laisserait lire « soixante-quatre machines prouvées ». Ce qui est prouvé
est que la porte frappe un parc de soixante-quatre identités réelles, et que là
où une machine existe vraiment son jugement correspond à ce que cette machine
fait vraiment.

### Limites

- Aucun registre Go n'est touché. Les bornes homonymes du registre Relay schéma
  2 et de l'inventaire du Controller sont les leurs, et restent sans épreuve.
- Les clés sont générées au montage et détruites au démontage ; aucune adresse
  et aucune matière de clé ne vit dans ces fichiers.
- Le compte synthétique ne porte ni commande forcée ni élévation : ce harnais
  ne dit donc rien de ce qu'une session ouverte peut faire.

## [`personal-access/`](personal-access/) — périmètre de l'accès personnel

La suite `personal-access-contract` de l'assistant natif ne peut pas être
synthétisée : elle exige un `ssh-agent` vivant qui détient réellement des clés
et un `sshd` vivant sur une **autre** machine, puisque le garde de cible refuse
les adresses de la machine locale. Ce harnais monte ce périmètre sur les deux VM
`quick`, exécute la suite, puis le démonte et prouve son absence.

- [`prove`](personal-access/prove) est l'entrée unique, exécutée depuis le poste
  de pilotage. Elle commence par la garde d'inventaire obligatoire
  (`tools/labctl list --format=tsv`), refuse une origine, une topologie, un état
  ou une adresse inattendus, puis enchaîne cinq sous-commandes également
  utilisables seules : `setup`, `sync`, `check`, `run` et `remove`. Sans
  argument, elle fait les cinq dans l'ordre et démonte le périmètre même
  lorsqu'une étape échoue.
- [`install-client`](personal-access/install-client) monte le côté client dans
  `lab-console` : trois identités Ed25519 synthétiques créées au montage, deux
  confiées à un vrai `ssh-agent` puis détruites du disque, le scalaire privé de
  l'identité autorisée extrait comme canari, les noms synthétiques du résolveur
  et le pont d'observation du serveur. La clé d'hôte du serveur est épinglée à
  partir de ce que le canal géré `labctl` a lu, jamais à partir d'une première
  réponse du réseau.
- [`install-server`](personal-access/install-server) monte le côté serveur dans
  `lab-machine-1` : cinq comptes synthétiques, quatre commandes forcées qui
  décident seules combien d'octets reviennent, l'identité d'observation, un
  journal verbeux et trois `sshd` supplémentaires qui ne négocient chacun qu'un
  jeu hors des listes positives du client.
- [`check`](personal-access/check) prouve que le crate de la Console compile
  encore contre les sources que `sync` vient de déposer. Il construit d'abord,
  depuis ces mêmes sources, le binaire externe que `tauri.conf.json` déclare —
  jamais téléchargé, jamais versionné — puis lance `cargo check` sur
  `your-cloud-console`. Il ne dépend d'aucun périmètre monté : c'est la seule
  garde qui dit qu'un changement de protocole n'a pas cassé la Console, et elle
  doit pouvoir être rejouée sans payer la suite.
- [`run`](personal-access/run) exécute la suite dans `lab-console` contre le
  périmètre monté, en repartant d'un répertoire de travail vide, d'aucune
  confiance enregistrée et d'aucune sonde héritée d'une exécution précédente.
  Elle l'exécute **deux fois**. D'abord sans le moindre affichage : le client,
  l'agent et le transport ne doivent rien à une session graphique, et c'est de
  ne pas en avoir qui le dit. Ensuite sous un `Xvfb` isolé, avec `--ignored`,
  pour les seuls cas dont l'affichage est l'objet : un helper lancé par le
  superviseur de la Console elle-même, observé par la fenêtre qu'il ouvre.
  `LC_ALL` y est fixé parce que GTK écrit sur la sortie d'erreur sous une
  locale absente.
- [`remove-client`](personal-access/remove-client) et
  [`remove-server`](personal-access/remove-server) rendent les deux machines à
  leur état initial et échouent visiblement s'ils ne peuvent pas prouver
  l'absence de ce qu'ils ont retiré.

### Usage

```text
tests/lab/v0.1.0/personal-access/prove              # montage, suite, démontage
tests/lab/v0.1.0/personal-access/prove setup
tests/lab/v0.1.0/personal-access/prove sync
tests/lab/v0.1.0/personal-access/prove check
tests/lab/v0.1.0/personal-access/prove run [filtre]
tests/lab/v0.1.0/personal-access/prove remove
```

`setup` écrit dans `lab-console` la description du périmètre sous forme des
vingt-quatre variables `YOUR_CLOUD_LAB_*` que la suite lit ; un périmètre qui
n'en décrit pas exactement vingt-quatre est refusé avant toute exécution.
`sync` copie `console/src-tauri` **et** `console/package.json` dans
`lab-console`, **sans** détruire le cache de compilation : reconstruire ce
workspace depuis rien coûte beaucoup plus que la copie qu'il remplacerait.
`package.json` fait partie du voyage parce que `tauri.conf.json` y lit sa
version ; sans lui le script de construction de la Console refuse le workspace,
et `check` ne serait rejouable qu'à la main. `check` et `run` peuvent être
rejoués autant de fois que voulu, `check` après un simple `sync`, `run` entre un
`setup` et un `remove`.

### Limites et hygiène

- Aucune matière de clé, aucun secret et aucune adresse de LAB ne vit dans ces
  fichiers : les identités sont générées au montage et les adresses viennent de
  `labctl`. Les seules adresses littérales sont celles de la plage de
  documentation RFC 5737, qui ne sont jamais jointes : l'une sert de nouvelle
  réponse à un nom après consentement, les autres saturent un nom au-delà du
  nombre d'adresses qu'une cible peut geler.
- Les comptes, clés et agents sont synthétiques, créés puis retirés par le
  harnais. Aucun groupe nommé, aucune élévation, aucune identité réelle.
- Le binaire externe que `check` construit ne vit que dans la copie de travail
  de `lab-console`, sous `src-tauri/binaries/`, que Git ignore. Il est
  reconstruit à chaque `check` depuis les sources synchronisées : rien n'est
  téléchargé, rien n'est figé dans le dépôt.
- Le canari est le scalaire privé de l'identité autorisée. Il n'existe que le
  temps du périmètre et il est détruit, pas seulement délié, au démontage.
- Les deux VM restent démarrées : ce harnais ne crée ni ne détruit de topologie.
  La fermeture LAB reste celle de [`docs/lab/README.md`](../../../docs/lab/README.md).
- La présence de ces sources ne constitue pas une preuve. Seule une exécution
  identifiée en est une.

## [`controller-install/`](controller-install/) — installation réelle d'un Controller

C'est le premier harnais du palier qui **mute** une machine du LAB. Il joue les
deux côtés que l'architecture nomme : `lab-console` porte la Console et
l'Assistant, `lab-machine-1` est la machine privée que le placement de #36 a
approuvée, et l'unique endpoint déclaré du prévol est `lab-console` elle-même —
joignable *depuis le Controller*, ce qui est tout l'objet de l'étape.

- [`prove`](controller-install/prove) est l'entrée unique, exécutée depuis le
  poste de pilotage. Elle commence par la garde d'inventaire obligatoire, puis
  enchaîne sept sous-commandes : `bundle`, `setup`, `judge`, `install`,
  `shutdown`, `rollback` et `remove`. Sans argument, elle fait les sept dans
  l'ordre et démonte le périmètre même lorsqu'une étape échoue. `setup` refuse
  d'être appelée seule : elle a besoin du lot construit par le même passage.
- `bundle` construit le `.deb` et son manifeste dans `lab-machine-1`, seule VM
  du LAB qui porte Go, puis les rapatrie. Rien n'est téléchargé et rien n'est
  versionné : l'artefact d'une preuve est produit par la preuve.
- [`judge`](controller-install/judge) exécute dans `lab-console` la matrice
  complète des refus et de leurs contrôles positifs. Chaque verdict sort du
  module `installation` compilé, à travers le binaire de fixture : un harnais
  qui comparerait les empreintes lui-même resterait vert contre un produit ayant
  cessé de juger.
- [`install-controller`](controller-install/install-controller) installe dans
  l'ordre que l'architecture fixe et **enregistre ce que chaque étape a
  observé**, jamais ce qu'elle espérait. `YOUR_CLOUD_FAIL_AT` arrête la séquence
  à une étape nommée : c'est ce qui donne au rollback un registre réel plutôt
  qu'une liste écrite à la main.
- `shutdown` tue les processus de l'Assistant, vérifie qu'aucun ne survit, puis
  **arrête réellement** `lab-console` par le contrôleur du LAB et interroge le
  Controller depuis le poste de pilotage. Le PID est comparé avant et après :
  une unité morte puis relancée par systemd rendrait elle aussi `active`.
- [`remove`](controller-install/remove) rend `lab-machine-1` à son état initial
  et échoue visiblement s'il ne peut pas prouver l'absence de ce qu'il a retiré.
  Il est aussi la remise à zéro entre les points d'arrêt du rollback, et c'est
  pourquoi il ne retire pas les entrées du périmètre lui-même.
- [`_signer/`](controller-install/_signer/) est le signataire synthétique du
  manifeste. Il signe les octets du fichier verbatim, sans canonicalisation, et
  son en-tête dit ce qu'il ne prouve pas.

### Usage

```text
tests/lab/v0.1.0/controller-install/prove            # les sept étapes
tests/lab/v0.1.0/controller-install/prove judge
tests/lab/v0.1.0/controller-install/prove rollback
tests/lab/v0.1.0/controller-install/prove remove
```

### Limites et hygiène

- Aucune adresse de LAB, aucune matière de clé et aucun secret ne vit dans ces
  fichiers. Les adresses viennent de `labctl`, l'ancre est générée au montage et
  détruite au démontage, les certificats sont synthétiques et valables un jour.
- L'ancre est un **paramètre** de la vérification, pas une constante compilée :
  ce harnais prouve que l'Assistant refuse ce que l'ancre n'a pas signé, jamais
  que l'ancre est la bonne. Sceller l'ancre dans l'installateur reste à faire.
- Le `.deb` est construit à chaque passage et n'est jamais versionné.
- Les deux VM restent démarrées ; ce harnais ne crée ni ne détruit de topologie.
- La présence de ces sources ne constitue pas une preuve. Seule une exécution
  identifiée en est une.

## [`machine-identity/`](machine-identity/) — identité SSH bornée par machine

C'est le harnais du moment où l'accès personnel de l'utilisateur cesse d'être le
chemin d'administration. Il joue trois rôles avec deux VM : `lab-console` est le
**Controller** — il détient les clés privées opérationnelles, décide tout et est
le seul côté qui ouvre une session avec une identité bornée — et `lab-console`
comme `lab-machine-1` sont les deux **machines enrôlées**. Deux est le minimum :
la propriété que ce palier existe pour établir est que l'identité d'une machine
est **refusée sur l'autre**.

- [`prove`](machine-identity/prove) est l'entrée unique, exécutée depuis le poste
  de pilotage. Elle commence par la garde d'inventaire obligatoire, puis enchaîne
  neuf sous-commandes également utilisables seules : `artifact`, `setup`,
  `enrol`, `judge`, `verify`, `refuse`, `mutate`, `interrupt` et `remove`. Sans
  argument, elle fait les neuf dans l'ordre et démonte le périmètre même lorsque
  l'une échoue.
- [`mount-personal-access`](machine-identity/mount-personal-access) monte sur
  chaque machine les deux comptes contre lesquels l'enrôlement est mesuré :
  `ycoperator`, qui tient lieu d'accès personnel de l'utilisateur et dont tout
  est enregistré **avant** qu'un enrôlement existe, et `ycpermissive`, le
  **contrôle positif** — même machine, même `sshd`, même algorithme, aucune
  restriction. Sans lui, « SFTP est refusé » et « ce serveur n'a pas SFTP »
  seraient la même observation.
- [`enrol-from-controller`](machine-identity/enrol-from-controller) enrôle une
  machine **par l'accès personnel**, puis relit sur la machine ce qu'elle détient
  vraiment : la ligne de compte, la chaîne `stat` du fichier de clés et du
  binaire, l'entrée et la règle. Rien n'est composé de ce côté-là.
- [`enrol-machine`](machine-identity/enrol-machine) exécute la séquence dans
  l'ordre que l'architecture fixe et **enregistre ce que chaque étape a
  observé**. Il refuse d'écrire le fichier de clés si le binaire nommé par la
  commande forcée n'est pas installé. `YOUR_CLOUD_FAIL_AT` arrête avant une
  étape ; `YOUR_CLOUD_CUT_AT` l'exécute sans l'observer, et les deux ne sont pas
  le même fait : le premier se défait complètement, le second rend un déroulé
  qui refuse de se dire complet et nomme ce qui reste.
- [`judge`](machine-identity/judge) exécute dans `lab-console` la matrice des
  refus et de leurs contrôles positifs. Chaque verdict sort du module
  `machine_identity` compilé, à travers le binaire de fixture, et porte sur les
  fichiers que les machines détiennent réellement.
- [`refuse`](machine-identity/refuse) éprouve un vrai `sshd` et un vrai `sudo`,
  capacité par capacité, chacune à côté de son contrôle positif : clé croisée,
  commande libre, PTY, SFTP, fichier rc, X11, transferts de port et d'agent,
  argument libre, variable d'environnement et règle `sudo` élargie.
- [`verify-path`](machine-identity/verify-path) fait parcourir au Controller le
  chemin qu'il vient d'installer, avec l'identité propre à la machine, puis
  n'active que les rôles approuvés.
- [`remove-machine`](machine-identity/remove-machine) rend chaque machine à son
  état initial, prouve l'absence de ce qu'il a retiré et **compare l'accès
  personnel** au relevé pris avant tout enrôlement.

### Usage

```text
tests/lab/v0.1.0/machine-identity/prove              # les neuf étapes
tests/lab/v0.1.0/machine-identity/prove judge
tests/lab/v0.1.0/machine-identity/prove refuse
tests/lab/v0.1.0/machine-identity/prove mutate
tests/lab/v0.1.0/machine-identity/prove remove
```

### Limites et hygiène

- Aucune adresse de LAB, aucune matière de clé et aucun secret ne vit dans ces
  fichiers. Les quatre paires Ed25519 sont générées au montage et détruites — pas
  seulement déliées — au démontage ; les adresses viennent de `labctl` et les
  clés d'hôte sont épinglées depuis le canal géré, jamais depuis une première
  réponse du réseau.
- Le **contrôle positif d'X11 est pris sur la politique et non sur le fil** :
  `sshd` refuse de transporter X11 sans `xauth`, et ces machines n'en portent
  pas. Ce qui isole le refus est le contraste que le serveur résout lui-même,
  `no` pour le compte borné et `yes` pour un compte que rien ne restreint, au
  même instant. Le refus vivant, lui, est bien observé côté borné.
- L'enrôlement pose un fragment `sshd_config.d` et recharge `sshd` après
  `sshd -t` ; le démontage le retire, revalide et recharge. Le canal `labctl`
  n'est jamais concerné par ce fragment, qui ne porte qu'un `Match User`.
- L'Agent est activé **seulement s'il est explicitement approuvé**. Le harnais
  ne fabrique aucune approbation : le témoin est construit dans la fixture par
  `placement::propose` puis `placement::approve` de #36, comme celui du Relay.
  Les deux périmètres joués côte à côte ne diffèrent que par l'approbation, et
  celui qui ne l'a pas se fait refuser `RoleNotApproved` ; un rapport dont
  l'identité ne vérifie pas fait refuser l'activation avant même la question du
  rôle. Ce que ce harnais ne prouve pas : aucune unité n'est réellement démarrée
  sur les machines — l'activation est une décision typée, pas un `systemctl`.
- Les deux VM restent démarrées ; ce harnais ne crée ni ne détruit de topologie.
- La présence de ces sources ne constitue pas une preuve. Seule une exécution
  identifiée en est une.

## [`controller-replacement/`](controller-replacement/) — remplacement explicite d'un Controller

C'est le seul harnais du palier dont le sujet est ce qui se passe **quand on ne
sait pas**. Il joue les deux rôles que l'incident sépare : `lab-console` porte
l'ancien Controller — celui qu'on remplace, et donc celui que le harnais
**arrête réellement** — et `lab-machine-1` porte le nouveau, le Relay et une
cible. Les deux machines sont aussi des cibles : « chaque cible rend l'un des
quatre états » ne veut rien dire sur une seule.

- [`prove`](controller-replacement/prove) est l'entrée unique, exécutée depuis
  le poste de pilotage. Elle commence par la garde d'inventaire obligatoire,
  puis enchaîne huit sous-commandes : `setup`, `incident`, `switch`,
  `withdraw`, `refuse`, `interrupt`, `mutate` et `remove`. Sans argument elle
  fait les huit dans l'ordre et démonte le périmètre même lorsqu'une étape
  échoue. Seules `setup` et `remove` s'appellent seules : les six autres
  refusent, parce qu'elles ont besoin du périmètre et des identités forgées par
  le même passage.
- `incident` est la phase qui coûte du temps, et c'est voulu. Elle arrête
  vraiment `lab-console` par le contrôleur du LAB, prend une sonde
  immédiatement, puis attend réellement la borne que le produit fixe avant d'en
  reprendre une. La panne de cette preuve n'est pas simulée, et les secondes qui
  sont jugées sont celles qui se sont écoulées.
- Les **deux observations indépendantes** de la panne sont d'espèces
  différentes : une vraie tentative TCP depuis `lab-machine-1`, et l'état du
  domaine tel que l'hyperviseur le rapporte par `labctl`. La seconde ne passe
  par aucun réseau invité, ce qui est exactement ce qu'on demande à une seconde
  observation.
- [`mount-perimeter`](controller-replacement/mount-perimeter) monte sur chaque
  machine un compte technique verrouillé, le fichier de clés géré que `sshd` lit
  pour lui seul, et **un compte personnel avec sa propre clé**. Ce dernier
  existe pour que « aucune clé personnelle n'est retirée » soit une observation
  sur un vrai fichier d'un vrai compte. Il ouvre et ferme aussi les sockets
  d'écoute, et les relève avec `ss` plutôt que de les déduire d'un pid.
- [`run-from-controller`](controller-replacement/run-from-controller) forge les
  deux identités opérationnelles et ouvre les sessions. `refused` est prononcé
  par `sshd` sous la forme `Permission denied (publickey)` et par rien d'autre ;
  un échec qui n'est ni un refus ni une réponse rend `no-answer`, qui ne tiendra
  jamais lieu de refus.
- Les quatre états sont reconstruits depuis **deux sources qui doivent
  s'accorder** : ce que le fichier root détient et ce que deux vraies sessions
  ont répondu. Le désaccord est obtenu honnêtement — la clé neuve est bien
  installée et `RevokedKeys` la fait refuser par `sshd` — et il rend `unknown`.
- `mutate` joue trois épreuves. Deux mutent une source du produit dans la VM et
  reconstruisent une fixture mutée *à côté* de la bonne ; la troisième est jouée
  sur les machines, en réinstallant l'entrée de l'ancienne identité derrière le
  remplacement. Chaque correctif vérifie son propre point d'application : une
  mutation dont la cible a bougé échoue bruyamment au lieu de laisser la suite
  verte pour rien.
- [`remove-machine`](controller-replacement/remove-machine) compare l'accès
  personnel au relevé pris **avant** tout remplacement, puis retire ce que ce
  harnais a créé — et seulement cela : la provenance de chaque compte est celle
  relevée au montage, exactement comme le registre de #38.

### Usage

```text
tests/lab/v0.1.0/controller-replacement/prove          # les huit étapes
tests/lab/v0.1.0/controller-replacement/prove setup
tests/lab/v0.1.0/controller-replacement/prove remove
```

### Limites et hygiène

- Aucune adresse de LAB, aucune matière de clé et aucun secret ne vit dans ces
  fichiers. Les adresses viennent de `labctl`, les identités sont générées au
  montage et détruites au démontage.
- Le socket du lecteur Relay est un socket, pas un lecteur : il n'y a ni TLS, ni
  certificat client, ni instantané servi. Ce que le harnais relève est
  « ouvert » ou « fermé » ; le manifeste, lui, est jugé par la porte compilée.
- La commande forcée est **écrite et jugée**, pas exécutée par un vrai
  Auxiliaire : ce que ces sessions établissent est l'authentification, et c'est
  `machine-identity/` qui prouve la commande.
- Il n'y a pas de troisième VM. Le nouveau Controller, le Relay et une cible
  partagent `lab-machine-1`, et il n'existe pas de machine hostile distincte.
- `incident` immobilise `lab-console` pendant plus de cinq minutes. C'est le
  prix de la seule borne qui empêche une bascule sur une panne trop jeune.
- Les deux VM restent démarrées ; ce harnais ne crée ni ne détruit de topologie.
  Le swap de `lab-console` ne survit pas à l'arrêt qu'il provoque : `prove` le
  réactive au redémarrage, avant toute compilation.
- La présence de ces sources ne constitue pas une preuve. Seule une exécution
  identifiée en est une.

## [`oci-plan/`](oci-plan/) — le plan OCI contrôlé, son rollback et sa coupure

Ce harnais rend le palier du **plan OCI contrôlé** (#14, preuve #86) et non
celui que l'orchestrateur ci-dessus enchaîne. Il n'a qu'une machine,
`lab-machine-1`, et c'est honnête plutôt que commode : le Controller et la
Console y sont une fixture synthétique — la fenêtre de la Console n'est pas
câblée à cette preuve — tandis que l'Auxiliaire est le vrai binaire du produit,
construit depuis les sources synchronisées, exécuté en root contre un vrai
systemd, un vrai Podman rootless et un vrai registre. Ce qui est prouvé est donc
ce qu'une machine fait de documents qu'elle n'a pas écrits.

- [`prove`](oci-plan/prove) est l'entrée unique, exécutée depuis le poste de
  pilotage. Elle commence par la garde d'inventaire obligatoire, puis enchaîne
  six sous-commandes : `setup`, `unit`, `run`, `reboot`, `verify` et `remove`.
  Sans argument, elle fait les six dans l'ordre et démonte le périmètre même
  lorsqu'une étape échoue, puis publie son rapport sous
  `tests/artifacts/proofs/oci-plan/<run>/report.txt` en nommant la révision
  exacte qu'elle a jugée.
- `unit` exécute la suite du produit **sur la machine et en root**. C'est la
  seule raison pour laquelle cette étape existe dans un harnais LAB : #85 s'est
  fermée avec la dette que ses contrôles à porte root — séquence dépensée encore
  refusée après une coupure, état à moitié écrit ni réparé ni repris — ne
  comptent que si un vrai root les joue.
- [`install`](oci-plan/install) monte l'ancre synthétique, la position
  anti-rejeu vide, le binaire et la fixture. Il **refuse de commencer** si la
  machine porte déjà le compte de sonde ou son domicile : une preuve qui
  partirait d'un reste mesurerait le reste.
- [`run-before`](oci-plan/run-before) joue la capacité de la machine, le
  déploiement approuvé, l'idempotence, le rejeu et les documents hostiles.
  Chaque refus est suivi d'une comparaison avec une empreinte prise avant lui,
  parce que « refusé » et « refusé sans effet » sont deux affirmations
  différentes.
- [`run-after`](oci-plan/run-after) joue ce que le redémarrage a porté seul,
  l'échec contrôlé, la coupure et le retrait. L'échec est produit honnêtement —
  un autre processus tient le port que le plan nomme — et la coupure est un
  `SIGKILL` envoyé dès que la fiche Quadlet apparaît. Rien du produit n'est
  modifié pour que l'un ou l'autre se produise.
- [`remove`](oci-plan/remove) est le seul script autorisé à faire ce qu'aucun
  plan ne peut. Le compte `your-cloud-probe` n'est décrit par aucun plan, donc
  aucun document approuvé ne le retire et le produit le laisse délibérément ; ce
  retrait-là est l'acte du harnais et il est nommé comme tel.
- [`_fixture/`](oci-plan/_fixture/) tient les deux autorités que ce palier
  sépare et n'en détient aucune pour de vrai. Les documents de plan viennent du
  constructeur `internal/plan` du produit, pour que les octets reçus soient bien
  les octets canoniques qu'un Controller aurait figés ; le transcript de
  l'enveloppe est réécrit à la main, comme celui de
  [`signed-approval/_signer`](signed-approval/_signer/), pour qu'une signature
  ne soit pas vérifiée par les lignes qui l'ont produite.

### Usage

```text
tests/lab/v0.1.0/oci-plan/prove            # les six étapes, rapport publié
tests/lab/v0.1.0/oci-plan/prove unit
tests/lab/v0.1.0/oci-plan/prove run
tests/lab/v0.1.0/oci-plan/prove verify
tests/lab/v0.1.0/oci-plan/prove remove
```

### Limites et hygiène

- Aucune adresse de LAB, aucune matière de clé et aucun secret ne vit dans ces
  fichiers. L'ancre est frappée d'une graine synthétique au montage et détruite
  au démontage ; les adresses viennent de `labctl`.
- **La Console n'est pas câblée.** La confirmation native et la signature
  humaine sont jouées par la fixture. Ce harnais ne dit donc rien de ce qu'une
  fenêtre affiche ni de ce qu'un humain confirme.
- **Une déviation de provisionnement est écrite dans `install` et nommée
  ici** : les plages `subuid`/`subgid` du compte de sonde sont posées par le
  harnais, parce que le produit crée ce compte avec `useradd --system` et que la
  suite shadow de Debian n'alloue aucune plage à un compte système. Sans elles,
  aucun déploiement ne peut aboutir sur une machine Debian neuve.
- La matrice exhaustive des refus reste celle de
  `internal/auxiliary/refusals_test.go`. Ce que ce harnais ajoute est qu'un
  sous-ensemble représentatif refuse contre un vrai compte, un vrai moteur et
  une vraie sonde en marche.
- La VM reste démarrée : ce harnais ne crée ni ne détruit de topologie, et il
  redémarre `lab-machine-1` une fois, réellement, par le contrôleur du LAB.
- La présence de ces sources ne constitue pas une preuve. Seule une exécution
  identifiée en est une, et le rapport de la première est
  [`docs/lab/v0.1.0-oci-plan.md`](../../../docs/lab/v0.1.0-oci-plan.md).

## [`windows-helper/`](windows-helper/) — moitié Windows du helper natif

Les suites de contrat propres à Windows n'ont pas d'équivalent Linux : le Job
Object, le pipe nommé et son authentification, la boîte de dialogue Win32 et le
dump de crash sont des objets du système, pas des abstractions. Le LAB Linux ne
peut donc rien en dire. Ce harnais les exécute dans la VM d'évaluation Windows
décrite par les [règles LAB](../../../docs/lab/README.md), avec les invocations
exactes de la porte native hébergée.

- [`prove`](windows-helper/prove) est l'entrée unique, exécutée depuis le poste
  de pilotage. Elle commence par la garde d'inventaire obligatoire
  (`tools/labctl list --format=tsv`), puis enchaîne trois sous-commandes
  également utilisables seules : `tools`, `sync` et `run`. Sans argument, elle
  fait les trois dans l'ordre.
- [`report-tools.ps1`](windows-helper/report-tools.ps1) **rend compte** de
  l'outillage épinglé que la machine détient : `rustc` et `rustfmt` `1.94.1` en
  `x86_64-pc-windows-msvc`, Node.js `24.18.0`, l'environnement MSVC x64, le SDK
  Windows et le runtime WebView2 Evergreen. Il n'installe rien : le
  provisionnement de cette machine est manuel et hors `labctl`, et un harnais
  qui la réparerait en silence cacherait le jour où elle dérive du runner
  hébergé qu'elle pré-valide.
- [`sync.ps1`](windows-helper/sync.ps1) dépose `console/src-tauri` **et**
  `console/package.json` dans la machine **sans** détruire le cache de
  compilation. `package.json` fait partie du voyage parce que `tauri.conf.json`
  y lit sa version. Chaque fichier extrait reçoit l'heure de l'extraction et
  non celle du poste de pilotage : Cargo décide de la fraîcheur sur les dates
  de modification, et des sources rendues plus anciennes que le cache feraient
  rejouer en silence la synchronisation précédente.
- [`run.ps1`](windows-helper/run.ps1) entre dans l'environnement MSVC — sans
  lui `link.exe` est absent et chaque suite échoue pour une raison qui ne dit
  rien du helper — puis exécute le catalogue, une suite à la fois, et rend un
  verdict par nom. Les arguments reproduisent ceux de la porte native ; la
  suite des handles suspendus reste non optimisée parce que la porte hébergée
  ne l'optimise pas non plus.

Le catalogue exécuté : `secret-crash-contract`, `native-lib`, `protocol`,
`delayed-start-contract`, `parent-contract`,
`windows-parent-spoof-contract`, `windows-agent-pipe-contract`,
`windows-personal-transport-contract`, `windows-live-prompt-contract`,
`windows-job-contract`, `win32-dialog` et `win32-identity-selection`.

`win32-identity-selection` éprouve la sélection d'identité de la fenêtre
d'accès personnel **dans le processus du test** : le contenu de la liste lu
depuis le contrôle lui-même, l'absence de tout certificat, l'acceptation
indisponible tant qu'aucune empreinte n'est nommée, l'empreinte que porte le
consentement, et les refus inchangés. Elle n'interroge jamais la visibilité de
la fenêtre — c'est pour cela qu'elle est observable ici, là où
`windows-live-prompt-contract` ne peut pas l'être.

`windows-agent-pipe-contract` est la seule suite du catalogue qui **mute** la
machine : elle arrête puis démarre le service `ssh-agent`, parce que c'est lui
qui tient ou libère le nom de pipe qu'elle met en cause, et elle repose la
configuration de démarrage qu'elle a trouvée. Elle exige donc un compte
administrateur pour *disposer la scène* — c'est aussi ce que la porte hébergée
offrirait — mais elle n'en exige pas un pour *attester* : sa seconde épreuve
fait chaque observation sous un jeton dont `Administrators` est désactivé et
dont tous les privilèges sont retirés, et exige que l'agent vivant y reste
attesté et qu'un squatteur y reste refusé. C'est la moitié qui compte : mesuré
sur Windows Server 2025, un simple membre de `Users` se voit refuser
`OpenProcess` sur le service `ssh-agent` avec `ERROR_ACCESS_DENIED`, pour
`PROCESS_QUERY_LIMITED_INFORMATION` comme pour `PROCESS_QUERY_INFORMATION`,
alors que `ssh-add -l` lui répond normalement. Une attestation qui aurait exigé
ce descripteur aurait fermé l'accès personnel contre l'utilisateur même de
`ssh-agent` ; c'est le propriétaire de l'objet pipe — lisible par tout compte
que le pipe laisse entrer — qui porte désormais la décision.

Cette mesure a été faite ici sous un **vrai compte local standard**, synthétique
et jetable, membre de `Users` seulement, exécuté par une tâche planifiée : une
session ouverte par OpenSSH est la session 0, dont un compte standard ne peut
pas ouvrir la station de fenêtres, et un processus créé là y meurt à
l'initialisation de ses DLL. Sous ce compte, agent vivant : `CreateFileW` sur le
pipe réussit — `READ_CONTROL` compris —, `GetNamedPipeServerProcessId` répond,
`OpenProcess` échoue avec `ERROR_ACCESS_DENIED`, `GetSecurityInfo` rend
`S-1-5-18`, et `ssh-add -l` répond normalement. Le binaire de fixture lancé par
ce compte rend `ATTESTED owner=S-1-5-18 image=- account=-` face à l'agent et
`REFUSED ForeignPipeOwner` face à un squatteur créé par ce même compte, sans lui
avoir envoyé un octet. Le compte a été retiré ensuite ; le harnais versionné ici
n'en crée aucun.

### Usage

La machine est décrite par l'environnement, jamais par ces fichiers :

```text
export YOUR_CLOUD_WINDOWS_LAB_ADDRESS=…       # adresse de la machine
export YOUR_CLOUD_WINDOWS_LAB_KEY=…           # chemin de la clé privée, 0600
export YOUR_CLOUD_WINDOWS_LAB_KNOWN_HOSTS=…   # clés d'hôte épinglées
tests/lab/v0.1.0/windows-helper/prove                 # outils, sources, suites
tests/lab/v0.1.0/windows-helper/prove tools
tests/lab/v0.1.0/windows-helper/prove sync
tests/lab/v0.1.0/windows-helper/prove run [suite...]
```

`YOUR_CLOUD_WINDOWS_LAB_USER` (défaut `Administrator`),
`YOUR_CLOUD_WINDOWS_LAB_DOMAIN` (défaut `windows-eval`) et
`YOUR_CLOUD_WINDOWS_LAB_PROFILE` (`release` ou `debug`) complètent cette
description.

### Limites et hygiène

- Aucune adresse, aucun chemin de clé et aucune matière de clé ne vit dans ces
  fichiers. La garde d'inventaire exige en outre que la machine ne porte **pas**
  l'origine `your-cloud/labctl` — elle est délibérément hors du contrôleur — et
  que l'adresse annoncée par l'environnement soit exactement celle que libvirt
  lui a attribuée.
- La même garde refuse de démarrer tant qu'une VM `labctl` tourne : six
  gibioctets de Windows et la topologie Linux ne partagent pas un laptop.
- La vérification stricte de la clé d'hôte n'est jamais relâchée et le harnais
  refuse une machine non épinglée. La confiance au premier contact n'en est pas
  une : la clé d'hôte est épinglée au provisionnement, hors de ce harnais.
- **Ce que ce transport ne peut pas observer.** Une session ouverte par
  OpenSSH est la session 0, dont la station de fenêtres n'est pas interactive :
  un dialogue modal y est bien créé — classe `#32770`, titre présent — mais il
  n'y gagne jamais le style `WS_VISIBLE`. `windows-live-prompt-contract`, qui
  cherche une fenêtre **visible** appartenant au processus fils, échoue donc
  ici sans rien dire du helper ; le reste de son contrat, lui, est vérifié.
  `run.ps1` imprime le numéro de session pour que ce rouge soit lisible plutôt
  que subi. Seule la porte native hébergée observe ce cas de bout en bout.
- `--release` est le défaut parce que la porte hébergée l'emploie.
  `YOUR_CLOUD_WINDOWS_LAB_PROFILE=debug` existe pour une machine trop étroite,
  et une exécution en `debug` doit se déclarer comme telle : elle n'observe pas
  le même code.
- Cette machine n'est **pas** une autorité d'attestation. Elle ne produit ni
  `.msi`, ni signature, ni gate PE, et une exécution verte ici ne ferme aucune
  ligne de palier. La porte native `workflow_dispatch` le reste.
- La VM reste démarrée : ce harnais ne crée, ne démarre ni n'arrête aucun
  domaine. `tools/labctl assert-clean` ne la voit pas ; son arrêt est explicite
  et décrit par les [règles LAB](../../../docs/lab/README.md).
- La présence de ces sources ne constitue pas une preuve. Seule une exécution
  identifiée en est une.

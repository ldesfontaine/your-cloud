# Preuve LAB de `v0.1.0`

Ce dossier contient les harnais LAB du palier `v0.1.0`. Il ne prépare aucune
capacité d'un autre palier et ne remplace aucun contrôle générique.

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
`windows-live-prompt-contract`, `windows-job-contract` et `win32-dialog`.

`windows-agent-pipe-contract` est la seule suite du catalogue qui **mute** la
machine : elle arrête puis démarre le service `ssh-agent`, parce que c'est lui
qui tient ou libère le nom de pipe qu'elle met en cause, et elle repose la
configuration de démarrage qu'elle a trouvée. Elle exige donc un compte
administrateur — sans quoi ni le service ni le processus qui sert le pipe ne
sont interrogeables — et c'est aussi ce que la porte hébergée offrirait.

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
`YOUR_CLOUD_WINDOWS_LAB_DOMAIN` (défaut `lab-windows`) et
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

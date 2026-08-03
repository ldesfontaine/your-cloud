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

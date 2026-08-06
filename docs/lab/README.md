# LAB de développement

`labctl` est le contrôleur borné des VM KVM/libvirt utilisées pour le
développement et les preuves. Il appartient à l'outillage de développement,
pas au produit.

## Règle de placement

Le laptop sert uniquement à éditer, inspecter Git et contrôler le LAB. Aucun
composant, test, build, serveur, playbook ou import exécutable du projet n'y est
lancé. Le code produit s'exécute dans une VM LAB ou un runner distant isolé.

## Capacités du contrôleur

[`tools/labctl`](../../tools/labctl) fournit notamment :

- une image Debian 13 datée et vérifiée par SHA512 ;
- la création et l'inspection de VM libvirt sans `sudo` ;
- des métadonnées d'origine et de gabarit contrôlées avant mutation ;
- des réseaux LAB séparés ;
- les snapshots et retours à un état propre ;
- des commandes SSH et de copie qui utilisent une identité synthétique dédiée.

Les noms de gabarits et de topologies tels que `console`, `coordinateur`,
`quick` ou `v1-full` décrivent uniquement l'outillage LAB. Ils ne constituent
ni l'architecture du produit ni une preuve fonctionnelle. Toute évolution de
ces profils suit le besoin du scénario concerné sans réutiliser implicitement
un ancien rôle.

## Garde obligatoire

Avant toute mutation de VM :

1. exécuter `tools/labctl list` pour une lecture humaine ou
   `tools/labctl list --format=tsv` pour une garde automatisée ;
2. confirmer l'origine et le gabarit de chaque cible ;
3. vérifier que son adresse diffère de `192.168.122.123` et `10.66.66.1` ;
4. arrêter immédiatement au moindre doute, en traitant la cible comme une
   production possible.

Une cible réelle ou une production exige une autorisation explicite qui nomme
la machine et le geste. Cette autorisation ne se déduit jamais d'un accès
technique existant.

`labctl` applique également ces gardes aux commandes mutantes. Cela ne remplace
pas le contrôle humain préalable.

## Fermeture obligatoire

Une VM arrêtée reste définie avec ses volumes et snapshots ; un réseau libvirt
persistant peut également rester actif sans VM connectée. La fin d'une tâche
LAB exige donc l'un des deux états explicites suivants :

1. chaque topologie devenue inutile est retirée avec
   `tools/labctl topology destroy <topologie>`, puis
   `tools/labctl assert-clean` réussit ;
2. une topologie est volontairement conservée pour une reprise identifiée :
   le compte rendu nomme la topologie, la raison, la prochaine tâche responsable
   et le résultat rouge attendu de `tools/labctl assert-clean`.

Une simple série de `stop` ne constitue pas une fermeture. La commande
`assert-clean` ne modifie rien : elle refuse les VM et réseaux portant
l'origine `your-cloud/labctl`, ainsi que les noms `lab-*` suspects. Elle échoue
également si l'inventaire libvirt est inaccessible, afin qu'une erreur de
contrôle ne puisse jamais être confondue avec un LAB vide.

Le contenu de `keys.txt` et de `/srv/infra/secrets/` ne doit jamais être lu,
affiché ou copié. Seuls des secrets synthétiques générés pour le scénario
entrent dans le LAB.

Un playbook réel reçoit d'abord un `--syntax-check`, puis un second passage doit
produire `changed=0`, entièrement dans le LAB. Une preuve non exécutée reste
annoncée comme telle.

## Commandes disponibles

```text
tools/labctl list [--format=tsv]
tools/labctl topology create <quick|v1-full>
tools/labctl topology inspect <quick|v1-full>
tools/labctl topology prepare v1-full
tools/labctl topology destroy <quick|v1-full>
tools/labctl revert <vm> [snapshot]
tools/labctl assert-clean
tools/labctl start <vm>
tools/labctl stop <vm>
tools/labctl ssh <vm> [commande...]
tools/labctl copy-to <vm> <source> <destination>
tools/labctl copy-from <vm> <source> <destination>
```

La sortie TSV possède les colonnes fixes `vm`, `state`, `ips`, `template`,
`topology` et `origin`. Plusieurs adresses sont séparées par une virgule ; une
VM arrêtée sans adresse rend `-`. Une erreur d'inspection d'une VM active reste
bloquante.

Pour `v0.0.1`,
[`tests/lab/v0.0.1/prove`](../../tests/lab/v0.0.1/prove) est l'entrée
d'orchestration. Le poste de développement ne fait qu'empaqueter le lot non
sensible, calculer ses empreintes et appeler `labctl`.
[`tests/checks/source-v0.0.1`](../../tests/checks/source-v0.0.1) s'exécute en
mode `lab` dans `lab-console` ou en mode `ci` dans un runner CI distant isolé ;
aucun de ces contrôles ni aucun build ne s'exécute sur le laptop. HTTP et
systemd restent propres à la preuve dans les VM LAB. Une erreur après mutation
sélectionne et vérifie l'état absent ; un succès réinstalle l'état final
documenté.

Pour `v0.1.0`,
[`tests/lab/v0.1.0/personal-access/prove`](../../tests/lab/v0.1.0/personal-access/prove)
est l'entrée d'orchestration du périmètre de l'accès personnel. Elle applique la
même garde d'inventaire, monte les deux côtés du périmètre sur `lab-console` et
`lab-machine-1`, exécute la suite `personal-access-contract`, puis démonte et
prouve l'absence de ce qu'elle a créé, même lorsque la suite échoue. Les
comptes, clés et agents sont synthétiques et générés au montage ; les deux VM
restent démarrées et aucune topologie n'est créée ni détruite.

Les **contrôles génériques** sous [`tests/checks/`](../../tests/checks/) portent
sur les sources et contrats réutilisables. La **preuve LAB** sous
[`tests/lab/`](../../tests/lab/) ajoute le placement réel, les processus,
systemd, le réseau et le nettoyage multi-VM. Une CI classique peut accueillir
la première couche dans une image isolée. La seconde exige un runner dédié avec
libvirt et les gabarits `labctl` ; une image préconstruite ne fournit pas à elle
seule cette topologie.

`labctl` reste donc utile dans deux contextes : pilotage autorisé depuis le
poste de développement et pilotage depuis un futur runner CI dédié. Dans les
deux cas, la même garde d'inventaire précède toute mutation.

L'existence d'une topologie dans `labctl` signifie uniquement que l'outil sait
la créer. Une capacité devient prouvée seulement après une exécution réelle,
documentée et reproductible dans le LAB approprié.

## Rapports exécutés

- [`v0.1.0` — audit d'endpoints déclarés, sans mutation et sans scan](v0.1.0-endpoint-audit.md) :
  passage `quick` du 6 août 2026 pour #36, à la révision `aac5d843`. La lecture
  seule est **prouvée et non affirmée** : l'empreinte de la machine auditée —
  chemins, tailles, dates de modification et modes — est identique avant et
  après sept audits, si bien qu'un fichier réécrit à longueur égale serait vu
  par sa date. L'endpoint canari est un vrai `sshd` portant la même clé d'hôte,
  les mêmes comptes et les mêmes algorithmes que l'endpoint déclaré, et ne
  déviant que sur un point : personne ne le déclare jamais. Il ne gagne pas une
  connexion — et son **contrôle positif appartient au cas**, une session
  délibérée y étant ouverte à la fin, sans quoi un journal vide n'aurait rien
  dit de l'audit et tout du journal. Chaque incompatibilité est assertée par
  égalité : la machine qui ne dévie que d'un point produit exactement ce
  refus-là, et celle qui dévie deux fois les nomme tous les deux. Une machine
  muette est refusée pour n'avoir **pas répondu**, pas pour avoir répondu faux.
  Une session d'audit ne garde aucun canal pour s'élever, et une recommandation
  n'installe rien — seule l'approbation exacte en est une. Limite qui commande
  la lecture du reste : **les machines déviantes sont synthétiques**, aucune
  vraie Ubuntu ni `aarch64` n'existant dans ce LAB, et le canari vit sur la
  machine auditée plutôt que sur une troisième machine du réseau.
- [`v0.1.0` — remplacement explicite d'un Controller, et retrait de ses autorités](v0.1.0-controller-replacement.md) :
  passage `quick` du 5 août 2026 pour #40, le seul palier dont le sujet est ce
  qui se passe **quand on ne sait pas**. `lab-console` est **réellement
  arrêtée** : la panne jugée est une vraie panne, observée depuis deux postes
  indépendants d'espèces différentes — une tentative TCP depuis `lab-machine-1`
  et l'état du domaine rapporté par l'hyperviseur — et les 310 secondes de
  silence qui qualifient la perte sont des secondes qui se sont écoulées. Rien
  ne bascule sans que l'utilisateur le demande ; un Controller qui répond encore
  rend `ControllerStillAnswering` alors qu'il écoutait vraiment ; un silence
  plus jeune que la borne rend `Ambiguous(SilenceTooYoung)`. La perte matérielle
  et la suspicion de compromission sont **deux séquences** que la porte rend
  elle-même, la seconde commençant par l'isolement et le refusant absent. Le
  socket du lecteur est relevé fermé à chacune des quatre transitions, et un
  manifeste nommant deux Controllers est refusé. L'ancienne identité n'est
  retirée qu'après que la nouvelle a répondu **sur la même machine**, le retrait
  exigeant par signature le témoin de #39 ; ensuite un vrai `sshd` répond
  `Permission denied (publickey)` à l'ancienne autorité sur les deux machines.
  La clé personnelle d'un vrai compte est **nommée parmi les conservées**. Les
  quatre états sont reconstruits depuis la machine après coupure, et le
  désaccord entre le fichier `root` et le fil rend `unknown` plutôt que la plus
  commode des deux lectures. Trois épreuves par mutation font rougir la suite.
  Aucun Controller Go ne tourne, aucun vrai lecteur Relay n'est servi,
  l'isolement n'est pas exécuté et il n'y a pas de VM hostile distincte.
- [`v0.1.0` — identité SSH bornée par machine, et activation des rôles approuvés](v0.1.0-machine-identity.md) :
  passage `quick` du 5 août 2026 pour #39. Chaque machine reçoit une paire qui
  n'est la sienne que sur elle : un **vrai `sshd`** refuse l'identité de
  `lab-machine-1` sur `lab-console` et l'inverse, et la porte compilée rend
  `ForeignIdentity`, `Unattributed` et `SharedIdentity` sous leur propre nom. La
  commande forcée n'ouvre ni shell, ni PTY, ni SFTP, ni fichier rc, ni X11, ni
  transfert de port ou d'agent, ni argument libre, chaque capacité étant refusée
  **à côté de son contrôle positif** sur le même serveur au même instant ; la
  règle `sudo` n'autorise qu'une invocation exacte, sans `SETENV`. Le Controller
  parcourt lui-même le nouveau chemin avant toute activation, et l'Auxiliaire
  reste un diagnostic en lecture seule (`changed: false`). Ce passage inclut
  l'arbitrage sur la frontière laissée ouverte par la passe précédente : **#36
  place désormais le rôle Agent**, avec ses exigences propres — aucun critère de
  confidentialité de placement, un plancher de ressources dérivé de sa propre
  unité — et l'activation d'un Agent explicitement approuvé est prouvée avec son
  contrôle négatif et le refus d'un chemin non vérifié. Six points d'arrêt
  rendent un registre que le déroulé reconstruit, une coupure rend `INCOMPLETE`
  et nomme ce qui reste. Deux épreuves par mutation font rougir la suite. Aucune
  unité n'est réellement démarrée : l'activation est une décision typée.
- [`v0.1.0` — installation d'un Controller depuis le lot embarqué](v0.1.0-controller-install.md) :
  passage `quick` du 5 août 2026 pour #38, premier palier qui **mute réellement**
  une machine. Le lot Debian 13 `amd64` est construit par la preuve, son
  manifeste signé lie version, cible, taille et SHA-256, et l'Assistant le juge
  avant tout privilège : artefact altéré d'un octet, artefact tronqué, manifeste
  réécrit, manifeste signé par une autre clé, `arm64`, autre version et autre
  genre sont refusés chacun par sa propre raison, avec leurs contrôles positifs.
  Le paquet ne possède que `/usr/lib/your-cloud/your-cloud` `root:root` `0755`
  et trois unités `root:root` `0644` livrées inactives, sans setuid, setgid ni
  capacité ; une seule unité est activée. Le Controller tourne sous un compte
  dynamique sans capacité, avec `TasksMax=128` et `MemoryMax=384 Mio`, ses
  secrets `root:root` `0600` remis par systemd seul. `lab-console` est
  **réellement arrêtée** après extinction des processus de l'Assistant : le
  Controller garde le **même PID** et écoute toujours. Un arrêt à chacune des
  quatre premières étapes rend un registre que le déroulé reconstruit
  exactement, et la machine revient à son état initial à chaque fois. Trois
  épreuves par mutation font rougir la suite. Le lot n'est pas encore embarqué
  dans l'installateur de la Console et l'ancre n'y est pas scellée.
- [`v0.1.0` — approbation signée vérifiée sans faire confiance au Controller](v0.1.0-signed-approval.md) :
  passage `quick` du 5 août 2026 pour #37. Le cœur natif signe une enveloppe
  canonique versionnée qui lie infrastructure, machine, époque, séquence, plan,
  rollback, privilèges, émission, expiration et clé d'approbation ; l'Auxiliaire
  de diagnostic la vérifie contre sa propre ancre `root`, consomme
  atomiquement la séquence avant tout traitement et refuse rejeu, séquence
  ancienne, sautée ou concurrente. Un vecteur déterministe unique est épinglé
  côté Console et côté Auxiliaire : la signature produite par le code Rust est
  vérifiée par le code Go. `lab-machine-1` est **réellement arrêtée puis
  redémarrée** par le contrôleur du LAB ; la position anti-rejeu est retrouvée
  octet pour octet et les mêmes refus tiennent. Une nouvelle clé humaine laisse
  l'action verrouillée jusqu'à la rotation de l'ancre par l'accès personnel.
  Trois épreuves par mutation font rougir la suite. Aucune mutation n'est
  exécutée : le rapport de l'Auxiliaire porte `changed: false`.
- [`v0.1.0` — bornes KDF et politique `sudo` de l'accès personnel](v0.1.0-personal-access-bounds.md) :
  passage `quick` du 3 août 2026 pour #51. La calibration `bcrypt_pbkdf` sur
  `lab-console` rend environ 4,6 ms par round, identiques pour Ed25519 et RSA
  3072, et fixe `MAX_BCRYPT_ROUNDS = 2048`, vérifié à 9355 ms sur les 300 s de
  l'échéance. La matrice `sudo` réelle sur Debian 13 valide les refus de
  `log_input` et `log_stdin` et révèle que les entrées Defaults sont réparties
  sur plusieurs lignes ; les cinq captures sont figées comme fixtures. 65 tests
  verts, secrets exclusivement synthétiques, compte et politiques retirés. Un
  second passage y ajoute les décisions pures de #52 : cible résolue une seule
  fois puis gelée contre le rebinding DNS, refus du lien-local et donc de
  l'endpoint de métadonnées cloud, normalisation des adresses IPv4 encapsulées
  et admissibilité de l'endpoint d'agent. L'observation d'un vrai `ssh-agent` y
  révèle que le socket `0600` est protégé par son répertoire parent `0700`, et
  non par son propre mode ; la règle vérifie désormais le parent. 86 tests
  verts. Ces passages ne prouvent ni connexion SSH, ni signature d'agent, ni
  envoi de mot de passe : ils restent à #52, #53 et #54.
- [`v0.1.0` — consentement natif et mémoire secrète Linux/Windows](v0.1.0-native-secret-consent-linux-windows.md) :
  #45 prouvée sur `c0569d0` par `30779157351` puis fermée le 3 août 2026 ;
  `ae550470bcff08c08624988c17d16db6cb62070a` reste un candidat intermédiaire et
  `c8643b0903aee8ad194fb7c34ae6e459c52550a3` ajoute la preuve de retrait
  manquante.
  `30768351689` et `30768749538` sont rouges sous l'ancien oracle ; ils
  caractérisent `LocalDumps` administrateur hors garantie avec contrôle et
  canari présents. `30769440106` a réussi ses quatre jobs sur `ae550470` et
  prouve cette observation, la suppression du dump, le répertoire vide et les
  deux inscriptions de registre absentes ; le répertoire n'est retiré
  qu'ensuite par `Drop`. Cette preuve reste intermédiaire et ne ferme pas #45.
  `c8643b0` exige désormais son absence avant verdict avec
  `remove_and_prove_absent`. `30770893733` réussit ensuite ses quatre jobs sur
  `b76ded8`, avec matrice native, paquets et trois artefacts inspectés. Le
  rapport distingue les sous-cas Linux exécutés, les limites
  Windows et l'enregistrement WER en défense en profondeur. Après trois
  corrections du harnais de captures, `30779157351` réussit ses quatre jobs sur
  `c0569d0` : ce run et ce SHA ferment #45. Cette
  preuve ne ferme ni #42, ni #35, ni le palier #13 ou `v0.1.0`.
- [`v0.1.0` — bornage IPC et helper Windows](v1-bootstrap-ipc-windows.md) : run
  GitHub Actions manuel `30753216798` entièrement vert sur le candidat produit
  exact `f3fef79` ; tests Linux et Windows, Job Object et arbre de processus,
  branches hostiles avant reprise, `.deb`, `.msi`, gates ELF/PE, installation,
  dispatch Tauri vivant depuis WebView2, refus forge/concurrence/rejeu, absence
  de listener et nettoyage exécutés le 2 août 2026. Cette intégration ferme
  #43 ; elle ne ferme ni #45, ni #42, ni #35, ni le palier #13 ou `v0.1.0`.
- [`v0.1.0` — bornage IPC et gate du helper Linux](v1-bootstrap-ipc-linux.md) :
  passage LAB Linux historique du 2 août 2026 ; WebKitGTK et JavaScriptCoreGTK
  sont des dépendances directes du binaire Console, ce qui impose le helper
  compagnon distinct prévu par #44. Le premier consentement GTK3 sans secret et
  la récolte autonome y sont prouvés. Les manques #43 Windows et Tauri vivant
  sont traités par le rapport Windows ci-dessus ; les secrets de #45 et l'accès
  SSH de #42 restent ouverts.
- [`v0.0.3` — porte Linux Console–Controller](v0.0.3-console-controller-linux.md) :
  `.deb` signé et installé, coffre et appairage, deux Controllers séparés,
  matrice hostile depuis une seconde VM, frontière réseau privée, Relay
  indisponible, donnée ancienne, lacune, reprise, redémarrages et sept vues
  claires/sombres exécutés le 20 juillet 2026 puis parcours critique revalidé le
  22 juillet. Après une matrice historique, la porte native Linux/Windows finale
  `30710037004` a entièrement réussi dans GitHub Actions sur le candidat produit
  exact `3b8f81f`. Elle reste une preuve hébergée distincte et ne modifie pas les
  faits du rapport LAB Linux. L'issue `#9` relie le run et le SHA intégré par
  fast-forward : `v0.0.3` est fermée pour ce candidat exact.
- [`v0.0.2` — observation authentifiée et bornée](v0.0.2-observation.md) :
  mTLS, enrôlement et révocation, profil fixe, tampon saturé avec lacune,
  reprise, redémarrages et cycle retrait-réinstallation exécutés dans
  `v1-full` le 18 juillet 2026 ; orchestration encore assistée.
- [`v0.0.1` — un artefact, trois processus isolés](v0.0.1-presence.md) : build
  Go unique, Daemon et Relay parallèles sur le VPS, Daemon seul sur le LAN,
  refus candidat et HTTP, transitions `recent`/`old`/`absent`, retrait et
  réinstallation dans `v1-full`, preuve initiale le 16 juillet puis référence
  automatisée propre le 17 juillet 2026, puis revalidation historique depuis
  les chemins réorganisés avec le run `20260717T100150Z-1543398`, antérieur aux
  derniers durcissements du banc et de la CI.

## Point d'arrêt avant la prochaine preuve

La preuve fonctionnelle `v0.0.3` a employé les six VM Debian de `v1-full` et son
résultat Linux reste conservé dans le rapport ci-dessus. Le runner Windows
hébergé porte uniquement la différence native : tests propres à la plateforme,
build et signature synthétique du `.msi`, installation, lancement, absence de
listener et smoke WebView2. Il ne reçoit aucune VM, route ou doublure de
Controller, Relay ou Daemon. Les flux, identités distribuées, pannes, reprises
et scénarios multi-VM restent sous l'autorité du LAB Linux.

## LAB Windows

Ce document n'ouvrait auparavant un LAB Windows que pour un défaut fonctionnel
réellement propre à Windows. Cette position reposait sur une prémisse devenue
fausse le 3 août 2026, jour de l'épuisement du quota Actions : la CI hébergée
ne couvre pas Windows sans contrainte. La décision de placement des preuves
[`#67`](https://github.com/ldesfontaine/your-cloud/issues/67) remplace donc
cette position.

Ce LAB Windows minimal existe depuis le 4 août 2026. Il tient dans un seul
domaine libvirt, `lab-windows` : Windows Server 2025 Standard Évaluation avec
interface graphique — le même système que le runner `windows-2025` de la porte
native, délibérément —, 6 Gio de mémoire, 4 processeurs virtuels, un disque de
80 Gio alloué à la demande et le réseau libvirt `default`. Il porte
l'outillage épinglé que la porte native emploie : les outils de build MSVC x64
et le SDK Windows, `rustc` et `rustfmt` `1.94.1` en `x86_64-pc-windows-msvc`,
Node.js `24.18.0`, le runtime WebView2 Evergreen et OpenSSH.

Cette VM est provisionnée **manuellement** et reste hors `labctl`, qui ne
connaît aujourd'hui qu'une image Debian datée et vérifiée par SHA512 ; une
automatisation complète attend que sa valeur soit démontrée. Elle sert la
validation continue du helper Windows pendant le développement, au même titre
que le LAB Linux pour sa moitié :
[`tests/lab/v0.1.0/windows-helper/prove`](../../tests/lab/v0.1.0/windows-helper/prove)
y synchronise les sources natives de la Console et y exécute les suites de
contrat propres à Windows — Job Object et handles suspendus, pipe nommé et
parent déclaré, dialogue Win32 vivant, crash et dump du secret — avec les
invocations exactes de la porte native. Son adresse et sa clé viennent de
l'environnement ; aucune ne vit dans le dépôt.

Elle ne devient pas une autorité d'attestation. La CI hébergée conserve ce
rôle : la porte native `workflow_dispatch` sur le candidat de palier reste
exigée pour fermer un palier, selon le [contrat CI](../contribution/CI.md). Une
observation faite dans ce LAB Windows ne ferme donc rien à elle seule, et elle
ne simule jamais la topologie multi-VM, qui reste propre au LAB Linux. Elle ne
produit ni `.msi`, ni signature Authenticode, ni gate PE, ni smoke WebView2
archivé.

**Sa fermeture est explicite.** `tools/labctl assert-clean` ne voit pas ce
domaine : il refuse les VM portant l'origine `your-cloud/labctl` et les noms
`lab-*` suspects, mais `lab-windows` n'a été créée ni par le contrôleur ni avec
ses métadonnées. Un `assert-clean` vert ne dit donc rien de six gibioctets
encore alloués. La fin d'une tâche qui l'emploie exige la commande suivante,
nommée dans le compte rendu :

```text
virsh -c qemu:///system shutdown lab-windows
```

Pour la même raison de mémoire, cette VM et les VM Debian de `labctl` ne
tournent jamais ensemble sur le poste ; le harnais refuse de démarrer lorsque
c'est le cas.

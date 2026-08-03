# `v0.1.0` — bornage IPC et gate du helper Linux

## Statut

Preuve Linux partielle exécutée puis étendue le 2 août 2026. À la révision de ce
passage, le bornage natif #43 compilait et ses scénarios d'état étaient verts
dans le LAB, mais l'absence d'équivalent Windows et de dispatch Tauri vivant
interdisait encore sa fermeture. Le gate ELF invalide le helper dans le même
exécutable Tauri et le binaire compagnon distinct prévu par #44 possède une
fondation fail-closed séparée de WebKit. L'extension prouve le lancement par le
parent Console, son arrêt borné et le premier dialogue GTK3 de consentement,
sans champ secret et sans succès d'amorçage inventé. Une revue finale a en outre
remplacé toute récolte bloquante par un worker créé avant le helper : l'appel
Console reste borné, la récolte continue sans nouvelle action et un résultat
non prouvable interdit tout nouveau lancement.

La [preuve native Linux/Windows suivante](v1-bootstrap-ipc-windows.md), exécutée
sur le candidat exact `f3fef79`, apporte le Job Object, les branches hostiles
Windows, le paquet MSI et le dispatch Tauri vivant qui manquaient à #43. Les
constats ci-dessous restent ceux de ce passage LAB Linux et ne sont pas réécrits
rétroactivement. #45 reste ouverte pour Win32, les secrets, l'annulation
coopérative et les protections mémoire ; #42 reste ouverte pour la connexion
SSH et ses vrais descendants.

## Candidat et placement

- branche de travail : `assistant-amorcage-natif` ;
- base Git locale : `3efdfcc` ;
- lot `console/` final hors `node_modules`, `dist`, `src-tauri/target` et
  `src-tauri/binaries` :
  `2c5acb2dbd2c33e4528f3015a71d090e906fe607dc051b000c49f23c00fdf5c9`,
  142848 octets ;
- empreinte contrôlée identique avant et après copie dans `lab-console` ;
- topologie : `quick`, VM `lab-console`, gabarit `console`, IP
  `192.168.240.185` ;
- système : Linux `6.12.90+deb13-cloud-amd64`, `x86_64`, Debian 13 ;
- Rust/Cargo `1.94.1`, Node.js `20.19.2`, npm `9.2.0`, LLD `19`,
  `pax-utils` `1.3.8` ;
- WebKitGTK et JavaScriptCoreGTK `2.52.5-1~deb13u1`.

Aucun contenu de `keys.txt` ou de `/srv/infra/secrets/` n'a été lu ou copié.
Le lot ne contient aucun secret ; les coffres créés par les tests utilisent
uniquement des données synthétiques dans la VM.

### Extension parent et consentement GTK3

- branche de travail : `assistant-amorcage-natif` ;
- base Git locale inchangée : `3efdfcc` ;
- snapshot de matrice complète de `.github/` et `console/`, hors `node_modules`,
  `dist`, `src-tauri/target` et `src-tauri/binaries` :
  `a0ef950ca69b4cdd298a00d8596fc202ea655b4a6553bb9669c511030a3d88c9`,
  155108 octets ;
- empreinte contrôlée identique avant et après copie dans `lab-console` ;
- topologie : `quick`, VM `lab-console`, gabarit `console`, IP
  `192.168.240.172` ; `lab-machine-1`, IP `192.168.240.193`, est restée hors
  du scénario ;
- système : Linux `6.12.90+deb13-cloud-amd64`, `x86_64`, Debian 13 ;
- Rust/Cargo `1.94.1`, Node.js `20.19.2`, npm `9.2.0`.

Ce snapshot étendu est distinct du premier candidat historique décrit
ci-dessus. Toutes les assertions ajoutées ci-dessous ont été rejouées depuis
son répertoire extrait neuf, et non attribuées rétroactivement au premier lot.

## Actions et résultats observés

| Action | Résultat observé |
|---|---|
| dépendances npm | les 33 paquets installés par `npm ci` pour le même `package-lock.json` ont été réutilisés ; le verrou n'a pas changé |
| `npm test` sur le snapshot de matrice complète | `source-contract: PASS`, `visual-contract: PASS` |
| `npm run build` | TypeScript et Vite verts, 1792 modules transformés |
| `cargo test --locked` sur le lot corrigé avant les deux derniers refus hostiles | 19 réussis, 0 échec, 1 test réseau explicitement ignoré, 605,66 s |
| tests du crate `your-cloud-bootstrap-protocol` | 8 réussis, 0 échec |
| tests du crate `your-cloud-native-bootstrap-assistant`, toutes cibles du paquet | 7 unitaires et 3 sous-processus réussis, 0 échec |
| `cargo test --locked bootstrap` sur le snapshot de matrice complète | 13 réussis, 0 échec, 75,11 s au dernier passage |
| `cargo build --locked --offline --bin your-cloud-console` sur le snapshot de matrice complète | succès sans avertissement avec LLD, binaire `a4fabcbec4d4b55d4a5cbca7daac0ecfbacf5a2586b99d554dc5b82b666255df` |
| `readelf -dW` sur ce binaire | `libwebkit2gtk-4.1.so.0` et `libjavascriptcoregtk-4.1.so.0` présents directement dans `DT_NEEDED` |
| build release hors ligne du helper distinct | succès, 780032 octets, SHA-256 `4089d8d1dd6d356283bce0fb04a0d1af671c8190c6180068dc3cf8fa2803abbb` |
| graphe Cargo de production du helper | 15 paquets avec le protocole partagé ; aucune famille Console, Tauri, Wry, Tao, WebKit, JavaScriptCore ou WPE |
| `DT_NEEDED`, `lddtree` et `/proc/<pid>/maps` du helper release | uniquement le helper, le chargeur ELF, `libc.so.6` et `libgcc_s.so.1` ; 35 mappings inspectés |
| protocole du helper release | une trame publique bornée rend l'unique événement expurgé `unavailable`, puis le processus sort avec le code non réussi `69` |
| mort du parent | le helper release bloqué sur son pipe disparaît après la mort de son parent ; aucun stderr ni processus survivant observé |
| SBOM CycloneDX 1.6 séparées | 14 composants dans la fermeture helper, 531 dans la fermeture Console ; aucun composant npm, Console ou WebView dans celle du helper |

### Actions de l'extension parent et GTK3

| Action | Résultat observé |
|---|---|
| `npm ci` sur le snapshot de matrice complète | 33 paquets installés depuis le verrou, 0 vulnérabilité signalée, verrou inchangé |
| `npm test` puis `npm run build` | contrats source et visuel verts ; TypeScript et Vite verts, 1792 modules transformés |
| préparation release du helper | succès, 839936 octets, SHA-256 `5d4c5ccd0075c29b72dc8e87780d4ce1f769a692dbc3b97cc5dd31890d8695ed` |
| graphe Cargo de production | 75 paquets dans la fermeture ; GTK3/GLib autorisés, aucune famille Console, Tauri, Wry, Tao, WebKit, JavaScriptCore ou WPE |
| en-tête et `DT_NEEDED` directs du helper | `PT_INTERP` désigne `ld-linux-x86-64.so.2` ; `DT_NEEDED` contient seulement `libc`, `libgcc_s`, `libglib-2.0`, `libgobject-2.0` et `libgtk-3` |
| `cargo test --release --locked --workspace --offline` | 47 tests actifs réussis ; 3 scénarios isolés ignorés par cette commande, dont les 2 scénarios GTK rejoués séparément |
| tests du dialogue sous Xvfb | refus, fermeture, expiration et autorisation sans faux succès réussis dans un même test release |
| test parent sous Xvfb | le parent transmet seulement la liste positive graphique après `env_clear`, observe le helper vivant, l'annule puis le récolte ; succès en 0,36 s |
| refus hostiles du processus | argument ou octet supplémentaire refusé, watchdog borné, descripteur explicitement rendu héritable fermé ; 4 tests réussis |
| contrat parent | corrélation stricte, trame bornée, échéance absolue non renouvelable et lancement réel du helper ; 4 tests actifs réussis |
| mappings du helper release vivant | 544 mappings ; GTK/GDK observés ; aucune occurrence WebKit, JavaScriptCore ou WPE ; exécutable vivant identique au SHA-256 préparé |
| SBOM CycloneDX 1.6 du helper | génération réussie avec 75 composants de fermeture, sans composant interdit par le gate |
| fin du probe | aucun processus ne conservait l'exécutable du helper selon `fuser` |

### Correctif final de récolte bornée

- snapshot final exact de `.github/` et `console/`, avec les mêmes exclusions :
  `0fc28a9a1a8d5b07156400568af603126c6c1486f617fa2664cc0f74e56c938e`,
  157920 octets ;
- empreinte identique avant et après copie dans `lab-console` ;
- VM Debian 13 `lab-console`, gabarit `console`, IP `192.168.240.134` ;
- Rust `1.94.1`, GTK3 `3.24.49`, compilation release hors ligne depuis le
  verrou, avec un répertoire `target` neuf.

| Action finale | Résultat observé |
|---|---|
| tests release de toutes les cibles du paquet helper | 18 tests actifs réussis : 8 unitaires, 6 contrats parent et 4 contrats processus ; 2 scénarios GTK isolés par la commande générale |
| récolte différée | un vrai processus hostile de 30 secondes est remis au worker autonome, tué et récolté sans nouvelle action ; un état de récolte non prouvable interdit un nouveau lancement |
| consentement GTK3 sous Xvfb | refus, fermeture, expiration et autorisation sans faux succès : 1 test réussi en 0,28 s |
| lancement GTK3 par le parent sous Xvfb | helper observé vivant, annulation et récolte : 1 test réussi en 0,36 s |
| formatage du snapshot exact | `cargo +1.94.1 fmt --check` réussi |
| fin du passage | `pgrep` ne trouve aucun `your-cloud-native-bootstrap-assistant` survivant |

Un premier rejeu incrémental a réutilisé l'artefact compilé depuis l'ancien
chemin et n'incluait donc pas les nouveaux tests. Il a été explicitement écarté
des preuves ci-dessus ; le passage retenu utilise un `target` vide et montre 6
contrats parent actifs, dont les deux nouveaux cas de nettoyage.

Le premier snapshot historique final inclut les deux corrections postérieures
au passage complet :
le verrouillage du coffre et l'effacement de l'amorçage précèdent désormais
toute attente du mutex réseau ; les IPv4 encapsulées en IPv6, notamment
`::ffff:127.0.0.1` et `::ffff:169.254.169.254`, suivent les mêmes refus que les
IPv4. Le passage ciblé final compile ces changements et exécute leurs cas
hostiles ainsi que les courses `start`/verrouillage et `start`/fermeture.

## Incidents du banc

Le premier `cargo test` a rempli le `tmpfs` de `/tmp`, limité à environ 1 Gio,
pendant la compilation Tauri. Les seuls artefacts Cargo temporaires ont été
retirés avec `cargo clean`, puis `CARGO_TARGET_DIR` a été déplacé vers
`/var/tmp/your-cloud-43-target` sur le disque de la VM.

Le linker GNU a ensuite été tué par la limite mémoire de la VM, qui possède
1,9 Gio sans swap. LLD 19 a été installé dans cette VM seulement et Cargo a été
relancé avec un job et un wrapper `cc -fuse-ld=lld`. Le build et les tests ont
alors terminé. Ces ajustements décrivent le gabarit de preuve ; ils ne modifient
pas le produit ni ses dépendances runtime.

Une régénération complète du verrou Cargo a proposé des mises à niveau registry
sans rapport avec le palier. Ce résultat a été refusé et le verrou antérieur a
été restauré. La mise à jour incrémentale hors ligne retenue ajoute seulement
les deux paquets workspace et la dépendance du paquet Console vers le protocole
partagé ; son SHA-256 final vaut
`c1a16f3b7b3c62a13856c496bb7fd6b3c50bd46cbc8fb333a96b1dc2f5a79c38`.

Le premier build Console du second passage a correctement refusé l'absence du
sidecar déclaré par Tauri. Le helper a été préparé et inspecté avant la relance.
Un import Rust réservé aux tests a ensuite produit un avertissement ; il a été
sorti du chemin de production, puis les 13 tests ciblés et le build Console ont
été rejoués sans avertissement.

Pendant l'extension, une insertion manuelle transitoire de `gtk` dans
`Cargo.lock` a ciblé le premier tableau de dépendances homonyme au lieu du
paquet helper. La revue du diff l'a détectée avant compilation ; l'entrée a été
retirée de `android_system_properties`, ajoutée au bloc
`your-cloud-native-bootstrap-assistant`, puis le verrou final a été consommé
avec `--locked --offline`.

Le premier snapshot d'extension ne contenait que `console/` : `npm test` s'est
arrêté avant assertion parce que le contrat source lit aussi
`.github/workflows/ci.yml`. Le snapshot final inclut les deux racines, possède
une nouvelle empreinte contrôlée et tous les tests lui sont attribués. La
préparation du helper a également refusé un premier appel distant sans
`YOUR_CLOUD_EXECUTION_ENV=lab`, puis a réussi avec ce marqueur uniquement dans
la VM.

Enfin, `labctl ssh` a retiré les guillemets d'un probe Python inline ; le shell
distant l'a refusé avant lancement. Un pilote temporaire copié dans `/tmp` a
remplacé cette commande, gardé le vrai helper release ouvert sous Xvfb pendant
l'inspection et l'a arrêté à échéance bornée.

Le gabarit minimal recréé pour le correctif final possédait Xvfb mais pas
`xauth`. Les deux commandes graphiques ont été refusées avant tout test ;
`xauth` a été installé dans la VM, puis les deux scénarios ont réussi. Aucun
échec produit n'est attribué à cet incident de banc.

## Ce que la preuve établit

- les enveloppes Tauri #43 reçoivent le corps JSON complet, refusent le corps
  brut et les champs inconnus, et bornent les chaînes avant leurs copies
  applicatives ;
- la cible, l'étape, l'action, l'identifiant et le TTL monotone de 300 secondes
  restent natifs et les sorties sérialisables suivent une liste positive ;
- annulation, expiration, verrouillage et fermeture rendent l'état inutilisable,
  y compris sous courses concurrentes testées avec de vrais coffres ;
- l'empreinte de clé d'hôte est décodée dans un tampon fixe et les cibles
  locales évidentes, y compris les IPv4 mappées, sont refusées ;
- le binaire Console Linux ne peut pas servir de helper sans WebKit : ses
  dépendances ELF directes chargent WebKitGTK et JavaScriptCoreGTK avant tout
  choix effectué dans `main` ;
- la fondation actuelle du helper est un paquet et un binaire autonomes, lancés
  seulement avec `--native-bootstrap-assistant`, sans plugin shell général ;
- son entrée encadrée est limitée à 4096 octets, sa sortie à 1024 octets, les
  champs supplémentaires sont refusés et le temps de lecture consomme le TTL au
  lieu de le renouveler ;
- le helper actuel ne charge directement, transitivement ou dynamiquement
  aucune bibliothèque Console, Tauri, WebView, WebKit, JavaScriptCore ou WPE ;
- son durcissement Linux s'exécute avant la lecture, le watchdog ferme une
  entrée gardée ouverte et `PDEATHSIG` ferme le processus avec son parent ;
- les fermetures Cargo et npm des deux artefacts sont inventoriées séparément.
- le parent conserve l'échéance native absolue au lieu de recréer un TTL,
  refuse un identifiant forgé sans arrêter la vraie session et tente toujours
  le nettoyage réseau après le verrouillage local ;
- sous Linux, le helper appartient à son propre groupe de processus, sa sortie
  est non bloquante pour le parent et les descripteurs hérités hors stdio sont
  fermés même lorsqu'un test les rend explicitement héritables ;
- le parent n'appelle aucun `wait()` sans échéance ; un worker de récolte est
  créé avant tout helper, poursuit le nettoyage hors du mutex et bloque les
  lancements suivants si une erreur rend la récolte non prouvable ;
- le parent lance le binaire exact avec un argument fixe, des pipes anonymes,
  un environnement vidé puis une liste positive limitée à l'affichage et à la
  locale ; les variables de chargement et `SSH_AUTH_SOCK` ne sont pas transmis
  dans ce palier. Cette observation reste celle de `#43` et n'a pas été
  réécrite : depuis, `#52` transmet `SSH_AUTH_SOCK` à la seule fenêtre d'accès
  personnel, les variables de chargement demeurant interdites ;
- le dialogue GTK3 répète en texte simple le parcours, la cible, la route,
  l'empreinte complète, l'étape, l'action, la demande et l'expiration ; refus,
  fermeture et expiration restent terminaux, tandis qu'une autorisation rend
  encore `unavailable` tant que l'audit #42 n'existe pas ;
- le workflow natif manuel est configuré pour préparer le sidecar puis tester
  explicitement tout le workspace ; les tests du helper, du processus et du
  parent ne dépendent plus des `default-members` du crate Console. Cette
  configuration source n'est pas présentée comme un run GitHub exécuté.

## Ce que ce passage Linux n'établit pas

Les manques propres à #43 cités dans cette liste ont depuis été traités par le
[rapport natif suivant](v1-bootstrap-ipc-windows.md). Ils restent ici pour
préserver la frontière exacte du snapshot et du LAB décrits dans ce document.

- le dispatch vivant d'un appel hostile depuis une vraie WebView Tauri ;
- l'équivalence du contrat et des courses sur un runner Windows ;
- les imports PE, les modules chargés, le Job Object et les protections mémoire
  du helper Windows, dont le durcissement est encore vide ;
- la résolution DNS et le refus, lors de la connexion #42, de toute adresse
  résolue vers loopback, link-local ou le laptop, y compris face au rebinding ;
- le dialogue Win32, une saisie secrète, `mlock`, `MADV_DONTDUMP`,
  `VirtualLock` et l'effacement mémoire ;
- l'effacement contrôlé lors du watchdog : le squelette actuel appelle
  `process::exit` et devra faire remonter une annulation avant de manipuler un
  secret ;
- la conservation de stdin comme lease d'annulation : le consentement sans
  secret ferme encore stdin après l'unique scope ; ce chemin doit devenir
  coopératif avant `KeyPassphrase` ou `SudoPassword` ;
- l'authentification forte du parent contre un autre processus local : le
  helper officiel accepte encore tout parent capable de lui fournir le
  protocole public, limite acceptable seulement tant qu'il ne collecte aucun
  secret et ne produit aucun succès ;
- la mort du parent pour de futurs sous-processus SSH ou `sudo` : le helper
  actuel n'en crée aucun, mais son seul `PDEATHSIG` ne suffira pas à fermer un
  descendant après un crash brutal de la Console ; avant #42, chaque enfant
  devra recevoir sa propre garde de mort-parent ou appartenir à un contenant
  noyau borné, avec un test hostile parent et descendant ;
- la fermeture atomique d'un arbre de processus sous Windows par Job Object ;
  le support produit Windows reste volontairement `unavailable` ;
- l'inclusion du helper dans un `.deb` ou un `.msi`, leur signature et leurs
  manifests candidats ; aucun paquet de release n'a été construit depuis ce
  worktree non committé ;
- une connexion SSH, un agent, une clé chiffrée, `sudo` ou une mutation de
  machine.

## Décision propagée

Le helper de `v0.1.0` devient un crate et un binaire compagnon autonomes
`your-cloud-native-bootstrap-assistant`, livrés dans la même release mais sans
dépendance à la Console, Tauri, Wry, Tao, WebKit ou JavaScriptCore. Sa fermeture
exigera le graphe Cargo, le `DT_NEEDED`, les dépendances transitives et
`/proc/<pid>/maps` sous Linux, puis les imports, la signature et le cycle de vie
équivalents sous Windows.

## Fermeture du LAB

Après vérification qu'aucun processus helper ni FIFO de preuve ne subsistait,
`tools/labctl topology destroy quick` a détruit `lab-machine-1` puis
`lab-console`. `tools/labctl assert-clean` a rendu
`aucune VM ni aucun réseau LAB persistant`. Le dernier `tools/labctl list` ne
montre plus que `gold`, arrêtée et hors de toute topologie.

Pour l'extension parent et GTK3, un premier appel de destruction dans le bac à
sable a rendu 0 sans accéder à libvirt ; l'inventaire suivant a correctement
montré que les deux VM tournaient encore et `assert-clean` a refusé l'absence
d'accès au socket. La commande a donc été rejouée avec l'accès libvirt requis :
`lab-machine-1` puis `lab-console` ont été détruites. L'assertion finale a rendu
`aucune VM ni aucun réseau LAB persistant` et le dernier inventaire ne montre
que `gold`, arrêtée et hors de toute topologie.

Après le correctif final, `pgrep` ne trouvait aucun helper survivant.
`tools/labctl topology destroy quick` a détruit `lab-machine-1` puis
`lab-console`, `tools/labctl assert-clean` a de nouveau rendu
`aucune VM ni aucun réseau LAB persistant`, et l'inventaire terminal ne montre
que `gold`, arrêtée et hors de toute topologie.

# `v0.1.0` — bornage IPC et helper Windows

## Statut

Preuve native hébergée entièrement verte le 2 août 2026 sur le candidat produit
exact `f3fef79b74a5e3115fb5fe93f21c6380ad116582`. Le run manuel
[`30753216798`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798)
a exécuté les deux gardes rapides puis les variantes Linux et Windows. Il ferme
les manques Windows et WebView vivante du bornage IPC #43. Cette intégration
documentaire relie la preuve au contrat et ferme l'issue.

Cette preuve ne ferme ni le consentement et la manipulation des secrets #45,
ni l'accès SSH personnel #42, ni leur parente #35. Elle ne ferme donc ni le
palier #13, ni sa milestone, ni `v0.1.0`. La suite reste `#45 → #42 → #35` avant
les contrats exécutables et la preuve globale du palier.

## Candidat et exécutions

- branche candidate : `assistant-ipc-windows-borne` ;
- commit produit exact :
  `f3fef79b74a5e3115fb5fe93f21c6380ad116582` ;
- déclenchement final : `workflow_dispatch`, run
  [`30753216798`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798) ;
- garde générique : job
  [`91510826593`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510826593),
  vert ;
- politique Plumber : job
  [`91510826335`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510826335),
  vert ;
- variante Windows : job
  [`91510938793`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510938793),
  verte ;
- variante Linux : job
  [`91510938804`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510938804),
  verte ;
- porte rapide de la pull request sur ce même SHA : run
  [`30753208857`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753208857),
  gardes générique et Plumber vertes ;
- verrou npm :
  `bb39f6f890355abe952bafc04b841ca6a9ab1c62a5d6f9fd67a7f7feeec792c9` ;
- verrou Cargo :
  `433cb2ad93fd644ed47b52ca25214b20ec30e96db38abbeeab9c3dbd7586e94e`.

Le JSON Windows publié confirme que le checkout correspond au SHA annoncé et
que le worktree du runner était propre avant le build. Aucun LAB KVM/libvirt
n'a été créé pour ce passage : les différences natives ont été exécutées sur
les runners GitHub jetables prévus par le contrat CI.

## Actions et résultats observés

### Variante Linux

La variante Linux a exécuté les tests release du workspace, les deux scénarios
GTK isolés, le build du helper et de la Console, la construction puis
l'installation du `.deb`, le lancement sous affichage virtuel et le refus de
listener TCP. Toutes ces étapes sont vertes.

Le helper release mesure 839856 octets et porte le SHA-256
`58d832460f0ce927ac3df0cb9640307c301555ad6b5d22b30efe74c80400a587`.
Son gate ELF confirme les dépendances directes attendues vers le chargeur,
`libc`, `libgcc_s`, GLib, GObject et GTK3, sans WebKit. Cette exécution hébergée
complète le [rapport Linux historique](v1-bootstrap-ipc-linux.md) ; elle ne lui
attribue pas rétroactivement un environnement ou des résultats différents.

### Variante Windows

| Action | Résultat observé |
|---|---|
| tests release du workspace | tous les tests actifs réussissent ; les scénarios explicitement ignorés restent identifiés comme tels |
| lancement durci | seul le jeu exact de handles prévu est transmis par `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` ; un handle sentinelle pourtant héritable n'atteint pas le fils, et les handles stdio perdent leur drapeau d'héritage dans le helper |
| Job Object | la racine et un vrai descendant appartiennent au même Job ; `TerminateJobObject`, l'attente bornée de la racine et la lecture de `ActiveProcesses` prouvent la récolte de l'arbre |
| injections avant reprise | les coupures après création, après affectation au Job et avant reprise empêchent toujours l'exécution de la fixture puis laissent le nettoyage prouvé |
| nettoyage devenu non prouvable | l'injection intervient après la vraie terminaison du Job, l'attente de la racine et la lecture de `ActiveProcesses` ; elle empoisonne ensuite le lanceur et toute nouvelle tentative est refusée |
| empaquetage MSI | l'image administrative contient exactement l'ensemble des deux fichiers exécutables installables : `your-cloud-console.exe` et `your-cloud-native-bootstrap-assistant.exe` |
| installation du helper | le helper installé est le frère direct exact de la Console, sans point de réanalyse, et son empreinte égale celle du fichier empaqueté |
| gate PE | PE32+ AMD64, imports normaux analysés et table d'imports différés vide ; aucune dépendance WebView ou WebKit dans ces tables |
| IPC WebView2 vivant | la Console installée reçoit réellement `start_bootstrap`, `bootstrap_status` et `cancel_bootstrap` via Tauri pour les modes `create` et `replace` |
| refus IPC hostiles | une seule session est active ; le départ concurrent rend `bootstrap_busy`, les identifiants forgés et les rejeux sont refusés, les champs inconnus ou sensibles rendent `invalid_input` |
| sortie publique | les erreurs sont réduites à leur code ; ni identifiant de requête, ni cible, ni canari sensible n'entrent dans l'erreur publique ou l'artefact de preuve |
| résultat métier | `success_claimed=false` et `bootstrap_business_result=not_implemented_fail_closed` ; `replace` finit par `native_assistant_unavailable` au lieu d'inventer un Controller |
| réseau local | aucun listener TCP du produit ou de ses descendants n'est observé au lancement normal |
| nettoyage | l'installation MSI, le helper, le certificat synthétique et sa clé privée, l'utilisateur et le profil temporaires, les processus, les données applicatives et le listener de debug WebView2 sont vérifiés absents |

Le MSI porte le SHA-256
`ac45b57bb11e60ea89e3f563a2ec7ad34d93da3a1d351ceee7055d540ec81bd3`.
La Console empaquetée et installée porte dans les deux cas
`5131fd56a21e884c986a649b0b1420bb1b9c06226fc280a290a4be9744d2f81f` ;
le helper empaqueté et installé porte dans les deux cas
`88ef5b5241a5c77f6323b3c83a7f8905197ff57db1192ded226c84e328069fa1`.
Les deux exécutables et le MSI ont le même signataire et le même horodatage
Authenticode synthétiques.

Le gate PE porte sur le helper installé exact, de 368296 octets. Sa fermeture
Cargo compte 16 paquets et possède l'empreinte
`16d8054e0031b678c83f53c1ac36810b03fc3ab6d0bbd4228d18aea1b0c5dd9d`.
Les tables d'imports normales et différées sont analysées ; ce contrôle ne
prouve pas l'absence universelle d'un chargement dynamique de module par un
autre mécanisme.

## Artefact expurgé

L'artefact GitHub `console-windows-webview2-smoke`, identifiant `8835381252`,
a le digest
`sha256:2e9db85120dbc86a5b7dd278630a4bbe064637173b35c15d92c8d68298345cdb`.
Il contient uniquement le rapport JSON et neuf captures PNG, sans MSI,
exécutable, certificat, clé privée ou secret synthétique. Le JSON porte le
SHA-256
`ee2f2345ceae81efabf8d748f043ed4992a419750804a34439bd4931e3447088`.

Les neuf captures couvrent les vues association, infrastructures et accès
local en `1280 × 800`, en `640 × 560` et avec texte à 200 %. Les assertions du
rapport n'observent aucun débordement horizontal ni ressource distante dans ces
neuf états. Elles ne remplacent pas une revue visuelle exhaustive ni les vues
post-association, volontairement absentes sans vrai Controller.

Le transport de debug emploie une boucle locale éphémère uniquement pour le
pilote WebView2 puis disparaît avant le lancement normal. Il ne doit pas être
confondu avec un listener produit.

## Ce que la preuve établit pour #43

- les trois commandes Tauri vivantes conservent le périmètre public de
  l'amorçage en natif et ne donnent au frontend aucune commande SSH, agent,
  signature générale ou approbation métier ;
- les schémas sérialisables utilisent une liste positive sans champ secret ;
- l'identifiant natif non rejouable, la concurrence unique, l'annulation et les
  états terminaux résistent aux identifiants forgés, aux champs supplémentaires
  et aux rejeux exercés ;
- la WebView ne peut ni approuver une action, ni faire progresser seule l'état,
  ni inventer un succès d'amorçage ;
- le helper Windows n'hérite que des handles explicitement transmis, rejoint
  un Job avant reprise et laisse racine et descendant récoltés sous les branches
  hostiles exercées ;
- un nettoyage dont l'observation finale devient non prouvable interdit toute
  relance, même après les vraies actions de terminaison ;
- le paquet Windows relie le MSI, les deux exécutables installables et leurs
  copies installées exactes, sans présenter la sortie Cargo restaurée comme
  l'exécutable signé du paquet ;
- les imports PE normaux et différés du helper installé sont bornés par le gate,
  sans dépendance WebView ou WebKit dans ces tables ;
- les variantes installées Linux et Windows se lancent sans listener TCP et se
  nettoient dans leurs runners isolés.

## Ce que la preuve n'établit pas

- la collecte secrète GTK3 ou Win32, `mlock`, `MADV_DONTDUMP`, `VirtualLock`,
  l'exclusion Windows Error Reporting, l'effacement des copies produit ou
  l'annulation coopérative pendant une saisie : ces contrôles appartiennent à
  #45 ;
- un agent SSH personnel, une clé privée chiffrée, une connexion SSH, `sudo`,
  un accès `root` ou les vrais descendants SSH et privilégiés : ils
  appartiennent à #42 ;
- un audit d'hôte, le déploiement d'un Controller, une mutation de machine ou
  un succès métier d'amorçage ;
- une identité publique de distribution Windows : le certificat éphémère
  prouve seulement la mécanique Authenticode et son nettoyage ;
- l'absence universelle de chargement dynamique de bibliothèques au-delà des
  tables d'imports PE réellement analysées ;
- la preuve fonctionnelle multi-VM, qui reste sous l'autorité du LAB Linux.

## Fermeture de l'environnement

Le nettoyage bloquant du job Windows a réussi et le rapport énumère chaque
classe de ressource vérifiée absente. Les runners Linux et Windows sont
jetables. Ce passage n'a créé ni VM, ni réseau, ni snapshot `labctl` ; il
n'exige donc aucune destruction de topologie locale et ne modifie pas les
fermetures LAB conservées dans le rapport Linux historique.

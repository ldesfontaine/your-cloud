# Anatomie du projet

> **Ce document projette l'architecture décidée** : les machines, les
> composants, leurs placements, leurs autorités et leurs flux — jamais l'état
> de ce qui est construit.

Une [édition HTML autonome et visuelle](../html/anatomie.html) accompagne
cette source Markdown. Elle évolue à chaque incrément qui modifie un composant,
un placement, une autorité ou un flux réseau.

La [chaîne d'observation détaillée](CHAINE-D-OBSERVATION.md) cartographie les
rôles Daemon, Relay et Diagnose, leurs appels, états, données, protections et
limites.

## Comment lire ce document

Trois états ne doivent jamais être confondus :

- **décidé** : le comportement appartient au contrat, mais aucun code ne le
  prouve encore ;
- **implémenté** : le code existe ;
- **prouvé** : le scénario annoncé a réellement réussi dans le LAB avec ses
  refus hostiles.

**Ce document ne porte que le premier.** Il projette ce qui est décidé — les
placements, les autorités, les flux — et rien de ce qui est atteint : une
anatomie qui tiendrait le compte des runs, des commits et des issues périmerait
à chaque fusion, et finirait par affirmer un état que personne n'a revérifié.

Ce qui est **implémenté et prouvé** se lit dans les [rapports LAB](../lab/),
qui portent seuls les dates, les commits et les résultats d'exécution. L'ordre
dans lequel le reste arrive se lit dans la
[direction](../projet/DIRECTION.md).

## Distribution : les mêmes octets, deux rôles

```text
Machine du LAN / non candidate              VPS simulé / candidat Relay
/usr/local/lib/your-cloud/your-cloud        /usr/local/lib/your-cloud/your-cloud
`- Daemon LAN -- mTLS :8443 --------------> |- Relay <--- mTLS local ---+
                                             `- Daemon VPS -------------+
```

Les mêmes octets sont installés sur les deux machines. Sur le VPS seulement, le
Daemon et le Relay fonctionnent en parallèle avec des comptes, configurations,
identités, credentials, états et politiques systemd distincts. La présence du
fichier ne suffit pas à ouvrir le port : sans manifeste candidat provisionné
localement, le mode Relay refuse avant toute écoute. Le
[rapport LAB](../lab/v0.0.2-observation.md) prouve mTLS, révocation, saturation,
lacune, reprise et cycle de retrait-réinstallation.

## Topologie de référence

```text
                            INTERNET
                                |
                           HTTPS :443
                                |
                 +--------------v---------------+
                 | VPS / zone d'exposition      |
                 |                              |
                 | Traefik ----> BentoPDF       |
                 |    |                         |
                 |    +---- route Vaultwarden --+-----+
                 | Relay                               |
                 | Agent                               |
                 | `- Daemon --mTLS--> Relay           |
                 +---------------------------+---------+
                                             |
                                  WireGuard, /32 et port
                                  Vaultwarden uniquement
                                             |
                 +---------------------------v---------+
                 | Machine du LAN                      |
                 |                                     |
                 | Vaultwarden                         |
                 | Agent                               |
                 | `- Daemon --mTLS--> Relay du VPS    |
                 | aucun accès latéral au LAN          |
                 +-------------------------------------+

       +--------------------------------------------------+
       | Environnement d'administration                   |
       | App installée -- API privée --> Controller       |
       | Controller -- GET mTLS :8444 -------> Relay      |
       | Controller -> SSH forcé -> Auxiliaire ponctuel   |
       +--------------------------------------------------+
```

Cette topologie rend les preuves déterministes ; elle ne prescrit pas
l'infrastructure réelle d'un utilisateur. BentoPDF et Vaultwarden sont deux
profils de service sélectionnés explicitement dans le LAB, jamais des composants
installés par défaut. Une infrastructure peut ne choisir aucun de ces profils ;
un service placé autrement reste externe tant qu'un parcours géré dédié n'est
pas pris en charge.

<!-- coherence: APP-ACCESS:start -->
L'App, le Controller et le Relay restent hors du chemin emprunté par le
trafic Web vers les services : la panne de leurs processus ne doit pas arrêter
un service hébergé sur une autre machine. La perte d'un hôte interrompt
cependant les services qui y cohabitent. Le Controller porte l'autorité d'une
seule infrastructure. Le produit tient une App installée, un Controller et une
infrastructure ; les associations futures à plusieurs Controllers isolent
identités d'appareil et sessions.

L'App est une application Tauri 2 signée qui embarque un frontend React,
TypeScript et Vite et son client réseau natif. Elle n'ouvre aucun serveur local,
n'utilise pas une page `localhost`, ne donne aucun client réseau général au
frontend et ne télécharge jamais son code depuis un Controller. Le premier
palier vise un `.deb` Linux et un `.msi` Windows issus du même commit et du même
frontend responsive ; le téléphone conserve ce design mais exige une preuve
ultérieure de son empaquetage et de son stockage sécurisé. Le Controller reste
un backend API privé sans frontend. L'App l'appelle sur une origine HTTPS
exacte avec identité d'appareil mTLS et session humaine séparée. Le Controller
initie sa lecture authentifiée du Relay ; l'App ne contacte jamais le Relay
et les Daemons ne connaissent aucun Controller.

L'interface est centrée sur l'infrastructure sélectionnée, avec `Synthèse`,
`Parc` et `Observations`. Le Controller reste sa liaison privée contextuelle et
les secrets, l'appareil et la session restent sous `Profil et sessions` ; aucun
de ces concepts ne devient une rubrique d'infrastructure artificielle. Les
tokens visuels communs pilotent thèmes, fontes, espacements et composants sous
Linux et Windows. Le statut Relay décrit le transport : l'App ne fabrique
ni machine Relay dédiée, ni badge de placement absent de l'API. Un hôte qui
exécute Daemon et Relay reste une machine normale lorsqu'il appartient réellement
à l'inventaire.

L'autorité TLS serveur des Controllers, l'autorité qui émet les certificats
d'appareil App, l'autorité cliente des Daemons et l'autorité cliente de
lecture Controller–Relay sont distinctes. Un certificat ou une chaîne d'une de
ces classes ne donne aucun droit dans une autre et doit y être refusé.

Le Relay garde l'ingestion Daemon sur `8443` et lie son unique lecture à
`GET /v0/snapshot` sur l'adresse privée exacte et `8444`. Ce port n'est pas
`localhost` : un pair routé pourrait le scanner. Le filtre `nftables` refuse
donc par défaut et n'autorise que l'interface privée et l'IP source provisionnée
du Controller ; les autres paquets sont supprimés par `drop`, et les nouveaux
TCP autorisés restent bornés à quatre en rafale puis douze par minute. mTLS et
un registre lecteur exact restent obligatoires derrière ce filtre. Les deux
autorités Ed25519 du lecteur, serveur et cliente, sont propres à
l'infrastructure et ne donnent aucun droit sur `8443`.

Le cœur Rust protège les clés d'appareil et humaines de chaque association dans
un coffre Tauri Stronghold commun à Linux et Windows, déverrouillé par une
phrase secrète locale dérivée avec Argon2id. Le frontend voit brièvement cette
saisie puis l'efface ; les clés dérivées, clés privées, contenus du coffre et
sessions restent hors de son autorité. Windows Hello, passkeys, FIDO2 et
SSO/OIDC ne sont portés par aucun chantier de la
[direction](../projet/DIRECTION.md).

La phrase contient six mots français aléatoires. Un appairage ou une
récupération n'ouvre `9444` sur l'adresse privée du Controller que pendant une
fenêtre locale de dix minutes, avec certificat serveur épinglé, preuve à usage
unique et aucune route métier. Le certificat d'appareil P-256 vaut 180 jours et
se remplace manuellement en deux phases ; le candidat n'obtient aucun droit
métier avant activation et l'ancien reste actif si l'activation n'aboutit pas.
La session opaque est liée à l'appareil et à l'infrastructure, expire après 30
minutes d'inactivité ou huit heures absolues et disparaît après logout,
révocation, rotation, récupération ou redémarrage. Un code global de 256 bits
conservé hors ligne dérive une clé de récupération différente par Controller.
Ce profil possède un seul humain et un seul appareil actifs par Controller.

Un Controller génère et conserve avant appairage des identifiants de Controller
et d'infrastructure UUIDv4 immuables. Il refuse une machine tant qu'une lecture
Relay réussie dans la même opération ne confirme pas son enrôlement actif dans
cette même infrastructure. Registre Daemon schéma 2, manifeste lecteur,
certificats, origine, Controller et réponse portent le même UUID
d'infrastructure. Une association, un certificat, une IP ou une session d'un autre
Controller ne donne donc aucune portée croisée. La preuve doit attaquer le
filtre puis mTLS depuis une VM distincte placée sur le même réseau LAB. Après
panne ou redémarrage, le dernier snapshot peut rester visible mais vaut
`indisponible` jusqu'à une nouvelle lecture valide et n'autorise rien. Une
lecture initiale suit l'entrée explicite dans une vue, puis l'actualisation reste
manuelle afin qu'un polling d'arrière-plan ne prolonge pas la session humaine.

Le Controller non-root sépare son autorité métier `inventory.json` du cache de
transport `relay-cache.json`. Ces fichiers privés, bornés et atomiques ne
partagent ni état P4 ni secret. Une insertion exige le snapshot P5 frais
persisté avant l'inventaire ; un renommage déjà rattaché reste local. La
projection App contient seulement les zéro à 64 machines attendues sous
128 Kio. Elle distingue transport, enrôlement, observation récente jusqu'à 90
secondes incluses ou ancienne, et continuité. Les lacunes sont résumées sans
troncature et les 2 Mio bruts restent côté Controller. Les libellés Unicode NFC
sont bornés et non autoritaires : le `machine_id` reste visible à côté.
Cette borne appartient au format et aux preuves de la version courante ; elle
n'est pas un plafond définitif de Your Cloud.

À long terme, l'API du Controller reste privée derrière WireGuard. Chaque
appareil administrateur possède un pair distinct et révocable, avec un routage
limité aux adresses d'administration et un refus serveur par défaut. La
possession de la clé du pair ne prouve ni l'intégrité de l'appareil ni l'identité
de l'humain. Une identité d'appareil et une authentification humaine forte
restent obligatoires après l'accès réseau ; SSO/OIDC est facultatif. L'App
devra masquer la configuration WireGuard derrière une opération de connexion
nommée, déverrouiller uniquement la clé de l'infrastructure choisie et fermer la
liaison au timeout ou à la demande. Cette direction ne choisit pas encore le
mécanisme système ou intégré, et aucun chantier de la
[direction](../projet/DIRECTION.md) ne le porte. Une
passerelle Web publique et un frontend navigateur pourront être étudiés comme un
mode futur distinct, sans autorité d'administration ni secret de machine. Les
services publiés conservent leur propre accès HTTPS sans WireGuard.
<!-- coherence: APP-ACCESS:end -->

Dans le scénario de référence, les deux profils de service suivent un autre
chemin. Leurs noms DNS pointent vers la même IP du VPS et Traefik reçoit les deux
sur `443`, puis route le nom BentoPDF vers le service local et le nom
Vaultwarden vers le passage WireGuard. Aucun port de backend n'est exposé
directement.

<!-- coherence: BOOTSTRAP-RECOVERY:start -->
## Créer puis remplacer le Controller

L'installation de l'App contient un Assistant natif temporaire distinct du
frontend. La création suit ce transfert d'autorité :

```text
Utilisateur
|- déclare les endpoints, aucun scan
|- confirme les clés d'hôte et le placement
`- prête son accès SSH personnel pour cette opération
                     |
                     v
App
|- frontend : demandes et résultats typés, aucun secret SSH
`- binaire compagnon signé lancé en helper éphémère
   |- graphe autonome sans Tauri, Wry, Tao ni WebKit
   |- garde fixe --native-bootstrap-assistant
   |- pipes typés : périmètre public entrant, états expurgés sortants
   |- prompt direct GTK3 ou Win32 : secret et consentement exact
   |- audit SSH en lecture seule
   |- installe et associe le Controller privé approuvé
   |- vérifie depuis lui la route SSH vers chaque cible
   |- installe l'artefact avant les accès forcés
   `- détruit son état SSH temporaire puis s'arrête
                     |
                     v
Controller autonome
|- une identité SSH Your Cloud différente par machine
|- clés privées root-owned fournies au service par credentials systemd
`- clés publiques -> commande forcée `your-cloud auxiliary`
                      `- protocole lecture seule, mutation refusée par défaut
```

Le binaire distinct n'est pas une préférence de packaging : le gate ELF Linux
du 2 août 2026 a trouvé WebKitGTK et JavaScriptCoreGTK dans le `DT_NEEDED` de la
App. Le helper possède donc son propre crate, son propre graphe et sa propre
preuve d'absence de WebView, tout en restant livré dans la même release.

Les modes `create` et `replace` passent
par trois commandes Tauri positives sans champ secret et un identifiant natif
anti-rejeu ; ni l'App ni le helper n'ouvrent de listener. Les gates natifs
bornent aussi le packaging. Sous Windows, le processus est créé suspendu avec
une liste exacte de handles héritables, affecté au Job Object avant reprise, et
les descendants ainsi que les branches d'échec sont terminés avec lui. Voir le
[rapport du runner Windows](../lab/v1-bootstrap-ipc-windows.md).

Le helper conserve le secret : le parent et le
pair IPC sont vérifiés contre un périmètre immuable, la durée monotone vaut 300
secondes et ne se renouvelle pas, puis GTK3 ou Win32 ouvre la fenêtre native.
Le tampon `ProtectedSecret`, borné à 4096 octets, est détruit avant l'événement
terminal public `Unavailable`. Sous Linux, la zone est
créée avec `mmap`, verrouillée par `mlock` et exclue par `MADV_DONTDUMP` ; sous
Windows, elle utilise `VirtualAlloc`, `VirtualLock` et l'exclusion Windows
Error Reporting.

Une frontière est nommée plutôt que promise : les `LocalDumps` d'un
administrateur sont **hors garantie**. Le contrat exige le contrôle et le
canari présents puis un nettoyage prouvé, et il n'affirme aucune exclusion
au-delà. Le
[rapport de consentement natif](../lab/v0.1.0-native-secret-consent-linux-windows.md)
distingue l'implémentation, les sous-cas Linux exécutés et la preuve Windows.

Il existe deux catégories d'accès SSH d'administration des machines : l'accès
personnel conservé par l'utilisateur et l'identité Your Cloud propre à chaque
machine. L'authentification App–Controller est séparée et ne devient pas une
troisième autorité SSH. Shell, PTY, SFTP et transferts sont interdits à la clé
Your Cloud. Un accès personnel `root` exige un consentement explicite pour
l'opération exacte ; le défaut recommandé reste un compte non-root avec `sudo`
protégé. La WebView ne reçoit ni secret, ni primitive SSH générale ; le prompt
natif lie l'utilisation aux cibles, actions et durées affichées.

Le helper embarque `russh 0.62.4` épinglé et ne reçoit qu'une capacité SSH
immuable : clé d'hôte exacte, algorithmes autorisés, endpoint d'agent système,
clé sélectionnée et budget fini de signatures. Linux accepte le socket Unix
absolu de l'utilisateur courant ; Windows accepte seulement le pipe OpenSSH
système. Le repli ouvre uniquement une clé OpenSSH chiffrée au format décidé.
`sudo` tente l'action non interactive exacte, puis permet au plus un mot de
passe sans PTY vers la même commande absolue. L'arrêt du parent ferme le helper
et ses enfants ; zéroïsation et protections anti-dump réduisent l'exposition
sans prétendre couvrir root, administrateur ou dumps noyau.

Le Controller réside sur une machine privée, de confiance et normalement
allumée. Il peut cohabiter dans une petite infrastructure si ses processus,
comptes, secrets, fichiers et budgets sont séparés ; une machine ou VM dédiée
est recommandée quand la taille ou le risque augmentent. Il ne dépend jamais du
laptop après l'amorçage et n'est pas placé par défaut sur le VPS public.

Le remplacement réutilise le même Assistant :

```text
perte confirmée ou ancien hôte isolé + choix explicite
        |
        v
accès SSH personnel -> Assistant -> nouveau Controller
                                      |
                                      |- nouvelle association App
                                      |- nouveau lecteur Relay exclusif
                                      |- réutilise les Agents compatibles
                                      |- tourne approbation, sessions et clés
                                      `- retire seulement les anciennes
                                         identités marquées Your Cloud

accès personnels -------------------------------> inchangés
services des autres hôtes ----------------------> inchangés
service colocalisé sur l'hôte perdu ------------> interruption possible
```

Le code de récupération d'une App réassocie celle-ci à un Controller encore
vivant ; il ne remplace pas ce parcours. Sans sauvegarde de l'ancien
Controller, l'utilisateur redéclare ses endpoints. L'installateur
embarque l'Assistant, un unique paquet serveur `.deb` Debian 13 `amd64`, ses
définitions statiques et le manifeste signé qui lie version, cible, taille et empreinte.
L'Assistant vérifie ce lot avant tout privilège, puis garde configurations,
secrets, activation et reprise hors du paquet. Le binaire root-owned vit sous
`/usr/lib/your-cloud` et les trois unités statiques inactives sous
`/usr/lib/systemd/system`. Le chemin `/usr/local/lib/your-cloud` des preuves
antérieures reste historique ; aucun binaire privilégié n'est téléchargé à la
volée.

Le remplacement avance cible par cible : `ancien seul`, `chevauchement borné`,
`nouveau seul` ou `inconnu`. Après une coupure, l'Assistant reconstruit ces
états depuis les marqueurs root-owned avant toute nouvelle décision. Il ne
déclare une réussite que lorsque l'App, le lecteur Relay et chaque cible
font confiance au nouveau Controller seul. Une suspicion de compromission
impose une base saine et l'isolement vérifié de l'ancien hôte.

Le [contrat d'amorçage et de remplacement](AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md)
fixe l'autorité de ce parcours et le sort de chaque clé ; cette section n'en
projette que les placements et les flux.
<!-- coherence: BOOTSTRAP-RECOVERY:end -->

<!-- coherence: SERVICE-LIFECYCLE:start -->
## Préparer fermé, publier en dernier

La roadmap indique comment construire Your Cloud. Une opération gérée suit ce
cycle distinct :

```text
inventaire et responsabilités
          |
          v
plan approuvé + reprise prouvée
          |
          v
identités et réseau privé encore fermé
          |
          v
service déployé sans exposition
          |
          v
vérification locale
          |
          v
flux exact autorisé -> publication ou bascule
          |
          v
observation -> retrait après la fenêtre de retour
```

Pour le profil de référence Vaultwarden, WireGuard peut donc être établi avec
des routes `/32` tandis que le port applicatif reste refusé. Le service est
d'abord vérifié localement, puis le seul flux VPS-destination est autorisé et
testé. Traefik ne reçoit sa route publique qu'en dernier.

Une migration avec données affiche la source qui possède l'écriture, la
synchronisation et le point de non-retour. Après les premières écritures sur la
destination, un retour devient conditionnel : aucune route ancienne n'est
restaurée automatiquement. Une panne du Controller ou de son chemin d'action
produit un résultat inconnu sans arrêter le service ni rejouer aveuglément
l'opération.

Le contrat et ses scénarios sont détaillés dans le
[cycle de vie sûr des services](CYCLE-DE-VIE-DES-SERVICES.md).
<!-- coherence: SERVICE-LIFECYCLE:end -->

<!-- coherence: AGENT-AUTHORITY:start -->
## Observer et agir sont deux chemins

Une action demandée dans l'interface suit ce chemin :

```text
Utilisateur -> App -> plan lisible -> confirmation native -> signature
                                                               |
                                                               v
Controller -> enveloppe inchangée -> identité SSH par machine -> commande forcée
                                                   |
                                                   v
machine -> Auxiliaire ponctuel -> opération typée -> résultat direct
                                                   |
                                                   v
Controller -> App
Daemon de la machine -> observations -> Relay -> Controller -> App
```

Le Daemon ne reçoit aucun ordre et ne connaît aucun Controller. Le Relay accuse
et conserve le dernier état d'observation validé sans porter l'inventaire métier
ni calculer le statut affiché. Le Controller rapproche les machines attendues,
les heures de réception, les séquences et les lacunes afin que l'App montre
l'état obtenu après qu'un autre chemin a appliqué le plan. Les dates réseau sont
normalisées en UTC `Z` : le fuseau n'affecte pas l'instant. L'âge part de
`snapshot_at - received_at`, puis avance sur l'horloge monotone du Controller.
`snapshot_at` doit rester dans `[fin - 30 s, départ + 30 s]` ; une dérive entre
hôtes supérieure à 30 secondes ou une correction civile supérieure à une
seconde ne produit jamais un état récent.

Une machine gérée reçoit les plans par l'accès SSH Your Cloud installé pendant
l'amorçage. Cet accès n'ouvre aucun port supplémentaire et ne donne aucun shell :

```text
Controller / constructeur et transport du plan
        |
        | plan exact + rollback signés par le cœur natif
        v
SSH existant + identité par machine + commande forcée
        |
        v
Agent sur la machine
|- même artefact signé
|- Daemon non-root : observation uniquement
`- Auxiliaire local
   |- clé publique + époque + séquence root-owned
   `- revérifie, consomme l'anti-rejeu, applique, puis s'arrête
```

L'Auxiliaire n'a aucun listener, aucun accès réseau général, aucun shell et
aucune élévation dormante. Il refuse une opération ou un paramètre hors de sa
liste positive locale. Une opération OCI peut seulement faire utiliser par
Podman rootless le registre autorisé et le digest exact annoncés dans le plan.
Une machine d'observation ne l'active pas. Le Daemon et le Relay restent
consacrés aux observations. Ansible reste disponible comme outil externe de
l'utilisateur ; il n'appartient pas au cœur du produit. Le Controller ne
possède pas la clé humaine de l'App et ne peut donc pas forger seul une approbation.

Les autres cibles utilisent leur propre autorité plutôt que ce chemin local :

```text
Plan approuvé
|- système Linux ou service local -> Agent -> Auxiliaire local
|- ressource OpenStack ------------> adaptateur API OpenStack
|- Terraform / OpenTofu / Ansible -> runner isolé
`- cluster K3s --------------------> adaptateur API K3s
```

Les adaptateurs OpenStack, IaC et K3s restent hors du produit. Le chemin local
par l'Auxiliaire appartient en revanche à son contrat : le plan inclut un rollback
exact ; la première mutation rend `changed=true`, le même état sans dérive rend
`changed=false` sans réécriture ni redémarrage, et une dérive exige un nouveau
plan. Un échec contrôlé tente le rollback approuvé tant que l'Auxiliaire garde
la maîtrise. Une coupure produit un résultat inconnu, sans rejeu ni continuation
autonome ; la séquence consommée reste refusée après redémarrage et le
Controller observe avant de proposer un autre plan.

Le Relay peut provenir du même exécutable que le Daemon sans appartenir au même
processus. Son compte, son identité réseau, ses secrets, son stockage et son
budget restent séparés. Une machine non candidate ne reçoit aucun manifeste
Relay exploitable et refuse ce mode avant l'ouverture d'un port.
<!-- coherence: AGENT-AUTHORITY:end -->

<!-- coherence: OBSERVATION-CHAIN:start -->
## Observer sans ouvrir une porte

```text
Profil approuvé
      |
      v
collecteurs nommés et bornés
      |
      v
Daemon non-root -> tampon local borné -> sortie mTLS -> Relay
      |                                      |
      `-> état local seulement               `-> aucun ordre retour
```

Chaque Daemon reçoit un endpoint Relay approuvé : route, port et identité
cryptographique attendue. Ce trajet peut rester entièrement privé ; le Relay
n'a pas besoin d'une IP publique si le routage autorisé le rend joignable. Un
remplacement automatique futur devra prouver la panne, choisir uniquement une
candidate autorisée, redistribuer cet endpoint et empêcher deux autorités
actives. Aucun de ces mécanismes n'est encore choisi.

Le Daemon n'ouvre aucun port réseau. Il conserve l'état courant et les données
non confirmées par le Relay dans un tampon limité. Une perte provoquée par la
limite apparaît comme une lacune explicite, jamais comme une période saine.

Le diagnostic de cet état est une commande administrative locale, exécutée
ponctuellement par `root` parce que le tampon du compte dynamique est protégé
sous `/var/lib/private`. Cette lecture seule n'ouvre aucun port et ne donne
aucun privilège supplémentaire au Daemon permanent.

Le premier profil prouvé `host-health.v1` fixe trois collecteurs : uptime,
mémoire et système de fichiers racine. Il annonce les données, la fréquence,
les ressources et les lectures locales nécessaires. Ni commande shell, ni
chemin arbitraire, ni plugin téléchargé à la demande ne peut devenir une
observation.

À l'avenir, une source d'observation nécessitant plus de droits demandera un
contrat local borné et une justification propre. Le Daemon entier ne devient
pas root pour faciliter une nouvelle métrique.
<!-- coherence: OBSERVATION-CHAIN:end -->

## Gestion explicite, jamais découverte du LAN

Un profil de service disponible dans l'App ne crée aucune ressource. Son
instance n'existe qu'après une déclaration, un placement, un plan et une
approbation explicites ; les profils nommés dans le LAB ne deviennent pas une
topologie imposée aux utilisateurs.

L'inventaire reste limité aux machines déjà enrôlées. Ni le Daemon, ni le Relay,
ni l'App ne scannent le LAN, et la présence d'un appareil sur le même réseau ne
lui donne aucune confiance.

## Pourquoi Traefik utilise le file provider

Traefik sait découvrir automatiquement les conteneurs avec son provider Docker.
Pour cela, il doit interroger l'API Docker, souvent au moyen du socket
`/var/run/docker.sock`. Cette API possède une autorité importante sur le moteur
et peut devenir un chemin vers l'hôte si le proxy exposé est compromis.

Your Cloud utilise donc le **file provider** :

1. l'utilisateur demande une publication dans l'App ;
2. Your Cloud calcule une route précise ;
3. le plan montre le nom public, la destination et le port ;
4. après approbation, l'Auxiliaire du VPS écrit atomiquement la configuration
   dynamique Traefik ;
5. Traefik charge uniquement cette route ;
6. Your Cloud vérifie HTTPS et le refus des chemins non prévus.

Cette décision protège contre la découverte et la publication implicites ainsi
que contre l'accès direct de Traefik au moteur de conteneurs. Elle ne protège
pas contre une configuration Traefik approuvée mais erronée, une vulnérabilité
du proxy ou la compromission d'un backend autorisé : les validations et le
confinement réseau restent nécessaires.

## Podman, Docker et Quadlet

Podman et Docker exécutent les mêmes familles d'images OCI. Tous deux isolent
des processus, mais les conteneurs partagent toujours le noyau de leur hôte.
Podman facilite un modèle sans démon central et rootless ; Docker possède aussi
un mode rootless. Aucun des deux noms ne constitue à lui seul une garantie de
sécurité.

**Quadlet** est un format déclaratif de Podman intégré à systemd. Une définition
`.container` indique notamment l'image, le compte, les volumes, le réseau, les
ports et les limites. À partir de cette fiche, systemd sait démarrer, arrêter,
redémarrer et observer le conteneur comme un service Linux ordinaire.

Podman rootless avec Quadlet est retenu. Le flux sera :

```text
Plan Your Cloud -> Auxiliaire -> fichier Quadlet -> systemd -> Podman -> conteneur
```

Ce flux n'existe que sur une machine hôte équipée de systemd et de cgroup v2.
Your Cloud vérifie ces capacités avant toute mutation. Si elles manquent, le
déploiement OCI géré est refusé clairement ; Quadlet ne crée ni unité OpenRC,
ni script runit, ni solution de repli implicite. Un service que l'utilisateur
gère autrement reste sous son autorité. Cette limite ne décide pas encore
à elle seule des systèmes capables d'exécuter le Daemon d'observation.

OWASP ne recommande pas Quadlet par son nom. Quadlet nous permet d'exprimer et
de relire les contrôles recommandés : utilisateur non privilégié, aucun socket
de moteur exposé, capacités minimales, aucune élévation, écritures et ressources
bornées. Le premier rapport qui l'utilisera expliquera chaque champ et montrera
la fiche, le service systemd généré et le conteneur résultant.

## Contrat de mise à jour visuelle

Chaque incrément qui change l'architecture met à jour cette source et son HTML
avec au minimum :

- les machines et composants réellement concernés ;
- les flux entrants et sortants ;
- le chiffrement et l'identité employés ;
- l'autorité capable de modifier chaque élément ;
- le statut décidé, implémenté ou prouvé ;
- les limites et résultats hostiles significatifs.

Les schémas ne doivent jamais afficher de secret, de clé, de jeton ou d'adresse
de production.

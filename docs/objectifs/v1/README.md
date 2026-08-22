# Objectif `v0.1.0`

> # ⬛ Objectif ATTEINT
>
> **`v0.1.0` est franchie**, et `v0.2.0` est publiée depuis. Ce dossier est
> conservé comme **récit** : il dit ce que le produit devait rendre et l'a
> rendu. Il ne décrit pas ce qu'il vise maintenant — cela se lit dans le
> [cap](../../projet/CAP.md) et la [direction](../../projet/DIRECTION.md).
>
> **Les tags de cette période n'existent plus.** `v0.1.0`, `v0.1.3` et `v0.1.4`
> ont été supprimés le 21 août 2026 avec le renommage `Console` → `App`
> ([#159](https://github.com/ldesfontaine/your-cloud/issues/159)). Leurs commits
> sont tous ancêtres de `main` — **rien n'est perdu** — mais un lecteur qui
> cherche ces tags ne les trouvera pas. Seule `v0.2.0` subsiste.
>
> Ce dossier ne porte plus aucune décision transverse : elles ont rejoint des
> foyers vivants au cours des amendements de la partie A.

> Statut : contrat fonctionnel validé pour le découpage de la roadmap. Les
> paramètres d'implémentation encore inconnus seront mesurés au palier concerné
> sans modifier silencieusement cette ligne d'arrivée.

Une [édition HTML autonome](../../html/objectif-v1.html) accompagne cette source
Markdown.

## Résultat attendu

`v0.1.0` se ferme contre un scénario LAB de référence, pas contre une
infrastructure imposée aux utilisateurs. Depuis l'App, un utilisateur y
demande au Controller de représenter une infrastructure à partir de deux
machines Linux déjà installées :

- un VPS disposant d'une adresse publique ;
- une machine située dans un LAN privé, sans adresse publique et sans port
  entrant ouvert sur Internet.

Your Cloud observe les deux machines, y déploie proprement deux profils de
service explicitement sélectionnés et les rend accessibles en HTTPS par le VPS.
Un service tourne sur le VPS ; l'autre tourne dans le LAN derrière un passage
chiffré sortant.

Your Cloud ne suppose pas ce passage et le proxy déjà préparés. Le Controller
prépare le plan, l'App le présente, puis l'autorité adaptée configure le
passage privé, les restrictions réseau, le point d'entrée HTTPS et la route vers
le service après approbation.

Atteindre ce scénario de manière reproductible, compréhensible et vérifiée
constitue la ligne d'arrivée fonctionnelle de `v0.1.0`.

Ce placement sert à prouver les capacités génériques d'observer des machines déjà
installées, de déployer un service web OCI public et de publier un service privé
persistant. Il ne provisionne pas les machines et n'oblige aucune infrastructure
réelle à employer deux hôtes, un VPS, un LAN ou les deux profils de référence.
L'utilisateur peut ne sélectionner aucun de ces profils. Un service placé
autrement reste externe tant qu'un parcours géré dédié n'est pas pris en charge.

## Placement du scénario de référence

```text
Navigateur Internet
        |
      HTTPS
        |
        v
VPS avec adresse publique
|- Daemon
|- Relay
|- point d'entree HTTPS
|- Service A
`- passage chiffre configure par Your Cloud
                  |
                  v
         Machine du LAN
         |- Daemon
         `- Service B
```

Le Controller s'exécute dans l'environnement d'administration et l'App est
une application installée sur l'appareil administrateur. Dans le LAB, le
Controller et l'App sont exécutés dans des environnements isolés distincts :
les « deux machines » du scénario désignent les deux machines gérées, pas toutes
les VM nécessaires à la preuve.

## Comment l'utilisateur atteint chaque interface

### Profils de référence BentoPDF et Vaultwarden

BentoPDF et Vaultwarden sont des charges de référence déterministes pour la
preuve de `v0.1.0`. Ils ne sont ni des composants de Your Cloud, ni des installations
par défaut. Chaque profil doit être déclaré, placé, planifié puis approuvé avant
la moindre création de ressource.

Dans ce scénario, les deux services sont publics par **la même adresse IP du
VPS et le même port HTTPS `443`**, mais l'utilisateur les ouvre avec deux noms
différents :

```text
https://pdf.<domaine> ----+
                          +--> IP publique du VPS:443 --> Traefik
https://vault.<domaine> --+                              |- nom pdf   -> BentoPDF sur le VPS
                                                         `- nom vault -> Vaultwarden par WireGuard
```

Le DNS traduit chaque nom vers l'adresse publique du VPS. Traefik écoute sur
`443`, vérifie le nom demandé puis sélectionne uniquement la route déclarée pour
ce nom. Le port `80` peut être ouvert seulement pour rediriger vers HTTPS.

Les ports internes de BentoPDF et Vaultwarden ne sont jamais publiés sur
Internet. BentoPDF est atteint par le réseau local de services du VPS ;
Vaultwarden est atteint par l'adresse WireGuard et le seul port autorisé dans le
passage privé. Une requête faite directement à l'IP du VPS sans nom pris en
charge ne reçoit aucune route applicative par défaut : elle est refusée ou
renvoie une réponse neutre, mais ne révèle pas arbitrairement un service.

Dans le LAB, des noms synthétiques remplaceront les vrais noms DNS et pointeront
vers le VPS simulé. La preuve extérieure vérifiera les deux noms, `443`, la
redirection éventuelle depuis `80` et le refus des ports internes.

### App Your Cloud : App et Controller

L'**App** désigne le produit formé de deux rôles qui ne partagent pas la même
autorité :

- l'**App** est une application cliente Tauri 2 installée et signée. Elle
  embarque le frontend React, TypeScript et Vite et le client réseau natif sans
  héberger de serveur local ni télécharger son code depuis un Controller. Elle
  n'est pas la source de l'inventaire, ne conserve aucun secret de machine ou
  de runner et ne possède aucune identité lui permettant d'exécuter seule une
  action d'infrastructure. Son Assistant temporaire reste la seule exception
  bornée pendant l'amorçage décrit plus bas ;
- le **Controller** est le backend d'une seule infrastructure. À terme, il porte
  son inventaire, ses utilisateurs et rôles, ses décisions d'enrôlement, ses
  plans, son état attendu et son audit. Dans `v0.1.0`, il coordonne l'Auxiliaire par un
  chemin SSH d'administration distinct pour chaque machine. Il expose une API
  privée authentifiée mais ne sert aucun frontend.

`v0.1.0` prouve une App installée, un Controller et une infrastructure. La
App peut conserver plusieurs associations approuvées, une par Controller.
L'utilisateur n'a pas à mémoriser leurs adresses, mais l'application connaît et
vérifie l'identité de chaque Controller. Sa distribution signée, ses identités
d'appareil et ses sessions séparées empêchent un Controller de fournir le code
de l'interface ou d'obtenir silencieusement autorité sur les autres.

Le trajet retenu est :

```text
Appareil administrateur
`- App installée et signée
   |- frontend embarqué, aucun serveur local
   |- identité d'appareil dans le stockage sécurisé
   `- API privée authentifiée ----> Controller d'une infrastructure
                                      `- GET mTLS ----> Relay reader privé :8444
```

La première App doit être fonctionnelle sur Linux et Windows depuis le même
frontend. Tauri 2 forme l'enveloppe native ; React, TypeScript et Vite forment le
frontend commun. Ces fichiers appartiennent à l'artefact signé : ce n'est ni un
site hébergé, ni une page `localhost`. Le client natif expose seulement des
opérations nommées et le frontend n'obtient aucun réseau, fichier ou shell libre.
Le `.deb` Linux et le `.msi` Windows viennent du même commit et du même verrou
frontend, avec manifeste, empreintes, SBOM, provenance et signatures
vérifiables. La mise à jour reste manuelle dans `v0.0.3`. Le design responsive
prépare le téléphone sans faire entrer la signature, le stockage sécurisé et la
distribution Android ou iOS dans ce palier.

Le système visuel emploie des tokens sémantiques : les couleurs, fontes,
espacements, rayons et états sont des variables communes plutôt que des valeurs
répétées dans les écrans. La direction retenue est claire, sobre, indigo et vert
canard, avec thème sombre système, Inter et IBM Plex Mono embarquées et icônes
Lucide. La fenêtre standard vaut `1280 x 800`, son minimum `640 x 560`, et la
mise en page relative reflue sans abstraction téléphone. L'infrastructure
sélectionnée porte `Synthèse`, `Parc` et `Observations` ; le Controller apparaît
seulement comme sa liaison privée contextuelle et la phrase, l'appareil et la
session restent sous `Profil et sessions`. L'interface n'invente ni rubrique
Controller ou Sécurité, ni machine Relay dédiée, ni score, historique ou donnée
actuelle absent de l'API.

La preuve sépare deux couches sans exécuter le produit sur le laptop. Le
fonctionnel multi-VM réutilise les six VM Debian `v1-full` : build et runtime
propres, seconde App hostile, deux Controllers synthétiquement séparés,
deux Daemons et un Relay colocalisé avec l'un d'eux. Une matrice native manuelle
construit, installe et lance ensuite le même candidat exact sur des runners
Linux et Windows jetables ; elle n'y crée ni Controller, ni Relay, ni Daemon ou
topologie simulée. Ces couches restent complémentaires. La porte native finale
a entièrement réussi dans le run `30710037004` sur le candidat produit exact
`3b8f81f`. L'[issue `#9`](https://github.com/ldesfontaine/your-cloud/issues/9)
relie ce SHA, le run et son intégration par fast-forward : `v0.0.3` est fermée
pour ce candidat, sans attribuer cette preuve aux changements ultérieurs.

Chaque association approuve une origine HTTPS TLS 1.3 exacte. L'enveloppe
présente une identité d'appareil mTLS puis une session humaine opaque, toutes
deux propres au Controller et à son identifiant d'infrastructure immuable. Le
Controller refuse une machine tant que son Relay authentifié ne confirme pas
son enrôlement dans cette même infrastructure. Le cœur Rust protège chaque
association dans un coffre Tauri Stronghold commun à Linux et Windows,
déverrouillé par une phrase secrète locale dérivée avec Argon2id. Le frontend
voit brièvement cette saisie puis l'efface ; il ne reçoit jamais la clé dérivée,
une clé privée, le contenu du coffre ou une session. La phrase est formée de six
mots français tirés aléatoirement. L'appairage ou la récupération exige un
listener TLS `9444` ouvert par l'autorité locale sur l'adresse privée exacte du
Controller pendant dix minutes au plus, le certificat serveur
épinglé et une preuve à usage unique ; aucune route métier n'y existe.

Dans ce palier, un Controller accepte un humain et un appareil actifs. Le
certificat P-256 de 180 jours se remplace manuellement en deux phases, de sorte
qu'une réponse perdue ne révoque jamais le seul accès valide. Une session opaque
liée au certificat et à l'infrastructure expire après 30 minutes d'inactivité ou
huit heures absolues, sans refresh token. Un code global de récupération de 256
bits, affiché une fois et conservé hors ligne, dérive une clé publique distincte
par Controller ; sa rotation après incident reste suivie association par
association. Le Controller revérifie l'état actif ou révoqué à chaque requête,
y compris sur une connexion TLS déjà établie.

Le Relay garde l'ingestion Daemon sur `8443` et ouvre un listener lecteur
distinct sur son adresse privée exacte et `8444`. Le filtre réseau refuse par
défaut toute source autre que l'IP privée provisionnée du Controller, supprime
ces paquets sans réponse et borne même les nouveaux TCP autorisés ; TLS 1.3
mTLS avec deux autorités Ed25519 dédiées par infrastructure et un manifeste
revérifié à chaque requête reste obligatoire derrière ce filtre. Seul
`GET /v0/snapshot`, sans corps ni query, rend un instantané borné. Le registre
Daemon porte l'`infrastructure_id` généré par le Controller après migration
locale explicite. Les dates sont normalisées en UTC : le fuseau d'un hôte ne
change pas l'instant, tandis que la double borne `[fin - 30 s, départ + 30 s]`
refuse une dérive réelle supérieure à 30 secondes.
Le dernier snapshot reste visible mais `indisponible` après panne ou redémarrage
jusqu'à une lecture valide ; il ne peut jamais autoriser seul un rattachement.

Le Controller conserve son inventaire métier et son dernier snapshot Relay dans
deux fichiers JSON privés distincts, bornés et publiés atomiquement sous un
compte non-root. Le cache n'acquiert jamais l'autorité d'ajouter une machine et
une régression conserve l'ancien état sans autoriser de rattachement. L'API
projette uniquement les zéro à 64 machines attendues sous 128 Kio : transport,
enrôlement, observation et lacunes restent séparés. Une observation issue d'une
lecture fiable est récente jusqu'à 90 secondes incluses, puis ancienne ; un
écart absolu de plus de 30 secondes entre heure déclarée et heure reçue est un
avertissement, jamais l'autorité de fraîcheur. Les plages de lacunes sont
résumées exactement et le snapshot brut de 2 Mio n'atteint jamais l'App.
Les libellés UTF-8 sont normalisés en NFC, bornés à 256 octets et 80 valeurs
scalaires par une liste positive Unicode ; l'identifiant immuable, non le
libellé, reste l'autorité visible.

La borne de 64 machines limite l'état et les preuves de cette version ; elle
n'est pas une limite générale du produit. Son relèvement exige des mesures et
des formats adaptés plutôt qu'une promesse non éprouvée dans `v0.1.0`.

La preuve de cette application, ses builds et ses tests restent dans le LAB ou
un runner isolé. Le laptop de développement continue de servir uniquement à
Git, l'édition, aux contrôles statiques et au pilotage de `labctl`.

À terme, l'API du Controller reste privée derrière WireGuard. Une clé privée de
pair distincte et révocable est attribuée à chaque appareil d'administration ;
un routage fractionné n'envoie dans le tunnel que les adresses d'administration.
Le réseau d'administration refuse aussi par défaut les destinations et ports non
nécessaires. Les personnes qui ne l'administrent pas et les utilisateurs des
services publiés ne passent pas par ce VPN.

Dans le profil géré, l'App doit abstraire cette liaison : l'administrateur
choisit une infrastructure et demande `connecter`, sans importer un fichier
WireGuard ni modifier des routes à la main. Le cœur natif déverrouille seulement
la clé de pair de cette association, établit une liaison bornée à l'API du
Controller, puis la ferme et reverrouille la clé après expiration ou
déconnexion explicite. La clé reste chiffrée au repos dans un stockage sécurisé
dont les propriétés sont prouvées ; sa valeur brute n'est jamais exposée au
frontend. Fermer la liaison ne révoque pas le pair côté infrastructure :
révocation et rotation restent des opérations distinctes et visibles.

Le mécanisme exact reste à contracter dans un palier postérieur à `v0.1.0` : tunnel géré par le
système ou pile WireGuard intégrée et limitée au seul client Controller. Un
coffre portable de liaison, distinct du coffre Stronghold de `v0.1.0`, reste aussi
une option postérieure à `v0.1.0`, pas une décision. S'il est retenu, la phrase ne devient
jamais directement une clé
WireGuard : une fonction de dérivation mémoire-dure produit une clé d'enveloppe
pour un chiffrement authentifié. Le risque d'essais hors ligne, la récupération,
le changement de phrase et l'effacement en mémoire devront être mesurés et
prouvés. Aucun de ces mécanismes n'appartient à `v0.1.0` ni à `v0.0.3`.

WireGuard authentifie la possession de la clé du pair ; il ne prouve ni
l'intégrité de l'appareil ni l'identité de l'humain. L'App possède donc une
identité d'appareil distincte et le Controller exige une authentification humaine
forte avant d'émettre une session courte liée à cet appareil. Dans `v0.1.0`,
une phrase secrète locale déverrouille le coffre Stronghold commun à Linux et
Windows ; le Controller vérifie une signature humaine distincte de mTLS.
Windows Hello, passkeys, FIDO2 et SSO/OIDC restent postérieurs à `v0.1.0`. Les effets d'une
future identité externe et sa récupération locale privée seront contractés à ce
moment.

Un futur accès par navigateur constituerait un mode distinct avec son propre
frontend distribué et, si nécessaire, une passerelle publique. Il reste hors de `v0.1.0`,
facultatif et sans autorité d'administration ni secret de machine. Ses pouvoirs
résiduels sur le routage, la disponibilité, TLS, l'intégrité du code livré et la
transmission d'identité devront être bornés.

## Amorçage et remplacement du Controller

Le premier Controller n'existe pas encore pour installer sa propre autorité.
`v0.1.0` fournit donc dans l'installation de l'App un **Assistant
d'amorçage** natif, temporaire et distinct du frontend. Le parcours utilisateur
reste simple :

1. choisir `Créer une infrastructure` ;
2. déclarer chaque machine par son nom, son endpoint SSH et son rôle envisagé ;
3. prêter un accès SSH personnel déjà fonctionnel ;
4. consulter l'audit en lecture seule et le placement recommandé ;
5. approuver les comptes, artefacts, flux et privilèges exacts ;
6. laisser l'Assistant installer et associer le Controller, vérifier depuis
   celui-ci la joignabilité des cibles, puis enrôler les machines et transférer
   l'autorité ;
7. fermer l'Assistant sans interrompre le Controller ni les services.

L'Assistant préfère un agent SSH déjà déverrouillé, qui signe sans livrer la
clé. En repli, il déchiffre en mémoire une clé chiffrée choisie par
l'utilisateur. Ni le frontend, ni le Controller, ni un journal ne reçoivent la
clé personnelle ou le mot de passe `sudo`. Un compte non-root avec `sudo`
protégé reste le défaut recommandé ; un accès SSH `root` exige un consentement
explicite à chaque opération. Your Cloud ne supprime jamais cet accès personnel.
Passphrase, mot de passe et consentement passent par une fenêtre du cœur natif
qui répète cibles, actions et expiration ; la WebView ne peut ni les fournir,
ni les valider, ni appeler librement SSH ou `ssh-agent`.

L'audit ne scanne pas le LAN. Pour le serveur de `v0.1.0`, il accepte Debian 13
`amd64` ; systemd et cgroup v2 sont en plus requis pour héberger un service OCI
géré. Il confirme les clés d'hôte, les rôles existants et les ressources avant
de proposer un Controller sur une machine privée, de confiance et normalement
allumée. Le Controller peut cohabiter sur une petite infrastructure si ses
processus, comptes, secrets, fichiers et budgets restent séparés ; une machine
ou VM dédiée est recommandée lorsque taille ou sensibilité augmentent. Le
laptop et le VPS public portant le Relay ne sont pas les placements permanents
par défaut. Cette cohabitation partage la panne matérielle : perdre ou isoler
l'hôte peut interrompre ses services locaux, et l'App doit le rendre
visible avant approbation.

Chaque rôle borne CPU, mémoire, processus et disque avec systemd/cgroup ou le
quota disponible. Ses destinations, listeners, tailles, concurrences, délais
et débits bornent séparément le réseau. L'audit rend ces coûts et ressources
disponibles. La preuve couvre une petite machine et les inventaires de 1, 2 et
64 machines. Un placement réellement insuffisant est refusé avec sa cause ; la
borne de 64 appartient à `v0.1.0` et ne constitue pas un plafond général du
produit.

Il existe exactement deux catégories d'accès SSH d'administration des machines :

- l'accès personnel indépendant que l'utilisateur conserve ;
- une identité Your Cloud différente par machine, créée et détenue par le
  Controller.

La seconde clé publique impose une commande forcée vers `your-cloud auxiliary` et
interdit shell, PTY, SFTP, transfert de port et transfert d'agent. Sa clé privée
reste sur le Controller dans un fichier possédé par `root`, fourni au seul
service Controller par les credentials systemd. L'authentification
App–Controller autorise l'humain dans le produit ; elle n'ajoute pas une
troisième autorité SSH.

La clé publique est installée pour un compte technique verrouillé, distinct du
Daemon et du Relay et sans mot de passe. Son fichier et ses parents root-owned
ne sont pas modifiables par ce compte. Les restrictions SSH refusent aussi rc
utilisateur, X11 et environnement, puis imposent le chemin absolu root-owned de
l'Auxiliaire. La politique d'élévation autorise uniquement cette invocation
exacte, environnement réinitialisé, avec le plan typé sur l'entrée standard,
jamais un `sudo`, `SETENV` ou des arguments libres.

Le lot serveur est installé avant cette clé. L'entrée Auxiliaire du palier
d'amorçage valide seulement son protocole en lecture seule et refuse par défaut
toute mutation ; la première opération réelle, la sonde OCI, appartient au
palier suivant.

Le même Assistant expose `Remplacer un Controller`. Ce choix reste manuel :
une panne temporaire ne déclenche aucune bascule. L'utilisateur redéclare les
endpoints si l'inventaire est perdu ; l'Assistant installe le nouveau
Controller et crée une nouvelle association App. Il réutilise les Agents
compatibles, reprovisionne l'identité et le filtre du lecteur Relay, puis tourne
l'époque d'approbation, les clés SSH, certificats, sessions et manifestes que
l'ancien Controller pouvait utiliser. Chaque nouvelle autorité est vérifiée
avant le retrait de l'ancienne. Une coupure rend un état partiel par machine et
interdit d'annoncer une réussite globale.

Si l'ancien Controller est soupçonné compromis, son hôte est d'abord isolé et
le nouveau part d'une base saine ; sinon le remplacement reste explicitement
non sécurisé. Les accès personnels restent intacts et les services des autres
hôtes continuent ; un service colocalisé sur l'hôte perdu ou isolé peut être
interrompu. Le code de récupération existant réassocie une App à un
Controller vivant ; il ne restaure pas un Controller détruit. Si cette
récupération remplace la clé humaine, les actions restent verrouillées jusqu'à
ce que l'Assistant tourne les ancres publiques avec l'accès SSH personnel.

L'installateur de `v0.1.0` embarque l'Assistant et un unique paquet serveur `.deb`
Debian 13 `amd64`, avec ses définitions statiques et le manifeste signé qui lie
sa version, sa cible, sa taille et son empreinte. Cette vérification précède tout
privilège. Le paquet possède seulement le binaire root-owned sous
`/usr/lib/your-cloud` et les unités statiques Controller, Daemon et Relay,
livrées inactives sous `/usr/lib/systemd/system` ; il ne porte ni secret, ni
configuration propre à une machine, ni activation de rôle ou transfert
d'autorité. L'Assistant orchestre hors ligne l'installation, la vérification,
le retour à la version ou à l'absence antérieure et le retrait explicite. Aucun
binaire privilégié n'est téléchargé à la volée. `arm64` attend une preuve
séparée et les mises à jour restent manuelles. Les builds Windows emploient un
certificat synthétique pour tester la mécanique ; une distribution publique
Windows reste bloquée tant qu'une signature reconnue et gratuite n'est pas
réellement opérationnelle.

Le contrat détaillé se trouve dans
[Amorçage et remplacement du Controller](../../architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md).
Cette capacité reste partielle. Le socle `#43` du helper, de l'IPC et de son
cycle de vie est implémenté et prouvé sous Linux et Windows sur le commit
`f3fef79`, dans le run `30753216798`. Les parcours `create` et `replace`
exposent uniquement des commandes Tauri positives sans secret, protégées par un
identifiant natif anti-rejeu ; le helper n'ouvre aucun listener. Sous Windows,
la preuve couvre aussi la création suspendue, la liste exacte de handles et le
Job Object, ainsi que les gates de packaging natif. Voir le
[rapport du runner Windows](../../lab/v1-bootstrap-ipc-windows.md).

Cette preuve ne ferme ni l'amorçage complet, ni `#35`, ni le palier `#13`.
`#45` est maintenant implémentée, prouvée et fermée pour les
fenêtres GTK3 et
Win32 natives, du périmètre immuable, de l'échéance monotone non renouvelable
de 300 secondes, du tampon protégé de 4096 octets et de son effacement, ainsi
que des protections mémoire Linux et Windows. Son
[rapport de preuve native](../../lab/v0.1.0-native-secret-consent-linux-windows.md)
conserve les résultats et limites. `30768351689` et `30768749538` sont rouges
sous l'ancien
oracle, mais montrent que `LocalDumps` administrateur contient le contrôle et
le canari ; cette autorité est hors garantie et l'enregistrement WER reste une
défense en profondeur. `ae550470` exige désormais cette présence, supprime le
dump, prouve son répertoire vide et les deux inscriptions de registre absentes,
mais ne retire le répertoire que par `Drop` après verdict. `30769440106` a
entièrement réussi ses quatre jobs et prouve cette étape intermédiaire, sans
fermer #45. `c8643b0` exige ensuite avec `remove_and_prove_absent` le
répertoire absent avant verdict. `30770893733` réussit ses quatre jobs sur
`b76ded8` et publie trois artefacts inspectés. Après trois corrections du
harnais de captures, `30779157351` réussit ses quatre jobs sur `c0569d0` :
l'issue #45 lie ce run et ce SHA, puis se ferme le 3 août 2026. Après
acceptation,
le secret est détruit et l'événement terminal public reste `Unavailable` jusqu'à
`#42` ; aucun SSH, `sudo`, `root`, audit ou succès d'amorçage n'est revendiqué.
L'accès SSH personnel `#42`, puis l'intégration complète suivie par `#35`
restent à implémenter et prouver avant la suite du palier.

## Quatre chemins différents

| Chemin | Rôle |
|---|---|
| Utilisateur vers App vers Controller | Authentifier l'humain, présenter l'infrastructure et recueillir ses demandes |
| Daemon vers Relay vers Controller | Transporter puis interpréter les observations des machines |
| Controller vers exécution contrôlée vers machine | Préparer puis exécuter les changements approuvés |
| Internet vers VPS vers service | Publier les applications destinées au Web, indépendamment de l'administration |

L'App ne devient pas un accès direct au Relay. Le Relay ne devient ni le
proxy Web, ni le backend métier, ni un canal d'action. Le Daemon ne devient pas
un accès d'administration. Une panne de l'App, du Controller ou de
l'observation ne doit pas arrêter, par elle-même, les services hébergés sur
d'autres machines ; la perte d'un hôte reste une panne de ses services
colocalisés.

### Comment l'interface agit réellement dans `v0.1.0`

Quand l'utilisateur demande un déploiement ou une modification prise en charge :

1. le Controller obtient le dernier état d'observation validé du Relay sans le
   confondre avec une preuve actuelle ;
2. il construit un plan borné pour les machines et services explicitement
   choisis ;
3. l'App affiche les changements, privilèges, flux, effets d'un échec et
   limites ;
4. l'utilisateur approuve ce plan dans l'App ;
5. le Controller utilise l'identité SSH propre à la machine et sa commande
   forcée pour faire appliquer le plan typé par l'Auxiliaire ponctuel ;
6. le Controller vérifie le résultat par des contrôles directs puis par les
   nouvelles observations du Daemon obtenues auprès du Relay.

Le Daemon ne reçoit donc jamais le clic de l'utilisateur et n'exécute aucune
commande. `v0.1.0` automatise les seules opérations prévues par son contrat ; elle
ne promet pas encore une app d'administration générale.

L'App communique uniquement avec les Controllers qui lui ont été
explicitement associés. Dans le LAB de `v0.1.0`, le Controller vit dans l'environnement
d'administration et possède un chemin réseau explicitement autorisé vers SSH,
sans exposition publique du port de la machine du LAN. `v0.1.0` ne prétend pas
encore qu'une App installée n'importe où peut traverser seule n'importe quel
NAT.

### Compatibilité avec la cible finale

`v0.1.0` et la cible à long terme conservent le même contrat utilisateur :
demander une action, comprendre le plan, approuver son contenu exact, appliquer
par une autorité adaptée puis vérifier le résultat.

`v0.1.0` distribue un seul exécutable `your-cloud` sur les deux machines. Sur la
machine du LAN, systemd lance `your-cloud daemon`. Sur le VPS, systemd lance en
parallèle `your-cloud daemon` et `your-cloud relay` depuis ce même fichier, mais
sous des comptes, configurations, identités, secrets et budgets distincts. Le
rôle Relay est désactivé par défaut et refuse de démarrer sans provisionnement
local explicite de la machine candidate. Une seule version à maintenir ne
signifie donc ni un seul processus, ni une autorité commune.

Sur une machine placée en mode géré, une commande SSH forcée peut lancer
ponctuellement `your-cloud auxiliary` depuis les mêmes octets. L'Auxiliaire n'est ni
une unité permanente, ni un listener, ni un shell général. Il reçoit un plan
typé dont l'enveloppe canonique a été signée par le cœur natif de l'App
après l'approbation explicite. La cible conserve la clé publique, l'époque et la
séquence anti-rejeu dans un état root-owned minimal. Le Controller transporte
l'enveloppe sans pouvoir la modifier. L'Auxiliaire revérifie signature, cible,
époque, successeur exact de la séquence, expiration et contraintes locales,
consomme durablement la séquence avant mutation, applique seulement l'opération
connue, rend un résultat structuré puis s'arrête. Il n'a aucun accès réseau
général ;
une opération OCI peut faire demander à Podman rootless uniquement un registre
autorisé et un digest exact déjà visibles dans le plan.

Ce chemin SSH d'action reste totalement séparé du Daemon et du Relay
d'observation. Ansible ne fait pas partie du runtime ou du cœur produit de `v0.1.0` :
l'utilisateur peut continuer à l'employer en mode externe et une intégration
isolée pourra être étudiée après stabilisation. OpenStack, Terraform, OpenTofu
et K3s utiliseront leurs API ou un runner isolé lorsque cette autorité est plus
adaptée. Cette cible est détaillée dans le
[cap du projet](../../projet/CAP.md).

Les contraintes de `v0.1.0` sont :

- le plan compris et approuvé est le document exact reçu par l'Auxiliaire ;
- l'approbation couvre aussi le rollback exact, borné aux seules ressources
  gérées par Your Cloud ;
- le cœur natif signe seulement cette enveloppe nommée ; le frontend n'obtient
  aucune signature libre et le Controller ne peut pas forger l'approbation ;
- tout artefact ou paramètre généré qui ne correspond plus à l'empreinte
  approuvée arrête l'application avant la première mutation ;
- le Controller ne reçoit depuis l'App ni playbook, inventaire, commande,
  argument libre ou chemin arbitraire : il sélectionne un parcours connu et des
  entrées typées, puis borne la cible à une machine enrôlée ;
- l'identité SSH opérationnelle est différente sur chaque machine ; sa commande
  forcée, son répertoire et son binaire root-owned interdisent shell, PTY, SFTP,
  rc, X11, environnement et transferts ;
- le Daemon et le Relay restent consacrés à l'observation ;
- la cohabitation sur le VPS ne leur donne aucun fichier d'identité, secret,
  stockage ou compte commun ;
- la première application d'un changement rend `changed=true` ; le même état
  demandé sans dérive et le retrait d'un élément déjà absent rendent
  `changed=false`, sans réécriture ni redémarrage inutiles ;
- une dérive est signalée et exige un nouveau plan ; elle n'est pas corrigée
  silencieusement ;
- après un échec contrôlé, l'Auxiliaire tente le rollback approuvé tant qu'il
  garde la maîtrise ; une coupure rend le résultat inconnu, interdit tout rejeu
  aveugle et impose d'observer avant de proposer un nouveau plan ; l'époque et
  la séquence consommée rendent ce refus durable après redémarrage ;
- l'échec de l'App, du Controller, du chemin SSH ou d'une action ne
  doit pas arrêter un service déjà déployé ;
- les résultats directs et les observations ultérieures restent deux preuves
  distinctes, visibles dans l'App.

## Identités et chiffrement

Seules les machines explicitement enrôlées peuvent devenir des pairs du passage
privé. L'enrôlement prouve une identité ; il n'autorise pas une machine à parler
librement à toutes les autres. `v0.1.0` n'est donc pas un réseau maillé de confiance
mais un ensemble de flux minimaux approuvés.

Chaque donnée Your Cloud qui traverse le réseau privé entre deux machines
enrôlées est chiffrée et authentifiée avant de quitter sa machine, avec le
mécanisme adapté au chemin :

| Flux | Protection retenue pour `v0.1.0` |
|---|---|
| Paquets privés entre machines enrôlées | WireGuard, pairs nommés et routes bornées |
| Daemon vers Relay | mTLS avec une identité propre à chaque Daemon, y compris au-dessus de WireGuard lorsque le Relay est distant |
| App installée vers Controller | origine HTTPS TLS 1.3 exacte ; identité d'appareil P-256 mTLS et signature humaine Ed25519 liées au Controller et à son infrastructure ; clés distinctes dans un coffre Tauri Stronghold commun Linux/Windows déverrouillé par six mots locaux Argon2id ; appairage et récupération sur listener temporaire épinglé, session bornée et rotations en deux phases |
| Controller vers Relay | `GET /v0/snapshot` sur le listener privé exact `8444`, filtré sur l'IP source Controller puis protégé par TLS 1.3 mTLS, CA Ed25519 dédiées, manifeste et `infrastructure_id` commun ; UTC et reprise bornées |
| Controller vers machine pour un plan approuvé | SSH avec une identité Your Cloud propre à la machine et une commande forcée root-owned ; enveloppe signée par l'App, clé publique, époque et anti-rejeu vérifiés sur la cible ; aucun shell, PTY, SFTP, rc, X11, environnement ou transfert |
| Navigateur vers service publié | HTTPS jusqu'au point d'entrée public |
| VPS vers service du LAN | WireGuard et autorisation limitée à la destination et au port du service |

WireGuard et mTLS ne sont pas deux synonymes. WireGuard chiffre et authentifie
les paquets entre machines ; mTLS identifie les composants Your Cloud qui
échangent des données applicatives. SSH protège le chemin d'administration et
HTTPS protège les accès Web. Après `v0.1.0`, l'accès d'un appareil administrateur
au Controller utilisera aussi un passage WireGuard borné, sans remplacer
l'authentification de l'humain dans le Controller. Ajouter mTLS indistinctement
à tous les services tiers n'apporterait pas automatiquement une meilleure
sécurité ; une couche supplémentaire doit protéger une identité ou une menace
réellement définie.

La règle « seules les machines enrôlées communiquent » concerne le réseau privé
de Your Cloud. Elle n'interdit pas les flux explicitement attendus vers un
navigateur, l'App, le Controller, le DNS, l'heure ou un registre
d'artefacts. Ces exceptions restent déclarées, limitées et vérifiables. Le
chiffrement protège le contenu,
pas les métadonnées nécessaires au routage telles que les adresses IP, les ports
et les horaires de communication.

### Justification de sécurité

- **Menace traitée** : écoute ou modification du trafic, fausse machine,
  composant usurpé et déplacement latéral depuis une machine compromise.
- **Alternatives écartées** : WireGuard seul ne distingue pas les composants
  applicatifs d'une même machine ; mTLS seul ne borne ni les routes ni les ports
  du système ; un réseau de confiance entre toutes les machines enrôlées donne
  trop de droits.
- **Choix** : WireGuard pour le transport privé borné, mTLS pour le protocole
  Daemon–Relay, SSH pour l'administration et HTTPS pour le Web, avec des
  identités et autorités séparées.
- **Preuves attendues** : un pair WireGuard inconnu, un certificat de Daemon
  inconnu ou révoqué, une mauvaise clé d'hôte SSH et un port non prévu sont tous
  refusés ; aucune donnée applicative utile ne traverse le réseau en clair.
- **Risque résiduel** : la compromission complète d'une machine peut donner
  accès aux clés présentes sur celle-ci et aux flux exactement autorisés pour
  elle ; le chiffrement en transit ne protège pas une donnée déjà déchiffrée en
  mémoire sur son extrémité légitime.

Ce choix applique la confidentialité, l'intégrité, l'authentification forte, la
segmentation et le moindre privilège recommandés par
[OWASP pour TLS](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
et s'inscrit dans les mesures proportionnées de cryptographie, contrôle d'accès
et gestion des risques de l'[article 21 de NIS2](https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555).
Il ne constitue pas à lui seul une preuve de conformité.

## Deux modes de responsabilité

`v0.1.0` distingue explicitement qui possède le droit de modifier chaque service
et chaque passage réseau.

### Mode géré

L'utilisateur choisit dans l'App « publier ce service par ce VPS ». Your Cloud :

1. observe l'état actuel des deux machines ;
2. calcule les adresses, routes et autorisations strictement nécessaires ;
3. présente le plan et les conséquences d'une suppression ou d'un échec ;
4. attend l'approbation ;
5. fait appliquer les opérations typées par l'Auxiliaire de chaque machine ;
6. vérifie le passage privé, le refus des autres ports et l'accès HTTPS ;
7. conserve l'état attendu afin de détecter une dérive ultérieure.

Le calcul est dynamique, mais l'application ne l'est pas : un changement de
placement, de port ou de VPS crée un nouveau plan à approuver. Aucun événement
de découverte ne modifie silencieusement le réseau.

La disponibilité d'un profil de service dans l'App ne déploie rien. Une
instance n'existe qu'après déclaration, placement, plan et approbation
explicites ; les profils BentoPDF et Vaultwarden de la preuve de `v0.1.0` ne sont donc
requis dans aucune infrastructure utilisateur.

### Mode externe

L'utilisateur peut installer lui-même un service et construire lui-même son
passage WireGuard. Il les déclare ensuite dans l'App sans remettre leurs clés
privées ni leur autorité à Your Cloud.

L'App affiche alors :

- la machine et le service déclarés ;
- le chemin d'exposition déclaré ;
- les observations que le Daemon ou un adaptateur en lecture seule sait
  réellement confirmer ;
- un statut explicite « externe vérifié » ou « externe non vérifié » ;
- les limites : aucune promesse de mise à jour, de rollback, de suppression ou
  de moindre privilège lorsque ces propriétés ne sont pas prouvées.

`v0.1.0` ne découvre pas arbitrairement tous les services et tunnels existants.
Elle exige une déclaration explicite. Une future reprise en **Mode géré** devra
commencer par un audit, un diff et une approbation ; elle n'est jamais implicite.

## Capacités nécessaires

- Amorcer une infrastructure depuis l'App avec un accès SSH personnel
  temporaire, sans scanner le LAN ni conserver cet accès.
- Installer un Controller autonome puis pouvoir le remplacer explicitement en
  conservant les accès personnels, les services des hôtes survivants et les
  Agents compatibles tout en renouvelant toutes les autorités que l'ancien
  Controller pouvait exercer ; rendre visible l'interruption possible d'un
  service colocalisé sur l'hôte perdu.
- Rattacher les deux machines existantes avec une identité SSH Your Cloud
  différente et restreinte par machine.
- Installer un Agent minimal proprement identifiable sur chaque machine, dont
  le Daemon est limité à l'observation.
- Activer sur le seul VPS déclaré candidat un processus Relay séparé à partir du
  même exécutable, sans rendre le rôle Relay démarrable sur la machine du LAN.
- Recevoir par le Relay leur présence, leur version et un premier état utile.
- Afficher clairement une donnée absente, récente ou devenue ancienne.
- Présenter depuis l'App un plan de déploiement avant exécution.
- Exécuter le déploiement approuvé par l'utilisateur et vérifié par
  l'Auxiliaire ponctuel de la machine concernée, sans shell ni commande libre.
- Déployer dans le LAB deux profils de référence aux versions précisément
  maîtrisées : un sur le VPS et un dans le LAN.
- Configurer le passage chiffré entre le VPS et la machine du LAN.
- Configurer le point d'entrée HTTPS du VPS et les routes des deux services.
- Ne donner au VPS que l'accès nécessaire au service privé publié.
- Permettre de déclarer un service ou un passage installé manuellement, puis
  afficher séparément ce qui est déclaré et ce qui est vérifié en lecture seule.
- Rejouer un déploiement sans changement inutile.
- Redémarrer les machines sans perdre les services ni leur observation.
- Retirer proprement un service, sa route publique et les autorisations devenues
  inutiles.

## Ce que « ne pas exposer le LAN » signifie

- Le DNS public désigne le VPS, jamais l'adresse du site privé.
- Aucun port entrant n'est transféré vers la machine du LAN.
- Le service du LAN n'accepte que le trafic nécessaire provenant du passage
  privé.
- Un contrôle extérieur ne trouve aucun port Your Cloud exposé sur le site
  privé.

Le VPS voit nécessairement l'adresse source utilisée par la connexion sortante.
`v0.1.0` ne promet donc pas qu'elle soit inconnue du VPS ; elle promet qu'elle
n'est ni publiée comme destination, ni rendue directement joignable par une
ouverture créée par Your Cloud.

## Frontière WireGuard retenue

WireGuard sert de transport chiffré entre le VPS et la machine privée, jamais
de VPN général vers le LAN :

- une paire de clés distincte par machine, sans secret de flotte partagé ;
- les clés privées sont générées et conservées sur leur machine ;
- une adresse de tunnel `/32` par pair ;
- aucune route vers le sous-réseau du LAN et aucun `0.0.0.0/0` ;
- aucun forwarding du tunnel vers les autres machines du LAN ;
- politique `nftables` en refus par défaut sur l'interface WireGuard ;
- autorisation limitée aux ports des services explicitement publiés ;
- aucun accès depuis le VPS vers SSH, l'administration ou les autres ports de
  la machine privée.

Le Daemon ne scanne aucun voisin et ne contacte que le Relay approuvé. Un
service géré déclare ses besoins réseau ; son environnement d'exécution refuse
par défaut les communications vers les autres appareils du LAN. Les flux
nécessaires à l'administration, au DNS, à l'heure, au téléchargement pendant le
déploiement ou à une fonction propre au service restent des exceptions
explicites et vérifiables, jamais une confiance générale dans le LAN.

WireGuard authentifie le pair et chiffre le transport. Il ne remplace ni
l'autorisation par service, ni HTTPS, ni le suivi des clés, ni les preuves de
révocation. Your Cloud porte ces responsabilités supplémentaires.

## Point d'entrée HTTPS retenu

Dans son scénario de référence, `v0.1.0` utilise **Traefik** sur le VPS pour
terminer HTTPS et router les noms publics vers BentoPDF et Vaultwarden. Ce
choix rend la preuve déterministe sans imposer ce proxy, ces services ou ce
placement à une infrastructure utilisateur.

Your Cloud reste l'autorité déclarative des publications : il génère une
configuration dynamique Traefik en YAML avec le `file provider`, la présente
dans le plan, la fait déposer atomiquement par l'Auxiliaire du VPS puis vérifie
le résultat. Traefik ne découvre pas seul les conteneurs et ne reçoit pas le
socket Docker dans `v0.1.0`. La configuration vise explicitement BentoPDF sur le
VPS et Vaultwarden par son adresse WireGuard et son port autorisé.

Contraintes de sécurité :

- version de Traefik et artefact épinglés précisément ;
- seuls les points d'entrée publics `80` pour la redirection et `443` pour HTTPS
  sont exposés ;
- API, mode `insecure`, endpoints de debug et dashboard publics désactivés ;
- données ACME persistantes accessibles uniquement au compte Traefik ;
- configuration dynamique sans secret en clair et écrite de manière atomique
  dans le répertoire surveillé ;
- vérification de la configuration, du certificat, des en-têtes nécessaires et
  des deux routes avant de considérer le plan réussi ;
- retrait d'un service accompagné du retrait de sa route et de son autorisation
  réseau.

### Justification de sécurité de Traefik

- **Menace traitée** : publication accidentelle d'un conteneur, compromission
  du proxy donnant accès au moteur de conteneurs, route trop large ou interface
  d'administration exposée.
- **Alternative considérée** : le provider Docker et ses labels faciliteraient
  la découverte, mais nécessiteraient un accès à l'API Docker et déplaceraient
  une partie de l'autorité de publication hors du plan explicite Your Cloud.
- **Moindre privilège** : le `file provider` ne donne à Traefik que les routes
  approuvées et aucun contrôle du moteur de conteneurs.
- **Preuves hostiles** : un conteneur non déclaré ne reçoit aucune route ; le
  socket Docker, l'API, le dashboard, les endpoints de debug et un port backend
  non autorisé restent inaccessibles depuis Internet et WireGuard.
- **Risque résiduel** : Traefik demeure un composant exposé ; sa compromission
  peut lire le trafic qu'il termine et utiliser les destinations strictement
  autorisées, sans toutefois donner par conception le contrôle de Docker ou du
  reste du LAN.

La documentation officielle distingue le
[file provider](https://doc.traefik.io/traefik/v3.6/reference/install-configuration/providers/others/file/)
du [provider Docker](https://doc.traefik.io/traefik/v3.6/reference/install-configuration/providers/docker/)
et signale elle-même le risque d'un accès non restreint à l'API Docker. Ce choix
applique le moindre privilège et la réduction de surface d'attaque attendus par
OWASP, ainsi que les mesures proportionnées de contrôle d'accès, développement
sûr et réduction du risque de NIS2, sans constituer une conformité à lui seul.

## Méthode de déploiement

Le Controller orchestre et vérifie les changements ; l'Auxiliaire applique sur
sa propre machine les opérations locales typées. `v0.1.0` n'en fait pas un format
universel des services : elle implémente un premier parcours officiel fondé sur
des **images OCI**. Ansible reste un outil externe de l'utilisateur, pas une
dépendance du produit ou du runtime de `v0.1.0`.

Lorsqu'un profil BentoPDF ou Vaultwarden est explicitement sélectionné, il est
référencé par un nom lisible, une version précise et le digest du manifeste
réellement approuvé. Un tag flottant comme `latest` est refusé. Le plan affiche
l'origine, la version, le digest, les volumes, les ports, les besoins réseau et
les limites de ressources avant approbation.

L'Auxiliaire demande à Podman rootless de télécharger l'image depuis le seul
registre autorisé dans le plan, vérifie que le digest obtenu correspond, puis
installe la définition du service et rend ses contrôles directs. Il n'ouvre
aucun listener et ne dispose d'aucun accès réseau général : le registre, le
digest et l'effet réseau appartiennent au plan. Une mise à jour produit un
nouveau plan vers un nouveau digest ; elle ne suit jamais silencieusement un
tag modifié. Une suppression retire le conteneur et ses autorisations, mais ne
détruit les données persistantes que si cette conséquence a été explicitement
demandée et approuvée.

Ce choix borne le premier adaptateur sans faire des conteneurs le modèle unique
du produit. Un futur adaptateur de paquet natif ou de K3s devra respecter le
même contrat de plan, provenance, vérification et retrait.

### Justification de sécurité des images OCI

- **Menaces traitées** : version remplacée sous un tag, origine ambiguë,
  dépendances inconnues, mise à jour involontaire et suppression de données.
- **Alternative considérée** : les paquets natifs s'intègrent mieux au système,
  mais BentoPDF et Vaultwarden fournissent déjà des images et exigeraient deux
  parcours d'installation différents pour cette première preuve.
- **Moindre privilège** : chaque service reçoit uniquement ses volumes, ports,
  ressources et flux déclarés ; aucun socket de moteur de conteneurs n'est
  monté dans les services.
- **Preuves attendues** : un digest différent, un registre non autorisé, un tag
  flottant, un volume ou un port non déclaré font échouer le plan ; le second
  passage reste sans changement et les données Vaultwarden survivent à la
  recréation contrôlée de son conteneur.
- **Risque résiduel** : une image approuvée peut encore contenir une
  vulnérabilité inconnue et les conteneurs partagent le noyau de l'hôte ; le
  digest garantit l'identité des octets, pas leur innocuité.

La provenance, l'inventaire, le SBOM et l'analyse de composants suivront une
adoption progressive de l'[OWASP Software Component Verification Standard](https://scvs.owasp.org/).
Ce choix contribue aux mesures NIS2 relatives à la chaîne d'approvisionnement,
au développement sûr et à la gestion des vulnérabilités, sans prouver à lui
seul une conformité.

## Moteur OCI retenu

`v0.1.0` exécute les images OCI avec **Podman en mode rootless** et les décrit par
des unités **Quadlet** gérées par systemd.

Ce parcours géré exige donc **systemd et cgroup v2 sur la machine qui héberge le
service OCI**. L'App vérifie ces deux prérequis avant de proposer le plan. Si
l'un manque, elle refuse le déploiement géré avec une explication précise :
Quadlet ne bascule pas automatiquement vers OpenRC, runit ou un script maison.
Un service installé par l'utilisateur peut rester représenté en mode externe.
Aucun adaptateur pour un autre système d'init n'est planifié dans `v0.1.0`.

Cette limite concerne le déploiement OCI géré. L'enveloppe serveur de `v0.1.0` est
bornée à Debian 13 `amd64` ; une autre architecture ou distribution n'est
annoncée qu'après une preuve dédiée.

Podman offre une ligne de commande comparable à celle de Docker, ce qui réduit
le coût d'apprentissage pour un utilisateur habitué aux commandes `docker`.
Cette compatibilité n'est pas promise comme parfaite : la documentation et
l'interface Your Cloud emploieront les commandes réellement prises en charge et
signaleront les différences utiles.

Quadlet n'est pas une couche d'orchestration cachée. C'est la fiche déclarative
qui associe une image précise à son compte, ses volumes, son réseau, ses ports,
ses limites et sa politique de redémarrage. systemd transforme cette fiche en
service Linux observable. L'Auxiliaire installe et retire ces définitions après
approbation ; aucune API Podman permanente n'est nécessaire à Traefik ou aux
services.

### Justification de sécurité de Podman et Quadlet

- **Menaces traitées** : compromission d'un démon privilégié, élévation depuis
  un conteneur, configuration manuelle non reproductible et dérive invisible.
- **Alternative considérée** : Docker rootless peut aussi réduire les
  privilèges et reste valide en mode externe, mais Podman rend le chemin sans
  démon central et l'intégration systemd déclarative naturels pour `v0.1.0`.
- **Moindre privilège** : un compte système rootless distinct exécute chaque
  famille de service ; aucun conteneur privilégié, aucun socket de moteur monté,
  aucune capacité, volume, port ou communication implicite.
- **Contrôles à exprimer dans Quadlet** : utilisateur non-root dans le
  conteneur, interdiction de nouveaux privilèges, capacités supprimées par
  défaut, système de fichiers en lecture seule lorsque compatible, volumes
  d'écriture explicites, limites CPU, mémoire et processus, réseau borné et
  politique de redémarrage finie.
- **Preuves hostiles** : une unité demandant root, le mode privilégié, un
  montage interdit, une capacité non approuvée, un port public ou un digest
  flottant est refusée ; une cible sans systemd ou sans cgroup v2 est refusée
  avant mutation ; une tentative d'écriture hors volume et une tentative
  d'élévation échouent.
- **Risque résiduel** : le noyau reste partagé ; une faille du noyau ou du
  runtime peut franchir l'isolation et rootless possède encore tous les droits
  de son compte hôte sur ses propres fichiers.

OWASP ne recommande pas Quadlet comme produit précis. Son
[guide de sécurité des conteneurs](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
recommande en revanche rootless, l'absence de socket exposé, les utilisateurs
non privilégiés, la réduction des capacités, l'interdiction d'élévation, la
limitation des ressources et les systèmes de fichiers en lecture seule. Quadlet
est le support choisi pour rendre ces réglages déclaratifs, relisibles et
testables. La [documentation Podman](https://docs.podman.io/en/latest/markdown/podman.1.html)
confirme sa CLI comparable à Docker, son architecture sans démon et son usage
rootless ; la [documentation Quadlet](https://docs.podman.io/en/stable/markdown/podman-quadlet.1.html)
confirme sa gestion déclarative par systemd.

Le refus d'un hôte incompatible applique l'échec sûr et la valeur sûre par
défaut : Your Cloud n'invente pas un mécanisme de démarrage moins maîtrisé pour
faire réussir le déploiement. Cette décision réduit le périmètre à maintenir et
à tester, ce qui contribue aux mesures NIS2 de développement sûr et
d'évaluation de l'efficacité sans constituer une conformité à elle seule.

Lors du premier incrément qui utilisera Podman et Quadlet, le rapport HTML
expliquera avant exécution chaque champ retenu, le risque qu'il traite, son
effet visible et le test qui le prouve. `v0.1.0` ne considérera pas ce parcours
terminé tant que la relation entre la fiche Quadlet, le conteneur et le service
systemd réellement observés ne sera pas compréhensible.

Un déploiement de `v0.1.0` est au minimum versionné, relançable, vérifié après
application et désinstallable. Les scripts opaques et non idempotents ne
constituent pas le parcours normal.

## Profils de service retenus pour la preuve finale

Deux services temporaires de type `hello-world` pourront servir de sondes dans
les micro-versions qui construisent le déploiement, le passage privé et le
routage. Ils ne compteront pas comme les deux véritables services de `v0.1.0`.

La preuve finale doit couvrir deux capacités génériques : un service web OCI
public et un service privé persistant publié par un point d'entrée séparé. Pour
rester déterministe, le LAB utilise les deux profils de référence suivants :

- **BentoPDF sur le VPS** : service public essentiellement statique, sans base
  de données, dont le traitement des PDF reste dans le navigateur ; son image et
  ses dépendances seront épinglées et les téléchargements d'actifs externes
  seront supprimés ou explicitement bornés ;
- **Vaultwarden sur la machine du LAN** : service sensible et persistant,
  accessible uniquement en HTTPS par le VPS ; sa preuve inclura le stockage,
  la sauvegarde, la restauration, le redémarrage, la fermeture des inscriptions
  et l'absence d'accès latéral au LAN.

Cette cible de preuve est validée pour `v0.1.0`. La preuve devra montrer que les
deux profils peuvent être proposés puis sélectionnés explicitement ; aucun ne
deviendra une obligation pour l'infrastructure réelle. Les sondes `hello-world`
restent uniquement des outils de construction intermédiaires et ne satisfont
pas sa preuve finale.

Vaultwarden est volontairement réservé à un incrément tardif : il ne doit pas
servir à déboguer en même temps le premier conteneur, WireGuard, le proxy et la
persistance. Le LAB n'utilisera que des secrets synthétiques.

La [documentation officielle de BentoPDF](https://www.bentopdf.com/docs/self-hosting/)
fournit une image OCI, des commandes Podman et un exemple Quadlet. Son profil
devra sélectionner une édition et une licence adaptées à l'exposition,
préserver HTTPS et les en-têtes COOP/COEP nécessaires à `SharedArrayBuffer`,
puis borner ou auto-héberger les dépendances chargées au runtime.

Le [dépôt officiel de Vaultwarden](https://github.com/dani-garcia/vaultwarden)
fournit une image OCI, documente Podman, utilise `/data` pour la persistance,
attend une origine `DOMAIN` cohérente en HTTPS et recommande un proxy inverse.
Ces propriétés rendent les deux profils compatibles **en principe** avec le
parcours cible. Rootless, Quadlet, filtrage, redémarrage, sauvegarde et
restauration restent à implémenter puis à prouver dans le LAB. Les exemples
amont utilisent parfois `latest` ; Your Cloud utilisera au contraire une
version et un digest précis, conformément à sa politique de chaîne
d'approvisionnement.


## Premier incrément déjà retenu

La `v0.0.1` ne construit pas toute la version `v0.1.0`. Sa preuve finale doit montrer,
uniquement dans le LAB :

- un seul exécutable Go `your-cloud`, identique sur les deux machines ;
- sur le VPS simulé, un Daemon et un Relay exécutés en parallèle depuis cet
  exécutable sous deux comptes distincts ;
- sur la machine du LAN, un Daemon seul et le refus du mode Relay faute de
  provisionnement candidat ;
- l'envoi d'un identifiant de machine, de la version du Daemon et d'un signal
  de présence horodaté ;
- la conservation par le Relay du dernier signal reçu ;
- le passage visible d'une machine à un état ancien lorsque son Daemon est
  arrêté.

Pas d'interface graphique, de métriques système, de déploiement de service ni
de mTLS dans cette première étape. Le réseau non sécurisé de ce prototype reste
strictement confiné au LAB. Chaque version suivante ferme une limite explicite
avant d'ajouter une nouvelle capacité.

## Preuve de `v0.1.0` dans le LAB

Le LAB simulera au minimum :

- des environnements d'administration isolés pour l'App, son Assistant
  temporaire et le Controller ;
- une VM jouant le rôle du VPS sur un réseau exposé ;
- une VM placée derrière un réseau LAN sans entrée directe ;
- une sonde extérieure au LAN pour vérifier les accès publics et l'absence
  d'exposition directe.

La preuve montrera le placement de référence, les commandes significatives, les
deux profils de service accessibles, les ports réellement exposés, un second
passage sans changement, les redémarrages et la suppression propre.

Un test hostile partira du VPS supposé compromis et tentera d'atteindre SSH,
les ports non publiés et le reste du LAN. Seul le port exact du service publié
devra rester joignable.

Un second test hostile partira du service placé dans le LAN et tentera de
joindre un appareil voisin synthétique. La tentative devra échouer tant qu'aucun
flux latéral n'a été déclaré et approuvé. Cette preuve porte sur les composants
et environnements gérés par Your Cloud ; elle ne prétend pas transformer à elle
seule tout le système Linux en pare-feu général du domicile.

## Hors du contrat actuel de `v0.1.0`

- Créer les VM ou installer leur système d'exploitation.
- Piloter OpenStack, Terraform, OpenTofu ou un fournisseur cloud.
- Transporter des plans par le Daemon ou le Relay, ou ouvrir un shell général
  par l'Auxiliaire.
- Intégrer Ansible dans le Controller ou l'imposer aux machines.
- Basculer automatiquement vers un autre Controller, reconstruire son
  inventaire par scan ou ajouter une troisième autorité SSH de secours.
- Reprendre automatiquement une action interrompue dont le résultat est
  inconnu.
- Fournir depuis l'interface des opérations générales sur la machine au-delà des
  déploiements, passages et routes précisément pris en charge par `v0.1.0`.
- Fournir un catalogue générique acceptant arbitrairement tout service.
- Découvrir automatiquement les services et passages existants ou les adopter
  en gestion. `v0.1.0` repose sur leur déclaration explicite et leur vérification
  en lecture seule lorsqu'un adaptateur existe.
- Scanner une plage réseau ou inventorier les appareils voisins du LAN.
- Exiger K3s standalone ou un cluster K3s pour atteindre `v0.1.0`.
- Fournir une haute disponibilité complète ou masquer les pannes.
- Déployer un fournisseur d'identité et activer le SSO de Vaultwarden.

Ces capacités restent hors de `v0.1.0`. Elles pourront venir ensuite ; leur ajout à
`v0.1.0` exigerait une modification explicite et une nouvelle validation du contrat,
jamais un simple changement de roadmap.

## Premier jalon demandé après `v0.1.0`

La `v0.1.1` « Services utilisateur » ajoutera les définitions de service
utilisateur : un document inerte, gelé et haché, que seuls des plans approuvés
et signés épinglent par digest, pour déployer une application choisie par
l'utilisateur dans les limites nommées de son contrat
([`SERVICE-UTILISATEUR.md`](../../architecture/SERVICE-UTILISATEUR.md)). Ce
contrat est la « modification explicite et nouvelle validation » que la liste
ci-dessus exige avant d'approcher un catalogue : la capacité reste bornée —
elle n'accepte pas arbitrairement tout service — et rien n'entre pour autant
dans `v0.1.0`. Le jalon est contracté en issues dans la
[milestone `v0.1.1` — Services utilisateur](https://github.com/ldesfontaine/your-cloud/milestone/8)
(`#115` à `#121`), dont l'issue de contrat
[`#115`](https://github.com/ldesfontaine/your-cloud/issues/115) porte cette
revalidation ; rien ne s'est implémenté avant qu'elle soit validée, et la
`v0.1.1` est déclarée atteinte depuis le 14 août 2026 — le candidat `f7583e2`
de `v0.1.0` étant attesté (matrice native `31840505025`, preuve complète,
tag `v0.1.0`). Le petit parcours
SSO OpenID Connect de Vaultwarden, demandé plus tôt pour ce jalon, passe à un
jalon ultérieur **non numéroté** sans changer de réserve : fournisseur,
placement et récupération seront choisis à son cadrage, et rien n'est installé
par défaut.

## Paramètres fixés au bon incrément

`v0.0.2` a mesuré le profil `host-health.v1` dans le LAB et fixé un tampon de
`64 KiB`, 120 observations ou une heure, première limite atteinte. Ces valeurs
sont prouvées pour ce profil et cet environnement ; elles ne constituent pas un
plafond de charge de production et ne préjugent pas des profils futurs.

Le contrat suffisant pour découper `v0.1.0` est le suivant :

- `v0.0.1` ne conserve que le signal de présence décrit plus haut ;
- `v0.0.2` ajoute la santé bornée de la machine et les limites mesurées ci-dessus ;
- chaque incrément ultérieur ajoute uniquement l'observation nécessaire à sa
  preuve : santé de la machine, état des services, du passage privé ou du point
  d'entrée ;
- aucun log, contenu de fichier, secret ou inventaire libre n'entre dans le
  profil par défaut ;
- le tampon possède toujours une limite d'âge, une limite de taille et un
  maximum non contournable ;
- l'état courant est conservé, les plus anciens événements historiques sont
  retirés en premier et chaque perte crée une lacune visible ;
- tout incrément qui change le profil ou ses limites remesure leur taille, leur
  fréquence et leur coût disque dans le LAB, puis documente ses valeurs par
  défaut et ses tests de saturation.

Ces paramètres sont une décision d'implémentation prouvée, pas une hypothèse
architecturale prise trop tôt. Le
[rapport LAB `v0.0.2`](../../lab/v0.0.2-observation.md) conserve les mesures et
leurs limites.

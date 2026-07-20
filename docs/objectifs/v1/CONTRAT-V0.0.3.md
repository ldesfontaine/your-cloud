# Contrat `v0.0.3` — Console cliente et Controller de lecture

> État au 20 juillet 2026 : **architecture produit et paramètres 1 à 8
> validés ; porte Linux exécutée et réussie** sur un candidat de worktree non
> commité. Le [rapport LAB Linux](../../lab/v0.0.3-console-controller-linux.md)
> conserve les preuves et limites. Lucas garde la porte Windows gelée jusqu'à
> validation explicite de la stabilisation `v0.0.3` ; elle restera ensuite
> obligatoire avant de déclarer le palier terminé et prouvé.

## Résultat utilisateur

Un administrateur installe la Console Your Cloud sur Linux ou Windows, lui
associe le Controller privé d'une infrastructure et consulte les deux machines
déjà enrôlées. Il voit leur dernier état `host-health.v1`, l'heure de réception,
la séquence, les lacunes connues et un statut `récent`, `ancien` ou `absent`,
sans confondre ces valeurs avec un Relay indisponible ou une horloge non fiable.

La Console permet de créer l'inventaire local du Controller et d'y rattacher des
identifiants de machines déjà enrôlés. Cette écriture concerne seulement les
données métier du Controller : elle ne délivre ni certificat, ni ordre, ni
modification à une machine ou au Relay.

## Placement validé

```text
Appareil administrateur
`- Console installée et signée
   |- frontend embarqué
   |- aucun serveur local, aucune page localhost
   |- associations de Controllers approuvées
   |- identité d'appareil et sessions protégées
   `- API privée authentifiée
                 |
                 v
Controller d'une infrastructure — backend uniquement, aucun frontend
`- lecture privée authentifiée --> Relay

Daemon -- POST mTLS --> Relay
`- aucune connaissance du Controller ou de la Console
```

Un **frontend embarqué** désigne les fichiers de l'interface inclus dans
l'artefact signé de la Console. Ils peuvent employer des technologies Web sans
être servis par un site, un Controller ou un serveur `localhost`.

Une **enveloppe cliente** désigne le programme natif léger qui affiche ce
frontend, contrôle le réseau, accède au stockage sécurisé du système et borne les
capacités exposées à l'interface. `v0.0.3` utilise Tauri 2 pour cette enveloppe
et React, TypeScript et Vite pour le frontend commun. Le frontend appelle
seulement des opérations Tauri nommées ; il ne reçoit ni client réseau général,
ni accès libre au système de fichiers, ni shell.

Une **CSP** est la politique qui borne les sources de contenu exécutables par la
WebView. Celle de la Console refuse le code distant et toute navigation non
prévue. Les ressources du frontend sont incluses dans l'artefact signé et Tauri
ne démarre aucun serveur local pour les afficher.

Ce choix ajoute au build la chaîne Rust, Node, Tauri et les dépendances natives
de WebView : WebKitGTK sous Linux, outils MSVC et WebView2 sous Windows. Les
versions exactes sont verrouillées dans les manifestes de dépendances et les
images de runner ; aucun plugin Tauri n'est ajouté sans une opération native
requise par ce contrat. À l'exécution, la Console réutilise la WebView du système,
dont une vulnérabilité non corrigée reste un risque résiduel.

## Frontières d'autorité

- La Console est un client multi-Controller ; elle n'est l'autorité d'aucune
  infrastructure et ne possède aucun secret de machine, de Relay, de runner ou
  de chemin d'action.
- Un Controller porte l'autorité métier d'exactement une infrastructure. Il
  authentifie l'humain et l'appareil, autorise la consultation, conserve
  l'inventaire attendu et interprète les observations.
- Le Controller expose une API privée, jamais un frontend. Un Controller
  compromis ne peut donc pas fournir directement du code exécutable à la
  Console. Ses réponses restent néanmoins des données hostiles à valider et à
  rendre sans interprétation active.
- Le Relay authentifie, borne, persiste et accuse les observations. Il ne porte
  aucun utilisateur, rôle, inventaire métier, statut d'interface ou action.
- Le Controller initie la lecture du Relay sur une frontière distincte du
  listener d'ingestion des Daemons, ou sur une séparation équivalente prouvée.
- Une architecture ultérieure peut faire cohabiter Relay et Controller avec des
  processus, comptes, identités, stockages et politiques séparés, tout en
  partageant la zone de compromission `root`. `v0.0.3` ne revendique pas ce mode :
  son filtre lecteur exige deux IPv4 privées distinctes. La preuve place le
  Controller sur `lab-coordinateur` et le Relay sur `lab-machine-1`.

## Plateformes et distribution

`v0.0.3` produit une Console fonctionnelle sur Linux et Windows depuis le même
frontend responsive. Les artefacts proviennent des mêmes sources, sont bornés,
inventoriés et signés. Aucun téléchargement de code ou de composant d'interface
depuis un Controller n'est permis.

Le téléphone conserve le même contrat visuel et réseau, mais Android et iOS
restent hors de ce palier. Leur empaquetage, signature, stockage sécurisé, cycle
de vie en arrière-plan et distribution demanderont une preuve propre.

Tout build, test, serveur, lancement ou preuve de la Console et du Controller
s'exécute dans le LAB ou un runner isolé. Le laptop de développement reste
limité à Git, l'édition, aux contrôles statiques autorisés et au pilotage de
`labctl`.

La première distribution est fixée ainsi :

- Linux `x86_64` reçoit un paquet `.deb` ; Windows `x86_64` reçoit un
  installateur `.msi` dont l'exécutable et l'installateur portent une signature
  Authenticode SHA-256 horodatée ;
- un manifeste commun signé relie version, commit Git exact, cible, noms,
  tailles, SHA-256, empreinte du signataire, runner et versions des outils ; une
  SBOM inventorie les composants embarqués ;
- sous Linux, une signature OpenPGP Ed25519 détachée couvre le manifeste et
  `gpg --verify` doit réussir avec l'empreinte de clé attendue avant
  l'installation du paquet ;
- les deux runners partent du même commit et du même verrou frontend, puis
  produisent chacun l'artefact natif de sa plateforme ;
- les clés synthétiques du LAB prouvent le mécanisme, pas une identité publique
  déjà reconnue par les systèmes d'exploitation.

`v0.0.3` ne possède aucun service de mise à jour intégré. Une nouvelle version
est téléchargée, vérifiée puis installée manuellement comme un artefact complet ;
le retour utilise de la même manière un artefact antérieur encore vérifiable.
Ni un Controller ni son contenu ne peuvent fournir ou imposer une mise à jour.

## Authentification à trois niveaux

L'accès réseau privé, l'identité de l'appareil et l'identité humaine sont trois
contrôles distincts :

1. le réseau privé borne les endpoints joignables sans prouver l'identité
   humaine ;
2. la Console présente une identité d'appareil propre, révocable et distincte
   pour chaque association ;
3. le Controller vérifie une authentification humaine forte avant d'émettre une
   session courte liée à cet appareil et à cette infrastructure.

Une **session opaque** est un jeton aléatoire sans droit lisible côté client :
seul le Controller retrouve sa portée dans son état serveur et peut l'invalider.

Une **phrase secrète locale** est une phrase connue de l'humain qui déverrouille
la Console sans être envoyée au Controller. Linux et Windows emploient le même
profil : ni Windows Hello, ni passkey, ni clé FIDO2, ni SSO/OIDC n'est requis ou
implémenté dans la V1. Ces profils pourront être étudiés après la V1 sans entrer
dans le contrat actuel.

Le cœur Rust conserve, dans un coffre Tauri Stronghold chiffré et authentifié,
une paire de clés d'appareil mTLS et une paire de clés humaines distinctes pour
chaque association. Le Controller ne reçoit que la clé publique humaine. Après
déverrouillage, il émet un challenge de 32 octets aléatoires, valable deux
minutes et une seule fois ; le cœur Rust le signe avec la clé humaine de cette
association. Le Controller vérifie séparément cette signature et le certificat
d'appareil mTLS avant d'émettre une session.

Aucune capacité `stronghold:*` ni aucun binding JavaScript du plugin n'est
accordé au frontend. Le moteur Stronghold est appelé directement par Rust,
derrière les seules opérations métier nommées ; React ne peut ni lire un
enregistrement, ni demander une procédure de signature libre. Les clés humaines
Ed25519 sont utilisées par les procédures du coffre. La clé d'appareil P-256,
qui n'est pas une procédure native de Stronghold, reste chiffrée au repos puis
est déchiffrée uniquement dans un tampon natif borné qui déclenche son
écrasement après le CSR ou la signature TLS. Elle n'atteint ni JavaScript, ni un
fichier clair. Une copie transitoire en mémoire Rust reste néanmoins un risque
résiduel mesuré, pas une propriété d'enclave.

La phrase dérive la clé de 32 octets du coffre par Argon2id avec un sel aléatoire
de 16 octets propre à la Console. Le profil initial fixe `m=65536` Kio,
`t=3`, `p=1` ; le format versionné conserve ces paramètres pour permettre une
augmentation ultérieure sans rendre l'ancien coffre illisible. La phrase et la
clé dérivée ne sont jamais persistées. La session humaine reste dans la seule
mémoire native et disparaît à la fermeture ou au verrouillage de la Console.
Le cœur Rust applique lui-même ce profil Argon2id et refuse sel absent, recréé,
mal dimensionné ou paramètres divergents ; il n'emploie pas les valeurs par
défaut du helper Stronghold. Un changement de phrase écrit et valide un nouveau
snapshot séparé, le publie par remplacement atomique, puis seulement retire
l'ancien ; crash ou erreur avant la publication conservent l'ancien coffre.

Le frontend affiche le champ de phrase puis la transmet uniquement à l'opération
Tauri nommée `unlock_console`. Il efface aussitôt son champ et ne reçoit jamais
la clé dérivée, une clé privée, le contenu du coffre ou un jeton de session.
JavaScript ne garantissant pas l'effacement immédiat de ses chaînes en mémoire,
ce bref passage de la phrase constitue une limite explicite. La CSP, l'absence
de code distant et l'absence de client réseau général réduisent cette surface
sans la supprimer.

Stronghold fournit un moteur commun aux deux systèmes, mais ne constitue pas
une enclave matérielle. Le vol du coffre autorise des essais hors ligne contre
la phrase ; Argon2id les ralentit sans les rendre impossibles. Un processus qui
compromet la Console pendant qu'elle est déverrouillée peut viser toutes ses
associations. Les clés restent néanmoins distinctes et le cœur Rust refuse
qu'une opération visant un Controller utilise le compartiment d'un autre. Ces
risques résiduels restent visibles et aucune résistance globale au logiciel
malveillant ou conformité ANSSI/OWASP n'est revendiquée.

### Phrase de déverrouillage et code de récupération

La **phrase de déverrouillage** sert au quotidien à ouvrir le coffre local. La
Console la génère avec un générateur cryptographiquement sûr en tirant six mots
indépendants et uniformes dans la liste française de 2 048 mots de
[BIP-39](https://github.com/bitcoin/bips/blob/8c369ac8e60629ac6c032ffe21bb5ec5b35213d7/bip-0039/french.txt), soit
66 bits d'entropie avant le coût Argon2id. Cette liste est seulement un
catalogue de mots : aucune graine ou mécanique de portefeuille BIP-39 n'est
utilisée. La révision normative est
`8c369ac8e60629ac6c032ffe21bb5ec5b35213d7` et le fichier attendu porte le
SHA-256 `ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59`.
Il est intégré aux sources signées, sans téléchargement à l'exécution.

La **normalisation NFKD** donne aux mêmes caractères Unicode une représentation
stable sur Linux et Windows. La forme canonique emploie les mots minuscules normalisés en NFKD, un espace
ASCII entre deux mots et aucun espace en tête ou en fin. L'entrée brute est
refusée au-delà de 192 octets UTF-8 avant toute normalisation, puis la forme
canonique est bornée à 96 octets. L'opération Rust `unlock_console`, pas
React, normalise Unicode et les espaces avant de vérifier exactement six
entrées de la liste. L'utilisateur peut régénérer la phrase
avant de la confirmer, mais ne compose pas une phrase plus faible. Le changement
ultérieur exige le coffre déjà déverrouillé, crée un nouveau sel Argon2id et
remplace atomiquement le chiffrement du coffre ; il ne réutilise ni ne fait
tourner les clés des Controllers. Une erreur conserve l'ancien coffre intact.

Le **code de récupération global** est un second secret, réservé aux incidents
et distinct de cette phrase. La Console génère 256 bits aléatoires, les encode
en 52 caractères Base32 RFC 4648 majuscules sans remplissage, puis ajoute deux
caractères de contrôle issus des dix premiers bits de
`SHA-256("your-cloud/v0.0.3/recovery-check" || code_brut)`. L'utilisateur doit
voir neuf groupes de six caractères séparés par `-`, le ressaisir et en
conserver deux copies hors ligne ; ni la Console, ni
Stronghold, ni un Controller ne le sauvegardent. Le frontend voit
temporairement la phrase, les codes d'appairage ou de récupération nécessaires
à l'interface, les efface après l'opération et ne les place ni dans un stockage
Web, ni dans une URL, un journal ou le presse-papiers automatiquement. Cette
exposition JavaScript transitoire reste une limite explicite.

**HKDF-SHA-256** est une fonction qui dérive des clés indépendantes depuis un
secret déjà aléatoire ; elle ne remplace pas Argon2id pour une phrase humaine.
Pour un Controller donné, le cœur natif dérive depuis les 256 bits du code une
graine Ed25519 par HKDF-SHA-256. L'**époque** est un compteur persistant qui
rend les anciennes preuves définitivement caduques. Le sel public aléatoire de
32 octets sert au `HKDF-Extract` avec `IKM=code_brut[32]`. Le `HKDF-Expand`
produit exactement 32 octets passés comme graine, jamais comme scalaire,
à Ed25519. Son champ `info` est, dans cet ordre : les octets ASCII
`your-cloud/v0.0.3/recovery-signing`, `0x00`, l'époque en entier non signé de
64 bits big-endian, les 16 octets bruts de l'UUID `infrastructure_id`, puis
l'empreinte SPKI de 32 octets — le SHA-256 de la clé publique de l'autorité TLS
serveur épinglée. Des vecteurs de dérivation figés prouvent l'interopérabilité
Linux/Windows. Le Controller
ne conserve que ce sel, cette époque et la clé publique résultante. Le code et
la clé privée dérivée ne quittent jamais la Console et sont effacés de la
mémoire native après l'opération.

La clé publique de cette autorité TLS reste immuable pendant la V1 ; un
certificat serveur feuille peut tourner sous elle. Son remplacement exige une
réinitialisation locale explicite et un nouvel appairage, jamais une poursuite
automatique avec une autre SPKI.

### Autorité locale et appairage temporaire

L'**autorité locale du Controller** est l'opération de maintenance lancée sur
son propre hôte par le compte système autorisé. Elle peut ouvrir une fenêtre
d'appairage ou de récupération, révoquer l'appareil actif ou réinitialiser
explicitement l'association ; elle n'est ni une API distante, ni un canal vers
les machines ou le Relay. Ses actions sensibles sont journalisées sans secret.

Avant tout appairage, le Controller génère et persiste deux UUIDv4 canoniques
minuscules et immuables : `controller_id` identifie cette installation du
backend et `infrastructure_id` l'unique infrastructure qu'elle représente. Il
génère aussi son identité TLS serveur et une autorité de délivrance d'appareils
propre. Cette autorité cliente est distincte de l'autorité TLS serveur, de celles
des Daemons et du lecteur Relay décidé ci-dessous. Une réinitialisation locale
explicite remplace l'installation et ses deux identifiants ; aucun démarrage,
appairage, renouvellement ou redémarrage ne les régénère. Le premier
`PUT /v0/infrastructure` ne choisit donc plus l'identifiant : il confirme la
valeur réservée puis fixe le libellé métier une seule fois.

L'autorité locale ouvre volontairement, sur l'adresse privée exacte du
Controller, un listener TLS 1.3 temporaire `9444`. Aucun bind public ou
générique, proxy, redirection, CORS ou repli HTTP n'est permis. Le listener
présente une chaîne TLS validable par la même autorité serveur que `9443`, mais
n'exige pas encore de certificat client. Pour une fenêtre d'appairage comme de
récupération, une feuille affichée localement une seule fois contient son type,
les origines exactes `9443` et temporaire `9444`, `infrastructure_id`, le
certificat de l'autorité serveur et son empreinte SHA-256, un `window_id`
aléatoire de 128 bits et un `window_code` aléatoire de 128 bits. Le code est
encodé en 26 caractères Base32 et affiché en groupes `5-5-5-5-6`. La Console
épingle ces données avant son premier octet applicatif ; la confiance système
seule ne suffit pas.

Une fenêtre dure au plus dix minutes et n'accepte qu'une transaction. Elle se
ferme après le `PUT` réussi qui livre le certificat candidat, le cinquième échec
cryptographique présenté avec les bons `window_id` et `window_code`, une
expiration ou un redémarrage. Fermer signifie arrêter réellement le socket
`9444`. Un identifiant ou code de fenêtre invalide reçoit une erreur générique
et un débit maximal d'une tentative par seconde et cinq par minute pour la même
source ; il ne consomme ni la transaction ni le budget des cinq preuves. Une VM
qui connaît le code peut encore fermer volontairement la fenêtre : ce déni de
service borné reste un risque résiduel à tester.

Le Controller ne conserve qu'un condensat du code et ne journalise ni code, ni
challenge, ni signature, ni CSR. Une seule fenêtre d'appairage ou de
récupération et une seule transaction d'identité sont actives à la fois.
`v0.0.3` limite volontairement chaque Controller à un humain local et un
appareil Console actifs ; un second appareil passe par une récupération qui
remplace le premier, pas par une extension silencieuse du modèle.

Un **CSR PKCS#10** est une demande de certificat signée par la nouvelle clé
d'appareil ; sa signature prouve que la Console possède la clé privée sans la
transmettre. Un **certificat candidat** est déjà signé par le Controller mais ne
possède encore aucun droit métier : seule son activation bornée peut le rendre
actif.

Le listener temporaire expose exactement :

| Méthode et route `9444` | Effet autorisé |
|---|---|
| `POST /v0/enrollment/challenge` | vérifier `window_id`, `window_code` et un `request_id` Console de 128 bits, puis faire générer au Controller `transaction_id`, `device_id`, challenge de 32 octets, sel public de récupération et époque initiale |
| `PUT /v0/enrollment` | vérifier le CSR P-256 et les signatures du transcript par les nouvelles clés humaine et de récupération, puis rendre un certificat candidat sans encore donner de droit métier |
| `POST /v0/recovery/challenge` | vérifier les mêmes identifiants et code locaux, puis faire générer au Controller `transaction_id`, nouveau `device_id`, challenge, prochain sel et prochaine époque ; rendre aussi le sel et l'époque courants sans recevoir le code global |
| `PUT /v0/recovery` | vérifier le CSR et les signatures du même transcript par l'ancienne clé de récupération, la nouvelle clé humaine et la prochaine clé de récupération, puis préparer le remplacement candidat sans révoquer encore l'état actif |

Seules les deux routes correspondant au type de fenêtre existent. Le challenge
vaut deux minutes et une fois ; les dix minutes concernent la fenêtre, pas la
preuve cryptographique. La Console génère `request_id` ; le Controller génère
`transaction_id` et le nouvel UUIDv4 `device_id`, qu'il n'a jamais attribué,
même à une identité révoquée. Tant que la fenêtre reste ouverte, le même
`request_id` et le même contenu rendent la même transaction ; un contenu
différent reçoit `409`.

Le transcript signé est binaire, versionné, à champs ordonnés et à longueurs
fixes ou préfixées. Il contient au minimum : domaine et version de l'opération,
type de fenêtre, origine `9444`, méthode et route exactes, `window_id`,
`request_id`, `transaction_id`, identité du Controller, `infrastructure_id`,
`device_id`, challenge, création et expiration, sels et époques courant et
suivant selon l'opération, SHA-256 du CSR DER complet, clé humaine Ed25519 et
clés de récupération courante et suivante applicables. Le JSON brut n'est
jamais signé. La vérification complète du PKCS#10 prouve séparément la possession
de la clé P-256.

Les nouvelles clés restent dans un compartiment Stronghold provisoire. Le
certificat candidat n'autorise sur `9443` que
`PUT /v0/enrollment/{transaction_id}/activation` ou
`PUT /v0/recovery/{transaction_id}/activation`. L'activation prouve la
possession du candidat puis publie en une transaction durable l'appareil, la clé
humaine, la clé de récupération, l'époque et la révision d'identité. Seule la
réussite durable de cette route d'activation modifie l'autorité active. Une
récupération révoque dans ce même commit tous les anciens appareils, clés
humaines, sessions, challenges et rotations. Si la réponse d'activation se
perd, le nouveau certificat fonctionne déjà et le même appel est rejouable à
l'aide du reçu durable borné décrit plus bas. Sans activation dans
les dix minutes, le candidat expire et l'ancien état reste intact ; un premier
appairage inachevé ne crée aucune autorité partielle. Si la réponse qui livre le
candidat se perd, le listener est déjà fermé : le candidat expire et l'autorité
locale ouvre une nouvelle fenêtre. Cette reprise est moins confortable, mais ne
révoque aucun état actif et n'autorise pas un listener permanent.

### Certificat d'appareil, rotation et révocation

La clé d'appareil est P-256, chiffrée au repos dans Stronghold et exposée
seulement au tampon Rust borné décrit plus haut. Son certificat client emploie
ECDSA avec SHA-256, un numéro de série aléatoire de 128 bits,
`basicConstraints=CA:false`, `keyUsage=digitalSignature` et
`extendedKeyUsage=clientAuth` critiques. Son SAN URI est exactement
`urn:your-cloud:v0.0.3:infrastructure:<infrastructure_id>:device:<device_id>`, où
`device_id` est un UUIDv4 aléatoire. Le certificat vaut 180 jours ; la Console
avertit à J-30 puis J-7, mais aucun renouvellement automatique n'entre dans ce
palier.

La rotation manuelle utilise deux phases pour qu'une réponse réseau perdue ne
verrouille jamais la Console :

1. sous l'ancien mTLS, avec session valide et preuve humaine fraîche liée au
   nouveau CSR, `PUT /v0/device-rotations/{rotation_id}` persiste et rend de
   manière idempotente un certificat candidat ; l'ancien reste seul actif ;
2. le candidat ne peut appeler que
   `PUT /v0/device-rotations/{rotation_id}/activation`. Ce commit rend le
   candidat actif, révoque l'ancien et toutes ses sessions, puis permet le rejeu
   de l'activation avec le nouveau certificat.

Un candidat non activé expire après dix minutes et n'obtient jamais une route
métier. L'autorité locale peut révoquer immédiatement l'appareil actif ; elle
invalide ses sessions, challenges et rotations. Le Controller consulte l'état
`candidate`, `active` ou `revoked` à chaque requête HTTP, y compris sur une
connexion TLS réutilisée : une validation faite seulement à la poignée de main
mTLS ne suffit pas. Un certificat expiré ou révoqué ne peut être renouvelé ; la
récupération ou un nouvel appairage local explicite est alors nécessaire.

Le Controller conserve au plus 32 **reçus d'idempotence** pendant 24 heures.
Un reçu durable contient seulement l'identifiant d'opération, le SHA-256 de la
requête validée, le résultat, la révision d'identité ou l'époque obtenue et
l'empreinte du certificat public concerné, jamais clé, code, signature brute ou
jeton. Un rejeu avec le même identifiant et le même condensat retrouve d'abord
le candidat persistant ou le reçu déjà commis ; un contenu différent reçoit
`409`. Une activation déjà commise peut ainsi être réaffirmée avec le nouveau
certificat, y compris après redémarrage. Pour `PUT /v0/recovery-key`, un appareil
et une session actuellement valides peuvent relire le reçu exact avant que
l'ancienne preuve de récupération soit revérifiée. Une fois 24 heures écoulées,
l'état actif reste autoritaire mais aucune réponse de rejeu historique n'est
promise.

### Preuve humaine et session

Sur l'origine principale `9443`, les routes d'authentification sont limitées à :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/session/challenge` | sous mTLS actif, émettre un challenge de 32 octets pour l'une des finalités fermées `open_session`, `rotate_device` ou `rotate_recovery_key` ; les deux dernières exigent déjà une session valide |
| `POST /v0/session` | vérifier la signature Ed25519 liée à l'appareil, au Controller et à l'infrastructure, invalider l'ancienne session de cet appareil et rendre une nouvelle session opaque |
| `DELETE /v0/session` | invalider immédiatement et de manière idempotente la session courante |
| `PUT /v0/recovery-key` | avec mTLS, session, preuve humaine fraîche, preuve de l'ancienne clé de récupération et possession de la nouvelle, remplacer la clé publique de récupération de ce seul Controller |

Les routes d'activation et de rotation décrites plus haut complètent cette
surface. `DELETE /v0/session` est l'unique `DELETE` d'authentification ; aucune
suppression métier n'est ajoutée. Un challenge vaut deux minutes, une fois et
une seule finalité. Il est lié à l'empreinte du certificat, à la clé humaine, à
`infrastructure_id`, au Controller, à la méthode, à la route et au SHA-256 du
corps visé. Une seule valeur active existe par appareil et finalité.
Une demande strictement identique rend le challenge déjà actif ; une demande
différente pour la même finalité reçoit `409` jusqu'à consommation ou
expiration. Un appareil ne crée pas plus de cinq challenges par minute.

La session est un jeton aléatoire de 32 octets rendu une fois en Base64url sans
remplissage dans `Authorization: Bearer`. Le Controller n'en conserve que le
SHA-256 et le lie à la clé humaine, au `device_id`, à l'empreinte et au numéro de
série du certificat, au Controller, à `infrastructure_id` et à la révision
d'identité. Une seule session existe par appareil et Controller ; une nouvelle
authentification détruit l'ancienne. Aucun refresh token n'existe. Le délai
d'inactivité est de 30 minutes et la durée absolue de huit heures, tous deux
imposés côté serveur. Seule une requête authentifiée acceptée prolonge
l'inactivité ; un refus ne la prolonge jamais.

Si la réponse qui contient un nouveau jeton se perd, la Console demande un
nouveau challenge et crée une autre session ; ce succès invalide le jeton perdu.
Le Controller n'a donc pas à conserver le jeton en clair pour rendre une réponse
identique.

La fermeture ou le verrouillage de la Console efface le jeton natif. Logout,
expiration, révocation, rotation, récupération ou redémarrage du Controller
l'invalident côté serveur. Sessions, challenges, fenêtres et candidats emploient
des échéances monotones ; un redémarrage les invalide et conserve uniquement
l'état actif durable. Les cinq signatures humaines invalides successives dans
dix minutes pour le même appareil et Controller imposent respectivement 1, 2,
4, 8 puis 16 secondes de délai ; le cinquième échec ouvre ensuite un blocage de
cinq minutes sans verrouillage permanent.
Les erreurs restent génériques et les journaux ne contiennent aucun jeton ou
matériel d'authentification.

### Récupération et incident sur le code global

Une récupération exige simultanément l'ouverture locale de `9444`, les bons
`window_id` et `window_code`, le certificat serveur épinglé et une signature
valide dérivée du code global. Le code seul n'ouvre donc aucun endpoint
permanent. La preuve couvre le transcript complet décrit plus haut. Le
`PUT /v0/recovery` ne prépare qu'un candidat ; seule son activation durable sur
`9443` révoque l'ancien état, active le nouveau certificat, incrémente l'époque
et change le sel et la clé publique de récupération. Une preuve de l'ancienne
époque ne redevient jamais valide. La récupération ne
sauvegarde ni inventaire ni observation : ces données restent dans le
Controller.

Si la phrase locale est oubliée, l'utilisateur crée un nouveau coffre et une
nouvelle phrase, puis récupère chaque association avec le code global. Si le
code global est perdu lui aussi, aucune récupération distante n'est promise :
l'autorité locale de chaque Controller doit réinitialiser explicitement son
unique association avant un nouvel appairage.

Si le code global est connu ou soupçonné compromis, la Console génère un
nouveau code et exige la confirmation de ses deux copies hors ligne avant le
premier commit. L'utilisateur garde l'ancien et le nouveau code hors ligne
jusqu'au dernier Controller. La Console exécute ensuite
`PUT /v0/recovery-key` séparément sur chaque association. Le corps versionné
porte un identifiant de transaction, l'époque suivante, un nouveau sel, la
nouvelle clé publique dérivée et les signatures humaine, de l'ancienne clé de
récupération et de la nouvelle clé prouvant sa possession.

Chaque commit incrémente seulement l'époque de récupération de ce Controller et
n'invalide pas la session ou l'appareil courants. Le reçu rend un rejeu
strictement identique observable sans seconde mutation ; un contenu différent
reçoit `409`. L'ancienne clé devient invalide dès ce commit. La Console persiste
uniquement l'identifiant et l'état de chaque Controller, l'époque cible et le
SHA-256 domainé du nouveau code, jamais les codes eux-mêmes. Après fermeture ou
crash, l'utilisateur ressaisit les deux codes ; la Console reprend les reçus
déjà commis et les associations encore à traiter. L'interface liste les
Controllers terminés, en échec et en attente et n'annonce jamais une rotation
globale tant qu'une association manque. Le code reste donc global pour
l'utilisateur, mais son impact et sa rotation sont explicitement suivis
Controller par Controller.

### Bornes et risques résiduels de l'authentification

Les identifiants d'infrastructure et d'appareil sont des UUIDv4 canoniques
minuscules. `window_id`, `request_id`, `transaction_id` et `rotation_id`
contiennent 16 octets aléatoires en Base64url sans remplissage ; challenges,
sessions et sels en
contiennent 32 ; clés Ed25519 et signatures ont exactement 32 et 64 octets. Un
CSR PKCS#10 DER encodé en Base64url est limité à 2 Kio. Les requêtes
d'authentification restent sous la borne générale de 4 Kio ; sur `9444`, une
réponse est limitée à 8 Kio, une erreur à 1 Kio, une seule requête est traitée
à la fois et les délais restent trois secondes pour la connexion et dix pour la
requête complète. Champs inconnus ou dupliqués, mauvaise casse d'un nom de
champ, algorithme ou valeur d'énumération, point P-256, CSR, usage X.509,
encodage, longueur ou époque sont refusés avant toute mutation.

Le parseur Rust refuse avant décodage plus de 64 octets bruts pour un
`window_code` et 80 pour le code global. Il accepte soit les caractères Base32
contigus, soit exactement les groupes `5-5-5-5-6` ou `6-6-6-6-6-6-6-6-6`
attendus ; les minuscules ASCII sont converties en majuscules, mais aucun autre
espace, séparateur, remplissage ou caractère Unicode n'est accepté. Après
décodage, il réencode et compare la forme canonique, exige les bits inutilisés à
zéro et vérifie les deux caractères de contrôle du code global.

Le code global crée volontairement un secret commun de récupération ; sa fuite
augmente le rayon d'incident même si les clés dérivées sont séparées et si une
fenêtre ouverte par l'autorité locale reste nécessaire. La durée de 180 jours laisse aussi une fenêtre
résiduelle entre compromission et révocation. La compromission du Controller ou
de son autorité de délivrance permet de fabriquer des identités, et celle d'une
Console déverrouillée vise les clés actives. La V1 prouve des contrôles bornés
contre ces scénarios. L'application ne peut pas exclure une capture par le
système d'exploitation, une méthode de saisie, une API d'accessibilité ou les
copies mémoire transitoires de l'IPC lorsque la phrase ou un code est affiché.
Elle ne revendique ni enclave matérielle, ni second facteur indépendant, ni
conformité globale.

Ce choix s'appuie sur l'analyse de risque et l'adaptation de la robustesse des
phrases au contexte décrites par le
[guide d'authentification de l'ANSSI](https://messervices.cyber.gouv.fr/guides/recommandations-relatives-lauthentification-multifacteur-et-aux-mots-de-passe),
sur les paramètres Argon2id de la
[fiche Password Storage OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
et sur le chiffrement authentifié et la dérivation d'une clé d'enveloppe depuis
une phrase de la
[fiche Cryptographic Storage OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
Le [plugin Stronghold officiel de Tauri](https://v2.tauri.app/plugin/stronghold/)
fournit le moteur de coffre commun à Linux et Windows ; le profil Argon2id exact
reste appliqué et validé par le cœur Rust. Les sessions
opaques, leurs expirations côté serveur et leur invalidation suivent la
[fiche Session Management OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) ;
les délais progressifs et la preuve fraîche des opérations sensibles suivent la
[fiche Authentication OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
La génération, l'usage unique et l'expiration des codes temporaires en ligne
d'appairage, de fenêtre et de challenge s'appuient sur la
[fiche Forgot Password OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html),
tandis que le code global hors ligne reste réutilisable jusqu'à rotation. La
séparation, la rotation et le plan de compromission des clés s'appuient sur la
[fiche Key Management OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
et les
[essentiels IGC de l'ANSSI](https://cyber.gouv.fr/sites/default/files/document/anssi_essentiels_igc_1.0.pdf).
Ces sources justifient les contrôles ; les six mots, les durées, les ports et la
surface de routes restent des choix de risque propres à `v0.0.3`.

## API Console–Controller décidée

Une **origine HTTPS** est le triplet exact protocole, nom et port. Chaque
association de la Console approuve une origine distincte de la forme
`https://controller.<infrastructure-id>.v0-0-3.your-cloud.test:9443` dans le
LAB. L'enveloppe Tauri, jamais le frontend, émet les requêtes REST JSON sur TLS
1.3. Elle refuse HTTP, utilisateur dans l'URL, autre hôte ou port, query,
fragment, redirection, proxy implicite et repli vers une autre origine.

Le certificat serveur est validé contre l'autorité enregistrée pour cette
association. L'identité d'appareil est présentée par mTLS et la session humaine
opaque est ajoutée par l'enveloppe. Sa création, ses routes, ses durées, ses
liaisons et sa révocation sont fixées ci-dessus ; son stockage reste limité à la
mémoire native.
Chaque requête métier exige simultanément l'appareil, l'humain et
l'infrastructure attendus ; la seule présence sur le réseau ne donne aucun
accès.

Le Controller porte un `infrastructure_id` unique et immuable. Aucune requête ne
peut sélectionner une autre infrastructure. Une machine ne rejoint son
inventaire que si le `GET /v0/snapshot` frais du Relay authentifié confirme que
son enrôlement actif appartient à ce même `infrastructure_id`. Le cache ne
suffit jamais à autoriser cette écriture.

Les routes métier sont limitées à :

| Méthode et route | Effet autorisé |
|---|---|
| `PUT /v0/infrastructure` | confirmer une seule fois l'identifiant réservé par l'autorité locale et fixer le libellé du Controller |
| `GET /v0/infrastructure` | lire l'identité et le libellé de son unique infrastructure |
| `GET /v0/machines` | lire l'instantané borné des machines attendues |
| `PUT /v0/machines/{machine_id}` | rattacher une machine déjà enrôlée dans cette infrastructure ou remplacer son libellé de manière idempotente |

Aucun `DELETE` métier, filtre libre, recherche, historique ou canal d'action
n'est exposé. L'unique `DELETE` invalide la session courante ; les routes
d'appairage, de preuve humaine, de session, de rotation et de récupération
fixées par le paramètre 4 ne changent pas cette API métier.

Le premier `PUT /v0/infrastructure` authentifié confirme l'identité réservée et
fixe son libellé. Un rejeu avec la même identité et le même libellé réussit sans
mutation ; toute autre identité ou tentative de substitution reçoit `409`. Les
deux `PUT` métier du tableau modifient uniquement l'état métier local du
Controller : ils ne changent ni le registre du Relay, ni
son instantané, ni une machine. Le rattachement d'une machine force une lecture
Relay valide pendant cette requête ; l'indisponibilité, une horloge non fiable
ou une réponse invalide reçoit `503` sans utiliser le dernier cache.

Les requêtes utilisent un objet JSON UTF-8 unique. Les noms non canoniques,
champs inconnus ou dupliqués, seconde valeur, mauvais `Content-Type` ou
`Accept` sont refusés. Le corps entrant est limité à 4 Kio, une réponse à
128 Kio et une erreur à 1 Kio. L'inventaire contient au plus 64 machines. Le
profil exact des libellés, leur normalisation et leur comptage sont fixés dans
la section de stockage et de projection ci-dessous. La connexion expire après
3 secondes, la requête complète après 10 secondes et un appareil ne possède pas
plus de quatre requêtes simultanées. Toute réponse porte
`Cache-Control: no-store`.

Une erreur contient exactement `schema_version`, un `error_code` de la liste
positive suivante et un `request_id` aléatoire de 16 octets encodé en 22
caractères Base64url sans remplissage. Elle ne contient jamais cause interne,
corps reçu, libellé hostile ou donnée Relay libre. Seul `429` ajoute
`Retry-After`, entier décimal de 1 à 300 secondes. Les échecs TLS n'obtiennent
aucune réponse HTTP.

| Statut | `error_code` autorisé | Condition publique |
|---|---|---|
| `400` | `invalid_request` | syntaxe, champ ou enveloppe invalide |
| `401` | `authentication_failed` | session, preuve ou fenêtre absente, invalide ou expirée, sans distinguer la cause cryptographique |
| `403` | `scope_forbidden` | appareil, candidat, Controller, infrastructure ou finalité sans portée |
| `404` | `route_not_found`, `resource_not_found` | route absente ou ressource authentifiée absente |
| `405` | `method_not_allowed` | méthode absente de la surface fermée |
| `406` | `not_acceptable` | valeur `Accept` incorrecte |
| `409` | `state_conflict` | initialisation, révision, transaction ou opération contradictoire |
| `413` | `request_too_large` | corps ou en-têtes au-delà de leur borne |
| `415` | `unsupported_media_type` | `Content-Type` incorrect ou interdit |
| `422` | `machine_not_active`, `label_invalid` | machine non enrôlée active ou libellé refusé |
| `429` | `rate_limited` | concurrence ou débit dépassé |
| `503` | `controller_state_unavailable`, `relay_unavailable`, `projection_unavailable` | autorité locale inutilisable, lecture Relay requise impossible ou réponse sûre impossible |

Tout autre statut, code, champ ou combinaison statut/code rend la réponse
entière hostile et provoque un échec local générique. La Console utilise le
contexte de la route pour son libellé utilisateur, jamais un texte fourni par le
serveur. Sur `401`, elle efface seulement la session native de l'association
visée ; sur `403`, elle ne tente ni autre compartiment, ni autre endpoint.

Les actifs protégés sont les observations, l'inventaire, les associations de
Controllers, les identités d'appareil et les sessions humaines. Les menaces
traitées sont la substitution de Controller, le rejeu ou le vol de session, la
confusion entre infrastructures, l'entrée hostile ou surdimensionnée, le déni
de service borné et la transformation d'une donnée en code. REST JSON a été
retenu contre gRPC, qui ajouterait une chaîne native inutile pour quatre routes,
et GraphQL, qui introduirait une surface de requête libre. Une session opaque a
été retenue contre un JWT autonome afin que le Controller conserve une
révocation locale immédiate.

Cette conception applique le moindre privilège, la séparation des autorités et
la validation locale par endpoint décrits par la
[fiche REST OWASP](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html),
ainsi que l'authentification explicite du serveur recommandée par le
[guide TLS de l'ANSSI](https://cyber.gouv.fr/sites/default/files/2017/07/anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf).
Ces références soutiennent les contrôles ; elles ne constituent aucune
revendication de conformité globale.

Un Controller compromis peut toujours mentir dans les données et libellés qu'il
rend. La Console les traite donc comme hostiles, sans HTML actif ni code reçu.
La preuve devra en plus attaquer l'API depuis une VM distincte placée sur le même
réseau LAB : aucun certificat, certificat inconnu, révoqué ou d'un autre
Controller, session ou infrastructure croisée, machine de l'autre
infrastructure, méthode, route, schéma et taille invalides. Après chaque refus,
l'API nominale et l'inventaire inchangé sont réaffirmés.

## API Controller–Relay décidée

Un **listener privé** est un socket lié à l'adresse privée exacte d'un hôte ; ce
n'est pas `localhost`. Une machine possédant une route vers cette adresse peut
donc détecter le port tant qu'un filtre réseau ne l'arrête pas. Un
**instantané** est une vue cohérente et bornée du dernier état connu ; il ne
contient ni journal exhaustif, ni série temporelle.

### Frontière réseau et identités

Le Relay conserve son listener d'ingestion Daemon sur `8443` et ouvre un second
listener strictement lecteur sur son adresse privée exacte et `8444`. Son
origine approuvée est
`https://relay-reader.<infrastructure-id>.v0-0-3.your-cloud.test:8444`, avec
l'UUID canonique minuscule de l'infrastructure comme label DNS. Aucun bind
public, wildcard, IPv6 implicite, HTTP, port implicite, autre nom, DNS dynamique,
proxy, redirection, CORS ou repli n'est admis. Le Controller ouvre TCP vers
l'IPv4 privée provisionnée tout en présentant le nom TLS et `Host` exacts. Pour
ce palier, Controller et Relay possèdent deux IPv4 privées distinctes ; aucun
mode loopback ou cohabité alternatif n'est implémenté.

Sur l'hôte Linux Relay, le filtre d'entrée applique à `8444` un refus par
défaut. Seuls l'interface privée et l'IP source privée exacte du Controller,
toutes deux provisionnées localement, reçoivent une règle d'acceptation ; aucune
interface publique, autre sous-réseau ou autre source n'en possède. Les paquets
non autorisés sont supprimés par `drop`, sans réponse TCP ni ICMP. Le listener
borne séparément, avant TLS, les nouvelles connexions de la source autorisée.
Un scan depuis l'extérieur ou une VM voisine voit donc le flux filtré. Depuis
la source autorisée, le port est visible, mais la connexion reste sans droit
tant que le contrôle cryptographique suivant n'a pas réussi. `drop` ne prétend
pas cacher l'hôte : un scanner peut conclure que le flux est filtré. Il évite
seulement une réponse à une source sans droit ; le diagnostic repose sur des
compteurs et journaux locaux agrégés et limités en débit. La preuve inspecte la
politique `nftables`, ces compteurs et les paquets ; le Controller ne la modifie
jamais à l'exécution. La politique root-owned est chargée avant le listener ;
le compte Relay ne reçoit ni `CAP_NET_ADMIN`, ni gestion générale du pare-feu.

Le registre d'enrôlement Daemon de `v0.0.2` ne porte pas encore
`infrastructure_id`. Avant d'ouvrir le lecteur, `v0.0.3` exige donc une migration
locale explicite vers son schéma 2. L'autorité locale du Controller est la
source des deux UUID publics : le registre root-owned importe exactement
`infrastructure_id` et le manifeste lecteur importe les deux valeurs par le
provisionnement explicite, sans les générer ni les déduire. Le schéma 2 contient
exactement `schema: 2`, `infrastructure_id` et `machines`, conserve la borne de
16 Kio et autorise de zéro à 64 entrées. Chaque entrée conserve exactement les
quatre champs du schéma 1 : `machine_id`, `certificate_serial`,
`certificate_sha256` et `status`, avec les mêmes formes canoniques et seulement
`active` ou `revoked`. La migration d'un schéma 1 reprend sans les inventer ses
1 à 64 entrées existantes ; tout candidat de 65 entrées ou plus est refusé avant
publication. Le candidat complet est validé puis publié atomiquement ; un
schéma 1, une migration partielle ou un identifiant contradictoire laisse
l'ancien registre et le listener `8443` intacts, mais interdit l'ouverture de
`8444`. Aucune association à une infrastructure n'est inférée du nom d'hôte ou
du réseau.

Dans ce palier, l'ensemble des `machine_id` du schéma 2 peut seulement croître
jusqu'à 64 : une entrée n'est jamais supprimée ni réutilisée et une sortie de
service passe par `status: revoked`. Cette règle garde aussi le stockage durable
d'observations sous la même borne au fil des rechargements. Un candidat qui
omet un identifiant déjà publié, réactive une entrée révoquée ou introduit un
65e identifiant est refusé avant toute mutation. Au démarrage, l'absence de
schéma 2 valide garde `8444` fermé. Lors d'un rechargement après une publication
valide, un candidat invalide conserve l'ancien registre et l'ancien lecteur
actifs et signale l'échec ; il ne remplace ni ne tronque rien.

Le listener `8444` accepte uniquement TLS 1.3 avec authentification mutuelle et
HTTP/1.1 annoncé par ALPN ; HTTP/2 et la compression sont désactivés pour garder
concurrence, en-têtes et corps dans une seule enveloppe contractée.
Deux autorités X.509 Ed25519 nouvelles, distinctes de l'ingestion et propres à
chaque infrastructure, sont provisionnées hors réseau :

- l'autorité serveur `relay-reader` signe seulement une feuille `serverAuth`
  avec un unique SAN pour le nom DNS exact ci-dessus ;
- l'autorité cliente `controller-reader` signe seulement une feuille
  `clientAuth` avec un unique SAN portant exactement l'URI
  `urn:your-cloud:controller-reader:<infrastructure-id>:<controller-id>` ;
- chaque feuille est `CA:false`, possède seulement `digitalSignature`, un
  numéro de série aléatoire de 128 bits et une validité de 180 jours ;
- les clés privées d'autorité ne résident ni sur le Relay ni sur le Controller.

Le Relay charge un manifeste root-owned de 1 octet à 4 Kio associant l'unique
`controller_id` UUIDv4 attendu, `infrastructure_id`, URI, numéro de série,
empreinte SHA-256 et état `active` ou `revoked`. Les deux identifiants sont ceux
générés et persistés par l'autorité locale du Controller. Chaîne, période, nom,
usage, identité, empreinte et état sont revérifiés à chaque requête, y compris
sur une connexion TLS réutilisée. Une feuille signée par la bonne autorité mais
absente du manifeste reste inconnue. Le Controller valide de son côté
l'autorité, le nom et l'usage serveur, puis recoupe les deux identifiants rendus
dans la réponse. Le même
`infrastructure_id` doit apparaître dans le registre Daemon schéma 2, le
manifeste lecteur, l'identité cliente, le nom serveur, la configuration du
Controller et la réponse ; toute divergence ferme la lecture.
Un rechargement de manifeste invalide garde l'ancienne politique valide et
signale l'échec ; une révocation n'est annoncée effective qu'après publication
et rechargement réussis.

Le renouvellement automatique reste exclu. Les échéances sont signalées à
J-30 et J-7. Pour tourner l'identité cliente, l'autorité locale ferme d'abord
`8444`, prépare et valide le nouveau bundle feuille-clé sur le Controller et le
nouveau manifeste sur le Relay, puis publie atomiquement chaque bundle sur son
propre hôte. Il n'existe pas de transaction atomique entre les deux machines :
la frontière reste fermée jusqu'au recoupement réussi de l'URI, de la série, de
l'empreinte, de `controller_id` et de `infrastructure_id`. En cas d'échec, elle
reste fermée ; les anciens bundles locaux ne sont restaurés qu'avant un nouveau
recoupement complet. Deux certificats clients lecteurs ne sont jamais acceptés
ensemble. La feuille serveur suit la même procédure avec son bundle local au
Relay. Un changement d'autorité exige un nouveau provisionnement explicite.

### Route, instantané et bornes

Le Controller initie toujours la lecture. Le Relay expose sur `8444` une seule
route :

| Méthode et route | Réponse autorisée |
|---|---|
| `GET /v0/snapshot` | dernier état borné des machines enrôlées dans l'unique infrastructure du lecteur |

Le `GET` n'accepte aucun corps, `Content-Type`, `Transfer-Encoding`, en-tête
`Authorization`, query — même vide —, fragment, filtre ou pagination. `Accept`
vaut exactement `application/json`. `HEAD`,
`POST`, `PUT`, `PATCH`, `DELETE`, toute autre route et toute tentative sur
`8443` sont refusés. La lecture ne change ni le registre, ni le stockage
d'observation, ni une machine et ne produit aucun accusé vers un Daemon.

Une réponse `200` possède exactement cette structure. L'exemple montre toutes
les branches de données ; l'ordre des membres d'un objet JSON n'est pas
significatif, contrairement à l'ordre croissant du tableau `machines` et des
lacunes :

```json
{
  "schema_version": 1,
  "infrastructure_id": "11111111-1111-4111-8111-111111111111",
  "controller_id": "22222222-2222-4222-8222-222222222222",
  "snapshot_at": "2026-07-19T12:00:00Z",
  "machines": [
    {
      "machine_id": "lab-machine-1",
      "enrollment_status": "active",
      "observation": {
        "schema_version": 1,
        "machine_id": "lab-machine-1",
        "daemon_version": "v0.0.2",
        "profile": "host-health.v1",
        "sequence": 31,
        "observed_at": "2026-07-19T11:59:58Z",
        "received_at": "2026-07-19T11:59:59Z",
        "gaps": [
          {
            "first_sequence": 15,
            "last_sequence": 30,
            "dropped_count": 16,
            "first_observed_at": "2026-07-19T11:51:58Z",
            "last_observed_at": "2026-07-19T11:59:28Z"
          }
        ],
        "health": {
          "uptime": {"status": "ok", "uptime_seconds": 86400},
          "memory": {
            "status": "ok",
            "total_bytes": 4294967296,
            "available_bytes": 2147483648
          },
          "rootfs": {"status": "error", "error": "source_unavailable"}
        }
      }
    }
  ]
}
```

Les objets sont à liste positive : aucun membre inconnu ou dupliqué n'est
admis. `schema_version` vaut l'entier `1`. Les deux identifiants sont des UUIDv4
canoniques minuscules. `machine_id` respecte
`^[a-z0-9][a-z0-9-]{2,62}$`, et ses valeurs intérieure et extérieure sont
identiques. `enrollment_status` vaut seulement `active` ou `revoked`.
`sequence` est un entier non signé strictement positif sur 64 bits. Toutes les
dates sont les formes UTC `Z` canoniques de RFC 3339 à précision nanoseconde ;
les fractions inutiles sont omises. Le Relay parse puis réencode donc les dates
durables de `v0.0.2` au lieu de recopier leurs octets historiques.

`gaps` est toujours présent, même vide. Chaque lacune reprend exactement les
cinq champs de `host-health.v1` : deux séquences positives formant un intervalle
ordonné antérieur à `sequence`, `dropped_count` égal à
`last_sequence - first_sequence + 1`, puis deux dates ordonnées. Les intervalles
sont croissants, disjoints et non adjacents après leur fusion durable. Tout
l'instantané contient au plus 8 192 lacunes ; au-delà, il devient indisponible
sans troncature.

Chaque collecteur de `health` suit exactement l'une des deux formes suivantes :

- `uptime` vaut soit `{"status":"ok","uptime_seconds":<uint64>}`, soit
  `{"status":"error","error":"source_unavailable"}` ou la même forme avec
  `source_invalid` ;
- `memory` et `rootfs` valent soit
  `{"status":"ok","total_bytes":<uint64>,"available_bytes":<uint64>}` avec
  `available_bytes <= total_bytes`, soit l'une des deux formes d'erreur
  précédentes sans valeur numérique.

Une machine sans état durable porte exactement `"observation": null`. Un
registre schéma 2 sans enrôlement produit exactement `"machines": []` : ce cas
est l'instantané vide. Il reste distinct d'une machine enrôlée mais jamais
observée, et distinct d'un échec de lecture.

La réponse est construite à partir du registre d'enrôlement courant, jamais en
énumérant seul le stockage d'observations qui conserve encore le dernier état
d'une machine révoquée. Le Relay prend sous un verrou logique unique une copie
profonde du registre et de tous les derniers états, puis capture `snapshot_at`
dans cette même opération. Il trie et encode la copie après libération du verrou
et vérifie la réponse complète avant d'émettre le statut ou le premier octet.
Un rechargement de registre et une ingestion ne peuvent donc pas produire une
vue composée de plusieurs instants.

La réponse est un objet JSON UTF-8 strict avec `schema_version: 1`, les
`infrastructure_id` et `controller_id` authentifiés, `snapshot_at` et un tableau
`machines` trié par `machine_id`, de zéro à 64 éléments. Aucun certificat,
secret, historique ou champ libre n'est rendu. Seul un enrôlement `active` peut
confirmer un rattachement métier. Une machine active jamais observée reste donc
visible avec `observation: null` ; seul le tableau sans élément est appelé
instantané vide.

Une erreur HTTP après TLS contient exactement un objet de 1 Kio au plus de la
forme
`{"schema_version":1,"error_code":"<code>","request_id":"<22 base64url>"}`.
Le Relay génère les 16 octets aléatoires de `request_id`, les encode en
Base64url sans remplissage et ne reprend aucune entrée du pair. La liste fermée
est :

| Statut | `error_code` | Condition rendue |
|---|---|---|
| `400` | `invalid_request` | query, `Authorization`, `Transfer-Encoding` ou syntaxe interdite |
| `403` | `reader_forbidden` | manifeste révoqué ou contradictoire sur une connexion TLS déjà établie |
| `404` | `route_not_found` | route différente |
| `405` | `method_not_allowed` | méthode différente ; `Allow: GET` |
| `406` | `not_acceptable` | `Accept` absent ou différent |
| `413` | `request_too_large` | corps non vide ; sa borne autorisée vaut zéro |
| `415` | `unsupported_media_type` | `Content-Type` présent |
| `421` | `origin_mismatch` | `Host` différent du nom et port exacts |
| `429` | `rate_limited` | concurrence ou débit applicatif dépassé |
| `431` | `headers_too_large` | en-têtes hors borne |
| `503` | `snapshot_unavailable` | registre, état ou encodage indisponible ou instantané supérieur à la borne |

Un échec avant HTTP — filtre, limite de nouvelles connexions, chaîne TLS, nom,
usage ou identité inconnue — ne reçoit aucun de ces documents. Toute erreur
HTTP ferme la connexion et porte seulement `Content-Type: application/json`,
un `Content-Length` exact et `Cache-Control: no-store`, plus `Allow` pour le
seul `405`.

Le Relay limite les en-têtes de requête et le Controller les en-têtes de
réponse à 8 Kio avant traitement. Le Relay pré-encode l'instantané entier et
refuse une représentation supérieure à 2 Mio avant d'émettre le statut ou le
premier octet. Le Controller refuse immédiatement un `Content-Length` supérieur
à 2 Mio et applique une lecture bornée à 2 Mio plus un octet lorsque l'en-tête
manque ou ment ; une réponse hors borne ne remplace jamais son cache. Le Relay
produit et le Controller lit une erreur de 1 Kio au plus.

Sur `8444`, la connexion TCP et la négociation TLS expirent après 3 secondes et
la transaction complète après 6 secondes. Le listener possède au plus quatre
sockets TCP ou TLS simultanés, compte au plus douze nouvelles connexions dans
toute fenêtre glissante de 60 secondes avant même l'authentification, puis
autorise une seule requête HTTP active et douze débuts de requêtes authentifiées
sur la même fenêtre. Les dépassements réseau sont supprimés sans réponse ; un
dépassement après TLS reçoit `429`.

Lorsqu'un `PUT` Console–Controller, lui-même borné à 10 secondes, exige cette
lecture, la deadline interne vaut le minimum entre 6 secondes et la deadline
externe moins 2 secondes. Si ce budget n'existe plus, le Controller n'ouvre pas
de connexion et rend `503`. Les deux secondes réservées bornent validation
stricte, éventuelle publication locale et émission de la réponse externe.

La réponse `200` porte
`Content-Type: application/json`,
`Content-Length` exact, `Cache-Control: no-store`, aucune
`Transfer-Encoding` et aucun contenu actif. Champs inconnus ou dupliqués,
identifiants incohérents, mauvaise casse, type, taille, date, séquence, lacune
ou valeur `host-health.v1` invalide rendent l'instantané entier inutilisable
avant toute publication par le Controller.

### UTC, fraîcheur technique et reprise

Un **fuseau horaire** ne change que la manière d'afficher un instant ; une
**dérive d'horloge** signifie que deux machines ne représentent pas le même
instant avec la même valeur UTC. Tous les champs réseau de ce protocole sont
donc des dates RFC 3339 avec précision nanoseconde, normalisées en UTC et
terminées par `Z`. Un VPS en France, en Amérique ou en Océanie compare ainsi la
même ligne de temps indépendamment de son fuseau local.

Le Relay produit `received_at` lors de la première ingestion durable — un rejeu
identique ne le rajeunit pas — et `snapshot_at` lors de la copie atomique. Il
exige `received_at <= snapshot_at`. Le Controller calcule d'abord l'âge de
transport `snapshot_at - received_at`, jamais depuis `observed_at` déclaré par
le Daemon, puis l'augmente avec son horloge monotone après réception.
`observed_at` reste une donnée authentifiée mais son horloge Daemon n'est pas
une autorité de temps : sa différence avec `received_at` reste visible sans
rajeunir ni vieillir silencieusement la réception déjà prouvée en `v0.0.2`.
L'avertissement métier exact est fixé dans la projection ci-dessous.

Le Controller capture séparément l'heure civile et l'instant monotone au départ
et à la fin de la requête. Si la différence entre la durée civile et la durée
monotone dépasse 1 seconde, une correction d'horloge a eu lieu et toute la
fraîcheur devient non fiable. Sinon, `snapshot_at` doit appartenir, bornes
incluses, à l'intervalle allant de l'heure civile de fin moins 30 secondes à
l'heure civile de départ plus 30 secondes. Cette double borne refuse un Relay
en avance ou en retard de plus de 30 secondes, sans élargir la tolérance avec
les 6 secondes de réseau. Un âge négatif, un instant hors de cet intervalle ou
une réponse de plus de 6 secondes invalide la fraîcheur de transport. Aucune
machine de cet instantané n'est alors rendue `récente` et aucun rattachement
n'est autorisé. La synchronisation NTP de l'hôte est une précondition mesurée
par la preuve, pas une source d'identité ni un contrôle que le produit modifie.

Une lecture réussie remplace atomiquement le dernier instantané validé du
Controller selon le format et les gardes de non-régression fixés ci-dessous.
Plusieurs demandes simultanées partagent la même lecture. Les
demandes espacées de moins de cinq secondes peuvent réutiliser le résultat
valide. Un rattachement n'utilise jamais ce cache : il exige une lecture réseau
commencée après l'authentification du `PUT`, tout en respectant la limite de
débit et la prochaine échéance de reprise ; avant cette échéance, il reçoit
`503` sans nouvelle connexion.

Une **gigue** est la petite variation aléatoire qui évite que plusieurs clients
réessaient ensemble. Après des échecs consécutifs, les délais nominaux sont
`1`, `2`, `4`, `8`, `16`, puis `30` secondes ; le délai effectif est choisi dans
`[80 %, 100 %]` du nominal et ne dépasse donc jamais 30 secondes. Une lecture
réussie remet le compteur à zéro. Il n'existe aucune goroutine de scrutation
permanente.

Le snapshot Relay pouvant atteindre 2 Mio n'est jamais retransmis tel quel par
l'API Console–Controller bornée à 128 Kio. Sa projection métier rend toute
synthèse explicite ; aucune lacune n'est tronquée ou abandonnée silencieusement.

En cas de Relay indisponible, de réponse hostile ou après redémarrage du
Controller, le dernier instantané de transport durable peut rester consultable
mais porte l'état `indisponible` jusqu'à une nouvelle lecture réussie ; il n'est
jamais promu `récent`. Sans cache de transport, aucune observation Relay n'est
disponible. Ce cas ne fabrique pas un inventaire vide et n'efface aucune machine
métier attendue. Le `PUT` de
rattachement reçoit `503`. Un Relay redémarré valide son registre et son
stockage d'ingestion avant de rouvrir `8443`, puis exige en plus le schéma 2, le
manifeste reader, les credentials et le filtre valides avant `8444`. Un
instantané sans observation est un succès distinct d'une panne. Comme `GET` ne
mute rien, une réponse perdue se reprend par une nouvelle lecture sans reçu
applicatif.

Les actifs protégés sont le dernier état observé, l'enrôlement machine et
l'appartenance à l'infrastructure. Les menaces traitées sont l'accès depuis
Internet ou une VM voisine, le vol ou croisement d'identité, la confusion
d'infrastructure, une réponse Relay hostile, l'épuisement de ressources, la
dérive d'horloge et le faux état actuel. Le filtre IP réduit l'exposition mais
ne constitue jamais une identité : une adresse usurpée ou un hôte Controller
compromis doit encore franchir mTLS et le registre.

Un root compromis sur le Relay peut toujours lire ou altérer les observations
après terminaison TLS ; le vol de la clé lecteur donne accès jusqu'à révocation,
une autorité compromise permet l'émission de feuilles, un attaquant réseau peut
provoquer une indisponibilité et une correction d'horloge dans la tolérance peut
influencer l'âge. La rotation manuelle peut créer une coupure. Une révocation
concurrente au rattachement peut laisser un libellé
local, mais ne rend aucun droit Relay et devient visible à la lecture suivante.
Ces risques sont résiduels et aucune signature de bout en bout, haute disponibilité ou
renouvellement automatique n'est ajouté à ce palier.

Le listener partagé `8443`, un bearer token, un socket local obligatoire et un
push Relay vers Controller ont été écartés respectivement pour éviter le
croisement d'identités, un secret copiable, un placement imposé et l'inversion
du sens d'autorité. HTTPS, mTLS, contrôle local par endpoint, méthodes en liste
positive et entrées bornées suivent les
[recommandations REST OWASP](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html),
la défense réseau suit le principe de segmentation décrit par la
[fiche OWASP correspondante](https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html),
le silence des sources non autorisées sur les interfaces externes suit la
recommandation R20 du
[guide d'interconnexion à Internet de l'ANSSI](https://cyber.gouv.fr/sites/default/files/2020/06/anssi-guide-passerelle_internet_securisee-v3.pdf) ;
son extension à la VM voisine privée est un choix propre au palier, qui ralentit
aussi le diagnostic sans constituer une identité,
les limites de ressources rendent explicite le risque décrit par
[OWASP API4](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
et les chaînes, noms et usages s'appuient sur le
[guide TLS de l'ANSSI](https://cyber.gouv.fr/sites/default/files/2017/07/anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf).
Ces sources motivent les contrôles sans revendiquer une conformité globale.

## Stockage, projection et fraîcheur décidés

Une **autorité métier** est ici l'état qui décide quelles machines la Console
attend et sous quel libellé ; un cache de transport ne possède jamais ce droit.
Une **publication atomique** remplace un fichier complet ou ne le remplace pas :
un crash ne doit pas laisser un document partiel considéré comme valide. Une
**valeur scalaire Unicode** est un point de code Unicode valide, par opposition
à un octet UTF-8 ou à une unité UTF-16.

### Deux fichiers, deux autorités

Le Controller fonctionne sous un utilisateur dynamique non privilégié, sans
capacité Linux. systemd crée son répertoire d'état privé
`/var/lib/private/your-cloud-controller/` en mode `0700`. Seul le compte courant
du service possède ses fichiers réguliers en mode `0600`. Aucun état métier ne
réside dans le répertoire du frontend ou dans le coffre de la Console.

`inventory.json`, limité à 65 536 octets, est l'unique autorité métier :

```json
{
  "schema_version": 1,
  "controller_id": "22222222-2222-4222-8222-222222222222",
  "infrastructure_id": "11111111-1111-4111-8111-111111111111",
  "inventory_revision": 0,
  "infrastructure_label": null,
  "machines": []
}
```

L'autorité locale crée ce document avant l'appairage avec les deux UUIDv4
canoniques immuables déjà propagés au Relay. Elle ne les régénère jamais parce
que le fichier manque, est vide, trop grand, corrompu ou d'une version inconnue.
`inventory_revision` est un entier non signé sur 64 bits qui commence à zéro et
augmente d'une unité après chaque mutation métier réelle ; un rejeu exact ne le
change pas et sa saturation reçoit `409` sans mutation. `infrastructure_label`
vaut `null` avant l'unique initialisation, puis sa valeur canonique. `machines`
contient de zéro à 64 objets exacts `{machine_id,label}`, uniques et triés par
`machine_id`. Aucun enrôlement, certificat, statut Relay, observation, session
ou credential n'entre dans ce fichier.

`relay-cache.json`, limité à 2 097 152 octets, est seulement le réencodage
déterministe du dernier snapshot P5 entièrement validé. Il ne contient aucun
libellé métier, secret, certificat ou état de session. Son absence est admise
avant la première lecture. Les échéances monotones, le backoff et la qualité de
la lecture courante restent en mémoire : après tout redémarrage, même un cache
durable valide porte `unavailable` jusqu'à une nouvelle lecture réseau valide.

Les fichiers P4 d'identité d'appareil, de preuve humaine, de session et de
récupération restent séparés de ces deux documents. Un fichier unique a été
écarté afin qu'une écriture fréquente du cache ou sa corruption ne puisse pas
remplacer l'autorité métier. Un inventaire seulement en mémoire a été écarté
car un redémarrage ne doit pas oublier les machines attendues. SQLite a été
écarté pour ce palier de 64 objets et deux autorités complètes : il ajouterait
une dépendance, des migrations, un moteur de requête et une politique de verrou
sans supprimer les publications atomiques déjà nécessaires.

Chaque lecture refuse lien symbolique, lien dur, mauvais propriétaire, mode
trop large, fichier non régulier, taille excessive, version ou champ inconnu.
Chaque mutation valide et préencode le candidat complet, crée un fichier
temporaire `0600` dans le même répertoire, synchronise ce fichier, le renomme sur
la cible puis synchronise le répertoire. L'état en mémoire ne devient courant
qu'après ce dernier succès. Un verrou logique unique sérialise les publications ;
`GET /v0/machines` copie sous ce verrou l'inventaire et le cache cohérents, puis
encode cette copie après l'avoir libéré.

Un inventaire absent ou invalide ferme les quatre routes métier avec `503` sans
création vide ni changement d'identité ; les autorités P4 séparées peuvent
rester disponibles pour une réparation locale explicite. Un cache absent,
corrompu ou d'une version inconnue ne supprime pas l'inventaire : la lecture
Relay devient `unavailable`, aucune valeur du fichier invalide n'est projetée et
un prochain snapshot réseau valide peut remplacer une cible régulière sûre.
Un propriétaire, un mode ou un type de fichier dangereux exige au contraire une
réparation locale et n'est pas corrigé silencieusement par le service.

Pour un nouveau rattachement, le Controller persiste d'abord le cache P5 frais
qui confirme l'enrôlement `active`, puis le nouvel inventaire. Un crash entre les
deux peut donc laisser un cache plus récent sans rattachement, jamais un
rattachement fondé sur un cache non durable. L'échec de l'une des deux
publications reçoit `503` sans publier l'inventaire candidat. Il n'existe pas de
transaction entre les fichiers : cette asymétrie sûre est explicite. Renommer
une machine déjà présente modifie seulement l'inventaire et n'exige pas le
Relay.

Avant de remplacer un cache valide, le candidat doit conserver les mêmes
`controller_id` et `infrastructure_id`. Il ne peut omettre ni réutiliser un
`machine_id`, réactiver une entrée `revoked`, remplacer une observation présente
par `null` ou diminuer sa séquence. À séquence identique, l'observation
réencodée — dates, profil, valeurs, lacunes et santé comprises — doit être
identique. Les lacunes déjà connues ne peuvent pas disparaître quand la séquence
augmente. Toute régression refuse le snapshot entier, conserve l'ancien cache et
rend la lecture courante `unavailable` ; elle n'autorise aucun rattachement.

### Corps métier et révisions

`PUT /v0/infrastructure` accepte exactement :

```json
{
  "schema_version": 1,
  "infrastructure_id": "11111111-1111-4111-8111-111111111111",
  "label": "Infrastructure principale"
}
```

La première valeur valide correspondant à l'UUID réservé reçoit `201`, fixe le
libellé et augmente la révision. Le rejeu du même UUID et du même libellé NFC
reçoit `200` sans mutation ; un UUID ou libellé différent reçoit `409`.
`GET /v0/infrastructure` répond exactement avec `schema_version`,
`controller_id`, `infrastructure_id`, `initialized`, `label` et
`inventory_revision`. `initialized` est faux et `label` vaut `null` avant le
premier `PUT` ; ils valent ensuite vrai et le libellé canonique.
La réponse réussie du `PUT` reprend exactement cette même vue.

`PUT /v0/machines/{machine_id}` exige un identifiant de chemin canonique et
accepte exactement `{"schema_version":1,"label":"..."}`. Une machine absente
de l'inventaire exige la lecture P5 fraîche décrite ci-dessus et reçoit `201`
après les deux publications. Une machine déjà présente avec le même libellé
NFC reçoit `200` sans mutation ; avec un libellé différent, elle reçoit `200`
après l'unique publication locale et l'incrément de révision. Sa réponse contient
exactement `schema_version`, `inventory_revision`, `machine_id` et `label`.
Chemin, corps, libellé, capacité de 64 machines et disponibilité de la prochaine
révision sont validés avant tout appel Relay. Un inventaire plein reçoit `409`
et une machine absente ou non `active` du snapshot frais reçoit `422`, sans
mutation.

### Profil canonique des libellés

Le Controller valide les libellés côté serveur ; la validation du frontend sert
seulement à expliquer un refus avant envoi. La chaîne JSON décodée doit être un
UTF-8 strict d'au plus 256 octets avant normalisation. Les séquences UTF-8
invalides et les substituts Unicode isolés sont refusés, jamais remplacés. Le
Controller normalise ensuite en NFC, sans suppression d'espace, changement de
casse ni autre correction silencieuse, puis exige simultanément de 1 à 80
valeurs scalaires Unicode et au plus 256 octets UTF-8.

La liste positive après NFC contient uniquement :

- les lettres des catégories Unicode `L*` ;
- les marques combinantes `M*`, seulement si la valeur précédente est une
  lettre ou une marque ;
- les chiffres décimaux `Nd` ;
- l'espace ASCII `U+0020` et les caractères ASCII `-`, `_`, `.`, `'`, `(` et
  `)`.

La première et la dernière valeur doivent être une lettre ou un chiffre
décimal. Deux espaces ASCII consécutifs sont refusés. Cette liste exclut entre
autres contrôles, formats, contrôles bidirectionnels, caractères invisibles,
séparateurs de ligne, symboles, emoji, slash, antislash, chevrons HTML,
caractères privés et non assignés. Les tables Unicode et la dépendance de
normalisation seront épinglées avec l'implémentation ; aucun résultat ne dépend
de la locale ou du navigateur.

Les octets NFC exacts déterminent l'idempotence : deux écritures canoniquement
équivalentes sont identiques, mais la casse reste significative. Deux machines
peuvent porter le même libellé. Un libellé ne sert jamais d'identité, de nom DNS,
de route, de chemin, de clé de tri autoritaire ou d'autorisation ; le
`machine_id` immuable reste affiché à côté. L'enveloppe native de la Console
revérifie ce profil sur chaque réponse et refuse le document entier avant le
frontend si un Controller compromis l'enfreint. Le rendu ultérieur utilise
seulement du texte isolé, jamais du HTML actif.

### Projection Console bornée

`GET /v0/machines` projette uniquement les machines attendues de l'inventaire,
triées par `machine_id`. Il ne révèle jamais une entrée du registre Relay qui
n'y est pas rattachée. Une réponse nominale possède exactement cette forme :

```json
{
  "schema_version": 1,
  "controller_id": "22222222-2222-4222-8222-222222222222",
  "infrastructure_id": "11111111-1111-4111-8111-111111111111",
  "inventory_revision": 2,
  "relay_status": "available",
  "relay_snapshot_at": "2026-07-19T12:00:00Z",
  "machines": [
    {
      "machine_id": "lab-machine-1",
      "label": "Serveur principal",
      "enrollment_status": "active",
      "observation_status": "recent",
      "observation": {
        "profile": "host-health.v1",
        "sequence": 31,
        "observed_at": "2026-07-19T11:59:58Z",
        "received_at": "2026-07-19T11:59:59Z",
        "observed_time_warning": false,
        "continuity": "gapped",
        "gap_summary": {
          "range_count": 1,
          "dropped_count": 16,
          "first_sequence": 15,
          "last_sequence": 30
        },
        "health": {
          "uptime": {"status": "ok", "uptime_seconds": 86400},
          "memory": {
            "status": "ok",
            "total_bytes": 4294967296,
            "available_bytes": 2147483648
          },
          "rootfs": {"status": "error", "error": "source_unavailable"}
        }
      }
    }
  ]
}
```

`relay_status` vaut seulement `available`, `unavailable` ou `clock_untrusted`.
Le premier exige une lecture P5 courante valide, éventuellement réutilisée dans
sa fenêtre de cinq secondes. Un échec réseau, TLS, HTTP, de schéma, de
persistance ou de non-régression produit `unavailable`; une dérive P5 produit
`clock_untrusted`. Ces deux échecs conservent le précédent cache entièrement
validé et n'y publient aucune valeur candidate. `relay_snapshot_at` reprend le
cache projeté ou vaut `null` en son absence.

`enrollment_status` vaut `active`, `revoked` ou `null` quand aucun cache valide
ne permet de le connaître. `observation_status` vaut `absent`, `recent`, `old`
ou `untrusted`. Avec un transport courant fiable, `absent` signifie exactement
`observation: null`; une observation présente est `recent` jusqu'à un âge de
90 secondes incluses et `old` au-delà. L'âge part de `received_at` selon le
calcul P5, jamais de `observed_at`. Si `relay_status` n'est pas `available`, les
valeurs du dernier cache peuvent rester visibles mais chaque
`observation_status` vaut `untrusted`; sans cache, l'enrôlement et l'observation
valent `null`. Une panne ne devient donc ni `absent`, ni `old`, et une révocation
reste une dimension indépendante de la fraîcheur.

`observed_time_warning` vaut vrai uniquement lorsque la valeur absolue de
`observed_at - received_at` dépasse 30 secondes ; exactement 30 secondes ne
déclenchent rien. Cet avertissement n'influence jamais l'âge. `continuity` vaut
`complete` avec `gap_summary: null` quand aucune lacune n'existe, sinon `gapped`.
Le résumé est calculé sur toutes les plages validées : `range_count` est leur
nombre, `dropped_count` leur somme exacte et `first_sequence` et
`last_sequence` les extrémités de la première et de la dernière plage. Tout
débordement ou invariant impossible refuse la projection ; les 8 192 plages
complètes restent dans le cache et aucune liste partielle n'est rendue à la
Console.

Le Controller préencode la réponse complète et vérifie sa taille maximale de
131 072 octets avant d'émettre le statut ou le premier octet. Un dépassement
reçoit `503` avec un code d'erreur fixe, sans troncature, pagination implicite,
nouvelle route, mutation de l'inventaire ou remplacement du cache. Les
frontières de 64 machines, 256 octets de libellé et la synthèse des lacunes
doivent néanmoins être prouvées compatibles avec cette enveloppe. Le snapshot
P5 brut de 2 Mio n'est jamais exposé à la Console ni au frontend.

### Menaces, choix et risques résiduels

Les actifs supplémentaires sont les identifiants immuables, l'inventaire
attendu, sa révision et le dernier snapshot validé. Les menaces traitées sont la
confusion entre état métier et cache, la publication partielle, la substitution
de fichier, le rejeu régressif du Relay, le faux état actuel, l'épuisement par
taille ou cardinalité et l'injection par un libellé hostile. Le compte non-root,
les modes privés, les fichiers séparés, les schémas fermés, les écritures
atomiques, la projection en liste positive et le rendu texte appliquent le
moindre privilège et séparent les autorités.

La validation serveur, la normalisation et les listes positives suivent la
[fiche Input Validation OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) ;
les tailles, cardinalités, délais et préencodages rendent explicite le risque de
consommation décrit par
[OWASP API4](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) ;
le compte de service dédié et ses droits minimaux sont cohérents avec le
[guide de configuration GNU/Linux de l'ANSSI](https://cyber.gouv.fr/sites/default/files/document/fr_np_linux_configuration-v2.0.pdf).
Ces sources soutiennent les contrôles ; elles ne prouvent aucune conformité
globale. Le seuil de 90 secondes, l'avertissement de 30 secondes, les deux
formats JSON et l'alphabet des libellés restent des choix propres au produit.

Un root Controller ou un accès d'écriture au disque peut encore lire, altérer ou
restaurer ensemble un ancien inventaire et un ancien cache ; aucune source
monotone externe ne détecte ce rollback. Un Relay root compromis peut fabriquer
un état croissant cohérent. La perte ou la corruption sûre du cache supprime
aussi la base locale de détection avant le prochain snapshot valide. Les
libellés Unicode conservent des homoglyphes ;
leur absence d'autorité et l'identifiant adjacent réduisent sans supprimer la
confusion humaine. La projection ne livre que la synthèse des lacunes, même si
le cache conserve leurs plages exactes. Le seuil de 90 secondes reste à éprouver
avec la cadence réelle. Enfin, une corruption de l'inventaire exige une
réparation locale explicite et réduit volontairement la disponibilité plutôt
que de fabriquer un état vide.

## Système visuel et premiers écrans décidés

Un **design token** est une variable nommée qui porte une décision visuelle,
par exemple `color-accent`, `font-body` ou `radius-card`. Les composants
consomment ces noms plutôt qu'une couleur, une police ou une dimension répétée
en dur. Changer ultérieurement un thème ou une fonte reste ainsi une modification
centrale vérifiable, pas une recherche dispersée dans chaque écran.

La direction retenue est une interface claire, sobre et contemporaine : fond
neutre chaud, cartes blanches, lignes fines, indigo profond et vert canard. Elle
reste une règle de composition, pas la copie d'une maquette générée. Le logo
illustré pendant l'exploration n'est pas validé : `v0.0.3` emploie seulement le
mot-symbole texte « Your Cloud » et ne bloque pas le produit sur un emblème.

### Tokens et dépendances visuelles

Les tokens sont définis une fois, typés lorsque leur usage le permet, puis
exposés aux composants par propriétés CSS. Aucun composant ne redéfinit sa
propre palette, fonte, échelle d'espacement, rayon ou ombre. Les seules valeurs
locales admises sont une dimension intrinsèque imposée par le contenu et une
ligne de séparation de `1px` issue du token de bordure.

La palette sémantique claire fixe :

| Usage | Token | Valeur initiale |
|---|---|---|
| action et sélection | `color-primary` | indigo `#3730A3` |
| information et liaison privée | `color-accent` | vert canard `#0F766E` |
| observation ancienne | `color-warning` | ambre `#B45309` |
| refus et erreur | `color-danger` | rouge `#B91C1C` |
| observation récente | `color-success` | vert `#047857` |
| texte principal | `color-text` | graphite `#111827` |
| texte secondaire | `color-muted` | gris `#4B5563` |
| bordure | `color-border` | gris `#D1D5DB` |
| fond d'application | `color-canvas` | pierre `#FAFAF9` |
| surface | `color-surface` | blanc `#FFFFFF` |

Le thème sombre suit le thème du système, sans interrupteur propre dans ce
palier. Il remappe les mêmes tokens vers `#818CF8`, `#5EEAD4`, `#FBBF24`,
`#F87171`, `#34D399`, `#F8FAFC`, `#CBD5E1`, `#334155`, `#0B1120` et
`#111827`. Les noms sémantiques restent identiques ; un statut n'est jamais
codé par une valeur de palette utilisée directement dans un écran.

Les fontes libres **Inter** et **IBM Plex Mono** sont embarquées dans
l'artefact, jamais téléchargées à l'exécution. Inter est la fonte principale,
avec les graisses 400, 500, 600 et 700. IBM Plex Mono est la fonte secondaire,
limitée aux UUID, empreintes et heures UTC, avec les graisses 400 et 500. Leurs
licences, fichiers et empreintes entrent dans le SBOM et la provenance.
L'échelle typographique vaut : titre de page `1.75rem/2.25rem` en 700, titre de
section `1.25rem/1.75rem` en 600, titre de composant `1rem/1.5rem` en 600,
texte `0.875rem/1.375rem` en 400 ou 500, aide et monospace
`0.75rem/1.125rem` en 400 ou 500.

Le `rem` est une unité relative à la taille de texte racine. La typographie, les
espacements, les rayons, les contrôles et les icônes l'emploient afin de suivre
le zoom et les préférences d'affichage. L'échelle d'espacement est
`0.25rem`, `0.5rem`, `0.75rem`, `1rem`, `1.5rem` et `2rem` ; les contrôles ont
un rayon de `0.5rem`, les cartes `0.875rem` et les cibles interactives une
hauteur minimale de `2.75rem`. Les pixels restent réservés à la fenêtre native,
aux séparateurs de `1px` et aux seuils où l'API Tauri exige cette unité. La mise
en page utilise `rem`, `%`, `fr`, `minmax()` et `clamp()` plutôt que des largeurs
d'écran figées.

La Console ouvre une fenêtre standard de `1280 x 800` pixels logiques et refuse
une taille inférieure à `640 x 560`. À partir de `64rem`, la synthèse peut
présenter sa fiche de contexte à droite ; entre `40rem` et `64rem`, cette fiche
passe sous le contenu ; à `40rem`, la navigation se compacte et les tableaux
deviennent des listes de cartes sans défilement horizontal obligatoire. Ces
seuils pourront évoluer après mesure sans changer l'architecture. Aucun
composant, breakpoint ou geste propre au téléphone n'entre dans ce palier.

Les icônes viennent uniquement du jeu cohérent **Lucide**, en contour, avec une
taille visuelle normale de `1.25rem`. Seuls les glyphes réellement employés sont
embarqués. Une icône ne remplace jamais un libellé accessible et ne porte jamais
seule un statut. Les composants communs couvrent l'enveloppe, le sélecteur
d'infrastructure, la navigation, cartes, listes adaptatives, badges, boutons,
champs, panneau latéral, dialogue, bannière, notification et états de
chargement. Boutons et champs possèdent au minimum les états `repos`, `survol`,
`focus`, `actif`, `désactivé`, `chargement` et, lorsqu'il s'applique,
`invalide`. Primaire, secondaire et dangereux restent trois intentions
distinctes ; aucune action destructive n'est présentée comme primaire.

### Hiérarchie et sept vues

L'infrastructure sélectionnée est le contexte principal. Le Controller reste la
liaison technique privée de cette infrastructure : il apparaît dans un panneau
contextuel « Connexion à cette infrastructure », jamais comme une entrée de
navigation. Il n'existe pas non plus d'entrée générique « Sécurité » : l'accès
privé appartient à l'infrastructure, tandis que la phrase, l'appareil et la
session appartiennent à « Profil et sessions ».

Après sélection d'une infrastructure, la navigation contient exactement
`Synthèse`, `Parc` et `Observations`. Le premier frontend comporte exactement
sept vues ; les variantes nominales et hostiles restent des états de ces vues,
pas des pages supplémentaires :

1. **Accès local** : création initiale du coffre, présentation et confirmation
   de la phrase et du code global, puis déverrouillage ou état verrouillé ;
2. **Infrastructures** : associations séparées, choix de l'infrastructure et
   état de sa liaison technique, avec identifiant immuable adjacent au libellé ;
3. **Association ou récupération** : parcours borné d'appairage ou de
   remplacement, origine et empreinte visibles, fenêtre et secrets transitoires
   effacés après usage ;
4. **Synthèse** : état du transport Relay, fraîcheur et compte des machines
   attendues, sans score de santé inventé ;
5. **Parc** : liste des machines attendues et fiche de la machine sélectionnée
   dans le même écran, avec identité, santé, dernière observation et lacunes ;
6. **Observations** : instantané courant, origine des heures UTC, fraîcheur,
   avertissement d'horloge et résumé exact des lacunes, sans historique ni série
   temporelle ;
7. **Profil et sessions** : état local du coffre, appareil, certificat et
   session du Controller sélectionné, verrouillage, logout et parcours manuels
   de rotation ou de récupération déjà autorisés par le contrat.

Le Relay n'est jamais inventé comme une machine dédiée. `Relay indisponible`
est un état de transport de l'infrastructure, rendu dans la synthèse et comme
cause de données non actualisables ; ce n'est pas une ligne `relay-01`. Si
l'hôte du Relay possède aussi un Daemon et figure réellement dans l'inventaire,
il reste une machine normale. `v0.0.3` ne lui ajoute pas un badge de rôle car
l'API décidée ne publie aucun champ de placement.

Une entrée dans une vue authentifiée déclenche au plus sa lecture initiale ;
ensuite seule l'action explicite `Actualiser` relit le Controller. Aucun polling
réseau de fond ne maintient artificiellement en vie la session de 30 minutes
d'inactivité. Un changement d'infrastructure annule les requêtes et vide l'état
de vue précédent avant toute nouvelle lecture. Chargement, vide, récent,
ancien, lacune, transport indisponible, horloge non fiable, refus et erreur sont
distincts ; le dernier état fiable peut rester visible avec sa date mais n'est
jamais recoloré en état actuel.

### Accessibilité et contenu hostile

Le clavier atteint toutes les actions dans l'ordre visuel, le focus reste
visible et non masqué, `Escape` ferme seulement une surface annulable et le
focus revient à son déclencheur. Les textes normaux visent un contraste d'au
moins `4.5:1`, les grands textes et composants graphiques `3:1`, le contenu
reste utilisable avec un zoom texte de 200 %, le mouvement réduit est respecté
et aucune information n'est portée uniquement par une couleur, une position ou
une icône. Les états de session et les opérations sensibles annoncent
explicitement leur échéance ou leur conséquence.

Ces objectifs reprennent les critères pertinents de
[WCAG 2.2 niveau AA](https://www.w3.org/TR/WCAG22/), notamment contraste,
redimensionnement, reflow, focus visible et cible minimale. Ils seront testés
sur les deux artefacts, mais ne constituent pas une revendication de conformité
globale. Les libellés et erreurs issus du Controller sont rendus comme nœuds
texte, jamais par HTML interprété, style, URL ou
`dangerouslySetInnerHTML`, conformément aux sorties sûres décrites par la
[fiche XSS Prevention OWASP](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html).

Aucune maquette Figma n'est requise. Les tokens, fontes, composants et états
versionnés forment le contrat visuel ; chaque écran les applique sans style
local opportuniste. Les trois images exploratoires ne sont ni des artefacts de
preuve, ni des spécifications à intégrer au produit.

## Runners et phases LAB décidés

Un **runner** est une machine isolée qui reçoit le lot de sources identifié,
exécute un build ou des tests et rend des artefacts et résultats bornés. Une
**porte** est un ensemble de contrôles qui doivent tous réussir avant de passer
à la plateforme suivante. Fermer la porte Linux autorise donc le travail
Windows ; cela ne prouve pas encore Windows.

L'inventaire lu par `tools/labctl list` le 19 juillet 2026 contient la topologie
Debian `v1-full`, entièrement arrêtée, mais aucune VM Windows. Le contrat ne
transforme pas cette absence en support implicite. Le travail suit deux portes
séquentielles.

### Porte Linux immédiate

La topologie `v1-full` existante reçoit exactement ces rôles :

| Machine LAB | Rôle pendant la preuve `v0.0.3` |
|---|---|
| `lab-console` | runner Linux, build natif `.deb`, orchestration, puis après retour à un snapshot propre installation et exécution de la Console Linux |
| `lab-console-recovery` | seconde Console et client hostile : appairage concurrent, récupération, appareil inconnu ou révoqué, session et infrastructure croisées, scan de l'API Controller |
| `lab-coordinateur` | Controller A réel ; un second processus Controller B synthétique emploie une autre IPv4 privée, un autre compte, une autre origine, d'autres CA, fichiers et identifiants pour les preuves multi-Controller |
| `lab-gateway` | routage et filtrage LAB uniquement, sans Console, Controller, Relay ou Daemon |
| `lab-machine-1` | Daemon et Relay A colocalisés mais séparés par processus, comptes, identités, stockages, ports et unités |
| `lab-machine-2` | second Daemon A ; client hostile sans credential lecteur contre `8444`, y compris présentation d'une identité Daemon dans l'autorité lecteur |

Les deux processus Controller restent chacun l'autorité d'une seule
infrastructure. Leur colocation LAB sert uniquement à attaquer la séparation
logique ; elle ne prouve pas une isolation contre `root` commun. Controller B
peut garder un inventaire vide et un Relay indisponible : sa fonction est de
prouver que certificat, session, état et réponse de B ne traversent jamais vers
A. Le déploiement nominal reste Controller A sur `lab-coordinateur`, Relay A
sur l'IPv4 privée distincte de `lab-machine-1`, et deux Daemons sur
`lab-machine-1` et `lab-machine-2`.

Le réseau refuse l'API Controller hors du segment d'administration. Depuis
`lab-console-recovery`, qui appartient à ce segment, la connexion peut atteindre
la frontière mais reste sans droit sans appareil et humain valides. Pour
`8444`, `lab-machine-2` prouve d'abord le filtrage de la mauvaise IP ; une phase
isolée arrête le lecteur du Controller puis tente depuis son IP exacte sans le
certificat lecteur, afin de prouver que l'autorisation réseau ne remplace pas
mTLS. Chaque phase réaffirme ensuite le nominal et l'état inchangé.

`lab-console` sépare build et exécution par snapshots. Il construit depuis le
lot Git exact, exporte le `.deb`, ses empreintes et métadonnées, revient à un
snapshot runtime propre, vérifie l'artefact puis l'installe. Le pilote externe
`tauri-driver` contrôle la WebView installée ; aucun plugin WebDriver, serveur
de test ou capacité supplémentaire n'entre dans l'artefact livré. Les processus
et ports du pilote restent inventoriés comme instrumentation LAB.

### Porte Windows différée, obligatoire

Après réussite stable de toute la porte Linux, `labctl` reçoit une seule machine
supplémentaire `lab-console-windows`, Windows 11 x86_64 installé depuis un média
officiel sous licence et identifié par empreinte. Deux snapshots séparent le
runner natif MSVC/WiX du runtime propre. La même archive de sources et le même
verrou frontend produisent nativement le `.msi`, qui est exporté, signé avec les
clés synthétiques LAB, réinjecté après retour au snapshot runtime, vérifié,
installé puis piloté par le WebDriver externe Windows.

La Console Windows rejoint le même segment d'administration et rejoue contre
Controller A et B les parcours utilisateur, tailles, thèmes, clavier, contenu
hostile, mauvaises identités et séparation des associations. Les attaques
réseau profondes déjà indépendantes de la WebView ne sont pas dupliquées sans
raison, mais TLS, coffre, IPC natif, installation, lancement, absence de
listener, rendu et cycle de session sont réellement exécutés sous Windows. Un
échec Windows laisse la preuve Linux visible mais bloque la fermeture de
`v0.0.3`.

### Ordre, artefacts et nettoyage

Le pilote exécute exactement :

1. `tools/labctl list`, validation des origines, gabarits, réseaux et adresses,
   puis verrou exclusif du run ;
2. retour aux snapshots propres et export Git non sensible du commit annoncé,
   avec empreinte vérifiée après chaque transfert ;
3. contrôles statiques, unitaires et hostiles puis build Linux natif ;
4. installation propre et parcours Console Linux à `1280 x 800` et
   `640 x 560`, thèmes clair et sombre, clavier et zoom 200 % ;
5. cycle nominal Daemon–Relay–Controller–Console, deux machines, Controller B,
   instantané vide, donnée ancienne, lacune, reprise et redémarrages ;
6. matrice hostile réseau, TLS, API, identités, sessions, fichiers, schémas,
   tailles, horloges, concurrence et réponses tardives ;
7. réaffirmation nominale, inventaire inchangé, collecte des empreintes, SBOM,
   captures et journaux expurgés, retrait des secrets synthétiques et retour
   vérifié à l'état final annoncé ;
8. seulement après stabilité Linux, préparation puis rejeu de la porte Windows
   native décrite ci-dessus.

Chaque étape possède une échéance, une assertion et un nettoyage d'échec. Les
résultats vont dans un dossier de run non versionné puis un rapport Markdown
expurgé ne publie que commandes, versions, empreintes, résultats, incidents et
limites. Phrase, codes, clés, sessions, CSR et corps hostiles sensibles sont
absents des captures et journaux. Une capture visuelle ne remplace jamais une
assertion ; un contrôle manuel nomme préconditions, action, attendu et observé.

## Données minimales visibles

Pour chaque machine attendue, le Controller rapproche :

- l'identifiant de machine et son libellé métier local ;
- le dernier profil et la dernière séquence acceptés ;
- l'heure d'observation déclarée par le Daemon ;
- l'heure locale de réception du Relay ;
- les lacunes persistées par le Relay ;
- les valeurs bornées de `host-health.v1` ;
- la fraîcheur calculée par la politique du Controller.

Le Relay fournit un instantané, pas un historique. Si plusieurs observations
arrivent entre deux lectures, seule la dernière peut être visible. Ce
remplacement n'est pas une lacune du tampon Daemon et l'interface ne doit jamais
inventer les séquences intermédiaires.

## Preuve de sortie à rendre exécutable

La preuve finale devra au minimum démontrer :

- artefacts Linux et Windows issus de la révision annoncée, inventoriés et
  signés ;
- aucun frontend hébergé, serveur local ou téléchargement de code depuis un
  Controller ;
- Controller inconnu, identité d'appareil inconnue ou révoquée, authentification
  humaine invalide, session expirée ou révoquée et mauvaise infrastructure
  refusés ;
- séparation des sessions entre deux Controllers synthétiques ;
- coffre Stronghold absent, déplacé, tronqué, altéré ou d'une version inconnue,
  mauvaise phrase et substitution du compartiment d'une association par celui
  d'une autre refusés sans secret, session ou état partiel rendu ; aucune
  capacité Stronghold disponible en JavaScript et paramètres KDF par défaut ou
  recréés refusés ;
- phrase brute ou canonique surdimensionnée, liste ou normalisation substituée,
  Base32 non canonique, `window_id` ou `window_code` absent, erroné, expiré,
  croisé ou tenté simultanément par deux VM refusés ; une tentative sans code ne
  consomme pas la fenêtre ;
- `9444` fermé avant et après la fenêtre, aucune route métier sur ce port, faux
  nom, certificat ou autorité, transaction, `device_id`, CSR, clé, sel ou époque
  substitués et possessions des nouvelles clés humaine et de récupération
  invalides refusés sans autorité partielle ;
- challenge humain rejoué, expiré, lié à une autre finalité ou issu d'un autre
  Controller et clé publique ou signature inconnue refusés ;
- session croisée avec un autre certificat, Controller, humain ou
  `infrastructure_id`, expirée par inactivité ou durée absolue, rejouée après
  logout, rotation, récupération, révocation ou redémarrage refusée ; réponse
  contenant le jeton perdue, challenge concurrent et délais 1/2/4/8/16 secondes
  puis blocage de cinq minutes prouvés ;
- certificat candidat refusé sur toute route métier, perte de réponse et crash
  avant ou après chaque commit, candidat jamais activé et ancien certificat sur
  une connexion TLS persistante prouvés sans verrouillage ni double autorité ;
  reçu exact rejoué après commit et redémarrage, puis expiré après 24 heures ;
- récupération avec mauvais code, sel, époque, Controller ou compartiment,
  preuve rejouée, remplacement de SPKI et rotation globale interrompue par crash
  refusés ou rendus honnêtement ;
- autorité TLS serveur, autorité d'appareil, autorité Daemon et autorité de
  lecteur Relay croisées refusées ;
- `8444` absent des interfaces publiques et filtré par `drop` depuis toute
  source autre que l'IP privée exacte du Controller ; politique `nftables`,
  rafale de quatre nouveaux TCP, douzième puis treizième connexion et scan
  depuis une VM hostile vérifiés avant l'attaque applicative ;
- absence de certificat lecteur, certificat Daemon, mauvaise CA, feuille,
  période, nom, URI, usage, série, empreinte, état révoqué, Controller ou
  infrastructure croisés refusés, y compris après rechargement sur une
  connexion TLS persistante ;
- rotation lecteur interrompue avant et après chaque publication locale, un
  seul hôte tourné, double certificat et réouverture prématurée gardant `8444`
  fermé jusqu'au recoupement complet ;
- schéma 1 non migré et migration du registre interrompue refusés ; tableau de
  zéro machine rendu avec succès puis 65e identité, suppression, réactivation,
  `controller_id` ou `infrastructure_id` absents, régénérés ou divergents entre
  registre Daemon, manifeste lecteur, certificat, origine, Controller ou
  réponse refusés sans arrêter l'ingestion `8443` existante ;
- `GET /v0/snapshot` nominal puis endpoint, Host, méthode, route, query vide ou
  non vide, body, `Content-Type`, `Accept`, schéma, erreur, champ, casse, UUID,
  séquence, collecteur, taille, `Content-Length`, délai, cinq sockets, treizième
  connexion et treizième lecture hors borne refusés ; 8 192 lacunes acceptées
  puis 8 193 refusées sans troncature ;
- instantané atomique construit depuis le registre courant, machine active sans
  observation rendue `null`, tableau réellement vide distingué, machine
  révoquée incapable d'autoriser un rattachement et réponse supérieure à 2 Mio
  refusée avant son premier octet ;
- timestamps UTC identiques sous plusieurs fuseaux, âge fondé sur
  `snapshot_at - received_at` puis durée monotone ; bornes incluses à moins et
  plus 30 secondes, nanoseconde extérieure, âge négatif et correction civile
  supérieure à une seconde pendant la requête jamais rendus récents ;
- Relay indisponible, réponse perdue ou hostile, backoff, instantané vide,
  reprise et redémarrages gardant le dernier cache `indisponible` jusqu'à une
  lecture valide ; réutilisation avant cinq secondes, gigue dans `[80 %,100 %]`
  et remise à zéro après succès prouvées ; rattachement refusé sans lecture
  réseau réussie dans la même opération et sans contournement du backoff ;
- inventaire et cache séparés, répertoire `0700`, fichiers `0600`, compte
  non-root sans capacité, liens, propriétaire ou modes hostiles refusés ; état
  absent, tronqué, corrompu, surdimensionné ou d'une version inconnue échouant
  fermé sans régénérer les UUID ni fabriquer un inventaire vide ;
- crash avant et après écriture, synchronisation, renommage et synchronisation
  du répertoire ; cache frais publié avant un nouveau rattachement, échec de
  persistance, révision saturée et mutations concurrentes laissant l'autorité
  précédente cohérente ;
- omission ou réutilisation d'une machine, réactivation, observation disparue,
  séquence décroissante, même séquence au contenu différent et lacune connue
  supprimée refusées sans remplacer le cache ;
- `GET /v0/machines` à zéro puis 64 machines, libellés maximaux et santé maximale
  restant sous 128 Kio ; octet suivant, somme de lacunes incohérente ou en
  débordement refusés avant le premier octet, sans troncature ni exposition du
  snapshot Relay brut de 2 Mio ;
- âge à `89,999999999`, `90` et `90,000000001` secondes, transport
  `unavailable` ou `clock_untrusted`, redémarrage avec ou sans cache et écart
  absolu `observed_at`/`received_at` à 30 secondes puis une nanoseconde au-delà,
  chacun séparé de l'enrôlement et des lacunes ;
- libellés UTF-8 et NFC testés avant et après les bornes de 256 octets et de 80
  valeurs scalaires ; formes composée et décomposée idempotentes, liste positive
  acceptée, contrôles, formats, bidi, invisibles, symboles, slash, chevrons,
  marque initiale et entrée UTF-8 invalide refusés sans mutation ; libellés
  identiques sur deux machines restant distingués par leur `machine_id` ;
- mauvais certificat, endpoint, méthode, route, portée, schéma ou taille refusé
  sur les frontières Console–Controller et Controller–Relay ;
- inventaire libre non borné, machine non enrôlée et champ d'interface inconnu
  refusés ;
- Relay indisponible, instantané vide, donnée ancienne, lacune, reprise et
  redémarrages rendus honnêtement sans faux état actuel ;
- les sept vues et leurs états nominaux, vides, chargés, refusés et hostiles
  rendus depuis les mêmes composants sous Linux et Windows à `1280 x 800` puis
  `640 x 560`, sans débordement masqué ni défilement horizontal obligatoire ;
- tokens clair et sombre, fontes embarquées, icônes cohérentes et absence de
  valeur visuelle locale interdite contrôlés statiquement ; aucune ressource de
  fonte, icône, style ou code téléchargée à l'exécution ;
- changement d'infrastructure annulant les requêtes et purgeant la vue
  précédente, absence de polling réseau de fond, Controller absent de la
  navigation et aucun Relay synthétique rendu comme machine dédiée ;
- libellés et erreurs Controller hostiles rendus comme texte inerte, sans HTML,
  style, URL, script, attribut actif ou fuite dans une notification technique ;
- frontend sans clé privée, clé dérivée, contenu de coffre ou session ; phrase,
  `window_code` et code de récupération transitoires absents du stockage Web,
  des URL, journaux, presse-papiers automatique et captures produites par la
  Console ou le protocole LAB après usage ;
- clavier, ordre et restitution du focus, zoom texte à 200 %, reflow, mouvement
  réduit, contrastes et libellés accessibles vérifiés ; l'automatisation et la
  revue manuelle sont distinguées sans revendiquer une conformité WCAG globale ;
- aucun listener Daemon, aucun canal d'action et aucune mutation des machines.

## Exclusions absolues

`v0.0.3` n'ajoute aucun Ansible métier, SSH d'action, plan appliqué, Auxiliaire
local, WireGuard, service OCI, téléphone, navigateur public, passerelle Web,
Proxmox, OpenStack, worker d'automatisation, projet IaC, série temporelle,
plugin libre, scan LAN, renouvellement automatique ou élection de Relay.

La cible ultérieure où la Console déverrouille et ferme elle-même une liaison
privée bornée au Controller est conservée dans le [cap du projet](../../projet/CAP.md).
Elle appartient à un palier post-V1 et
ne fournit ici ni dépendance, ni abstraction anticipée, ni exception à cette
exclusion.

## Paramètres exécutables validés

1. Tauri 2 avec React, TypeScript et Vite, frontend embarqué, capacités nommées
   et mise à jour manuelle ;
2. `.deb` Linux et `.msi` Windows natifs, manifeste, empreintes, SBOM,
   provenance et signatures vérifiables ;
3. API Console–Controller REST JSON sur HTTPS TLS 1.3, appareil mTLS et session
   humaine opaque, quatre routes métier, limites fermées et séparation stricte
   des infrastructures ;
4. authentification locale et cycle d'identité :
   - 4A : phrase secrète locale et coffre Tauri Stronghold commun à Linux et
     Windows, Argon2id, clés d'appareil et humaines distinctes par Controller,
     sans clé privée ni session rendue au frontend ;
   - 4B : phrase aléatoire de six mots, appairage et récupération sur listener
     `9444` temporaire épinglé, certificats d'appareil P-256 de 180 jours,
     challenges Ed25519, session opaque de 30 minutes d'inactivité et huit
     heures absolues, rotation en deux phases, révocation locale et code global
     de récupération dérivé séparément par Controller ;
5. API Controller–Relay : listener lecteur privé `8444` filtré par défaut sur
   l'IP source Controller, TLS 1.3 mTLS avec deux autorités Ed25519 dédiées par
   infrastructure, manifeste lecteur et registre Daemon schéma 2 liés au même
   `infrastructure_id`, seul `GET /v0/snapshot` borné, timestamps UTC et contrôle
   de dérive, cache atomique indisponible après panne puis reprise bornée ;
6. stockage et projection : inventaire métier et cache Relay dans deux fichiers
   JSON privés publiés atomiquement sous un compte non-root, révisions et
   non-régression fermées, projection de zéro à 64 machines sous 128 Kio,
   fraîcheur `recent` jusqu'à 90 secondes incluses, transport et continuité
   séparés, avertissement d'horloge à plus de 30 secondes et libellés UTF-8 NFC
   bornés par une liste positive Unicode ;
7. système visuel : direction claire indigo et vert canard, tokens sémantiques,
   Inter et IBM Plex Mono embarquées, icônes Lucide, thèmes système clair et
   sombre, fenêtre `1280 x 800` minimale `640 x 560`, mise en page relative et
   sept vues centrées sur l'infrastructure sans rubrique Controller ou
   Sécurité ;
8. preuve : porte Linux immédiate sur les six VM `v1-full`, Relay et Daemon
   colocalisés sur `lab-machine-1`, seconde Console hostile et deux Controllers
   logiquement séparés ; puis seulement après stabilité, porte Windows native
   obligatoire sur `lab-console-windows` avant fermeture du palier.

## Paramètres encore ouverts avant le code

Aucun. Toute modification de ces huit paramètres exige une nouvelle décision
explicite ; un incident d'implémentation ne les élargit pas silencieusement.

## Point d'arrêt

Les paramètres 1 à 8 sont validés et la porte Linux de la branche
`console-controller` a réussi dans le LAB. Son artefact reste explicitement un
candidat non commité : aucun commit ou push n'est autorisé implicitement. Le
point d'arrêt est maintenant sa stabilisation et sa relecture ; Windows ne
commence qu'après une nouvelle validation explicite de Lucas, sans rouvrir le
périmètre ni préparer une abstraction réseau post-V1. Les preuves et limites
réellement exécutées restent visibles, et le palier ne devient terminé qu'après
les deux portes.

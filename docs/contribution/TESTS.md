# Stratégie et registre d'automatisation des tests

> Statut : stratégie active et registre des régressions. Ce document n'est ni
> un journal d'exécution ni une preuve. Les exécutions LAB appartiennent aux
> rapports sous [`docs/lab/`](../lab/) ; les exécutions hébergées restent liées
> à leur run GitHub exact depuis le [contrat CI](CI.md).

Ce registre conserve les contrôles réalisés, les difficultés rencontrées et le
travail restant pour rejouer les vérifications sans intervention manuelle. Il
distingue la couverture automatisée de `v0.0.1`, la preuve assistée de
`v0.0.2`, la preuve fonctionnelle Linux assistée puis revalidée de `v0.0.3` et
la matrice native Linux/Windows déjà exécutée. La fermeture est attribuée au
candidat produit exact `3b8f81f`, dont le run manuel `30710037004` entièrement
vert est lié depuis l'[issue `#9`](https://github.com/ldesfontaine/your-cloud/issues/9).
Il prépare aussi les matrices
d'amorçage et d'action V1 ; une ligne planifiée ne constitue jamais une preuve.

## Vocabulaire de travail

- Une **assertion** compare automatiquement un résultat observé avec le résultat
  attendu et termine en échec si les deux diffèrent.
- La **préparation** place les sources, l'artefact, les configurations et les VM
  dans l'état initial nécessaire au test.
- L'**orchestration** ordonne les actions entre les processus et les VM : arrêt,
  démarrage, requête, attente bornée puis observation.
- Le **nettoyage** retire les processus et fichiers temporaires ou restaure un
  état final annoncé, même après un échec.
- Une **preuve LAB** relie une version des sources à un environnement identifié,
  aux commandes réellement exécutées et à leurs résultats. Un test vert sans
  ce contexte ne devient pas, à lui seul, une preuve publiée.
- Un **contrôle générique** vérifie un contrat de source ou d'outil sans exiger
  la topologie métier complète. Générique ne signifie pas « autorisé sur le
  laptop » : il s'exécute dans le runner isolé prévu par le projet.
- Un **contrôle natif** vérifie la différence propre à un système : build,
  installation, lancement et WebView ; Windows ajoute la signature
  Authenticode synthétique. Il ne prouve ni ne simule une infrastructure
  fonctionnelle distribuée.

Les tableaux utilisent trois niveaux : `automatique` signifie qu'une commande
porte déjà l'assertion ou l'étape concernée ; `assisté` signifie qu'un script
réalise une partie du travail mais qu'une personne enchaîne ou interprète encore
les étapes ; `manuel` signifie que l'action ou la conclusion dépend encore
d'une personne.

## Stratégie durable

Les contrôles progressent du plus petit au plus représentatif. Une couche ne
remplace pas la précédente : elle répond à une question différente.

1. **Statique** : les sources, scripts et liens sont-ils formés comme attendu ?
2. **Unitaire et hostile** : chaque contrat refuse-t-il les entrées invalides
   sans réseau ni VM métier ?
3. **Frontière HTTP vivante** : un Relay réellement lancé conserve-t-il le même
   comportement face aux requêtes hostiles ?
4. **Cycle multi-VM** : placement, systemd, processus, ports, retrait et
   réinstallation produisent-ils l'état annoncé ?
5. **Restitution visuelle** : la synthèse rend-elle fidèlement les observations
   déjà collectées, sans fabriquer une nouvelle conclusion ?

Toute exécution du produit, des tests, du build ou d'un serveur reste dans
`lab-console`, une autre VM LAB isolée ou un runner CI jetable explicitement
cadré. Le laptop peut éditer, inspecter Git, contrôler l'inventaire et piloter
`labctl`, conformément aux
[règles LAB](../lab/README.md).

L'arborescence rend cette frontière visible :

- [`tests/checks/`](../../tests/checks/) contient les contrôles génériques,
  réutilisables dans un runner CI isolé ;
- [`tests/lab/v0.0.1/`](../../tests/lab/v0.0.1/) contient l'orchestrateur, les
  scénarios distants et la restitution de la preuve multi-VM ;
- [`tests/lab/v0.0.2/`](../../tests/lab/v0.0.2/) contient seulement les
  auxiliaires synthétiques déjà utilisés par la preuve assistée, pas encore un
  orchestrateur multi-VM ;
- [`tests/lab/v0.0.3/`](../../tests/lab/v0.0.3/) contient les pilotes bornés de
  la preuve Linux assistée ; `tests/checks/console-linux-ci` et
  `console-windows-ci.ps1` portent seulement les smokes natifs génériques ;
- les sous-dossiers `deploy/` de
  [`tests/lab/v0.0.1/`](../../tests/lab/v0.0.1/) à
  [`tests/lab/v0.0.3/`](../../tests/lab/v0.0.3/) figent les cycles de vie et
  unités exercés par chaque preuve, jamais un installateur de production ;
- [`tests/artifacts/`](../../tests/artifacts/) reçoit les résultats locaux
  rapatriés des preuves ; ses sorties générées ne sont pas versionnées.

Une image CI ordinaire peut fournir la première couche, mais elle ne remplace
pas automatiquement KVM/libvirt, les réseaux et les six VM de `v1-full`.
La preuve complète pourra entrer dans la CI sur un runner dédié : inventaire en
lecture seule, mutation bornée, publication des artefacts, puis nettoyage
vérifié même si une assertion échoue. `labctl` reste le même contrôleur pour une
preuve lancée localement ou par ce runner dédié.

Le pilote garde les phases séparées. Une mutation ne commence qu'après la garde
d'inventaire et l'acquisition atomique d'un verrou LAB attribué au run ; un
verrou déjà présent est laissé visible et provoque un refus. Chaque attente
possède une échéance ; chaque
assertion conserve son code de sortie ; le nettoyage s'exécute aussi après un
échec. Aucun `|| true` global, agrégat de logs ou rapport visuel ne doit masquer
le premier contrôle rouge.

La clôture de l'environnement possède une assertion distincte :
`tools/labctl assert-clean` échoue si une VM ou un réseau LAB reste persistant,
y compris sous un nom `lab-*` absent du contrôleur courant. Le contrôle
générique [`tests/checks/labctl-clean`](../../tests/checks/labctl-clean) couvre
l'état vide, les ressources conservées et l'indisponibilité de libvirt. Cette
assertion ne détruit rien et ne remplace pas la décision humaine de conserver
explicitement une topologie entre deux tâches.

## Matrice de `v0.0.3` — fonctionnel LAB Linux et natif Linux/Windows exécutés

Cette première matrice vient du
[contrat `v0.0.3`](../objectifs/v1/CONTRAT-V0.0.3.md). Elle enregistre les
preuves attendues pour l'enveloppe, la distribution, les deux API, le cycle
d'authentification Console–Controller, le stockage et la projection déjà
décidés, ainsi que le système visuel, les sept vues et les couches de preuve.
Le [rapport Linux exécuté](../lab/v0.0.3-console-controller-linux.md) distingue
les tests automatiques, les scénarios vivants assistés, les incidents et les
limites. Dans la colonne finale ci-dessous, `planifié, non exécuté` désigne
encore l'orchestration rejouable de toute la ligne en une commande ; cela
n'efface pas les sous-cas déjà prouvés et ne transforme pas les sous-cas
restants en réussite implicite.

La porte Linux emploie les six VM `v1-full` existantes : `lab-console` construit
puis exécute après retour à un snapshot propre ; `lab-console-recovery` porte la
seconde Console hostile ; `lab-coordinateur` exécute Controller A et un
Controller B synthétique sous autorités séparées ; `lab-gateway` reste un
routeur sans produit ; `lab-machine-1` colocalise Daemon et Relay séparés ;
`lab-machine-2` porte le second Daemon et les tentatives lecteur hostiles. La
porte Linux a réellement employé ces six VM et a réussi le 20 juillet 2026 sur
`afb31e8`. Le run `linux-review-02fe4f5-20260722` a ensuite reconstruit
`02fe4f5` depuis un checkout propre et rejoué le parcours critique installé,
la panne/reprise Relay et les vues claires/sombres. Il n'a pas rejoué toute la
matrice hostile initiale. Le run GitHub Actions historique `30700406219` a
ensuite réussi sur `9c6f14f` les variantes natives Linux et Windows : tests,
builds, installations, lancements et refus de listener, plus signature
Authenticode synthétique et smoke WebView2 sous Windows. Après durcissement du
workflow, la porte finale `30710037004` a entièrement réussi sur le candidat
produit exact `3b8f81f`. Cette preuve hébergée ne démarre aucune infrastructure
produit et ne remplace aucune ligne fonctionnelle ou multi-VM du LAB. L'issue
`#9` relie le run final au SHA intégré par fast-forward : `v0.0.3` est fermée
pour ce candidat.

Le smoke Windows publie uniquement un JSON et des captures PNG. Le JSON lie le
SHA et l'identifiant du run GitHub au checkout propre, conserve les SHA-256 des
verrous npm et Cargo, puis relie les noms et empreintes du `.msi`, de
l'exécutable signé extrait de l'image administrative du MSI et de l'exécutable
installé identique. Tauri restaure sa sortie Cargo originale après le bundling ;
elle n'est donc pas prise à tort pour l'exécutable signé du paquet. Le
nettoyage bloquant vérifie notamment l'absence de l'installation, du certificat
et de sa clé privée, du compte et profil éphémères, des fichiers temporaires,
des processus, du port de debugger WebView2 et des données applicatives. Aucun
paquet, exécutable, certificat ou secret synthétique n'entre dans l'archive.
Le drain final attribue les processus au SID éphémère ou aux chemins exacts des
binaires de preuve ; il ne tue pas une WebView2 étrangère d'après son seul
chemin. Chaque arrêt relit le PID, l'heure de création et l'attribution, emploie
un handle de processus et aucun nouvel arrêt n'est engagé après l'échéance
globale de quinze secondes. Le profil est retiré par le service de profils
Windows, autorisé comme
`SYSTEM` par la DACL du coffre, sans `takeown`, élargissement d'ACL ni suppression
directe privilégiée des données privées.
Cette structure renforcée n'est pas attribuée rétroactivement au run
`30700406219` ; la preuve finale `30710037004`, liée depuis l'issue `#9`,
l'attribue à sa révision exacte `3b8f81f`.

Le run final tenté `30705241755` sur `46b05ce` a réussi les gardes rapides et
la variante Linux. Sous Windows, le MSI a été construit et signé avant que le
contrôle de la sortie Cargo restaurée non signée échoue ; l'agrégateur de
nettoyage a ensuite refusé sa liste vide et masqué cette cause initiale. Le
garde rapide extrait désormais cette fonction, prouve que la liste vide est
acceptée et qu'une erreur synthétique est agrégée. La preuve native extrait de
son côté l'image administrative du MSI, vérifie son exécutable signé puis son
égalité avec l'installation réelle. Ce run en échec ne ferme aucun palier.

Le run `30706885722` sur `eb34fc1` a ensuite réussi les gardes, Linux et toutes
les assertions produit Windows jusqu'au message de succès du smoke WebView2.
Son nettoyage a refusé un processus encore observé par une attribution globale
et la suppression directe du coffre par le compte runner, correctement rejetée
par la DACL privée utilisateur plus `SYSTEM`. Aucun artefact Windows n'a été
publié. Le contrat rapide couvre désormais l'attribution positive par SID et
chemins bornés, refuse une WebView2 d'un autre SID, un PID réutilisé et un
chemin frère du profil, borne l'attente globale, verrouille l'ordre du nettoyage
et interdit la suppression directe du coffre.
À ce stade, une nouvelle preuve native entièrement verte restait nécessaire
avant fermeture.

Le run `30708995783` sur `c302a39` a ensuite réussi les gardes, Linux et toute
la preuve produit Windows, jusqu'au succès du smoke WebView2. Le nettoyage a
échoué avant son drain parce que les résultats nuls des processus non attribués
étaient conservés comme candidats. Aucun artefact Windows n'a été publié. Le
contrat rapide exige désormais zéro candidat pour une collection étrangère, un
seul candidat pour un mélange étranger et attribué, et interdit qu'un refus
d'attribution émette une valeur nulle dans le pipeline. Une preuve native
entièrement verte restait nécessaire avant fermeture.

Le run final `30710037004` sur `3b8f81f` a ensuite réussi les deux gardes, Linux
et Windows, y compris le drain sans résultat nul, l'attribution positive des
processus et le nettoyage complet. Son artefact expurgé contient le rapport JSON
et neuf PNG, sans binaire, certificat, clé privée ou secret. L'issue `#9` lie ce
run au candidat intégré par fast-forward : la porte native et `v0.0.3` sont
fermées pour ce SHA exact.

Le contrôle statique `tests/checks/ci-workflow-policy.py`, appelé par la porte
générique, ferme les déclencheurs et permissions du workflow, sa concurrence,
ses trois jobs et le caractère exclusivement manuel de la matrice native. Il
prouve la forme versionnée de cette politique, pas son exécution sur GitHub.

| Frontière | Nominal à automatiser | Refus hostile à automatiser | Automatisation rejouable complète |
|---|---|---|---|
| sources et artefacts | `package.json` fournit la version Console à Tauri, au SBOM et au manifeste candidat ; Cargo et le verrou npm doivent rester alignés ; même commit et même verrou frontend pour le `.deb` Linux et le `.msi` Windows ; manifeste, SHA-256, SBOM, provenance et signatures vérifiés | version divergente, identifiant d'exécution couplé à une version de livraison, artefact modifié, signature inconnue ou invalide, commit, cible, taille ou empreinte contradictoire | garde source et Linux exact prouvés ; lot Linux/Windows final accepté dans `30710037004` sur `3b8f81f` et lié par `#9` |
| enveloppe Tauri | frontend React, TypeScript et Vite embarqué ; opérations natives nommées ; aucun listener sur l'appareil Console ou chargement de code distant | navigation distante, ressource active externe, appel réseau frontend, accès fichier ou shell non autorisé | Linux LAB prouvé ; installation, lancement, absence de listener et smoke WebView2 Windows exécutés dans `30710037004` sur `3b8f81f` |
| origine Console–Controller | TLS 1.3 sur l'origine exacte avec certificat serveur, identité d'appareil et session humaine attendus | HTTP, mauvais nom, CA, port, query, fragment, redirection, proxy, certificat inconnu, révoqué ou d'un autre Controller | planifié, non exécuté |
| API métier | initialisation unique, lecture de l'infrastructure, lecture des machines et rattachement idempotent d'une machine enrôlée | méthode, route, type, `Accept`, schéma, doublon, casse, seconde valeur, taille, délai ou concurrence hors borne | planifié, non exécuté |
| enveloppe d'erreur Console–Controller | combinaison statut/code issue de la liste fermée, `request_id` canonique et seul `429` portant `Retry-After` borné ; libellé local choisi depuis la route et le code | statut/code inconnu ou croisé, champ supplémentaire, identifiant invalide, cause interne, corps hostile ou `Retry-After` absent, non canonique ou hors borne ; réponse entière refusée | planifié, non exécuté |
| séparation des infrastructures | Controller A ne rend et ne rattache que les machines confirmées par le Relay de A | certificat ou session de B contre A, identifiant de B dans A, `infrastructure_id` divergent et machine non enrôlée | planifié, non exécuté |
| VM hostile sur le même réseau | l'API nominale reste disponible après chaque tentative et l'inventaire demeure identique | accès sans certificat, appel direct du Relay et croisements Controller, session, infrastructure et machine | planifié, non exécuté |
| coffre Stronghold | même format et dérivation Argon2id sous Linux et Windows ; changement de phrase publié atomiquement après validation du nouveau coffre ; aucune permission ou API JS Stronghold ; clés Ed25519 utilisées dans le coffre et clé P-256 déchiffrée seulement dans un tampon Rust effaçable | coffre absent, déplacé, tronqué, altéré ou d'une version inconnue, sel recréé ou paramètres KDF divergents, helper par défaut, mauvaise phrase, DACL ouverte, héritée, lien dur ou point de réanalyse ; crash à chaque étape du changement de phrase laissant l'ancien coffre utilisable, compartiment A substitué dans B, accès frontend ou clé/session recherchée en clair | Linux prouvé ; tests natifs ACL Windows exécutés dans `30710037004` sur `3b8f81f` ; matrice hostile de persistance encore distincte |
| preuve humaine locale | phrase saisie puis effacée, challenge de 32 octets consommé une fois avant deux minutes et signé par la clé humaine du Controller choisi | rejeu, expiration, challenge d'un autre Controller, clé publique ou signature inconnue, phrase, clé dérivée, clé privée ou session rendue par IPC | planifié, non exécuté |
| phrase et récupération hors ligne | six mots uniformes de la liste et du SHA-256 épinglés, code global canonique de 256 bits affiché et confirmé une fois, vecteurs HKDF identiques Linux/Windows et clés distinctes par Controller | entrée brute ou normalisée surdimensionnée, séparateur, remplissage ou bits Base32 non canoniques, liste, SPKI, sel, époque ou compartiment substitué ; secret retrouvé dans stockage Web, URL, journal, presse-papiers automatique ou capture produite par la Console/LAB | planifié, non exécuté |
| listener temporaire `9444` | socket ouvert par l'autorité locale sur l'adresse privée exacte pour une seule fenêtre et fermé après le `PUT` qui livre le candidat, dix minutes, cinq preuves authentifiées ou redémarrage ; certificat serveur épinglé et aucune route métier | port ouvert hors fenêtre, faux nom, CA ou certificat, HTTP, proxy, route métier, `window_id`/code absent, faux, expiré ou croisé sans consommation de la transaction ; requête sans code tentant de consommer le budget ; deux VM avec le bon code dont une seule gagne ; code connu fermant la fenêtre après cinq preuves invalides, risque de déni de service rendu visible | planifié, non exécuté |
| appairage Console et récupération | identifiants attribués par la bonne autorité, CSR et possessions des nouvelles clés humaine et de récupération prouvés ; ancienne clé de récupération autorisant le remplacement ; candidat sans droit métier puis activation atomique | fenêtre croisée, transaction, `device_id`, CSR, clés, sel ou époque substitués, point P-256, usage X.509 ou signature invalide, candidat sur route métier, crash et perte de chaque réponse avant ou après commit | planifié, non exécuté |
| certificat d'appareil | certificat P-256 `clientAuth` de 180 jours, SAN exact, état actif revérifié à chaque requête et avertissements J-30/J-7 | mauvaise CA, SAN, EKU, série, algorithme, certificat expiré, inconnu ou révoqué, y compris sur connexion TLS persistante | planifié, non exécuté |
| rotation d'appareil et reçus | candidat idempotent puis activation avec le nouveau certificat ; ancien seul actif avant le commit, nouveau seul actif après ; reçu exact rejouable après réponse perdue et redémarrage | challenge déjà consommé avant recherche du candidat, activation répétée avec contenu changé, reçu au-delà de 24 h, candidat expiré, ancien certificat après activation ou deux certificats métier simultanés | planifié, non exécuté |
| session humaine | jeton opaque de 32 octets lié à l'humain, l'appareil, le Controller et l'infrastructure ; 30 min d'inactivité, 8 h absolues, logout et redémarrage | jeton croisé, expiré ou rejoué ; réponse contenant le jeton perdue puis remplacée ; challenge concurrent différent ; refus prolongeant l'inactivité ; délais 1/2/4/8/16 s puis blocage de 5 min au cinquième échec | planifié, non exécuté |
| incident de récupération | deux copies du nouveau code confirmées, ancienne et nouvelle conservées hors ligne, rotation et reprise après crash suivies séparément sur chaque Controller avec ancienne preuve, nouvelle possession, session et challenge humain frais | remplacement avec seule session, crash au milieu du parcours, ancien code après commit, contenu changé sous le même identifiant, reçu perdu ou succès global annoncé malgré un Controller en échec | planifié, non exécuté |
| séparation des autorités d'authentification | autorité TLS serveur, émission d'appareil, Daemons et lecteur Controller–Relay distincts et limités à leur usage | certificat ou CA d'une classe présenté dans une autre, remplacement de la SPKI serveur sans réinitialisation locale et chaîne valide mais identité absente du registre | planifié, non exécuté |
| filtre réseau du lecteur Relay | listener `8444` lié seulement à l'adresse privée exacte ; règle `nftables` autorisant l'interface et l'IP source provisionnées du Controller, `drop` silencieux ailleurs ; compteurs et journal local agrégé borné ; `8443` reste l'ingestion distincte | scan depuis une VM externe et une VM voisine, autre interface, sous-réseau ou IP source ; absence de réponse mais état `filtered` possible, compteurs bornés exacts ; tentative d'usurpation de l'IP autorisée ensuite arrêtée par mTLS | planifié, non exécuté |
| identité et rotation du lecteur Relay | TLS 1.3 mTLS, CA Ed25519 serveur et cliente dédiées à l'infrastructure, nom et URI SAN exacts, feuille de 180 jours, manifeste de 1..4 Kio revérifié à chaque requête ; fermeture de `8444`, publication locale atomique des deux bundles puis recoupement avant réouverture | absence de certificat, certificat Daemon, CA, nom, URI, EKU, série, empreinte, période, état révoqué, Controller ou infrastructure croisés, y compris sur TLS persistant ; crash avant et après chaque publication locale, un seul hôte tourné, deux certificats actifs ou réouverture avant recoupement | planifié, non exécuté |
| migration et liaison d'infrastructure Relay | `controller_id` et `infrastructure_id` UUIDv4 immuables générés par le Controller puis importés explicitement ; registre Daemon schéma 2 de 0..64 machines, tableau vide inclus, migré atomiquement sous 16 Kio ; ensemble des `machine_id` seulement croissant, sortie par révocation ; même `infrastructure_id` partout et même `controller_id` dans manifeste, certificat, Controller et réponse | schéma 1, suppression, réactivation, réutilisation ou 65e identité refusée, candidat partiel, registre copié d'une autre infrastructure, identifiant absent, régénéré au restart ou divergent ; au démarrage `8444` reste fermé, au reload l'ancienne politique reste active, et l'ingestion `8443` saine demeure disponible | planifié, non exécuté |
| API lecteur `GET /v0/snapshot` | unique GET sans corps ni query, schéma et erreurs à liste positive, vue atomique triée du registre et du dernier état, tableau réellement vide distinct d'une machine avec `observation: null`, 8 192 lacunes acceptées, réponse pré-encodée sous 2 Mio | Host, méthode, route, query même vide, corps, `Content-Type`, `Accept`, champ, casse, doublon, type, UUID, séquence, 8 193 lacunes, collecteur, taille, en-têtes, délai, cinq sockets, treizième connexion ou lecture invalides ; `Content-Length` absent, mensonger ou trop grand ; aucune réponse partielle ni cache remplacé | planifié, non exécuté |
| UTC et reprise du lecteur | dates RFC 3339 nanoseconde en `Z`, âge de transport `snapshot_at - received_at` puis durée monotone ; `snapshot_at` dans `[fin-30 s, départ+30 s]`, écart civil/monotone au plus 1 s ; dernier cache publié atomiquement et marqué indisponible après panne ou restart | fuseaux différents représentant le même instant, âge négatif, Relay à `-30 s`, `-30 s - 1 ns`, `+30 s`, `+30 s + 1 ns`, saut d'horloge inférieur, égal ou supérieur à 1 s, `observed_at` Daemon ancien restant non autoritaire, Relay arrêté, réponse perdue, réutilisation avant 5 s, délais `1/2/4/8/16/30 s` tirés dans `[80 %,100 %]`, succès remettant le compteur à zéro, cache ancien ou rattachement d'une machine révoquée tentant d'autoriser un PUT | planifié, non exécuté |
| autorité des états Controller | compte dynamique non-root sans capacité, répertoire privé `0700`, `inventory.json` `0600` d'au plus 64 Kio et `relay-cache.json` `0600` d'au plus 2 Mio ; inventaire de 0..64 machines séparé du cache et des états P4 | lien symbolique ou dur, fichier non régulier, propriétaire ou mode incorrect, fichier absent, vide, tronqué, corrompu, surdimensionné, champ ou version inconnue ; aucun UUID régénéré, inventaire vide fabriqué ou donnée P4/cache promue en autorité métier | planifié, non exécuté |
| publication et révision de l'inventaire | candidat complet validé et préencodé, temporaire dans le même répertoire, `fsync`, `rename`, `fsync` du répertoire puis publication mémoire ; initialisation, rattachement et renommage incrémentent une révision `uint64`, rejeu exact sans incrément | crash avant et après chaque étape, échec disque, temporaire hostile, deux mutations concurrentes et saturation de révision ; ancienne autorité cohérente, aucune réponse réussie avant durabilité et aucune correction silencieuse des métadonnées dangereuses | planifié, non exécuté |
| ordre et non-régression du cache | nouveau rattachement persistant d'abord le snapshot P5 frais puis l'inventaire ; identifiants et machines conservés, `active` pouvant seulement devenir `revoked`, observation et séquence progressant, lacunes connues conservées | échec entre les deux publications, cache absent ou corrompu, machine omise ou réutilisée, réactivation, observation devenue `null`, séquence décroissante, même séquence au contenu différent, lacune supprimée ou cache d'une autre infrastructure ; inventaire inchangé et lecture `unavailable` | planifié, non exécuté |
| projection et fraîcheur Console | uniquement les machines attendues triées ; `relay_status`, enrôlement, `observation_status` et continuité séparés ; `recent` jusqu'à 90 s incluses, `old` au-delà, écart déclaré supérieur à 30 s signalé ; résumé exact de toutes les lacunes et réponse complète sous 128 Kio | âges `89,999999999`, `90` et `90,000000001` s, écart `observed_at`/`received_at` à 30 s puis `30 s + 1 ns`, Relay indisponible, horloge non fiable, restart avec ou sans cache, observation absente, révocation et lacune combinés ; somme ou bornes incohérentes, overflow, 64 machines maximales, 128 Kio + 1 refusé avant premier octet, aucune troncature, pagination ou exposition des 2 Mio bruts | planifié, non exécuté |
| libellés métier Unicode | UTF-8 strict jusqu'à 256 octets inclus avant et après NFC, 1 et 80 valeurs scalaires, lettres `L*`, marques `M*` après lettre ou marque, chiffres `Nd` et ponctuation ASCII décidée ; composé/décomposé idempotents, casse significative, doublons entre machines sans fusion, même corpus côté Controller et Console Linux/Windows | UTF-8 ou substitut invalide, 257 octets, 0 ou 81 scalaires, marque initiale, espace initial/final ou doublé, contrôle, format, bidi, invisible, séparateur de ligne, symbole, emoji, slash, antislash, chevron, privé ou non assigné ; bypass du frontend et réponse Controller hostile refusés sans mutation ni HTML actif | planifié, non exécuté |
| tokens et ressources visuelles | palette sémantique claire et sombre, échelle `rem`, Inter et IBM Plex Mono embarquées avec licences et empreintes, seuls glyphes Lucide utilisés présents ; contrôle statique interdisant couleurs, fontes, rayons et espacements locaux hors exceptions contractées | ressource distante, fonte absente, token inconnu, couleur de statut directe, icône seule ou mélange de jeux détectés ; build et vue nominale restent inchangés après le refus | planifié, non exécuté |
| vues et hiérarchie | exactement sept vues ; sélecteur d'infrastructure global puis `Synthèse`, `Parc`, `Observations` et `Profil et sessions` ; Controller seulement contextuel, Relay indisponible comme transport et aucune machine Relay synthétique | rubrique Controller ou Sécurité générique, badge de placement Relay non fourni par l'API, score de santé inventé, historique ou action machine apparaissant dans le frontend | planifié, non exécuté |
| responsive Linux et Windows | mêmes composants à `1280 x 800` et `640 x 560`, fiche contextuelle refluée, navigation compactée et parc transformé en cartes ; captures comparables issues des deux artefacts | largeur ou hauteur inférieure refusée, zoom texte 200 %, libellé maximal, 64 machines, erreur longue bornée et états combinés sans chevauchement, texte coupé ni défilement horizontal obligatoire | Linux LAB éprouvé ; smoke WebView2 Windows borné exécuté ; comparaison exhaustive encore planifiée |
| accessibilité et contenu hostile | clavier seul, ordre et retour du focus, contraste texte `4.5:1`, grand texte et composants `3:1`, cible de `2.75rem`, mouvement réduit, statuts par texte et icône ; données Controller injectées par nœuds texte | focus masqué ou perdu, piège clavier, couleur ou icône seule, HTML, style, URL, attribut, script ou chaîne bidi hostile tenté depuis les libellés et erreurs sans interprétation active | planifié, non exécuté |
| session et changement de contexte | une lecture initiale à l'entrée d'une vue puis actualisation explicite ; changement d'infrastructure annulant les requêtes et purgeant les données précédentes | polling de fond prolongeant l'inactivité, réponse tardive de A rendue après passage à B, état, erreur, identifiant ou session de A restant visible dans B | planifié, non exécuté |
| cardinalité `v0.0.3` | exactement un humain et un appareil Console actifs par Controller, plusieurs Controllers restant isolés dans la même Console | second appairage actif sans récupération, deux certificats métier actifs dans un Controller ou partage d'une clé/session entre Controllers | planifié, non exécuté |

### Ordre des couches de preuve

Le pilote LAB Linux garde huit phases nommées : inventaire et verrou, snapshots et
lot Git, contrôles puis build, installation et interface Linux, nominal
multi-VM, hostile, réaffirmation et nettoyage, puis autorisation de préparer
le candidat natif final. Chaque phase publie son statut et sa durée ; un échec
bloque les suivantes sauf le nettoyage. Le `.deb` est sorti du runner de build
avec son empreinte avant le retour au snapshot runtime, puis réinjecté et
vérifié.

La matrice native manuelle reprend la même révision et le même verrou frontend.
Le runner CI `windows-2025` construit nativement le `.msi` sous MSVC/WiX avec
un certificat synthétique éphémère, vérifie les signatures horodatées, installe
puis lance la Console réelle et produit son smoke WebView2. Le runner Linux
fait de même pour le `.deb` et WebKitGTK. Cette matrice ne crée ni Controller,
ni Relay, ni Daemon ou réseau produit ; aucune réussite native ne remplit une
case multi-VM et aucune réussite Linux ne remplit une différence Windows.

La préparation du 20 juillet 2026 a compilé isolément le module ACL avec
`windows-sys 0.61.2` pour la cible `x86_64-pc-windows-msvc` après correction de
deux imports Win32. Deux tentatives de contrôle croisé de toute la Console ont
d'abord été tuées par la limite de 2 Gio du runner, puis, après ajout d'un swap
temporaire, se sont arrêtées dans le build tiers `libsodium-sys-stable` : son
script Autotools croisé a choisi une branche Unix incompatible avec MSVC. Cet
incident ne valide ni n'invalide le produit Windows ; le build complet et les
tests ACL restent volontairement confiés au runner Windows natif.

Le contrôle YAML de la matrice, les 23 tests du garde Plumber et
`tools/check-docs` avaient réussi statiquement avant la première publication.
Le run `30700406219` a depuis exécuté sur GitHub le workflow à trois jobs et huit
références d'action, y compris l'action Plumber et son garde indépendant. Le
rejeu LAB historique de `prove-generic-ci` reste une preuve séparée de transit
et de nettoyage ; il ne remplace pas ce run hébergé.

La VM hostile partage volontairement le réseau LAB de la cible afin de prouver
que la connectivité seule ne vaut ni identité d'appareil, ni identité humaine,
ni appartenance à l'infrastructure. Pour `8444`, une première phase vérifie le
refus réseau depuis `lab-machine-2` ; une seconde arrête le lecteur légitime et
atteint la frontière applicative depuis l'IP exacte de `lab-coordinateur`, mais
sans le bon certificat, afin de prouver que le filtre IP ne remplace pas mTLS.
Chaque phase réaffirme ensuite l'état nominal et le nettoyage attendu.

## Matrice V1 planifiée — amorçage et première action

Cette matrice projette les contrats désormais décidés dans
[l'amorçage du Controller](../architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md)
et la [roadmap](../objectifs/v1/ROADMAP.md). Le bornage IPC #43, le gate ELF qui
choisit un helper séparé, sa fondation fail-closed, son lancement parent et le
premier consentement GTK3 sans secret ont reçu une preuve Linux le 2 août 2026,
conservée dans le
[rapport LAB dédié](../lab/v1-bootstrap-ipc-linux.md). Les autres scénarios
restent planifiés ; ce passage ne prouve ni une saisie secrète, ni son
équivalent Windows, ni une connexion SSH.

Le workflow natif reste volontairement déclenché par `workflow_dispatch`, selon
le [contrat CI](CI.md). Il est configuré pour exécuter tout le workspace et les
deux scénarios Xvfb, mais aucun run GitHub de ce diff local ne leur est encore
attribué ; la preuve ci-dessous est celle du LAB exact.

La décision documentaire #44 fixe le canal à construire, mais n'exécute aucun
scénario runtime. Le bornage du processus et de son IPC appartient à #43, la
surface de consentement native à #45, puis l'accès SSH personnel à #42. Leurs
preuves Linux et Windows devront reprendre les lignes correspondantes ci-dessous
avec des secrets exclusivement synthétiques.

| Frontière | Nominal à automatiser | Refus hostile à automatiser | État |
|---|---|---|---|
| lot Console et serveur | installateur contenant l'Assistant, l'unique `.deb` Debian 13 `amd64`, ses définitions statiques et le manifeste signé exact ; signature, cible, version, taille, SHA-256 et dépendances hors ligne vérifiés avant privilège ; `/usr/lib/your-cloud/your-cloud` `root:root` `0755` sans setuid, setgid ni capacité et exactement trois unités `root:root` `0644` inactives sous `/usr/lib/systemd/system` ; état propre à la machine géré par l'Assistant ; binaire installé et vérifié avant la clé forcée ; retour à l'absence ou à la version antérieure avant transfert d'autorité ; entrée Auxiliaire initiale en lecture seule et en refus de mutation | paquet ou manifeste altéré, cible, version, taille ou empreinte divergente, dépendance exigeant le réseau, fichier ou unité supplémentaire, propriétaire ou mode divergent, setuid, setgid, capacité ou unité activée par l'installation, script mainteneur interactif ou activant un rôle, secret ou configuration propre à une machine dans le paquet, état à demi configuré présenté comme sain, retrait aveugle après coupure, binaire privilégié téléchargé à la volée, clé activée avant le binaire, mutation acceptée avant son contrat, `arm64` accepté sans preuve ; certificat Windows synthétique présenté comme signature publique | planifié, non exécuté |
| helper natif et cycle de vie | binaire compagnon `your-cloud-native-bootstrap-assistant` lancé une fois par consentement avec la garde `--native-bootstrap-assistant`, graphe autonome sans Tauri, Wry, Tao, WebKit ou JavaScriptCore ; pipes anonymes typés portant seulement le périmètre public immuable et des états expurgés ; expiration native monotone fixe de 300 secondes ; fermeture des enfants après succès, refus, annulation, timeout, EOF, mort du parent et crash | durée fournie ou prolongée par le frontend, dépendance directe, transitive ou chargée dynamiquement vers WebKit/JavaScriptCore, seconde WebView, secret dans l'IPC frontend, arguments, environnement, URL, descripteur hérité inattendu, fichier temporaire, journal ou dump ; helper ou enfant survivant, état réutilisé entre deux opérations | Linux partiel prouvé : gate Console, crate autonome, framing, échéance parent absolue, watchdog, groupe de processus, FD héritable hostile, mort du parent, lancement Console, récolte autonome sans attente non bornée, refus de relance si le nettoyage n'est pas prouvable, GTK3 sans secret, Cargo, `DT_NEEDED`, transitif, mappings et SBOM ; stdin coopératif, descendants futurs, Windows, packaging et secrets restent ouverts (#43 et #45) |
| moteur SSH et agent personnel | `russh 0.62.4` épinglé, algorithmes sur liste positive, clé d'hôte exacte ; socket Unix absolu appartenant à l'utilisateur courant sous Linux ou pipe `\\.\pipe\openssh-ssh-agent` sous Windows ; une clé et un budget fini de signatures pour l'authentification exacte | clé d'hôte inattendue, DSA, DES, compression ou `ssh-rsa` SHA-1, autre endpoint d'agent, deuxième signature, message de signature libre, TOFU, écriture de `known_hosts`, shell, PTY, SFTP, X11, redirection, transfert d'agent ou commande générale | planifié, non exécuté (#42) |
| repli par fichier de clé | sélecteur natif ouvrant sans réécriture une clé `OPENSSH PRIVATE KEY` chiffrée bcrypt + `aes256-ctr`, Ed25519 ou RSA d'au moins 3072 bits ; octets, passphrase et clé déchiffrée zéroïsés sur sortie contrôlée | clé en clair, RSA trop courte, PKCS#1, PKCS#8, SEC1, PPK, autre KDF ou chiffrement, fichier trop grand ou remplacé pendant l'ouverture, passphrase ou clé retrouvée dans un état persistant ou un artefact | planifié, non exécuté (#42 et #45) |
| déclaration et audit | endpoints fournis un par un, clé d'hôte confirmée, audit SSH strictement en lecture seule, Debian 13 `amd64`, rôles et ressources rendus ; chaque endpoint et sa clé d'hôte revérifiés depuis le Controller avant mutation des cibles | scan du LAN, plage ou fournisseur, clé d'hôte acceptée silencieusement, mutation pendant l'audit, cible ou rôle incompatible proposé, cible joignable depuis le laptop mais pas depuis le Controller | planifié, non exécuté |
| consentement privilégié | dialogue GTK3 direct sous Linux et Win32 modal `EDIT | ES_PASSWORD` sous Windows, répétant empreintes, étape, actions et expiration ; `sudo -n` tenté d'abord, puis un unique envoi sans PTY à `sudo -k -S` pour le chemin absolu autorisé ; accès `root` explicite | secret livré par IPC, cible, action ou expiration substituée, essai `root` implicite, réutilisation ou retry, prompt distant inattendu, shell ou interpolation, politique distante non bornable ou journalisation d'entrée susceptible de capturer le mot de passe | consentement GTK3 initial sans secret prouvé sous Xvfb : scope répété, refus, fermeture, expiration et autorisation sans faux succès ; Win32, secrets et privilège restent planifiés (#45 puis #42) |
| effacement et anti-dump | buffers du helper zéroïsés ; sous Linux mort avec parent, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlock` et `MADV_DONTDUMP` disponibles ; sous Windows Job Object, `VirtualLock` et exclusion Windows Error Reporting disponibles ; limites observées et publiées | faux résultat « aucun secret possible » après crash, core dump ou fichier d'échange sans inspection ; descendant survivant ; copie propre au produit retrouvée après sortie contrôlée ; root/admin, accessibilité hostile ou dump noyau présentés comme couverts | planifié, non exécuté (#43, #45 et #42) |
| placement et autonomie | Controller privé normalement allumé, cohabitation isolée sur petite infrastructure et recommandation dédiée lorsque taille ou risque augmentent ; fermeture de la Console sans arrêt du contrôle ou des services ; perte du Controller sans arrêt des services des autres hôtes et interruption colocalisée rendue visible | Controller permanent sur le laptop ou proposé par défaut sur le VPS public ; partage de compte, secret, répertoire ou budget entre rôles ; promesse de continuité d'un service placé sur l'hôte perdu | planifié, non exécuté |
| identités SSH par machine | paire différente sur chaque machine, clé privée root-owned fournie au seul Controller par credentials systemd, clé publique vérifiée avant transfert d'autorité | même clé sur deux machines, clé d'une machine acceptée par une autre, clé privée visible à la Console ou à l'Agent, clé personnelle retirée | planifié, non exécuté |
| commande forcée Auxiliaire | compte technique verrouillé sans mot de passe ; fichier de clés, parents et chemin absolu du binaire root-owned et non inscriptibles ; restrictions SSH et élévation exacte avec environnement réinitialisé ; plan typé sur stdin | option SSH retirée, répertoire remplaçable, binaire ou parent inscriptible, shell, PTY, SFTP, rc, X11, transfert, `environment=`, `SETENV`, règle `sudo` générale, sous-commande, argument, chemin ou opération libre | planifié, non exécuté |
| approbation et anti-rejeu | cœur natif signant l'enveloppe canonique plan + rollback ; clé publique, infrastructure, machine, époque et successeur exact de la séquence vérifiés localement ; séquence consommée avant mutation et persistante après redémarrage | signature libre accessible au frontend, plan forgé ou altéré par un Controller compromis, mauvaise clé ou époque, séquence sautée, ancienne, concurrente ou rejouée avant et après restart | planifié, non exécuté |
| récupération de Console et actions | rotation du certificat avec même clé humaine conservant l'ancre ; nouvelle clé humaine verrouillant les actions jusqu'à rotation cible par cible via l'Assistant et l'accès personnel | Controller tournant seul l'ancre, code de récupération signant une action, ancienne et nouvelle clés humaines acceptées ensemble, action disponible pendant une rotation partielle | planifié, non exécuté |
| remplacement du Controller | choix explicite, nouvelle association Console, Agents compatibles réutilisés, lecteur Relay limité au nouveau Controller, nouvelle époque et toutes identités exposées tournées avant retrait des seules anciennes identités marquées | remplacement automatique sur panne ambiguë, Controller compromis non isolé ou hôte non assaini, ancien lecteur/session/clé encore actif, Controller sain écrasé, clé personnelle ou inconnue retirée, ancienne identité retirée avant preuve de la nouvelle | planifié, non exécuté |
| plan et sonde OCI | plan et rollback exacts approuvés, registre et digest épinglés, sonde locale Podman rootless/Quadlet ; premier passage `changed=true`, nouveau plan demandant le même état `changed=false`, retrait absent `changed=false` | plan altéré, expiré ou rejoué, digest flottant, registre, volume, port, privilège, système d'init ou cgroup hors contrat ; dérive corrigée silencieusement ou réécriture/redémarrage inutile | planifié, non exécuté |
| échec, reprise et rollback | échec contrôlé tentant le rollback approuvé et borné ; échec du rollback rendu partiel ; injection d'une coupure à chaque étape d'amorçage, de rotation et d'action ; reconstruction des états `ancien seul`, `chevauchement borné`, `nouveau seul`, `inconnu` avant nouvelle décision | rollback non approuvé ou touchant une ressource externe, retrait dans un état inconnu, rejeu automatique, succès global inventé après coupure, continuation autonome non contractée | planifié, non exécuté |
| ressources et échelle V1 | CPU, mémoire, processus et disque bornés avec le mécanisme disponible ; destinations, listeners, tailles, concurrences, délais et débits réseau mesurés sur petite machine ; cohabitation puis placement dédié ; scénarios à 1, 2 et 64 machines | dépassement silencieux, OOM ou saturation réseau masqués, limite systemd fictive, 65e machine acceptée dans le format courant, borne de 64 présentée comme limite définitive du produit | planifié, non exécuté |

## Matrice exécutée de `v0.0.2` — orchestration assistée

Cette matrice vient du
[contrat exécutable](../objectifs/v1/CONTRAT-V0.0.2.md). Les résultats du 18
juillet 2026 sont conservés dans le
[rapport LAB](../lab/v0.0.2-observation.md). Les tests Go sont automatiques ;
le cycle multi-VM a été exécuté et affirmé, mais son enchaînement reste assisté
et doit devenir un pilote rejouable.

| Frontière | Résultat exécuté | Automatisation restante |
|---|---|---|
| provenance commit → artefact | le commit final de l'implémentation `2f93f71` a été exporté directement par Git le 19 juillet, son lot transféré avec la même empreinte, puis le gate complet a reconstruit l'artefact final `f4a791f8...423d` | intégrer l'export exact, les empreintes et le gate au futur pilote et à son rapport structuré |
| certificats mTLS | nominal et certificats inconnu, révoqué, expiré, mauvaise CA, mauvais usage et mauvaise association refusés | intégrer les commandes vivantes au pilote unique |
| endpoint Relay | HTTPS exact ; HTTP, mauvais nom/CA, chemin et query refusés ; port, fragment et redirection couverts en tests Go | rejouer toute la matrice en réseau vivant |
| profil `host-health.v1` | trois collecteurs réels ; profil, champ, version et entrée libre refusés en tests Go | intégrer coûts et schémas au rapport structuré |
| accusé durable | retrait après accusé, rejeu exact accepté, collision refusée et échec de persistance injecté sans faux état mémoire | porter ensuite l'injection au pilote multi-VM |
| tampon | Relay indisponible, 120 éléments, 46 272 octets, lacune `15..30`, redémarrage et reprise | automatiser l'accélération sans boucle manuelle |
| diagnostic administratif local en `root` | nominal, indisponible, saturé et repris ; format, sujet et chemin libres refusés | capturer automatiquement les quatre états |
| cycle systemd | rôles séparés, redémarrages, rollbacks d'artefact invalide, gardes processus/listener, retrait, état absent et réinstallation finale | intégrer ces étapes au pilote et lancer le processus hostile avec l'UID du service |

Les mesures LAB ont fixé `64 KiB`, 120 observations et une heure, sous les
plafonds absolus. Les microbenchmarks et leurs limites figurent dans le rapport.
La matrice ne s'étend pas à l'App, Ansible métier, un canal d'action,
l'Auxiliaire, WireGuard, OCI, Proxmox, OpenStack, un worker d'automatisation ou
un projet IaC.

## Archive de couverture du premier contrat

Cette section décrit la preuve historique de présence et les incidents qui ont
fait progresser le banc LAB. Son sender, son serveur HTTP et leurs tests
unitaires ont été retirés du cœur courant afin de ne pas maintenir deux chemins
Daemon–Relay. Les scripts et lots numérotés restent consultables pour relire la
preuve, mais ne constituent plus une suite exécutable contre le binaire actuel.

### Contrôles statiques, tests Go et build

| Contrôle | Assertion | Préparation | Orchestration | Nettoyage | Limite actuelle |
|---|---|---|---|---|---|
| `gofmt -l` vide | automatique | automatique | automatique | sans objet | couvre les sources Go de `cmd/` et `internal/` |
| `bash -n` sur les scripts Bash du lot | automatique | automatique | automatique | sans objet | sélection par shebang dans `tools/` et `tests/`, lots de déploiement LAB compris |
| syntaxe du générateur Python de restitution | automatique | automatique | automatique | automatique | compilation seule de `tests/lab/v0.0.1/report/renderer.py` ; le rendu réel reste vérifié dans `lab-console` |
| résultat structuré Plumber absent, ambigu, incomplet, sauté ou dégradé | automatique | automatique | automatique | automatique | 23 cas de frontière (20 refus, 3 acceptations), liaison au lot et refus intégré d'un tag mutable exécutés dans `lab-console` ; porte finale verte dans `30710037004` sur `3b8f81f`, liée par `#9` |
| contrat `labctl list` humain et TSV | automatique | automatique | automatique | automatique | double `virsh` isolé ; le vrai inventaire reste contrôlé avant mutation |
| `tools/check-docs` sur l'arbre complet | automatique | automatique | automatique | automatique | la cohérence sémantique reste une relecture humaine |
| `go test -count=1 ./...` | automatique | automatique | automatique | automatique | mode `lab` sur `lab-console` root ou mode `ci` sur runner distant non privilégié |
| `go vet ./...` | automatique | automatique | automatique | automatique | intégré à la même entrée source |
| build `CGO_ENABLED=0` de l'unique exécutable | automatique | automatique | automatique | automatique | le lot doit être initialement dépourvu de `dist/` ; le mode CI construit dans un temporaire |
| SHA-256 identique dans le build, sur le VPS et sur la machine LAN | automatique | automatique | automatique | automatique | le résultat structuré conserve l'empreinte exacte du lot exécuté |

Au moment de cette preuve, les tests Go portaient les assertions suivantes :

- `cmd/your-cloud` refuse un rôle absent ou inconnu, les arguments d'un autre
  rôle, un Relay sans candidature et toute adresse d'écoute différente de
  `192.168.242.103:8443`, ainsi que toute autre origine Relay pour le Daemon ;
- `internal/daemon` vérifie le schéma exact envoyé, les seules transitions de
  journal `indisponible` puis `rétabli`, les configurations dangereuses et la
  propagation d'un refus Relay ;
- `internal/presence` refuse les documents non objets ou tronqués, les champs
  absents, dupliqués, inconnus, de casse différente ou de type incorrect, les
  seconds objets, identifiants, versions et horodatages invalides ;
- `internal/relay` vérifie le passage `absent` vers `recent` puis `old`, le tri
  des machines, l'usage de l'heure de réception du Relay et la disponibilité du
  handler après chaque corps hostile ;
- la frontière `POST /v0/presence` refuse contenu absent ou inconnu, identifiant
  mal formé ou non autorisé, champ dupliqué ou de mauvaise casse, second objet,
  type incorrect et corps supérieur à 512 octets ;
- la frontière `QUERY /v0/machines` accepte exactement `{}` en JSON, annonce
  `Accept-Query` et `Cache-Control: no-store`, puis refuse méthode, type,
  `null`, tableau, document tronqué, filtre futur, second objet, partie query
  d'URI et corps supérieur à 32 octets ;
- le manifeste Relay refuse document vide, tableau ou tronqué, champ absent,
  inconnu, de mauvaise casse ou de type incorrect, schéma ou rôle incorrect,
  doublon, second objet, taille excessive, propriétaire non-root, lien
  symbolique, fichier ou répertoire modifiable par d'autres.

### Pilote HTTP vivant

[`tests/lab/v0.0.1/remote/prove-hostile-relay`](../../tests/lab/v0.0.1/remote/prove-hostile-relay)
exécute sur `lab-coordinateur` la matrice vivante `POST` et `QUERY` : schémas,
tailles, méthodes croisées, `Content-Type`, partie query non vide ou vide et
cache interdit. Après chaque refus, il vérifie le même PID, l'exécutable, le
listener exact relié à ce PID et une consultation valide. Chaque appel possède
un délai de connexion de deux secondes et une durée totale de cinq secondes.
Un serveur synthétique muet sur loopback prouve en plus que la borne totale
interrompt réellement un client connecté qui ne reçoit aucune réponse.

| Partie | Niveau actuel | Ce qui manque |
|---|---|---|
| Matrice `POST`, `QUERY` et méthodes croisées | automatique | étendre seulement avec un nouveau cas réellement introduit |
| `Accept-Query` et `Cache-Control: no-store` | automatique | aucun cache intermédiaire réel n'est introduit dans ce palier |
| Unité, PID, exécutable et listener après chaque refus | automatique | les transitions de journal sont comptées dans le cycle multi-VM |
| Préparation de la candidate et de l'origine exacte | automatique | bornée au scénario LAB `v0.0.1` |
| Nettoyage du client | automatique | le Relay reste géré par le cycle multi-VM |

### Placement et cycle multi-VM

[`tests/lab/v0.0.1/prove`](../../tests/lab/v0.0.1/prove) est l'unique entrée du cycle.
Le laptop ne fait que lire Git, fabriquer depuis une liste positive Git
l'archive non sensible, calculer ses empreintes et piloter `labctl` ; tout code
produit, test, build, HTTP et systemd s'exécute dans le LAB. L'empreinte du lot
est comparée après transit avant extraction. Une erreur après mutation déclenche
un retrait vérifié sur les trois cibles ; un succès réinstalle l'état final
annoncé.

| Scénario réellement couvert | Assertions | Préparation | Orchestration | Nettoyage |
|---|---|---|---|---|
| garde `labctl list`, origine, gabarit, topologie et adresses interdites | automatique | sans objet | automatique | automatique |
| verrou LAB exclusif attribué au run, refus sans vol du verrou et libération vérifiée | automatique | automatique | automatique | automatique |
| build unique, copie et comparaison des trois empreintes SHA-256 | automatique | automatique | automatique | automatique |
| installation du Daemon seul sur le LAN, puis Daemon et Relay parallèles sur le VPS | automatique | automatique | automatique | automatique |
| unités distinctes, PID et UID dynamiques distincts, un processus par rôle et listener exact | automatique | automatique | automatique | automatique |
| refus Relay sans candidature sur le LAN avant ouverture de `8443` | automatique | automatique | automatique | automatique |
| chaque couple hôte/identifiant autorisé et écoute locale, wildcard ou mauvais port | automatique | automatique | automatique | automatique |
| manifeste `0666` jusqu'à `start-limit-hit`, Daemon indépendant, aucun listener puis `reset-failed` | automatique | automatique | automatique | automatique |
| deux machines `recent` malgré l'écart entre les horloges | automatique | automatique | automatique | automatique |
| arrêt d'un Daemon : lui seul devient `old`, puis revient `recent` | automatique | automatique | automatique avec attente bornée | automatique |
| arrêt des deux Daemons et redémarrage Relay : deux états `absent`, puis retour à `recent` | automatique | automatique | automatique | automatique |
| un seul log d'indisponibilité puis un seul de rétablissement, aucun succès chaque seconde | automatique | automatique | automatique | automatique |
| Relay synthétique hors unité : `disable-relay` refuse et conserve le manifeste | automatique | automatique | automatique | automatique après arrêt explicite du PID |
| Daemon synthétique hors unité : `remove-agent` refuse et conserve l'artefact | automatique | automatique | automatique | automatique après arrêt explicite du PID |
| premier lot ou remplacement invalide : retour à l'état absent ou restauration de l'artefact et des deux rôles | automatique | automatique | automatique | automatique |
| désactivation Relay : port, unité, configuration et manifeste absents, Daemon VPS inchangé | automatique | automatique | automatique | automatique |
| retrait sur les trois machines : aucun processus, unité, binaire ou configuration | automatique | automatique | automatique | automatique |
| réinstallation finale : état annoncé et deux présences `recent` | automatique | automatique | automatique | état conservé volontairement |

### Restitution visuelle

Le Markdown et la page HTML sont générés dans `lab-console` depuis les seuls
champs autorisés du résultat P1. La page est servie sur `127.0.0.1:18080` sous
`nobody`, vérifiée par HTTP puis capturée par Chromium headless. Un scénario
injecte aussi un échec de capture et affirme l'arrêt du serveur avant le rendu
nominal.

| Partie | Niveau actuel | Limite |
|---|---|---|
| production des tableaux Markdown et de la page HTML | automatique | le schéma et les champs sont bornés ; le sens reste relu par une personne |
| démarrage et arrêt du serveur temporaire LAB | automatique | identité, listener et absence finale sont affirmés, y compris après capture en échec |
| ouverture et capture Chromium headless | automatique | Chromium est un prérequis du runner LAB, pas une dépendance du produit |
| validation du contenu servi | automatique | une capture prouve un rendu, jamais le comportement du produit |

## Refus attendus, distincts des incidents

Un refus attendu est un test réussi : l'entrée hostile est volontaire et le
système doit échouer fermé sans élargir son autorité. Il ne doit pas être classé
comme incident du produit.

| Refus provoqué | Résultat attendu |
|---|---|
| mode Relay sans manifeste candidat | code de sortie `2`, aucun listener |
| activation Relay sur une machine autre que `lab-coordinateur` | refus avant effet |
| identité autorisée mais différente du nom d'hôte | installation refusée avant mutation |
| adresse d'écoute autre que `192.168.242.103:8443` | refus avant lecture de la candidature et avant écoute |
| manifeste mal formé, surdimensionné, non-root, modifiable ou symbolique | Relay en échec, Daemon indépendant, aucun listener |
| présence absente, mal formée, non autorisée, dupliquée, de mauvaise casse, inconnue ou trop grande | `400` ou `413`, puis Relay toujours disponible |
| `GET /v0/machines`, type absent ou incorrect, `QUERY` non vide, multiple ou trop grande | `400`, `405`, `415` ou `413`, puis `QUERY {}` toujours disponible |
| processus Relay hors unité pendant `disable-relay` | code `1`, manifeste et fichiers conservés |
| processus Daemon hors unité pendant `remove-agent` | code `1`, binaire et fichiers conservés |
| redémarrage Relay sans signal reçu | états `absent`, puis `recent` après reprise des Daemons |

## Incidents et difficultés réellement rencontrés

Ces événements étaient inattendus pendant la réalisation ou l'audit. Une
correction locale déjà apportée n'implique pas que sa non-régression soit
automatisée.

| Incident ou difficulté | Cause observée | Traitement appliqué | Garde d'automatisation à ajouter |
|---|---|---|---|
| `tools/labctl list` affichait l'inventaire correct puis quittait avec le code `1` | `virsh domifaddr` rend `1` pour une VM arrêtée sans adresse et interrompait la boucle | une VM arrêtée rend désormais `ips=-`, une erreur d'adresse sur une VM active reste bloquante ; TSV et code `0` sont testés avec un double `virsh` | garde automatique active avant chaque mutation |
| une première archive LAB omettait `tools/labctl`, donc le contrôle documentaire signalait des liens cassés | lot préparé depuis une sélection incomplète de l'arbre | archive reconstruite depuis l'arbre complet | fabriquer le lot depuis une liste traçable et vérifier la présence de chaque cible de lien avant les tests |
| les VM avaient des horloges différentes et `tar` avertissait de fichiers datés dans le futur | décalage d'environ quatre jours sur `lab-machine-1` et de quelques dizaines de secondes entre contrôleur et builder, dont environ 35 secondes mesurées le 17 juillet 2026 | fraîcheur calculée sur l'heure de réception Relay ; avertissement de transport conservé visible | décalage contrôlé de deux jours, état `recent` par réception Relay et restauration automatique prouvés en P1 |
| `gofmt -d` a trouvé un alignement à corriger | formatage non exécuté assez tôt | source reformattée puis contrôle rejoué | exécuter le contrôle de format en première phase et bloquer avant tout build ou déploiement |
| les premières commandes `curl` traversant `labctl ssh` souffraient de guillemets imbriqués | construction distante fragile entre plusieurs shells | requêtes corrigées puis regroupées dans le pilote copié au LAB | transférer un script à arguments bornés ; ne pas construire de JSON dans une commande SSH concaténée |
| le manifeste hostile a épuisé la limite de redémarrage systemd après cinq refus | les échecs répétés laissaient l'unité en `start-limit-hit` après réparation | `enable-relay` exécute désormais `reset-failed` avant relance | événement journalisé, refus avant `reset-failed` et récupération après réinitialisation prouvés en P1 |
| le client vivant envoyait `/chemin` au lieu de `/chemin?` | `curl` normalise un `?` final vide | le pilote force la cible de requête brute avec `--request-target` | le cas vide est vérifié après chaque build au niveau Go et HTTP vivant |
| un cas nommé « Content-Type absent » envoyait en réalité le type formulaire de `curl` | `--data-binary` ajoute un en-tête par défaut | le pilote supprime explicitement cet en-tête | les réponses distinctes `400` absent et `415` non pris en charge sont vérifiées |
| la première readiness transactionnelle pouvait accepter brièvement `/bin/false` | une observation instantanée a croisé un processus voué à mourir | le même PID doit rester `active/running` pendant trois contrôles consécutifs | l'injection du faux artefact appartient désormais au P0 vivant |
| le premier rollback du faux artefact ne relançait pas l'ancien lot | les échecs avaient déclenché `start-limit-hit` | le rollback restaure les fichiers, réinitialise seulement les unités présentes, puis revérifie Daemon et Relay | injection `/bin/false`, état absent initial, empreinte restaurée et deux rôles actifs sont automatiques |
| le premier serveur de preuve visuelle sous `DynamicUser` ne pouvait pas servir correctement le fichier temporaire | isolement de l'utilisateur dynamique et du répertoire temporaire | serveur relancé sous le compte non privilégié `nobody`, puis arrêté et nettoyé | UID 65534, listener loopback et nettoyage après échec de capture prouvés en P2 |
| le retrait pouvait supprimer les fichiers malgré un arrêt ou une inspection incertaine | logique de retrait ouverte sur l'échec | contrôles `stop`, `show`, état, `MainPID`, processus hors unité et port ajoutés ; suppression bloquée au moindre doute | Daemon et Relay synthétiques hors unité, refus et empreintes de fichiers inchangées prouvés en P1 |
| l'identifiant de machine n'était pas lié au nom d'hôte LAB | la liste positive seule n'empêchait pas un identifiant autorisé sur le mauvais hôte | égalité exacte avec le nom d'hôte ajoutée avant installation | matrice de tous les couples entre les trois hôtes et les deux identifiants autorisés prouvée en P1 |
| le Relay pouvait recevoir une autre adresse d'écoute | le port et la cible n'étaient pas figés dans le binaire du palier | adresse exacte `192.168.242.103:8443` imposée | écoute locale, wildcard et mauvais port refusés par activation et binaire vivant en P1 |
| le décodage JSON acceptait des clés dupliquées ou une casse différente | comportement permissif du décodage JSON générique | décodeurs stricts ajoutés pour présence, candidature et requête | conserver la matrice hostile au niveau unitaire et vivant, avec un cas où la seconde valeur serait autorisée |
| le Daemon pouvait produire un log à chaque signal ou tentative | journalisation pensée par événement réseau plutôt que par changement d'état | journal limité aux transitions indisponible/rétabli | zéro ligne en réussite prolongée puis exactement une indisponibilité et une récupération sur les deux Daemons en P1 |
| les appels hostiles `curl` n'avaient pas tous de délai borné | une panne réseau pouvait bloquer le pilote | `--connect-timeout` et `--max-time` ajoutés partout | comptage statique des bornes et destination synthétique muette sur loopback interrompue automatiquement |
| les premiers diagrammes montraient un sens de flux incorrect | confusion visuelle entre placement et destination HTTP | flèches corrigées du Daemon vers le Relay | comparer une source unique de flux aux éditions Markdown et HTML pendant le contrôle documentaire |
| le run `20260717T091821Z-1389363` a échoué pendant la dérive d'horloge et son nettoyage | la synchronisation NTP externe n'est pas revenue dans la fenêtre bornée | l'échec est resté classé `cleanup_failure`, les trois cibles ont été rendues absentes et `clock_restored=false` est resté visible | conserver la dépendance NTP comme incident d'infrastructure ; ne jamais transformer son absence en réussite |
| le retrait de l'identité de transfert pouvait croiser un processus SSH tué mais encore visible dans `/proc` | course entre terminaison, récolte du processus par son parent et `userdel` | contrôle des UID réel et effectif, attente bornée de disparition puis suppression de l'identité ; le run `20260717T093905Z-1478107` a ensuite nettoyé proprement | le nettoyage final doit refuser tant qu'un processus du compte temporaire reste observable |
| le premier run post-réorganisation `20260717T100017Z-1539228` a refusé le lot avant mutation produit | le répertoire de déploiement LAB copié avait conservé le mode `0775`, hors contrat root-owned `0755` | échec classé `infrastructure_failure`, état `not-mutated`, nettoyage et horloge verts ; modes distants normalisés avant les gardes | conserver le refus de permissions trop larges et vérifier le mode du lot avant toute installation |
| les deux premières analyses Plumber n'ont pas trouvé de dépôt Git dans `lab-console` | l'image LAB ne contient pas `git`, alors que Plumber lit trois métadonnées avant les workflows | doublure bornée à l'origin public, la racine temporaire et l'identifiant dérivé du lot ; toute autre commande sort avec `2` | le runner GitHub utilisera le vrai checkout ; la doublure reste limitée à la simulation LAB |
| le run générique `20260717T102446Z-1570931` s'est arrêté sur la mutation hostile | un délimiteur `sed` a été réinterprété pendant le transit SSH | délimiteur sans échappement ambigu puis vérification du rapport `ISSUE-701` ; chemins distants et locaux vérifiés absents après l'échec | la preuve doit attribuer le refus au rapport structuré, jamais au seul code de sortie |
| le premier rejeu de la liste positive finale s'est arrêté avant copie LAB | GNU `tar` traite `--no-recursion` comme une option positionnelle lorsqu'elle suit `--files-from` | toutes les options d'archive précèdent désormais la liste NUL de fichiers | conserver le même constructeur de lot dans les preuves générique et multi-VM ; aucun résultat vert n'est publié après un échec d'empaquetage |
| le téléchargement de Plumber du rejeu `20260717T112941Z-1606633` a dépassé 120 secondes après 14,5 Mio reçus | débit sortant du LAB insuffisant pour le binaire de 32,3 Mio dans l'ancienne fenêtre | code `28` conservé, aucun rapport publié, répertoire et archive distants vérifiés absents ; borne totale portée à 420 secondes | garder version, SHA-256, taille maximale et échéance explicites ; une lenteur réseau reste un échec d'infrastructure, jamais un scan vert |

## Écarts techniques révélés par l'audit statique

Un **audit statique** relit le code sans l'exécuter. Il peut découvrir une
frontière insuffisamment exprimée, mais il ne remplace pas la reproduction dans
le LAB. Les écarts ci-dessous ont été trouvés après la première preuve
`v0.0.1`. Leur état reste visible même lorsqu'une correction et sa revalidation
existent.

Deux notions sont utiles avant de lire le tableau :

- un **cache HTTP** peut conserver une réponse et la réutiliser sans joindre le
  Relay ; `Cache-Control: no-store` lui demanderait de ne pas la stocker ;
- l'**horloge monotone** mesure une durée écoulée sans dépendre des corrections
  de l'heure civile. Go la conserve dans certains `time.Time`, mais une
  conversion prématurée avec `UTC()` la retire ;
- une mise à jour **transactionnelle** ne laisse pas deux versions ou un état
  partiel lorsqu'une étape intermédiaire échoue.

| Priorité avant usage concerné | Écart observé | État actuel | Preuve ou reste |
|---|---|---|---|
| avant d'intercaler l'App, un proxy ou un cache | réponse `QUERY` cacheable | `Cache-Control: no-store` ajouté | en-tête vérifié dans les tests Go, chaque requête saine du pilote et la matrice vivante ; aucun proxy réel dans ce palier |
| avant d'élargir le contrat HTTP | parties query d'URI ignorées | `RawQuery` et `ForceQuery` refusés sur les deux routes | paramètres et `?` vide vérifiés au niveau Go et HTTP vivant |
| avant de donner une valeur opérationnelle au seuil d'âge | conversion UTC prématurée | temps brut conservé pour le calcul, UTC réservé au rendu | recul contrôlé de l'émetteur et saut contrôlé du Relay, fraîcheur monotone et restauration ont réussi dans la référence post-réorganisation |
| avant toute destination autre que le LAB figé | origine Daemon insuffisamment stricte | package et point d'entrée refusent utilisateur, chemin, query, fragment et toute origine autre que l'origine LAB exacte | cas hostiles Go ; la V1 définira son propre endpoint authentifié |
| avant une fonction de mise à jour ou de rollback | installation ou remplacement partiel du lot | staging, restauration des fichiers, états systemd et rôles précédents | `/bin/false` injecté sur état absent puis installé ; absence ou ancienne empreinte et rôles parallèles sont restaurés automatiquement |
| prochaine révision des tests HTTP | méthodes croisées non nommées | `GET /v0/machines`, `POST /v0/machines` et `QUERY /v0/presence` couverts | tests Go et pilote vivant |
| lors de l'automatisation des retraits | la garde `stop_and_disable` est dupliquée dans `disable-relay` et `remove-agent` | les deux copies ont passé les scénarios LAB actuels | extraire seulement lorsque le pilote sait prouver les deux appelants, afin d'éviter leur divergence sans créer une bibliothèque shell prématurée |
| avant deux preuves concurrentes | les chemins temporaires historiques du cycle P1 sont fixes | verrou atomique root-owned avec propriétaire de run exact ; aucun verrou existant n'est volé | libération vérifiée après nettoyage ; un arrêt non rattrapable peut laisser un verrou volontairement visible pour inspection |
| avant de donner autorité aux états observés | l'assertion Relay cherchait une sous-chaîne JSON et le listener n'était pas lié au PID de l'unité | parseur JSON à schéma exact, doublons et machine supplémentaire refusés ; PID unique extrait de `ss -ltnp` | fixtures hostiles du parseur puis document vivant exact sur les deux machines |

La [RFC 10008](https://www.rfc-editor.org/rfc/rfc10008.html) est la source du
contrat HTTP `QUERY` : méthode sûre et idempotente, contenu typé obligatoire,
réponse cacheable et partie query de l'URI intégrée à la ressource ciblée.

## Automatisation historique du premier contrat

### P0 historique — résultat reproductible et fiable

1. `labctl list` possède un code de sortie fiable et une sortie TSV
   stable contenant origine, gabarit, topologie et adresses ; le pilote doit
   s'arrêter avant mutation si cette garde n'est pas entièrement verte.
2. `tests/checks/source-v0.0.1` est l'entrée source commune. Le mode `lab`
   prépare le lot dans `lab-console` ; le mode `ci` utilise un runner distant
   non privilégié. Les deux lancent format, syntaxe shell, documentation, tests
   Go sans cache, `go vet` et build statique, publient le détail des étapes et
   préservent le premier code d'échec.
3. Cette entrée refuse un mode implicite, un mode `lab` qui n'est pas root sur
   `lab-console`, un mode `ci` root ou hors GitHub Actions, un lien
   documentaire absent et tout lot qui ne produit pas l'unique artefact Go
   attendu à l'emplacement propre au runner.
4. Le pilote HTTP vivant couvre la matrice `POST` et `QUERY`, avec une
   vérification automatique de l'unité, du PID, du listener et d'une requête
   valide après chaque refus.
   Cette matrice couvre aussi le cache interdit, les parties query d'URI et les
   méthodes croisées nommées par l'audit statique.
5. `tests/lab/v0.0.1/prove` orchestre le cycle `v1-full` depuis un état connu :
   installation, placement, processus parallèles, transitions
   `recent`/`old`/`absent`, redémarrages, retrait, contrôle d'absence puis
   réinstallation finale.
6. Le cycle possède un nettoyage garanti qui refuse de déclarer le LAB
   propre tant qu'un PID, une unité, un listener ou un fichier qui devrait être
   absent subsiste.

### P1 historique — régressions automatisées

1. Le manifeste invalide atteint la limite de démarrage ; le manifeste réparé
   reste refusé avant `reset-failed`, puis le Relay récupère.
2. Des Daemon et Relay synthétiques hors unité bloquent le retrait ; les
   empreintes et métadonnées des fichiers gérés restent identiques avant arrêt.
3. Les couples hôte/identifiant, les trois classes d'écoute interdites, les
   propriétaires, permissions et protections systemd sont affirmés.
4. L'horloge de l'émetteur est reculée de deux jours puis celle du Relay avancée
   de deux jours ; la fraîcheur reste fondée sur la réception et la durée
   monotone, puis les deux trajectoires d'horloge sont restaurées.
5. Les deux Daemons produisent zéro transition en réussite prolongée, une seule
   indisponibilité pendant la panne et une seule récupération.
6. Les réponses d'état sont parsées selon leur schéma exact ; doublons, machine
   supplémentaire ou listener porté par un autre PID sont refusés. La borne
   réseau est éprouvée contre une destination muette strictement locale au LAB.
7. `result.json` contient la révision Git, les empreintes, la topologie, les
   cibles, la fenêtre Relay et le nettoyage puis, pour chaque étape, son
   identifiant, sa catégorie, son titre et son statut. Cette liste fixe exclut
   logs bruts et données sensibles.

### P2 historique — restitution automatisée sans autorité indue

1. Le rapport Markdown et la page HTML sont générés depuis `result.json`, sans
   recopier manuellement PID, empreintes ou états.
2. La page est servie seulement dans `lab-console` sous `nobody` sur loopback ;
   contenu, identité, listener et arrêt sont affirmés après échec injecté puis
   après capture nominale.
3. Chaque exécution archive sous `tests/artifacts/proofs/v0.0.1/<horodatage>/` son
   `result.json`. Une exécution P1 réussie archive en plus le résultat P2, le
   rapport, la page et la capture. `result.json` reste l'autorité ;
   `render-result.json` et l'image prouvent seulement la restitution.

## Condition de sortie de l'automatisation complète

Le run post-réorganisation historique `20260717T100150Z-1543398` a satisfait
P0, P1 et P2 avant les derniers durcissements de CI et d'orchestration. Il ne
prouve donc pas à lui seul les sources courantes. Chaque exécution autorisée
doit :

- partir d'un inventaire LAB vérifié et d'un état initial déclaré ;
- ne lancer aucun code du projet sur le laptop ;
- tracer la révision testée et l'empreinte exacte de l'artefact déployé ;
- exécuter toutes les assertions statiques, unitaires, HTTP et multi-VM sans
  interprétation manuelle ;
- distinguer refus attendu, échec du produit, échec d'infrastructure et échec du
  nettoyage ;
- borner toutes les attentes et toutes les communications réseau ;
- restaurer ou laisser un état final explicitement choisi et le vérifier ;
- produire les données permettant un rapport LAB relisible, sans transformer ce
  rapport ou sa capture en substitut aux assertions.

Le présent registre reste le cahier de reprise. Le statut prouvé de `v0.0.1`
repose sur le rapport LAB lié en tête de page et sur les revalidations qui y
sont explicitement ajoutées, jamais sur cette liste seule.

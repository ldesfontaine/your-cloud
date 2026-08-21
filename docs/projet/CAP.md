# Cap du projet

Une [édition HTML autonome](../html/cap.html) accompagne cette source
Markdown.

## Pourquoi Your Cloud existe

Les outils d'infrastructure sont puissants, mais ils obligent souvent à passer
entre de nombreuses interfaces et commandes pour comprendre une situation puis
agir dessus. Cette fragmentation rend l'apprentissage difficile pour un
débutant et ralentit aussi les personnes expérimentées.

Your Cloud veut rendre une infrastructure lisible et administrable depuis une
interface cohérente, sans masquer ce qui est réellement exécuté.

## Objectif à long terme

Un utilisateur peut représenter son infrastructure, y rattacher des machines,
comprendre visuellement leur état, puis déployer et gérer progressivement des
services.

Le débutant bénéficie d'un parcours guidé et de refus explicites lorsqu'une
opération est dangereuse ou incomplète. L'utilisateur expérimenté retrouve les
mêmes machines, états, plans et preuves sans devoir ouvrir plusieurs outils en
parallèle ni abandonner ses pratiques externes.

À terme, l'interface doit permettre de suivre et de faire évoluer une
infrastructure de bout en bout : observation, déploiement de services,
exposition contrôlée, opérations courantes, puis intégrations plus avancées.
Cette destination n'est pas une promesse de tout construire avant de livrer une
première version utile.

<!-- coherence: AGENT-AUTHORITY:start -->
## Cible d'action à long terme

L'objectif final exige que l'utilisateur puisse demander depuis l'interface des
actions sur ses machines, ses services et ses plateformes. Your Cloud orchestre
ces actions ; il ne transforme pas chaque machine en serveur d'administration
général et ne réimplémente pas les API d'OpenStack ou de K3s.

<!-- coherence: V1-APP-ACCESS:start -->
### Une App installée distincte d'un Controller privé

Your Cloud désigne le produit, mais pas une autorité unique. L'**App** est une
application cliente installée et signée sur un appareil administrateur. Elle
embarque son frontend et son client réseau sans héberger de serveur local ni
télécharger son code depuis l'infrastructure. Le **Controller** est le backend
d'autorité d'une seule infrastructure : il porte son inventaire, ses utilisateurs
et rôles, ses décisions d'enrôlement, ses plans, son état attendu et son audit,
mais aucun frontend. Chaque Controller ne détient aucune autorité ni secret d'un
autre.

L'App, l'appareil d'administration et un éventuel fournisseur d'identité
restent toutefois des points communs. L'isolation multi-Controller dépend de la
distribution signée de l'application, des associations approuvées, des identités
d'appareil et des sessions séparées ; elle doit être prouvée.

Le trajet humain est `utilisateur -> App -> Controller`. Le trajet
d'observation est `Daemon -> Relay -> Controller`. Le trajet d'action part du
Controller vers l'autorité d'exécution adaptée, puis vers la machine. Le trafic
des services publiés suit encore un quatrième chemin indépendant. L'App ne
contacte jamais directement le Relay ; le Daemon connaît seulement son endpoint
Relay approuvé et ne connaît aucun Controller.

L'API du Controller est privée derrière WireGuard, et c'est le **nominal** :
le Controller n'écoute que sur son adresse du réseau d'accès, jamais nu sur
Internet. **L'App est un pair de ce réseau** — sa clé privée naît dans son
coffre à la création de l'infrastructure, distincte et révocable par appareil
d'administration ; un routage fractionné limite le tunnel aux seules adresses
d'administration. Le réseau d'administration refuse
aussi par défaut toute destination et tout port non nécessaires. WireGuard
authentifie la possession de cette clé, pas l'intégrité de l'appareil ni
l'identité de l'humain : le Controller exige encore une authentification humaine
forte et autorise chaque demande pour l'infrastructure, la cible et l'action
concernées. **Cette clé est un moyen de transport, jamais une identité
d'action** : l'App ne gagne par elle aucun pouvoir d'exécuter seule une
opération d'infrastructure.

Cette liaison ne devient pas une configuration WireGuard à
administrer à la main. L'App expose une opération bornée du type
`connecter cette infrastructure` ; son cœur natif déverrouille uniquement la clé
de pair associée, limite la liaison à l'API du Controller, puis la ferme et
reverrouille la clé au timeout ou à la déconnexion explicite. La clé brute ne
traverse jamais le frontend. La fermeture locale n'est pas une révocation du
pair : révocation, rotation et retrait d'un appareil restent des opérations
distinctes.

Deux familles techniques restent à comparer avant ce palier postérieur à
`v0.1.0` : piloter
un tunnel fourni par le système, avec une autorité privilégiée minimale, ou
intégrer une pile WireGuard en espace utilisateur qui ne transporte que le
client du Controller. Un coffre portable de liaison protégé par phrase secrète,
distinct du coffre Stronghold de `v0.1.0`, reste également ouvert ; il devra
utiliser une dérivation mémoire-dure et un
chiffrement authentifié, puis rendre visible le risque résiduel d'attaque hors
ligne. Aucun
choix n'autorise une route libre, un shell réseau ou une confiance implicite
envers les autres machines.

Pour `v0.1.0`, l'App protège ses clés d'appareil et humaines dans un
coffre Tauri Stronghold commun à Linux et Windows, déverrouillé par une phrase
secrète locale dérivée avec Argon2id. Chaque Controller garde des clés et une
autorisation distinctes. Le frontend voit brièvement la phrase saisie puis
l'efface ; il ne reçoit jamais la clé dérivée, une clé privée, le contenu du
coffre ou une session. Le matériel de récupération reste conservé hors ligne.
Dans `v0.1.0`, la phrase quotidienne contient six mots aléatoires et le code global
de récupération contient 256 bits ; ce dernier dérive une clé différente par
Controller et n'est jamais sauvegardé par l'App. L'appairage et la
récupération passent par un listener TLS ouvert par l'autorité locale sur
l'adresse privée exacte du Controller, puis réellement fermé. Un
certificat d'appareil de 180 jours et une session de 30 minutes d'inactivité,
huit heures au maximum, restent liés à un seul Controller ; leur rotation ou
révocation ne donne jamais autorité sur une autre association.
Dans `v0.0.3` seulement, chaque Controller possède exactement un humain et un
appareil App actifs ; cette cardinalité n'est pas étendue silencieusement
aux paliers restants de `v0.1.0`.
Windows Hello, passkeys, clés FIDO2 et SSO/OIDC pourront être étudiés après
`v0.1.0` ; aucun ne constitue une dépendance ou une autorisation implicite sur
plusieurs infrastructures.

Un futur accès par navigateur pourra ajouter un frontend distribué et une
passerelle publique facultative reliée au Controller privé par un canal dédié.
Ce mode ne fait pas partie de `v0.1.0`. La passerelle ne
détiendra aucune autorité d'administration ni secret de machine, mais gardera des
pouvoirs sur le routage et la disponibilité, voire sur TLS ou la transmission
d'identité selon son contrat. Ces pouvoirs devront être bornés ; l'absence de
pouvoir d'usurpation exigera une authentification de bout en bout réellement
prouvée. Elle ne devient pas le chemin requis.

`v0.1.0` introduit d'abord une App installable sur Linux et Windows depuis
le même frontend et un Controller backend dans l'environnement d'administration.
Le téléphone reste une cible du même contrat visuel et réseau, mais son
empaquetage, son stockage sécurisé, sa signature et sa distribution sont prouvés
dans un incrément ultérieur. La preuve `v0.0.3` s'exécute dans le LAB ou un runner
isolé : elle ne lance pas le produit sur le laptop de développement et
n'implémente pas WireGuard par avance.

Le frontend et le fonctionnement normal de l'App ne reçoivent jamais une
clé de machine, un secret de runner ou une identité d'Agent. Seul l'Assistant
temporaire décrit ci-dessous peut utiliser l'accès personnel en mémoire pendant
l'amorçage. Une panne de l'App, du Controller, du Relay ou du chemin
d'administration ne doit pas interrompre, par elle-même, les services hébergés
sur d'autres machines. La perte d'un hôte peut interrompre les services qui y
cohabitent. Les services destinés à Internet restent accessibles par leur HTTPS
normal, sans imposer WireGuard à leurs utilisateurs.
<!-- coherence: V1-APP-ACCESS:end -->

<!-- coherence: BOOTSTRAP-RECOVERY:start -->
### Amorcer une fois, remplacer sans nouvelle autorité

L'utilisateur installe seulement l'App sur son appareil d'administration.
Son **Assistant d'amorçage** natif et temporaire prend en charge les deux
parcours explicites `Créer une infrastructure` et `Remplacer un Controller`.
Il utilise un accès SSH personnel déjà possédé par l'utilisateur, de préférence
par son agent SSH, seulement pendant l'opération. Le frontend, le Controller et
les journaux ne reçoivent jamais cet accès. Un fichier de clé chiffré peut
servir de repli, mais il est déchiffré uniquement en mémoire par l'Assistant.
L'état temporaire disparaît à la fermeture, à l'échec ou au timeout.
Passphrase, mot de passe `sudo` et consentement `root` passent par une fenêtre
du cœur natif hors de la WebView. Elle répète les cibles, actions et durées
exactes ; le frontend ne peut ni fournir le secret, ni approuver à la place de
l'utilisateur, ni obtenir une primitive SSH ou de signature générale.

Avant toute mutation, l'utilisateur déclare les endpoints un par un et
l'Assistant réalise un audit en lecture seule. Il ne scanne ni le LAN, ni une
plage réseau, ni un compte fournisseur. L'App recommande ensuite un
placement et montre les comptes, artefacts, flux et privilèges exacts.
L'utilisateur l'approuve avant que l'Assistant installe le premier Controller.
Un compte non-root avec clé SSH et `sudo` protégé par mot de passe reste le
choix recommandé. Un accès SSH `root` n'est utilisé qu'après consentement
explicite pour cette opération et n'est jamais repris silencieusement.
Après l'installation du Controller et avant de modifier une autre machine, la
joignabilité SSH et la clé d'hôte de chaque cible sont aussi vérifiées depuis
ce Controller.

Il existe exactement deux catégories d'accès SSH d'administration des
machines :

1. l'accès personnel, indépendant, conservé sous l'autorité de l'utilisateur ;
2. une identité Your Cloud différente par machine, générée et détenue par le
   Controller.

L'authentification App–Controller autorise l'humain dans le produit, mais
ne constitue pas une troisième autorité SSH. Your Cloud ne retire jamais le
compte, la clé ou le droit d'administration personnel. La clé publique Your
Cloud d'une machine impose une commande forcée vers l'Auxiliaire et interdit
shell, PTY, SFTP, transfert de port et transfert d'agent. Sa clé privée reste
sur le Controller, dans un fichier possédé par `root` fourni au seul service
Controller par les credentials systemd ; elle ne rejoint ni l'App, ni le
frontend, ni l'Agent.

Sur la cible, la clé publique appartient à un compte technique verrouillé,
séparé du Daemon et du Relay. Son fichier et ses parents root-owned ne sont pas
inscriptibles par ce compte. Les restrictions SSH refusent shell, PTY, SFTP,
rc utilisateur, X11, environnement et transferts, puis imposent le chemin
absolu root-owned de l'Auxiliaire. Une politique root-owned permet uniquement
cette invocation exacte, avec environnement réinitialisé, sans argument,
`SETENV` ou `sudo` général ; le plan typé arrive sur l'entrée standard.

Le Controller vit sur une machine privée, de confiance et normalement allumée,
jamais durablement sur le laptop. Pour une petite infrastructure, il peut
cohabiter avec d'autres rôles si processus, comptes, secrets, fichiers et
budgets restent séparés. Une machine ou VM dédiée devient la recommandation
pour une infrastructure plus grande ou plus sensible. Le VPS public portant un
Relay ou des services exposés n'est pas proposé par défaut pour ce rôle.
La cohabitation partage cependant la panne matérielle : perdre ou isoler cet
hôte peut interrompre ses services locaux, ce que l'App doit annoncer
avant le placement.

Perdre le Controller ne retire pas l'accès personnel. Les services hébergés sur
d'autres machines continuent ; ceux qui cohabitent sur l'hôte perdu ou isolé
peuvent être interrompus. Après choix explicite de l'utilisateur, le même
Assistant installe un nouveau Controller, crée une nouvelle association
App–Controller et tourne toutes les autorités que l'ancien pouvait
exercer : identité lecteur Relay, filtre et manifeste associés, clés SSH par
machine, clé publique d'approbation et sessions. Les Daemons, le Relay
d'ingestion et les services compatibles des hôtes survivants restent en place.
Chaque nouvelle autorité est vérifiée avant le retrait de l'ancienne ; une
coupure rend les états `ancien seul`, `chevauchement borné`, `nouveau seul` ou
`inconnu` par machine et interdit d'annoncer un succès global.

Une suspicion de compromission impose d'abord l'isolement de l'ancien hôte et
un nouveau Controller sur une base saine ; sinon le résultat reste
`remplacement non sécurisé`. Sans sauvegarde de l'ancien inventaire,
l'utilisateur redéclare ses endpoints. Le code de récupération
App–Controller répond à un autre incident : il réassocie une App à un
Controller encore vivant, sans restaurer un Controller perdu.
S'il remplace la clé humaine, le chemin d'action reste verrouillé jusqu'à ce que
l'Assistant tourne les clés publiques d'approbation avec l'accès SSH personnel ;
le Controller ne peut pas s'autoriser lui-même.

L'installateur de l'App pour `v0.1.0` embarque l'Assistant, un unique paquet
serveur `.deb` Debian 13 `amd64`, ses définitions statiques et le manifeste signé qui
lie sa version, sa cible, sa taille et son empreinte. L'Assistant vérifie ce lot
avant tout privilège ; le paquet n'embarque ni secret, ni configuration propre à
une machine, ni activation de rôle ou transfert d'autorité. Il inventorie les
fichiers immuables dans les chemins paquet bornés sous `/usr/lib`, avec les
trois unités Controller, Daemon et Relay livrées inactives sous
`/usr/lib/systemd/system`, tandis que l'Assistant garde l'installation hors
ligne, la reprise et le retrait explicite des états qu'il génère. Aucun binaire privilégié
n'est téléchargé dynamiquement à l'amorçage. La prise en charge de `arm64` et
d'autres distributions attend une preuve séparée. La mise à jour reste manuelle
dans `v0.1.0`.

Le contrat complet et ses preuves attendues sont fixés dans
[Amorçage et remplacement du Controller](../architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md).
La capacité globale reste partielle. Le socle `#43` du helper, de l'IPC et de
son cycle de vie est implémenté et prouvé sous Linux et Windows sur le commit
`f3fef79`, dans le run `30753216798` : modes `create` et `replace`, commandes
Tauri positives sans secret, identifiant natif anti-rejeu, aucun listener et,
sous Windows, création suspendue avec liste exacte de handles puis Job Object.
Le [rapport du runner Windows](../lab/v1-bootstrap-ipc-windows.md) borne aussi
les gates de packaging natif. Les dialogues et protections de secrets `#45`
sont maintenant implémentés, prouvés et fermés : fenêtres
GTK3 et Win32
natives, périmètre et parent liés, échéance monotone non renouvelable de 300
secondes, tampon protégé de 4096 octets puis destruction, protections
`mmap`/`mlock`/`MADV_DONTDUMP` sous Linux et
`VirtualAlloc`/`VirtualLock`/Windows Error Reporting sous Windows. Leur
[rapport de preuve native](../lab/v0.1.0-native-secret-consent-linux-windows.md)
conserve les résultats et leurs limites. `30768351689` et `30768749538` sont
rouges sous un
ancien oracle qui exigeait l'absence du canari dans `LocalDumps` ; leurs
observations caractérisent désormais cette collecte administrateur hors
garantie. `WerRegisterExcludedMemoryBlock` reste une défense en profondeur. Le
candidat intermédiaire `ae550470`, dont le run `30769440106` a entièrement
réussi ses quatre jobs, exige le contrôle et le canari présents puis supprime
le dump, prouve le répertoire vide et les deux inscriptions de registre
absentes. Comme le répertoire n'est retiré que par `Drop` après verdict, ce run
ne peut pas fermer #45. `c8643b0` ajoute `remove_and_prove_absent` ; le run
`30770893733` réussit ses quatre jobs sur `b76ded8`, prouve le répertoire et les
deux inscriptions absents avant verdict et publie trois artefacts inspectés.
Après trois corrections du harnais de captures, `30779157351` réussit ses
quatre jobs sur `c0569d0` : l'issue #45 lie ce run et ce SHA, puis se ferme.
L'accès SSH
personnel `#42`, puis l'intégration complète suivie
par `#35` restent aussi à implémenter et prouver avant de poursuivre le reste
du palier `#13`. L'acceptation actuelle détruit le secret et termine par
l'événement public `Unavailable` ; elle ne prouve ni SSH, ni `sudo`, ni `root`, ni audit ou
succès d'amorçage.
<!-- coherence: BOOTSTRAP-RECOVERY:end -->

### Un seul artefact, des rôles réellement isolés

Une machine enrôlée reçoit une seule installation Your Cloud et un seul
exécutable Go versionné, signé et inventorié. Cette unité de distribution ne
fusionne pas les autorités : chaque rôle actif s'exécute dans son propre
processus, avec son compte, son identité, sa configuration, ses secrets, son
stockage et ses limites de ressources.

L'**Agent** active son **Daemon** permanent après enrôlement. Le même exécutable
peut aussi fournir deux capacités optionnelles, sans les activer par sa seule
présence :

- son **Daemon** permanent fonctionne sans privilège d'administration. Il
  observe la machine, conserve les données en attente et ouvre lui-même les
  communications sortantes authentifiées vers son Relay approuvé. Il ne connaît
  aucun Controller et ne modifie pas directement le système ;
- le **Relay** reste un processus réseau distinct, non privilégié et consacré
  aux observations. Il peut cohabiter avec le Daemon sur une machine déclarée
  candidate, mais son démarrage refuse toute machine qui n'a pas reçu au
  préalable une configuration et une identité Relay explicitement
  provisionnées. Cette capacité est optionnelle sur chaque Agent, mais la chaîne
  d'observation de `v0.1.0` provisionne exactement un Relay ;
- un **Auxiliaire local** optionnel peut être activé uniquement pour une machine
  enrôlée. Il n'est pas permanent, n'écoute aucun port, est lancé
  pour un plan précis, applique une opération nommée avec les seuls privilèges
  nécessaires, renvoie un résultat structuré puis s'arrête.

Une machine ordinaire lance donc seulement `your-cloud daemon`. Une candidate
Relay explicitement provisionnée peut lancer simultanément `your-cloud daemon`
et `your-cloud relay` depuis les mêmes octets, sous deux comptes différents.
Dans `v0.1.0`, `your-cloud auxiliary` devient un troisième processus ponctuel. Le
Controller l'invoque par une identité SSH propre à la machine et une commande
forcée pour un plan exact. Après confirmation native, le cœur de l'App
signe l'enveloppe canonique du plan et de son rollback avec la clé humaine de
l'association ; le Controller ne fait que la transporter. Chaque machine garde
la clé publique correspondante, une époque d'autorité et une séquence
anti-rejeu minimale dans des fichiers root-owned. L'Auxiliaire revérifie
signature, infrastructure, machine, époque, séquence, expiration et contraintes
avant tout privilège, exige le successeur exact de la valeur locale, puis
consomme durablement la séquence avant la première mutation. Il renvoie un
résultat structuré et s'arrête. Une machine placée seulement en observation
n'active pas ce chemin.

Cette séparation constitue une frontière de sécurité réellement maintenue et
testée. Une machine limitée à l'observation ne possède aucune élévation dormante
de type binaire `setuid` ou règle `sudo` générale. Ni le Daemon ni le Relay ne
transportent un plan, un shell, un script libre ou un chemin arbitraire. Le
chemin d'action et l'Auxiliaire revérifient indépendamment le plan avant tout
changement privilégié. Les privilèges appartiennent à l'opération autorisée,
pas à un auxiliaire root universel.

Partager un exécutable simplifie la chaîne d'approvisionnement, les mises à jour
et le retour à une version précédente. Cela ne constitue pas une isolation :
celle-ci vient des processus, comptes, identités, fichiers et politiques
systemd distincts. Un défaut du lot commun peut atteindre plusieurs rôles ; les
tests par rôle, la cohabitation, les déploiements progressifs et le rollback du
lot entier restent donc obligatoires.

L'activation initiale exige l'accès SSH personnel prêté à l'Assistant
d'amorçage. Une fois le Controller installé et son accès par machine vérifié,
l'Assistant détruit tout état temporaire permettant de l'utiliser, sans
modifier l'accès qui reste sous le contrôle de l'utilisateur. Un Agent non
privilégié ne s'accorde jamais lui-même de nouveaux droits.

### Utiliser l'autorité adaptée à chaque cible

Toutes les actions de l'interface ne traversent donc pas l'Agent :

| Cible | Autorité à utiliser à terme |
|---|---|
| Système Linux et service local | Auxiliaire local avec une opération typée et bornée |
| Ressource OpenStack | Adaptateur central utilisant l'API OpenStack et une identité limitée |
| Plan Terraform, OpenTofu ou Ansible | Runner d'automatisation isolé avec artefact et résultat vérifiables |
| K3s | Agent pour l'amorçage local si nécessaire, puis adaptateur utilisant l'API du cluster |
| Service dont Your Cloud ne connaît pas la recette | Outil de l'utilisateur ; Your Cloud observe sans reprendre l'autorité |

Pour une opération coordonnée sur plusieurs machines, le Controller construit un
plan global puis une partie ciblée par machine ou plateforme. L'App le rend
lisible et recueille son approbation. Son cœur natif signe seulement l'enveloppe
exacte de chaque partie après ce consentement ; il n'expose aucune signature
libre au frontend. Chaque autorité ne voit et ne peut appliquer que la partie
qui la concerne.

### Contrat commun d'une action

Quel que soit l'adaptateur, le parcours final conserve les mêmes garanties :

1. l'utilisateur est authentifié et autorisé pour l'infrastructure, la cible et
   l'opération demandée ;
2. le Controller produit un plan typé qui nomme la cible, l'action et sa version, les
   changements, privilèges, flux, effets d'échec et possibilités de retour ;
3. l'approbation est liée au contenu exact du plan, pas seulement à son titre ;
4. l'ordre résultant est signé par la clé humaine native, authentifié, ciblé,
   unique, de courte durée et protégé contre la modification et le rejeu sans
   faire confiance au seul Controller ;
5. l'autorité qui applique revérifie la cible, l'action, sa version, la durée,
   l'approbation et les limites locales ;
6. l'adaptateur refuse par défaut tout champ ou comportement inconnu et valide
   aussi le sens des paramètres : volumes, chemins, destinations, ports,
   capacités, règles réseau et ressources restent dans des listes positives
   locales ;
7. le plan décrit un rollback exact, borné aux ressources Your Cloud, et son
   approbation couvre ce rollback ;
8. l'adaptateur applique de façon idempotente lorsqu'il le promet : le premier
   changement rend `changed=true`, le même état sans dérive rend
   `changed=false` sans réécriture ni redémarrage, et un retrait déjà effectif
   rend aussi `changed=false` ;
9. une dérive reste visible et exige un nouveau plan ; après un échec contrôlé,
   le rollback approuvé est tenté tant que l'autorité garde la maîtrise ;
10. le résultat direct puis l'observation indépendante rendent le succès,
   l'échec ou l'état partiel visibles dans l'App ;
11. demande, approbation, identité, empreinte du plan et résultat forment une
   trace d'audit expurgée des secrets.

Une action possède des états honnêtes : en attente, en cours, réussie, échouée
ou résultat inconnu. Une coupure ne déclenche aucun rejeu aveugle d'une mutation
non idempotente et ne permet pas de promettre un rollback autonome dans
`v0.1.0`. Après
reconnexion, le Controller observe l'état réel puis prépare un nouveau plan.
L'expiration et l'anti-rejeu survivent aux redémarrages grâce à l'époque et à la
séquence consommée dans l'état root-owned minimal de chaque cible. Cet état
n'est pas un historique d'actions et ne permet aucune reprise autonome. Une
opération réseau susceptible de couper son propre contrôle annonce et prouve
son chemin de reprise avant d'être proposée.

Un plan d'action ne transporte pas de secret persistant en clair. Les actions
qui nécessiteront un secret demanderont un canal et un cycle de vie dédiés,
bornés et auditables ; ce contrat sera conçu avant leur prise en charge réelle.
L'Agent, l'Auxiliaire, leurs catalogues et leurs politiques ne se mettent pas à
jour par une action ordinaire : leur lot signé, épinglé et réversible suit une
autorité de mise à jour distincte.

### Pourquoi cette cible est retenue

| Option | Conclusion |
|---|---|
| Daemon unique fonctionnant en root | Plus simple, mais sa compromission donnerait une autorité générale : refusé |
| Ansible dans le cœur de `v0.1.0` | Bon moteur externe de convergence, mais ajoute un second langage et une autorité générale au premier parcours : conservé comme outil utilisateur et intégration future éventuelle, pas comme dépendance de `v0.1.0` |
| SSH restreint vers l'Auxiliaire | Transport simple pour les machines Linux déjà déclarées, sans ordre par le Daemon ni shell général : cible retenue pour `v0.1.0` |
| Binaires indépendants pour Daemon et Relay | Isolation visible, mais versions, signatures, SBOM et mises à jour peuvent dériver : écarté |
| Exécutable unique lancé comme un seul processus multi-rôle | Distribution simple, mais mémoire, compte, secrets, crash et surface réseau partagés : refusé |
| Exécutable unique, processus et comptes séparés | Une version et une chaîne d'approvisionnement, avec des frontières d'exécution par rôle : cible retenue |
| Agent non-root et Auxiliaire local ponctuel | Aucun port d'action entrant, privilège seulement pendant une opération typée : cible retenue |
| API native ou runner isolé hors de la machine | Évite de détourner l'Agent pour OpenStack, K3s ou l'IaC : cible retenue selon le besoin |

### Vérification OWASP et approche NIS2

OWASP et NIS2 n'imposent ni un Agent Go, ni un Auxiliaire, ni Ansible. Le choix
ci-dessous est notre traduction architecturale de leurs principes ; il reste à
prouver par le code, la configuration et les scénarios du LAB.

Cette architecture est cohérente avec les valeurs sûres par défaut, la réduction
de surface, la défense en profondeur, le moindre privilège et la séparation des
responsabilités de
[l'OWASP Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html).
Elle applique aussi le refus par défaut et la vérification de chaque action
recommandés par le
[guide OWASP sur l'autorisation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) :

- l'observation seule est le profil initial le moins privilégié ;
- activer une capacité d'action constitue une décision explicite par machine ;
- l'App, le Controller, le Daemon, le Relay et l'autorité locale n'ont pas
  les mêmes droits, même lorsqu'ils appartiennent au même produit ;
- un schéma positif d'opérations remplace les commandes libres ;
- la validation porte sur le type et sur la portée réelle des paramètres, afin
  qu'une opération autorisée ne puisse pas devenir un montage de `/`, une règle
  pare-feu libre ou une destination réseau arbitraire ;
- chaque demande est autorisée pour l'utilisateur, l'infrastructure, la machine,
  l'action et le moment concernés ;
- les échecs d'autorisation, d'intégrité ou de validation terminent sans
  mutation et produisent une preuve exploitable.

La validation syntaxique **et sémantique** des paramètres suit le
[guide OWASP sur la validation des entrées](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).
La trace d'action suit le
[guide OWASP sur la journalisation](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) :
elle permet l'attribution et l'enquête sans enregistrer de clé, jeton, mot de
passe ou contenu applicatif sensible.

| Principe ou mesure | Application dans Your Cloud | Preuve attendue |
|---|---|---|
| Valeur sûre et moindre privilège | Daemon seul après enrôlement ; Relay et action locale exigent chacun un provisionnement explicite | Une machine non candidate refuse le Relay et une machine non activée refuse toute mutation locale |
| Séparation et défense en profondeur | Un artefact commun, mais processus, comptes, identités et politiques distincts ; validation locale avant privilège | Compromettre ou simuler le Daemon ne donne ni l'identité Relay ni le droit d'appliquer un faux plan |
| Autorisation et refus par défaut | Décision par utilisateur, infrastructure, cible, action, version et durée | Mauvaise combinaison refusée avant toute mutation |
| Validation des entrées | Schéma strict et contraintes sémantiques locales | Chemin, port, volume, capacité et destination hors liste refusés |
| Journalisation et incident | Identifiant, acteur, empreinte, transitions et résultat sans secret | Reconstituer une action et une erreur sans exposer ses secrets |
| Continuité NIS2 | Services indépendants des processus App, Controller, Relay et du canal d'action ; domaine de panne d'une éventuelle cohabitation rendu visible | Une panne du contrôle retarde les actions sans arrêter les services des autres hôtes ; la perte d'un hôte peut interrompre ses services colocalisés |
| Chaîne d'approvisionnement et développement sûr | Artefacts épinglés et signés, SBOM, tests hostiles, mise à jour séparée | Refus d'un lot altéré et retour vers le dernier lot valide |
| Cryptographie, accès et actifs | Identités bornées, communications chiffrées, inventaire et révocation | Pair, identité, cible ou plan inconnu refusé et révocable |

La cible contribue aux mesures proportionnées de l'
[article 21 de NIS2](https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555) :
analyse de risques, continuité, chaîne d'approvisionnement, développement sûr,
évaluation d'efficacité, cryptographie, contrôle d'accès et gestion des actifs.
Les artefacts et adaptateurs devront être épinglés, signés, inventoriés et testés
dans le LAB ; les opérations critiques demanderont une authentification et une
approbation proportionnées. Cette orientation aide à construire un produit
responsable, mais ne prouve ni la conformité d'un utilisateur ni celle de Your
Cloud à NIS2.

### Risques résiduels à conserver visibles

- La compromission d'une App déverrouillée ou de sa clé humaine pourrait
  produire des approbations valides. Un Controller compromis ne peut pas les
  forger seul, mais il expose ses clés SSH, peut transporter une enveloppe
  signée encore valide et peut viser une erreur de l'Auxiliaire.
- Une machine compromise peut falsifier ses observations et détourner les
  capacités locales qui lui ont déjà été accordées.
- Une erreur dans un adaptateur privilégié peut endommager sa cible malgré un
  plan valide ; ses entrées, effets et rollback doivent donc être testés de
  façon hostile.
- Le chemin d'action ajoute une autorité sensible même s'il reste séparé
  du Daemon et du Relay. Sa compromission pourrait utiliser les opérations qui
  lui sont permises ; l'identité bornée, la révocation et la validation
  indépendante par l'Auxiliaire resteront nécessaires.
- Un défaut ou un lot compromis dans l'exécutable partagé peut toucher Daemon,
  Relay et Auxiliaire. Les comptes séparés limitent les droits à
  l'exécution, mais ne remplacent ni signature, SBOM, tests par mode, déploiement
  progressif ni retour atomique vers le dernier lot valide.
- La gestion des secrets applicatifs, des mises à jour de l'Agent et des rôles
  multi-utilisateurs reste à concevoir dans les incréments qui en auront
  réellement besoin ; elle ne réutilise pas implicitement les autorités
  d'amorçage et d'action déjà bornées.

### Cohérence avec `v0.1.0`

`v0.1.0` constitue une première marche cohérente, pas une implémentation anticipée
de toute cette cible. Son exécutable commun fournit `daemon`, `relay` et
`aux`, lancés comme des processus séparés. Elle prouve le parcours utilisateur
stable — plan exact avec rollback exact, approbation liée au contenu,
enveloppe signée par le cœur natif, anti-rejeu durable, application locale typée
et vérification — par une identité SSH distincte sur chaque machine. Son Daemon
reste strictement limité à l'observation, son Relay ne transporte aucune action
et son Auxiliaire n'est ni permanent, ni un listener, ni un shell général.

Le contrat de `v0.1.0` n'exige aucun adaptateur OpenStack ou K3s ni runner IaC.
Ansible reste utilisable par l'utilisateur hors de Your Cloud ; une intégration
isolée pourra être étudiée après stabilisation sans changer le plan que
l'utilisateur comprend et approuve.
<!-- coherence: AGENT-AUTHORITY:end -->

<!-- coherence: SERVICE-LIFECYCLE:start -->
## Déployer, publier et migrer sans exposer trop tôt

La roadmap construit les capacités du produit une par une. Une opération réelle
suit un autre ordre durable : inventorier les responsabilités, préparer et
prouver la reprise, préparer les identités et le réseau en état fermé, déployer
sans exposition, vérifier localement, autoriser le flux exact, puis publier ou
basculer. L'ancien état reste disponible pendant une fenêtre de retour annoncée
et n'est retiré qu'après observation.

Une migration avec données nomme son autorité d'écriture et son point de
non-retour. Après de nouvelles écritures sur la destination, Your Cloud ne remet
jamais simplement l'ancienne route : il exige une resynchronisation prouvée, un
RPO accepté ou une réparation vers l'avant. Une coupure produit un résultat
inconnu et une observation indépendante, jamais le rejeu aveugle d'une mutation.

Le [cycle de vie sûr des services](../architecture/CYCLE-DE-VIE-DES-SERVICES.md)
détaille les scénarios homelab, PME, migration et panne qui portent ce contrat.
<!-- coherence: SERVICE-LIFECYCLE:end -->

## Plateformes et extensions

Your Cloud peut partir de machines Linux déjà installées ou déléguer leur
provisionnement à des intégrations explicites. OpenStack reste la plateforme
d'infrastructure visée, tandis que Terraform ou OpenTofu peuvent décrire et
appliquer ce provisionnement. Your Cloud ne réimplémente pas silencieusement
leurs moteurs ni leurs autorités.

K3s standalone, les clusters K3s et d'autres familles de services font partie
de la direction produit. Chaque intégration est introduite seulement lorsqu'un
parcours plus petit a rendu ses besoins, son autorité et ses preuves
compréhensibles.

<!-- coherence: V1-NETWORK:start -->
## Zone d'exposition et vraie DMZ

Le VPS public du scénario de référence de `v0.1.0` constitue une zone
d'exposition
durcie, pas à lui seul une DMZ. Une vraie DMZ nécessite une séparation réseau vérifiable : le trafic
Internet entre par une frontière filtrante, les composants exposés résident
dans un segment dédié, puis une seconde politique limite leurs accès vers les
services privés et le plan d'administration reste séparé.

Your Cloud pourra représenter cette architecture, préparer les flux strictement
nécessaires et en vérifier les refus. Il ne qualifiera jamais automatiquement
une machine publique de « DMZ » en raison de son adresse ou de son fournisseur.
<!-- coherence: V1-NETWORK:end -->

## Rien n'est imposé, rien n'est deviné

Your Cloud n'impose ni une topologie type, ni un catalogue de services à
installer. Un **profil de service** décrit seulement un parcours pris en charge :
sa présence dans l'App ne crée rien sans déclaration, placement, plan et
approbation. Les services nommés dans une preuve LAB rendent ce scénario
reproductible ; ils ne deviennent pas des prérequis de l'infrastructure réelle.

L'inventaire que Your Cloud construit reste **local aux machines déjà
enrôlées**. Your Cloud ne scanne pas le réseau environnant : un VPS chez un
fournisseur n'en a pas besoin, et la présence sur un LAN privé ne crée aucune
autorisation envers les autres appareils.

## Contraintes durables

- Le code de chaque étape reste petit, lisible, testé et sans abstraction créée
  uniquement pour une hypothétique version future.
- L'interface montre le résultat attendu, les changements prévus et les preuves
  obtenues.
- Chaque rôle annonce et respecte des budgets mesurés sur de petites machines :
  CPU, mémoire, processus et disque par systemd/cgroup ou quota disponible ;
  réseau par destinations, listeners, tailles, concurrence, délais et débits
  propres au rôle. Un placement trop faible est refusé avec sa cause ; une borne
  de capacité propre à une version, comme les 64 machines actuelles, n'est
  jamais présentée comme une limite durable du produit.
- Une machine située dans un LAN privé n'exige ni adresse publique, ni
  redirection de port entrante pour être observée ou publier un service par un
  point d'entrée distinct.
- Your Cloud configure lui-même le passage privé et le point d'entrée public
  nécessaires au parcours qu'il annonce prendre en charge.
- L'utilisateur peut continuer à déployer un service ou configurer un passage
  par ses propres outils. Your Cloud représente alors cet élément comme
  externe, sépare ce qui est déclaré de ce qui est vérifié et ne le reprend
  jamais en gestion silencieusement.
- La découverte future reste en lecture seule et au moindre privilège. Elle ne
  collecte aucun secret, ne transforme pas une présence réseau en confiance et
  ne déclenche aucune mutation.
- Chaque composant et intégration déclare les communications entrantes et
  sortantes nécessaires. Les flux latéraux vers d'autres appareils du LAN sont
  refusés par défaut et ne peuvent être ouverts que par un plan explicite,
  borné et approuvé.
- Seules les machines explicitement enrôlées peuvent participer au réseau privé
  de Your Cloud. Cet enrôlement donne une identité, jamais une autorisation
  générale : chaque pair, destination, port et protocole reste borné au besoin
  approuvé, et chaque donnée Your Cloud qui traverse ce réseau privé est
  protégée avant de quitter sa machine.
- Un service déjà déployé ne s'arrête pas uniquement parce que l'App, le
  Controller ou le Relay est indisponible.
<!-- coherence: V1-OBSERVATION:start -->
- Chaque Daemon enrôlé reçoit un endpoint Relay approuvé qui borne la route, le
  port et l'identité cryptographique attendue. Le Relay n'exige pas d'adresse
  publique lorsqu'un routage privé autorisé le rend joignable aux Daemons et au
  Controller ; une adresse IP seule ne constitue jamais son identité.
- Un futur remplacement automatique du Relay reste limité aux machines
  candidates explicitement autorisées. Il doit prouver la panne, empêcher deux
  autorités actives concurrentes, redistribuer un endpoint authentifié et
  annoncer la continuité ou la perte d'état réellement garantie ; son
  mécanisme précis reste ouvert.
- Le Daemon n'accepte aucune connexion réseau entrante et le Relay ne lui donne
  jamais d'ordre. L'utilisateur choisit des observations nommées ; le Daemon les
  envoie par une connexion sortante authentifiée et conserve localement un
  tampon borné tant qu'elles ne sont pas confirmées durablement.
- L'Agent reste limité à l'observation par défaut. Une capacité locale d'action
  est activée explicitement par machine, utilise un Auxiliaire sans listener ni
  accès réseau général et ne fournit jamais de commande ou de script libre. Une
  opération OCI peut autoriser uniquement un registre et un digest exacts,
  visibles dans le plan.
- Le transport des plans d'action de `v0.1.0` reste séparé du Relay d'observation.
  Le cœur natif signe une approbation liée au contenu exact, au rollback, à la
  cible, à l'époque et à la séquence ; l'Auxiliaire la vérifie contre son état
  root-owned. Une action inconnue, expirée, rejouée ou insuffisamment autorisée
  est refusée sans mutation.
- Une action visant une plateforme disposant de sa propre API ou un moteur IaC
  passe par un adaptateur ou runner borné, pas artificiellement par l'Agent
  d'une machine.
- L'extension future de l'observation repose sur des collecteurs versionnés, à
  sortie typée et aux privilèges déclarés, jamais sur un shell distant, un
  chemin libre ou un plugin téléchargé silencieusement.
<!-- coherence: V1-OBSERVATION:end -->
- Les changements sont rejouables, vérifiables et réversibles dans les limites
  annoncées.
- Le projet est exécuté et éprouvé dans le LAB ; le laptop reste réservé à
  l'édition, Git, l'inspection et au contrôle du LAB.
- La documentation Markdown reste la source éditoriale. Les documents qui
  expliquent visuellement le produit conservent une édition HTML autonome.
- Chaque choix technique ou de développement porte une justification de
  sécurité : menace, alternatives, principes OWASP concernés, mesures NIS2
  pertinentes, preuves attendues et risque résiduel. Cette justification ne
  constitue jamais à elle seule une déclaration de conformité réglementaire.

## Manière de construire

Le [contrat `v0.1.0`](../objectifs/v1/README.md) fixe une ligne d'arrivée
globale. La [roadmap `v0.1.0`](../objectifs/v1/ROADMAP.md) ne détaille que le
chemin jusqu'à `v0.1.0`. Le cap
présent n'est pas une roadmap globale : les capacités postérieures sont cadrées
au moment où elles deviennent le prochain objectif réel.

Chaque incrément ajoute une capacité observable et prouvable avant d'ouvrir le
suivant. Son placement, son flux de données, ses commandes, ses échecs et ses
limites doivent être compréhensibles avant que le projet continue.

Un ADR n'est pas créé pour documenter chaque choix. Il n'est envisagé que pour
une décision coûteuse à renverser, surprenante sans contexte et issue d'un
véritable compromis, puis seulement après discussion avec le mainteneur.

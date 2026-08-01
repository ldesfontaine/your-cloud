# Amorçage et remplacement du Controller

> Statut : contrat d'architecture décidé, non implémenté et non prouvé. Il
> décrit le parcours qui devra être fermé avant le premier plan d'action V1.

Une [édition HTML autonome et visuelle](../html/amorcage-controller.html)
accompagne cette source Markdown.

<!-- coherence: BOOTSTRAP-RECOVERY:start -->

## Résultat recherché

L'utilisateur installe uniquement la Console sur son appareil
d'administration. Depuis cette interface, il déclare les machines Linux déjà
installées, prête temporairement un accès SSH existant, fait auditer leur
compatibilité, approuve le placement proposé, puis laisse Your Cloud installer
le premier Controller et enrôler les machines.

Le même parcours sert plus tard à remplacer explicitement un Controller perdu.
Il ne dépend donc ni du Controller à créer, ni du Controller disparu. Une fois
l'opération terminée, le Controller est autonome : éteindre le laptop ou fermer
la Console n'arrête ni l'administration future ni les services déployés.

Ce contrat ne crée aucune troisième autorité SSH ou autorité de secours. Il
distingue deux accès SSH et une authentification produit séparée :

1. l'accès d'administration personnel que l'utilisateur possède déjà ;
2. l'identité d'administration Your Cloud propre à chaque machine ;
3. l'authentification Console–Controller, qui autorise l'humain et son appareil
   dans le produit mais ne constitue pas un accès SSH aux machines.

## Assistant natif temporaire

L'**Assistant d'amorçage** appartient à l'installation signée de la Console,
mais reste distinct du frontend. Il est lancé seulement pour `Créer une
infrastructure` ou `Remplacer un Controller`, ne fournit aucun service réseau
permanent et ne conserve aucune clé SSH personnelle après l'opération.

Le frontend transmet uniquement des demandes typées et affiche les cibles, les
constats et les changements. Il ne reçoit jamais :

- une clé privée SSH ;
- le contenu d'un agent SSH ;
- un mot de passe SSH ou `sudo` ;
- une identité d'administration Your Cloud ;
- un shell, un playbook, un inventaire ou des arguments libres.

La saisie d'une passphrase de clé ou d'un mot de passe `sudo`, comme le
consentement à employer `root`, appartient à une fenêtre du cœur natif distincte
de la WebView. Cette fenêtre répète les empreintes des machines, l'étape, les
actions et l'expiration exactes. Le secret rejoint directement la mémoire de
l'Assistant ; le frontend ne peut ni le fournir par IPC, ni marquer lui-même
l'étape comme approuvée.

Une demande du frontend peut seulement ouvrir ce parcours nommé. Elle ne donne
pas accès à une primitive SSH ou de signature générale. Après la confirmation
native, l'Assistant borne l'utilisation de `ssh-agent` à la connexion SSH exacte
vers les hôtes affichés et refuse toute cible, action ou durée différente. Un
nouvel hôte, une nouvelle étape privilégiée ou une expiration impose une
nouvelle confirmation native.

L'Assistant préfère un agent SSH déjà déverrouillé : il lui demande de signer
sans extraire la clé privée. En solution de repli, il peut ouvrir une clé
chiffrée choisie par l'utilisateur et la déchiffrer uniquement dans sa mémoire
pendant l'opération. Le secret ne rejoint ni le frontend, ni le Controller, ni
un journal. La fermeture, l'échec ou le timeout détruisent cet état temporaire.

L'utilisateur peut fournir :

- de préférence, un compte d'administration non-root avec clé SSH et élévation
  `sudo` protégée par mot de passe ;
- si l'environnement l'exige, un accès SSH `root`, prêté explicitement pour
  cette opération précise.

L'accès `root` n'est jamais tenté implicitement. La Console nomme les machines,
les actions et la durée avant de le demander. Chaque nouvelle utilisation
exige un nouveau consentement et une nouvelle mise à disposition de l'accès.

Your Cloud ne supprime ni la clé personnelle de l'utilisateur, ni son compte,
ni son droit d'administration. Cet accès reste le chemin indépendant qui
permettra de remplacer le Controller. La vérification de la clé d'hôte SSH est
explicite : empreinte fournie par une source de confiance ou premier contact
affiché et confirmé, jamais acceptation silencieuse.

## Audit puis proposition

L'utilisateur déclare chaque machine une par une avec un nom, une adresse IP ou
DNS, un port SSH et son caractère privé ou exposé. L'Assistant ne scanne ni le
LAN, ni une plage d'adresses, ni un compte fournisseur.

Avant toute mutation, il effectue un audit SSH en lecture seule et rapporte au
minimum :

- l'identité et la clé d'hôte observées ;
- la distribution et l'architecture ;
- la présence de Debian 13 `amd64`, seule cible serveur prise en charge par la
  V1 ;
- systemd et cgroup v2 lorsque la machine doit héberger un service OCI géré ;
- les ressources utiles au placement ;
- une installation Your Cloud existante et ses rôles actifs ;
- les incompatibilités et les faits qu'il n'a pas pu vérifier.

La Console propose ensuite :

- un Controller sur une machine privée, de confiance et normalement allumée ;
- un Relay seulement sur une machine explicitement déclarée candidate ;
- un Agent et son Daemon sur chaque machine enrôlée ;
- l'Auxiliaire seulement comme autorité ponctuelle d'une machine placée en mode
  géré.

Pour une petite infrastructure, le Controller peut cohabiter avec d'autres
rôles sur une machine privée si ses processus, comptes, secrets, fichiers et
budgets restent séparés. Une machine ou VM dédiée est recommandée lorsque la
taille ou le risque le justifie. La Console ne propose pas par défaut le
Controller sur le VPS public qui porte le Relay et les services exposés.

Cette cohabitation partage néanmoins le domaine de panne matériel. La perte ou
l'isolement de l'hôte peut interrompre les services placés sur ce même hôte ;
Your Cloud doit l'annoncer avant le placement. La continuité du plan de données
signifie seulement que la perte du Controller n'arrête pas, par elle-même, les
services hébergés sur les autres machines. Une continuité face à la perte de
l'hôte exige donc un placement dédié ou une redondance qui n'appartient pas à
ce palier.

Une recommandation n'est pas une installation. L'utilisateur voit et approuve
le placement, les artefacts, les comptes, les flux et les privilèges exacts
avant la première mutation.

## Ressources et taille de l'infrastructure

Your Cloud ne suppose ni une flotte homogène, ni des machines rapides. L'audit
rend les ressources observées et chaque rôle annonce son coût mesuré. CPU,
mémoire, nombre de processus et espace disque sont bornés par les unités
systemd, cgroup v2 et les quotas réellement disponibles sur la cible. Le réseau
est borné séparément par les listeners, destinations, tailles, concurrences,
délais et limites de débit propres au rôle ; systemd n'est pas présenté comme
une limite réseau générique. Une cohabitation ne doit pas consommer
silencieusement toute la machine. Les délais et files sont bornés, mais une
machine lente n'est pas déclarée en échec uniquement parce qu'elle ne ressemble
pas au LAB ; les bornes retenues sont mesurées sur un profil de petite machine
et rendues visibles.

Aucun logiciel ne peut fonctionner sans minimum matériel. Lorsque les
ressources ne suffisent pas au rôle demandé, l'Assistant refuse ce placement et
explique la ressource manquante au lieu d'installer un ensemble instable. Il
peut encore proposer un rôle plus léger, une cohabitation différente ou une
machine dédiée sans modifier silencieusement les choix de l'utilisateur.

La borne actuelle de 64 machines appartient au format et aux preuves du
Controller de cette version. Elle permet une V1 finie et vérifiable ; elle
n'est pas une limite générale de Your Cloud. Les relèvements futurs partiront
de mesures de l'inventaire, de l'observation et des actions concurrentes avant
d'introduire pagination, partitionnement ou plusieurs Controllers. La V1 ne
préconçoit pas ces mécanismes, mais ne présente jamais 64 comme un plafond
durable du produit.

## Création d'une infrastructure

Après approbation, l'Assistant :

1. revérifie les cibles, clés d'hôte et préconditions observées ;
2. installe le lot serveur et le Controller sur la machine privée choisie ;
3. associe la Console à ce Controller par le mécanisme Console–Controller ;
4. fait générer sur le Controller une identité SSH différente par cible et
   obtient de la Console la clé publique qui vérifiera les approbations ;
5. vérifie depuis le Controller que chaque endpoint SSH déclaré est joignable
   et présente la clé d'hôte déjà confirmée ; si cette précondition échoue,
   aucune autre machine n'est modifiée ;
6. installe sur chaque cible l'artefact `your-cloud`, le compte technique, la
   clé publique d'approbation, l'état anti-rejeu initial et la clé SSH publique
   propre à la machine ;
7. fait vérifier depuis le Controller le nouvel accès et l'entrée ponctuelle
   de l'Auxiliaire avant d'activer l'Agent, le Daemon et l'éventuel Relay
   approuvés ;
8. détruit tout état temporaire permettant d'utiliser l'accès SSH personnel,
   sans modifier cet accès qui reste sous le contrôle de l'utilisateur, puis
   rend le résultat exact de chaque machine.

Le lot installe donc le binaire avant de rendre sa commande forcée joignable.
Dans ce palier, `your-cloud aux` sait uniquement valider son enveloppe et rendre
un diagnostic de protocole en lecture seule ; toute opération de mutation est
refusée par défaut. Le palier suivant ajoute explicitement la première
opération, la sonde OCI jetable. L'amorçage ne préautorise aucune action future.

La clé Your Cloud d'une machine ne peut ouvrir ni shell, ni PTY, ni SFTP, ni
transfert de port ou d'agent. Son entrée `authorized_keys` lance uniquement
l'Auxiliaire pour un plan typé, ciblé, approuvé et encore valide. Chaque
machine reçoit une paire différente : compromettre une identité ne donne pas
l'identité SSH des autres machines.

Sur une machine gérée, cette clé est liée à un compte technique verrouillé,
distinct des comptes Daemon et Relay et sans authentification par mot de passe.
Le fichier de clés se trouve hors d'un répertoire modifiable par ce compte :
fichier et parents appartiennent à `root` et ne sont inscriptibles ni par le
compte ni par un groupe. L'entrée emploie les restrictions OpenSSH équivalentes
à `restrict`, refuse aussi fichier rc, X11, environnement, shell, PTY, SFTP et
transferts, puis impose le chemin absolu du binaire et de ses parents
root-owned.

Une règle d'élévation possédée par `root`, avec environnement réinitialisé et
sans `SETENV`, autorise seulement l'invocation exacte de `your-cloud aux` sans
argument libre. Le plan typé arrive sur son entrée standard et est revérifié
avant que le processus ponctuel agisse avec les privilèges nécessaires. Aucune
règle `sudo` générale n'est créée.

Les clés privées opérationnelles restent sur le Controller. Leurs sources sont
des fichiers root-owned fournis en lecture au seul service Controller par les
credentials systemd ; elles ne sont copiées ni dans la Console, ni dans le
frontend, ni dans l'Agent. Le service et `root` peuvent nécessairement les lire
à l'exécution : cette protection réduit l'exposition aux autres comptes, mais
ne protège pas contre une compromission complète du Controller.

Concrètement, `root-owned` signifie que `root` possède le fichier source avec
des permissions restrictives, par exemple `0600`. Au démarrage, systemd expose
le credential dans le répertoire privé du service au lieu de placer la clé dans
la ligne de commande ou une variable d'environnement ; cette copie de runtime
disparaît avec le service. La clé opérationnelle n'attend pas une passphrase
humaine, car le Controller doit rester autonome lorsque la Console est fermée.
Sa protection repose donc sur ce stockage borné, le compte du service, les
permissions, la rotation et la sécurité de la machine Controller.

## Approbation indépendante du Controller

Le Controller construit et transporte le plan, mais ne peut pas fabriquer
l'approbation humaine. Après déverrouillage et confirmation native du contenu
affiché, le cœur de la Console signe une enveloppe canonique avec la clé humaine
Ed25519 de son association au Controller. Il n'expose au frontend aucune
opération de signature libre.

L'enveloppe versionnée lie au minimum l'infrastructure, la machine, l'époque
d'autorité, le successeur exact de la séquence propre à cette machine, le
condensat du plan et de son rollback, les privilèges, l'heure d'émission et
l'expiration. L'Assistant installe seulement la clé publique d'approbation,
liée à cette infrastructure et à cette machine, dans un fichier root-owned que
l'Auxiliaire peut lire. La clé privée reste dans le coffre natif de la Console.

Avant la première mutation, l'Auxiliaire vérifie localement la signature, tous
les liens de l'enveloppe et les contraintes de l'opération, puis consomme
atomiquement la séquence dans un état anti-rejeu root-owned. Seul le successeur
exact est accepté ; une séquence sautée, déjà consommée ou plus ancienne est
refusée, y compris après redémarrage. Cet état minimal ne contient ni secret ni
historique général des actions ; il est l'exception nécessaire à l'absence de
journal local de l'Auxiliaire. Une coupure après consommation exige une
observation puis un nouveau plan signé : le plan interrompu n'est jamais
relancé.

Le remplacement crée une nouvelle époque et, si l'association change, une
nouvelle clé publique d'approbation. Activer cette époque sur une machine
invalide l'ancienne au lieu de maintenir deux signataires. Ce contrôle empêche
un Controller compromis de forger seul une nouvelle approbation ; il ne protège
pas une Console déverrouillée compromise ni une cible dont `root` est
compromis.

La même règle ferme le cycle d'une Console récupérée sur un autre appareil. Une
rotation du seul certificat d'appareil qui conserve la clé humaine ne change
pas les ancres des machines. Si la récupération remplace la clé humaine, elle
rétablit l'API du Controller mais le chemin d'action reste verrouillé.
L'Assistant redemande alors l'accès SSH personnel et remplace, machine par
machine, la clé publique et l'époque d'approbation. Le Controller vivant ne
peut pas effectuer seul cette rotation et le code de récupération ne devient
pas une autorité d'action hors ligne.

## Remplacement explicite d'un Controller

Une indisponibilité ne déclenche jamais un remplacement automatique : une panne
réseau, une machine arrêtée et une perte définitive ne sont pas équivalentes.
La Console informe l'utilisateur, puis celui-ci choisit explicitement
`Remplacer un Controller`.

Avant toute mutation, l'utilisateur qualifie l'incident. Une perte matérielle
confirmée n'est pas une compromission. Si une compromission est soupçonnée,
l'ancien hôte doit d'abord être isolé du réseau et le nouveau Controller doit
vivre sur un hôte sain ou réinstallé depuis une base de confiance. Tant que
l'ancien Controller reste actif ou que son isolement n'est pas vérifiable,
Your Cloud affiche `remplacement non sécurisé` et ne prétend pas avoir restauré
l'autorité.

L'Assistant redemande l'accès SSH personnel et :

1. audite les machines redéclarées et leurs marqueurs gérés, sans scan réseau ;
2. refuse d'écraser silencieusement un Controller encore sain et recoupe
   l'`infrastructure_id` sur les états indépendants disponibles ;
3. installe le nouveau Controller avec un nouveau `controller_id` ; il ne
   conserve l'`infrastructure_id` que si les machines et le Relay concordent ;
4. crée une nouvelle association Console–Controller, épingle la nouvelle
   autorité TLS et démarre sans importer aucun appareil, certificat ou session
   de l'ancienne association ;
5. reprovisionne l'identité cliente Controller–Relay, l'adresse source et le
   manifeste du lecteur ; `8444` reste fermé pendant la bascule et n'accepte
   jamais simultanément les deux Controllers ;
6. réutilise les Daemons et le Relay d'ingestion compatibles, dont les
   identités ne dépendaient pas du Controller perdu ;
7. crée une nouvelle époque d'approbation et de nouvelles identités SSH propres
   à chaque machine, installe et vérifie les nouveaux accès, puis retire
   seulement les anciennes clés et ancres Your Cloud identifiées par empreinte
   et marqueur géré ;
8. vérifie qu'aucun secret, certificat, session, filtre réseau ou manifeste que
   l'ancien Controller pouvait utiliser ne lui donne encore d'autorité ;
9. archive l'ancienne association dans la Console ; si l'ancien Controller est
   encore sain et joignable, révoque explicitement son appareil et ses sessions
   avant son arrêt, puis laisse intacts les comptes, clés et accès personnels
   de l'utilisateur.

Les autorités TLS serveur et d'émission des appareils du nouveau Controller
sont nouvelles ; ses certificats d'appareil et sessions ne sont jamais copiés
depuis l'ancien. La clé privée cliente du lecteur Relay et les clés SSH
opérationnelles sont tournées parce que l'ancien Controller pouvait les lire.
Les autorités privées qui n'ont jamais résidé sur l'ancien hôte ne sont pas
renouvelées sans motif, mais chaque feuille ou manifeste qui autorisait
l'ancien `controller_id` est révoqué ou remplacé.

Le remplacement n'est pas atomique à l'échelle de plusieurs machines. Pour
chaque cible, l'Assistant rend l'un des états `ancien seul`, `chevauchement
borné`, `nouveau seul` ou `inconnu`. Une coupure peut donc laisser une flotte
partielle, mais jamais un succès inventé : au prochain lancement, l'utilisateur
reprête son accès personnel et l'Assistant reconstruit l'état depuis les
empreintes root-owned et des tests directs avant de proposer une nouvelle
étape. Il ne retire rien dans un état inconnu et ne conserve pour cette reprise
aucun secret personnel.

La création suit la même règle. Avant l'enrôlement d'une cible, un échec peut
retirer seulement les éléments nouvellement installés dont l'absence est
prouvée sans danger. Après un premier transfert d'autorité, tout arrêt rend un
état partiel machine par machine ; aucun rollback global aveugle n'est tenté.
Le succès final exige le nouveau Controller joignable, la Console associée, le
lecteur Relay limité au nouveau Controller, chaque cible en `nouveau seul` et,
en cas d'incident hostile, l'ancien hôte isolé.

Si l'inventaire de l'ancien Controller est perdu, l'utilisateur redéclare les
endpoints. Un futur plan de sauvegarde pourra réduire ce travail, mais
l'amorçage ne dépend pas d'une nouvelle autorité de récupération. Le code de
récupération de la Console conserve un autre sens : il associe une nouvelle
Console à un Controller encore vivant ; il ne restaure ni l'inventaire, ni les
identités SSH, ni un Controller détruit. Lorsqu'il remplace la clé humaine, les
actions restent verrouillées jusqu'à la rotation personnelle décrite plus haut.

Le remplacement restaure l'autorité de gestion, pas les données applicatives.
Sauvegarder et restaurer Vaultwarden, un drive ou des photos appartient au
cycle de sauvegarde des services et reste obligatoire indépendamment de la
santé du Controller.

## Distribution bornée

L'installateur de Console V1 contient l'Assistant, le binaire Go `your-cloud`
pour Debian 13 `amd64`, les définitions d'installation et un manifeste reliant
version, cible, taille et empreinte. L'Assistant sélectionne l'artefact après
l'audit puis revérifie le manifeste avant toute installation privilégiée. Il ne
télécharge aucun plugin ou binaire root à la demande.

Cette enveloppe rend le parcours initial et le remplacement reproductibles avec
le même lot. La mise à jour reste manuelle en V1. Une architecture ou
distribution supplémentaire n'est annoncée comme prise en charge qu'après une
preuve LAB dédiée ; `arm64` reste le premier incrément de portabilité envisagé
après stabilisation.

La signature synthétique Windows prouve seulement le mécanisme de build et
d'installation. La distribution Windows publique reste bloquée tant qu'une
identité de signature reconnue et gratuite n'est pas réellement opérationnelle ;
le projet ne transforme pas un certificat de test en promesse publique.

## Limites V1

La première version ne fournit :

- ni bascule ou réplication automatique du Controller ;
- ni troisième autorité SSH ou autorité de secours hors ligne ;
- ni inventaire retrouvé par scan réseau ;
- ni conservation de la clé SSH personnelle par la Console ;
- ni reprise autonome d'une action interrompue ;
- ni transaction atomique de remplacement sur toute la flotte ;
- ni shell d'administration général par l'Auxiliaire ;
- ni Ansible obligatoire dans le Controller ou sur les machines.

Une coupure pendant une action produit `résultat inconnu`. Le Controller
n'effectue aucun rejeu aveugle : après reconnexion, il observe l'état réel puis
propose seulement une réparation ou un retrait compatible avec cet état.

## Preuves attendues

Le palier d'amorçage ne sera prouvé qu'après avoir montré dans le LAB :

- audit sans mutation et absence de scan ;
- refus d'une clé d'hôte non confirmée, d'une cible incompatible et d'un rôle
  non approuvé ;
- absence de clé ou mot de passe personnel dans le frontend, le Controller, les
  fichiers persistants et les journaux ;
- prompts et consentements natifs sous Linux et Windows, avec refus d'une cible,
  d'une action ou d'une expiration différente de ce qui a été confirmé ;
- installation du Controller, fermeture de l'Assistant puis fonctionnement
  lorsque la Console et le laptop sont arrêtés ;
- refus avant mutation lorsqu'une cible n'est pas joignable en SSH depuis le
  Controller choisi ;
- artefact installé avant la commande forcée, entrée Auxiliaire de bootstrap en
  lecture seule et refus de toute mutation encore inconnue ;
- une identité SSH différente par machine et l'impossibilité d'ouvrir un shell,
  un PTY, SFTP ou un transfert ;
- répertoire de clés, chemin du binaire, environnement et élévation
  non modifiables par le compte technique ;
- refus de la clé d'une machine sur une autre ;
- plan signé par le cœur natif, Controller incapable de le modifier ou d'en
  forger un nouveau, puis refus du rejeu avant et après redémarrage ;
- récupération d'une Console avec nouvelle clé humaine laissant les actions
  verrouillées jusqu'à rotation des ancres par l'accès personnel ;
- maintien de l'accès personnel après création et remplacement ;
- remplacement explicite du Controller, nouvelle association Console,
  nouvelle identité lecteur Relay, rotation de toutes les autorités exposées,
  vérification des nouvelles clés puis retrait des seules anciennes identités
  Your Cloud ;
- isolement obligatoire d'un Controller soupçonné compromis et refus d'un
  succès sécurisé tant qu'il peut encore agir ;
- injection d'une coupure à chaque étape de création et de remplacement,
  reconstruction des états partiels et absence de retrait aveugle ;
- réutilisation d'un Agent compatible et refus d'un état altéré ou ambigu ;
- budgets respectés sur une petite machine, cohabitation isolée et comportement
  mesuré avec 1, 2 puis 64 machines ;
- aucune interruption due à la seule perte de la Console ou du processus
  Controller pour les services hébergés sur d'autres machines ; un service
  colocalisé est annoncé comme interruptible si l'hôte est perdu ou isolé.

Ces preuves emploient uniquement des identités et secrets synthétiques. Elles
ne rendent pas le Controller invulnérable et ne remplacent pas les sauvegardes
des services.

<!-- coherence: BOOTSTRAP-RECOVERY:end -->

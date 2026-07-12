# Pilotage d’infrastructures

Ce contexte décrit le langage du produit qui permet de suivre et piloter plusieurs infrastructures sans rendre leurs services dépendants de l’outil.

## Language

**Console**:
Interface utilisée par l’opérateur pour consulter et piloter ses infrastructures.
_Avoid_: Master, maître

**Machine gérée**:
Hôte déclaré dans le produit et placé sous son suivi.
_Avoid_: Agent, serveur

**Machine dédiée**:
Machine dont l’opérateur confirme que les usages et autorités existants permettent au produit de prendre en charge les politiques annoncées sans affecter une charge inconnue.
_Avoid_: Machine vide, machine disponible, machine automatiquement sûre

**Daemon d’observation**:
Composant installé sur une machine gérée qui produit sa télémétrie sans autorité de modification.
_Avoid_: Agent, exécuteur, daemon d’administration

**Exécuteur**:
Composant optionnel distinct auquel l’opérateur pourrait déléguer des actions distantes strictement bornées.
_Avoid_: Daemon d’observation, shell distant, agent

**Observation continue**:
Capacité du produit à conserver un état récent des machines gérées lorsque la console de l’opérateur est éteinte.
_Avoid_: Supervision temps réel

**Pilotage indisponible**:
État dégradé dans lequel les infrastructures continuent de servir mais ne peuvent temporairement plus être observées ni commandées à distance.
_Avoid_: Infrastructure en panne

**Confinement d’une machine**:
Garantie selon laquelle la compromission d’une machine gérée ne fournit aucun accès aux autres machines, au pilotage ou au poste de l’opérateur.
_Avoid_: Réseau de confiance

**Enrôlement**:
Passage contrôlé par lequel une machine auditée reçoit une identité propre et rejoint le suivi du produit après accord de l’opérateur.
_Avoid_: Installation, ajout automatique

**Renouvellement d’identité**:
Remplacement approuvé de l’identité d’une machine gérée qui révoque l’ancienne sans changer la machine logique ni son historique.
_Avoid_: Acceptation automatique, désenrôlement, changement d’adresse

**Coordinateur**:
Point de rencontre remplaçable par lequel les machines gérées et la console échangent leur état sans connexion entrante chez l’opérateur.
_Avoid_: Master, orchestrateur central

**Coordinateur autorisé**:
Machine gérée explicitement préparée et approuvée pour assurer la fonction de coordinateur, indépendamment des machines applicatives ordinaires.
_Avoid_: Machine disponible, agent élu automatiquement

**Point de coordination**:
Association explicite entre une localisation réseau et l’identité cryptographique d’un coordinateur autorisé.
_Avoid_: Adresse de confiance, DNS obligatoire, découverte automatique

**Reprise de coordination**:
Bascule de l’observation vers un autre coordinateur autorisé après l’indisponibilité du coordinateur courant.
_Avoid_: Élection automatique, reprise des services, exécution distante

**Mode local**:
Mode de pilotage dans lequel un coordinateur reste joignable uniquement au sein du réseau local ou du plan d’administration de l’opérateur.
_Avoid_: Mode débutant, mode hors ligne, absence de coordinateur

**Inspection ponctuelle**:
Consultation déclenchée par l’opérateur au travers du chemin d’administration sans collecte continue entre deux ouvertures de la console.
_Avoid_: Mode local, observation continue, télémétrie récente garantie

**Mode distant**:
Mode de pilotage dans lequel un ou plusieurs coordinateurs rendent les machines visibles à travers plusieurs sites sans connexion entrante chez l’opérateur.
_Avoid_: Mode cloud, mode expert

**Infrastructure**:
Regroupement logique, éventuellement vide, de machines gérées qui concourent à un même ensemble de services.
_Avoid_: Machine, cluster

**Machine disponible**:
Machine gérée qui n’est actuellement affectée à aucune infrastructure.
_Avoid_: Machine orpheline, machine libre

**Machine pilote**:
Machine gérée choisie pour prouver un changement sur un site avant son extension progressive aux autres machines concernées.
_Avoid_: Leader, machine élue, coordinateur

**Rôle**:
Responsabilité attribuée à une machine au sein de son infrastructure, cumulable avec d’autres responsabilités compatibles.
_Avoid_: Type de machine, infrastructure

**Nœud d’entrée**:
Machine chargée de recevoir les accès externes autorisés et de les transmettre aux services de son infrastructure.
_Avoid_: DMZ, VPS public

**DMZ**:
Zone de sécurité isolant les composants exposés des autres composants d’une infrastructure.
_Avoid_: Rôle, machine publique

**Plan d’administration**:
Plan de confiance depuis lequel l’opérateur détient ses autorités, prend ses décisions et approuve les changements.
_Avoid_: Console exposée, réseau public

**Plan de pilotage**:
Plan de confiance consacré à l’observation et à la coordination sans porter les services ni leurs secrets.
_Avoid_: Plan d’administration, plan de services

**Zone d’exposition**:
Zone regroupant les composants autorisés à recevoir des accès externes, indépendamment de leur emplacement physique.
_Avoid_: Cloud, IP publique, machine interne

**Chemin d’exposition**:
Voie isolée par laquelle un nœud d’entrée transmet un accès externe vers un service sans exposer directement l’adresse du backend.
_Avoid_: Chemin d’administration, réseau de confiance, réseau plat

**Zone de services et données**:
Zone regroupant les applications, calculs et données qui ne doivent pas être directement exposés par défaut.
_Avoid_: On-premise, réseau local

**Redondance**:
Présence de plusieurs machines capables d’assurer une même fonction sans garantie qu’elles résistent à une cause de panne commune.
_Avoid_: Haute disponibilité

**Haute disponibilité**:
Garantie qu’une fonction reste disponible après la perte d’un domaine de panne prévu grâce à une relève automatique entre machines indépendantes.
_Avoid_: Redondance, plusieurs machines

**Domaine de panne**:
Ensemble de machines susceptibles de devenir indisponibles pour une même cause identifiée ou déclarée.
_Avoid_: Datacenter, fournisseur

**Budget de pilotage**:
Part strictement limitée des ressources d’une machine que les composants du produit peuvent consommer au détriment des services hébergés.
_Avoid_: Ressources restantes, consommation négligeable

**Service d’infrastructure**:
Fonction applicative appartenant à une unique infrastructure et portée par une ou plusieurs de ses machines gérées.
_Avoid_: Rôle, machine, service inter-infrastructures

**Placement de service**:
Association approuvée entre un service d’infrastructure et les machines de son infrastructure qui le portent.
_Avoid_: Suggestion, attribution automatique, ordonnanceur

**Service détecté**:
Service dont l’existence a été constatée sur une machine sans observation périodique ni autorisation de modification.
_Avoid_: Service observé, service géré

**Service observé**:
Service sélectionné dont l’état est remonté périodiquement sans que le produit soit autorisé à le modifier.
_Avoid_: Service géré, service sain

**Service géré**:
Service que le produit est explicitement autorisé à modifier selon un plan approuvé.
_Avoid_: Service détecté, service observé

**Gestion externe**:
Régime dans lequel le cycle de vie d’un service reste sous l’autorité de configuration d’un outil extérieur au produit.
_Avoid_: Plugin, service abandonné, gestion concurrente

**Service d’identité d’infrastructure**:
Service géré qui authentifie les utilisateurs des applications hébergées sans porter l’identité d’administration du produit.
_Avoid_: Identité d’administration, IAM du produit, racine de confiance

**Service protégé**:
Service géré dont tout accès exposé exige l’autorisation d’un service d’identité d’infrastructure.
_Avoid_: Service privé, service sain

**Service public**:
Service géré dont l’accès exposé contourne explicitement le service d’identité d’infrastructure après justification de l’opérateur.
_Avoid_: Service non protégé, bypass implicite

**Journal d’état**:
Historique borné des changements significatifs observés sur les machines et services, distinct d’une conservation complète des métriques.
_Avoid_: Logs, base de séries temporelles

**État de machine**:
Vue récente, bornée et non sensible de la santé d’une machine gérée, accompagnée de l’instant où elle a été observée.
_Avoid_: Inventaire exhaustif, configuration, état désiré, logs

**Lacune de télémétrie**:
Intervalle signalé pendant lequel le journal borné n’a pas pu conserver toutes les observations produites.
_Avoid_: État sain, panne de service, perte silencieuse

**Télémétrie**:
Données d’observation dérivées et perdables dont la disparition n’altère ni les infrastructures ni leur configuration.
_Avoid_: État désiré, sauvegarde

**Enveloppe signée**:
Unité de télémétrie dont le contenu exact est lié à une identité de machine par une signature et doit être relayé sans réécriture.
_Avoid_: Réponse du coordinateur, donnée reconstruite, transport chiffré

**Identité de machine**:
Identité unique créée lors de l’enrôlement à partir d’une clé privée qui reste sur la machine et d’une partie publique approuvée par la console.
_Avoid_: Nom de machine, adresse IP, secret de flotte

**Clé d’hôte SSH**:
Partie publique par laquelle la console reconnaît le serveur SSH contacté, distincte de l’identité du daemon et des clés d’administration.
_Avoid_: Identité de machine, clé utilisateur, adresse IP

**Registre d’identités**:
État durable et non secret par lequel la console associe chaque machine logique à ses identités publiques actives ou révoquées.
_Avoid_: Déclaration d’infrastructure, cache de coordinateur, trousseau privé

**Provenance vérifiable**:
Garantie permettant à la console de vérifier qu’une donnée a bien été produite par l’identité de machine annoncée, indépendamment du coordinateur qui la relaie.
_Avoid_: Transport chiffré, donnée reçue

**Séquence de télémétrie**:
Compteur croissant propre à un flux signé d’une identité de machine qui permet de détecter les doublons, retours en arrière et messages rejoués.
_Avoid_: Horodatage, identifiant aléatoire, ordre de réception

**Accusé de réception durable**:
Confirmation par un coordinateur autorisé qu’une télémétrie identifiée par sa séquence a été enregistrée durablement et peut être retirée du journal local.
_Avoid_: Succès réseau, réponse HTTP, donnée seulement reçue en mémoire

**Opérateur**:
Personne qui possède les autorités de la console et approuve les actions sur ses infrastructures.
_Avoid_: Utilisateur final, coordinateur, agent

**Identité d’administration**:
Identité par laquelle un opérateur s’authentifie et reçoit l’autorisation d’approuver des changements.
_Avoid_: Identité de machine, clé SSH, session

**Identité de transport de console**:
Identité cryptographique limitée par laquelle la console lit la télémétrie d’un coordinateur sans obtenir d’autorité d’administration.
_Avoid_: Identité d’administration, identité de machine, clé SSH

**Compte d’administration de machine**:
Compte système non-root par lequel la console applique sur une machine les changements approuvés de l’opérateur au travers du chemin d’administration.
_Avoid_: Identité d’administration, compte du daemon, compte root, compte de bootstrap

**Accès résiduel**:
Moyen de connexion administrative encore actif après une sécurisation mais non créé, adopté ni révoqué par le produit.
_Avoid_: Accès approuvé, accès supprimé, backdoor présumée

**Machine observable**:
Machine gérée dont la télémétrie peut être consultée sans disposer d’un canal d’administration actif.
_Avoid_: Machine administrable, machine saine

**Machine administrable**:
Machine gérée pour laquelle l’opérateur dispose d’un canal de maintenance explicitement autorisé.
_Avoid_: Machine observable, machine joignable

**Désaffectation**:
Retrait d’une machine de son infrastructure qui la rend disponible sans révoquer son identité ni désinstaller le daemon.
_Avoid_: Désenrôlement, désinstallation

**Désenrôlement**:
Révocation de l’identité d’une machine qui met fin à son suivi sans modifier ses services hébergés.
_Avoid_: Désaffectation, destruction

**Désinstallation**:
Suppression explicite du daemon et de ses données propres sans supprimer les services hébergés par la machine.
_Avoid_: Désenrôlement, destruction de machine

**Plan d’action**:
Présentation préalable des changements, impacts et refus éventuels qu’une action approuvée produirait sur une infrastructure.
_Avoid_: Exécution, suggestion automatique

**Audit préalable**:
Inspection ponctuelle en lecture seule qui établit la compatibilité, les conflits et les risques avant de proposer une mutation.
_Avoid_: Télémétrie, inventaire continu, approbation

**Autorité de configuration**:
Composant explicitement reconnu comme seul responsable d’une politique système donnée sur une machine.
_Avoid_: Outil détecté, configuration fusionnée

**Dérive de configuration**:
Écart constaté entre une politique approuvée et l’état réel d’une machine, dont la provenance doit être comprise avant toute correction.
_Avoid_: Erreur automatiquement réparable, changement autorisé, non-conformité globale

**Chemin d’administration**:
Voie explicitement autorisée et vérifiée par laquelle l’opérateur peut maintenir une machine sans exposer durablement SSH à Internet.
_Avoid_: Port public, accès implicite

**Accès hors bande**:
Voie de récupération indépendante du chemin d’administration réseau courant, telle qu’une console fournisseur, une console physique ou une interface de gestion dédiée.
_Avoid_: Deuxième session SSH, coordinateur, tunnel d’administration

**Rollback armé**:
Restauration de la configuration précédente préparée avant un changement risquant de couper l’administration, sans promettre une transaction complète de la machine.
_Avoid_: Sauvegarde complète, snapshot obligatoire, annulation garantie de tout effet

**Profil de sécurisation**:
Ensemble borné de protections système visant un niveau minimal déclaré sans prétendre certifier toute la machine.
_Avoid_: Machine sécurisée, rôle applicatif, conformité complète

**Mise à jour pilotée**:
Passage volontaire d’un composant du produit vers une version précise dont l’origine et l’intégrité sont vérifiées, avec un chemin de retour préparé.
_Avoid_: Mise à jour automatique, version flottante, auto-update

**Politique de correctifs système**:
Choix approuvé qui détermine comment une machine détecte et installe les correctifs de sécurité fournis par sa distribution.
_Avoid_: Mise à jour pilotée, changement de distribution, redémarrage automatique

**Déclaration d’infrastructure**:
Description lisible et durable de la composition et de l’état désiré d’une infrastructure.
_Avoid_: Cache, télémétrie, base interne

**Secret d’infrastructure**:
Information sensible nécessaire au pilotage ou aux services, conservée séparément de la déclaration d’infrastructure.
_Avoid_: Variable de configuration, valeur en clair

**Référence de secret**:
Identifiant non sensible par lequel une déclaration désigne un secret conservé dans un stockage séparé.
_Avoid_: Valeur secrète, mot de passe, clé privée

**Kit de récupération**:
Artefact chiffré exporté par l’opérateur pour restaurer l’accès aux secrets gérés après la perte de sa console.
_Avoid_: Backup d’infrastructure, clé active, secret en clair

**Politique de sauvegarde**:
Règles décrivant les données protégées, les copies, destinations, domaines de panne, rétentions et preuves de restauration d’une infrastructure.
_Avoid_: Kit de récupération, réplication, snapshot unique, synchronisation

## Relationships

- Une **Console** présente l’état d’une ou plusieurs **Machines gérées**.
- Une **Console** peut gérer plusieurs **Infrastructures** distinctes.
- L’**Observation continue** ne dépend pas de la disponibilité de la **Console**.
- Un **Pilotage indisponible** n’interrompt jamais les services des **Machines gérées**.
- Le **Confinement d’une machine** s’applique individuellement à chaque **Machine gérée**, y compris lorsqu’elle se trouve en DMZ.
- L’**Enrôlement** transforme une machine auditée en **Machine gérée**, installe son **Daemon d’observation** et n’installe aucun **Exécuteur**.
- L’**Enrôlement** et l’observation n’exigent pas qu’une **Machine gérée** soit une **Machine dédiée**.
- Le parcours guidé enrôle d’abord une machine comme **Machine disponible**, puis propose de créer ou choisir son **Infrastructure** ; l’affectation n’est jamais une condition de l’observation.
- Un **Daemon d’observation** ne reçoit aucune **Autorité de configuration** et ne devient jamais un **Exécuteur**.
- Un éventuel **Exécuteur** possède un processus, un compte système et une identité distincts, et n’est installé qu’au moyen d’un **Plan d’action** explicite.
- La **Console** et les **Machines gérées** contactent un **Coordinateur** sans accepter de connexion entrante pour le pilotage.
- Un **Coordinateur** ne reçoit aucun **Secret d’infrastructure**, aucune clé d’administration privée et aucune autorité de déchiffrement.
- Un **Coordinateur** peut relayer une donnée chiffrée de bout en bout sans être autorisé à l’ouvrir.
- Un **Coordinateur** peut être colocalisé avec un **Nœud d’entrée** dans une petite infrastructure, mais reste une fonction et une autorité distinctes dont la réduction d’isolation est visible.
- Un **Coordinateur autorisé** est d’abord enrôlé, audité et sécurisé comme **Machine gérée** avant de recevoir la fonction de coordination par un **Plan d’action** distinct.
- L’appartenance de l’hôte d’un **Coordinateur** à une **Infrastructure** ne limite pas les infrastructures qu’il peut coordonner, car la coordination appartient au **Plan de pilotage** et n’est pas un **Service d’infrastructure**.
- Le **Daemon d’observation** et le **Coordinateur** colocalisés conservent des comptes, identités et stockages distincts ; leur auto-observation ne prouve pas la disponibilité indépendante de l’hôte.
- Un **Point de coordination** peut utiliser une adresse IP ou un nom DNS ; aucun des deux ne suffit à établir la confiance sans l’identité cryptographique attendue.
- Un changement de résolution DNS ne peut mener qu’à un **Coordinateur autorisé** présentant l’identité attendue ; une nouvelle identité exige une approbation explicite.
- Seul un **Coordinateur autorisé** peut reprendre la fonction d’un **Coordinateur** indisponible.
- Une **Reprise de coordination** n’élit jamais une machine ordinaire et ne prétend assurer ni la reprise des services ni celle des commandes.
- Pendant une **Reprise de coordination**, le **Daemon d’observation** conserve un journal borné et la **Console** distingue une télémétrie retardée d’un état sain actuel.
- Le **Mode local** utilise le même **Coordinateur** et les mêmes garanties cryptographiques que le **Mode distant**, sans exposer son **Point de coordination** à Internet.
- Un **Coordinateur autorisé** peut être colocalisé avec son **Daemon d’observation** sur l’unique machine toujours allumée d’un **Mode local**.
- Sans **Coordinateur** disponible en permanence, la **Console** ne fournit qu’une **Inspection ponctuelle** et ne prétend pas assurer l’**Observation continue**.
- Le passage d’un site vers un nouveau **Point de coordination** commence par une **Machine pilote** qui conserve l’ancien point comme secours jusqu’à preuve du nouveau chemin.
- L’échec d’une **Machine pilote** arrête l’extension du changement sans retirer l’ancien **Coordinateur autorisé** aux autres machines.
- Une infrastructure peut évoluer du **Mode local** vers le **Mode distant** sans réenrôler ses **Machines gérées**.
- Une **Infrastructure** contient zéro, une ou plusieurs **Machines gérées**.
- Une **Machine disponible** peut rejoindre une **Infrastructure** sans nouvel **Enrôlement**.
- Une **Machine gérée** peut quitter une **Infrastructure** et en rejoindre une autre sans perdre son identité.
- Une **Machine gérée** appartient à zéro ou une **Infrastructure**, jamais plusieurs simultanément.
- Une **Machine gérée** peut cumuler plusieurs **Rôles** compatibles dans son unique **Infrastructure**.
- Un **Nœud d’entrée** appartient à une **Zone d’exposition** ; une **DMZ** est une manière classique de réaliser cette zone.
- Un **Nœud d’entrée** n’atteint un service de la **Zone de services et données** qu’au travers d’un **Chemin d’exposition** limité aux flux explicitement publiés.
- La **Redondance** ne devient une **Haute disponibilité** que lorsque la relève est automatique et que les machines ne partagent pas le domaine de panne couvert.
- Un **Domaine de panne** peut être détecté par le produit ou précisé par l’opérateur, avec sa provenance toujours visible.
- L’**Observation continue** doit respecter le **Budget de pilotage** de chaque **Machine gérée**.
- Un **Service d’infrastructure** appartient à exactement une **Infrastructure** et dépend d’une ou plusieurs **Machines gérées** de celle-ci.
- L’accès à un **Service d’infrastructure** depuis une autre infrastructure ne change ni son appartenance ni son **Placement de service**.
- La **Console** peut proposer un **Placement de service**, mais seul un **Plan d’action** approuvé l’établit ou le modifie.
- Un **Service détecté** ne devient un **Service observé** qu’après sélection explicite ou installation par le produit.
- Observer un **Service observé** ne donne aucun droit de **Service géré**.
- Un **Service observé** peut relever d’une **Gestion externe** sans que le produit soit autorisé à modifier son cycle de vie.
- La **Gestion externe** d’un service n’interdit pas au produit de gérer une politique d’exposition distincte dont il est l’unique **Autorité de configuration**.
- Un **Service d’identité d’infrastructure** peut protéger des **Services gérés**, mais le **Plan d’administration** nécessaire à sa restauration ne dépend jamais de lui.
- Tout service nouvellement exposé devient un **Service protégé** par défaut.
- Un **Service public** exige une exception explicite et reste disponible lorsque le **Service d’identité d’infrastructure** est indisponible.
- Un **Service protégé** refuse les accès lorsque son **Service d’identité d’infrastructure** est indisponible.
- L’**Observation continue** alimente le dernier état connu et le **Journal d’état** sans conserver toutes les mesures brutes.
- Un **Daemon d’observation** produit un **État de machine** sans lire ni transmettre le contenu des fichiers, journaux, commandes ou secrets de la machine.
- Une **Machine observable** présente son dernier **État de machine** avec sa date et sa **Provenance vérifiable**, jamais comme une vérité actuelle lorsque la télémétrie est retardée.
- Après une coupure, le **Daemon d’observation** envoie d’abord l’état actuel puis les changements significatifs encore présents dans son **Journal d’état**, sans rejouer les mesures brutes intermédiaires.
- Un débordement du **Journal d’état** produit une **Lacune de télémétrie** explicite plutôt qu’une perte silencieuse.
- Le **Journal d’état** et le dernier état connu sont de la **Télémétrie** reconstructible.
- La **Déclaration d’infrastructure** reste indépendante de la **Télémétrie** et peut être versionnée sans imposer Git à l’opérateur.
- Chaque **Machine gérée** possède sa propre **Identité de machine**.
- Au premier bootstrap explicitement ciblé, la **Console** peut enregistrer la **Clé d’hôte SSH** présentée si aucune référence plus fiable n’est disponible ; elle rend son empreinte et sa provenance visibles.
- Après ce premier contact, toute nouvelle **Clé d’hôte SSH** est refusée jusqu’à un renouvellement explicitement vérifié et n’est jamais acceptée par simple correspondance d’adresse ou de nom.
- La **Console** est l’unique autorité de référence du **Registre d’identités** ; un **Coordinateur** n’en conserve qu’une copie dérivée.
- La partie privée d’une **Identité de machine** ne quitte jamais sa machine ; un **Coordinateur** ne reçoit que le matériel public nécessaire à l’accepter ou la révoquer.
- Une adresse, un nom d’hôte ou les caractéristiques d’une machine ne remplacent jamais la preuve de son **Identité de machine**.
- Un **Renouvellement d’identité** exige un **Chemin d’administration** vérifié, révoque l’ancienne identité et conserve l’affectation ainsi que l’historique de la **Machine gérée**.
- La **Télémétrie** importante doit conserver une **Provenance vérifiable** jusqu’à la **Console**.
- Une **Enveloppe signée** est conservée et relayée par le **Coordinateur** sous sa forme exacte ; la **Console** vérifie sa signature avant de faire confiance à son contenu décodé.
- L’**État de machine** et le **Journal d’état** possèdent des **Séquences de télémétrie** distinctes afin que l’état courant puisse précéder la reprise des anciens événements sans les rendre invalides.
- Un événement du **Journal d’état** n’est purgé qu’après un **Accusé de réception durable** portant sa **Séquence de télémétrie** ; sa retransmission avec la même identité et la même séquence ne crée aucun doublon.
- La première version d’une **Console** appartient à un seul **Opérateur**.
- Un **Opérateur** utilise une **Identité d’administration** distincte des **Identités de machine**.
- La **Console** utilise une **Identité de transport de console** distincte pour lire les **Enveloppes signées** d’un **Coordinateur** ; cette identité ne permet ni enrôlement, ni changement, ni autorisation d’une autre identité.
- Un **Daemon d’observation** ne peut publier que pour sa propre **Identité de machine**, tandis qu’une **Identité de transport de console** ne peut que lire la **Télémétrie** autorisée.
- Le compte initial fourni avec une machine peut servir temporairement au bootstrap, mais ne devient pas automatiquement son **Compte d’administration de machine**.
- Le premier profil sécurisé crée ou adopte explicitement un **Compte d’administration de machine** non-root, puis prouve une nouvelle connexion et son élévation avant de fermer un ancien accès.
- Chaque **Compte d’administration de machine** reçoit une clé propre à sa machine ; sa partie privée est un **Secret d’infrastructure** détenu par la **Console**, jamais par un **Coordinateur**.
- Les secrets SSH gérés par la **Console** restent séparés des clés, de la configuration, des hôtes connus et de l’agent SSH personnels de l’**Opérateur**.
- Après preuve du **Compte d’administration de machine**, le **Profil de sécurisation** interdit l’authentification SSH par mot de passe et la connexion directe de root.
- Un compte ou une clé SSH que le produit ne possède pas reste un **Accès résiduel** visible ; sa révocation exige un **Plan d’action** séparé.
- Une **Machine observable** n’est pas nécessairement une **Machine administrable**.
- Une **Désaffectation** produit une **Machine disponible** encore observable.
- Une **Désaffectation** est refusée tant que des **Rôles** ou services actifs dépendent de la machine sans plan de sortie approuvé.
- Un **Désenrôlement** révoque l’**Identité de machine** avant toute purge différée de sa **Télémétrie**.
- Une **Désinstallation** ne supprime jamais les services de l’**Infrastructure**.
- L’**Enrôlement** n’applique aucun **Rôle** d’infrastructure ; un rôle ne peut être appliqué qu’au moyen d’un **Plan d’action** approuvé.
- La première application d’un **Profil de sécurisation** exige un **Audit préalable** concluant et la confirmation explicite que la cible est une **Machine dédiée**.
- La confirmation d’une **Machine dédiée** est nécessaire mais ne permet jamais de contourner un conflit technique détecté par l’**Audit préalable**.
- Un **Audit préalable** ne collecte que les preuves nécessaires au **Plan d’action** concerné ; il ne devient ni un inventaire exhaustif ni une nouvelle source de **Télémétrie**.
- Un **Plan d’action** refuse de modifier une politique lorsque son **Autorité de configuration** est inconnue ou concurrente.
- Une **Dérive de configuration** reste visible sans être corrigée tant qu’un nouveau **Plan d’action** n’a pas été approuvé.
- Une **Dérive de configuration** sur une politique dont l’**Autorité de configuration** n’est plus certaine provoque un refus plutôt qu’un écrasement.
- Un **Profil de sécurisation** est refusé avant toute modification si l’**Autorité de configuration** du pare-feu hôte est inconnue, concurrente ou détenue par un outil extérieur.
- Un **Profil de sécurisation** refuse les accès entrants qui ne servent ni un **Chemin d’administration** ni un **Chemin d’exposition** explicitement approuvé ; il n’ouvre aucun service par anticipation.
- Un **Profil de sécurisation** protège toutes les familles réseau actives ; un **Chemin d’exposition** choisit explicitement celles sur lesquelles un service devient joignable.
- Le **Profil de sécurisation** V1 n’impose pas une politique générique de restriction des sorties ; l’isolation entre zones demeure une responsabilité explicite de l’architecture réseau.
- Un **Profil de sécurisation** ne modifie un réglage système que lorsque son bénéfice, son autorité et sa compatibilité avec les responsabilités de la machine sont établis.
- Le **Plan d’administration** atteint une **Machine administrable** uniquement par un **Chemin d’administration** validé.
- Après le bootstrap, un **Chemin d’administration** repose sur le LAN restreint, WireGuard ou une identité courte avec SSO/MFA, jamais sur un SSH public permanent.
- La création ou l’adoption d’un **Chemin d’administration** précède tout **Plan d’action** de sécurisation qui dépend de ce chemin ; ce dernier ne crée jamais implicitement le tunnel ou le réseau dont il dépend.
- Un parcours guidé peut enchaîner la préparation du **Chemin d’administration** et la sécurisation, mais chacun reste un **Plan d’action** distinct avec ses propres preuves et son propre retour arrière.
- Un **Plan d’action** qui peut interrompre un **Chemin d’administration** est refusé sans **Rollback armé**.
- En V1, le **Rollback armé** conserve la session courante, prépare les configurations précédentes et exige la confirmation d’un **Accès hors bande** ; il n’installe aucun minuteur de restauration autonome.
- Le nouveau **Chemin d’administration** est prouvé par une connexion distincte avant de fermer la session conservée ; un échec restaure la configuration précédente par cette session ou, en dernier recours, par l’**Accès hors bande**.
- Le **Daemon d’observation** et le **Coordinateur** évoluent uniquement par une **Mise à jour pilotée** approuvée par l’**Opérateur** ; ils ne téléchargent ni n’installent seuls une nouvelle version.
- Le **Profil de sécurisation** recommande une **Politique de correctifs système** automatique limitée à la sécurité, mais seul l’**Opérateur** peut l’activer et peut lui préférer un simple signalement.
- Une **Politique de correctifs système** ne change jamais la distribution, ne met jamais à jour les composants du produit et ne redémarre jamais automatiquement la machine.
- Le **Plan d’administration**, le **Plan de pilotage**, la **Zone d’exposition** et la **Zone de services et données** sont logiques et ne dépendent pas d’un emplacement cloud ou sur site.
- Une petite **Infrastructure** peut colocaliser plusieurs plans sur une machine, avec cette réduction d’isolation rendue explicite.
- Une **Infrastructure** possède une **Déclaration d’infrastructure** qui constitue sa source de vérité.
- Le parcours guidé et l’édition directe produisent la même **Déclaration d’infrastructure** et traversent les mêmes validations et **Plans d’action**.
- Un **Secret d’infrastructure** n’apparaît jamais en clair dans une **Déclaration d’infrastructure**, qui ne porte que sa **Référence de secret**.
- Une **Référence de secret** peut être versionnée sans rendre versionnable la valeur du **Secret d’infrastructure**.
- L’**Enrôlement** et l’observation restent possibles sans **Kit de récupération**.
- Le premier **Plan d’action** qui introduit un secret non régénérable exige un **Kit de récupération** exporté hors de la console et vérifié sur une donnée de test.
- Le **Kit de récupération** remet la **Console** en capacité d’accéder à son état ; il ne remplace jamais une **Politique de sauvegarde** des services et données d’infrastructure.
- Une **Politique de sauvegarde** rend visibles l’indépendance réelle de ses copies et leurs **Domaines de panne**, puis exige une preuve de restauration plutôt qu’un simple succès de copie.

## Example dialogue

> **Développeur :** « La **Console** doit-elle rester ouverte pour suivre une **Machine gérée** ? »
> **Expert du domaine :** « Non, l’**Observation continue** doit fonctionner même lorsque mon laptop est éteint. »

## Flagged ambiguities

- « agent » mélangeait l’assistant de développement, le **Daemon d’observation** et un éventuel **Exécuteur** ; le produit utilise désormais ces deux derniers termes distincts.
- « master » est écarté pour la **Console**, car celle-ci ne doit pas être indispensable au fonctionnement des infrastructures.
- « prendre le relais » est remplacé par **Reprise de coordination** lorsqu’il s’agit de l’observation ; la continuité des services et celle des commandes restent des garanties distinctes.
- « DMZ » ne désigne plus une machine ou un rôle ; le terme désigne uniquement une zone de sécurité.
- « accès à une machine » mélangeait observation et administration ; utiliser **Machine observable** ou **Machine administrable** selon le cas.
- « tunnel » mélangeait **Chemin d’administration** et **Chemin d’exposition** ; ils restent distincts même lorsqu’ils reposent sur la même technologie.
- « IAM » mélangeait l’**Identité d’administration** du produit et le **Service d’identité d’infrastructure** qui protège les applications hébergées ; ces autorités restent indépendantes.
- « service partagé » ne désigne pas un service commun à plusieurs infrastructures ; un **Service d’infrastructure** peut être répliqué sur plusieurs machines de son unique infrastructure.
- « configuration » et « déclaration » désignaient la même source de vérité ; **Déclaration d’infrastructure** est le terme retenu.

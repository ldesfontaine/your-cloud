# Contexte

Ce fichier est uniquement le glossaire minimal de Your Cloud ; il ne contient
ni roadmap, ni choix de technologie, ni spécification détaillée.

## Language

**Utilisateur**:
Personne qui représente, observe ou fait évoluer son infrastructure depuis Your Cloud.

**Infrastructure**:
Groupe logique dans lequel l'utilisateur rassemble des machines et les services qui y sont placés.

**Machine**:
Hôte Linux physique ou virtuel déjà installé et accessible à Your Cloud jusqu'à `v0.1.0`.

**Machine enrôlée**:
Machine dont l'identité a été explicitement approuvée pour rejoindre une infrastructure Your Cloud.

**Service**:
Application ou capacité que l'utilisateur veut exécuter sur une ou plusieurs machines.

<!-- coherence: V1-APP-ACCESS:start -->
**Your Cloud**:
Produit formé par une App et un ou plusieurs Controllers, sans confondre leur interface et leur autorité.

**App**:
Application cliente installée et signée sur un appareil administrateur. Elle embarque l'interface, conserve les associations approuvées vers des Controllers et recueille les demandes sans être la source de leur inventaire ni conserver de secret de machine. Elle n'héberge aucun serveur local et ne télécharge pas son code depuis un Controller.
Dans le profil géré, elle présente une opération de connexion privée nommée pour
chaque infrastructure sans exposer à l'administrateur une configuration réseau
libre.

**Controller**:
Backend privé d'autorité d'une seule infrastructure, chargé de ses utilisateurs, de son état métier, de ses plans et de leur coordination. Il expose une API authentifiée mais n'héberge aucun frontend.
<!-- coherence: V1-APP-ACCESS:end -->

<!-- coherence: BOOTSTRAP-RECOVERY:start -->
**Amorçage**:
Parcours qui utilise temporairement l'accès personnel pour installer un Controller, créer les identités Your Cloud et enrôler les machines.
_Avoid_: « découverte automatique », car l'utilisateur déclare chaque machine et prête lui-même l'accès initial.

**Assistant d'amorçage**:
Composant temporaire de l'App qui utilise l'accès personnel seulement pendant un amorçage ou un remplacement du Controller, sans le transmettre au frontend ni le conserver.
_Avoid_: « Controller local », car l'Assistant s'arrête après le transfert d'autorité.

**Accès d'administration personnel**:
Accès SSH indépendant que l'utilisateur apporte, conserve et peut reprêter pour remplacer le Controller ; Your Cloud ne le possède pas et ne le retire jamais.
_Avoid_: « clé de secours Your Cloud », car cet accès reste sous l'autorité de l'utilisateur.

**Identité d'administration Your Cloud**:
Accès SSH opérationnel propre à une machine, détenu par son Controller et limité au lancement de l'Auxiliaire local pour un plan que l'utilisateur a explicitement approuvé.
_Avoid_: « clé SSH globale », car deux machines ne partagent jamais cette identité.

**Remplacement du Controller**:
Amorçage explicite après la perte ou l'isolement d'un Controller, qui associe l'App à son remplaçant et renouvelle ses autorités sans réinstaller les Agents compatibles.
_Avoid_: « récupération de l'App », qui réassocie seulement une App à un Controller encore vivant.

Il existe exactement deux catégories d'accès SSH d'administration des machines :
l'accès personnel conservé par l'utilisateur et l'identité Your Cloud propre à
chaque machine. L'authentification App–Controller autorise l'humain dans le
produit, mais ne constitue pas une troisième autorité SSH.
<!-- coherence: BOOTSTRAP-RECOVERY:end -->

<!-- coherence: AGENT-AUTHORITY:start -->
**Agent**:
Frontière de l'installation locale unique de Your Cloud sur une machine enrôlée, qui n'est pas elle-même un processus et ne regroupe que les rôles explicitement activés pour cette machine.

**Daemon**:
Processus permanent non privilégié fourni par l'Agent, chargé uniquement des échanges sortants d'observation sans connaître le Controller ni appliquer lui-même de changement privilégié.

**Auxiliaire local**:
Processus ponctuel de l'Agent qui vérifie puis applique sur sa machine une opération explicitement approuvée, sans devenir un shell ni un service permanent.

**Relay**:
Rôle activé seulement sur une machine candidate qui authentifie, borne, persiste et accuse les observations des Daemons sans porter d'utilisateur ni d'action.
<!-- coherence: AGENT-AUTHORITY:end -->

<!-- coherence: V1-NETWORK:start -->
**Point d'entrée public**:
Fonction joignable depuis Internet qui reçoit le trafic Web destiné aux services publiés.

**Zone d'exposition**:
Zone logique qui contient les composants autorisés à recevoir du trafic extérieur.

**DMZ**:
Zone d'exposition séparée d'Internet et des zones privées par des frontières réseau filtrantes indépendantes.

**Passage privé**:
Liaison chiffrée entre deux machines enrôlées sans ouverture entrante vers le LAN privé.
<!-- coherence: V1-NETWORK:end -->

**Plan d'action**:
Description lisible et figée d'un changement proposé, de sa cible, de ses effets et des autorités nécessaires avant son approbation.

**Plan de déploiement**:
Plan d'action consacré à l'installation, la mise à jour ou au retrait d'un service.

<!-- coherence: SERVICE-LIFECYCLE:start -->
**Bascule**:
Changement contrôlé qui fait passer le trafic ou l'autorité d'écriture d'une source vers une destination préparée.

**Fenêtre de retour**:
Période annoncée après une bascule pendant laquelle l'ancien état reste conservé et un retour demeure pris en charge dans ses limites explicites.

**Point de non-retour**:
Événement après lequel restaurer simplement l'ancien placement ou l'ancienne route pourrait perdre ou rendre incohérentes des données nouvelles.
<!-- coherence: SERVICE-LIFECYCLE:end -->

<!-- coherence: V1-OBSERVATION:start -->
**Observation ancienne**:
Dernier état reçu d'une machine dont l'âge dépasse la limite annoncée et qui ne doit plus être présenté comme actuel.

**Profil d'observation**:
Sélection approuvée d'informations nommées que le Daemon peut relever sur des cibles explicitement déclarées.

**Lacune d'observation**:
Intervalle signalé pour lequel le tampon local n'a pas pu conserver toutes les observations en attente.
<!-- coherence: V1-OBSERVATION:end -->

**Profil de service**:
Définition bornée d'un type de service que Your Cloud sait proposer dans un plan. Sa disponibilité ne crée aucune ressource : chaque instance exige une déclaration, un placement, un plan et une approbation explicites. Un profil utilisé comme référence dans le LAB n'est pas imposé aux infrastructures utilisateur.

**Définition de service**:
Document inerte rédigé par l'utilisateur dans des bornes fermées, puis gelé et haché par le Controller. Elle décrit un service sans produire aucun effet : seul un plan approuvé et signé peut l'épingler par son digest et en faire naître une instance.
_Avoid_: « catalogue », car aucune liste d'applications n'est fournie ni promise ; chaque définition est écrite, gelée et déployée sous l'autorité de son utilisateur.

**Révision**:
Nouveau gel d'une définition de service sous le même nom, qui coexiste avec les gels précédents sans jamais les remplacer ni les effacer. Chaque instance déployée nomme la révision exacte qu'elle exécute.

**Consentement**:
Ce qu'une surface séparée de l'interface recueille auprès de l'humain et rend : la preuve qu'il a lu et accepté les phrases exactes qui décrivent un plan et son retour. Il ne prouve jamais que ces phrases décrivent fidèlement le plan ; cette fidélité est prouvée par le composant qui a dérivé les phrases et re-dérivée sur la machine.
_Avoid_: « confirmation de l'interface », car la surface qui affiche le reste du produit n'est pas celle qui recueille le consentement.

**Rapport d'exécution**:
Conclusion que la machine rend après une opération approuvée : ce qu'elle a vérifié, ce qu'elle a changé et ce qui survit. Il appartient à la machine et jamais à ce qui a transporté le plan ; son absence est un état affiché, jamais un succès supposé.
_Avoid_: « accusé de réception », car un plan parti n'est pas un plan appliqué.

## Relationships

- Une **Infrastructure** regroupe des **Machines** et leurs **Services**.
- Une **Machine** devient une **Machine enrôlée** seulement après approbation de
  son identité.
- Deux **Machines enrôlées** ne reçoivent aucune autorisation mutuelle générale :
  chaque communication reste limitée à un besoin déclaré.
- Un **Service** est placé sur au moins une **Machine**.
- Chaque **Machine** gérée par `v0.1.0` reçoit un **Agent** dont le **Daemon** ne
  fait encore qu'observer.
- Les **Daemons** transmettent leurs observations au **Relay**.
- Une machine n'active pas nécessairement le rôle **Relay**, mais la chaîne
  d'observation de `v0.1.0` exige un Relay explicitement provisionné pour l'infrastructure.
- Un **Daemon** connaît uniquement son **Relay** approuvé. Il ne connaît aucun
  **Controller** et ne reçoit aucune action de sa part.
- L'**Utilisateur** agit dans une **App**. L'App contacte le
  **Controller** approuvé de l'**Infrastructure** concernée ; elle peut conserver
  plusieurs associations indépendantes sans fusionner leurs autorités.
- Un **Agent** peut rester limité à l'observation. Activer un **Auxiliaire local**
  constitue un choix explicite de gestion pour la machine concernée.
- Un **Auxiliaire local** n'applique qu'un **Plan d'action** approuvé qui cible
  sa propre machine et une opération qu'il connaît.
- Un **Profil d'observation** donne au **Daemon** le droit de relever uniquement
  les informations nommées qu'il sait prendre en charge, jamais d'exécuter une
  commande arbitraire.
- Une **Lacune d'observation** reste visible et ne doit jamais être remplacée par
  une continuité supposée.
- Le **Controller** obtient les observations auprès du **Relay**, mais dirige les
  **Plans d'action** approuvés vers une autorité distincte adaptée à leur cible.
  L'**App** ne contacte pas le Relay et le Relay ne transporte jamais ces
  actions.
- Un **Plan de déploiement** est une forme de **Plan d'action**.
- Une **Bascule** avec données nomme son **Point de non-retour** et conserve
  l'ancien état pendant la **Fenêtre de retour** annoncée.
- Pour publier un service privé, le **Controller** prépare un plan que la
  **App** présente avant de faire configurer le **Passage privé** et le
  **Point d'entrée public** par l'autorité adaptée.
- Un **Point d'entrée public** appartient à une **Zone d'exposition**, mais cette
  zone ne devient une **DMZ** que si sa séparation réseau avec Internet et les
  zones privées est réellement appliquée et vérifiée.
- Un changement de placement ou de publication produit un nouveau **Plan
  d'action** ; il ne déclenche aucune mutation silencieuse.
- Une **Définition de service** ne crée rien par elle-même : seul un **Plan de
  déploiement** approuvé qui épingle une de ses **Révisions** par digest
  produit une instance sur une machine.
- Un **Profil de service** est fourni et borné par Your Cloud ; une
  **Définition de service** est rédigée par l'utilisateur dans des bornes que
  Your Cloud fixe. Les deux familles ne partagent jamais un nom.
- Un **Consentement** précède toute approbation d'un **Plan d'action** ; il est
  recueilli hors de la surface qui affiche le reste du produit, et il nomme la
  paire qu'il confirme.
- Un **Rapport d'exécution** vient de l'**Auxiliaire local** qui a agi. Le
  **Controller** le lit, le refuse s'il ne nomme pas cette machine, cette
  opération et cette séquence, et affiche « lancé, non rapporté » plutôt que de
  supposer un résultat.
- Une panne de l'**App**, du **Controller** ou du **Relay** ne doit pas
  arrêter un **Service** déjà déployé.

## Example dialogue

> **Utilisateur :** « Je publie ce service du LAN par mon VPS. Qu'est-ce que
> Your Cloud va modifier ? »
>
> **App :** « Voici le plan : créer le passage privé, limiter le trafic
> autorisé et ajouter la route HTTPS sur le VPS. Rien ne sera appliqué avant ton
> approbation. »

## Flagged ambiguities

- « Gérer une machine » signifie jusqu'à `v0.1.0` l'observer et y appliquer des
  déploiements approuvés. Cela ne signifie pas encore créer la VM ou installer
  son système d'exploitation.
- « Ne jamais diffuser l'IP du LAN » signifie ne pas la publier comme
  destination et ne créer aucune entrée directe. Le VPS voit nécessairement
  l'adresse source utilisée par la connexion sortante.
- L'appartenance éventuelle d'une machine à plusieurs infrastructures n'est pas
  encore décidée.
- « Afficher un élément manuel » ne signifie pas que Your Cloud peut deviner ou
  garantir toute sa configuration. Sans adaptateur de lecture et preuve
  actuelle, l'App affiche un état déclaré non vérifié.
- La découverte reste limitée aux machines déjà déclarées ou enrôlées. Your
  Cloud ne scanne pas le LAN et ne déduit aucune confiance de la présence d'un
  appareil sur le même réseau.
- « Agent unique » signifie une seule installation locale, pas une autorité ou
  une exécution unique : son Daemon permanent, son éventuel Relay et son
  Auxiliaire local restent des rôles séparés avec des droits différents.
- L'utilisateur n'a pas à mémoriser l'adresse d'un **Controller**, mais la
  **App** possède nécessairement une association approuvée pour le joindre.
  Cela ne donne aucune connaissance du Controller aux **Daemons**.
- Une **App** installée n'est ni un site hébergé par le Controller, ni une
  page servie sur `localhost`. Son interface peut employer des technologies Web
  embarquées sans ouvrir de serveur local ni dépendre d'une origine distante.
- Une App multi-Controller reste une cible. Sa distribution signée, ses
  identités d'appareil et ses sessions séparées doivent empêcher qu'un
  Controller fournisse du code ou obtienne silencieusement autorité sur les
  autres.
- Un futur accès par navigateur serait un mode distinct à contracter. Il ne
  remplace pas implicitement l'App installée et ne rend aucun Controller
  public.

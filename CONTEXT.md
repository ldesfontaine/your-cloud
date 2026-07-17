# Contexte

Ce fichier est uniquement le glossaire minimal de Your Cloud ; il ne contient
ni roadmap, ni choix de technologie, ni spécification détaillée.

## Language

**Utilisateur**:
Personne qui représente, observe ou fait évoluer son infrastructure depuis Your Cloud.

**Infrastructure**:
Groupe logique dans lequel l'utilisateur rassemble des machines et les services qui y sont placés.

**Machine**:
Hôte Linux physique ou virtuel déjà installé et accessible à Your Cloud jusqu'à la V1.

**Machine enrôlée**:
Machine dont l'identité a été explicitement approuvée pour rejoindre une infrastructure Your Cloud.

**Service**:
Application ou capacité que l'utilisateur veut exécuter sur une ou plusieurs machines.

**App**:
Interface utilisateur et service qui présente l'infrastructure, prépare les plans, recueille leur approbation et coordonne leur application.

<!-- coherence: AGENT-AUTHORITY:start -->
**Agent**:
Frontière de l'installation locale unique de Your Cloud sur une machine enrôlée, qui n'est pas elle-même un processus et ne regroupe que les rôles explicitement activés pour cette machine.

**Daemon**:
Processus permanent non privilégié fourni par l'Agent, chargé des échanges sortants et de l'observation sans appliquer lui-même de changement privilégié.

**Auxiliaire local**:
Autorité optionnelle et ponctuelle de l'Agent capable d'appliquer sur sa propre machine une opération nommée et approuvée, sans devenir un shell général.

**Relay**:
Rôle optionnel, activé explicitement sur une machine candidate, qui reçoit les observations des Daemons et les rend disponibles à l'App lorsqu'elle les consulte.
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

<!-- coherence: OWNERSHIP-MODES:start -->
**Mode géré**:
Mode dans lequel Your Cloud conserve l'état attendu d'un élément, prépare ses changements et peut les appliquer après approbation.

**Mode externe**:
Mode dans lequel l'utilisateur configure un élément en dehors de Your Cloud tandis que l'App peut le représenter et l'observer sans le modifier.

**État déclaré**:
Information fournie par l'utilisateur sans preuve actuelle obtenue par Your Cloud.

**État vérifié**:
Information confirmée par une observation en lecture seule, datée et adaptée au type d'élément.

**Élément détecté**:
Service, passage ou autre capacité observée en lecture seule sur une machine enrôlée mais pas encore déclarée ni placée sous gestion de Your Cloud.

**Adoption**:
Parcours explicite qui audite un élément détecté ou externe avant de permettre son passage en mode géré après approbation.
<!-- coherence: OWNERSHIP-MODES:end -->

## Relationships

- Une **Infrastructure** regroupe des **Machines** et leurs **Services**.
- Une **Machine** devient une **Machine enrôlée** seulement après approbation de
  son identité.
- Deux **Machines enrôlées** ne reçoivent aucune autorisation mutuelle générale :
  chaque communication reste limitée à un besoin déclaré.
- Un **Service** est placé sur au moins une **Machine**.
- Chaque **Machine** gérée par la V1 reçoit un **Agent** dont le **Daemon** ne
  fait encore qu'observer.
- Les **Daemons** transmettent leurs observations au **Relay**.
- Un **Agent** peut rester limité à l'observation. Activer un **Auxiliaire local**
  constitue un choix explicite de gestion pour la machine concernée.
- Un **Auxiliaire local** n'applique qu'un **Plan d'action** approuvé qui cible
  sa propre machine et une opération qu'il connaît.
- Un **Profil d'observation** donne au **Daemon** le droit de relever uniquement
  les informations nommées qu'il sait prendre en charge, jamais d'exécuter une
  commande arbitraire.
- Une **Lacune d'observation** reste visible et ne doit jamais être remplacée par
  une continuité supposée.
- L'**App** consulte le **Relay**, mais dirige les **Plans d'action** approuvés
  vers une autorité distincte adaptée à leur cible. Le **Relay** ne transporte
  jamais ces actions.
- Un **Plan de déploiement** est une forme de **Plan d'action**.
- Une **Bascule** avec données nomme son **Point de non-retour** et conserve
  l'ancien état pendant la **Fenêtre de retour** annoncée.
- Pour publier un service privé, l'**App** prépare et fait appliquer un plan qui
  configure le **Passage privé** et le **Point d'entrée public**.
- Un **Point d'entrée public** appartient à une **Zone d'exposition**, mais cette
  zone ne devient une **DMZ** que si sa séparation réseau avec Internet et les
  zones privées est réellement appliquée et vérifiée.
- En **Mode géré**, un changement de placement ou de publication produit un
  nouveau **Plan d'action** ; il ne déclenche aucune mutation silencieuse.
- En **Mode externe**, un **Service** ou un **Passage privé** reste sous
  l'autorité de l'utilisateur. L'App distingue toujours son **État déclaré** de
  son **État vérifié**.
- Un **Élément détecté** ne devient jamais géré par sa seule découverte. Une
  **Adoption** réussie est nécessaire pour transférer cette autorité.
- Une panne de l'**App** ou du **Relay** ne doit pas arrêter un **Service** déjà
  déployé.

## Example dialogue

> **Utilisateur :** « Je publie ce service du LAN par mon VPS. Qu'est-ce que
> Your Cloud va modifier ? »
>
> **App :** « Voici le plan : créer le passage privé, limiter le trafic autorisé
> et ajouter la route HTTPS sur le VPS. Rien ne sera appliqué avant ton
> approbation. »

## Flagged ambiguities

- « Gérer une machine » signifie jusqu'à la V1 l'observer et y appliquer des
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
  une exécution unique : son Daemon permanent, son éventuel Relay et son futur
  Auxiliaire local restent des rôles séparés avec des droits différents.
- Rendre l'App accessible depuis le Web ne signifie pas publier SSH, le Daemon
  ou l'Auxiliaire d'une machine. Seul le point d'entrée de l'App est concerné.

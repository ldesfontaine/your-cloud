# Roadmap V1

> Statut : `v0.0.1` et `v0.0.2` sont décidées, implémentées et prouvées dans le
> LAB. La preuve assistée de `v0.0.2` date du 18 juillet 2026 ; aucun palier
> suivant n'est ouvert par cette clôture.

Une [édition HTML autonome et visuelle](../../html/roadmap-v1.html) accompagne cette source
Markdown.

## Rôle de cette roadmap

Le [cap du projet](../../projet/CAP.md) décrit la destination à long terme et
l'[objectif V1](README.md) fixe la première ligne d'arrivée. Cette roadmap
ne remplace aucun des deux : elle ordonne seulement les preuves nécessaires
pour atteindre la V1.

Il n'existe volontairement pas de roadmap globale découpant aujourd'hui toutes
les versions futures. Les idées postérieures restent dans le cap et seront
cadrées lorsqu'elles deviendront le prochain objectif réel.

## Règle de progression

- Un palier doit être **décidé**, puis **implémenté**, puis **prouvé** dans le
  LAB avant d'ouvrir le suivant.
- Seul le prochain incrément reçoit un numéro, un périmètre de code et des
  critères détaillés. Les numéros suivants ne sont pas réservés à l'avance.
- Un palier peut être découpé en plusieurs micro-versions si sa première étude
  montre qu'une preuve serait trop large.
- Chaque incrément produit un résultat visible, un test nominal, un refus
  hostile et une limite explicitement annoncée.
- Chaque choix technique respecte la [politique de qualité](../../contribution/QUALITE.md) :
  menace, alternatives, moindre privilège, recommandations OWASP, mesures NIS2
  pertinentes, preuve attendue et risque résiduel restent visibles sans être
  transformés en déclaration de conformité.
- Une faiblesse temporaire n'est admise que dans un LAB isolé, clairement
  signalée et fermée avant d'exposer le composant ou de lui donner une autorité
  supplémentaire.
- Une nouvelle capacité ne peut pas entrer par simple modification de roadmap :
  si elle change la ligne d'arrivée, le contrat V1 doit être rediscuté et
  revalidé d'abord.

## État de départ

Le développement produit commence avec le prochain incrément décrit ci-dessous.
`tools/labctl` contrôle le LAB sans constituer une capacité de Your Cloud.

| Élément | Décidé | Implémenté | Prouvé |
|---|---:|---:|---:|
| Cap global | oui | sans objet | sans objet |
| Contrat V1 | oui | non | non |
| `v0.0.1` | oui | oui | oui — artefact unique, cohabitation isolée et refus Relay inclus |
| `v0.0.2` | oui | oui | oui — mTLS, profil borné, saturation, lacune et reprise |
| Paliers postérieurs de la V1 | proposés, à relire | non | non |

## Couverture des décisions validées

Cette table sert d'index de contrôle. Elle ne transforme pas les décisions
postérieures en backlog et ne leur attribue aucune version : elle empêche
simplement la roadmap V1 d'oublier la direction déjà validée.

| Sujet | Avant la fin de la V1 | Direction conservée après la V1 | Source détaillée |
|---|---|---|---|
| Produit | Représenter une infrastructure, observer deux machines et déployer deux services depuis une interface qui montre les opérations réelles | Étendre progressivement l'observation, les opérations et les plateformes sans retirer les parcours externes | [Cap](../../projet/CAP.md) |
| Machines | Partir de machines Linux déjà installées | Provisionner plus tard par des intégrations OpenStack et Terraform/OpenTofu explicites | [Cap](../../projet/CAP.md) |
| Agent | Un exécutable `your-cloud` identique par version sur chaque machine ; Daemon actif après enrôlement, autres rôles refusés sans activation explicite | Conserver un cycle de vie unique avec des capacités optionnelles explicitement activées et des processus isolés | [Glossaire](../../../CONTEXT.md) et [cap](../../projet/CAP.md) |
| Daemon | Processus permanent Go, non-root, sans port entrant ; collecteurs nommés, tampon borné et communications sortantes | Peut transporter plus tard un plan par un canal sortant séparé, mais reste non fiable pour l'autorité et n'applique jamais lui-même un changement privilégié | [Cap](../../projet/CAP.md) |
| Relay | Mode du même exécutable, activé seulement sur le VPS candidat ; processus, compte, identité, secrets et stockage séparés du Daemon ; aucun ordre retour | Rester limité à l'observation et explicitement provisionné : ni canal d'action, ni proxy Web, ni moteur de découverte ou de confiance réseau | [Objectif V1](README.md) et [cap](../../projet/CAP.md) |
| Auxiliaire local | Absent du contrat et de l'exécutable V1 | Futur mode ponctuel du même artefact, sans réseau, invoqué pour un plan exact mais validé indépendamment avant privilège ; aucun shell général | [Cap](../../projet/CAP.md) |
| Chemin d'action | App → plan lisible → approbation liée au contenu → Ansible → SSH borné → vérification | Garder le même plan approuvé mais choisir l'autorité adaptée : Auxiliaire pour Linux local, API OpenStack, runner IaC isolé ou API K3s | [Cap](../../projet/CAP.md) et [objectif V1](README.md) |
| App | Backend et Ansible dans une VM de contrôle privée ; navigateur du laptop par tunnel SSH local sur `127.0.0.1`, sans Podman requis sur le laptop | Fournir un point d'entrée HTTPS authentifié utilisable sans VPN manuel et sans dépendre du laptop ; une App locale conteneurisée restera au plus un mode optionnel | [Objectif V1](README.md) et [cap](../../projet/CAP.md) |
| Chiffrement et identités | mTLS pour Daemon–Relay, HTTPS authentifié pour App–Relay, SSH pour l'administration, HTTPS pour le Web et WireGuard pour le passage privé ; chaque identité et chaque flux restent bornés | Conserver la séparation des rôles : le chiffrement ne crée jamais une autorisation générale entre machines enrôlées | [Objectif V1](README.md) |
| Exposition des services | Traefik sur le VPS, file provider sans socket de moteur, deux noms sur la même IP et `443` ; BentoPDF local au VPS et Vaultwarden atteint uniquement par WireGuard | Représenter plus tard une vraie DMZ seulement si des frontières réseau indépendantes sont appliquées et vérifiées | [Objectif V1](README.md) et [cap](../../projet/CAP.md) |
| Exécution OCI | Podman rootless et Quadlet uniquement sur un hôte systemd avec cgroup v2 ; prérequis contrôlés avant mutation, images, versions et digests épinglés | Un hôte incompatible est refusé pour le déploiement géré ou reste externe ; aucun adaptateur d'init alternatif n'est planifié | [Objectif V1](README.md) |
| Responsabilité | Mode géré pour ce que Your Cloud applique ; mode externe pour les services ou passages installés manuellement, avec état déclaré distinct de l'état vérifié | Découverte future uniquement en lecture seule sur les machines enrôlées, jamais par scan du LAN ; toute adoption reste auditée et approuvée | [Cap](../../projet/CAP.md) et [objectif V1](README.md) |
| Sécurité et preuves | Justification OWASP et NIS2 proportionnée, refus hostiles, secrets synthétiques, artefacts épinglés, rapport visuel et aucune revendication de conformité | Conserver le moindre privilège, les mises à jour séparées, la révocation, les SBOM, la provenance et les risques résiduels visibles | [Qualité](../../contribution/QUALITE.md) et [cap](../../projet/CAP.md) |
| Premier jalon post-V1 | Hors V1 | `v1.0.1` : petit parcours SSO OpenID Connect pour Vaultwarden ; fournisseur, placement et récupération seront cadrés seulement après la preuve V1 | [Cap](../../projet/CAP.md) |

## Incrément prouvé : `v0.0.1`

Le comportement mesurable de ce palier est figé dans son
[contrat exécutable](CONTRAT-V0.0.1.md).

### Résultat

Le même exécutable Go `your-cloud` est installé sur les deux machines cibles du
LAB. Sur le VPS simulé, deux unités lancent en parallèle les modes `daemon` et
`relay` sous des comptes distincts. Sur la machine du LAN, seul le mode `daemon`
est activé et le mode `relay` refuse de démarrer sans manifeste candidat local.
Le Relay conserve le dernier signal reçu et permet de distinguer une machine
vue récemment d'une machine devenue ancienne. Aucun Auxiliaire local n'est
installé ou simulé.

Le message contient uniquement :

- l'identifiant synthétique de la machine ;
- la version du Daemon ;
- l'heure du signal de présence.

### Preuve de sortie

- le placement des trois processus est visible dans le rapport LAB ;
- l'empreinte du même exécutable est identique sur les deux machines ;
- le VPS exécute simultanément Daemon et Relay depuis ce fichier, mais sous deux
  comptes, configurations et politiques systemd séparés ;
- la machine non candidate refuse un lancement direct du Relay avant toute
  écoute réseau ;
- le Relay reçoit un signal des deux machines ;
- l'arrêt d'un Daemon rend uniquement sa machine ancienne après la durée
  annoncée ;
- un identifiant absent ou mal formé et un message dépassant le schéma sont
  refusés sans faire tomber le Relay ;
- redémarrer le Relay et les Daemons produit l'état annoncé, sans processus
  orphelin ;
- l'installation, le démarrage, l'arrêt et le retrait des composants produisent
  l'état annoncé sans reste actif ;
- le code, les tests et le rapport expliquent l'origine, la destination et la
  limite de chaque donnée.

### Limites assumées

`v0.0.1` ne revendique ni interface graphique, ni métrique système, ni mTLS, ni
déploiement, ni WireGuard. Son transport non sécurisé reste strictement confiné
au LAB. Aucune installation ou exécution du produit n'a lieu sur le laptop.

## Paliers nécessaires après `v0.0.1`

<!-- coherence: SERVICE-LIFECYCLE:start -->
Les paliers ci-dessous fixent un ordre de dépendance, pas encore des numéros de
version ni un dessin détaillé de leur code. Cet ordre construit progressivement
les capacités de Your Cloud ; il ne décrit pas l'ordre d'une opération sur une
infrastructure réelle. Une opération suit le
[cycle de vie sûr validé](../../architecture/CYCLE-DE-VIE-DES-SERVICES.md) :
préparer un réseau fermé, déployer sans exposition, vérifier, autoriser le flux
exact, publier ou basculer, observer, puis retirer l'ancien état.
<!-- coherence: SERVICE-LIFECYCLE:end -->

<!-- coherence: V1-OBSERVATION:start -->
### Incrément prouvé : `v0.0.2` — observation authentifiée et bornée

Le comportement mesurable, les paramètres décidés et les exclusions de ce
palier sont figés dans son
[contrat exécutable](CONTRAT-V0.0.2.md) et exécuté dans son
[rapport LAB](../../lab/v0.0.2-observation.md).

**Résultat :** enrôler explicitement les deux machines, donner une identité
distincte à chaque Daemon, protéger le transport Daemon–Relay par mTLS, puis
introduire le premier profil d'observation utile composé de collecteurs nommés.
Le plan du profil montre les champs, lectures locales, privilèges, fréquence et
coûts. Les observations en attente restent dans un tampon local borné. Chaque
Daemon reçoit un endpoint Relay approuvé comprenant route, port et identité ;
cet endpoint peut être privé. L'élection ou le remplacement automatique d'un
Relay reste hors de ce palier tant que candidature, détection de panne,
autorité active unique, redistribution et reprise d'état ne sont pas définies.

**Preuve de sortie :** un Daemon inconnu, révoqué ou utilisant la mauvaise
identité est refusé ; une panne du Relay ne remplit pas le disque ; le retour du
Relay reprend la livraison sans inventer de continuité ; le Daemon n'accepte
aucune connexion réseau entrante et le Relay ne peut transmettre aucun ordre.
Une commande locale en lecture seule affiche le dernier état et la santé du
tampon sans ouvrir d'API réseau. Commande shell, chemin libre, collecteur inconnu,
plugin téléchargé et scan du LAN sont refusés. Ce palier mesure dans le LAB la
taille et la fréquence réelles, fixe les limites d'âge et de taille, puis prouve
qu'une saturation conserve l'état courant et crée une lacune visible.

**Dépendance validée :** ce palier précède l'App. L'interface ne commence pas
par afficher un transport provisoire : l'identité de la source, l'âge de la
donnée et les lacunes éventuelles sont déjà définis et vérifiables.
<!-- coherence: V1-OBSERVATION:end -->

<!-- coherence: V1-APP-ACCESS:start -->
### 2. App de lecture dans la VM de contrôle

**Résultat :** créer une infrastructure, y rattacher les deux machines et voir
leur présence récente, ancienne ou absente depuis une véritable interface Web.
L'App et son backend vivent dans la VM de contrôle ; le navigateur du laptop les
rejoint par un tunnel SSH local lié à `127.0.0.1`. L'App consulte le Relay par
HTTPS avec une identité de service propre et un endpoint explicitement approuvé.

**Précondition validée :** le chemin Daemon–Relay authentifié, le tampon borné
et la représentation des données anciennes ou lacunaires ont franchi leur
preuve de sortie.

**Preuve de sortie :** aucun port de l'App n'est public, aucun autre appareil du
LAN ne peut utiliser le transfert local, Podman n'est pas requis sur le laptop
et une donnée non reçue n'est jamais présentée comme actuelle. Un certificat,
une identité, un hôte ou un port Relay non approuvé est refusé ; le navigateur
n'accède ni directement au Relay, ni aux identités d'administration.

Ce tunnel est le chemin privé de la V1, pas la cible finale : l'App devra ensuite
recevoir un point d'entrée HTTPS authentifié utilisable sans VPN manuel et sans
dépendre de la disponibilité du laptop.
<!-- coherence: V1-APP-ACCESS:end -->

### 3. Premier plan appliqué de manière contrôlée

**Résultat :** l'App construit un plan lisible, lie l'approbation à son contenu
exact, puis son backend utilise Ansible et une identité SSH bornée pour déployer
sur le VPS du LAB une **sonde OCI de validation** avec Podman rootless et
Quadlet. Cette sonde est un petit service HTTP jetable, sans donnée persistante,
accessible uniquement localement sur la machine. Son image est choisie à ce
palier, puis épinglée par version et digest ; elle ne devient pas un composant
de Your Cloud.

**Preuve de sortie :** aucun playbook, inventaire, argument, chemin ou commande
libre ne vient du navigateur ; une cible inconnue, un digest flottant, un volume,
un port ou un privilège non approuvé est refusé ; une cible sans systemd ou sans
cgroup v2 est refusée avant mutation, sans solution de repli automatique ; le
second passage Ansible reste à `changed=0` ; une requête locale obtient la
réponse attendue ; redémarrage et retrait produisent l'état annoncé sans port
public ni donnée restante.

**Dépendance validée :** ce mécanisme générique est prouvé avant BentoPDF. Le
palier suivant réutilise donc un chemin de plan, d'approbation et d'exécution
déjà compris au lieu de déboguer simultanément l'action, le proxy, TLS et le
premier véritable service.

<!-- coherence: V1-NETWORK:start -->
### 4. Premier véritable service public

**Résultat :** déployer BentoPDF sur le VPS, installer Traefik sans socket de
moteur, générer sa route avec le file provider et terminer HTTPS sur un nom
explicitement déclaré.

**Preuve de sortie :** seul `443` est nécessaire publiquement, avec `80`
éventuellement limité à la redirection ; le port interne de BentoPDF reste
privé ; une requête directe par l'IP ou un nom inconnu n'obtient aucune route
applicative ; l'image, la configuration et les dépendances sont épinglées et
vérifiées.

### 5. Passage privé limité au service

**Résultat :** Your Cloud prépare, fait approuver puis applique le passage
WireGuard entre les deux machines enrôlées, avec adresses `/32`, routes et règles
`nftables` limitées au service prévu.

**Preuve de sortie :** la machine du LAN n'a aucun port Internet entrant ; le
VPS ne peut joindre ni SSH, ni les autres ports, ni le sous-réseau du LAN ; une
modification de pair, destination ou port produit un nouveau plan au lieu d'une
mutation silencieuse.

### 6. Véritable service privé publié par le VPS

**Résultat :** déployer Vaultwarden avec Podman rootless et stockage persistant
sur la machine du LAN, puis ajouter dans Traefik une seconde route HTTPS qui le
rejoint uniquement par WireGuard.

**Preuve de sortie :** `pdf.<domaine>` et `vault.<domaine>` utilisent la même IP
publique et `443` sans exposer leurs ports internes ; Vaultwarden survit aux
redémarrages et à une recréation contrôlée ; sauvegarde et restauration avec des
secrets synthétiques sont prouvées ; le service ne peut joindre aucun voisin
synthétique du LAN sans flux approuvé.

Le VPS ainsi durci reste une zone d'exposition, pas une DMZ revendiquée. Une
future DMZ exigera un segment dédié et des frontières filtrantes indépendantes
vers Internet, les zones privées et le plan d'administration.
<!-- coherence: V1-NETWORK:end -->

<!-- coherence: OWNERSHIP-MODES:start -->
### 7. Responsabilité externe visible

**Résultat :** déclarer dans l'App un service ou un passage installé à la main,
sans transférer son autorité à Your Cloud, et distinguer l'état déclaré de ce
qu'un adaptateur en lecture seule sait réellement vérifier.

**Preuve de sortie :** un élément inconnu n'est ni découvert par scan, ni adopté
silencieusement, ni présenté comme géré ; l'App annonce clairement ce qu'elle ne
peut ni mettre à jour, ni restaurer, ni supprimer.
<!-- coherence: OWNERSHIP-MODES:end -->

### 8. Preuve complète de la V1

**Résultat :** rejouer depuis une base LAB propre le scénario complet de
l'[objectif V1](README.md), puis produire les artefacts et preuves de
release.

**Preuve de sortie :** deux machines observées, deux véritables services
accessibles en HTTPS, App privée utilisable depuis le navigateur, plans
approuvés, second passage sans changement, redémarrages, sauvegarde/restauration,
retrait propre, refus hostiles réseau et autorisation, secrets expurgés, versions
épinglées, SBOM, provenance et rapport visuel. Toute capacité non prouvée reste
annoncée comme telle et bloque la V1.

<!-- coherence: AGENT-AUTHORITY:start -->
## Décisions conservées après la V1, sans les planifier

La roadmap s'arrête à la preuve complète précédente. Elle conserve toutefois
les frontières déjà validées afin qu'une future roadmap ne reparte pas d'une
architecture contradictoire :

- l'Agent reste une installation unique ; son Daemon permanent non-root et son
  éventuel Auxiliaire local conservent des autorités différentes ; le Relay
  optionnel utilise le même artefact mais un processus et une identité séparés ;
- l'Auxiliaire n'est ni un second Daemon permanent ni un service réseau. Il est
  optionnel, lancé pour une opération connue, puis s'arrête ;
- le futur transport sortant des plans reste séparé du Relay d'observation. Le
  Daemon est traité comme un transport non fiable et l'Auxiliaire revérifie
  indépendamment origine, cible, empreinte, approbation, expiration, anti-rejeu
  et limites sémantiques locales ;
- une action OpenStack, Terraform/OpenTofu, Ansible ou K3s utilise l'API ou le
  runner adapté au lieu de détourner artificiellement l'Agent d'une machine ;
- l'App finale possède un accès HTTPS authentifié sans rendre SSH ou les Agents
  publics et sans dépendre de la disponibilité du laptop ;
- la découverte assistée reste locale aux machines enrôlées, en lecture seule,
  et ne transforme jamais un appareil voisin en élément de confiance ;
- une vraie DMZ n'est revendiquée qu'après preuve de frontières filtrantes
  indépendantes ; le VPS de la V1 reste seulement une zone d'exposition durcie.

Cette section ne planifie ni OpenStack, ni Terraform/OpenTofu, ni K3s, ni
l'Auxiliaire, ni la découverte assistée, ni la haute disponibilité. Elle fixe
leurs frontières avant leur futur cadrage.
<!-- coherence: AGENT-AUTHORITY:end -->

Le seul jalon déjà noté après cette limite est la demande d'une `v1.0.1` pour un
petit parcours SSO OpenID Connect de Vaultwarden. Son fournisseur, son placement
et sa récupération seront cadrés après la preuve V1 ; ils ne font pas partie de
la présente roadmap.

## Points volontairement non décidés

- Les numéros et le découpage exacts des paliers postérieurs à `v0.0.2`.
- L'enveloppe de distribution autour de l'exécutable unique — paquet Debian,
  archive signée ou autre format — sans rouvrir la séparation des processus.
- Le port local et le nom de la commande qui ouvrira l'App dans le LAB.
- Le placement final, l'identité utilisateur et le mécanisme d'authentification
  de l'App publiquement hébergée après la V1.
- Le fournisseur, le placement et la récupération du SSO `v1.0.1`.

## Point d'arrêt

`v0.0.1` et `v0.0.2` restent fermées par leurs contrats et rapports LAB. La
prochaine décision est le cadrage du palier App ; aucune App, action distante,
Ansible métier, Auxiliaire, WireGuard, OCI, Proxmox, OpenStack, worker
d'automatisation, projet IaC ou autre capacité post-V1 n'a été ouverte ici.

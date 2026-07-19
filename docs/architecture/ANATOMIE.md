# Anatomie du projet

> Statut : représentation vivante de l'architecture en construction.

Une [édition HTML autonome et visuelle](../html/anatomie.html) accompagne
cette source Markdown. Elle évolue à chaque incrément qui modifie un composant,
un placement, une autorité ou un flux réseau.

La [chaîne d'observation détaillée](CHAINE-D-OBSERVATION.md) cartographie les
rôles Daemon, Relay et Diagnose, leurs appels, états, données, protections et
limites dans `v0.0.2`.

## Comment lire ce document

Trois états ne doivent jamais être confondus :

- **décidé** : le comportement appartient au contrat, mais aucun code ne le
  prouve encore ;
- **implémenté** : le code existe ;
- **prouvé** : le scénario annoncé a réellement réussi dans le LAB avec ses
  refus hostiles.

À ce jour, `v0.0.1` et la chaîne d'observation authentifiée et bornée de
`v0.0.2` sont implémentées et prouvées dans le LAB. L'App, le chemin d'action et
les services du reste de la V1 restent décidés mais pas implémentés.

## Distribution réellement prouvée pour `v0.0.2`

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

<!-- coherence: V1-NETWORK:start -->
## Placement V1

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
       | Console navigateur -- tunnel SSH --> Controller  |
       | Controller -- lecture authentifiée --> Relay     |
       | Controller -> plan -> approbation -> Ansible     |
       +--------------------------------------------------+
```

<!-- coherence: V1-APP-ACCESS:start -->
La Console, le Controller et le Relay restent hors du chemin emprunté par le
trafic Web vers les services : leur panne ne doit pas arrêter BentoPDF ou
Vaultwarden. Le Controller porte l'autorité d'une seule infrastructure. La V1
prouve une Console, un Controller et une infrastructure ; l'association future
à plusieurs Controllers devra encore isoler distribution, origine Web et
sessions.

La décision V1 est que la Console rendue dans le navigateur du laptop rejoint le
Controller de la VM de contrôle au travers d'un transfert SSH lié à
`127.0.0.1`. Cela ne lance aucun serveur Your Cloud sur le laptop, ne nécessite
pas Podman sur celui-ci et ne publie pas le port du Controller sur Internet. Le
Controller initie lui-même sa lecture privée authentifiée du Relay ; la Console
ne contacte jamais le Relay et les Daemons ne connaissent aucun Controller.

À long terme, le Controller et l'interface Web qu'il sert restent privés derrière
WireGuard. Chaque appareil administrateur possède un pair distinct et révocable,
avec un routage limité aux adresses d'administration et un refus serveur par
défaut. La possession de la clé du pair ne prouve ni l'intégrité de l'appareil ni
l'identité de l'humain. Une authentification humaine forte reste obligatoire
après l'accès réseau ; SSO/OIDC, l'appui sur un fournisseur central d'identité,
est facultatif.
Une passerelle Web publique pourra être étudiée comme option sans autorité
d'administration ni secret de machine. Ses pouvoirs résiduels de routage, de
disponibilité, de terminaison TLS ou de transmission d'identité devront rester
bornés. Les services publiés conservent leur propre accès HTTPS sans WireGuard.
<!-- coherence: V1-APP-ACCESS:end -->

Les deux services suivent un autre chemin. Leurs noms DNS pointent vers la même
IP du VPS et Traefik reçoit les deux sur `443`, puis route le nom BentoPDF vers
le service local et le nom Vaultwarden vers le passage WireGuard. Aucun port de
backend n'est exposé directement.
<!-- coherence: V1-NETWORK:end -->

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

Pour Vaultwarden, WireGuard peut donc être établi avec des routes `/32` tandis
que le port applicatif reste refusé. Le service est d'abord vérifié localement,
puis le seul flux VPS-destination est autorisé et testé. Traefik ne reçoit sa
route publique qu'en dernier.

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

En V1, une action demandée dans l'interface suit ce chemin :

```text
Utilisateur -> Console -> Controller -> plan lisible -> approbation
                                                       |
                                                       v
Controller -> Ansible -> SSH distinct -> machine
machine -> contrôles directs -> Controller -> Console
Daemon de la machine -> observations -> Relay -> Controller -> Console
```

Le Daemon ne reçoit aucun ordre et ne connaît aucun Controller. Le Relay accuse
et conserve le dernier état d'observation validé sans porter l'inventaire métier
ni calculer le statut affiché. Le Controller rapproche les machines attendues,
les heures de réception, les séquences et les lacunes afin que la Console montre
l'état obtenu après qu'un autre chemin a appliqué le plan.

À terme, une machine gérée pourra recevoir les plans sans ouvrir de port
d'administration sur le LAN, au moyen de son Agent unique :

```text
Controller / autorité du plan
        |
        | plan exact, approuvé, ciblé et expirant
        v
chemin d'action distinct, transport et lancement encore à cadrer
        |
        v
Agent sur la machine
|- même artefact signé
|- Daemon non-root : observation uniquement
`- Auxiliaire local : processus ponctuel, revérifie, applique, puis s'arrête
```

L'Auxiliaire n'a aucun réseau, aucun shell général et aucune élévation dormante.
Il refuse une opération ou un paramètre hors de sa liste positive locale. Une
machine d'observation ne l'active pas. Le Daemon et le Relay restent consacrés
aux observations ; le chemin d'action sera contracté séparément et le chemin
Ansible ou externe reste disponible.

Les autres cibles utilisent leur propre autorité plutôt que ce chemin local :

```text
Plan approuvé
|- système Linux ou service local -> Agent -> Auxiliaire local
|- ressource OpenStack ------------> adaptateur API OpenStack
|- Terraform / OpenTofu / Ansible -> runner isolé
`- cluster K3s --------------------> adaptateur API K3s
```

Cette cible n'appartient pas au contrat V1. La roadmap garde
`Console -> Controller -> plan -> approbation -> Ansible -> SSH` et un Daemon
d'observation seulement. La modifier exige une nouvelle validation du contrat ;
elle ne peut pas dériver silencieusement au cours d'un incrément.

Le Relay peut provenir du même exécutable que le Daemon sans appartenir au même
processus. Son compte, son identité réseau, ses secrets, son stockage et son
budget restent séparés. Une machine non candidate ne reçoit aucun manifeste
Relay exploitable et refuse ce mode avant l'ouverture d'un port.
<!-- coherence: AGENT-AUTHORITY:end -->

<!-- coherence: V1-OBSERVATION:start -->
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
<!-- coherence: V1-OBSERVATION:end -->

<!-- coherence: OWNERSHIP-MODES:start -->
## Gestion explicite, jamais découverte du LAN

```text
élément déclaré par l'utilisateur
|- mode externe -> état déclaré -> vérification en lecture seule éventuelle
`- mode géré ----> plan -> approbation -> application -> vérification

future observation locale sur une machine enrôlée
`- élément détecté -> ignorer | garder externe | demander une adoption
```

Un élément externe reste sous l'autorité de l'utilisateur. Une observation peut
faire passer son état de déclaré à vérifié, mais ne donne à Your Cloud aucun
droit de modification. Une future adoption exige un audit et un nouveau plan
approuvé ; elle n'est jamais déclenchée par la seule découverte.

La découverte future reste limitée à des adaptateurs en lecture seule sur les
machines déjà enrôlées. Ni le Daemon, ni le Relay, ni l'App ne scannent le LAN,
et la présence d'un appareil sur le même réseau ne lui donne aucune confiance.
<!-- coherence: OWNERSHIP-MODES:end -->

## Pourquoi Traefik utilise le file provider

Traefik sait découvrir automatiquement les conteneurs avec son provider Docker.
Pour cela, il doit interroger l'API Docker, souvent au moyen du socket
`/var/run/docker.sock`. Cette API possède une autorité importante sur le moteur
et peut devenir un chemin vers l'hôte si le proxy exposé est compromis.

La V1 utilise donc le **file provider** :

1. l'utilisateur demande une publication dans l'App ;
2. Your Cloud calcule une route précise ;
3. le plan montre le nom public, la destination et le port ;
4. après approbation, Ansible écrit la configuration dynamique Traefik ;
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

Podman rootless avec Quadlet est retenu pour la V1. Le flux sera :

```text
Plan Your Cloud -> Ansible -> fichier Quadlet -> systemd -> Podman -> conteneur
```

Ce flux n'existe que sur une machine hôte équipée de systemd et de cgroup v2.
Your Cloud vérifie ces capacités avant toute mutation. Si elles manquent, le
déploiement OCI géré est refusé clairement ; Quadlet ne crée ni unité OpenRC,
ni script runit, ni solution de repli implicite. Un service que l'utilisateur
gère autrement peut rester en mode externe. Cette limite ne décide pas encore
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

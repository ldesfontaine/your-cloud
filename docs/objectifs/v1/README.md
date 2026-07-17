# Objectif V1

> Statut : contrat fonctionnel validé pour le découpage de la roadmap. Les
> paramètres d'implémentation encore inconnus seront mesurés au palier concerné
> sans modifier silencieusement cette ligne d'arrivée.

Une [édition HTML autonome](../../html/objectif-v1.html) accompagne cette source
Markdown.

## Résultat attendu

Depuis l'App, un utilisateur crée une infrastructure composée de deux machines
Linux déjà installées :

- un VPS disposant d'une adresse publique ;
- une machine située dans un LAN privé, sans adresse publique et sans port
  entrant ouvert sur Internet.

Your Cloud observe les deux machines, y déploie proprement deux véritables
services et les rend accessibles en HTTPS par le VPS. Un service tourne sur le
VPS ; l'autre tourne dans le LAN derrière un passage chiffré sortant.

Your Cloud ne suppose pas ce passage et le proxy déjà préparés. L'App présente
le plan, puis configure elle-même le passage privé, les restrictions réseau, le
point d'entrée HTTPS et la route vers le service après approbation.

Atteindre ce scénario de manière reproductible, compréhensible et vérifiée
constitue la ligne d'arrivée fonctionnelle de la V1.

## Placement visé

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

L'App s'exécute dans l'environnement d'administration. Dans le LAB, elle tourne
dans une VM de contrôle séparée : les « deux machines » du scénario désignent
les deux machines gérées, pas toutes les VM nécessaires à la preuve.

## Comment l'utilisateur atteint chaque interface

### BentoPDF et Vaultwarden

Les deux services sont publics par **la même adresse IP du VPS et le même port
HTTPS `443`**, mais l'utilisateur les ouvre avec deux noms différents :

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

<!-- coherence: V1-APP-ACCESS:start -->
### App Your Cloud

L'**App** désigne à la fois l'interface Web visible dans le navigateur et son
service backend, qui prépare les plans et coordonne Ansible. Elle ne tourne pas
dans le navigateur ni sur le laptop.

Pour la V1 dans le LAB, la décision retenue est :

```text
Navigateur du laptop
        |
        v
127.0.0.1:<port local>
        |
        | tunnel SSH local, clé et hôte vérifiés
        v
VM de contrôle:127.0.0.1:<port App> -> App
```

Le port local est lié uniquement à `127.0.0.1` : aucun autre appareil du LAN ne
peut l'utiliser. Le laptop exécute seulement le navigateur et le client SSH ;
l'App, son backend, Ansible et le projet restent dans la VM du LAB.

Podman n'est donc pas un prérequis du laptop utilisateur en V1. Une App locale
conteneurisée pourra être étudiée plus tard comme mode d'hébergement optionnel,
mais elle ne deviendra ni le chemin par défaut ni le seul moyen d'accéder au
produit : rootless limite les privilèges sans supprimer les risques liés aux
montages, au réseau, au noyau partagé ou aux identités d'administration.

`labctl` sait actuellement ouvrir une session SSH, mais ne possède pas encore de
commande dédiée à ce tunnel. Lorsque l'incrément de l'interface arrivera, une
commande bornée pourra ouvrir et fermer uniquement ce transfert. Les numéros de
ports exacts seront choisis à cet incrément.

Ce tunnel est un moyen d'accès privé à la V1, pas l'architecture finale. À terme,
l'App possédera son propre nom HTTPS et une authentification adaptée afin d'être
utilisable depuis un navigateur ou un téléphone sans dépendre du laptop.

Publier l'App dès la V1 ajouterait l'identité utilisateur, les autorisations par
infrastructure et par action, les sessions, la protection CSRF, la limitation
des tentatives, la réauthentification des opérations critiques et l'isolation
des clés SSH et du runner Ansible au périmètre déjà large des deux services.
La garder sur le plan d'administration réduit cette première preuve, sans
revendiquer encore l'accès Web final sans tunnel.
<!-- coherence: V1-APP-ACCESS:end -->

## Trois chemins différents

| Chemin | Rôle |
|---|---|
| Daemon vers Relay | Transporter l'état et les métriques des machines |
| App vers machines | Préparer puis exécuter les changements approuvés |
| Internet vers VPS vers service | Publier les applications destinées au Web |

Le Relay ne devient pas le proxy Web. Le Daemon ne devient pas un accès
d'administration. Une panne de l'observation ne doit pas arrêter les services.

### Comment l'interface agit réellement en V1

Quand l'utilisateur demande un déploiement ou une modification prise en charge :

1. l'App consulte l'état connu sans le confondre avec une preuve actuelle ;
2. elle construit un plan borné pour les machines et services explicitement
   choisis ;
3. elle affiche les changements, privilèges, flux, effets d'un échec et limites ;
4. l'utilisateur approuve ce plan ;
5. l'environnement d'administration l'applique avec Ansible par le chemin SSH
   distinct ;
6. l'App vérifie le résultat par des contrôles directs puis par les nouvelles
   observations reçues du Daemon.

Le Daemon ne reçoit donc jamais le clic de l'utilisateur et n'exécute aucune
commande. La V1 automatise les seules opérations prévues par son contrat ; elle
ne promet pas encore une console d'administration générale.

Le navigateur communique uniquement avec l'App. Dans le LAB V1, son backend vit
dans l'environnement d'administration et possède un chemin réseau explicitement
autorisé vers SSH, sans exposition publique du port de la machine du LAN. La V1
ne prétend pas encore qu'une App hébergée n'importe où peut traverser seule
n'importe quel NAT.

<!-- coherence: AGENT-AUTHORITY:start -->
### Compatibilité avec la cible finale

La V1 et la cible à long terme conservent le même contrat utilisateur :
demander une action, comprendre le plan, approuver son contenu exact, appliquer
par une autorité adaptée puis vérifier le résultat. Seul le chemin d'application
évoluera.

La V1 distribue un seul exécutable `your-cloud` sur les deux machines. Sur la
machine du LAN, systemd lance uniquement `your-cloud daemon`. Sur le VPS,
systemd lance en parallèle `your-cloud daemon` et `your-cloud relay` depuis ce
même fichier, mais sous des comptes, configurations, identités, secrets et
budgets distincts. Le rôle Relay est désactivé par défaut et refuse de démarrer
sans provisionnement local explicite de la machine candidate. Une seule version
à maintenir ne signifie donc ni un seul processus, ni une autorité commune.

Dans la V1, cette autorité est Ansible par SSH. Après la V1, une machine placée
en mode géré pourra recevoir une capacité optionnelle d'action dans son Agent :
le Daemon non privilégié récupérera un plan par une communication sortante
séparée du Relay, puis un Auxiliaire local sans réseau pourra appliquer une
opération nommée. OpenStack, Terraform, OpenTofu et K3s utiliseront plutôt leurs
API ou un runner isolé lorsque cette autorité est plus adaptée. Cette cible est
détaillée dans le [cap du projet](../../projet/CAP.md).

Le contrat V1 n'ajoute aucun canal d'action au Daemon et aucun Auxiliaire local.
La roadmap conserve Ansible et SSH comme unique chemin d'application géré. Une
réouverture de ce périmètre exigerait une modification explicite et une nouvelle
validation du contrat V1. Les contraintes imposées dès maintenant sont :

- le plan compris et approuvé reste distinct de son rendu Ansible ;
- l'approbation identifie le contenu exact qui sera appliqué ;
- tout artefact ou paramètre généré qui ne correspond plus à l'empreinte
  approuvée arrête l'application avant la première mutation ;
- le backend ne reçoit depuis l'interface ni playbook, inventaire, commande,
  argument libre ou chemin arbitraire : il sélectionne un parcours connu et des
  entrées typées, puis borne la cible à une machine enrôlée ;
- l'identité SSH, la clé d'hôte et les droits `sudo` sont propres au chemin
  prévu et minimaux pour l'opération ;
- le Daemon et le Relay restent consacrés à l'observation ;
- la cohabitation sur le VPS ne leur donne aucun fichier d'identité, secret,
  stockage ou compte commun ;
- l'échec de l'App, du chemin SSH ou d'une future action ne doit pas arrêter un
  service déjà déployé ;
- les résultats directs et les observations ultérieures restent deux preuves
  distinctes, visibles dans l'App.
<!-- coherence: AGENT-AUTHORITY:end -->

<!-- coherence: V1-NETWORK:start -->
## Identités et chiffrement

Seules les machines explicitement enrôlées peuvent devenir des pairs du passage
privé. L'enrôlement prouve une identité ; il n'autorise pas une machine à parler
librement à toutes les autres. La V1 n'est donc pas un réseau maillé de confiance
mais un ensemble de flux minimaux approuvés.

Chaque donnée Your Cloud qui traverse le réseau privé entre deux machines
enrôlées est chiffrée et authentifiée avant de quitter sa machine, avec le
mécanisme adapté au chemin :

| Flux | Protection retenue pour la V1 |
|---|---|
| Paquets privés entre machines enrôlées | WireGuard, pairs nommés et routes bornées |
| Daemon vers Relay | mTLS avec une identité propre à chaque Daemon, y compris au-dessus de WireGuard lorsque le Relay est distant |
| App vers Relay | HTTPS avec authentification forte de l'App |
| App vers machine pour un plan approuvé | SSH avec identité d'administration distincte et clé d'hôte vérifiée |
| Navigateur vers service publié | HTTPS jusqu'au point d'entrée public |
| VPS vers service du LAN | WireGuard et autorisation limitée à la destination et au port du service |

WireGuard et mTLS ne sont pas deux synonymes. WireGuard chiffre et authentifie
les paquets entre machines ; mTLS identifie les composants Your Cloud qui
échangent des données applicatives. SSH protège le chemin d'administration et
HTTPS protège les accès Web. Ajouter mTLS indistinctement à tous les services
tiers n'apporterait pas automatiquement une meilleure sécurité ; une couche
supplémentaire doit protéger une identité ou une menace réellement définie.

La règle « seules les machines enrôlées communiquent » concerne le réseau privé
de Your Cloud. Elle n'interdit pas les flux explicitement attendus vers un
navigateur, l'App, le DNS, l'heure ou un registre d'artefacts. Ces exceptions
restent déclarées, limitées et vérifiables. Le chiffrement protège le contenu,
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

<!-- coherence: OWNERSHIP-MODES:start -->
## Deux modes de responsabilité

La V1 distingue explicitement qui possède le droit de modifier chaque service
et chaque passage réseau.

### Mode géré

L'utilisateur choisit dans l'App « publier ce service par ce VPS ». Your Cloud :

1. observe l'état actuel des deux machines ;
2. calcule les adresses, routes et autorisations strictement nécessaires ;
3. présente le plan et les conséquences d'une suppression ou d'un échec ;
4. attend l'approbation ;
5. applique la configuration avec Ansible ;
6. vérifie le passage privé, le refus des autres ports et l'accès HTTPS ;
7. conserve l'état attendu afin de détecter une dérive ultérieure.

Le calcul est dynamique, mais l'application ne l'est pas : un changement de
placement, de port ou de VPS crée un nouveau plan à approuver. Aucun événement
de découverte ne modifie silencieusement le réseau.

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

La V1 ne découvre pas arbitrairement tous les services et tunnels existants.
Elle exige une déclaration explicite. Une future reprise en **Mode géré** devra
commencer par un audit, un diff et une approbation ; elle n'est jamais implicite.
<!-- coherence: OWNERSHIP-MODES:end -->

## Capacités nécessaires

- Créer une infrastructure et lui rattacher les deux machines existantes.
- Installer un Agent minimal proprement identifiable sur chaque machine, dont
  le Daemon est limité à l'observation.
- Activer sur le seul VPS déclaré candidat un processus Relay séparé à partir du
  même exécutable, sans rendre le rôle Relay démarrable sur la machine du LAN.
- Recevoir par le Relay leur présence, leur version et un premier état utile.
- Afficher clairement une donnée absente, récente ou devenue ancienne.
- Présenter depuis l'App un plan de déploiement avant exécution.
- Exécuter le déploiement approuvé avec Ansible vers la machine concernée.
- Déployer deux services aux versions précisément maîtrisées : un sur le VPS et
  un dans le LAN.
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
La V1 ne promet donc pas qu'elle soit inconnue du VPS ; elle promet qu'elle
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

La V1 utilise **Traefik** sur le VPS pour terminer HTTPS et router les noms
publics vers BentoPDF et Vaultwarden. Ce choix tient compte de son usage réel
dans l'environnement professionnel de référence et permettra de comparer plus
facilement le plan Your Cloud à une configuration déjà familière.

Your Cloud reste l'autorité déclarative des publications : il génère une
configuration dynamique Traefik en YAML avec le `file provider`, la présente
dans le plan, la dépose avec Ansible puis vérifie le résultat. Traefik ne
découvre pas seul les conteneurs et ne reçoit pas le socket Docker dans la V1.
La configuration vise explicitement BentoPDF sur le VPS et Vaultwarden par son
adresse WireGuard et son port autorisé.

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
<!-- coherence: V1-NETWORK:end -->

## Méthode de déploiement

Ansible est le moyen retenu pour orchestrer et vérifier un changement. Il n'est
pas le format universel des services : une intégration peut installer un paquet
natif ou une image OCI, mais la V1 n'implémente qu'un premier parcours officiel
fondé sur des **images OCI**.

BentoPDF et Vaultwarden sont référencés par un nom lisible, une version précise
et le digest du manifeste réellement approuvé. Un tag flottant comme `latest`
est refusé. Le plan affiche l'origine, la version, le digest, les volumes, les
ports, les besoins réseau et les limites de ressources avant approbation.

Ansible télécharge l'image depuis un registre explicitement autorisé, vérifie
que le digest obtenu correspond au plan, installe la définition du service puis
prouve son état. Une mise à jour est un nouveau plan vers un nouveau digest ;
elle ne suit jamais silencieusement un tag modifié. Une suppression retire le
conteneur et ses autorisations, mais ne détruit les données persistantes que si
cette conséquence a été explicitement demandée et approuvée.

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

La V1 exécute les images OCI avec **Podman en mode rootless** et les décrit par
des unités **Quadlet** gérées par systemd.

Ce parcours géré exige donc **systemd et cgroup v2 sur la machine qui héberge le
service OCI**. L'App vérifie ces deux prérequis avant de proposer le plan. Si
l'un manque, elle refuse le déploiement géré avec une explication précise :
Quadlet ne bascule pas automatiquement vers OpenRC, runit ou un script maison.
Un service installé par l'utilisateur peut rester représenté en mode externe.
Aucun adaptateur pour un autre système d'init n'est planifié dans la V1.

Cette limite concerne le déploiement OCI géré. Elle ne suffit pas, à elle seule,
à décider si une machine peut être enrôlée et observée : le paquet et les
prérequis définitifs de l'Agent seront cadrés dans leur propre incrément.

Podman offre une ligne de commande comparable à celle de Docker, ce qui réduit
le coût d'apprentissage pour un utilisateur habitué aux commandes `docker`.
Cette compatibilité n'est pas promise comme parfaite : la documentation et
l'interface Your Cloud emploieront les commandes réellement prises en charge et
signaleront les différences utiles.

Quadlet n'est pas une couche d'orchestration cachée. C'est la fiche déclarative
qui associe une image précise à son compte, ses volumes, son réseau, ses ports,
ses limites et sa politique de redémarrage. systemd transforme cette fiche en
service Linux observable. Ansible installe et retire ces définitions après
approbation ; aucune API Podman permanente n'est nécessaire à Traefik ou aux
services.

### Justification de sécurité de Podman et Quadlet

- **Menaces traitées** : compromission d'un démon privilégié, élévation depuis
  un conteneur, configuration manuelle non reproductible et dérive invisible.
- **Alternative considérée** : Docker rootless peut aussi réduire les
  privilèges et reste valide en mode externe, mais Podman rend le chemin sans
  démon central et l'intégration systemd déclarative naturels pour cette V1.
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
effet visible et le test qui le prouve. La V1 ne considérera pas ce parcours
terminé tant que la relation entre la fiche Quadlet, le conteneur et le service
systemd réellement observés ne sera pas compréhensible.

Un déploiement V1 est au minimum versionné, relançable, vérifié après
application et désinstallable. Les scripts opaques et non idempotents ne
constituent pas le parcours normal.

## Services envisagés pour la preuve finale

Deux services temporaires de type `hello-world` pourront servir de sondes dans
les micro-versions qui construisent le déploiement, le passage privé et le
routage. Ils ne compteront pas comme les deux véritables services de la V1.

La cible recommandée pour la preuve finale est :

- **BentoPDF sur le VPS** : service public essentiellement statique, sans base
  de données, dont le traitement des PDF reste dans le navigateur ; son image et
  ses dépendances seront épinglées et les téléchargements d'actifs externes
  seront supprimés ou explicitement bornés ;
- **Vaultwarden sur la machine du LAN** : service sensible et persistant,
  accessible uniquement en HTTPS par le VPS ; sa preuve inclura le stockage,
  la sauvegarde, la restauration, le redémarrage, la fermeture des inscriptions
  et l'absence d'accès latéral au LAN.

Cette cible est validée pour la V1. Les sondes `hello-world` restent uniquement
des outils de construction intermédiaires et ne satisfont pas sa preuve finale.

Vaultwarden est volontairement réservé à un incrément tardif : il ne doit pas
servir à déboguer en même temps le premier conteneur, WireGuard, le proxy et la
persistance. Le LAB n'utilisera que des secrets synthétiques.

Les documentations officielles confirment que
[BentoPDF peut être auto-hébergé](https://www.bentopdf.com/docs/self-hosting/)
comme site statique et que ses fonctions traitent les fichiers dans le
navigateur. [Vaultwarden](https://github.com/dani-garcia/vaultwarden) recommande
une image de conteneur avec stockage persistant, HTTPS et un proxy inverse. Les
exemples amont utilisent parfois `latest` ; Your Cloud utilisera au contraire
une version et un digest précis, conformément à sa politique de chaîne
d'approvisionnement.

<!-- coherence: V1-OBSERVATION:start -->
## Contrat d'observation du Daemon

Les données, la vérification d'un élément externe et les choix de l'interface
forment un même contrat : **l'utilisateur choisit ce qu'il veut observer, puis
Your Cloud montre exactement les données, droits et coûts nécessaires avant de
l'appliquer**.

### Aucun accès entrant au Daemon

Le Relay ne vient jamais « récupérer » les données en se connectant au Daemon.
Le Daemon :

1. relève uniquement les observations approuvées ;
2. les écrit dans un tampon local protégé ;
3. ouvre lui-même une connexion sortante mTLS vers le Relay approuvé ;
4. envoie des observations identifiées par une séquence ;
5. supprime seulement les éléments dont le Relay confirme l'enregistrement
   durable.

Le Daemon n'écoute sur aucun port TCP ou UDP, et le protocole Daemon–Relay ne
transporte aucune commande en sens inverse. Le Relay peut accuser réception ou
refuser un message invalide ; il ne peut ni changer le profil, ni demander un
fichier, ni lancer une collecte ponctuelle.

Un endpoint Relay approuvé réunit la route, le port et l'identité
cryptographique attendue. Chaque Daemon enrôlé en reçoit un ; le Relay n'a pas
besoin d'une IP publique si un réseau fournisseur, un segment interne ou un
passage privé borné le rend joignable. Un futur remplacement automatique reste
un contrat séparé : il devra limiter les candidates, prouver la panne,
redistribuer l'endpoint authentifié, annoncer la perte d'état éventuelle et
empêcher deux Relay de devenir simultanément responsables. Son mécanisme n'est
pas choisi par la V1 actuelle.

Sans Relay disponible, une commande exécutée **localement sur la machine** peut
afficher le dernier état et la santé du tampon. Cette consultation utilisera un
fichier protégé ou un socket Unix local aux permissions bornées, jamais une API
réseau. L'App distante ne prétendra pas voir ces données tant qu'elles n'auront
pas rejoint le Relay.

### Rétention locale liée à la livraison

Le dernier état courant remplace sa version précédente afin de toujours garder
une vue locale récente. Les observations historiques et événements en attente
restent dans un journal borné jusqu'à leur accusé de réception durable.

Le tampon possède obligatoirement une limite de taille et d'âge afin qu'une
panne longue du Relay ne remplisse jamais le disque de la machine. Lorsque la
limite est atteinte, le Daemon conserve l'état courant, retire les éléments les
plus anciens et crée une **lacune d'observation** indiquant l'intervalle et le
nombre d'éléments perdus. Ni le Daemon ni le Relay ne reconstruisent une fausse
continuité. Les limites chiffrées seront choisies avec le premier profil réel et
rendues visibles dans l'App.

### Profil d'observation choisi par l'utilisateur

Un profil est une liste de collecteurs **nommés et pris en charge par la version
du Daemon**. Pour chaque collecteur, le plan présente :

- la cible exacte : machine, service déclaré, volume ou passage privé ;
- les champs produits et ceux explicitement exclus ;
- la fréquence, la rétention et le budget CPU, mémoire et disque ;
- le compte, les fichiers, sockets ou API locales qu'il doit lire ;
- les flux réseau éventuellement nécessaires ;
- ce que le résultat permet réellement de conclure.

Le même mécanisme sert à observer un service géré et à vérifier en lecture seule
un service ou un passage externe explicitement déclaré. Le statut reste
« externe vérifié » : obtenir une preuve ne transfère aucune autorité de
modification à Your Cloud.

Le Daemon refuse :

- toute commande shell ou suite d'arguments libre ;
- tout chemin de fichier arbitraire, motif global ou lecture de contenu ;
- toute découverte du LAN, des voisins ou de services non déclarés ;
- tout collecteur inconnu, non versionné ou téléchargé à la demande ;
- tout résultat qui ne respecte pas son schéma, sa taille et son type attendus.

### Extension future sans backdoor

La V1 commence avec un petit ensemble de collecteurs intégrés et audités. De
nouvelles observations pourront être ajoutées dans les versions suivantes sans
changer ce modèle de sécurité : chaque collecteur possède un identifiant, une
version, un schéma de sortie, un manifeste de privilèges et des tests hostiles.

Le Daemon principal reste non-root. Si une future donnée exige davantage de
droits, elle sera lue par un auxiliaire local séparé, sans réseau, qui n'expose
qu'une opération fixe et renvoie une sortie typée. Donner root au Daemon entier
ou lui permettre d'exécuter des plugins arbitraires reste exclu.

### Justification OWASP et NIS2

- **Menaces traitées** : Daemon transformé en shell distant, exfiltration de
  fichiers ou secrets, collecte excessive, faux état après perte de données,
  déni de service par remplissage du disque et Relay compromis donnant des
  ordres aux machines.
- **Choix** : connexion sortante uniquement, séparation observation/commande,
  collecteurs sur liste positive, schémas stricts, privilèges par collecteur,
  tampon borné et lacunes explicites.
- **Preuves hostiles** : tentative de connexion entrante, commande déguisée en
  profil, collecteur inconnu, chemin libre, message trop grand, sortie mal typée,
  faux accusé et indisponibilité prolongée du Relay sont refusés ou produisent
  l'état dégradé annoncé sans arrêter les services.
- **Risque résiduel** : une machine compromise peut falsifier ce qu'elle
  observe et lire les données auxquelles son propre Daemon ou auxiliaire est
  autorisé ; l'identité mTLS prouve l'origine machine, pas la véracité absolue
  de son système compromis.

Cette conception applique les valeurs sûres par défaut, la réduction de surface,
le moindre privilège et la séparation des responsabilités de
[l'OWASP Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html).
La sélection des données, l'exclusion des secrets, la protection en transit et
les tests de saturation suivent aussi le
[guide OWASP sur la journalisation](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
Elle contribue aux mesures NIS2 de gestion des risques, contrôle d'accès,
cryptographie, continuité, gestion des actifs et mesure d'efficacité, sans
constituer à elle seule une déclaration de conformité.
<!-- coherence: V1-OBSERVATION:end -->

## Premier incrément déjà retenu

La `v0.0.1` ne construit pas toute la V1. Sa preuve finale doit montrer,
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

## Preuve de V1 dans le LAB

Le LAB simulera au minimum :

- une VM de contrôle pour l'App ;
- une VM jouant le rôle du VPS sur un réseau exposé ;
- une VM placée derrière un réseau LAN sans entrée directe ;
- une sonde extérieure au LAN pour vérifier les accès publics et l'absence
  d'exposition directe.

La preuve montrera le placement, les commandes significatives, les deux
services accessibles, les ports réellement exposés, un second passage sans
changement, les redémarrages et la suppression propre.

Un test hostile partira du VPS supposé compromis et tentera d'atteindre SSH,
les ports non publiés et le reste du LAN. Seul le port exact du service publié
devra rester joignable.

Un second test hostile partira du service placé dans le LAN et tentera de
joindre un appareil voisin synthétique. La tentative devra échouer tant qu'aucun
flux latéral n'a été déclaré et approuvé. Cette preuve porte sur les composants
et environnements gérés par Your Cloud ; elle ne prétend pas transformer à elle
seule tout le système Linux en pare-feu général du domicile.

## Hors du contrat V1 actuel

- Créer les VM ou installer leur système d'exploitation.
- Piloter OpenStack, Terraform, OpenTofu ou un fournisseur cloud.
- Recevoir des plans d'action par l'Agent ou activer un Auxiliaire local pour
  les appliquer sans SSH.
- Fournir depuis l'interface des opérations générales sur la machine au-delà des
  déploiements, passages et routes précisément pris en charge par la V1.
- Fournir un catalogue générique acceptant arbitrairement tout service.
- Découvrir automatiquement les services et passages existants ou les adopter
  en gestion. La V1 repose sur leur déclaration explicite et leur vérification
  en lecture seule lorsqu'un adaptateur existe.
- Scanner une plage réseau ou inventorier les appareils voisins du LAN.
- Exiger K3s standalone ou un cluster K3s pour déclarer la V1 atteinte.
- Fournir une haute disponibilité complète ou masquer les pannes.
- Déployer un fournisseur d'identité et activer le SSO de Vaultwarden.

Ces capacités restent hors V1. Elles pourront venir ensuite ; leur ajout à la
V1 exigerait une modification explicite et une nouvelle validation du contrat,
jamais un simple changement de roadmap.

## Premier jalon demandé après la V1

La `v1.0.1` ajoutera un petit parcours SSO pour Vaultwarden au moyen d'un
fournisseur d'identité compatible OpenID Connect. Le fournisseur, son placement
et son mode de récupération seront choisis seulement lors du cadrage de ce
jalon ; cette note ne les impose pas à la V1 et ne préconçoit pas encore sa
solution.

## Paramètres décidés au bon incrément

Le profil détaillé et les chiffres du tampon ne bloquent plus l'écriture de la
roadmap. Nous n'inventerons pas aujourd'hui une taille ou une fréquence sans
connaître la taille réelle des messages et leur coût sur une machine du LAB.

Le contrat suffisant pour découper la V1 est le suivant :

- `v0.0.1` ne conserve que le signal de présence décrit plus haut ;
- chaque incrément suivant ajoute uniquement l'observation nécessaire à sa
  preuve : santé de la machine, état des services, du passage privé ou du point
  d'entrée ;
- aucun log, contenu de fichier, secret ou inventaire libre n'entre dans le
  profil par défaut ;
- le tampon possède toujours une limite d'âge, une limite de taille et un
  maximum non contournable ;
- l'état courant est conservé, les plus anciens événements historiques sont
  retirés en premier et chaque perte crée une lacune visible ;
- le premier incrément qui ajoute de vraies observations mesure leur taille,
  leur fréquence et leur coût disque dans le LAB, puis fixe et documente les
  valeurs par défaut ainsi que les tests de saturation.

Ces paramètres deviendront alors une petite décision d'implémentation prouvée,
pas une hypothèse architecturale prise trop tôt. La roadmap V1 utilise ce
travail comme porte de sortie du palier concerné.

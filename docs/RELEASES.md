# Politique de releases

## Rôle d’une release

Une release désigne une version cohérente, installable et utilisable de bout en bout. Les étapes internes, prototypes et fonctionnalités isolées restent traçables par les commits et ne reçoivent pas automatiquement de tag.

Une release GitHub doit fournir plus qu’une archive du dépôt : documentation d’installation, artefacts nécessaires, sommes de contrôle et preuves de vérification adaptées à chaque composant distribué.

## Histoire précédente

Les tags `v0.1.0` à `v0.9.0` restent dans l’ancien dépôt comme traces de l’ancienne lignée. Le nouveau dépôt privé conserve l’historique des commits au moyen de sa branche principale et de la branche d’archive `old-project`, sans importer ces anciens tags.

## Première release stable

Le tag `v1.0.0` ne sera créé que lorsque le produit accomplira un parcours utilisateur complet et prouvé. Aucun tag de confort ne remplace cette preuve. Une pré-release `v1.0.0-rc.N` pourra être utilisée uniquement pour valider les artefacts finaux.

Les étapes P0 à P6 de la [`Roadmap`](ROADMAP.md) sont des paliers internes et ne reçoivent pas automatiquement de tag. P6 correspond à la preuve complète exigée avant la première release candidate.

La candidate `v1.0.0-rc.1` a fermé P6 dans le LAB, puis son
[essai d'adoption](lab/rc1-adoption.md) a trouvé deux écarts de distribution :
les dépendances d'automatisation exigeaient encore le dépôt source et le
premier parcours n'était pas assez explicite. Elle n'est donc pas promue en
stable. Ces écarts appartiennent à `v1.0.0-rc.2` et doivent être rejoués depuis
le seul lot distribué.

La [preuve d'adoption RC2](lab/rc2-adoption.md) confirme la construction signée,
l'installation autonome de l'extra Ansible, l'audit sans mutation,
l'enrôlement d'une cible Debian distante neuve et son re-run `changed=0`. La
promotion stable attend encore la publication d'une pré-release signée par une
clé approuvée hors du LAB, puis son utilisation sans défaut bloquant.

La V1 doit au minimum permettre à un opérateur de :

- installer la console sur le système pris en charge ;
- gérer plusieurs infrastructures distinctes ;
- auditer et enrôler plusieurs machines Debian 13 amd64 ;
- observer une machine disponible avant de l'affecter volontairement à une infrastructure ;
- observer localement un état de santé minimal via les daemons Go en lecture seule ;
- déployer un coordinateur distant auto-hébergé ;
- observer les machines à distance sans port entrant chez l’opérateur ni sur les machines gérées ;
- appliquer volontairement un premier profil Linux sécurisé après un audit préalable concluant et la confirmation explicite que la machine est dédiée ;
- créer ou adopter explicitement un compte d’administration non-root, puis prouver une nouvelle connexion par clé et son élévation avant de fermer l’accès de bootstrap ;
- rejouer ce profil sans changement lorsque la machine est déjà conforme ;
- déplacer, désenrôler et désinstaller une machine sans supprimer ses services ;
- révoquer individuellement une identité de machine ;
- renouveler explicitement une identité perdue sans accepter une nouvelle clé par simple correspondance d'adresse ou de nom ;
- enregistrer la première clé d’hôte SSH d’une cible explicitement choisie, puis refuser strictement toute différence jusqu’à un renouvellement vérifié ;
- rejeter une télémétrie non signée, issue d'une identité inconnue ou rejouée ;
- sauvegarder et restaurer le registre public des identités sans dépendre de la base d'un coordinateur ;
- comprendre les erreurs et vérifier les preuves sans dépendre d’une interface graphique.

La V1 vise un homelab débutant et une petite PME administrée par une seule personne. La haute disponibilité du pilotage, le multi-utilisateur, le front graphique, les commandes distantes générales et l'orchestration d'une politique de sauvegarde 3-2-1 ne conditionnent pas cette première release. Aucun connecteur S3, planificateur de sauvegarde de services ou déploiement de serveur de backup n'est ajouté pour anticiper cette capacité future.

La V1 signale l'indisponibilité d'un coordinateur et l'heure de son dernier contact, mais ne centralise pas les journaux des machines et ne prétend pas déterminer automatiquement la cause d'une panne. Les erreurs normales du coordinateur restent consultables dans les journaux système de son hôte ; leur collecte, leur corrélation et leur présentation dans la console sont reportées jusqu'à ce qu'un besoin concret les justifie.

Une petite installation peut colocaliser le coordinateur avec son nœud d’entrée afin de ne pas imposer une VM supplémentaire. Les deux fonctions conservent des processus, comptes système, stockages, limites de ressources et expositions réseau distincts, sans partage de secrets d’administration. Le parcours rend visible que cette économie crée un domaine de panne commun et réduit l’isolation ; une PME peut placer le même coordinateur sur une VM séparée sans changer le modèle. Cette colocalisation ne constitue jamais une preuve de haute disponibilité.

Avant cette installation, l’hôte du coordinateur est obligatoirement enrôlé, audité et sécurisé comme machine gérée au moyen de l’accès SSH direct de la console. Un plan distinct installe ensuite la fonction de coordination. L’hôte peut rester disponible s’il est réservé au pilotage, ou appartenir à une infrastructure s’il porte aussi un rôle tel que nœud d’entrée ; cette affectation ne limite pas les infrastructures relayées, car le coordinateur appartient au plan de pilotage et non aux services de l’infrastructure. Son daemon et son coordinateur conservent des comptes, identités et stockages séparés. Leur auto-observation est utile tant que l’hôte fonctionne, mais ne constitue aucune preuve indépendante de sa disponibilité ; l’observation croisée et la reprise automatique restent des capacités futures à prouver.

Le mode local emploie le même coordinateur Go et les mêmes contrôles mTLS que le mode distant, mais le point de coordination reste limité au LAN ou au plan d’administration. Sur un homelab à une seule machine toujours allumée, daemon et coordinateur peuvent être colocalisés ; la console retrouve l’historique lorsqu’elle revient sur le réseau. Sans hôte toujours allumé, le produit propose uniquement une inspection ponctuelle par le chemin d’administration et ne prétend pas fournir une observation continue. L’ajout ultérieur d’un point distant est d’abord testé sur une machine pilote de chaque site, avec l’ancien coordinateur conservé comme secours. Plusieurs états signés et accusés valides sont exigés avant une propagation progressive, arrêtée au premier échec. Le retrait de l’ancien point forme un plan séparé ; aucune de ces étapes ne renouvelle les identités ni ne réenrôle les machines.

Le mode distant fonctionne avec une adresse IP seule ou un nom DNS optionnel. Chaque point de coordination associe cette localisation à une identité de transport autorisée par la console : ni l’adresse ni le DNS ne deviennent une preuve de confiance. Les daemons ne découvrent aucun coordinateur automatiquement et refusent toute identité inconnue. Un nom DNS permet d’en changer l’adresse sous-jacente sans réenrôlement, tandis qu’une adresse IP littérale modifiée exige un nouveau plan. L’autorité privée qui autorise les identités de transport reste chiffrée dans la console, n’est jamais copiée sur un coordinateur et doit être présente dans le kit de récupération vérifié avant l’activation du mode distant. Un certificat public peut compléter ce modèle sans le remplacer.

Le coordinateur Go termine directement le mTLS sur un port configurable et n’exige ni Traefik, ni nginx, ni runtime de conteneurs. Il vérifie l’identité cliente avant de traiter une requête, tandis que la console conserve la vérification indépendante des signatures de télémétrie. Le parcours audite le port choisi, propose `443` s’il est libre ou un port dédié dans le cas contraire, puis n’ouvre que ce point dans le pare-feu. Le processus reste sous un compte dédié non-root et ne reçoit qu’une capacité de bind bornée si un port privilégié est retenu. Les délais TLS et HTTP, tailles de messages, connexions, concurrence et ressources systemd sont bornés ; ces protections ne sont pas présentées comme une défense suffisante contre un déni de service volumétrique. Le port public ne fournit aucune route anonyme de santé, version, métriques ou diagnostic : les détails sont accessibles localement et les refus distants restent génériques. Un routeur TCP transparent peut rester sous gestion externe pour un utilisateur avancé, mais une terminaison TLS déléguée ne fait pas partie du chemin V1.

L'état V1 d'une machine couvre son identité, la version du daemon, Debian et son noyau, le dernier démarrage, la charge CPU, la mémoire, l'espace du système de fichiers principal, le besoin de redémarrage de sécurité et les unités systemd explicitement sélectionnées. Il est publié au démarrage puis chaque minute, avec publication immédiate des changements significatifs ; après trois minutes sans état, la console affiche une télémétrie retardée sans conclure à une panne. Chaque daemon utilise un stockage SQLite embarqué limité à 10 Mio pour sa reprise locale ; le coordinateur utilise son propre SQLite pour le dernier état et trente jours d'événements significatifs. Il n'inventorie pas automatiquement les processus, utilisateurs, ports, fichiers, commandes ou journaux.

Les publications utilisent des requêtes HTTPS/mTLS bornées, jamais une session permanente nécessaire au fonctionnement. Une connexion peut être réutilisée, mais sa fermeture par un NAT ou un firewall est normale. À chaque réponse, le coordinateur n’accuse que les séquences déjà validées dans SQLite ; le daemon conserve les événements tant qu’un coordinateur autorisé ne les a pas durablement confirmés. Une retransmission de la même identité, du même flux et de la même séquence reste idempotente. Les échecs entraînent une reprise temporisée avec part aléatoire et envoi prioritaire de l’état actuel, sans modifier les services ni provoquer de tempête de reconnexion.

Les payloads et accusés V1 sont des messages Protobuf transmis par ces requêtes HTTPS, sans framework gRPC ni streaming. Le daemon signe les octets exacts de son payload avec un séparateur de domaine ; le coordinateur conserve cette enveloppe originale même lorsqu’il en décode les champs nécessaires, puis la console vérifie la même signature avant d’utiliser les données. Les `.proto`, générateurs et plugins sont versionnés et épinglés, et les sorties Go et Python générées restent dans le dépôt. Une vue JSON lisible peut être produite après validation pour la CLI, mais n’est ni acceptée sur le fil ni utilisée comme source de signature. La V1 n’ajoute aucune compression applicative à ces messages bornés.

La console interroge le coordinateur avec une identité mTLS de lecture distincte des identités de machine, de l’identité d’administration et des clés SSH. Elle récupère des pages bornées d’enveloppes originales puis vérifie elle-même leurs signatures ; le coordinateur ne pousse aucune donnée vers le laptop. Cette API ne peut ni enrôler ou révoquer une machine, ni modifier le registre dérivé, la déclaration, les services ou les points de coordination. Ces changements continuent de passer par le chemin SSH/Ansible en V1. La clé de lecture reste chiffrée dans la console, révocable et incluse dans le kit de récupération ; son vol expose au plus la télémétrie conservée, jamais une autorité d’administration ou un secret d’infrastructure.

Les daemons et coordinateurs de la V1 ne se mettent jamais à jour seuls et ne récupèrent pas de version flottante depuis Internet. Une mise à jour est initiée par l'opérateur depuis la console, cible une version précise, vérifie l'origine et l'intégrité de l'artefact, présente son plan d'action et prépare le retour à la version précédente avant le déploiement. Le protocole est versionné indépendamment des binaires et les releases stables successives restent normalement interopérables. La console vérifie toute la topologie, met à jour les coordinateurs autorisés avant les daemons, puis avance une machine à la fois avec preuve du retour de l'observation et arrêt au premier échec. Ces détails sont automatiques dans le parcours guidé ; une transition incompatible est refusée avant tout changement avec indication de la release intermédiaire nécessaire. La RC V1 signe `SHA256SUMS` en Ed25519 avec OpenSSL puis revérifie signature et sommes. La preuve LAB emploie une clé synthétique ; une release publique exige une empreinte distribuée par un canal indépendant approuvé.

Seule la console peut effectuer une vérification passive, désactivable et non bloquante d'un manifeste signé afin de signaler une nouvelle version ; les daemons et coordinateurs ne contactent jamais le service de distribution. L'emplacement du manifeste ne devient aucune dépendance de fonctionnement.

Le premier profil reste volontairement borné au socle Linux Debian 13. Au premier bootstrap d’une cible explicitement choisie, la console peut enregistrer par TOFU sa clé d’hôte SSH si aucune empreinte fournisseur ou hors bande n’est disponible ; l’empreinte et sa provenance restent visibles. Toute différence ultérieure est refusée jusqu’à un renouvellement vérifié, sans remplacement automatique fondé sur l’adresse ou le hostname. Ce registre interne ne modifie pas le `known_hosts` personnel.

Le compte initial du fournisseur ou root ne sert qu’au bootstrap ; le profil crée par défaut un compte d’administration non-root, ou adopte explicitement un compte existant après les mêmes contrôles, puis vérifie une nouvelle connexion SSH par clé et `sudo` avant de fermer un ancien accès. Chaque machine reçoit une clé distincte, chiffrée dans le stockage propre à la console et jamais confiée au coordinateur. Ce mécanisme ne modifie ni `~/.ssh`, ni la configuration, ni les hôtes connus, ni l’agent SSH permanent de l’opérateur.

Après cette preuve, le profil désactive l’authentification SSH par mot de passe et interactive, puis interdit la connexion directe de root. Il valide la configuration avec `sshd -t`, recharge SSH sans le redémarrer et prouve une nouvelle session avant de fermer la session conservée. Il ne pose pas de `AllowUsers` limité au compte du produit et ne supprime aucun autre compte ou clé publique : ces accès résiduels restent visibles et leur révocation exige un plan séparé.

La création ou l’adoption du chemin d’administration forme un plan d’action séparé de ce profil. Le parcours guidé peut enchaîner les deux, mais il doit prouver le premier et préparer son chemin de retour avant de proposer le second ; le profil n’installe jamais WireGuard implicitement. La première application exige un audit en lecture seule et la confirmation explicite que la machine est dédiée. « Dédiée » ne signifie pas vide : des composants de base connus peuvent rester présents s’ils ne revendiquent aucune politique concernée. La déclaration de l’opérateur ne contourne toutefois jamais un conflit technique, et un refus du profil ne bloque ni l’enrôlement ni l’observation.

Avant un changement SSH ou pare-feu, l’opérateur confirme disposer d’un accès hors bande. La V1 conserve la session courante, prépare les configurations précédentes, applique des fichiers validés et teste une seconde connexion réellement distincte ; un échec restaure l’état précédent par la session conservée. Aucun minuteur privilégié ni rollback autonome n’est installé. Si les deux connexions disparaissent, la récupération passe explicitement par la console fournisseur ou physique. En LAB, seules la restauration ou la recréation de la VM sont utilisées.

Cet audit V1 se limite aux preuves directement nécessaires : cible Debian 13 amd64 avec systemd, accès SSH et `sudo`, espace disque, horloge, autorités concurrentes, outils de conteneurs ou de configuration connus, ports qui seraient fermés et empreintes des clés publiques encore actives. Il ne produit aucun inventaire complet, ne lit aucun contenu applicatif, journal, environnement, clé privée ou secret. Seuls les constats normalisés restent localement dans la console ; les sorties brutes temporaires sont purgées et rien n’est transmis au coordinateur.

Avant toute mutation, l’audit refuse le profil complet si le pare-feu hôte est déjà administré par `ufw`, `firewalld`, des règles personnalisées, un runtime de conteneurs ou une autre autorité que le produit ne peut pas identifier comme sienne. Il ne fusionne et ne vide jamais un ruleset inconnu. Un pare-feu extérieur fourni par l’hébergeur reste une protection complémentaire, pas un substitut au pare-feu hôte.

Une exécution ultérieure distingue une politique encore conforme d’une dérive de configuration. La conformité ne produit aucun changement ; une dérive est affichée et ne peut être corrigée qu’au moyen d’un nouveau plan approuvé. Si le produit peut toujours prouver qu’il est l’unique autorité de la politique, le plan peut proposer de restaurer l’état déclaré. Si une modification inconnue ou un autre outil remet cette autorité en cause, la V1 refuse l’écrasement et demande une adoption ou une migration explicite. Elle n’effectue aucune auto-réparation silencieuse.

Le ruleset du profil refuse par défaut les nouveaux flux entrants et le transfert, autorise les sorties et conserve les échanges de contrôle nécessaires au réseau. Cette politique couvre IPv4 et IPv6 sans désactiver ce dernier ; ICMPv6 indispensable au fonctionnement du réseau reste autorisé. Une exposition choisit explicitement IPv4, IPv6 ou les deux et n’est jamais reproduite silencieusement d’une famille vers l’autre. SSH n’est admis que par le chemin d’administration prouvé. Aucun port applicatif n’est ouvert par anticipation : son ouverture et sa fermeture appartiennent au plan du service ou du chemin d’exposition concerné. Le confinement d’une zone exposée vis-à-vis des réseaux internes repose d’abord sur les frontières et pare-feux de zone ; un futur filtrage sortant spécialisé pourra les renforcer sans alourdir le socle V1 avec une allowlist générique fragile.

Le profil ne reprend aucune checklist sysctl générique. Chaque paramètre doit apporter un bénéfice démontré par rapport au défaut de Debian 13, avoir une autorité de configuration non concurrente et passer des preuves LAB IPv4, IPv6 et WireGuard avec rollback. Le profil générique ne modifie pas les réglages dépendant d’une fonction de passerelle, d’une topologie multihomée ou de l’autoconfiguration IPv6 ; l’ancien fichier de durcissement est réévalué paramètre par paramètre plutôt que copié.

Le parcours guidé recommande l'installation automatique des correctifs provenant exclusivement des dépôts de sécurité Debian autorisés, mais ne l'active qu'après approbation explicite. Un opérateur avancé peut choisir le simple signalement ou désactiver cette politique. Elle ne change jamais de version Debian et n'inclut pas les composants du projet. Aucun redémarrage automatique de la machine n'est autorisé : le besoin est observé puis présenté comme une action séparée. Le plan prévient néanmoins qu'un paquet corrigé peut redémarrer son propre service pendant l'installation. Le profil n’installe pas automatiquement k3s, IAM ou une application. Les mécanismes exacts seront retenus après audit des rôles existants et preuve qu’ils ne verrouillent pas l’opérateur hors de sa machine.

Le scénario cible VPS, Proxmox, OPNsense, Raspberry Pi 5, SSO et services exposés décrit dans [`VISION.md`](VISION.md) guide les versions ultérieures sans devenir une condition cachée du tag `v1.0.0`.

Les preuves de release, compilations, tests et essais d'installation sont produits dans des environnements LAB isolés ou sur des exécutants distants dédiés, jamais en exécutant le projet sur le laptop de l'opérateur. La preuve V1 de bout en bout utilise une topologie séparant une console, un coordinateur, une passerelle et au moins deux machines gérées ; le LAB rapide à deux VM reste réservé aux boucles locales qui ne prétendent pas valider le mode distant.

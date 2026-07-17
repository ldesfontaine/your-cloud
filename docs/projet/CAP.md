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
### Une interface Web sans exposer les machines

À terme, un utilisateur autorisé doit pouvoir ouvrir l'App en HTTPS depuis le
Web sans établir lui-même un VPN. Cela n'expose ni SSH, ni l'Agent, ni une API
d'administration sur les machines du LAN : seul le point d'entrée de l'App est
public, et les machines continuent d'ouvrir leurs communications nécessaires
vers l'extérieur.

Le navigateur ne reçoit jamais une clé de machine, un secret de runner ou une
identité d'Agent. Le backend authentifie l'utilisateur, autorise chaque demande
pour l'infrastructure, la cible et l'action concernées, protège sa session et
demande une preuve renforcée pour les opérations critiques.

En V1, ce backend reste dans une VM de contrôle privée. Le navigateur du laptop
le rejoint par un tunnel SSH local lié à `127.0.0.1` ; seuls BentoPDF et
Vaultwarden sont publiés par le VPS. Ce placement réduit la première surface
d'attaque sans décider du placement final : à terme, l'App aura son propre
point d'entrée HTTPS authentifié et ne dépendra pas du laptop.
<!-- coherence: V1-APP-ACCESS:end -->

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
  communications sortantes authentifiées. Il ne modifie pas directement le
  système ;
- le **Relay** reste un processus réseau distinct, non privilégié et consacré
  aux observations. Il peut cohabiter avec le Daemon sur une machine déclarée
  candidate, mais son démarrage refuse toute machine qui n'a pas reçu au
  préalable une configuration et une identité Relay explicitement
  provisionnées ;
- un **Auxiliaire local** optionnel peut être activé uniquement pour une machine
  placée en mode géré. Il n'est pas permanent, n'écoute aucun port, est lancé
  pour un plan précis, applique une opération nommée avec les seuls privilèges
  nécessaires, renvoie un résultat structuré puis s'arrête.

Une machine ordinaire lance donc seulement `your-cloud daemon`. Une candidate
Relay explicitement provisionnée peut lancer simultanément `your-cloud daemon`
et `your-cloud relay` depuis les mêmes octets, sous deux comptes différents.
Lorsqu'il sera implémenté après la V1, `your-cloud aux` sera un troisième
processus ponctuel : le Daemon pourra demander son activation pour un plan
exact, mais l'autorité locale de lancement et l'Auxiliaire revérifieront ce plan
indépendamment avant tout privilège. Les versions qui ne prennent pas encore
l'Auxiliaire en charge ne l'exposent pas et ne l'installent pas par avance.

Cette séparation constitue une frontière de sécurité réellement maintenue et
testée. Une machine limitée à l'observation ne possède aucune élévation dormante
de type binaire `setuid` ou règle `sudo` générale. Le Daemon est traité comme un
transport non fiable : il ne peut transmettre ni shell, ni script libre, ni
chemin arbitraire, et l'Auxiliaire revérifie indépendamment le plan avant tout
changement privilégié. Les privilèges appartiennent à l'opération autorisée,
pas à un auxiliaire root universel.

Partager un exécutable simplifie la chaîne d'approvisionnement, les mises à jour
et le retour à une version précédente. Cela ne constitue pas une isolation :
celle-ci vient des processus, comptes, identités, fichiers et politiques
systemd distincts. Un défaut du lot commun peut atteindre plusieurs rôles ; les
tests par rôle, la cohabitation, les déploiements progressifs et le rollback du
lot entier restent donc obligatoires.

L'activation initiale de cette capacité exige nécessairement une autorité déjà
présente : chemin SSH/Ansible approuvé, installation manuelle ou mécanisme du
fournisseur. Un Agent non privilégié ne s'accorde jamais lui-même de nouveaux
droits.

### Utiliser l'autorité adaptée à chaque cible

Toutes les actions de l'interface ne traversent donc pas l'Agent :

| Cible | Autorité à utiliser à terme |
|---|---|
| Système Linux et service local | Auxiliaire local avec une opération typée et bornée |
| Ressource OpenStack | Adaptateur central utilisant l'API OpenStack et une identité limitée |
| Plan Terraform, OpenTofu ou Ansible | Runner d'automatisation isolé avec artefact et résultat vérifiables |
| K3s | Agent pour l'amorçage local si nécessaire, puis adaptateur utilisant l'API du cluster |
| Élément conservé en mode externe | Outil de l'utilisateur ; Your Cloud observe sans reprendre l'autorité |

Pour une opération coordonnée sur plusieurs machines, l'App construit un plan
global puis une partie ciblée par machine ou plateforme. Chaque autorité ne voit
et ne peut appliquer que la partie qui la concerne.

### Contrat commun d'une action

Quel que soit l'adaptateur, le parcours final conserve les mêmes garanties :

1. l'utilisateur est authentifié et autorisé pour l'infrastructure, la cible et
   l'opération demandée ;
2. l'App produit un plan typé qui nomme la cible, l'action et sa version, les
   changements, privilèges, flux, effets d'échec et possibilités de retour ;
3. l'approbation est liée au contenu exact du plan, pas seulement à son titre ;
4. l'ordre résultant est authentifié, ciblé, unique, de courte durée et protégé
   contre la modification et le rejeu ;
5. l'autorité qui applique revérifie la cible, l'action, sa version, la durée,
   l'approbation et les limites locales ;
6. l'adaptateur refuse par défaut tout champ ou comportement inconnu et valide
   aussi le sens des paramètres : volumes, chemins, destinations, ports,
   capacités, règles réseau et ressources restent dans des listes positives
   locales ;
7. l'adaptateur applique de façon idempotente lorsqu'il le promet et annonce
   honnêtement les effets partiels ainsi que son rollback ;
8. le résultat direct puis l'observation indépendante rendent le succès,
   l'échec ou l'état partiel visibles dans l'App ;
9. demande, approbation, identité, empreinte du plan et résultat forment une
   trace d'audit expurgée des secrets.

Une action possède des états honnêtes : en attente, en cours, réussie, échouée
ou résultat inconnu. Une coupure ne déclenche aucun rejeu aveugle d'une mutation
non idempotente. L'expiration et l'anti-rejeu survivent aux redémarrages ; une
opération réseau susceptible de couper son propre contrôle annonce et prouve son
chemin de reprise avant d'être proposée.

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
| SSH et Ansible comme unique chemin final | Valable pour la V1 et le mode manuel, mais insuffisant pour une App distante face au NAT : conservé sans devenir l'unique modèle |
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
- l'App, l'autorité de plan, le Daemon et l'autorité locale n'ont pas les mêmes
  droits, même lorsqu'ils appartiennent au même produit ;
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
| Continuité NIS2 | Services indépendants de l'App, du Relay et du canal d'action | Une panne du contrôle retarde les actions sans arrêter les services |
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

- La compromission de l'autorité centrale d'action pourrait produire des plans
  valides pour toutes les opérations qu'elle est autorisée à signer.
- Une machine compromise peut falsifier ses observations et détourner les
  capacités locales qui lui ont déjà été accordées.
- Une erreur dans un adaptateur privilégié peut endommager sa cible malgré un
  plan valide ; ses entrées, effets et rollback doivent donc être testés de
  façon hostile.
- Regrouper observation et transport d'action dans un même Daemon réduit
  l'exploitation quotidienne, mais augmente l'impact de sa compromission. La
  validation indépendante par l'Auxiliaire, les identités bornées et la
  révocation constituent les défenses compensatoires.
- Un défaut ou un lot compromis dans l'exécutable partagé peut toucher Daemon,
  Relay et futur Auxiliaire. Les comptes séparés limitent les droits à
  l'exécution, mais ne remplacent ni signature, SBOM, tests par mode, déploiement
  progressif ni retour atomique vers le dernier lot valide.
- La gestion des secrets, des mises à jour de l'Agent, de la révocation et des
  rôles multi-utilisateurs reste à concevoir dans les incréments qui en auront
  réellement besoin.

### Cohérence avec la V1

La V1 constitue une première marche cohérente, pas une implémentation anticipée
de toute cette cible. Son exécutable commun ne fournit que les modes réellement
pris en charge par la V1 : `daemon` et `relay`, lancés séparément. Il ne contient
aucun Auxiliaire actif ni canal d'action caché. Elle prouve le parcours
utilisateur stable — plan,
approbation, application et vérification — avec Ansible et une identité SSH
distincte. Son Daemon reste strictement limité à l'observation et son Relay ne
transporte aucune action.

Le contrat V1 n'exige ni canal sortant d'action, ni Auxiliaire local, ni
adaptateur OpenStack ou K3s. La roadmap V1 ne les avance donc pas. Les ajouter
exigerait de modifier et de faire revalider explicitement le contrat, pas de les
glisser dans un incrément. La V1 garde toutefois le plan utilisateur séparé de
son application Ansible afin qu'un futur adaptateur puisse changer le chemin
d'exécution sans changer ce que l'utilisateur approuve.
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

Le VPS public de la V1 constitue une zone d'exposition durcie, pas à lui seul
une DMZ. Une vraie DMZ nécessite une séparation réseau vérifiable : le trafic
Internet entre par une frontière filtrante, les composants exposés résident
dans un segment dédié, puis une seconde politique limite leurs accès vers les
services privés et le plan d'administration reste séparé.

Your Cloud pourra représenter cette architecture, préparer les flux strictement
nécessaires et en vérifier les refus. Il ne qualifiera jamais automatiquement
une machine publique de « DMZ » en raison de son adresse ou de son fournisseur.
<!-- coherence: V1-NETWORK:end -->

<!-- coherence: OWNERSHIP-MODES:start -->
## Gestion choisie, jamais imposée

Un élément est **géré** seulement lorsque Your Cloud conserve son état attendu
et peut appliquer un plan approuvé. Il reste **externe** lorsque l'utilisateur
le configure avec ses propres outils : l'App peut alors le représenter et, si
un adaptateur borné existe, le vérifier en lecture seule sans revendiquer son
cycle de vie. Un état fourni par l'utilisateur reste **déclaré** tant qu'une
observation datée ne l'a pas rendu **vérifié**.

## Découverte et adoption

Your Cloud peut construire un inventaire assisté depuis les machines déjà
enrôlées. Des adaptateurs en lecture seule peuvent notamment
relever les unités systemd, conteneurs, services K3s, ports d'écoute, passages
réseau et routes d'exposition qu'ils savent interpréter.

Un élément trouvé apparaît d'abord comme **détecté**, avec la preuve et la date
de l'observation. L'utilisateur choisit ensuite :

- l'ignorer ;
- le déclarer externe et continuer à le gérer manuellement ;
- demander son adoption par Your Cloud.

L'adoption n'est jamais une importation silencieuse. Elle commence par un audit
de la configuration actuelle, indique les parties comprises ou inconnues,
compare cet état au modèle pris en charge, prépare un plan de reprise et attend
une approbation. Your Cloud n'affirme pouvoir mettre à jour, restaurer ou
supprimer l'élément qu'après une adoption réellement réussie.

Cette capacité vise à rendre une infrastructure existante lisible sans imposer
Your Cloud comme autorité unique. La découverte reste locale aux machines déjà
déclarées ou enrôlées. Your Cloud ne scanne pas le réseau environnant : un VPS
chez un fournisseur n'en a pas besoin et la présence sur un LAN privé ne crée
aucune autorisation envers les autres appareils.
<!-- coherence: OWNERSHIP-MODES:end -->

## Contraintes durables

- Le code de chaque étape reste petit, lisible, testé et sans abstraction créée
  uniquement pour une hypothétique version future.
- L'interface montre le résultat attendu, les changements prévus et les preuves
  obtenues.
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
- Un service déjà déployé ne s'arrête pas uniquement parce que l'App ou le Relay
  est indisponible.
<!-- coherence: V1-OBSERVATION:start -->
- Chaque Daemon enrôlé reçoit un endpoint Relay approuvé qui borne la route, le
  port et l'identité cryptographique attendue. Le Relay n'exige pas d'adresse
  publique lorsqu'un routage privé autorisé le rend joignable aux Daemons et à
  l'App ; une adresse IP seule ne constitue jamais son identité.
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
  est activée explicitement par machine, utilise un Auxiliaire sans réseau et ne
  fournit jamais de commande ou de script libre.
- Le futur transport des plans d'action reste séparé du Relay d'observation.
  Une approbation est liée au contenu exact, à la cible et à l'opération ; une
  action inconnue, expirée, rejouée ou insuffisamment autorisée est refusée sans
  mutation.
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

Le [contrat V1](../objectifs/v1/README.md) fixe une ligne d'arrivée globale. La
[roadmap V1](../objectifs/v1/ROADMAP.md) ne détaille que le chemin jusqu'à cette V1. Le cap
présent n'est pas une roadmap globale : les capacités postérieures sont cadrées
au moment où elles deviennent le prochain objectif réel.

Chaque incrément ajoute une capacité observable et prouvable avant d'ouvrir le
suivant. Son placement, son flux de données, ses commandes, ses échecs et ses
limites doivent être compréhensibles avant que le projet continue.

Un ADR n'est pas créé pour documenter chaque choix. Il n'est envisagé que pour
une décision coûteuse à renverser, surprenante sans contexte et issue d'un
véritable compromis, puis seulement après discussion avec le mainteneur.

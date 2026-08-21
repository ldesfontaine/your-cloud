# Responsabilité externe : représenter sans posséder

> Statut : contrat d'architecture validé (`#105`) pour le palier `#18`.
> Il fixe ce qu'une déclaration externe porte, ce qu'un adaptateur en lecture
> seule a le droit de faire, la distinction entre ce qui est déclaré et ce qui
> est vérifié, et la liste de ce que l'App annonce ne pas pouvoir faire.
> L'implémentation le suit depuis `#106` (l'inventaire déclaré du Controller, sa
> surface et son seuil d'ancienneté) puis `#107` (l'adaptateur en lecture seule,
> son trajet, sa cadence et le refus croisé que la machine décide) ; l'affichage
> reste `#108` et la preuve LAB du palier `#109`.

## Le palier qui n'ajoute aucun plan

Les quatre paliers précédents ont appris au produit à agir. Celui-ci lui
apprend à **s'abstenir tout en montrant**, et c'est une capacité distincte :
un utilisateur a des services que Your Cloud n'a pas installés, et le pire
service à représenter est celui qu'on laisse croire géré.

Conséquence structurante : **une déclaration externe ne produit aucun plan.**
Aucune opération n'est ajoutée à aucun schéma, aucune enveloppe n'est signée,
aucun Auxiliaire ne mute quoi que ce soit. Ce que ce palier ajoute est un
inventaire, une lecture et un affichage. Si un jour un élément externe doit
devenir piloté, ce sera une **reprise** — un audit puis un plan approuvé — et
c'est un palier qui n'existe pas encore.

## Ce qu'une déclaration porte, et ce qu'elle ne porte pas

Une déclaration externe est un document strict borné à 4096 octets, aux
champs fermés :

| Champ | Forme | Sens |
|---|---|---|
| `schema_version` | entier, `1` | version du schéma de déclaration |
| `machine_id` | borne des machines | la machine enrôlée depuis laquelle on regarde |
| `label` | 1..64 caractères imprimables ASCII | le nom que l'humain donne à la chose |
| `kind` | `external_service` ou `external_passage` | ce dont l'humain parle |
| `probe_port` | entier, `1..65535` | le port loopback qu'un adaptateur interrogera |

Décisions portées par cette forme :

- **`machine_id` est le point de vue, pas la propriété.** Déclarer un
  élément externe, c'est dire « depuis cette machine enrôlée, on peut le
  regarder ». Cela ne place rien, n'installe rien et n'attribue rien.
- **`probe_port` est un port de loopback, jamais une adresse.** Un
  adaptateur regarde ce que la machine enrôlée voit chez elle ; il ne
  parcourt pas le réseau, ne résout pas de nom et ne joint aucun tiers. Un
  élément externe qui vit ailleurs n'est pas vérifiable par ce palier, et
  l'App le dit plutôt que de le deviner.
- **Il n'y a pas de champ d'image, de version, de digest ni de commande.**
  Le produit n'a rien à épingler sur une chose qu'il n'installe pas ;
  prétendre connaître la version d'un service externe serait exactement le
  mensonge que ce palier existe pour éviter.
- **Un identifiant déjà géré ne peut pas être déclaré externe**, et une
  déclaration externe ne peut pas devenir la cible d'un plan : les deux
  inventaires se refusent l'un l'autre, dans les deux sens, comme les deux
  portes de service du palier `#17`.

## Trois états, et jamais un quatrième déguisé

Le produit distingue par le vocabulaire, pas par la nuance :

```text
déclaré        l'humain l'a dit ; personne ne l'a constaté
vérifié        constaté à telle date, par une lecture qui a réussi
contredit      constaté à telle date, et ce qui répond n'est pas ce qui est déclaré
invérifiable   la lecture n'a pas pu conclure, et la raison est nommée
```

- **Une date accompagne tout constat**, et son ancienneté est un fait
  affiché. Passé un seuil annoncé, un état vérifié devient une **observation
  ancienne** au sens de `CONTEXT.md` : il n'est plus présenté comme actuel.
  Le produit ne remplace jamais une lacune par une continuité supposée.
- **`invérifiable` n'est pas un échec silencieux** : « rien n'écoute sur ce
  port », « la réponse dépasse la borne », « la machine n'est pas joignable »
  sont des phrases différentes, et l'App les rend telles quelles.
- **Aucune inférence.** Ce qui n'est pas constaté n'est pas affirmé : un
  service qui répond prouve qu'*une chose* répond sur ce port, pas qu'elle
  est celle que l'humain a nommée. Le libellé reste la parole de l'humain.

## L'adaptateur : lire, borner, ne jamais écrire

- **Aucun chemin d'écriture par construction.** L'adaptateur n'emprunte pas
  la couture d'effets de l'Auxiliaire ; il ne dispose que d'une lecture
  bornée. Ce n'est pas une discipline de revue mais une propriété du type :
  un code qui ne reçoit pas de quoi écrire ne peut pas écrire.
- **Bornes de lecture** : une connexion au loopback, un délai borné, une
  réponse tronquée à quelques kilo-octets, aucune redirection suivie, aucun
  contenu interprété.
- **Ce qui est lu est inerte.** Les octets d'un tiers ne sont ni du code, ni
  du balisage, ni une instruction : ils sont bornés, échappés, et jamais
  exécutés. La même règle vaut pour le `label` que l'humain a écrit.

## Ce que l'App annonce ne pas pouvoir faire

Pour tout élément externe, l'App affiche explicitement l'absence de ces
quatre capacités, plutôt que d'offrir des commandes qui échoueraient :

```text
mettre à jour    non — aucun plan ne décrit cet élément
restaurer        non — le produit ne détient aucune de ses données
supprimer        non — retirer la déclaration ne retire pas la chose
garantir l'état  non — seule une lecture datée est offerte
```

Retirer une déclaration retire **la déclaration** et rien d'autre : la chose
continue d'exister, et l'App le dit en propres termes au moment du retrait.

## Surface du Controller étendue de trois routes

`PLAN-OCI-CONTROLE.md`, `PROFIL-PUBLIC-BENTOPDF.md`,
`PASSAGE-PRIVE-WIREGUARD.md` puis `PROFIL-PRIVE-VAULTWARDEN.md` ont étendu la
surface métier du Controller d'une, trois, trois puis quatre routes, toutes
constructrices de plans. Le présent contrat l'étend de trois, et d'aucune autre —
et aucune des trois ne construit de plan :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/external-elements` | enregistrer une déclaration externe sur une machine de l'inventaire — libellé, nature, port de sonde —, sans rien installer, sans rien muter et sans produire aucun plan |
| `GET /v0/external-elements` | lire l'inventaire déclaré borné, chaque élément accompagné de son dernier constat daté et de l'ancienneté de ce constat |
| `POST /v0/external-element-withdrawals` | retirer une déclaration nommée, et elle seule |

Décisions attachées à ces routes :

- **Le retrait est un `POST` sur une route distincte, pas un `DELETE`.** Le
  contrat `v0.0.3` ferme la surface métier sur « aucun `DELETE` métier »,
  l'unique `DELETE` du produit invalidant la session courante. Ce palier est le
  dernier endroit où en ouvrir un : un `DELETE` sur `/v0/external-elements/{id}`
  dirait que le produit supprime la ressource qu'il possède, et il ne possède
  rien ici. La route nomme ce qui se passe — un retrait de déclaration — et la
  chose déclarée continue d'exister. La règle du contrat reste donc intacte et
  n'est pas amendée. Le chemin `/v0/external-elements/{id}` n'existe sous aucune
  méthode, et un test le tient.
- **Une déclaration n'a pas d'identifiant choisi par la requête.** Le Controller
  frappe un `element_id` de 16 octets Base64url, comme les autres identifiants
  opaques du produit, et frappe aussi `declared_at`. Une requête qui pourrait
  nommer son identifiant pourrait viser une déclaration qu'elle n'a pas faite ;
  une requête qui pourrait nommer sa date pourrait faire passer un constat
  ancien pour frais.
- Elles empruntent la **même authentification de session** que les routes métier
  existantes : aucun nouveau chemin d'autorité, **aucun nouveau code d'erreur**.
  Une machine hors inventaire reçoit `422 machine_not_active`, un libellé refusé
  `422 label_invalid`, une déclaration qui en répète une autre
  `409 state_conflict`, un `element_id` que personne n'a déclaré
  `404 resource_not_found` — tous dans la liste fermée existante.
- **L'inventaire déclaré est durable et tenu dans son propre document**, à côté
  de l'inventaire géré et jamais dedans : la révision de l'inventaire géré est ce
  contre quoi une App cache ses machines, et une déclaration n'a pas à la
  déplacer. Il porte sa propre révision, est borné à 128 déclarations et refuse
  de s'ouvrir sur un document corrompu plutôt que de fabriquer un inventaire vide
  qui effacerait en silence ce qu'un humain a saisi.
- **Le libellé n'emprunte pas le profil des libellés gérés.** Un libellé géré
  nomme une chose que le produit possède, il est donc normalisé et tenu à une
  liste positive Unicode. Celui-ci est la parole de l'humain sur une chose que le
  produit ne possède pas : le contrat le ferme sur des octets — 1 à 64
  caractères ASCII imprimables — et il est conservé exactement tel quel, sans
  rognage ni normalisation. Son inertie est obtenue là où il s'affiche, borné et
  échappé, jamais en le corrigeant à l'entrée.
- **Aucune capacité n'est projetée.** Les quatre absences annoncées — mettre à
  jour, restaurer, supprimer, garantir l'état — sont des propriétés de ce qu'est
  un élément externe, identiques pour toutes les lignes, et il n'existe aucun
  état où elles diffèrent. Les projeter suggérerait qu'un Controller pourrait un
  jour répondre autrement, et une App qui les lirait au lieu de les savoir
  offrirait une action de gestion le jour où un Controller compromis dirait oui.
  L'App les annonce depuis le contexte de la route, comme toute phrase
  destinée à l'humain.

## Le seuil d'ancienneté : celui qui existe déjà, et pas un second

`CONTEXT.md` définit une **observation ancienne** comme un dernier état « dont
l'âge dépasse la limite annoncée ». Le produit annonce **une** limite, fixée par
`CONTRAT-V0.0.3` pour la chaîne d'observation : `recent` jusqu'à **90 secondes
incluses**, `old` au-delà. Ce palier la **reprend telle quelle** pour les
constats externes plutôt que d'en inventer une seconde, et le code ne la porte
plus qu'une fois, sous un nom partagé par les deux projections.

La justification est un écran, pas une horloge : les machines gérées et les
éléments externes s'affichent côte à côte, et deux seuils différents mettraient
deux sens du mot « ancien » sur la même page, sans que le lecteur sache lequel
parle. Ce que le seuil coûte est nommé plutôt que caché : un adaptateur qui
lirait moins souvent que toutes les 90 secondes rendrait chaque élément externe
`old` en permanence. `#107` reçoit donc cette contrainte de cadence explicite —
lire au moins aussi souvent, ou assumer qu'un constat vérifié ne soit jamais
présenté comme actuel.

L'ancienneté est une **dimension séparée de l'état**, comme l'enrôlement est
séparé de la fraîcheur du côté géré. Un constat `vérifié` dépassé continue de
dire `vérifié` et cesse de dire `recent` : c'est exactement « l'état n'est plus
présenté comme actuel », sans inventer un quatrième état pour le dire. Un constat
que le Controller ne sait pas placer avant l'instant courant est `old` : un âge
qu'on ne peut pas calculer n'est jamais une raison d'appeler une chose actuelle.

## Ce que le refus croisé décide ici, et ce qu'il ne peut pas décider

Les deux inventaires se refusent l'un l'autre dans les deux sens, mais tout ce
refus n'est pas décidable au même endroit. Ce que le Controller **décide
réellement** :

- **Aucun plan ne peut viser une déclaration.** C'est un refus par construction
  et non une comparaison qu'il faut penser à écrire : `element_id` n'est un champ
  d'aucun schéma de plan, donc une requête qui le porte est refusée par le
  décodage strict avant que sa valeur soit lue. Symétriquement, une déclaration
  n'a ni opération, ni profil, ni image, ni document à geler : il n'y a rien dans
  son schéma qui décrive un acte. Un test tient les deux directions, et un
  troisième tient la propriété par les imports : les deux fichiers de
  l'inventaire déclaré ne reçoivent pas de quoi construire un plan.
- **Une déclaration doit nommer une machine de l'inventaire géré.** C'est une
  exigence et non un refus : la machine est le point de vue, et une déclaration
  visant une machine que le produit n'a jamais enrôlée décrit un point de vue que
  personne ne détient.
- **Le couple machine et port de sonde est unique.** Deux libellés ou deux
  natures n'en font pas deux choses ; le même port vu depuis une autre machine
  en fait bien deux, parce que la machine est le point de vue.

Ce que le Controller **ne peut pas décider, et ne feint pas de décider** :
qu'un port déclaré externe soit déjà celui d'un **service géré de cette
machine**. Le Controller connaît les machines, pas leurs fiches : il gèle des
octets de plan et n'en conserve aucun, aucun registre d'état appliqué n'existe de
ce côté, et le port de loopback qu'un service géré occupe n'est écrit nulle part
dans son état. Écrire ici une comparaison partielle qui aurait l'air totale
serait pire que ne rien écrire. Ce refus appartient donc à la machine : c'est
l'Auxiliaire qui connaît son propre état appliqué, et c'est l'adaptateur de
`#107`, qui lit sur place, qui peut constater qu'un port déclaré externe répond
en réalité pour un service que le produit a posé. Tant que ce constat n'existe
pas, l'App dit ce qu'elle sait et rien de plus.

## Une huitième vue, nommée ici et non ailleurs

`CONTRAT-V0.0.3.md` dit que **le premier** frontend comporte exactement sept
vues, et cette phrase reste vraie : elle décrit un incrément clos et prouvé.
Le présent palier en ajoute une huitième, et il la nomme ici pour la même
raison que les contrats précédents nomment les routes qu'ils ajoutent — un
incrément qui réécrirait le contrat d'un autre effacerait ce que celui-ci
avait prouvé.

| Vue | Ce qu'elle montre |
|---|---|
| `Éléments externes` | l'inventaire déclaré, chaque élément avec son dernier constat daté, son ancienneté et les quatre capacités que l'App annonce ne pas avoir |

Elle obéit à tout ce que les sept autres doivent : les deux tailles de
fenêtre, le texte agrandi au double, le reflow sans coupe ni défilement
horizontal imposé, la navigation au clavier et un focus visible. Elle n'est
pas une page de plus au sens du contrat d'origine — ses variantes vides,
chargées, refusées et hostiles restent des états d'elle-même.

Ce qu'elle n'a pas, et qui la distingue des sept : aucune action de gestion.
La navigation y mène, la lecture s'y arrête.

## Ce que la preuve devra constater

1. un service posé à la main, qu'aucun plan ne décrit, est déclaré externe :
   rien n'est installé, aucun plan n'est constructible pour lui ;
2. la lecture le rend `vérifié` avec sa date ; le service arrêté à la main,
   la lecture suivante rend `contredit` — et jamais l'inverse par défaut ;
3. le temps passé sur un constat est affiché ; au-delà du seuil, l'état
   cesse d'être présenté comme actuel ;
4. un voisin jamais déclaré reste inconnu : rien ne le découvre, rien ne le
   nomme, aucun scan n'a lieu ;
5. un libellé hostile — balisage, séquence d'échappement, taille excessive —
   reste une donnée inerte partout où il apparaît ;
6. aucune action de gestion n'est offerte pour un élément externe, et la
   déclaration retirée laisse le service intact, que le harnais retire
   lui-même comme son propre acte.

## Additif `#107` : par où la lecture voyage

`#106` a laissé une dette nommée : `RecordObservation` existe, aucune route ne
la sert, et le trajet par lequel la lecture d'une machine atteint le Controller
appartenait à ce palier. Il est tranché ici.

### La chaîne d'observation, pas un second chemin de remontée

**La lecture voyage par la chaîne que le produit possède déjà** : le Daemon
relève, le Relay transporte, le Controller lit et enregistre. Aucune autorité
n'est ajoutée, aucun port n'est ouvert, aucun certificat n'est émis.

Les raisons de ce choix, et ce qu'il refuse :

- **L'adaptateur lit sur la machine enrôlée**, dit le contrat. Le Daemon est
  déjà le processus permanent, non privilégié, qui observe sur place et rapporte
  vers l'extérieur sans connaître le Controller. Inventer un second rapporteur
  aurait dupliqué une identité, un transport mTLS, un enrôlement et un tampon
  pour transporter deux entiers par port.
- **Une lecture ponctuelle empruntant le chemin de l'Auxiliaire est refusée.**
  L'Auxiliaire est une commande forcée, root, à approbation signée et à séquence
  anti-rejeu consommée : ce palier n'ajoute ni plan, ni approbation, ni séquence,
  ni mutation. Et la cadence à elle seule l'écarte — une approbation humaine
  toutes les 90 secondes n'est pas une cadence, c'est un renoncement.
- **Les règles d'autorité de la chaîne ne bougent pas.** Le Daemon ne connaît
  toujours que son Relay ; le Relay ne transporte toujours aucun ordre, dans
  aucun sens ; le Controller lit toujours. Rien ne descend vers une machine.

### Le profil d'observation : comment la machine sait quoi regarder

Le Daemon ignore l'inventaire déclaré du Controller, et rien ne peut le lui
apprendre sans créer le chemin descendant que le produit refuse. La liste vient
donc **de la machine** : un document root-owned et borné,
`/etc/your-cloud/external-targets.json`, relu à chaque collecte, qui ne porte
que sa version de schéma, l'identité de sa machine et des ports de loopback.

C'est exactement la forme du registre d'enrôlement : la machine dit ce qui peut
être regardé, l'humain dit ce que cela signifie, et **aucune des deux moitiés ne
peut écrire l'autre**. Un document nommant une autre machine est refusé — le
Controller identifie une déclaration par le couple machine et port, donc un point
de vue déplaçable par copie de fichier ne serait pas un point de vue. Le document
ne porte ni adresse, ni libellé, ni identifiant, ni chemin, ni commande : le
provisionner n'accorde rien de plus que d'être lu.

La jointure est faite par le Controller, et elle est possible sans rien
inventer : la machine rapporte un port, et le couple machine et port est
précisément ce sur quoi une déclaration est unique.

### Ce que l'enveloppe porte en plus, et ce qu'elle ne renomme pas

Les lectures voyagent dans l'enveloppe d'observation existante, sous une section
`external` **absente par défaut**. Une machine dont la fiche ne nomme aucune
cible émet octet pour octet le message que `v0.0.2` a prouvé.

`profile` continue de nommer l'ensemble fixe des trois collecteurs de `health`,
parce que c'est ce qu'il a toujours nommé. Une lecture externe n'est pas un
quatrième collecteur : elle ne porte ni valeur, ni santé, ni contenu — seulement
ce qu'une connexion à un port déclaré a fait. Chaque lecture est deux champs, le
port et l'un de quatre mots fermés ; la section est bornée à seize entrées,
triée et unique par port.

### L'incapacité d'écrire, par construction

L'adaptateur reçoit **une fonction, qui prend un port et rend un `io.ReadCloser`**.
Pas d'adresse, pas de schéma, pas de chemin, pas de couture d'effets, pas de
magasin. L'interface rendue expose `Read` et `Close` : l'adaptateur ne peut pas
même envoyer un octet à ce qu'il lit.

Trois preuves le tiennent, et ce sont des tests :

1. `probe.go` importe **exactement** `context`, `errors` et `io` — une liste
   positive, pas une liste d'interdits ;
2. la couture rend un `io.ReadCloser` dont l'ensemble de méthodes est exactement
   `Read` et `Close`, et un `Adapter` ne porte qu'un seul champ ;
3. aucun fichier du paquet n'importe `os/exec`, `net/http`, `crypto/tls`,
   `syscall`, `internal/plan`, `internal/approval`, `internal/auxiliary` ni
   `internal/controller` ; seul le fichier qui relie le paquet à une machine peut
   nommer `os`, `net` ou `internal/securefile`.

L'absence de `net/http` est ce qui rend « aucune redirection suivie » et « aucune
décision de confiance TLS » vraies par construction : il n'existe ici aucun
client qui pourrait suivre ou décider quoi que ce soit. Le reste des bornes est
au même endroit : `127.0.0.1` est une constante de la liaison, la connexion et la
lecture ont chacune leur délai, la réponse est comptée puis jetée dans
`io.Discard` au-delà de quatre kilo-octets.

### Ce que `contredit` veut dire ici, exactement

> **contredit** : un port qu'une lecture datée avait trouvé répondant n'accepte
> plus aucune connexion. La machine contredit ce que la déclaration dit s'y
> trouver.

Et rien d'autre. Ce n'est jamais une comparaison de contenu — aucun profil ne
décrit le contenu d'une chose externe, donc rien ici ne pourrait en comparer un.
Ce n'est jamais la première réponse au sujet d'un élément : personne n'a vu ce
port répondre, il n'y a donc rien à contredire, et la lecture dit
`invérifiable` avec `nothing_listening`. Une fois établi, `contredit` tient
jusqu'à une lecture qui vérifie de nouveau : un élément dont rien ne change ne
doit pas osciller entre deux mots.

### La collision géré/externe : la machine tranche, et le dit

Le contrat laissait ce refus à la machine, parce que le Controller connaît les
machines et non leurs fiches. La machine y répond par un constat, non par une
comparaison à un registre : **le noyau écrit qui détient une socket en écoute**,
et la table des comptes dit à qui appartient cet identifiant. Un compte de ce
produit porte le préfixe du produit — les fiches le disent déjà, et ce préfixe
existe précisément pour qu'un nom de rôle n'adopte jamais un groupe système
générique.

Un port déclaré externe que ce produit détient est **lu comme
`invérifiable`, motif `port_is_managed`**, et n'est jamais connecté du tout : la
lecture qui aurait suivi n'aurait pu dire que « quelque chose répond », c'est-à-
dire exactement la phrase qui ferait passer un service géré pour un service
externe.

C'est une **extension nommée** de la liste fermée de `#105`, et les deux autres
réponses possibles sont refusées :

- refuser la lecture laisserait l'élément affiché `déclaré`, c'est-à-dire
  silencieusement présenté comme externe : le contraire du but ;
- un quatrième état romprait la règle « trois états, et jamais un quatrième
  déguisé ».

La déclaration n'est pas retirée pour autant : retirer est un acte humain, jamais
celui d'un Controller. Une machine qui ne peut pas lire sa propre table de
comptes ne rapporte aucune lecture du tout, plutôt que d'en rapporter en
supposant qu'aucun port n'est géré.

`machine_unreachable` garde le troisième motif honnête : un instantané que le
Controller a bien lu, dans lequel la machine ne porte aucune observation, dit à
un élément **déjà lu une fois** que le point de vue qu'il nomme a cessé de
répondre. Un élément que personne n'a jamais lu reste `déclaré` : « pas encore
provisionné » n'est pas « injoignable ».

### La cadence, et où elle est tenue

Le Collector relève toutes les **30 secondes**, soit trois fois à l'intérieur de
la limite de 90 secondes que le produit annonce. La contrainte que `#105` posait
à ce palier — lire au moins aussi souvent, ou assumer qu'un constat vérifié ne
soit jamais présenté comme actuel — est donc **tenue**, et elle l'est par la
cadence qui existait déjà.

L'enregistrement, lui, se fait à la lecture : `GET /v0/external-elements`
absorbe l'instantané du Relay avant de projeter, par la même lecture bornée que
`GET /v0/machines` fait déjà, avec son cache et son backoff. Cela ne déplace pas
l'âge affiché : un constat porte **la date de collecte de la machine**, pas celle
du rafraîchissement qui l'a rapportée. Absorber deux fois le même instantané ne
change rien, ne déplace aucune révision et ne réécrit aucun fichier. Un Relay que
le Controller ne peut pas lire est sa propre panne et jamais un fait sur une
machine : rien n'est enregistré, et les derniers constats vieillissent
honnêtement.

### Ce que cet additif n'ajoute pas

Aucune route n'est ajoutée à la surface du Controller : les trois de `#105`
restent les trois. Aucun `DELETE` n'apparaît. Le Relay n'expose ni route, ni
champ, ni réponse nouvelle vers un Daemon. Aucune découverte n'existe nulle part :
un voisin que personne n'a déclaré reste inconnu, parce qu'il n'y a ni balayage,
ni plage, ni résolution de nom dans aucun de ces chemins.

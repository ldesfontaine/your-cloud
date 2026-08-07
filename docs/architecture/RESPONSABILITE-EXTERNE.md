# Responsabilité externe : représenter sans posséder

> Statut : contrat d'architecture validé (`#105`) pour le palier `#18`.
> Il fixe ce qu'une déclaration externe porte, ce qu'un adaptateur en lecture
> seule a le droit de faire, la distinction entre ce qui est déclaré et ce qui
> est vérifié, et la liste de ce que l'App annonce ne pas pouvoir faire.
> L'implémentation le suit depuis `#106` (l'inventaire déclaré du Controller, sa
> surface et son seuil d'ancienneté) ; l'adaptateur en lecture seule reste
> `#107`, l'affichage `#108` et la preuve LAB du palier `#109`.

## Le palier qui n'ajoute aucun plan

Les quatre paliers précédents ont appris au produit à agir. Celui-ci lui
apprend à **s'abstenir tout en montrant**, et c'est une capacité distincte :
un utilisateur a des services que Your Cloud n'a pas installés, et le pire
service à représenter est celui qu'on laisse croire géré.

Conséquence structurante : **une déclaration externe ne produit aucun plan.**
Aucune opération n'est ajoutée à aucun schéma, aucune enveloppe n'est signée,
aucun Auxiliaire ne mute quoi que ce soit. Ce que ce palier ajoute est un
inventaire, une lecture et un affichage. Si un jour un élément externe doit
devenir géré, ce sera une **adoption** — un audit puis un plan approuvé — et
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

Pour tout élément externe, la Console affiche explicitement l'absence de ces
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
  contre quoi une Console cache ses machines, et une déclaration n'a pas à la
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
  jour répondre autrement, et une Console qui les lirait au lieu de les savoir
  offrirait une action de gestion le jour où un Controller compromis dirait oui.
  La Console les annonce depuis le contexte de la route, comme toute phrase
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

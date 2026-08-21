# Passage privé WireGuard borné au service

> Statut : proposition de contrat pour le palier `#16`, suivie par `#93`, dont
> l'application est portée par `#96` (cycle de vie WireGuard) et `#97` (bornes
> `nftables`, règle de présence et matrice des refus).
> Il étend le contrat du plan aux opérations de lien entre deux machines
> enrôlées, fixe le sort des clés, les constantes du scénario de référence et
> les règles qui bornent le passage au seul service approuvé. Rien ici n'est
> implémenté tant que ce contrat n'est pas validé.

## Ce que ce passage est, et n'est pas

Le passage privé du scénario de référence relie le VPS public à la machine du
LAN **sans ouverture entrante vers le LAN** : la machine du LAN initie le
tunnel vers le VPS, et le seul flux applicatif autorisé va du VPS vers le
service approuvé du LAN. WireGuard, ce VPS et cette topologie sont le
scénario LAB qui rend la preuve reproductible — jamais un prérequis produit.
Une infrastructure peut employer un autre placement, garder son passage en
sous sa propre autorité, ou ne rien publier de privé.

## Deux machines, quatre plans, aucune clé en voyage

Un passage est établi par **quatre plans, chacun ciblant une seule machine**,
dans un ordre que le Controller séquence et que chaque Auxiliaire revérifie :

```text
1. prepare_link (écouteur, VPS)     génère les clés, crée l'interface fermée
2. prepare_link (initiateur, LAN)   idem, aucun port n'écoute
3. attach_link_peer (écouteur)      joint le pair LAN, pose les bornes
4. join_link_peer (initiateur)      joint le pair VPS, pose les bornes
```

- **Les clés privées naissent sur leur machine et n'en sortent jamais** :
  générées par l'Auxiliaire, root-owned en `0600` sous
  `/etc/your-cloud/link/`, absentes de tout rapport, plan ou journal.
- **Seule la clé publique voyage** : le rapport de `prepare_link` la porte,
  le Controller la lit comme une observation, et elle entre — lisible — dans
  le plan de jonction de l'autre machine. L'humain approuve donc un plan qui
  nomme exactement le pair qu'il accepte.
- La jonction avant préparation est refusée sur la machine (pas de clé, pas
  d'interface) ; la préparation est idempotente et **ne régénère jamais** une
  clé existante — remplacer une clé est un retrait puis une préparation,
  deux plans visibles.

## Opérations du schéma 3

Le schéma `3` conserve tout le procédé (document strict borné à 4096 octets,
transcript à domaine séparé `your-cloud/oci-plan.v3\0`, rollback comme
document complet inverse, même chaîne gel → signature → revérification) et
ajoute six opérations en trois paires inverses :

| Opération | Champs propres (au-delà de la tête commune) |
|---|---|
| `prepare_link` / `withdraw_link` | `link_role` |
| `attach_link_peer` / `detach_link_peer` | `peer_public_key`, `service_port` |
| `join_link_peer` / `leave_link_peer` | `peer_public_key`, `peer_endpoint_host`, `service_port` |

Décisions portées par cette forme :

- **`link_role` est une liste fermée à deux entrées** : `listener` (le VPS,
  qui écoute sur le port du contrat) et `initiator` (le LAN, qui sort et
  maintient le tunnel). Le rôle décide des constantes ; aucun champ ne les
  rouvre.
- **L'asymétrie est dans les opérations, pas dans des champs optionnels** :
  l'écouteur n'a pas d'endpoint à joindre, donc `attach_link_peer` n'a pas le
  champ — un champ vide n'existe pas, un champ d'un autre groupe est un champ
  inconnu, refusé avant lecture.
- **`peer_public_key`** : base64 standard canonique de 44 caractères décodant
  exactement 32 octets (le ré-encodage doit reproduire la chaîne).
- **`peer_endpoint_host`** reprend la borne de `route_host` (minuscules,
  chiffres, tirets, points, 3..253, premier et dernier alphanumériques) — un
  littéral IPv4 s'y écrit naturellement. Le port d'endpoint n'est pas un
  champ : c'est le port d'écoute du contrat.
- **`service_port`** (1024..65535) est le seul port que les règles
  autoriseront à travers le tunnel. Sur la machine du service, il doit nommer
  le port loopback d'un service géré présent — même règle de présence que la
  route du palier `#15`. Changer de pair, d'endpoint ou de port est un
  nouveau plan ; rien ne se modifie en place.
- **Les rollbacks sont les inverses exacts** : `withdraw_link` pour
  `prepare_link`, `detach_link_peer` pour `attach_link_peer`,
  `leave_link_peer` pour `join_link_peer`.

## Constantes du scénario de référence

```text
sous-réseau du lien   10.66.66.0/24 — réservé ; la garde labctl refuse déjà
                      de muter une machine portant 10.66.66.1
écouteur              10.66.66.1/32
initiateur            10.66.66.2/32
interface             yc-link0 (les noms d'interface sont bornés à 15 octets)
port d'écoute (UDP)   51820, sur l'écouteur seulement
keepalive             25 s, sur l'initiateur seulement (il traverse le NAT)
clés                  /etc/your-cloud/link/, root-owned, privée en 0600
```

Aucune de ces valeurs n'est un champ de plan. `AllowedIPs` est le `/32` du
pair et rien d'autre : le sous-réseau du LAN n'est jamais annoncé, jamais
routé, et le VPS ne connaît du LAN qu'une adresse de tunnel.

Le mode de la clé privée est précisé par l'addendum d'application en fin de
document : `0600` y devient `0640` root et `systemd-network`, et la raison de
cet écart y est nommée plutôt que tue.

## Le passage est borné par nftables, des deux côtés

Une table nommée `inet your-cloud-link` est posée par la jonction et retirée
avec elle. Ses règles ne portent que des constantes du contrat et les valeurs
du plan approuvé :

- **Écouteur (VPS)** : en entrée publique, seul l'UDP du port d'écoute est
  accepté pour le tunnel — il rejoint 443 et la redirection 80 dans la liste
  fermée de ce que le VPS écoute. Sur `yc-link0` : en sortie, uniquement TCP
  vers `10.66.66.2` sur le `service_port` approuvé ; en entrée, uniquement
  les réponses des connexions établies. Aucun forward. SSH, tout autre port
  et tout autre destinataire sont refusés par défaut.
- **Initiateur (LAN)** : aucun port entrant depuis Internet, le tunnel sort.
  Sur `yc-link0` : en entrée, uniquement TCP depuis `10.66.66.1` vers le
  `service_port` ; en sortie, uniquement les réponses établies. Aucun
  forward, aucun accès au reste du LAN par le tunnel — la machine du LAN ne
  relaie rien.
- La dérive des règles est un changement réappliqué par un nouveau plan,
  jamais une réparation silencieuse ; retirer la jonction retire la table et
  rien d'autre ; retirer le lien (`withdraw_link`) pendant qu'une jonction
  existe est refusé en la nommant — l'ordre du retrait est une affaire de
  séquence de plans, comme au palier `#15`.

## Surface du Controller étendue de trois routes

`PROFIL-PUBLIC-BENTOPDF.md` avait étendu la surface métier du Controller de
trois routes. Le présent contrat l'étend de trois, et d'aucune autre :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/link-plans` | construire et geler la paire plan/rollback du côté propre d'une machine de l'inventaire — son rôle et rien d'autre —, sans muter aucune machine |
| `POST /v0/listener-peer-plans` | construire et geler la paire plan/rollback de la jonction de l'écouteur, sans muter aucune machine |
| `POST /v0/initiator-peer-plans` | construire et geler la paire plan/rollback de la jonction de l'initiateur, sans muter aucune machine |

Décisions attachées à ces routes :

- **Trois routes sœurs plutôt qu'une route à discriminant**, pour la raison déjà
  retenue au palier précédent : une route unique portant un rôle et une phase
  aurait exigé un schéma de requête déclarant les champs des trois groupes, donc
  une lecture avant refus. Séparées, chaque requête est une liste fermée, et un
  champ d'un autre groupe est refusé par le décodage strict avant que sa valeur
  soit lue.
- **L'asymétrie est dans les routes comme elle est dans les opérations.**
  L'écouteur n'a pas d'endpoint à joindre : la route qui construit sa jonction
  n'a pas le champ — ni vide, ni conditionné par un rôle qu'il faudrait lire.
- Elles empruntent la **même authentification de session** que les routes métier
  existantes : aucun nouveau chemin d'autorité, aucun nouveau code d'erreur. Une
  machine hors inventaire reçoit `422 machine_not_active`, dans la liste fermée
  existante.
- Les deux documents voyagent comme **chaînes JSON portant leurs octets
  canoniques exacts**, accompagnés de leurs digests, dans la même vue que les
  routes du profil public ; son `schema_version` vaut `3` et dit sous quel
  contrat les deux documents ont été écrits.
- L'App ne choisit **ni l'infrastructure, ni le sous-réseau, ni les adresses
  du tunnel, ni le nom d'interface, ni le port d'écoute, ni le keepalive** :
  l'infrastructure est celle dont ce Controller est l'autorité, et le reste est
  une constante que le rôle décide. Aucune de ces valeurs n'est un champ, donc
  aucune requête ne peut élargir le passage.
- **La clé publique du pair est la seule valeur que personne n'a choisie** :
  c'est une observation que la préparation de l'autre machine a rapportée. La
  App la porte dans la requête, et elle est tenue exactement par la
  validation du document — 44 caractères de base64 standard canonique décodant 32
  octets, ré-encodage identique. Une clé que la route accepterait et que le
  paquet `plan` refuserait serait un refus arrivé une couche trop tard.
- Aucune de ces routes ne **génère ni ne transporte de clé privée** : une clé
  privée naît sur sa machine et n'en sort jamais, donc rien ici ne pourrait en
  porter une.

`peer_endpoint_host` se lit exactement comme `route_host` du palier précédent :
minuscules, chiffres, tirets et points ; 3 à 253 caractères ; premier et dernier
caractère lettre ou chiffre ; aucun label vide. Un littéral IPv4 s'y écrit
naturellement ; un littéral IPv6 n'appartient pas au jeu de caractères et n'a
donc pas de refus propre.

## Ce que la preuve devra constater

Le service de référence joint par le tunnel est un **service géré d'un
profil** — celui du palier `#15`, déployé sur la machine du LAN par le chemin
déjà prouvé. La première rédaction de ce contrat nommait la sonde du palier
`#14`, et la première preuve machine a montré que c'était la mauvaise
lecture : la règle de présence lit les profils de service, et la sonde n'en
est pas un — c'est un instrument de validation jetable, et un passage qui se
bornerait à un instrument serait un passage bordé à rien de durable. La
sonde sert au contraire de **cas négatif** : déployée à côté, elle prouve
qu'un port qu'aucun profil ne publie est refusé. Le passage borne un service
géré existant, il n'en invente pas. Chaque critère de `#16` correspond à un
constat :

1. rien n'existe avant l'approbation : ni pair, ni route, ni règle, ni clé ;
2. après les quatre plans : le tunnel est établi, et depuis le VPS le
   `service_port` de `10.66.66.2` répond ;
3. depuis le VPS, par le tunnel : SSH refusé, tout autre port refusé, toute
   adresse du sous-réseau LAN réel refusée — seul le couple approuvé passe ;
4. depuis la machine hostile (le pilote ou `lab-app`) : la machine du
   LAN n'expose **aucun** port entrant ; le VPS n'expose que 443, 80 et
   l'UDP du tunnel ;
5. idempotence : rejouer les quatre plans rend `changed=false` sans
   rétablissement ni régénération de clé ;
6. modification = nouveau plan : un pair, un endpoint ou un port différent
   n'est jamais une mutation en place ;
7. redémarrage des deux machines : le tunnel revient sans action et les
   règles avec lui ; révocation (`detach`/`leave`) : le flux cesse, l'état
   est vérifiable ; retrait complet : interfaces, clés et tables absentes ;
8. le rapport qualifie la topologie de scénario de référence, pas de
   prérequis produit, et le démontage rend les machines à leur état de
   clôture nommé.

## Addendum d'application : ce que l'Auxiliaire écrit vraiment (`#96`)

Le contrat ci-dessus dit quel état une machine doit tenir. Cet addendum dit par
quel mécanisme elle le tient, parce que trois décisions d'application ne se
déduisent pas du contrat et qu'une d'elles s'en écarte.

**Le mécanisme est `systemd-networkd`, deux fichiers par machine.** Une
`yc-link0.netdev` déclare l'interface fermée et nomme la clé **par son chemin**
(`PrivateKeyFile=`) ; une `yc-link0.network` porte l'adresse `/32` du rôle. La
règle du contrat sur les clés décide ce choix à elle seule : une configuration
`wg-quick` porte la clé privée *à l'intérieur* du fichier, donc une machine qui
en tient une tient sa clé deux fois, à deux endroits et sous deux modes. Le
`.netdev` la nomme, il ne la contient pas. La persistance au redémarrage ne
coûte alors rien de plus : networkd recrée l'interface depuis ces deux fichiers
au démarrage, ce qui est exactement le critère 7.

**La clé privée est en `0640`, root et `systemd-network`, et non en `0600`.**
C'est le seul écart de cette implémentation au texte ci-dessus, et il est
arithmétique : `systemd-networkd` tourne sous un compte non privilégié, donc une
clé que seul root peut lire est un passage qui ne monte jamais. `0640` avec le
groupe de ce compte est l'arrangement le plus étroit qui laisse lire exactement
une identité de plus — celle à qui ce produit a demandé de tenir l'interface.
Aucun compte humain, aucun compte de service de ce produit et aucun conteneur
n'est dans ce groupe. Une machine sans ce groupe garde `0600` : rien n'y est
élargi en silence, l'interface ne monte pas et la préparation le dit.

**Une jonction écrit aussi une route, et c'est le `/32` qui l'impose.** Les deux
adresses du tunnel sont des `/32`, donc aucune d'elles ne donne à sa machine de
route vers l'autre : sans une ligne `[Route]` nommant l'adresse du pair sur
cette interface, le tunnel serait établi et inutilisable. La destination est
l'adresse du rôle opposé — une constante, jamais une valeur de plan — donc la
route atteint exactement ce que `AllowedIPs` autorise et pas une adresse de
plus. Elle est écrite avec la jonction et retirée avec elle.

**Ce que le retrait ne défait pas est nommé.** `withdraw_link` retire
l'interface, les deux fichiers et la clé. Il ne désactive pas le gestionnaire de
réseau : networkd ne gère que les interfaces que ses propres `[Match]`
désignent, et couper le gestionnaire de réseau d'une machine comme effet de bord
du retrait d'un tunnel est une liberté que ce produit ne prend pas.

**Découpage entre `#96` et `#97`.** `#96` tient le cycle de vie WireGuard :
clés, interface, pairs, idempotence, rollback, refus. Les tables `nftables`, la
règle de présence du `service_port` et la matrice complète des refus du palier
sont `#97`, et les points de couture sont nommés dans le flux des jonctions —
les règles se posent avant que le pair existe et se retirent avec lui.

## Addendum d'application : comment les bornes tiennent vraiment (`#97`)

Le contrat dit ce que le passage a le droit de porter. Cet addendum dit par quel
mécanisme la machine le tient, parce que cinq décisions d'application ne se
déduisent pas du texte ci-dessus et qu'une d'elles ajoute une relaxation d'hôte
qu'il faut nommer.

**Une table nommée, posée par la jonction, appliquée en même temps qu'écrite.**
Chaque jonction écrit `/etc/your-cloud/link/rules.nft`, root-owned comme la clé,
et le charge dans le noyau dans le même effet — un fichier seul ne bornerait
qu'au prochain démarrage, une table seule disparaîtrait à ce démarrage. Le
fichier s'ouvre sur `add table` / `delete table` / définition complète : ajouter
ne fait rien quand la table est déjà là, ce qui garantit que la suppression
réussit, et la définition réécrit tout. Recharger deux fois vaut recharger une
fois, et une dérive est réappliquée entière plutôt que cumulée. Le retrait
supprime **la table par son nom** puis le fichier : le pare-feu qu'une machine
tient par ailleurs n'est jamais nommé, donc jamais touché.

**Cette table ne peut qu'enlever, jamais donner.** Ses chaînes de base ont une
politique `accept` et ne coupent que ce qui entre ou sort par `yc-link0`. Ce
n'est pas une facilité d'écriture : deux tables au même hook se traversent
toutes les deux, donc une politique `drop` ici déciderait pour tout le reste de
la machine — SSH compris — et un `accept` ici n'ouvre rien que la machine ne
faisait déjà. Une conséquence est écrite dans le fichier et tenue par un test :
**aucune règle sans portée d'interface**, sauf une. Cette exception est
l'`accept` de l'UDP `51820` de l'écouteur ; elle ne donne aucun droit et elle
existe pour que le seul port public que le passage ajoute à cette machine se
lise dans le jeu de règles de la machine, à côté du reste du passage, plutôt que
de se déduire d'une socket. Ce produit ne tient aucun pare-feu d'hôte, et cette
table n'en est pas un.

**Une redirection sur l'initiateur, et pourquoi elle est le moindre
élargissement.** Un service géré publie sur `127.0.0.1` et sur rien d'autre :
c'est une constante des fiches de service, et c'est elle qui est portante. Le
trafic du tunnel arrive pourtant sur `10.66.66.2`, où rien n'écoute. Deux
réponses étaient possibles : faire écouter les services sur l'adresse du tunnel,
ce qui élargirait **chaque** fiche de service au bénéfice d'un seul lien ; ou
rediriger, sur la seule machine concernée et pour le seul port approuvé. C'est
la seconde qui est retenue. La table de l'initiateur porte donc une chaîne
`nat prerouting` qui envoie `iif yc-link0`, `saddr 10.66.66.1`, `tcp dport
service_port` vers `127.0.0.1:service_port`, et rien d'autre.

Le noyau refuse de router vers une adresse de loopback depuis une interface
réelle tant qu'on ne le lui permet pas, donc cette redirection exige
`net.ipv4.conf.yc-link0.route_localnet=1`. Le réglage est **porté par
l'interface du passage et jamais par `all`** : toutes les autres interfaces de
la machine, celle du LAN en premier, continuent de refuser une destination
loopback. Il est écrit dans `/etc/sysctl.d/your-cloud-link.conf`, posé avec la
jonction et retiré avec elle, exactement comme la politique de ports de l'entrée
publique — même forme, même discipline, même retrait qui remet la valeur par
défaut par son nom.

**Le résidu est nommé plutôt que tu.** `route_localnet` sur `yc-link0` autorise
le pair du tunnel à atteindre le `127.0.0.1` de la machine du LAN — **sur le
seul port redirigé**. Deux couches indépendantes le tiennent, et aucune ne
couvre pour l'autre : la redirection choisit la destination et ne redirige que
le port approuvé, donc tout autre port garde une destination où rien ne répond ;
et la chaîne de filtrage, séparément, n'accepte que `tcp dport service_port`
depuis `10.66.66.1` et jette le reste. Les deux sont éprouvées séparément.

**La persistance au redémarrage est une unité oneshot déclarée par le plan.**
Ni la table ni le réglage ne survivent seuls à un redémarrage, et le mécanisme
habituel ne suffit pas ici : `/etc/sysctl.d` est lu par `systemd-sysctl` bien
avant qu'un gestionnaire de réseau ait créé l'interface, donc une ligne portée
par `yc-link0` s'y appliquerait à rien. Une unité `your-cloud-link-rules.service`
— `Type=oneshot`, ordonnée après `systemd-networkd` — applique les deux
fichiers, dans l'ordre où la jonction les a appliqués. Elle est écrite et activée
par la jonction et retirée par le départ : c'est un effet déclaré du plan, comme
la politique d'hôte de l'entrée, et non une étape d'amorçage. C'est ce qui rend
le critère 7 vrai des règles et pas seulement du tunnel.

**Les bornes se posent avant le pair et se retirent après lui.** L'ordre est
l'argument entier : à l'aller, la relaxation puis la table puis l'unité, et
seulement ensuite le pair — pendant toute cette suite l'interface n'a aucun pair,
donc le passage ne porte rien. Au retour, l'inverse exact : le pair d'abord, puis
l'unité, la table et la relaxation. Retirer les bornes en premier laisserait un
pair que rien ne borne pendant la durée du détachement, ce qui est le seul état
qu'aucune des deux opérations n'a le droit de traverser ; les retirer en dernier
ne coupe qu'un flux établi vers un pair déjà injoignable.

**La règle de présence est asymétrique, et c'est voulu.** Sur la machine du
service — l'initiateur du scénario de référence — le `service_port` doit nommer
le port loopback d'un service géré dont cette machine tient la fiche, lu comme
la route du palier `#15` le lit, et refusé avant tout effet sinon. L'écouteur
n'a aucun service local à nommer : le lui demander refuserait toutes les
jonctions correctes. Ce qui le borne est que le port qu'il peut atteindre est
celui que l'humain a approuvé sur les deux plans.

**Ce qu'aucune jonction ne peut nommer.** L'adresse qu'une règle atteint est la
constante du rôle opposé. Aucun champ d'aucun document de ce contrat ne la
nomme, donc une jonction dont les règles viseraient un autre destinataire n'est
pas un refus à écrire : c'est un document qui n'existe pas.

**Ce que la preuve machine `#98` doit encore constater.** Que le fichier de
règles est bien rechargé au démarrage par son unité ; que la redirection vers le
loopback fonctionne réellement à travers le tunnel ; que `route_localnet` est
bien porté par la seule interface du passage ; et ce qu'un flux établi devient
quand les règles sont retirées.

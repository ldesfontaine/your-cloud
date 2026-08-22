# DNS et certificats : le wildcard, et un jeton qui ne peut presque rien

> **Ce document fixe comment un nom public désigne une infrastructure et comment
> son certificat se renouvelle sans humain.** C'est le premier territoire où le
> produit **écrit chez un tiers**, et il est traité comme tel.
>
> Ce qui route une requête une fois arrivée appartient au
> [point d'entrée](POINT-D-ENTREE.md).

## Le wildcard est le nominal

Un seul certificat `*.domaine` couvre tous les services, présents et à venir.
Ce n'est pas une commodité, c'est ce qui **empêche de publier la liste des
sous-domaines privés** : un certificat par service ferait apparaître chaque nom
dans les journaux publics de transparence, et l'inventaire d'une infrastructure
privée s'y lirait à livre ouvert.

Un certificat par service reste possible pour un service **public pur**, où il
n'y a rien à cacher. L'app dit alors ce que cela publie, plutôt que de le taire.

## Le jeton ne peut écrire que des TXT sans valeur

C'est la décision qui structure tout le reste.

Le mode géré exige un jeton d'API capable d'écrire dans le DNS. Un tel jeton,
compromis, permettrait de **réécrire le domaine** — donc de détourner le trafic
de tous les services, ce qui est un pouvoir supérieur à celui de la machine qui
le porte.

**On le lui retire par construction.** Le nom `_acme-challenge.domaine` est
**délégué par CNAME à une zone dédiée**, et le jeton n'a de droits **que sur
cette zone**. Il peut y écrire les enregistrements TXT que le défi ACME
réclame ; il ne peut rien faire d'autre.

Ce que gagne un attaquant qui le vole : la capacité d'écrire des TXT sans valeur
dans une zone qui ne sert qu'à cela. **Il ne peut ni détourner un nom, ni
émettre un certificat** — l'émission exige aussi de répondre au défi pour le
compte ACME de l'infrastructure.

**Cette délégation est une exigence du mode géré, pas une recommandation.** Elle
se pose une fois, avec l'aide de l'app, et se vérifie par résolution avant que
le mode géré soit déclaré actif.

## Ce que la délégation exige, et qui ne l'a pas

**Le mode géré exige que vous possédiez une seconde zone DNS.** C'est une
limite dure, et c'est le cas le plus courant qui s'y heurte.

Un jeton d'API se restreint à une **zone**, jamais à un préfixe à l'intérieur
d'une zone. `_acme-challenge.example.com` ne peut donc pas être délégué *dans*
`example.com` : la délégation doit pointer vers une zone distincte, sur laquelle
le jeton est restreint. **Qui ne possède qu'un seul domaine ne peut pas activer
le mode géré.**

Le chemin de cette personne est le **mode manuel**, et son coût est réel : un
wildcard s'y renouvelle à la main **tous les ~90 jours**. Pour beaucoup
d'auto-hébergeurs, ce n'est pas tenable — le badge d'expiration transforme une
panne silencieuse en rappel, il ne supprime pas la corvée.

Le produit dit cela **avant** que l'utilisateur choisisse, pas au moment où le
mode géré refuse de s'activer.

> **Direction identifiée, pas promesse.** Une sortie propre existe et n'est pas
> écrite ici : déléguer `acme.example.com` par enregistrement **NS** vers la
> machine du point d'entrée — ce qu'une zone unique permet — laisserait Your
> Cloud **répondre lui-même aux défis**. Ni seconde zone, ni jeton pour la
> partie ACME : le jeton ne servirait plus qu'aux enregistrements `A`. C'est
> hors périmètre aujourd'hui, et l'inscrire comme direction n'en fait pas une
> capacité annoncée.

## Où vit le jeton, et pourquoi la question est devenue secondaire

**Sur la machine du point d'entrée**, déposé par un plan approuvé, propriété de
`root`, illisible par les services.

Ce choix aurait été lourd sans la délégation : y poser un jeton capable de
réécrire le DNS reviendrait à mettre le pouvoir le plus dangereux sur la machine
la plus attaquable, celle qui termine le TLS et reçoit le trafic d'Internet.

**La délégation ayant vidé le jeton de ce pouvoir**, le compromis change de
nature. Restent deux propriétés, et elles vont dans le même sens :

- **le renouvellement reste un geste local** d'un service déjà approuvé, dans
  son confinement. Le conduire depuis le Controller ferait acquérir au produit
  son **premier effet récurrent et non surveillé sur une machine distante** —
  une catégorie neuve, qui exigerait sa propre justification et ses propres
  bornes ;
- **le certificat n'a pas à voyager.** Il naît là où il est présenté.

Le défi DNS-01 **n'implique jamais le point d'entrée en tant que serveur** :
c'est ce qui le distingue de HTTP-01. Le défi se répond par un enregistrement
TXT ; aucun service ne présente rien. C'est ce qui rend possible un wildcard, et
c'est aussi ce qui rend ce choix de machine peu coûteux.

## Deux modes par domaine

| | **géré** | **manuel** |
|---|---|---|
| le DNS | l'app écrit, via le jeton délégué | l'app **affiche exactement quoi créer** |
| la vérification | par résolution, avant de déclarer actif | par résolution, puis confirmation |
| le certificat | wildcard ACME DNS-01, renouvelé seul | apporté par l'utilisateur, posé par plan |
| l'oubli | impossible — le renouvellement est automatique | **un badge de rappel avant expiration** |

Dans les deux modes, l'écran montre **l'attendu et l'observé**. Un domaine qui
pointe à côté se voit au lieu de se découvrir en panne.

**Le badge du mode manuel n'est pas un confort.** Un certificat apporté à la
main meurt en silence : rien dans le système ne prévient, et la panne arrive un
matin sans cause visible. Le badge est la seule chose qui distingue « manuel »
de « oublié ».

**Le mode géré n'est jamais obligatoire.** Un utilisateur qui ne veut confier
aucun jeton garde un produit complet, au prix d'un geste tous les quelques mois.

## Chaque écriture DNS est une action nommée

Publier un service inclut son enregistrement dans la fenêtre qui décrit
l'action. Il n'y a pas de guichet de configuration DNS séparé : on approuve une
action, elle porte ses effets — y compris ceux qui sortent de l'infrastructure.

C'est la même règle que partout ailleurs, et elle compte davantage ici :
**écrire chez un tiers est un effet que l'utilisateur ne peut pas défaire
lui-même** s'il ne sait pas qu'il a eu lieu.

## Justification de sécurité du jeton délégué

- **Scénario et actifs** : un jeton d'API DNS, déposé sur la machine du point
  d'entrée, utilisé toutes les ~60 jours sans humain présent ; et le nom public
  de l'infrastructure, dont dépend l'acheminement de tous les services.
- **Menace traitée** : le vol du jeton. Sans borne, il permettrait de réécrire
  le domaine — détourner tout le trafic, obtenir des certificats valides pour
  n'importe quel nom, et le faire silencieusement.
- **Alternatives considérées** : un jeton pleins droits sur la zone — **écarté**,
  il place sur la machine la plus exposée un pouvoir supérieur à celui de la
  machine elle-même ; le renouvellement conduit par le Controller — écarté une
  fois la délégation posée, parce qu'il ferait acquérir au produit un effet
  récurrent non surveillé sur une machine distante, catégorie neuve dont le coût
  dépasse le gain restant ; HTTP-01 par service — écarté pour le privé, il
  publie la liste des noms.
- **Portée accordée et moindre privilège** : le jeton n'a de droits que sur une
  **zone dédiée qui ne sert qu'aux défis**. Il écrit des TXT sans valeur. Il ne
  peut ni détourner un nom, ni émettre seul un certificat.
- **OWASP** : moindre privilège (délégation), réduction de surface (une zone,
  un type d'enregistrement), défense en profondeur (le vol du jeton ne suffit
  pas à émettre), valeur sûre par défaut (le mode géré n'est pas activé tant
  que la délégation n'est pas vérifiée).
- **NIS2** : contrôle d'accès, gestion des actifs, continuité — le renouvellement
  automatique retire la panne par oubli, et le mode manuel la signale.
- **Preuves attendues** : ci-dessous.
- **Risque résiduel** : la compromission de la machine du point d'entrée donne
  le jeton **et** la clé privée du certificat en place. Le jeton ne l'aggrave
  plus — c'est la clé qui compte, et elle était déjà là. Le rayon reste celui de
  cette machine.

## Ce que la preuve devra constater

- le mode géré **refuse de s'activer** tant que la délégation `_acme-challenge`
  n'est pas vérifiée par résolution ;
- l'app **annonce l'exigence d'une seconde zone avant le choix du mode**, et non
  au moment du refus ;
- le jeton **ne peut écrire** hors de la zone déléguée — tenté, refusé ;
- un wildcard se renouvelle **sans humain** et sans que l'app soit ouverte ;
- aucun sous-domaine privé n'apparaît dans les journaux publics de transparence ;
- en mode manuel, le badge d'expiration **précède** la panne ;
- l'écran montre l'attendu et l'observé, y compris quand ils diffèrent.

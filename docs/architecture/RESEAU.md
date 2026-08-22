# Le réseau : ce qui transporte n'autorise rien

> **Ce document fixe la frontière du réseau interne de Your Cloud** : qui peut
> parler à qui, par où, et sous quelle autorisation. Ce qu'il fixe engage le
> produit — un flux qui existerait sans figurer dans une liste approuvée est un
> défaut, pas une variante.
>
> L'exposition d'un service vers l'extérieur est fixée par le
> [point d'entrée](POINT-D-ENTREE.md). Les deux frontières se touchent sans se
> recouvrir : ici on transporte entre machines, là on ouvre vers Internet.

## L'idée qui fonde tout le reste

**Séparer le transport de l'autorisation.** Un lien chiffré transporte ; il
n'autorise rien. Deux machines reliées ne peuvent, par défaut, échanger
strictement aucun paquet.

Cette séparation n'est pas une précaution de style : c'est ce qui permet de
répondre à « qu'est-ce qui circule ? » par une liste finie, nommée et vérifiable,
plutôt que par « tout ce que le lien permet ».

## Deux réseaux, jamais un seul

| Réseau | Qui y est | Ce qu'il sert |
|---|---|---|
| **réseau d'accès** | l'app et le Controller | piloter l'infrastructure |
| **réseau interne** | les machines enrôlées entre elles | faire communiquer les services |

Deux interfaces WireGuard distinctes, gérées par le produit, invisibles pour
l'utilisateur. La raison est un rayon d'explosion, pas une élégance : **une clé
d'app compromise ne donne aucune route vers les services, et une machine de
service compromise n'a aucune route vers le Controller.**

Un seul réseau serait plus simple à poser et rendrait cette phrase impossible à
écrire.

## Les adresses : choisies une fois, stables à vie

- à la création de l'infrastructure, un sous-réseau est **proposé** et reste
  **modifiable à ce moment-là seulement** ;
- chaque machine reçoit son adresse interne à l'enrôlement et **la garde à
  vie**, quel que soit le transport en dessous ;
- le réseau interne est un **overlay** : chaque machine porte deux adresses, la
  physique que gère le routeur de l'utilisateur et l'interne que gère le
  produit. Seule contrainte : des plages disjointes. L'app détecte un conflit
  avec le LAN et propose un autre défaut.

Une adresse stable à vie est ce qui permet à un service de nommer son voisin
sans le redécouvrir à chaque redémarrage.

## La topologie : directe, jamais de détour caché

- deux machines d'un même LAN se parlent **en direct** — le trafic ne quitte pas
  la maison ;
- une machine du LAN et une machine publique se parlent en direct, **la
  connexion étant initiée depuis le LAN** : elle traverse le NAT, n'exige rien
  d'ouvert sur la box, et survit à un changement d'adresse ;
- **aucun relais par défaut.** La machine la plus exposée ne voit jamais transiter
  le trafic interne entre deux machines privées.

Les sites multiples sans aucune adresse publique sont **explicitement remis à
plus tard** : rien dans ce contrat ne les couvre.

## Zéro flux par défaut, et chaque flux nommé

Un lien ne donne aucun droit. Chaque flux est une **permission explicite,
nommée, approuvée et visible**.

**Les actions ouvrent leurs propres flux.** Publier un service inclut son flux
dans la fenêtre d'approbation qui décrit l'action — « ouvre le flux services →
point d'entrée, port interne 443 ». L'utilisateur n'administre pas des règles :
il approuve des actions qui les portent. Une ouverture manuelle reste possible
pour les besoins que le produit ne connaît pas.

L'application est faite par la table `nftables` du produit, celle qui **ne peut
que retirer** — jamais accorder au-delà de ce qu'un plan approuvé a nommé.

Deux vues permanentes rendent cela lisible, et elles ne sont pas la même :

- **la carte des liens** — qui est relié à qui, par quel transport, dernière
  poignée de main ;
- **la liste des flux autorisés** — chaque règle nommée, avec le service qui l'a
  demandée.

**Rien ne circule qui ne figure dans la seconde.**

## Solide veut dire : vit sans le pilotage

Les liens et les règles sont posés en configuration persistante. Un redémarrage
les remonte seul. **Une panne du Controller ou de l'app ne coupe rien** : le
pilotage sert à *changer* le réseau, pas à le faire tenir.

Chaque changement passe par un plan approuvé — l'état réel du réseau est donc
celui qui a été approuvé, et le Daemon l'observe : interfaces, pairs, fraîcheur
des poignées de main.

## Le canal d'accès à l'infrastructure

L'app est un **pair du réseau d'accès**. Sa clé naît dans son coffre à la
création de l'infrastructure.

- **la porte d'entrée** est sur la machine à adresse publique quand il en existe
  une, sinon sur celle du Controller. C'est un port UDP dédié et **silencieux** :
  il ne répond pas aux inconnus, il n'y a rien à scanner ;
- **le Controller n'écoute que sur son adresse du réseau d'accès** ;
- **les transports sont essayés dans l'ordre** — la machine publique d'abord,
  puis le LAN direct quand l'administrateur est sur place. **Les adresses ne
  changent pas** : seul le transport varie ;
- **le tunnel monte au clic** sur une infrastructure et tombe à la fermeture de
  l'app ou au changement d'infrastructure.

**Le tunnel est un transport, jamais une authentification.** L'identité
d'appareil et la session humaine restent exigées par-dessus, et le
[cap](../projet/CAP.md) le dit avant ce contrat.

## Ce que la preuve devra constater

- deux machines reliées et **sans flux approuvé** n'échangent rien ;
- un flux ouvert par une action apparaît **nommé** dans la liste, avec son
  demandeur ;
- un redémarrage remonte liens et règles **sans le Controller** ;
- le trafic entre deux machines privées **ne traverse pas** la machine publique ;
- le port d'accès **ne répond pas** à un inconnu.

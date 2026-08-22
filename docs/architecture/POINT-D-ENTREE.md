# Le point d'entrée : ce qui entre, et sous quelle identité

> **Ce document fixe la frontière de l'exposition publique** : comment un
> service devient joignable depuis Internet, et ce que le produit fait des
> identités qu'on lui présente. Ce qu'il fixe engage le produit — un service
> joignable sans figurer dans une exposition approuvée est un défaut, pas une
> variante.
>
> Le transport entre machines est fixé par le [réseau](RESEAU.md). Les deux
> frontières se touchent sans se recouvrir : là on transporte entre machines,
> ici on ouvre vers l'extérieur.

## Deux familles, un seul point d'entrée

| Famille | Ce qui entre | Comment |
|---|---|---|
| **HTTPS** | un navigateur | route par nom d'hôte, terminaison TLS |
| **L4** | tout ce qui n'est pas HTTP | un port public, redirigé |

Elles partagent la même machine et la même discipline : **une exposition est un
objet nommé, visible dans une liste, retirable en un clic.** Ce n'est jamais une
règle de pare-feu qu'on a oubliée d'écrire quelque part.

## L'exposition L4

- sur un service : « exposer sur Internet », puis le port public. Le protocole
  se dérive du service ;
- **un port public sert un seul service.** Il n'y a pas de multiplexage par nom
  en L4 — un protocole de jeu n'envoie aucun nom d'hôte. Deux serveurs du même
  jeu demandent deux ports ;
- l'app affiche **l'adresse exacte à communiquer** : c'est ce que l'utilisateur
  transmettra à ses joueurs ;
- **pas d'adresse publique, pas d'exposition publique** — par nature, non par
  choix. Les invités identifiés passent alors par le web authentifié.

### L'adresse du visiteur est préservée — et ce n'est pas encore prouvé

**La cible est que le service voie la vraie adresse de chaque visiteur**, pour
que ses propres protections fonctionnent.

L'implémentation qu'elle impose : redirection au point d'entrée **sans
réécriture de l'adresse source**, et route de retour marquée sur la machine de
service, posées des deux côtés par les plans. Un proxy applicatif terminerait la
connexion et perdrait l'adresse par construction — il est écarté pour la cible.

**Cette capacité n'est pas promise tant qu'une preuve LAB ne l'a pas
constatée** : MTU, suivi de connexions, expirations UDP et retour symétrique
sont exactement ce qui casse ce montage. Le repli, s'il casse, est l'exposition
simple — le service voit l'adresse du point d'entrée — **avec la limite écrite
noir sur blanc** et les protections déplacées au point d'entrée. Il n'y aura pas
deux implémentations entretenues en parallèle.

## Les identités présentées : toutes écrasées

**Le point d'entrée écrase tous les en-têtes d'identité entrants** — les
`X-Forwarded-*`, `X-Real-IP` et leurs variantes — et pose les siens. **Aucune
confiance n'est accordée à ce qui vient de l'extérieur.**

Cette règle ne tient pas seule : elle repose sur le fait qu'un service **n'est
joignable que par le point d'entrée**. Les flux nommés du [réseau](RESEAU.md) et
le cloisonnement local ci-dessous garantissent que personne ne peut lui
présenter d'en-têtes forgés en direct.

Une règle de proxy sans cette garantie serait une politesse ; avec elle, c'est
une frontière.

## Le cloisonnement local

Un service ne partage pas son voisinage. Sur une machine qui en héberge
plusieurs :

- chaque service tourne sous **son compte dédié**, dans son conteneur, avec son
  répertoire propre et sans accès au socket du moteur ;
- **le port local d'un service n'est joignable que par qui en a besoin** —
  règles `nftables` **par compte**, posées **automatiquement par chaque
  déploiement**, dans la table qui ne peut que retirer. Un service compromis ne
  peut plus atteindre le port local de son voisin. **Zéro geste utilisateur** ;
- **la frontière forte reste la machine virtuelle.** Pour un service sensible,
  c'est une recommandation au placement — jamais une obligation imposée.

## Les deux visibilités d'un service

| Visibilité | Qui | Par où |
|---|---|---|
| **publique** | tout le monde | le point d'entrée, sans authentification |
| **privée** | les personnes créées par l'administrateur | le point d'entrée, **portail devant** |

**Pas d'authentification à deux facteurs sur du public** : les clients d'un jeu
ne savent pas la présenter, et l'exiger reviendrait à fermer ce qu'on voulait
ouvrir.

Pour un service privé, le point d'entrée **délègue la validation au portail
avant de servir quoi que ce soit**. Le service n'est jamais atteint par une
requête non validée. Le portail lui-même — son image, sa preuve, son cycle —
appartient à son contrat de profil, qui reste à écrire : ce contrat-ci fixe le
branchement, pas le composant branché.

## Ce que ce contrat ne lève pas

- une exposition **n'est jamais implicite** : aucun service ne devient joignable
  par le seul fait d'être déployé ;
- le retrait d'une exposition **retire le flux qu'elle avait ouvert** — une
  exposition supprimée qui laisserait sa règle serait un défaut ;
- le point d'entrée **ne détient aucune autorité d'administration** : il route,
  termine du TLS et valide des sessions ; il ne pose ni ne modifie de service.

## Ce que la preuve devra constater

- un en-tête d'identité forgé, présenté au point d'entrée, **n'atteint jamais**
  le service ;
- un service **n'est pas joignable** autrement que par le point d'entrée ;
- deux services de la même machine **ne peuvent pas** s'atteindre par le
  loopback ;
- une exposition retirée **ferme** son port et son flux ;
- pour l'adresse préservée : **soit** le service voit la vraie adresse du
  visiteur, **soit** la limite est écrite et le repli documenté. Pas de troisième
  issue silencieuse.

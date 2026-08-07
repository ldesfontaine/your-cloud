# Responsabilité externe : représenter sans posséder

> Statut : proposition de contrat pour le palier `#18`, suivie par `#105`.
> Il fixe ce qu'une déclaration externe porte, ce qu'un adaptateur en lecture
> seule a le droit de faire, la distinction entre ce qui est déclaré et ce qui
> est vérifié, et la liste de ce que l'App annonce ne pas pouvoir faire. Rien
> ici n'est implémenté tant que ce contrat n'est pas validé.

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

# Versions et mises à jour : le tag à l'écran, le digest dessous

> **Ce document fixe comment une version est vue, choisie, gelée et
> remplacée.** Le déploiement lui-même et sa fenêtre de retour appartiennent au
> [cycle de vie](CYCLE-DE-VIE-DES-SERVICES.md) ; ce qu'une recette contient
> appartient aux [services](SERVICES-DECOUVERTE-ET-REPRISE.md).

## Le tag à l'écran, le digest dessous

L'utilisateur choisit un **tag lisible** — `vaultwarden:1.32`. Il ne tape jamais
un digest.

**L'app résout le tag en digest au moment du gel**, par une lecture du registre,
et **c'est le digest qui est gravé dans la recette et déployé**. Si le tag bouge
ensuite chez son éditeur, la recette ne bouge pas.

C'est ce qui rend un déploiement reproductible : même recette, mêmes octets,
partout et plus tard. Un tag est un nom que son propriétaire peut redéfinir ; un
digest est ce qu'on a réellement exécuté.

## La surveillance : automatique pour tous, sans travail de mainteneur

Le produit lit les registres en **lecture seule** et compare le tag suivi au
digest déployé. Quand ils divergent, le service porte un badge **« nouvelle
version disponible »**.

Cela vaut pour les services **proposés** comme pour ceux que l'utilisateur a
écrits : la surveillance ne dépend d'aucun catalogue tenu à la main.

### Où tourne ce collecteur, et pourquoi

**Chez le Controller.** Trois raisons, dans cet ordre :

1. **il détient les recettes gelées** — comparer un tag à un digest déployé exige
   de connaître le digest déployé, et c'est lui qui le porte ;
2. **il est allumé en permanence** — un collecteur qui vivrait dans l'app ne
   verrait les nouvelles versions qu'à son ouverture, et un badge périmé est pire
   qu'aucun badge ;
3. **il a déjà une sortie** — lui en ajouter une n'ouvre pas une catégorie de
   chemin qui n'existait pas.

**Ce que cela coûte, et qui est assumé** : le Controller acquiert une
communication sortante vers des registres publics, donc un lien entre une
infrastructure privée et l'extérieur qui n'existait pas. C'est borné à une
**lecture** de métadonnées de manifestes, vers des hôtes déclarés par les
recettes, et jamais un canal par lequel quelque chose entre. Le refus du canal
descendant est intact : personne ne *pousse* une version.

## Jamais d'auto-update silencieux

Le badge **informe**, il n'agit pas. La mise à jour est un geste approuvé :

1. le badge mène à une fenêtre qui nomme la version et sa source ;
2. l'approbation déclenche **un instantané automatique** ;
3. le service est redéployé depuis la recette mise à jour ;
4. une **fenêtre de retour** reste ouverte — les volumes survivent, et revenir
   est un clic.

Un produit qui met à jour tout seul décide à la place de l'utilisateur sur sa
propre infrastructure. Le badge lui rend l'information ; le geste lui reste.

## Pas d'étiquette « testée » à l'écran

L'écran montre des **faits** — numéro de version, date, source. Il ne porte
aucun label de confiance.

La raison n'est pas un manque de rigueur, c'est l'inverse : **la protection de
l'utilisateur est le mécanisme**, pas une étiquette. Approbation, instantané
préalable et fenêtre de retour protègent quelle que soit la version. Une
étiquette « testée » ferait porter à un mot ce que le mécanisme tient déjà, et
inviterait à baisser la garde là où elle est le plus utile — sur une version que
personne n'a essayée.

**La discipline de preuve reste côté dépôt** : un profil n'entre au catalogue
que prouvé en LAB, avec son contrat. Ses évolutions structurelles sont des mises
à jour du profil. Aucun label d'écran n'en découle.

## Qui répond de quoi

| | version d'entrée | mises à jour ensuite |
|---|---|---|
| **services proposés** | le produit la fournit, prouvée en LAB | les badges suivent l'éditeur amont |
| **services de l'utilisateur** | sa recette, son choix | son geste, aidé par le badge |

**Le geste du mainteneur — ré-épingler et re-prouver un profil — est optionnel
et n'est jamais bloquant.** Un utilisateur n'attend pas qu'un profil soit
re-certifié pour mettre à jour son service : le badge et le mécanisme suffisent.
Sans cette règle, le catalogue deviendrait un goulot, et un catalogue qui
retarde les correctifs de sécurité nuit plus qu'il ne protège.

## Ce que ce contrat ne lève pas

- **la mise à jour ne migre aucune donnée.** Si une version exige une migration,
  c'est le service qui la porte, pas le produit ;
- **un retour n'annule pas ce qu'une version a écrit** dans ses volumes : il
  restaure l'instantané, ce qui est une autre promesse et elle est nommée ;
- **le produit ne juge pas une version** : il dit ce qu'elle est et d'où elle
  vient.

## Ce que la preuve devra constater

- un tag qui bouge chez son éditeur **ne change pas** la recette gelée ;
- le digest déployé est **exactement** celui que le gel a résolu ;
- une mise à jour **crée son instantané avant** de toucher au service ;
- un retour ramène le service à sa version précédente, **volumes intacts** ;
- aucune version ne s'installe **sans approbation**.

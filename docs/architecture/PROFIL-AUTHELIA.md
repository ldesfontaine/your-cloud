# Profil de référence — Authelia, le portail des services privés

> **Ce document fixe ce que Your Cloud pose quand un service exige une
> connexion**, et à quelle barre. Le branchement au point d'entrée est fixé par
> le [point d'entrée](POINT-D-ENTREE.md) ; ce contrat décrit le composant
> branché, pas le branchement.

## Ce que ce profil est, et n'est pas

**C'est** un profil de référence à la barre des existants : image épinglée par
digest, contrat, preuve LAB. Le produit le pose, le met à jour et le retire
comme tout service qu'il connaît par sa recette.

**Ce n'est pas** un composant du produit. Your Cloud n'écrit pas de fournisseur
d'identité : maintenir un service de plus quand des alternatives éprouvées
existent n'apporte rien à l'utilisateur. Si un composant natif se justifiait un
jour, **il remplacerait ce profil sans changer un écran** — c'est la propriété
qui rend ce choix réversible, et elle est une exigence du contrat, pas un
espoir.

**Ce n'est pas non plus** un annuaire d'entreprise. Les personnes créées ici
accèdent à des services ; elles ne pilotent aucune infrastructure.

## Image épinglée

À épingler par digest au moment de la première preuve LAB, comme les profils
existants : liste de manifestes, digest `amd64` résolu, et **constat sur le
registre plutôt que croyance** — port interne, volumes déclarés par l'image.

Tant que ce constat n'est pas fait, ce contrat ne nomme aucune version : un
profil dont l'image n'est pas épinglée n'entre pas au catalogue.

## Quand il est posé, et par quel geste

**Au premier « Exiger une connexion »** sur un service, et pas avant. Poser un
portail que personne n'utilise serait une surface offerte sans contrepartie.

La pose suit le chemin ordinaire : une pop-up d'approbation qui nomme ce qui va
être fait sur quelle machine, un plan, un rapport. **L'utilisateur n'installe
pas un portail** — il exige une connexion, et le produit en tire ce qu'il faut.

Le retirer suit le chemin inverse : quand plus aucun service n'exige de
connexion, le portail devient retirable comme tout service dont la recette est
connue.

## Les deux populations ne se mélangent jamais

| | l'administrateur | les personnes du portail |
|---|---|---|
| **par où** | l'app, sur le canal d'accès | le web, par le point d'entrée |
| **ce qu'il ou elle peut** | piloter l'infrastructure | utiliser les services accordés |
| **où vit son identité** | le coffre de l'app | l'annuaire du portail |

**Une personne du portail ne gagne aucune capacité d'infrastructure**, quel que
soit le nombre de services qu'on lui accorde. Ce n'est pas une convention
d'usage : les deux populations n'ont ni le même chemin réseau, ni la même
autorité, ni le même magasin d'identités.

Accorder, révoquer, réinitialiser un second facteur sont des gestes de
l'administrateur depuis l'app. **L'annuaire vit chez lui**, pas chez un tiers.

## Ce que le portail exige, et ce qu'il n'exige pas

- **un second facteur est obligatoire** pour une personne du portail. Un mot de
  passe seul, sur un service exposé à Internet, n'est pas une protection ;
- **le service n'est jamais servi avant validation** : le point d'entrée délègue
  au portail et attend son verdict ;
- **aucun client à installer.** C'est la condition pour que le portail serve des
  gens qui ne sont pas administrateurs — un proche n'installera rien.

**Un allègement, jamais une exigence.** Sur un chemin déjà authentifié par un
réseau de confiance de l'utilisateur, le second facteur **peut** être allégé.
Jamais l'inverse : aucun chemin ne peut *exiger* plus que le portail, et aucun
ne peut contourner sa validation.

## Ce que ce contrat ne lève pas

- **le portail n'est pas une frontière réseau** : il valide des sessions. Ce qui
  empêche d'atteindre un service sans passer par lui appartient au point
  d'entrée et au réseau ;
- **le portail ne protège pas un service public** : par définition, un service
  public n'en a pas, et lui en poser un fermerait ce qu'on voulait ouvrir ;
- **une personne révoquée perd l'accès aux services**, pas les données qu'elle y
  a créées. Ce qu'il advient de ces données appartient au service, pas au
  portail.

## Justification de sécurité du choix d'un profil plutôt qu'un composant

- **Scénario et actifs** : l'annuaire des personnes autorisées à joindre les
  services privés d'une infrastructure, et les sessions qu'il délivre.
- **Menace traitée** : un fournisseur d'identité écrit et maintenu par nous,
  avec sa cryptographie, sa gestion de sessions et ses seconds facteurs, serait
  une surface neuve dont chaque défaut nous appartiendrait — sur un composant où
  les défauts sont catastrophiques et bien connus.
- **Alternatives considérées** : écrire le composant — écarté, coût permanent
  sans valeur pour l'utilisateur ; déléguer à un service tiers hébergé —
  écarté, l'annuaire quitterait la machine de l'utilisateur, ce que le cap
  refuse.
- **Portée accordée et moindre privilège** : le portail valide des sessions et
  rien d'autre. Il ne détient aucune autorité d'infrastructure, aucun secret de
  machine, et son compte est cloisonné comme tout service.
- **OWASP** : réduction de surface (pas de code d'authentification maison),
  séparation des responsabilités (valider n'est pas router ni administrer),
  défense en profondeur (le portail s'ajoute au fait que le service n'est
  joignable que par le point d'entrée).
- **NIS2** : contrôle d'accès, chaîne d'approvisionnement — l'image est épinglée
  par digest et sa mise à jour est un geste approuvé, jamais silencieux.
- **Preuves attendues** : ci-dessous.
- **Risque résiduel** : la compromission du portail donne accès aux services
  privés qu'il protège — pas à l'infrastructure, pas aux machines, pas aux
  autres populations. Le rayon est celui des services, et il est nommé.

## Ce que la preuve devra constater

- un service privé **n'est jamais servi** avant validation du portail ;
- une personne révoquée **perd l'accès immédiatement**, sans attendre
  l'expiration d'une session ;
- une personne du portail **ne peut atteindre aucune surface d'infrastructure** ;
- le portail est **posé au premier « Exiger une connexion »** et pas avant ;
- son image déployée est **exactement le digest épinglé**.

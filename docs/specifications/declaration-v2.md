# Déclaration V2 et domaines de panne

> État : schéma, migration explicite et vues de domaines prouvés dans le LAB
> `v1-full` le 2026-07-12.

## Frontière entre intention et constat

La déclaration contient l'intention éditable de l'opérateur. Le registre
runtime contient les constats produits par un détecteur identifié. Une
détection ne modifie jamais la déclaration et une déclaration ne devient jamais
une preuve de topologie.

## Schéma 2

La racine conserve exactement :

- `schema_version`, égal à `2` ;
- `machines`, liste des machines logiques ;
- `infrastructures`, liste des regroupements logiques.

Une infrastructure contient exactement :

- `id`, identifiant stable borné ;
- `name`, nom humain non vide ;
- `failure_domain`, identifiant de domaine déclaré ou `null` lorsque
  l'opérateur ne sait pas.

Un domaine déclaré commence par un caractère alphanumérique, contient au plus
128 caractères et peut ensuite employer lettres, chiffres, `.`, `_`, `:`, `/`
et `-`. Ce champ ne contient ni secret ni contenu exécutable.

Les champs d'une machine restent inchangés : identité logique, adresse, port,
utilisateur, clé SSH référencée et infrastructure facultative. L'affectation à
une infrastructure ne change ni l'identité, ni l'historique, ni les services de
la machine.

## Migration depuis le schéma 1

Une commande normale refuse le schéma 1 et indique `declaration migrate`. La
migration :

1. valide strictement toute la déclaration v1 ;
2. affiche le nombre de machines et d'infrastructures conservées ;
3. ajoute `failure_domain: null` à chaque infrastructure ;
4. n'écrit rien sans `--approve` ;
5. ne crée aucune détection et ne touche à aucun état runtime ou distant.

La migration ne modifie pas rétroactivement les kits de récupération existants.
Une déclaration v1 restaurée depuis un ancien kit repasse par le même plan
explicite.

## Registre runtime des détections

`failure_domains.json` reste sous le répertoire privé de l'état console, en
mode `0600`. Chaque dernière détection contient exactement :

- l'identifiant d'infrastructure ;
- le domaine détecté ;
- la source du détecteur ;
- une preuve textuelle bornée et non sensible ;
- l'instant UTC d'observation.

La V1 n'offre aucune commande permettant à l'opérateur de fabriquer une
détection. Un adaptateur ou un contrôleur de LAB appelle l'API interne après
avoir vérifié sa propre preuve.

## Vue rendue

La console rend cinq états distincts :

| État | Signification |
|---|---|
| `unknown` | ni domaine déclaré ni détection disponible |
| `declared` | intention présente, aucune détection disponible |
| `detected` | constat sourcé présent, aucune intention déclarée |
| `confirmed` | déclaration et détection désignent le même domaine |
| `conflict` | déclaration et détection diffèrent ; aucune correction automatique |

Deux infrastructures qui partagent le même domaine restent deux regroupements
logiques, sans être présentées comme indépendantes ni hautement disponibles.

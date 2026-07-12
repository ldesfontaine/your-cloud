# Séparer déclaration versionnable et état runtime

Statut : accepté · ratification P0 du 2026-07-12

## Contexte

Le parcours guidé, la CLI, une future interface et l’édition avancée doivent
exprimer la même intention sans obliger l’utilisateur à adopter Git. Mélanger
intention, secrets et état calculé rendrait les migrations opaques et
autoriserait facilement l’exécution de contenu arbitraire.

## Décision

- Une déclaration lisible et versionnée par schéma constitue l’intention
  éditable commune à toutes les interfaces.
- Git reste optionnel et entièrement contrôlé par l’opérateur ; le produit ne
  clone, commit, pousse ou fusionne rien automatiquement.
- Secrets, identités actives, télémétrie, caches et sorties calculées restent
  hors de la déclaration.
- Une politique possède une seule autorité de configuration. Une gestion
  externe est possible si les responsabilités ne se chevauchent pas.
- La V1 n’exécute aucun script, hook, plugin, template actif ou playbook fourni
  par la déclaration ou un dépôt utilisateur.
- Une migration de schéma est explicite, inspectable et jamais silencieuse.

## Conséquences

Les utilisateurs débutants et avancés traversent les mêmes validations et
plans. L’état runtime nécessite son propre stockage et sa propre récupération,
mais un fichier versionné ne peut pas autoriser seul une nouvelle identité ou
introduire un mécanisme d’exécution arbitraire.

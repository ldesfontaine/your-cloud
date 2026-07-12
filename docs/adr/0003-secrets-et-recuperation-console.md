# Séparer les secrets, la déclaration et le kit de récupération

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

La console détient des autorités non régénérables. Les placer en clair dans la
déclaration ou sauvegarder ciphertext et clé dans le même domaine de panne
donnerait une récupération illusoire.

## Décision

- La déclaration contient uniquement des références de secrets.
- Le parcours guidé utilise un stockage chiffré piloté par la console ; le
  backend sera choisi après preuve de récupération.
- SOPS/age reste une intégration optionnelle pour les utilisateurs avancés.
- Une identité de déchiffrement ne réside jamais dans le dépôt ni dans la même
  sauvegarde que les données qu’elle protège.
- Avant la première mutation introduisant un secret non régénérable, la console
  exige un kit de récupération indépendant et vérifie une donnée synthétique.
- Les secrets nés sur une machine y restent par défaut ; toute sauvegarde
  éventuelle transporte du ciphertext.
- Le kit restaure la console et son registre. Il ne constitue pas une politique
  générale de sauvegarde des services, reportée après la V1.

## Conséquences

La récupération devient une capacité du premier parcours sûr et non une
promesse documentaire tardive. Le produit doit gérer un stockage chiffré et une
procédure de restauration, mais n’impose pas Git ou SOPS à un débutant et ne
prétend pas sauvegarder les applications en V1.

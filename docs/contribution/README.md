# Contribuer au projet

Ces règles sont communes aux contributions humaines et aux agents. Elles
décrivent une manière de travailler ; la vision et les choix techniques vivent
dans leurs sources documentaires dédiées.

## Collaboration

- Écrire en français naturel, résultat d'abord, sans faux brief.
- Le mainteneur du projet fixe la direction et tranche les choix engageants.
- Comprendre, recommander, réaliser ou intégrer, puis vérifier. Challenger une
  idée lorsqu'une option plus sûre ou plus maintenable existe.
- Chercher dans le dépôt avant de poser une question. Pour une ambiguïté
  engageante, avancer une question à la fois avec une recommandation.
- Borner chaque tâche à un résultat et une preuve annoncés. Noter les écarts
  annexes sans les intégrer silencieusement au chantier actif.
- Préserver les changements de travail existants et signaler les conflits avant
  de les modifier.

## Décisions et documentation

- Une réflexion ne devient une décision qu'après validation explicite.
- Utiliser la [carte documentaire](../README.md), puis ouvrir seulement la
  source canonique et les projections utiles au sujet.
- Dès validation, propager la décision dans le même travail. Ne jamais la
  laisser uniquement dans une conversation.
- Appliquer le contrat de [cohérence documentaire](../projet/COHERENCE.md),
  mettre à jour les vues HTML concernées, puis exécuter `tools/check-docs`.
- Capitaliser les contrôles encore manuels, incidents et écarts techniques dans
  le [registre d'automatisation](TESTS.md), sans le confondre avec un rapport de
  preuve réellement exécutée.
- Appliquer le [contrat CI](CI.md) aux runners génériques et conserver la preuve
  multi-VM hors CI tant qu'un contrôleur LAB dédié n'existe pas.
- Un contrôle vert prouve la couverture et les liens, pas l'absence de
  contradiction sémantique : relire le sens avant de poursuivre.
- Créer un ADR seulement si la décision est difficile à renverser, surprenante
  sans contexte et issue d'un véritable compromis.

## Compréhension et organisation du travail

- Suivre la [méthode de lecture du projet](COMPRENDRE-LE-PROJET.md) pour rendre
  visibles les sources consultées, les hypothèses et les vérifications, sans
  charger indistinctement toute la documentation.
- Garder la roadmap comme source de l'ordre des preuves et utiliser les
  [issues GitHub](ISSUES.md) comme suivi concret de leur exécution.
- Représenter chaque palier ou étape décidé de la roadmap par une issue de
  suivi. Avant de coder le prochain palier, le découper en sous-issues dont le
  résultat, le périmètre et la preuve sont exécutables.
- Par défaut, une issue bornée donne une branche, une pull request et un
  résultat vérifiable. Les regroupements plus larges restent des issues parentes
  et ne sont pas fermés par une preuve partielle.
- Ne pas inventer d'avance les sous-issues techniques d'un palier encore
  lointain : son issue de suivi conserve le résultat et les dépendances, puis le
  découpage détaillé est validé lorsqu'il devient le prochain chantier.

## Poste de développement et LAB

- Le poste de développement sert à l'édition, à l'inspection Git, aux
  validations statiques et au contrôle de `labctl`.
- Exécuter le produit, les tests, builds, serveurs, playbooks et scénarios dans
  une VM LAB ou un runner distant isolé, selon les [règles LAB](../lab/README.md).
- Ne jamais présenter comme prouvée une capacité qui n'a pas été réellement
  exécutée dans l'environnement annoncé.

## Secrets et Git

- Ne jamais ajouter au dépôt une clé privée, un secret réel ou une adresse de
  production présentée comme cible de test.
- Ne jamais lire, afficher ou copier le contenu de `keys.txt` ni de
  `/srv/infra/secrets/`. Les noms peuvent être cités, jamais les valeurs.
- Vérifier le diff et l'absence de secret avant tout commit.
- Conserver l'identité Git réelle de l'auteur. Ne pas ajouter automatiquement
  un outil ou une IA comme auteur ou co-auteur.
- Préparer des commits petits et cohérents au format `type(scope): action`.
- Ne jamais réécrire l'historique ni supprimer une modification existante par
  une commande destructive sans demande explicite.
- Un push de la branche principale, un tag ou une release exige l'accord
  explicite du mainteneur pour la référence exacte.

## Fin d'un travail

Résumer simplement le résultat, les preuves exécutées, les limites connues et
la prochaine étape sûre. Pour une décision validée, nommer les sources mises à
jour et les choix qui restent ouverts. Toute preuve manuelle destinée à être
rejouée rejoint aussi le [registre des tests](TESTS.md). Après toute tâche qui
a utilisé le LAB, exécuter `tools/labctl assert-clean` ; un échec interdit une
clôture silencieuse et impose soit la destruction des topologies, soit la
documentation explicite de leur conservation et de la tâche responsable.

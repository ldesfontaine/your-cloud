# Runbooks

Le nouveau projet ne possède encore aucun runbook opérationnel exécutable.

Les procédures de l’ancien wrapper restent sur la branche `old-project`. Elles
conservent une valeur historique, mais leurs commandes ne s’appliquent ni à la
console, ni au daemon, ni au coordinateur de la nouvelle architecture.

Un runbook rejoint `main` seulement lorsque la capacité correspondante a été
implémentée et prouvée dans le LAB. Les premiers candidats sont :

- le premier contact SSH en lecture seule ;
- l’enrôlement et le renouvellement d’identité d’une machine ;
- la sécurisation avec accès hors bande et retour préparé ;
- la récupération de la console ;
- la mise à jour progressive des composants distribués.

Une spécification décrit ce qui doit être construit. Un runbook décrit une
procédure réellement disponible et vérifiée ; les deux ne sont jamais
confondus.

# Employer le même coordinateur en mode local et distant

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

Un mini-coordinateur propre au LAN créerait une seconde architecture et une
migration obligatoire au passage distant. Installer le coordinateur sur un
hôte non géré créerait par ailleurs une exception dans le parcours de confiance
et de maintenance.

## Décision

- Le mode local et le mode distant utilisent le même binaire Go, le même
  protocole mTLS et le même stockage.
- Un coordinateur V1 est installé uniquement sur une machine d’abord enrôlée,
  auditée, sécurisée et administrable par le chemin normal.
- Le mode local limite son écoute au LAN ou au plan d’administration. Le mode
  distant l’expose de manière bornée sur une IP ou un nom DNS facultatif.
- Le daemon et le coordinateur colocalisés gardent des processus, comptes,
  identités, données et limites de ressources séparés.
- L’hôte peut être disponible ou appartenir à une infrastructure ; la fonction
  de coordination reste dans le plan de pilotage et peut relayer plusieurs
  infrastructures de la même console.
- Sans machine toujours allumée, seule une inspection ponctuelle est promise.

## Conséquences

Une installation peut commencer dans le LAN puis ajouter un VPS sans
réenrôlement ni second protocole. La colocalisation réduit l’isolation et partage
un domaine de panne ; l’auto-observation du coordinateur ne constitue aucune
preuve indépendante de sa disponibilité.

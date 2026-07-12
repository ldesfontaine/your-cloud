# Utiliser des identités individuelles sans secret de flotte

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

Un secret partagé étendrait la compromission d’une machine à toute la flotte.
Faire du DNS ou d’une adresse la racine de confiance confondrait localisation
et identité.

## Décision

- Chaque machine génère localement une paire de clés dont la partie privée ne
  quitte jamais le compte du daemon.
- La console approuve la partie publique par un chemin d’administration
  vérifié et conserve l’unique registre de référence des identités actives,
  remplacées et révoquées.
- Une nouvelle clé n’est jamais reconnue par l’adresse, le hostname ou une
  ressemblance matérielle. Le renouvellement passe par un plan vérifié.
- Les coordinateurs reçoivent uniquement une copie dérivée des clés publiques
  autorisées et des révocations.
- Un point de coordination associe une IP ou un nom DNS à une identité de
  transport autorisée. L’adresse permet de joindre le service sans prouver son
  identité.
- L’autorité privée qui délivre les identités de transport reste dans la
  console et appartient au kit de récupération.
- Le projet emploie des primitives et bibliothèques maintenues, jamais une
  cryptographie maison.

## Conséquences

La compromission d’une machine permet d’imiter cette machine jusqu’à révocation,
mais pas une autre. Un changement DNS peut provoquer un déni de service sans
produire une identité valide. Le registre public de la console devient un état
durable à sauvegarder, même s’il ne contient aucune clé privée.

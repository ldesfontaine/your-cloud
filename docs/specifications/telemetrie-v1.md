# Télémétrie V1

> État : collecte et file locale confirmées par P2 ; transport, conservation
> bornée et reprise du coordinateur confirmés par P4.

## État collecté

Le daemon publie uniquement un état borné :

- identité logique de machine et version du daemon ;
- version Debian, noyau, dernier démarrage et durée de fonctionnement ;
- charge CPU, mémoire disponible et utilisée ;
- espace du système de fichiers principal ;
- besoin de redémarrage de sécurité ;
- état des unités systemd choisies explicitement.

Il n’énumère pas par défaut les processus, utilisateurs, ports, fichiers,
variables d’environnement ou journaux. Il ne lit ni ne transmet de secret.

## Rythme et fraîcheur

- état au démarrage puis toutes les 60 secondes ;
- publication immédiate d’un changement significatif ;
- télémétrie qualifiée de retardée après 3 minutes sans nouvel état ;
- aucune absence de données n’est transformée en diagnostic de panne.

Ces valeurs sont des paramètres de contrat V1, pas des constantes dispersées
dans le code. Toute modification doit mettre à jour cette spécification et ses
preuves.

## Conservation

Le daemon conserve dans SQLite un journal local borné à 10 Mio par machine. Il
contient les événements significatifs non confirmés et les marqueurs de lacune,
pas les échantillons périodiques bruts.

Le coordinateur conserve dans sa propre base SQLite le dernier état de chaque
machine et 30 jours d’événements significatifs. Cette base reste une donnée
dérivée : sa perte n’altère ni la déclaration, ni une autorité, ni un service
hébergé.

Après une coupure, le daemon republie d’abord son état courant, puis les
événements encore conservés. Un débordement produit une lacune explicite au
lieu d’un historique présenté comme complet.

À P2, SQLite emploie des transactions synchrones et une limite dure de pages.
L'état périodique remplace l'état courant au lieu d'alimenter le journal. Un
changement de démarrage, noyau, besoin de redémarrage ou unité choisie produit
un événement significatif. Le dépassement de la part réservée au journal
supprime les événements les plus anciens et produit un marqueur de lacune
signé.

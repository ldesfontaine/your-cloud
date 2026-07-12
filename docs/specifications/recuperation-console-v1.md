# Récupération de la console V1

> État : prouvé dans `lab-console-recovery`, VM Debian neuve de la topologie P6.

## Frontière du kit

Le kit complet restaure l'autorité de la console, pas les services des machines.
Il contient la déclaration et les registres publics courants ainsi que, toujours
chiffrées, les clés d'administration de chaque machine, l'autorité de transport
et les identités mTLS de rôle lorsqu'elles existent. Il ne contient aucune clé
privée d'identité de télémétrie du daemon ni secret de service.

Le kit initial créé lors de la préparation du premier accès reste accepté pour
vérification. Avant une restauration complète, `recovery refresh` le remplace par
le schéma 3 et capture l'état courant de toute la console. Le mot de passe et le
kit doivent rester dans deux domaines de panne distincts.

## Actualisation

L'actualisation :

1. ouvre et vérifie le kit existant avec son mot de passe ;
2. déchiffre seulement en mémoire chaque clé pour vérifier son algorithme ;
3. vérifie la cohérence entre la clé et le certificat de l'autorité mTLS, puis
   chaque paire privée chiffrée et certificat de rôle ;
4. capture la déclaration, les clés d'hôte SSH et le registre d'identités ;
5. remplace atomiquement le fichier du kit en mode `0600`.

Elle ne contacte aucune machine. Elle doit être répétée après un changement
d'autorité, de registre ou de déclaration que l'opérateur veut pouvoir reprendre.

## Restauration

La restauration exige une déclaration absente et un répertoire d'état vide. Elle
valide l'intégralité du kit avant la première écriture, refuse une clé liée à une
machine non déclarée et n'écrase jamais un état existant.

Après restauration, la console retrouve les mêmes machines logiques, clés d'hôte,
identités de télémétrie et autorités chiffrées. L'identité cliente de la console
est restaurée elle aussi afin de reprendre immédiatement une lecture mTLS. La
restauration ne réenrôle pas les daemons et ne déduit jamais une identité depuis
une adresse.

## Preuve P6

Dans le LAB `v1-full`, `lab-console-recovery` a restauré un kit actualisé,
consulté les deux infrastructures existantes puis produit et appliqué un plan
idempotent sans réenrôlement. Un second essai sur un état non vide a été refusé
sans écrasement.

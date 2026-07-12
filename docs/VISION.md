# Vision du projet

## Promesse

Une console souveraine qui enrôle, observe et fait évoluer des infrastructures Linux, du homelab à la PME, sans exposer directement leurs réseaux pour la télémétrie ni rendre leurs services dépendants du pilotage.

## Public

Le produit accompagne un développeur ou homelabber débutant sans lui imposer Git, un cloud ou une plateforme d’observabilité. Il conserve en parallèle une CLI, des fichiers lisibles et des preuves détaillées pour les utilisateurs expérimentés et les petites équipes techniques.

## Progression

Une installation peut commencer avec une machine locale, puis accueillir plusieurs infrastructures composées de mini-PC, de serveurs et de VPS. Elle peut évoluer vers le pilotage distant, la séparation des zones et la haute disponibilité sans réenrôler les machines ni reconstruire les services par principe.

## Architecture en une minute

La console Python vit sur le poste Linux de l’opérateur : elle porte les décisions, les déclarations, les secrets et les accès d’administration. Chaque machine Debian gérée exécute un daemon Go léger et en lecture seule. Un coordinateur Go toujours allumé, placé dans le LAN ou sur un VPS, reçoit et conserve uniquement leur télémétrie signée.

Le chemin d’observation va des daemons vers le coordinateur, puis de la console vers le coordinateur lorsqu’elle veut consulter l’état. Le chemin de changement reste séparé : la console atteint directement les machines par SSH et Ansible après présentation et approbation d’un plan. Ni le daemon ni le coordinateur ne peuvent administrer l’infrastructure.

Une panne de la console ou du coordinateur peut retarder l’observation et les changements, mais ne doit jamais provoquer à elle seule l’arrêt des services déjà déployés.

## Principes

- Le pilotage peut devenir indisponible sans provoquer à lui seul l’arrêt des services.
- La télémétrie ne requiert aucune connexion entrante vers le daemon ou le réseau privé de l’opérateur ; le chemin d’administration reste distinct et explicitement autorisé.
- La compromission d’une machine doit rester confinée à cette machine.
- La sécurité vient d’abord des frontières d’architecture, puis des secrets.
- Le cœur reste léger ; les intégrations avancées ne deviennent pas des dépendances obligatoires.
- Les données de configuration sont durables et lisibles ; la télémétrie est dérivée et reconstructible.
- Les débutants reçoivent un parcours guidé ; les utilisateurs avancés gardent accès aux mêmes concepts et preuves.
- Le produit final pourra exécuter sa console publiée sur un poste Linux approuvé ou dans une VM d’administration. Le laptop de développement de Lucas reste un poste d’édition et de contrôle : aucun build, binaire de travail, test, playbook, service ou dépendance exécutable du projet n’y est lancé ; ces exécutions restent dans le LAB.

## Première étape utile

La première version valide une chaîne minimale : une console Linux en Python audite puis enrôle par Ansible une machine Debian 13 amd64 comme machine disponible, y installe un daemon Go natif et strictement en lecture seule, puis affiche son état courant via la CLI. Cette première inspection par le chemin d’administration reste ponctuelle. Le parcours sécurise ensuite une machine gérée et y installe le même coordinateur Go en mode local ou distant afin de conserver l’état courant et un journal borné lorsque le laptop est éteint. Il propose enfin de créer ou choisir une infrastructure et d’y affecter la machine, sans appliquer de rôle automatiquement.

Le protocole distant, les commandes, le front graphique, les intégrations de runtimes et la haute disponibilité ne sont pas présumés acquis. Ils seront ouverts seulement après preuve du palier précédent.

## Scénario cible de réussite

À long terme, le produit sera considéré comme pleinement réussi lorsqu’il saura déclarer, observer, faire évoluer et restaurer de bout en bout l’infrastructure réelle de référence suivante :

- un VPS Linux comme nœud d’entrée public et façade des services ;
- un mini-PC comme hôte de virtualisation Proxmox ;
- un mini-PC comme passerelle et pare-feu OPNsense ;
- un Raspberry Pi 5 comme serveur de sauvegarde ;
- un service d’identité tel qu’Authelia, Vaultwarden, un portfolio et d’autres services publics ou protégés ;
- des chemins WireGuard distincts pour l’exposition et l’administration, sans exposer directement l’adresse du site domestique.

Ce scénario doit prouver le confinement des zones, la stabilité des mises à jour, l’idempotence, l’absence d’arrêt des services causé par une panne du pilotage, puis la restauration réelle de la console, des secrets et des sauvegardes. Proxmox et OPNsense ne sont jamais traités comme de simples hôtes Debian : ils nécessitent une intégration dédiée ou restent sous gestion externe avec une autorité clairement déclarée.

À ce stade ultérieur, le produit guidera une politique de sauvegarde de type 3-2-1 sans l'enfermer dans un fournisseur : machine locale ou dédiée, stockage objet compatible S3 et autres destinations resteront des adaptateurs. Il distinguera une copie d'une sauvegarde réellement indépendante, isolée ou immuable, et ne déclarera jamais une stratégie valide sans restauration testée. Cette capacité n'appartient pas au périmètre de la V1.

Ce scénario constitue un objectif de version ultérieure et n’élargit pas le périmètre de la V1.

## Fin du recadrage

`AGENTS.md` a été réécrit à la fin du grill. Les anciens rôles et comptes-rendus en cartouche sont remplacés par une collaboration humaine, concise et orientée preuves : un Lead responsable de l’ensemble et, seulement lorsque cela apporte une vraie valeur, un spécialiste temporaire dont le travail reste relu par le Lead.

## Langage partagé

Les termes du produit et leurs relations sont définis dans [`CONTEXT.md`](../CONTEXT.md).

## Pour aller plus loin

Le [`Guide du bâtisseur`](GUIDE-DU-BATISSEUR.md) raconte le produit et ses scénarios sans exiger la lecture des décisions techniques. La [`Roadmap`](ROADMAP.md) transforme cette vision en paliers de développement et preuves LAB.

Une [édition HTML autonome et illustrée](guide-du-batisseur.html) rassemble cette trajectoire sous forme de planches visuelles. Le guide Markdown et la roadmap restent les sources de référence.

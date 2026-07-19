# Contrat `v0.0.3` — Console cliente et Controller de lecture

> État au 19 juillet 2026 : **architecture produit validée, paramètres
> exécutables à terminer**. Ce document autorise le cadrage de `v0.0.3`, pas
> encore la création d'une branche ou l'implémentation. Les choix ouverts à la
> fin doivent être approuvés explicitement avant le code.

## Résultat utilisateur

Un administrateur installe la Console Your Cloud sur Linux ou Windows, lui
associe le Controller privé d'une infrastructure et consulte les deux machines
déjà enrôlées. Il voit leur dernier état `host-health.v1`, l'heure de réception,
la séquence, les lacunes connues et un statut `récent`, `ancien` ou `absent`.

La Console permet de créer l'inventaire local du Controller et d'y rattacher des
identifiants de machines déjà enrôlés. Cette écriture concerne seulement les
données métier du Controller : elle ne délivre ni certificat, ni ordre, ni
modification à une machine ou au Relay.

## Placement validé

```text
Appareil administrateur
`- Console installée et signée
   |- frontend embarqué
   |- aucun serveur local, aucune page localhost
   |- associations de Controllers approuvées
   |- identité d'appareil et sessions protégées
   `- API privée authentifiée
                 |
                 v
Controller d'une infrastructure — backend uniquement, aucun frontend
`- lecture privée authentifiée --> Relay

Daemon -- POST mTLS --> Relay
`- aucune connaissance du Controller ou de la Console
```

Un **frontend embarqué** désigne les fichiers de l'interface inclus dans
l'artefact signé de la Console. Ils peuvent employer des technologies Web sans
être servis par un site, un Controller ou un serveur `localhost`.

Une **enveloppe cliente** désigne le programme natif léger qui affiche ce
frontend, contrôle le réseau, accède au stockage sécurisé du système et borne les
capacités exposées à l'interface. Son choix technique reste ouvert.

## Frontières d'autorité

- La Console est un client multi-Controller ; elle n'est l'autorité d'aucune
  infrastructure et ne possède aucun secret de machine, de Relay, de runner ou
  de chemin d'action.
- Un Controller porte l'autorité métier d'exactement une infrastructure. Il
  authentifie l'humain et l'appareil, autorise la consultation, conserve
  l'inventaire attendu et interprète les observations.
- Le Controller expose une API privée, jamais un frontend. Un Controller
  compromis ne peut donc pas fournir directement du code exécutable à la
  Console. Ses réponses restent néanmoins des données hostiles à valider et à
  rendre sans interprétation active.
- Le Relay authentifie, borne, persiste et accuse les observations. Il ne porte
  aucun utilisateur, rôle, inventaire métier, statut d'interface ou action.
- Le Controller initie la lecture du Relay sur une frontière distincte du
  listener d'ingestion des Daemons, ou sur une séparation équivalente prouvée.
- Relay et Controller peuvent cohabiter dans une petite infrastructure avec des
  processus, comptes, identités, stockages et politiques séparés. Ils partagent
  alors malgré tout la zone de compromission `root` de l'hôte.

## Plateformes et distribution

`v0.0.3` produit une Console fonctionnelle sur Linux et Windows depuis le même
frontend responsive. Les artefacts proviennent des mêmes sources, sont bornés,
inventoriés et signés. Aucun téléchargement de code ou de composant d'interface
depuis un Controller n'est permis.

Le téléphone conserve le même contrat visuel et réseau, mais Android et iOS
restent hors de ce palier. Leur empaquetage, signature, stockage sécurisé, cycle
de vie en arrière-plan et distribution demanderont une preuve propre.

Tout build, test, serveur, lancement ou preuve de la Console et du Controller
s'exécute dans le LAB ou un runner isolé. Le laptop de développement reste
limité à Git, l'édition, aux contrôles statiques autorisés et au pilotage de
`labctl`.

## Authentification à trois niveaux

L'accès réseau privé, l'identité de l'appareil et l'identité humaine sont trois
contrôles distincts :

1. le réseau privé borne les endpoints joignables sans prouver l'identité
   humaine ;
2. la Console présente une identité d'appareil propre, révocable et distincte
   pour chaque association ;
3. le Controller vérifie une authentification humaine forte avant d'émettre une
   session courte liée à cet appareil et à cette infrastructure.

Une **passkey** est une preuve cryptographique conservée par l'authentificateur
de l'appareil ; le Controller vérifie un challenge sans recevoir le secret
privé. Elle constitue le premier profil local visé. OIDC/SSO reste facultatif
pour les organisations et ne donne jamais d'autorité implicite sur plusieurs
Controllers.

Le frontend ne reçoit aucun secret long terme. L'enveloppe cliente limite
l'accès au stockage sécurisé du système et n'expose à l'interface que des
opérations nommées. Les formats d'identité, la récupération, les durées, la
rotation, la révocation et le stockage exacts restent à contracter.

## Frontend inclus dans le palier

Avant le premier écran, le dépôt fixe un système visuel commun :

- palette sémantique et proportions d'usage ;
- typographies, grille, espacements et densité ;
- navigation, boutons, formulaires, tableaux, cartes, icônes et retours d'état ;
- états `chargement`, `vide`, `récent`, `ancien`, `lacune`, `indisponible`,
  `refusé` et `erreur` ;
- adaptation fenêtre étroite, desktop et préparation téléphone ;
- contraste, navigation clavier, focus visible et aucune information portée
  uniquement par la couleur.

Aucune maquette Figma n'est requise. Les règles et composants versionnés dans le
dépôt forment le contrat visuel, puis les écrans les appliquent sans style local
opportuniste.

## Données minimales visibles

Pour chaque machine attendue, le Controller rapproche :

- l'identifiant de machine et son libellé métier local ;
- le dernier profil et la dernière séquence acceptés ;
- l'heure d'observation déclarée par le Daemon ;
- l'heure locale de réception du Relay ;
- les lacunes persistées par le Relay ;
- les valeurs bornées de `host-health.v1` ;
- la fraîcheur calculée par la politique du Controller.

Le Relay fournit un instantané, pas un historique. Si plusieurs observations
arrivent entre deux lectures, seule la dernière peut être visible. Ce
remplacement n'est pas une lacune du tampon Daemon et l'interface ne doit jamais
inventer les séquences intermédiaires.

## Preuve de sortie à rendre exécutable

La preuve finale devra au minimum démontrer :

- artefacts Linux et Windows issus de la révision annoncée, inventoriés et
  signés ;
- aucun frontend hébergé, serveur local ou téléchargement de code depuis un
  Controller ;
- Controller inconnu, identité d'appareil inconnue ou révoquée, authentification
  humaine invalide, session expirée ou révoquée et mauvaise infrastructure
  refusés ;
- séparation des sessions entre deux Controllers synthétiques ;
- mauvais certificat, endpoint, méthode, route, portée, schéma ou taille refusé
  sur les frontières Console–Controller et Controller–Relay ;
- inventaire libre non borné, machine non enrôlée et champ d'interface inconnu
  refusés ;
- Relay indisponible, instantané vide, donnée ancienne, lacune, reprise et
  redémarrages rendus honnêtement sans faux état actuel ;
- frontend sans secret long terme et stockage sécurisé inaccessible aux données
  d'interface hors des opérations autorisées ;
- fonctionnement clavier, contrastes et états critiques vérifiés ;
- aucun listener Daemon, aucun canal d'action et aucune mutation des machines.

## Exclusions absolues

`v0.0.3` n'ajoute aucun Ansible métier, SSH d'action, plan appliqué, Auxiliaire
local, WireGuard, service OCI, téléphone, navigateur public, passerelle Web,
Proxmox, OpenStack, worker d'automatisation, projet IaC, série temporelle,
plugin libre, scan LAN, renouvellement automatique ou élection de Relay.

## Paramètres encore ouverts avant le code

1. enveloppe cliente et framework frontend, avec leur coût, leurs dépendances et
   leur modèle de mise à jour ;
2. format, signature, inventaire et provenance des artefacts Linux et Windows ;
3. API Console–Controller : transport LAB, endpoint, identité, méthodes, routes,
   portées, schémas, limites et erreurs ;
4. identité d'appareil, stockage sécurisé par plateforme, passkey, récupération,
   session, durées, rotation et révocation ;
5. API Controller–Relay : listener séparé, CA, certificats, endpoint, méthodes,
   routes, portées, schémas, limites, horloges, instantané et reprise ;
6. stockage de l'inventaire du Controller, valeurs exactes de fraîcheur et bornes
   des libellés métier ;
7. tokens du système visuel et liste exacte des premiers écrans ;
8. runners et machines LAB qui construisent et prouvent Linux et Windows sans
   exécuter le produit sur le laptop.

## Point d'arrêt

La prochaine tâche reprend ces huit décisions par petits groupes. Après leur
validation explicite, elle crée la branche `console-controller`, implémente
uniquement ce contrat et conserve les preuves et limites réellement exécutées.
Avant cette validation, aucune branche, dépendance ou ligne de code produit
n'est ajoutée.

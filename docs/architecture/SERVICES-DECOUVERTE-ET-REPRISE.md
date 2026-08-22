# Les services : découverte et reprise

> **Ce document fixe ce que Your Cloud peut faire d'un service, et pourquoi.**
> Il remplace `RESPONSABILITE-EXTERNE.md`, qui décrivait un modèle abandonné :
> les modes « géré » et « externe » n'existent plus. Ce qu'il fixe engage le
> produit — un écran qui offrirait un verbe que ce contrat refuse est un défaut,
> pas une variante.

La frontière de l'observation elle-même — ce que le Daemon relève, ce qu'il
refuse, ce que le Relay ne peut pas lui demander — est fixée par la
[chaîne d'observation](CHAINE-D-OBSERVATION.md). Ce contrat s'y appuie et ne la
redit pas.

## Ce qui a changé, et pourquoi le dire ici

Le modèle précédent demandait à l'utilisateur de **déclarer** ce qui tournait
déjà sur ses machines, puis distinguait un mode où Your Cloud possédait
l'autorité d'un mode où il se contentait de regarder. Deux choses l'ont tué :

- la **double déclaration** — déposer un fichier sur la machine *et* redéclarer
  dans l'app — demandait un terminal, ce que le cap refuse désormais ;
- les **modes** décrivaient une possession, alors que la vraie question est plus
  simple et plus vérifiable : **sait-on refaire ce service ?**

## La règle unique : les verbes suivent la recette

La frontière n'est pas « qui a posé ce service » mais **« connaît-on sa
recette »** — son image épinglée par digest, ses volumes, son environnement, son
port.

| Situation | Voir et superviser | Démarrer, arrêter, redémarrer | Mettre à jour, sauvegarder, publier, recréer |
|---|---|---|---|
| Recette connue — créé dans l'app **ou** repris | oui | oui | **oui** |
| Conteneur découvert, recette inconnue | oui | oui, **avec approbation** | non → « Reprendre ce service » |
| Service système de l'OS | vue machine seulement | **non** | **non** |
| Processus nu, ni unité ni conteneur | vue machine seulement | **non** | **non** |

Ce tableau repose sur un fait technique, pas sur une préférence : **« modifier »
un conteneur en place n'existe pas.** Un conteneur est immuable ; changer une
option, c'est le détruire et le recréer. Lire sa configuration est possible,
l'éditer non. « Gérer » un conteneur trouvé serait donc de toute façon une
recréation — c'est exactement ce que la reprise fait, proprement et sous
approbation.

**Your Cloud ne gère jamais les services système du système d'exploitation.**
Ni `getty`, ni `dbus`, ni `cron`. Ils apparaissent dans la vue machine parce
qu'ils occupent des ports, jamais dans la liste des services.

## Ce que la découverte donne, et ce qu'elle ne donne pas

Le Daemon énumère localement, sans rien recevoir d'en haut : unités systemd et
ports en écoute. Cette énumération est **une capacité de sa version, approuvée
dans un profil** — jamais une commande venue du Relay.

**L'identité d'un service découvert est son nom d'unité ou de conteneur, jamais
son port.** Un service qui redémarre ou change de port reste le même service. Un
processus nu, sans unité ni conteneur, n'a pas d'identité stable : il est montré
comme « port en écoute », pas comme service.

Deux écrans, deux périmètres :

- **Services** ne montre que l'applicatif — conteneurs et services reprenables ;
- **la vue machine** porte « ports en écoute » : la surface d'exposition réelle,
  services système compris. Un port inattendu qui apparaît se voit.

La découverte **ne donne aucune recette**. Elle dit qu'un service existe et
qu'il écoute ; elle ne dit pas comment le refaire. Le détail riche d'un
conteneur — image exacte, volumes, environnement — n'est lu qu'à la reprise, par
un audit ponctuel approuvé.

## La reprise, en cinq temps

1. Sur un service découvert : **« Reprendre ce service »**.
2. **Un audit approuvé, en lecture seule.** La machine rend la configuration
   réelle : image et digest, volumes, environnement, ports. **Rien n'est
   modifié.** C'est le premier usage d'un privilège ponctuel, et il est nommé
   comme tel.
3. **L'humain relit et valide.** L'app ouvre la modal de création, pré-remplie
   avec ce qui a été lu. Il ajuste si besoin, puis la recette est gelée. C'est
   lui qui valide ce que Your Cloud croit avoir compris — jamais l'inverse.
4. **Le déploiement.** L'ancien conteneur est arrêté **et conservé** ; le service
   redémarre depuis la recette, sous compte dédié cloisonné, en unité posée par
   plan.
5. **Le service est repris à cet instant** : quand il tourne depuis la recette
   validée. **L'audit seul ne reprend rien.**

Le chemin détaillé de cette bascule, sa fenêtre de retour et son point de
non-retour appartiennent au
[cycle de vie des services](CYCLE-DE-VIE-DES-SERVICES.md).

En une phrase : **démarrer et arrêter pilotent l'existant sans le connaître ; la
reprise donne la recette, et la recette donne tous les autres verbes.**

## Ce que l'app annonce ne pas pouvoir faire

Un produit qui tait ses limites les fait découvrir au pire moment. Sur un
service dont la recette est inconnue, l'app dit, en propres termes, qu'elle ne
sait ni le mettre à jour, ni le sauvegarder, ni le republier, ni le recréer
ailleurs — et elle nomme le geste qui lève cette limite : la reprise.

Sur un processus nu, elle dit ce qu'elle sait déployer : des images
conteneurisées. Elle ne propose pas un verbe qu'elle refusera ensuite.

## Les quatre invariants que ce contrat ne lève pas

1. **Jamais d'écriture hors plan approuvé** — sur rien. Démarrer et arrêter
   passent aussi par une approbation.
2. **Jamais afficher comme su ce qui est supposé.** La fraîcheur et la source
   d'une information restent visibles. Ce sont des attributs d'affichage, pas
   des états de premier rang.
3. **Pas de canal descendant** du Controller vers le Daemon, et **pas de scan du
   réseau**. L'énumération est locale à des machines déjà enrôlées.
4. **Pas de privilège permanent d'observation.** Le privilège de l'audit de
   reprise est ponctuel, approuvé, en lecture seule.

## Ce qui reste à borner avant d'implémenter

Nommé plutôt que tu, et sans valeur inventée :

- **les bornes de l'enveloppe d'inventaire.** L'enveloppe d'observation actuelle
  est bornée à 4 096 octets ; un inventaire de machine exigera sa propre borne,
  choisie avec le premier profil réel ;
- **la liste exacte de ce que l'audit de reprise lit.** Elle doit être fermée et
  nommée, comme l'est un profil d'observation ;
- **la forme du démarrage et de l'arrêt sur un conteneur au runtime Docker
  root.** L'acte passe par l'Auxiliaire privilégié — faisable — mais sa forme
  exacte se décide avec le premier cas réel.

Aucun de ces trois points n'autorise à livrer sans l'avoir tranché.

## Ce que la preuve devra constater

- un service découvert apparaît par son **nom d'unité ou de conteneur**, et
  survit à un changement de port ;
- un service système de l'OS n'offre **aucun verbe** ;
- l'audit de reprise **n'écrit rien** — l'empreinte de la machine est identique
  avant et après ;
- un service repris **tourne depuis sa recette**, et l'ancien conteneur est
  encore là ;
- l'app **nomme** ce qu'elle ne sait pas faire d'un service à recette inconnue.

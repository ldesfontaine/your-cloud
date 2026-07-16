# Chaîne d'observation — Daemon, Relay et signal de présence

> Statut : guide d'architecture vivant. Il décrit ce qui est réellement prouvé
> par `v0.0.1`, puis sépare les décisions V1 qui ne sont pas encore
> implémentées. La V1 complète n'est pas déclarée prouvée.

## Les notions avant le schéma

Une **chaîne d'observation** est le chemin suivi par une information depuis la
machine qui la produit jusqu'au composant qui permet de la consulter. Ce chemin
transporte des faits observés ; il ne transporte aucun ordre vers les machines.

Pour lire les schémas sans confondre installation, programme et exécution :

- l'**Agent** est l'installation locale de Your Cloud sur une machine ;
- un **artefact** est le fichier exécutable construit pour une version ; dans
  `v0.0.1`, ce fichier unique s'appelle `your-cloud` ;
- un **rôle** est une capacité choisie au démarrage de cet exécutable, comme
  `daemon` ou `relay` ;
- un **processus** est une exécution en mémoire. Deux rôles issus des mêmes
  octets restent deux processus lorsqu'ils sont lancés séparément ;
- une **autorité** est l'ensemble des ressources qu'un processus peut lire,
  modifier ou joindre. Des comptes, configurations et cycles systemd séparés
  empêchent les rôles de partager implicitement la même autorité ;
- un **signal de présence** est le petit message par lequel un Daemon indique
  au Relay qu'il vient de communiquer.

La **Présence n'est donc pas un troisième processus**. Dans `v0.0.1`, c'est le
contrat de données partagé entre le Daemon et le Relay. Le package Go
`internal/presence` décrit ce contrat ; son nom ne crée pas un rôle à déployer.

## Vue rapide

```text
machine du LAN                              VPS simulé
Agent                                      Agent
`- processus Daemon                        |- processus Daemon
      |                                    |      |
      | POST /v0/presence                  |      | POST /v0/presence
      | HTTP sortant                       |      | HTTP local
      +-----------------------------+      |      |
                                    v      v      |
                                  processus Relay-+
                                          |
                                          | QUERY /v0/machines
                                          v
                             client de consultation du LAB
                             future App : décidée, non présente ici
```

Le Daemon produit et envoie. Le Relay reçoit, valide, mémorise le dernier
signal et calcule son âge. Le client consulte cette vue. Aucun de ces échanges
ne demande au Daemon d'exécuter une commande.

<!-- coherence: AGENT-AUTHORITY:start -->
## Placement réellement prouvé par `v0.0.1`

Une **machine candidate Relay** est une machine sur laquelle l'administrateur a
explicitement autorisé le rôle Relay. La simple présence de l'exécutable ne
suffit pas. `v0.0.1` matérialise cette autorisation par un manifeste local
provisionné par root et vérifié avant l'ouverture du port.

```text
lab-console
`- construit et teste ; aucun rôle produit permanent

lab-machine-1 · LAN privé · non candidate
/usr/local/lib/your-cloud/your-cloud
`- your-cloud daemon

lab-coordinateur · VPS simulé · seule candidate Relay
/usr/local/lib/your-cloud/your-cloud
|- your-cloud daemon
`- your-cloud relay

lab-machine-2
`- aucun composant Your Cloud dans l'état final de la preuve
```

Les mêmes octets sont installés sur `lab-machine-1` et `lab-coordinateur`. Sur
le VPS simulé, les deux rôles ont des PID, comptes dynamiques, configurations
et unités systemd distincts. Ils peuvent donc démarrer, échouer et redémarrer
indépendamment, même si une défaillance de l'artefact commun peut toucher les
deux.

## Rôles et autorités

### Daemon

Le **Daemon** est le processus permanent d'observation de l'Agent. Dans
`v0.0.1`, il ne relève encore aucune métrique système : il connaît seulement
son identifiant synthétique, la version de l'exécutable et l'heure courante.

Ses actions sont bornées :

1. valider son identifiant et les bornes HTTP actuellement reconnues pour la
   destination Relay ;
2. construire un signal de présence ;
3. ouvrir une connexion sortante vers le Relay ;
4. envoyer immédiatement, puis toutes les secondes ;
5. attendre exactement `204 No Content` ;
6. réessayer après une indisponibilité sans s'arrêter ni produire un log à
   chaque seconde.

Le Daemon n'écoute aucun port et ne reçoit aucun ordre. Il journalise seulement
la première transition vers `presence unavailable`, puis le retour
`presence recovered`. Cette limitation évite qu'une panne répétée du Relay
remplisse les journaux avec un message identique par tentative.

### Relay

Le **Relay** est le processus qui reçoit les observations des Daemons et expose
une vue consultable. Il ne relaie pas du trafic Web, ne découvre pas le LAN et
ne transporte aucune action vers les Daemons.

Avant d'assembler son serveur HTTP, il vérifie :

- l'adresse d'écoute exacte autorisée par ce palier ;
- l'existence du manifeste candidat au chemin fixe
  `/etc/your-cloud/relay-candidate.json` ;
- un répertoire et un fichier réels, détenus par root et non modifiables par le
  groupe ou les autres utilisateurs ;
- un document JSON court contenant exactement le schéma et le rôle attendus.

En l'absence de cette autorisation locale, le Relay refuse avant toute écoute.
Le manifeste protège contre une activation accidentelle ; il n'est ni une
identité réseau, ni une élection, ni une protection contre root.

Une fois démarré, le Relay :

1. représente toutes les machines de la liste positive comme `absent` ;
2. reçoit et valide les signaux ;
3. conserve uniquement le dernier signal valide de chaque machine, en mémoire ;
4. ajoute sa propre heure de réception ;
5. calcule `recent` ou `old` à partir de cette heure ;
6. rend la vue disponible à un client de consultation.

<!-- coherence: AGENT-AUTHORITY:end -->

<!-- coherence: V1-OBSERVATION:start -->
### Signal de présence

Le **signal de présence `v0.0.1`** est un objet JSON contenant exactement :

| Champ | Produit par | Utilisé pour | Limite |
|---|---|---|---|
| `machine_id` | configuration locale du Daemon | rattacher le signal à une machine autorisée | syntaxe contrôlée et liste positive exacte |
| `daemon_version` | exécutable | refuser une version incompatible | exactement `v0.0.1` |
| `sent_at` | horloge de la machine | information visible | RFC 3339, jamais utilisé pour décider de la fraîcheur |

Le Relay ajoute `received_at` avec sa propre horloge. Cette distinction est
essentielle : une horloge de machine fausse ne peut pas maintenir
artificiellement un état `recent`.

## Moments du cycle

Une **séquence** décrit l'ordre des interactions ; elle ne signifie pas qu'un
coordinateur central ordonne toutes les étapes.

```text
Administrateur       systemd Daemon        systemd Relay       client LAB
      |                     |                    |                   |
      | installe Agent      |                    |                   |
      |-------------------->| démarre            |                   |
      |                     |                    |                   |
      | active candidature Relay sur le VPS      |                   |
      |----------------------------------------->| vérifie manifeste |
      |                                         | ouvre :8443       |
      |                     | POST présence      |                   |
      |                     |------------------->| valide + mémorise |
      |                     |<-------------------| 204               |
      |                     |                    |                   |
      |                     |                    |<------------------| QUERY {}
      |                     |                    |------------------>| vue machines
      |                     |                    |                   |
      |                     | nouvel envoi après 1 s                 |
```

Le Daemon peut démarrer avant le Relay : son premier envoi échoue, puis ses
tentatives reprennent automatiquement. Le Relay n'a pas besoin de démarrer le
Daemon et ne se connecte jamais à lui.

## Schéma réseau HTTP actuel

Une **frontière réseau** est l'endroit où une entrée non fiable arrive dans un
processus. Dans `v0.0.1`, cette frontière est volontairement petite et reste
limitée au LAB :

```text
origine                              destination Relay
lab-machine-1 Daemon  ----HTTP---->  192.168.242.103:8443
lab-coordinateur Daemon --HTTP---->  192.168.242.103:8443
client LAB             ----HTTP---->  192.168.242.103:8443

écriture :     POST  /v0/presence
consultation : QUERY /v0/machines
```

Le package Daemon exige actuellement le schéma `http`, un hôte non vide et
l'absence de chemin, puis ajoute `/v0/presence`. Le script d'installation borne
en plus l'origine exacte à `http://192.168.242.103:8443`. L'audit statique a
toutefois montré que le binaire ne revérifie pas encore cette valeur exacte et
ne refuse pas tous les composants annexes d'une URL. Le Relay, lui, revérifie
son écoute exacte sur `192.168.242.103:8443`. Ces valeurs prouvent un scénario
LAB ; elles ne constituent pas une configuration de production.

### Pourquoi `POST` pour le signal

Une **écriture** modifie l'état conservé par le serveur. Chaque signal valide
remplace la dernière présence de la machine et crée une nouvelle heure de
réception côté Relay. `POST /v0/presence` exprime donc cette écriture. Le corps
doit être un JSON de 512 octets au maximum, avec `Content-Type:
application/json`. Un succès reçoit `204 No Content`.

### Pourquoi `QUERY` pour consulter

Une méthode HTTP est dite **sûre** lorsqu'elle est destinée à lire sans demander
de modification de l'état du serveur. Une opération est **idempotente** lorsque
la répéter n'ajoute pas d'effet de bord. Ces propriétés ne promettent pas une
réponse octet pour octet identique : l'heure et l'âge des présences peuvent
continuer d'évoluer entre deux lectures.

`QUERY /v0/machines` exprime cette consultation avec un corps structuré. Dans
`v0.0.1`, aucun filtre n'existe encore : le corps doit être exactement l'objet
JSON vide `{}`, avec `Content-Type: application/json`, et rester inférieur ou
égal à 32 octets. Le Relay annonce le format accepté avec :

```text
Accept-Query: "application/json"
```

Répéter cette requête ne modifie pas le stockage du Relay. L'ancien
`GET /v0/machines` est refusé avec `405 Method Not Allowed`; un corps absent,
`null`, non JSON, trop grand, contenant un filtre ou suivi d'un second objet est
également refusé. La réponse valide contient l'heure de génération, la limite
d'ancienneté et la vue des machines.

Un **cache HTTP** est un intermédiaire capable de conserver une réponse et de
la réutiliser. La RFC rend une réponse `QUERY` cacheable ; or `v0.0.1` ne renvoie
pas encore `Cache-Control: no-store`. La preuve directe du LAB n'incluait aucun
cache, mais cette directive et son test deviennent obligatoires avant d'ajouter
l'App, un proxy ou un autre intermédiaire.

La **partie query d'une URI** est le texte situé après `?`. Le corps JSON est le
seul emplacement prévu ici pour décrire la consultation. Le handler actuel
ignore pourtant encore une partie query au lieu de la refuser. Cet écart doit
être fermé et testé avant d'élargir le contrat HTTP.

## États `absent`, `recent` et `old`

Un **état de présence** décrit seulement l'âge du dernier signal reçu. Il ne
prouve ni la santé complète de la machine, ni celle de ses services, ni
l'absence de compromission.

- `absent` : le Relay n'a reçu aucun signal depuis son propre démarrage ;
- `recent` : un signal valide a été reçu depuis moins de quatre secondes ;
- `old` : le dernier signal a été reçu il y a au moins quatre secondes.

```text
                         premier signal valide
             +------------------------------------------+
             |                                          v
        +---------+                                +----------+
        | absent  |                                | recent   |
        +---------+                                +----------+
             ^                                          |
             | redémarrage du Relay                     | âge >= 4 s
             | mémoire perdue                            v
             +-------------------------------------+----------+
                                                   | old      |
                                                   +----------+
                                                        |
                                                        | nouveau signal valide
                                                        +----------> recent
```

Un message refusé ne change pas cet automate. Le seuil utilise `received_at`,
pas `sent_at`.

Une **horloge monotone** mesure une durée écoulée sans être perturbée par une
correction de l'heure civile. L'intention est de comparer les réceptions avec
cette horloge côté Relay. L'implémentation `v0.0.1` convertit toutefois les
instants en UTC avant le calcul et perd l'information monotone de Go. Les
transitions observées dans le LAB restent prouvées, mais un saut de l'horloge du
Relay n'a pas encore été injecté : ce point doit être corrigé et automatisé
avant de donner au seuil une valeur opérationnelle.

## Pannes et redémarrages

| Événement | Effet visible | Ce qui continue |
|---|---|---|
| arrêt d'un Daemon | sa machine devient `old` après quatre secondes | l'autre Daemon et le Relay |
| retour du Daemon | son premier nouveau signal la rend `recent` | le PID Relay ne doit pas changer |
| Relay indisponible | les envois échouent et le Daemon réessaie | les Daemons restent démarrés |
| redémarrage du Relay | toutes les machines redeviennent `absent` | les Daemons renvoient ensuite leurs signaux |
| manifeste candidat invalide | le Relay échoue avant écoute | le Daemon colocalisé reste indépendant |
| désactivation du Relay | unité, configuration et manifeste Relay sont retirés | le Daemon et l'artefact commun restent installés |
| retrait complet de l'Agent | les deux rôles doivent être arrêtés avant suppression | aucun processus orphelin n'est accepté |

Le stockage Relay est volontairement en mémoire dans `v0.0.1`. Un redémarrage
ne doit donc jamais être présenté comme une continuité historique.

## Où vit le code réel

Un **point d'entrée** transforme des arguments de lancement en objets métier et
gère le cycle du processus. Une **logique métier** exprime les validations et
décisions propres au produit. Un **outil de déploiement** installe ou retire ces
éléments sur une machine.

```text
cmd/your-cloud/
|- main.go       choisit strictement le rôle daemon ou relay
|- daemon.go     assemble le Sender et son arrêt propre
`- relay.go      vérifie l'écoute et assemble le serveur HTTP

internal/
|- presence/     schéma, limites et validation du signal partagé
|- daemon/       construction, envoi, retry et logs du Daemon
`- relay/        manifeste candidat, frontière HTTP et stockage mémoire

deploy/v0.0.1/
|- unités systemd
|- installation et retrait de l'Agent
|- activation et désactivation explicites du Relay
`- pilote de refus HTTP hostile réservé à la preuve LAB
```

La logique réelle vit donc principalement dans `internal/`. En Go, ce nom a
aussi un effet : les packages concernés ne peuvent pas être importés directement
depuis un autre module. `cmd/` reste la couture de l'exécutable et de ses cycles
de vie. `deploy/` ne devient pas un troisième composant permanent : ses scripts
préparent les fichiers et unités puis peuvent disparaître de la cible.

Le pilote `prove-hostile-relay` est spécifique à la preuve LAB. Les scripts
d'installation et les unités systemd décrivent, eux, le cycle de déploiement de
ce palier, mais ne constituent pas encore un installateur de production V1.

## Ce qui est prouvé, décidé ou absent

| Niveau | Chaîne d'observation concernée |
|---|---|
| **Prouvé dans `v0.0.1`** | un exécutable commun ; processus Daemon et Relay isolés ; signal minimal ; HTTP `POST` et `QUERY` ; schémas et tailles bornés ; liste de deux machines LAB ; dernier état en mémoire ; transitions `absent`/`recent`/`old` ; refus Relay par défaut ; retraits fail-closed |
| **Décidé pour la V1, non encore prouvé ici** | identité propre à chaque Daemon ; transport mTLS ; collecteurs nommés ; tampon local borné et lacunes visibles ; enregistrement durable côté Relay ; consultation HTTPS authentifiée par l'App |
| **Absent de ce contrat** | Auxiliaire local ; commande distante ; plugin arbitraire ; scan du LAN ; élection, réplication ou remplacement automatique du Relay ; base ou historique durable ; métriques système réelles |

Cette séparation doit rester visible à chaque évolution. Ajouter un dessin V1
ne transforme jamais une décision en implémentation ou en preuve.
<!-- coherence: V1-OBSERVATION:end -->

## Limites et sécurité proportionnée

Une **valeur sûre par défaut** laisse une capacité sensible désactivée jusqu'à
une autorisation explicite. Le refus du Relay sans manifeste applique ce
principe. Le compte non privilégié du Daemon, les processus distincts, les
listes positives, les corps bornés et les délais HTTP contribuent aussi au
moindre privilège, à la réduction de surface et à la séparation des
responsabilités recommandés par
[OWASP Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html).

Ces choix participent de manière proportionnée aux mesures de gestion des
risques, de contrôle d'accès, de développement sûr, de continuité et de mesure
d'efficacité citées par
[NIS2, article 21](https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555).
Ils ne suffisent pas à déclarer Your Cloud ou son utilisateur conforme à OWASP
ou NIS2.

Les limites actuelles restent explicites :

- HTTP n'apporte ni chiffrement ni authentification ; le port `8443` ne change
  pas cette réalité ;
- la liste d'identifiants autorisés n'authentifie pas la machine émettrice ;
- un pair capable d'atteindre le Relay peut lire la vue ou usurper un signal
  autorisé ;
- root conserve l'autorité de modifier ou contourner les fichiers locaux ;
- un redémarrage Relay perd l'état mémoire ;
- un défaut de l'artefact partagé peut toucher plusieurs rôles malgré leur
  isolation d'exécution ;
- une présence `recent` ne garantit pas la véracité d'une machine compromise.

La V1 devra apporter ses propres preuves pour mTLS, identités, tampon borné,
persistance et App. Ce document ne les déduit pas du succès de `v0.0.1`.

## Sources et évolution de ce document

Ce guide relie plusieurs sources sans les remplacer :

- le vocabulaire du produit reste dans [`CONTEXT.md`](../../CONTEXT.md) ;
- les contraintes durables de l'Agent sont dans
  [`CAP.md`](../projet/CAP.md) ;
- la ligne d'arrivée V1 est dans
  [`objectifs/v1/README.md`](../objectifs/v1/README.md) ;
- le contrat exécutable du palier est dans
  [`CONTRAT-V0.0.1.md`](../objectifs/v1/CONTRAT-V0.0.1.md) ;
- les résultats réellement exécutés sont dans le
  [rapport LAB `v0.0.1`](../lab/v0.0.1-presence.md) ;
- les contrôles, incidents et écarts à automatiser sont dans le
  [registre des tests](../contribution/TESTS.md) ;
- la vue d'ensemble des autres composants reste dans
  [`ANATOMIE.md`](ANATOMIE.md).

Lorsqu'une évolution modifie :

- un terme métier, elle commence par `CONTEXT.md` ;
- le rôle ou l'autorité d'un composant, elle propage le cap, l'objectif,
  l'anatomie et ce guide selon le registre de cohérence ;
- le schéma, la méthode HTTP, les états ou les limites d'un palier, elle met à
  jour son contrat, son code, ses tests et ce guide ;
- un résultat réellement exécuté, elle l'inscrit d'abord dans un rapport LAB ;
- un flux visuel, elle met à jour la source Markdown et son édition HTML dans le
  même changement.

Chaque mise à jour conserve la distinction **décidé / implémenté / prouvé**, et
nomme les limites que l'automatisation ne sait pas encore vérifier.

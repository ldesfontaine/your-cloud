# Stratégie et registre d'automatisation des tests

> Statut : stratégie active et registre des régressions. Les P0, P1 et P2 du
> pilote sont automatisés ; ce document n'est toujours ni un journal d'exécution
> ni une preuve. La référence post-réorganisation conservée dans la
> documentation est le run LAB `20260717T100150Z-1543398`, décrit dans le
> [rapport `v0.0.1`](../lab/v0.0.1-presence.md). Il a réussi depuis les chemins
> réorganisés avant le durcissement final de la CI et du banc de preuve ;
> `20260717T093905Z-1478107` reste sa référence pré-réorganisation. L'identité
> exacte d'un rejeu courant appartient à son dossier d'artefacts non versionné.

Ce registre conserve les contrôles réalisés, les difficultés rencontrées et le
travail restant pour rejouer les vérifications sans intervention manuelle. Il
distingue la couverture automatisée de `v0.0.1` de la preuve assistée de
`v0.0.2` ; une ligne planifiée ne constitue jamais une preuve.

## Vocabulaire de travail

- Une **assertion** compare automatiquement un résultat observé avec le résultat
  attendu et termine en échec si les deux diffèrent.
- La **préparation** place les sources, l'artefact, les configurations et les VM
  dans l'état initial nécessaire au test.
- L'**orchestration** ordonne les actions entre les processus et les VM : arrêt,
  démarrage, requête, attente bornée puis observation.
- Le **nettoyage** retire les processus et fichiers temporaires ou restaure un
  état final annoncé, même après un échec.
- Une **preuve LAB** relie une version des sources à un environnement identifié,
  aux commandes réellement exécutées et à leurs résultats. Un test vert sans
  ce contexte ne devient pas, à lui seul, une preuve publiée.
- Un **contrôle générique** vérifie un contrat de source ou d'outil sans exiger
  la topologie métier complète. Générique ne signifie pas « autorisé sur le
  laptop » : il s'exécute dans le runner isolé prévu par le projet.

Les tableaux utilisent trois niveaux : `automatique` signifie qu'une commande
porte déjà l'assertion ou l'étape concernée ; `assisté` signifie qu'un script
réalise une partie du travail mais qu'une personne enchaîne ou interprète encore
les étapes ; `manuel` signifie que l'action ou la conclusion dépend encore
d'une personne.

## Stratégie durable

Les contrôles progressent du plus petit au plus représentatif. Une couche ne
remplace pas la précédente : elle répond à une question différente.

1. **Statique** : les sources, scripts et liens sont-ils formés comme attendu ?
2. **Unitaire et hostile** : chaque contrat refuse-t-il les entrées invalides
   sans réseau ni VM métier ?
3. **Frontière HTTP vivante** : un Relay réellement lancé conserve-t-il le même
   comportement face aux requêtes hostiles ?
4. **Cycle multi-VM** : placement, systemd, processus, ports, retrait et
   réinstallation produisent-ils l'état annoncé ?
5. **Restitution visuelle** : la synthèse rend-elle fidèlement les observations
   déjà collectées, sans fabriquer une nouvelle conclusion ?

Toute exécution du produit, des tests, du build ou d'un serveur reste dans
`lab-console` ou une autre VM LAB isolée. Le laptop peut éditer, inspecter Git,
contrôler l'inventaire et piloter `labctl`, conformément aux
[règles LAB](../lab/README.md).

L'arborescence rend cette frontière visible :

- [`tests/checks/`](../../tests/checks/) contient les contrôles génériques,
  réutilisables dans un runner CI isolé ;
- [`tests/lab/v0.0.1/`](../../tests/lab/v0.0.1/) contient l'orchestrateur, les
  scénarios distants et la restitution de la preuve multi-VM ;
- [`tests/lab/v0.0.2/`](../../tests/lab/v0.0.2/) contient seulement les
  auxiliaires synthétiques déjà utilisés par la preuve assistée, pas encore un
  orchestrateur multi-VM ;
- [`deploy/v0.0.1/`](../../deploy/v0.0.1/) et
  [`deploy/v0.0.2/`](../../deploy/v0.0.2/) ne contiennent que les cycles de vie
  et unités installables de leur contrat, jamais un scénario hostile.

Une image CI ordinaire peut fournir la première couche, mais elle ne remplace
pas automatiquement KVM/libvirt, les réseaux et les quatre VM de `v1-full`.
La preuve complète pourra entrer dans la CI sur un runner dédié : inventaire en
lecture seule, mutation bornée, publication des artefacts, puis nettoyage
vérifié même si une assertion échoue. `labctl` reste le même contrôleur pour une
preuve lancée localement ou par ce runner dédié.

Le pilote garde les phases séparées. Une mutation ne commence qu'après la garde
d'inventaire et l'acquisition atomique d'un verrou LAB attribué au run ; un
verrou déjà présent est laissé visible et provoque un refus. Chaque attente
possède une échéance ; chaque
assertion conserve son code de sortie ; le nettoyage s'exécute aussi après un
échec. Aucun `|| true` global, agrégat de logs ou rapport visuel ne doit masquer
le premier contrôle rouge.

## Matrice exécutée de `v0.0.2` — orchestration assistée

Cette matrice vient du
[contrat exécutable](../objectifs/v1/CONTRAT-V0.0.2.md). Les résultats du 18
juillet 2026 sont conservés dans le
[rapport LAB](../lab/v0.0.2-observation.md). Les tests Go sont automatiques ;
le cycle multi-VM a été exécuté et affirmé, mais son enchaînement reste assisté
et doit devenir un pilote rejouable.

| Frontière | Résultat exécuté | Automatisation restante |
|---|---|---|
| certificats mTLS | nominal et certificats inconnu, révoqué, expiré, mauvaise CA, mauvais usage et mauvaise association refusés | intégrer les commandes vivantes au pilote unique |
| endpoint Relay | HTTPS exact ; HTTP, mauvais nom/CA, chemin et query refusés ; port, fragment et redirection couverts en tests Go | rejouer toute la matrice en réseau vivant |
| profil `host-health.v1` | trois collecteurs réels ; profil, champ, version et entrée libre refusés en tests Go | intégrer coûts et schémas au rapport structuré |
| accusé durable | retrait après accusé, rejeu exact accepté, collision refusée et échec de persistance injecté sans faux état mémoire | porter ensuite l'injection au pilote multi-VM |
| tampon | Relay indisponible, 120 éléments, 46 272 octets, lacune `15..30`, redémarrage et reprise | automatiser l'accélération sans boucle manuelle |
| diagnostic administratif local en `root` | nominal, indisponible, saturé et repris ; format, sujet et chemin libres refusés | capturer automatiquement les quatre états |
| cycle systemd | rôles séparés, redémarrages, rollbacks d'artefact invalide, gardes processus/listener, retrait, état absent et réinstallation finale | intégrer ces étapes au pilote et lancer le processus hostile avec l'UID du service |

Les mesures LAB ont fixé `64 KiB`, 120 observations et une heure, sous les
plafonds absolus. Les microbenchmarks et leurs limites figurent dans le rapport.
La matrice ne s'étend pas à l'App, Ansible métier, un canal d'action,
l'Auxiliaire, WireGuard, OCI, Proxmox, OpenStack, un worker d'automatisation ou
un projet IaC.

## Couverture actuelle de `v0.0.1`

### Contrôles statiques, tests Go et build

| Contrôle | Assertion | Préparation | Orchestration | Nettoyage | Limite actuelle |
|---|---|---|---|---|---|
| `gofmt -l` vide | automatique | automatique | automatique | sans objet | couvre les sources Go de `cmd/` et `internal/` |
| `bash -n` sur les scripts Bash du lot | automatique | automatique | automatique | sans objet | sélection par shebang dans `deploy/`, `tools/` et `tests/` |
| syntaxe du générateur Python de restitution | automatique | automatique | automatique | automatique | compilation seule de `tests/lab/v0.0.1/report/renderer.py` ; le rendu réel reste vérifié dans `lab-console` |
| résultat structuré Plumber absent, ambigu, incomplet, sauté ou dégradé | automatique | automatique | automatique | automatique | 23 cas de frontière (20 refus, 3 acceptations), liaison au lot et refus intégré d'un tag mutable exécutés dans `lab-console` ; le vrai workflow GitHub reste à exécuter après publication |
| contrat `labctl list` humain et TSV | automatique | automatique | automatique | automatique | double `virsh` isolé ; le vrai inventaire reste contrôlé avant mutation |
| `tools/check-docs` sur l'arbre complet | automatique | automatique | automatique | automatique | la cohérence sémantique reste une relecture humaine |
| `go test -count=1 ./...` | automatique | automatique | automatique | automatique | mode `lab` sur `lab-console` root ou mode `ci` sur runner distant non privilégié |
| `go vet ./...` | automatique | automatique | automatique | automatique | intégré à la même entrée source |
| build `CGO_ENABLED=0` de l'unique exécutable | automatique | automatique | automatique | automatique | le lot doit être initialement dépourvu de `dist/` ; le mode CI construit dans un temporaire |
| SHA-256 identique dans le build, sur le VPS et sur la machine LAN | automatique | automatique | automatique | automatique | le résultat structuré conserve l'empreinte exacte du lot exécuté |

Les tests Go portent déjà les assertions suivantes :

- `cmd/your-cloud` refuse un rôle absent ou inconnu, les arguments d'un autre
  rôle, un Relay sans candidature et toute adresse d'écoute différente de
  `192.168.242.103:8443`, ainsi que toute autre origine Relay pour le Daemon ;
- `internal/daemon` vérifie le schéma exact envoyé, les seules transitions de
  journal `indisponible` puis `rétabli`, les configurations dangereuses et la
  propagation d'un refus Relay ;
- `internal/presence` refuse les documents non objets ou tronqués, les champs
  absents, dupliqués, inconnus, de casse différente ou de type incorrect, les
  seconds objets, identifiants, versions et horodatages invalides ;
- `internal/relay` vérifie le passage `absent` vers `recent` puis `old`, le tri
  des machines, l'usage de l'heure de réception du Relay et la disponibilité du
  handler après chaque corps hostile ;
- la frontière `POST /v0/presence` refuse contenu absent ou inconnu, identifiant
  mal formé ou non autorisé, champ dupliqué ou de mauvaise casse, second objet,
  type incorrect et corps supérieur à 512 octets ;
- la frontière `QUERY /v0/machines` accepte exactement `{}` en JSON, annonce
  `Accept-Query` et `Cache-Control: no-store`, puis refuse méthode, type,
  `null`, tableau, document tronqué, filtre futur, second objet, partie query
  d'URI et corps supérieur à 32 octets ;
- le manifeste Relay refuse document vide, tableau ou tronqué, champ absent,
  inconnu, de mauvaise casse ou de type incorrect, schéma ou rôle incorrect,
  doublon, second objet, taille excessive, propriétaire non-root, lien
  symbolique, fichier ou répertoire modifiable par d'autres.

### Pilote HTTP vivant

[`tests/lab/v0.0.1/remote/prove-hostile-relay`](../../tests/lab/v0.0.1/remote/prove-hostile-relay)
exécute sur `lab-coordinateur` la matrice vivante `POST` et `QUERY` : schémas,
tailles, méthodes croisées, `Content-Type`, partie query non vide ou vide et
cache interdit. Après chaque refus, il vérifie le même PID, l'exécutable, le
listener exact relié à ce PID et une consultation valide. Chaque appel possède
un délai de connexion de deux secondes et une durée totale de cinq secondes.
Un serveur synthétique muet sur loopback prouve en plus que la borne totale
interrompt réellement un client connecté qui ne reçoit aucune réponse.

| Partie | Niveau actuel | Ce qui manque |
|---|---|---|
| Matrice `POST`, `QUERY` et méthodes croisées | automatique | étendre seulement avec un nouveau cas réellement introduit |
| `Accept-Query` et `Cache-Control: no-store` | automatique | aucun cache intermédiaire réel n'est introduit dans ce palier |
| Unité, PID, exécutable et listener après chaque refus | automatique | les transitions de journal sont comptées dans le cycle multi-VM |
| Préparation de la candidate et de l'origine exacte | automatique | bornée au scénario LAB `v0.0.1` |
| Nettoyage du client | automatique | le Relay reste géré par le cycle multi-VM |

### Placement et cycle multi-VM

[`tests/lab/v0.0.1/prove`](../../tests/lab/v0.0.1/prove) est l'unique entrée du cycle.
Le laptop ne fait que lire Git, fabriquer depuis une liste positive Git
l'archive non sensible, calculer ses empreintes et piloter `labctl` ; tout code
produit, test, build, HTTP et systemd s'exécute dans le LAB. L'empreinte du lot
est comparée après transit avant extraction. Une erreur après mutation déclenche
un retrait vérifié sur les trois cibles ; un succès réinstalle l'état final
annoncé.

| Scénario réellement couvert | Assertions | Préparation | Orchestration | Nettoyage |
|---|---|---|---|---|
| garde `labctl list`, origine, gabarit, topologie et adresses interdites | automatique | sans objet | automatique | automatique |
| verrou LAB exclusif attribué au run, refus sans vol du verrou et libération vérifiée | automatique | automatique | automatique | automatique |
| build unique, copie et comparaison des trois empreintes SHA-256 | automatique | automatique | automatique | automatique |
| installation du Daemon seul sur le LAN, puis Daemon et Relay parallèles sur le VPS | automatique | automatique | automatique | automatique |
| unités distinctes, PID et UID dynamiques distincts, un processus par rôle et listener exact | automatique | automatique | automatique | automatique |
| refus Relay sans candidature sur le LAN avant ouverture de `8443` | automatique | automatique | automatique | automatique |
| chaque couple hôte/identifiant autorisé et écoute locale, wildcard ou mauvais port | automatique | automatique | automatique | automatique |
| manifeste `0666` jusqu'à `start-limit-hit`, Daemon indépendant, aucun listener puis `reset-failed` | automatique | automatique | automatique | automatique |
| deux machines `recent` malgré l'écart entre les horloges | automatique | automatique | automatique | automatique |
| arrêt d'un Daemon : lui seul devient `old`, puis revient `recent` | automatique | automatique | automatique avec attente bornée | automatique |
| arrêt des deux Daemons et redémarrage Relay : deux états `absent`, puis retour à `recent` | automatique | automatique | automatique | automatique |
| un seul log d'indisponibilité puis un seul de rétablissement, aucun succès chaque seconde | automatique | automatique | automatique | automatique |
| Relay synthétique hors unité : `disable-relay` refuse et conserve le manifeste | automatique | automatique | automatique | automatique après arrêt explicite du PID |
| Daemon synthétique hors unité : `remove-agent` refuse et conserve l'artefact | automatique | automatique | automatique | automatique après arrêt explicite du PID |
| premier lot ou remplacement invalide : retour à l'état absent ou restauration de l'artefact et des deux rôles | automatique | automatique | automatique | automatique |
| désactivation Relay : port, unité, configuration et manifeste absents, Daemon VPS inchangé | automatique | automatique | automatique | automatique |
| retrait sur les trois machines : aucun processus, unité, binaire ou configuration | automatique | automatique | automatique | automatique |
| réinstallation finale : état annoncé et deux présences `recent` | automatique | automatique | automatique | état conservé volontairement |

### Restitution visuelle

Le Markdown et la page HTML sont générés dans `lab-console` depuis les seuls
champs autorisés du résultat P1. La page est servie sur `127.0.0.1:18080` sous
`nobody`, vérifiée par HTTP puis capturée par Chromium headless. Un scénario
injecte aussi un échec de capture et affirme l'arrêt du serveur avant le rendu
nominal.

| Partie | Niveau actuel | Limite |
|---|---|---|
| production des tableaux Markdown et de la page HTML | automatique | le schéma et les champs sont bornés ; le sens reste relu par une personne |
| démarrage et arrêt du serveur temporaire LAB | automatique | identité, listener et absence finale sont affirmés, y compris après capture en échec |
| ouverture et capture Chromium headless | automatique | Chromium est un prérequis du runner LAB, pas une dépendance du produit |
| validation du contenu servi | automatique | une capture prouve un rendu, jamais le comportement du produit |

## Refus attendus, distincts des incidents

Un refus attendu est un test réussi : l'entrée hostile est volontaire et le
système doit échouer fermé sans élargir son autorité. Il ne doit pas être classé
comme incident du produit.

| Refus provoqué | Résultat attendu |
|---|---|
| mode Relay sans manifeste candidat | code de sortie `2`, aucun listener |
| activation Relay sur une machine autre que `lab-coordinateur` | refus avant effet |
| identité autorisée mais différente du nom d'hôte | installation refusée avant mutation |
| adresse d'écoute autre que `192.168.242.103:8443` | refus avant lecture de la candidature et avant écoute |
| manifeste mal formé, surdimensionné, non-root, modifiable ou symbolique | Relay en échec, Daemon indépendant, aucun listener |
| présence absente, mal formée, non autorisée, dupliquée, de mauvaise casse, inconnue ou trop grande | `400` ou `413`, puis Relay toujours disponible |
| `GET /v0/machines`, type absent ou incorrect, `QUERY` non vide, multiple ou trop grande | `400`, `405`, `415` ou `413`, puis `QUERY {}` toujours disponible |
| processus Relay hors unité pendant `disable-relay` | code `1`, manifeste et fichiers conservés |
| processus Daemon hors unité pendant `remove-agent` | code `1`, binaire et fichiers conservés |
| redémarrage Relay sans signal reçu | états `absent`, puis `recent` après reprise des Daemons |

## Incidents et difficultés réellement rencontrés

Ces événements étaient inattendus pendant la réalisation ou l'audit. Une
correction locale déjà apportée n'implique pas que sa non-régression soit
automatisée.

| Incident ou difficulté | Cause observée | Traitement appliqué | Garde d'automatisation à ajouter |
|---|---|---|---|
| `tools/labctl list` affichait l'inventaire correct puis quittait avec le code `1` | `virsh domifaddr` rend `1` pour une VM arrêtée sans adresse et interrompait la boucle | une VM arrêtée rend désormais `ips=-`, une erreur d'adresse sur une VM active reste bloquante ; TSV et code `0` sont testés avec un double `virsh` | garde automatique active avant chaque mutation |
| une première archive LAB omettait `tools/labctl`, donc le contrôle documentaire signalait des liens cassés | lot préparé depuis une sélection incomplète de l'arbre | archive reconstruite depuis l'arbre complet | fabriquer le lot depuis une liste traçable et vérifier la présence de chaque cible de lien avant les tests |
| les VM avaient des horloges différentes et `tar` avertissait de fichiers datés dans le futur | décalage d'environ quatre jours sur `lab-machine-1` et de quelques dizaines de secondes entre contrôleur et builder, dont environ 35 secondes mesurées le 17 juillet 2026 | fraîcheur calculée sur l'heure de réception Relay ; avertissement de transport conservé visible | décalage contrôlé de deux jours, état `recent` par réception Relay et restauration automatique prouvés en P1 |
| `gofmt -d` a trouvé un alignement à corriger | formatage non exécuté assez tôt | source reformattée puis contrôle rejoué | exécuter le contrôle de format en première phase et bloquer avant tout build ou déploiement |
| les premières commandes `curl` traversant `labctl ssh` souffraient de guillemets imbriqués | construction distante fragile entre plusieurs shells | requêtes corrigées puis regroupées dans le pilote copié au LAB | transférer un script à arguments bornés ; ne pas construire de JSON dans une commande SSH concaténée |
| le manifeste hostile a épuisé la limite de redémarrage systemd après cinq refus | les échecs répétés laissaient l'unité en `start-limit-hit` après réparation | `enable-relay` exécute désormais `reset-failed` avant relance | événement journalisé, refus avant `reset-failed` et récupération après réinitialisation prouvés en P1 |
| le client vivant envoyait `/chemin` au lieu de `/chemin?` | `curl` normalise un `?` final vide | le pilote force la cible de requête brute avec `--request-target` | le cas vide est vérifié après chaque build au niveau Go et HTTP vivant |
| un cas nommé « Content-Type absent » envoyait en réalité le type formulaire de `curl` | `--data-binary` ajoute un en-tête par défaut | le pilote supprime explicitement cet en-tête | les réponses distinctes `400` absent et `415` non pris en charge sont vérifiées |
| la première readiness transactionnelle pouvait accepter brièvement `/bin/false` | une observation instantanée a croisé un processus voué à mourir | le même PID doit rester `active/running` pendant trois contrôles consécutifs | l'injection du faux artefact appartient désormais au P0 vivant |
| le premier rollback du faux artefact ne relançait pas l'ancien lot | les échecs avaient déclenché `start-limit-hit` | le rollback restaure les fichiers, réinitialise seulement les unités présentes, puis revérifie Daemon et Relay | injection `/bin/false`, état absent initial, empreinte restaurée et deux rôles actifs sont automatiques |
| le premier serveur de preuve visuelle sous `DynamicUser` ne pouvait pas servir correctement le fichier temporaire | isolement de l'utilisateur dynamique et du répertoire temporaire | serveur relancé sous le compte non privilégié `nobody`, puis arrêté et nettoyé | UID 65534, listener loopback et nettoyage après échec de capture prouvés en P2 |
| le retrait pouvait supprimer les fichiers malgré un arrêt ou une inspection incertaine | logique de retrait ouverte sur l'échec | contrôles `stop`, `show`, état, `MainPID`, processus hors unité et port ajoutés ; suppression bloquée au moindre doute | Daemon et Relay synthétiques hors unité, refus et empreintes de fichiers inchangées prouvés en P1 |
| l'identifiant de machine n'était pas lié au nom d'hôte LAB | la liste positive seule n'empêchait pas un identifiant autorisé sur le mauvais hôte | égalité exacte avec le nom d'hôte ajoutée avant installation | matrice de tous les couples entre les trois hôtes et les deux identifiants autorisés prouvée en P1 |
| le Relay pouvait recevoir une autre adresse d'écoute | le port et la cible n'étaient pas figés dans le binaire du palier | adresse exacte `192.168.242.103:8443` imposée | écoute locale, wildcard et mauvais port refusés par activation et binaire vivant en P1 |
| le décodage JSON acceptait des clés dupliquées ou une casse différente | comportement permissif du décodage JSON générique | décodeurs stricts ajoutés pour présence, candidature et requête | conserver la matrice hostile au niveau unitaire et vivant, avec un cas où la seconde valeur serait autorisée |
| le Daemon pouvait produire un log à chaque signal ou tentative | journalisation pensée par événement réseau plutôt que par changement d'état | journal limité aux transitions indisponible/rétabli | zéro ligne en réussite prolongée puis exactement une indisponibilité et une récupération sur les deux Daemons en P1 |
| les appels hostiles `curl` n'avaient pas tous de délai borné | une panne réseau pouvait bloquer le pilote | `--connect-timeout` et `--max-time` ajoutés partout | comptage statique des bornes et destination synthétique muette sur loopback interrompue automatiquement |
| les premiers diagrammes montraient un sens de flux incorrect | confusion visuelle entre placement et destination HTTP | flèches corrigées du Daemon vers le Relay | comparer une source unique de flux aux éditions Markdown et HTML pendant le contrôle documentaire |
| le run `20260717T091821Z-1389363` a échoué pendant la dérive d'horloge et son nettoyage | la synchronisation NTP externe n'est pas revenue dans la fenêtre bornée | l'échec est resté classé `cleanup_failure`, les trois cibles ont été rendues absentes et `clock_restored=false` est resté visible | conserver la dépendance NTP comme incident d'infrastructure ; ne jamais transformer son absence en réussite |
| le retrait de l'identité de transfert pouvait croiser un processus SSH tué mais encore visible dans `/proc` | course entre terminaison, récolte du processus par son parent et `userdel` | contrôle des UID réel et effectif, attente bornée de disparition puis suppression de l'identité ; le run `20260717T093905Z-1478107` a ensuite nettoyé proprement | le nettoyage final doit refuser tant qu'un processus du compte temporaire reste observable |
| le premier run post-réorganisation `20260717T100017Z-1539228` a refusé le lot avant mutation produit | le répertoire `deploy/` copié avait conservé le mode `0775`, hors contrat root-owned `0755` | échec classé `infrastructure_failure`, état `not-mutated`, nettoyage et horloge verts ; modes distants normalisés avant les gardes | conserver le refus de permissions trop larges et vérifier le mode du lot avant toute installation |
| les deux premières analyses Plumber n'ont pas trouvé de dépôt Git dans `lab-console` | l'image LAB ne contient pas `git`, alors que Plumber lit trois métadonnées avant les workflows | doublure bornée à l'origin public, la racine temporaire et l'identifiant dérivé du lot ; toute autre commande sort avec `2` | le runner GitHub utilisera le vrai checkout ; la doublure reste limitée à la simulation LAB |
| le run générique `20260717T102446Z-1570931` s'est arrêté sur la mutation hostile | un délimiteur `sed` a été réinterprété pendant le transit SSH | délimiteur sans échappement ambigu puis vérification du rapport `ISSUE-701` ; chemins distants et locaux vérifiés absents après l'échec | la preuve doit attribuer le refus au rapport structuré, jamais au seul code de sortie |
| le premier rejeu de la liste positive finale s'est arrêté avant copie LAB | GNU `tar` traite `--no-recursion` comme une option positionnelle lorsqu'elle suit `--files-from` | toutes les options d'archive précèdent désormais la liste NUL de fichiers | conserver le même constructeur de lot dans les preuves générique et multi-VM ; aucun résultat vert n'est publié après un échec d'empaquetage |
| le téléchargement de Plumber du rejeu `20260717T112941Z-1606633` a dépassé 120 secondes après 14,5 Mio reçus | débit sortant du LAB insuffisant pour le binaire de 32,3 Mio dans l'ancienne fenêtre | code `28` conservé, aucun rapport publié, répertoire et archive distants vérifiés absents ; borne totale portée à 420 secondes | garder version, SHA-256, taille maximale et échéance explicites ; une lenteur réseau reste un échec d'infrastructure, jamais un scan vert |

## Écarts techniques révélés par l'audit statique

Un **audit statique** relit le code sans l'exécuter. Il peut découvrir une
frontière insuffisamment exprimée, mais il ne remplace pas la reproduction dans
le LAB. Les écarts ci-dessous ont été trouvés après la première preuve
`v0.0.1`. Leur état reste visible même lorsqu'une correction et sa revalidation
existent.

Deux notions sont utiles avant de lire le tableau :

- un **cache HTTP** peut conserver une réponse et la réutiliser sans joindre le
  Relay ; `Cache-Control: no-store` lui demanderait de ne pas la stocker ;
- l'**horloge monotone** mesure une durée écoulée sans dépendre des corrections
  de l'heure civile. Go la conserve dans certains `time.Time`, mais une
  conversion prématurée avec `UTC()` la retire ;
- une mise à jour **transactionnelle** ne laisse pas deux versions ou un état
  partiel lorsqu'une étape intermédiaire échoue.

| Priorité avant usage concerné | Écart observé | État actuel | Preuve ou reste |
|---|---|---|---|
| avant d'intercaler l'App, un proxy ou un cache | réponse `QUERY` cacheable | `Cache-Control: no-store` ajouté | en-tête vérifié dans les tests Go, chaque requête saine du pilote et la matrice vivante ; aucun proxy réel dans ce palier |
| avant d'élargir le contrat HTTP | parties query d'URI ignorées | `RawQuery` et `ForceQuery` refusés sur les deux routes | paramètres et `?` vide vérifiés au niveau Go et HTTP vivant |
| avant de donner une valeur opérationnelle au seuil d'âge | conversion UTC prématurée | temps brut conservé pour le calcul, UTC réservé au rendu | recul contrôlé de l'émetteur et saut contrôlé du Relay, fraîcheur monotone et restauration ont réussi dans la référence post-réorganisation |
| avant toute destination autre que le LAB figé | origine Daemon insuffisamment stricte | package et point d'entrée refusent utilisateur, chemin, query, fragment et toute origine autre que l'origine LAB exacte | cas hostiles Go ; la V1 définira son propre endpoint authentifié |
| avant une fonction de mise à jour ou de rollback | installation ou remplacement partiel du lot | staging, restauration des fichiers, états systemd et rôles précédents | `/bin/false` injecté sur état absent puis installé ; absence ou ancienne empreinte et rôles parallèles sont restaurés automatiquement |
| prochaine révision des tests HTTP | méthodes croisées non nommées | `GET /v0/machines`, `POST /v0/machines` et `QUERY /v0/presence` couverts | tests Go et pilote vivant |
| lors de l'automatisation des retraits | la garde `stop_and_disable` est dupliquée dans `disable-relay` et `remove-agent` | les deux copies ont passé les scénarios LAB actuels | extraire seulement lorsque le pilote sait prouver les deux appelants, afin d'éviter leur divergence sans créer une bibliothèque shell prématurée |
| avant deux preuves concurrentes | les chemins temporaires historiques du cycle P1 sont fixes | verrou atomique root-owned avec propriétaire de run exact ; aucun verrou existant n'est volé | libération vérifiée après nettoyage ; un arrêt non rattrapable peut laisser un verrou volontairement visible pour inspection |
| avant de donner autorité aux états observés | l'assertion Relay cherchait une sous-chaîne JSON et le listener n'était pas lié au PID de l'unité | parseur JSON à schéma exact, doublons et machine supplémentaire refusés ; PID unique extrait de `ss -ltnp` | fixtures hostiles du parseur puis document vivant exact sur les deux machines |

La [RFC 10008](https://www.rfc-editor.org/rfc/rfc10008.html) est la source du
contrat HTTP `QUERY` : méthode sûre et idempotente, contenu typé obligatoire,
réponse cacheable et partie query de l'URI intégrée à la ressource ciblée.

## Backlog priorisé d'automatisation

### P0 réalisé — résultat reproductible et fiable

1. `labctl list` possède un code de sortie fiable et une sortie TSV
   stable contenant origine, gabarit, topologie et adresses ; le pilote doit
   s'arrêter avant mutation si cette garde n'est pas entièrement verte.
2. `tests/checks/source-v0.0.1` est l'entrée source commune. Le mode `lab`
   prépare le lot dans `lab-console` ; le mode `ci` utilise un runner distant
   non privilégié. Les deux lancent format, syntaxe shell, documentation, tests
   Go sans cache, `go vet` et build statique, publient le détail des étapes et
   préservent le premier code d'échec.
3. Cette entrée refuse un mode implicite, un mode `lab` qui n'est pas root sur
   `lab-console`, un mode `ci` root ou hors GitHub Actions, un lien
   documentaire absent et tout lot qui ne produit pas l'unique artefact Go
   attendu à l'emplacement propre au runner.
4. Le pilote HTTP vivant couvre la matrice `POST` et `QUERY`, avec une
   vérification automatique de l'unité, du PID, du listener et d'une requête
   valide après chaque refus.
   Cette matrice couvre aussi le cache interdit, les parties query d'URI et les
   méthodes croisées nommées par l'audit statique.
5. `tests/lab/v0.0.1/prove` orchestre le cycle `v1-full` depuis un état connu :
   installation, placement, processus parallèles, transitions
   `recent`/`old`/`absent`, redémarrages, retrait, contrôle d'absence puis
   réinstallation finale.
6. Le cycle possède un nettoyage garanti qui refuse de déclarer le LAB
   propre tant qu'un PID, une unité, un listener ou un fichier qui devrait être
   absent subsiste.

### P1 réalisé — régressions historiques automatisées

1. Le manifeste invalide atteint la limite de démarrage ; le manifeste réparé
   reste refusé avant `reset-failed`, puis le Relay récupère.
2. Des Daemon et Relay synthétiques hors unité bloquent le retrait ; les
   empreintes et métadonnées des fichiers gérés restent identiques avant arrêt.
3. Les couples hôte/identifiant, les trois classes d'écoute interdites, les
   propriétaires, permissions et protections systemd sont affirmés.
4. L'horloge de l'émetteur est reculée de deux jours puis celle du Relay avancée
   de deux jours ; la fraîcheur reste fondée sur la réception et la durée
   monotone, puis les deux trajectoires d'horloge sont restaurées.
5. Les deux Daemons produisent zéro transition en réussite prolongée, une seule
   indisponibilité pendant la panne et une seule récupération.
6. Les réponses d'état sont parsées selon leur schéma exact ; doublons, machine
   supplémentaire ou listener porté par un autre PID sont refusés. La borne
   réseau est éprouvée contre une destination muette strictement locale au LAB.
7. `result.json` contient la révision Git, les empreintes, la topologie, les
   cibles, la fenêtre Relay et le nettoyage puis, pour chaque étape, son
   identifiant, sa catégorie, son titre et son statut. Cette liste fixe exclut
   logs bruts et données sensibles.

### P2 réalisé — restitution automatisée sans autorité indue

1. Le rapport Markdown et la page HTML sont générés depuis `result.json`, sans
   recopier manuellement PID, empreintes ou états.
2. La page est servie seulement dans `lab-console` sous `nobody` sur loopback ;
   contenu, identité, listener et arrêt sont affirmés après échec injecté puis
   après capture nominale.
3. Chaque exécution archive sous `artifacts/proofs/v0.0.1/<horodatage>/` son
   `result.json`. Une exécution P1 réussie archive en plus le résultat P2, le
   rapport, la page et la capture. `result.json` reste l'autorité ;
   `render-result.json` et l'image prouvent seulement la restitution.

## Condition de sortie de l'automatisation complète

Le run post-réorganisation historique `20260717T100150Z-1543398` a satisfait
P0, P1 et P2 avant les derniers durcissements de CI et d'orchestration. Il ne
prouve donc pas à lui seul les sources courantes. Chaque exécution autorisée
doit :

- partir d'un inventaire LAB vérifié et d'un état initial déclaré ;
- ne lancer aucun code du projet sur le laptop ;
- tracer la révision testée et l'empreinte exacte de l'artefact déployé ;
- exécuter toutes les assertions statiques, unitaires, HTTP et multi-VM sans
  interprétation manuelle ;
- distinguer refus attendu, échec du produit, échec d'infrastructure et échec du
  nettoyage ;
- borner toutes les attentes et toutes les communications réseau ;
- restaurer ou laisser un état final explicitement choisi et le vérifier ;
- produire les données permettant un rapport LAB relisible, sans transformer ce
  rapport ou sa capture en substitut aux assertions.

Le présent registre reste le cahier de reprise. Le statut prouvé de `v0.0.1`
repose sur le rapport LAB lié en tête de page et sur les revalidations qui y
sont explicitement ajoutées, jamais sur cette liste seule.

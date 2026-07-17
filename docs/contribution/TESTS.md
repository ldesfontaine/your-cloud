# Stratégie et registre d'automatisation des tests

> Statut : stratégie active et registre des régressions. Le socle P0 possède un
> pilote automatique ; ce document n'est toujours ni un journal d'exécution ni
> une preuve. La preuve publiée pour `v0.0.1` reste le
> [rapport LAB du 16 juillet 2026](../lab/v0.0.1-presence.md).

Ce registre conserve les contrôles réalisés, les difficultés rencontrées et le
travail restant pour rejouer les vérifications sans intervention manuelle. Il
décrit uniquement le périmètre `v0.0.1` : il ne crée aucune exigence ni aucune
capacité d'un palier suivant.

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

Le pilote garde les phases séparées. Une mutation ne commence qu'après la garde
d'inventaire ; chaque attente possède une échéance ; chaque
assertion conserve son code de sortie ; le nettoyage s'exécute aussi après un
échec. Aucun `|| true` global, agrégat de logs ou rapport visuel ne doit masquer
le premier contrôle rouge.

## Couverture actuelle de `v0.0.1`

### Contrôles statiques, tests Go et build

| Contrôle | Assertion | Préparation | Orchestration | Nettoyage | Limite actuelle |
|---|---|---|---|---|---|
| `gofmt -l` vide | automatique | automatique | automatique | sans objet | couvre les sources Go de `cmd/` et `internal/` |
| `bash -n` sur les scripts Bash du lot | automatique | automatique | automatique | sans objet | sélection par shebang dans `deploy/` et `tools/` |
| contrat `labctl list` humain et TSV | automatique | automatique | automatique | automatique | double `virsh` isolé ; le vrai inventaire reste contrôlé avant mutation |
| `tools/check-docs` sur l'arbre complet | automatique | automatique | automatique | automatique | la cohérence sémantique reste une relecture humaine |
| `go test -count=1 ./...` en root | automatique | automatique | automatique | automatique | le runner refuse de démarrer hors `lab-console` ou sans uid `0` |
| `go vet ./...` | automatique | automatique | automatique | automatique | intégré à la même entrée source |
| build `CGO_ENABLED=0` de l'unique exécutable | automatique | automatique | automatique | automatique | le lot doit être initialement dépourvu de `dist/` |
| SHA-256 identique dans le build, sur le VPS et sur la machine LAN | automatique | automatique | automatique | automatique | le pilote affiche l'empreinte ; le rapport structuré reste en P1 |

Les tests Go portent déjà les assertions suivantes :

- `cmd/your-cloud` refuse un rôle absent ou inconnu, les arguments d'un autre
  rôle, un Relay sans candidature et toute adresse d'écoute différente de
  `192.168.242.103:8443`, ainsi que toute autre origine Relay pour le Daemon ;
- `internal/daemon` vérifie le schéma exact envoyé, les seules transitions de
  journal `indisponible` puis `rétabli`, les configurations dangereuses et la
  propagation d'un refus Relay ;
- `internal/presence` refuse les champs absents, dupliqués, de casse différente,
  les seconds objets, identifiants, versions et horodatages invalides ;
- `internal/relay` vérifie le passage `absent` vers `recent` puis `old`, le tri
  des machines, l'usage de l'heure de réception du Relay et la disponibilité du
  handler après chaque corps hostile ;
- la frontière `POST /v0/presence` refuse contenu absent ou inconnu, identifiant
  mal formé ou non autorisé, champ dupliqué ou de mauvaise casse, second objet,
  type incorrect et corps supérieur à 512 octets ;
- la frontière `QUERY /v0/machines` accepte exactement `{}` en JSON, annonce
  `Accept-Query` et `Cache-Control: no-store`, puis refuse méthode, type,
  `null`, filtre futur, second objet, partie query d'URI et corps supérieur à
  32 octets ;
- le manifeste Relay refuse document vide, tableau, champ absent ou inconnu,
  schéma ou rôle incorrect, doublon, second objet, taille excessive, propriétaire
  non-root, lien symbolique, fichier ou répertoire modifiable par d'autres.

### Pilote HTTP vivant

[`deploy/v0.0.1/prove-hostile-relay`](../../deploy/v0.0.1/prove-hostile-relay)
exécute sur `lab-coordinateur` la matrice vivante `POST` et `QUERY` : schémas,
tailles, méthodes croisées, `Content-Type`, partie query non vide ou vide et
cache interdit. Après chaque refus, il vérifie le même PID, l'exécutable, le
listener exact et une consultation valide. Chaque appel possède un délai de
connexion de deux secondes et une durée totale de cinq secondes.

| Partie | Niveau actuel | Ce qui manque |
|---|---|---|
| Matrice `POST`, `QUERY` et méthodes croisées | automatique | étendre seulement avec un nouveau cas réellement introduit |
| `Accept-Query` et `Cache-Control: no-store` | automatique | aucun cache intermédiaire réel n'est introduit dans ce palier |
| Unité, PID, exécutable et listener après chaque refus | automatique | les journaux structurés restent en P1 |
| Préparation de la candidate et de l'origine exacte | automatique | bornée au scénario LAB `v0.0.1` |
| Nettoyage du client | automatique | le Relay reste géré par le cycle multi-VM |

### Placement et cycle multi-VM

[`tools/prove-v0.0.1`](../../tools/prove-v0.0.1) est l'unique entrée du cycle.
Le laptop ne fait que lire Git, fabriquer l'archive, calculer ses empreintes et
piloter `labctl` ; tout code produit, test, build, HTTP et systemd s'exécute dans
le LAB. Une erreur après mutation déclenche un retrait vérifié sur les trois
cibles ; un succès réinstalle l'état final annoncé.

| Scénario réellement couvert | Assertions | Préparation | Orchestration | Nettoyage |
|---|---|---|---|---|
| garde `labctl list`, origine, gabarit, topologie et adresses interdites | automatique | sans objet | automatique | automatique |
| build unique, copie et comparaison des trois empreintes SHA-256 | automatique | automatique | automatique | automatique |
| installation du Daemon seul sur le LAN, puis Daemon et Relay parallèles sur le VPS | automatique | automatique | automatique | automatique |
| unités distinctes, PID et UID dynamiques distincts, un processus par rôle et listener exact | automatique | automatique | automatique | automatique |
| refus Relay sans candidature sur le LAN avant ouverture de `8443` | automatique | automatique | automatique | automatique |
| refus d'une identité autorisée placée sur le mauvais hôte et d'une écoute sur `8444` | manuel | assisté | manuel | manuel |
| manifeste `0666` : Relay en échec, Daemon indépendant et aucun listener | manuel | manuel | manuel | assisté par `reset-failed` |
| deux machines `recent` malgré l'écart entre les horloges | automatique | automatique | automatique | automatique |
| arrêt d'un Daemon : lui seul devient `old`, puis revient `recent` | automatique | automatique | automatique avec attente bornée | automatique |
| arrêt des deux Daemons et redémarrage Relay : deux états `absent`, puis retour à `recent` | automatique | automatique | automatique | automatique |
| un seul log d'indisponibilité puis un seul de rétablissement, aucun succès chaque seconde | manuel | assisté | manuel | sans objet |
| Relay synthétique hors unité : `disable-relay` refuse et conserve le manifeste | manuel | manuel | manuel | manuel après arrêt explicite du PID |
| Daemon synthétique hors unité : `remove-agent` refuse et conserve l'artefact | manuel | manuel | manuel | manuel après arrêt explicite du PID |
| premier lot ou remplacement invalide : retour à l'état absent ou restauration de l'artefact et des deux rôles | automatique | automatique | automatique | automatique |
| désactivation Relay : port, unité, configuration et manifeste absents, Daemon VPS inchangé | automatique | automatique | automatique | automatique |
| retrait sur les trois machines : aucun processus, unité, binaire ou configuration | automatique | automatique | automatique | automatique |
| réinstallation finale : état annoncé et deux présences `recent` | automatique | automatique | automatique | état conservé volontairement |

### Restitution visuelle

La page HTML autonome a été servie temporairement depuis `lab-console`, ouverte
dans un navigateur puis capturée après contrôle des mêmes placements, PID,
empreintes et limites que le rapport Markdown.

| Partie | Niveau actuel | Limite |
|---|---|---|
| production de la page HTML | assisté | la cohérence sémantique avec le rapport reste relue par une personne |
| démarrage et arrêt du serveur temporaire LAB | manuel | aucune enveloppe garantit encore l'arrêt après erreur du navigateur |
| ouverture et capture | manuel | dépend d'une session de navigateur |
| validation visuelle du contenu | manuel | une capture prouve un rendu, jamais le comportement du produit |

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
| les VM avaient des horloges différentes et `tar` avertissait de fichiers datés dans le futur | décalage d'environ quatre jours sur `lab-machine-1` et de quelques secondes entre contrôleur et builder | fraîcheur calculée sur l'heure de réception Relay ; avertissement de transport conservé visible | créer en P1 un décalage d'horloge contrôlé et distinguer dérive attendue et horloge LAB mal synchronisée |
| `gofmt -d` a trouvé un alignement à corriger | formatage non exécuté assez tôt | source reformattée puis contrôle rejoué | exécuter le contrôle de format en première phase et bloquer avant tout build ou déploiement |
| les premières commandes `curl` traversant `labctl ssh` souffraient de guillemets imbriqués | construction distante fragile entre plusieurs shells | requêtes corrigées puis regroupées dans le pilote copié au LAB | transférer un script à arguments bornés ; ne pas construire de JSON dans une commande SSH concaténée |
| le manifeste hostile a épuisé la limite de redémarrage systemd après cinq refus | les échecs répétés laissaient l'unité en `start-limit-hit` après réparation | `enable-relay` exécute désormais `reset-failed` avant relance | provoquer ce cas précis avec le manifeste reste en P1 |
| le client vivant envoyait `/chemin` au lieu de `/chemin?` | `curl` normalise un `?` final vide | le pilote force la cible de requête brute avec `--request-target` | le cas vide est vérifié après chaque build au niveau Go et HTTP vivant |
| un cas nommé « Content-Type absent » envoyait en réalité le type formulaire de `curl` | `--data-binary` ajoute un en-tête par défaut | le pilote supprime explicitement cet en-tête | les réponses distinctes `400` absent et `415` non pris en charge sont vérifiées |
| la première readiness transactionnelle pouvait accepter brièvement `/bin/false` | une observation instantanée a croisé un processus voué à mourir | le même PID doit rester `active/running` pendant trois contrôles consécutifs | l'injection du faux artefact appartient désormais au P0 vivant |
| le premier rollback du faux artefact ne relançait pas l'ancien lot | les échecs avaient déclenché `start-limit-hit` | le rollback restaure les fichiers, réinitialise seulement les unités présentes, puis revérifie Daemon et Relay | injection `/bin/false`, état absent initial, empreinte restaurée et deux rôles actifs sont automatiques |
| le premier serveur de preuve visuelle sous `DynamicUser` ne pouvait pas servir correctement le fichier temporaire | isolement de l'utilisateur dynamique et du répertoire temporaire | serveur relancé sous le compte non privilégié `nobody`, puis arrêté et nettoyé | créer un répertoire lisible dédié, lancer sous une identité non privilégiée connue et garantir l'arrêt par piège de sortie |
| le retrait pouvait supprimer les fichiers malgré un arrêt ou une inspection incertaine | logique de retrait ouverte sur l'échec | contrôles `stop`, `show`, état, `MainPID`, processus hors unité et port ajoutés ; suppression bloquée au moindre doute | automatiser les injections de PID et listener résiduels et vérifier la conservation de tous les fichiers |
| l'identifiant de machine n'était pas lié au nom d'hôte LAB | la liste positive seule n'empêchait pas un identifiant autorisé sur le mauvais hôte | égalité exacte avec le nom d'hôte ajoutée avant installation | tester chaque couple hôte/identifiant autorisé et affirmer zéro fichier créé après refus |
| le Relay pouvait recevoir une autre adresse d'écoute | le port et la cible n'étaient pas figés dans le binaire du palier | adresse exacte `192.168.242.103:8443` imposée | tester adresse locale, wildcard et mauvais port, puis comparer les listeners avant/après |
| le décodage JSON acceptait des clés dupliquées ou une casse différente | comportement permissif du décodage JSON générique | décodeurs stricts ajoutés pour présence, candidature et requête | conserver la matrice hostile au niveau unitaire et vivant, avec un cas où la seconde valeur serait autorisée |
| le Daemon pouvait produire un log à chaque signal ou tentative | journalisation pensée par événement réseau plutôt que par changement d'état | journal limité aux transitions indisponible/rétabli | compter les lignes sur plusieurs intervalles de réussite, panne prolongée et récupération |
| les appels hostiles `curl` n'avaient pas tous de délai borné | une panne réseau pouvait bloquer le pilote | `--connect-timeout 2` et `--max-time 5` ajoutés partout | contrôle statique du pilote et test d'une destination qui ne répond pas |
| les premiers diagrammes montraient un sens de flux incorrect | confusion visuelle entre placement et destination HTTP | flèches corrigées du Daemon vers le Relay | comparer une source unique de flux aux éditions Markdown et HTML pendant le contrôle documentaire |

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
| avant de donner une valeur opérationnelle au seuil d'âge | conversion UTC prématurée | temps brut conservé pour le calcul, UTC réservé au rendu | transitions automatiques ; saut contrôlé de l'horloge Relay encore en P1 |
| avant toute destination autre que le LAB figé | origine Daemon insuffisamment stricte | package et point d'entrée refusent utilisateur, chemin, query, fragment et toute origine autre que l'origine LAB exacte | cas hostiles Go ; la V1 définira son propre endpoint authentifié |
| avant une fonction de mise à jour ou de rollback | installation ou remplacement partiel du lot | staging, restauration des fichiers, états systemd et rôles précédents | `/bin/false` injecté sur état absent puis installé ; absence ou ancienne empreinte et rôles parallèles sont restaurés automatiquement |
| prochaine révision des tests HTTP | méthodes croisées non nommées | `GET /v0/machines`, `POST /v0/machines` et `QUERY /v0/presence` couverts | tests Go et pilote vivant |
| lors de l'automatisation des retraits | la garde `stop_and_disable` est dupliquée dans `disable-relay` et `remove-agent` | les deux copies ont passé les scénarios LAB actuels | extraire seulement lorsque le pilote sait prouver les deux appelants, afin d'éviter leur divergence sans créer une bibliothèque shell prématurée |

La [RFC 10008](https://www.rfc-editor.org/rfc/rfc10008.html) est la source du
contrat HTTP `QUERY` : méthode sûre et idempotente, contenu typé obligatoire,
réponse cacheable et partie query de l'URI intégrée à la ressource ciblée.

## Backlog priorisé d'automatisation

### P0 réalisé — résultat reproductible et fiable

1. `labctl list` possède un code de sortie fiable et une sortie TSV
   stable contenant origine, gabarit, topologie et adresses ; le pilote doit
   s'arrêter avant mutation si cette garde n'est pas entièrement verte.
2. `tools/test-v0.0.1` est l'entrée exécutée dans `lab-console` pour préparer le
   lot complet puis lancer format, syntaxe shell, documentation, tests Go sans
   cache, `go vet` et build statique. Elle publie le détail des étapes et
   préserver le premier code d'échec.
3. Cette entrée échoue si le runner n'est pas root, si un
   lien documentaire vise un fichier absent du lot ou si l'exécutable n'est pas
   le seul artefact Go attendu.
4. Le pilote HTTP vivant couvre la matrice `POST` et `QUERY`, avec une
   vérification automatique de l'unité, du PID, du listener et d'une requête
   valide après chaque refus.
   Cette matrice couvre aussi le cache interdit, les parties query d'URI et les
   méthodes croisées nommées par l'audit statique.
5. `tools/prove-v0.0.1` orchestre le cycle `v1-full` depuis un état connu :
   installation, placement, processus parallèles, transitions
   `recent`/`old`/`absent`, redémarrages, retrait, contrôle d'absence puis
   réinstallation finale.
6. Le cycle possède un nettoyage garanti qui refuse de déclarer le LAB
   propre tant qu'un PID, une unité, un listener ou un fichier qui devrait être
   absent subsiste.

### P1 — automatiser les régressions révélées par la preuve

1. Injecter un manifeste invalide jusqu'à `start-limit-hit`, remettre un
   manifeste valide et vérifier la récupération par `reset-failed`.
2. Lancer des Daemon et Relay synthétiques hors unité, puis prouver que les
   scripts de retrait échouent fermés et ne suppriment rien avant leur arrêt.
3. Tester les couples nom d'hôte/identifiant, toutes les adresses d'écoute
   interdites, les propriétaires et permissions de chaque fichier systemd.
4. Décaler volontairement l'horloge d'un émetteur sans modifier l'horloge Relay
   et affirmer que seule la réception décide de `recent` ou `old`.
5. Compter automatiquement les transitions de journal pendant une réussite
   prolongée, une panne prolongée et une récupération.
6. Produire un résultat structuré par étape avec version Git, empreinte du lot,
   topologie, cibles, horaires Relay et statut du nettoyage, en expurgeant toute
   donnée sensible.

### P2 — automatiser la restitution sans lui donner une autorité indue

1. Générer les tableaux et la page visuelle depuis les résultats structurés du
   pilote, sans recopier manuellement PID, empreintes ou états.
2. Servir temporairement la page dans le LAB sous une identité non privilégiée,
   effectuer les contrôles de présence du contenu puis arrêter le serveur même
   si la capture échoue.
3. Archiver la capture avec le rapport d'exécution, tout en gardant les
   assertions machine comme critère de réussite principal.

## Condition de sortie de l'automatisation complète

Le P0 satisfait déjà le socle source, HTTP et multi-VM ci-dessous.
L'automatisation de toutes les régressions historiques et de la restitution ne
pourra être dite complète qu'après P1 et P2, lorsqu'une seule exécution
autorisée :

- part d'un inventaire LAB vérifié et d'un état initial déclaré ;
- ne lance aucun code du projet sur le laptop ;
- trace la révision testée et l'empreinte exacte de l'artefact déployé ;
- exécute toutes les assertions statiques, unitaires, HTTP et multi-VM sans
  interprétation manuelle ;
- distingue refus attendu, échec du produit, échec d'infrastructure et échec du
  nettoyage ;
- borne toutes les attentes et toutes les communications réseau ;
- restaure ou laisse un état final explicitement choisi et le vérifie ;
- produit les données permettant un rapport LAB relisible, sans transformer ce
  rapport ou sa capture en substitut aux assertions.

Le présent registre reste le cahier de reprise. Le statut prouvé de `v0.0.1`
repose sur le rapport LAB lié en tête de page et sur les revalidations qui y
sont explicitement ajoutées, jamais sur cette liste seule.

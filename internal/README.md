# Cœur du produit

`internal/` contient la logique appelée par l’exécutable Go. En Go, ce nom
interdit aussi son import direct depuis un autre module.

Les responsabilités principales sont :

| Package | Responsabilité |
|---|---|
| `buffer` | file locale durable et bornée du Daemon |
| `credentials` | lecture de noms de credentials systemd fixés par le rôle |
| `daemon` | collecte et publication sortante des observations |
| `enrollment` | registre des certificats Daemon autorisés ou révoqués |
| `observation` | schéma typé de santé d’une machine |
| `relay` | ingestion, persistance, instantané privé et limites de connexions |
| `readeridentity` | identité du seul Controller autorisé à lire un Relay |
| `controller` | autorité locale, inventaire, sessions, projection et API privée |
| `securefile` | validation des petits fichiers d’autorité préparés par root |
| `strictjson` | refus des JSON ambigus avant décodage métier |
| `transport` | politiques TLS et clients HTTP bornés |
| `identifier`, `machineid`, `protocol` | formats et espaces de noms partagés |

## Lecture simple des packages demandés

### `transport`

- `NewDaemonClient` construit le client sortant du Daemon : une seule autorité
  Relay, un certificat Daemon, TLS 1.3 et aucune redirection ;
- `NewRelayConfig` construit le côté serveur de l’ingestion et exige un
  certificat Daemon enrôlé ;
- `NewRelayReaderConfig` construit une frontière mTLS distincte pour le lecteur
  Controller ;
- `NewControllerReaderClient` contacte une IP privée provisionnée tout en
  vérifiant le nom TLS et l’origine HTTP attendus ; il ignore les proxies ;
- `certificatePool` refuse un PEM ambigu et accepte exactement une autorité.

Pseudo-code : `charger CA + identité -> fixer TLS 1.3 -> fixer destination ->
refuser redirect/proxy/certificat inattendu -> rendre un client borné`.

### `strictjson`

Ce package ne fournit pas des opérations génériques pour modifier du JSON. Il
durcit une frontière avant le décodage métier : une seule valeur, aucun champ
dupliqué, nom et casse exacts, aucun champ inconnu. Les fonctions `scan*`
parcourent la structure et la réflexion sert seulement à comparer les clés au
type Go attendu ; le second décodage produit ensuite la valeur typée.

### `securefile`

`ReadRootOwned` ne crée rien, ne change aucun droit et ne donne aucun accès
root au processus. Il ouvre un petit fichier en lecture seule sans suivre le
dernier lien symbolique, puis vérifie que le répertoire et le fichier ont été
préparés par root et ne sont pas modifiables par un groupe ou un autre compte.

```text
administrateur root prépare /etc/your-cloud/politique.json
  -> service non-root ouvre en lecture seule
  -> securefile vérifie chemin, type, propriétaire, mode et taille
  -> la politique est décodée
  -> sinon le rôle refuse de démarrer ou garde l’ancienne politique
```

Le but est d’empêcher un compte de service compromis de remplacer sa propre
autorisation, pas de permettre à Your Cloud d’agir comme root.

### `relay`

- `candidate.go` vérifie avant toute écoute le marqueur local préparé par
  l’administrateur ; il prouve seulement que la machine peut être candidate ;
- `observation_http.go` reçoit une observation mTLS, relie le certificat à la
  machine, borne le corps puis accuse seulement après persistance ;
- `observation_store.go` conserve le dernier état durable par machine et les
  lacunes connues ;
- `reader_listener.go` ajoute à `nftables` une limite de source, de connexions
  simultanées et de nouvelles connexions ; il réduit un déni de service mais ne
  prétend pas l’éliminer ;
- `snapshot_http.go` rend au seul Controller autorisé l’instantané global borné ;
- `store.go` et `http.go` appartiennent au banc synthétique de présence et ne
  sont pas assemblés dans le Relay d’observation actuel.

Le Relay ne met pas à jour l’état des dizaines de fois par seconde. Chaque
Daemon collecte une fois toutes les 30 secondes. Le Publisher regarde sa petite
file locale au plus une fois par seconde lorsqu’elle est vide et draine sans
attendre seulement un retard existant. Le Controller réutilise une lecture
réussie pendant cinq secondes et l’interface ne fait aucun polling de fond.

### `readeridentity`

`Manifest` décrit l’unique certificat Controller autorisé à lire un Relay :
infrastructure, Controller, URI, série, empreinte et état. `Store` charge cette
politique root-owned, garde la précédente si un rechargement est invalide et la
revérifie à chaque requête, y compris sur une connexion TLS réutilisée.

### `enrollment`

`Registry` est la politique des certificats Daemon. Chaque entrée lie un
`machine_id` à une série et une empreinte exactes, avec état actif ou révoqué.
`Store` publie un registre complet seulement après validation et refuse
suppression, réutilisation d’identité ou retour de révoqué vers actif.

### `identifier`

`ValidateUUIDv4` accepte uniquement la forme canonique minuscule. `NewUUIDv4`
tire l’aléa depuis le système. `UUIDv4From` contient le même calcul avec une
source injectée uniquement pour rendre les tests hostiles déterministes. Ce
package ne choisit pas le rôle d’un identifiant ; Controller, infrastructure et
appareil restent des champs séparés.

### `buffer` et `credentials`

`buffer` garde la file durable du Daemon : ajout atomique, lecture du plus
ancien élément, retrait seulement après accusé exact, saturation bornée et
lacune visible. `credentials` lit seulement des noms de fichiers fixés par le
rôle dans le répertoire fourni par systemd ; aucun argument libre ne peut le
pointer vers une clé arbitraire.

### `controller`

- `authority.go` crée et charge l’identité immuable du Controller et ses
  autorités serveur/appareil ;
- `identity_flow.go`, `candidate.go` et `temporary_http.go` gèrent la fenêtre
  locale, le candidat et l’activation en deux phases ;
- `session.go` prouve l’humain, borne les échecs et garde les sessions opaques ;
- `recovery_key.go` et les chemins de rotation remplacent une autorité sans
  double appareil actif ;
- `inventory.go` porte les machines attendues et leurs libellés ;
- `reader.go`, `snapshot.go` et `cache.go` lisent, valident et conservent le
  dernier instantané Relay sans le promouvoir en inventaire ;
- `projection.go` transforme enfin cet instantané en états affichables ;
- `http.go` expose uniquement la liste fermée des routes métier.

En pseudo-code : `authentifier appareil -> authentifier humain -> lire autorité
locale -> lire Relay privé -> projeter sans inventer -> répondre avec un schéma
borné`.

Les anciens types de présence synthétique ne résident plus dans `internal/` :
le produit ne conserve qu’un chemin Daemon–Relay. Les rapports, scripts et lots
d’installation historiques gardent la preuve passée lisible sans maintenir une
seconde implémentation inactive dans le cœur courant.

La carte des flux et des protections se trouve dans
[`CHAINE-D-OBSERVATION.md`](../docs/architecture/CHAINE-D-OBSERVATION.md).

# Console Your Cloud

La Console est l’application installée sur l’appareil de l’administrateur. Elle
embarque son interface et ne reçoit jamais de code d’un Controller. Aucun
serveur local n’est nécessaire dans l’application distribuée.

## Installer et retirer la Console sous Linux

Le paquet Debian ne livre que quatre fichiers — les deux binaires, l’entrée de
menu et l’icône — et **n’emporte aucun script de mainteneur ni aucun
conffile**. Deux conséquences, l’une et l’autre mesurées par
[la preuve du retrait propre](../docs/lab/v0.1.2-clean-removal.md) :

- **`dpkg --remove` retire déjà tout ce que le paquet a posé.** `purge` n’a rien
  de plus à effacer, parce qu’il n’y a aucun fichier de configuration système à
  effacer : la Console n’écrit rien sous `/etc` ni sous `/var`, jamais ;
- **`apt purge your-cloud` échoue** — `Unable to locate package`. Ce n’est pas un
  défaut du paquet : apt ne sait nommer que ce qu’un dépôt lui décrit, et cette
  Console s’installe depuis un fichier. Le retrait se fait donc avec `dpkg`.

```text
sudo dpkg --install your-cloud_<version>_amd64.deb
sudo dpkg --remove your-cloud
```

### Ce que le retrait garde, et pourquoi

**Le retrait ne touche pas au dossier de la Console dans le foyer de
l’humain**, et c’est voulu. On y trouve, après désinstallation :

```text
~/.local/share/fr.your-cloud.console/
  native-vault/                      (0700)
    console-<identifiant>.stronghold (0600)  le coffre chiffré
    vault.json                       (0600)  son enveloppe
  storage/ CacheStorage/ WebKitCache/ mediakeys/   sels et caches du moteur
  hsts-storage.sqlite                        cache HSTS du moteur
```

Le coffre porte les clés de l’humain : sa phrase de déverrouillage, son identité
d’appareil, ses associations. **Un retrait qui l’effacerait détruirait ces clés
sans les remplacer**, et une réinstallation ne les retrouverait pas — c’est un
geste que seul l’humain peut vouloir, et il le fait en supprimant ce dossier.
Aucune de ces données n’est un fichier de configuration au sens Debian : `purge`
ne les vise pas, et n’a jamais promis de les viser.

Le reste — les sels de huit octets, les caches WebKit, le cache de shaders — est
de l’artefact d’exécution du moteur de rendu, recréé au prochain lancement.

## Pourquoi `src` et `src-tauri/src`

- `src/` contient l’interface React : écrans, formulaires, navigation et rendu
  des données déjà validées ;
- `src-tauri/src/` contient le noyau natif Rust : coffre chiffré, identités,
  certificats, client HTTPS privé et protections propres au système ;
- `src/product/native.ts` est la liste fermée des opérations que l’interface a
  le droit de demander au noyau.

En pseudo-code :

```text
bouton React
  -> opération Tauri nommée
  -> validation et secret dans Rust
  -> requête privée éventuelle vers le Controller
  -> réponse bornée rendue comme donnée
```

React ne reçoit ni clé privée, ni clé dérivée, ni client réseau général, ni
accès libre aux fichiers ou au shell.

## Organisation de l’interface

- `src/design/` contient les tokens et composants visuels communs ;
- `src/product/App.tsx` orchestre l’état global et choisit la vue ;
- `src/product/access-views.tsx` porte le coffre initial et l’association ;
- `src/product/infrastructure-views.tsx` porte synthèse, parc et observations ;
- `src/product/profile-view.tsx` porte sessions, renouvellement et récupération ;
- `src/product/models.ts` décrit les seules données affichables ;
- `src/product/native.ts` appelle les opérations natives autorisées.

Les dépendances, tests, builds et lancements s’exécutent dans le LAB ou un
runner isolé. Ouvrir seulement le frontend dans un navigateur ne teste pas la
Console : les opérations natives seraient absentes. La preuve réelle construit
et lance l’artefact Tauri natif puis vérifie son rendu et l’absence de listener.

Pour travailler seul sur l’interface dans un runner LAB muni d’un affichage :

```text
cd console
npm ci
npm run tauri dev
```

Cette commande lance Vite uniquement sur `127.0.0.1:1420`, puis ouvre la vraie
fenêtre Tauri avec le noyau Rust. `npm run dev` seul permet seulement une revue
visuelle partielle dans un navigateur : les actions de coffre, identité et
réseau échouent volontairement sans l’enveloppe native.

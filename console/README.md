# Console Your Cloud

La Console est l’application installée sur l’appareil de l’administrateur. Elle
embarque son interface et ne reçoit jamais de code d’un Controller. Aucun
serveur local n’est nécessaire dans l’application distribuée.

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

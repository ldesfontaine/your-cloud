# Preuve LAB `v0.0.1`

Ce dossier contient uniquement l'automatisation de preuve du palier `v0.0.1`.
Il ne prépare aucune capacité de `v0.0.2`.

- [`prove`](prove) est l'entrée unique : garde d'inventaire, lot source,
  contrôle générique dans `lab-console`, transfert, cycle multi-VM, résultat P1
  et restitution P2. Son lot est construit depuis la liste positive des
  fichiers Git non ignorés, haché avant et après transit, puis protégé par un
  verrou LAB exclusif attribué au run. Un verrou existant n'est jamais repris
  automatiquement.
- [`prove-generic-ci`](prove-generic-ci) rejoue séparément le mode CI du contrôle
  source sous l'UID non privilégié `65534`, puis vérifie la disparition du
  build et des caches. Il télécharge aussi Plumber `v0.4.8`, refuse tout SHA-256
  différent du lot publié, sélectionne explicitement le fournisseur GitHub,
  analyse la politique exacte et valide son rapport sans toucher aux machines
  produit. Comme la VM ne contient pas `git`, une doublure bornée fournit
  uniquement l'origin public, la racine temporaire et un identifiant de quarante
  caractères dérivé du SHA-256 du lot que Plumber lit avant d'analyser les vrais
  fichiers ; toute autre commande est refusée. Avant le scan nominal, une copie
  temporaire remplace le SHA de
  `actions/checkout` par `v7` et doit rendre Plumber bloquant ; le workflow est
  ensuite restauré octet pour octet.
  Le lot provient d'une liste positive Git : fichiers suivis et nouveaux
  fichiers non ignorés, moins les routeurs locaux et chemins sensibles nommés.
  Son SHA-256 est comparé après transit. Les rapports nominal et hostile ne
  sont publiés localement qu'après leur validation et le nettoyage distant.
- [`transfer-artifact`](transfer-artifact) transfère le binaire directement de
  `lab-console` vers les cibles avec une identité synthétique temporaire et des
  bornes fixes.
- [`remote/`](remote/) contient les assertions et scénarios hostiles copiés
  avec les fichiers de [`deploy/`](../../../deploy/) sur les VM cibles. Les
  états Relay y sont parsés selon un schéma JSON exact, le listener est lié au
  PID de l'unité et une destination muette strictement locale éprouve les
  bornes réseau du pilote.
- [`report/`](report/) valide le schéma P1, génère Markdown et HTML, sert la
  page sur loopback sous `nobody`, réalise la capture puis arrête le serveur.
  Le contrôleur et ses deux composants proviennent du même snapshot haché que
  les autres assertions ; la capture doit être un PNG de taille bornée et les
  vingt identifiants d'étape doivent rester présents dans Markdown et HTML.

Avant toute mutation, l'orchestrateur exécute `tools/labctl list --format=tsv`
et refuse une origine, un gabarit, une topologie ou une adresse inattendus. Son
nettoyage restaure l'horloge contrôlée et retire les identités, processus et
fichiers temporaires ; un échec de nettoyage reste un échec visible.

Les sorties sont écrites sous
[`artifacts/proofs/v0.0.1/`](../../../artifacts/README.md). `result.json` et les
codes de sortie des assertions sont l'autorité ; le rapport, le résultat P2 et
la capture prouvent seulement leur restitution.

Limite de transport visible : la clé hôte de chaque cible est d'abord observée
par le canal géré `labctl`, puis épinglée pour le SSH direct qui transporte le
binaire depuis `lab-console`. Cet épinglage détecte une dérive pendant le run,
mais ne fournit pas un second ancrage d'identité indépendant de `labctl`.

## Référence historique de la réorganisation

Le run `20260717T100150Z-1543398` a réussi depuis cette arborescence avec vingt
étapes P1, la restitution P2, la restauration d'horloge et le nettoyage verts,
avant le durcissement final du banc de preuve et de la CI. Il conserve
l'artefact produit
`4d58798e7c0f1440af22f631b24f6b99c34491765bb41d1c6fc1f46c365f0d41`.
Le run `20260717T093905Z-1478107` reste l'historique propre qui précède le
déplacement. Un rejeu courant doit être identifié par son propre dossier sous
`artifacts/proofs/` ; ce README ne transforme pas une ancienne empreinte en
preuve des sources actuelles.

Cette preuve peut être appelée par une CI seulement depuis un runner dédié qui
possède le même isolement et les mêmes gardes. `labctl` reste également le
contrôleur des preuves lancées depuis le poste de développement ; il ne devient
pas un outil propre à la CI.

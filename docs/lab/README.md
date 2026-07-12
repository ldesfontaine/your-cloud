# LAB de développement V1

> État : topologie `quick` créée puis utilisée pour le premier contact, la
> machine observable et la première sécurisation le 2026-07-12.
> La topologie `v1-full` reste à valider ; aucun de ses gabarits n'est présenté
> comme attesté avant une création réelle.

Le laptop de développement contrôle le LAB mais n’exécute jamais le projet. La
console de développement, les tests, builds, playbooks, daemons et
coordinateurs tournent dans des VM KVM/libvirt ou sur un runner distant offrant
une isolation au moins équivalente.

## Ce qui est repris de l’ancien `labctl`

- contrôle libvirt sans `sudo` ;
- noms et gabarits validés avant tout effet ;
- images datées, épinglées et vérifiées par SHA512 ;
- volumes gérés par l’API libvirt ;
- snapshots shutoff et retour déterministe ;
- commandes simples de création, destruction, inspection et console.

Ne sont pas repris comme preuves : Debian 12, la golden base k3s, le réseau
libvirt unique, les secrets ou tarballs de l’ancien wrapper et ses drills.

## Gabarits initiaux

Ces dimensions servent à construire le LAB ; elles ne constituent pas des
minima produit. Les budgets publiés seront mesurés à P6.

| Gabarit | vCPU | RAM | Disque | Image |
|---|---:|---:|---:|---|
| `console` | 2 | 2048 Mio | 20 Gio | Debian 13 amd64, build `20260525-2489` |
| `machine` | 1 | 1024 Mio | 10 Gio | Debian 13 amd64, build `20260525-2489` |
| `coordinateur` | 1 | 1024 Mio | 10 Gio | Debian 13 amd64, build `20260525-2489` |
| `passerelle` | 1 | 512 Mio | 5 Gio | Debian 13 amd64, build `20260525-2489` |

Une modification de cette table et de l’implémentation `labctl` appartient au
même changement. Aucun alias flou comme « petite VM » n’est accepté.

## LAB rapide

Topologie `quick` :

- `lab-console`, gabarit `console` ;
- `lab-machine-1`, gabarit `machine` ;
- un réseau isolé `lab-quick` avec sortie NAT pour Debian et les dépendances.

Cette topologie couvre compilation, tests, premier contact, audit et
enrôlement sur une image Debian 13 nue. Aucun artefact préinstallé ne doit
fausser le parcours jour zéro.

La création du LAB, le [premier contact](p1-premier-contact.md), la
[machine observable](p2-machine-observable.md) et la
[sécurisation sans perte d'accès](securiser-une-machine.md) sont prouvés.

## LAB V1 complet

Topologie `v1-full` :

- `lab-console` ;
- `lab-coordinateur` ;
- `lab-gateway` ;
- `lab-machine-1` et `lab-machine-2` ;
- réseaux séparés `lab-operator`, `lab-public` et `lab-site-private`.

La passerelle relie de manière bornée le site privé au réseau public simulé.
Les machines privées initient la télémétrie vers le coordinateur ; aucune
connexion de télémétrie entrante n’est ouverte vers elles. Le chemin
d’administration de la console reste distinct et les coupures peuvent être
provoquées réseau par réseau.

## Contrôleur `labctl`

[`tools/labctl`](../../tools/labctl) adapte les mécanismes utiles de l’ancien
outil sans reprendre ses gabarits Debian 12 ni son réseau unique. Il fournit :

- l’image Debian 13 par nom daté, URL et SHA512 épinglés ;
- les quatre gabarits de la table ci-dessus ;
- les topologies nommées `quick` et `v1-full` ;
- la création reprenable, l’inspection et la destruction bornée de ces
  topologies ;
- des métadonnées libvirt portant l’origine, la version du contrôleur, le
  gabarit et la topologie de chaque VM ;
- un refus avant mutation si ces métadonnées sont absentes ou incompatibles.

Le réseau `lab-quick` et le réseau public simulé ont une sortie NAT. Les
réseaux opérateur et site privé restent isolés. Les plages LAB sont dédiées :

| Réseau | Plage | Rôle |
|---|---|---|
| `lab-quick` | `192.168.240.0/24` | boucle rapide avec sortie NAT |
| `lab-operator` | `192.168.241.0/24` | chemin d’administration simulé |
| `lab-public` | `192.168.242.0/24` | Internet simulé avec sortie NAT |
| `lab-site-private` | `192.168.243.0/24` | machines privées sans sortie directe déclarée |

Les commandes de cycle de vie sont volontairement peu nombreuses :

```text
labctl topology create quick
labctl topology inspect quick
labctl topology destroy quick

labctl topology create v1-full
labctl topology inspect v1-full
labctl topology destroy v1-full
```

Une nouvelle golden base ne sera créée que si un coût réel et mesuré la
justifie. L’image Debian nue reste la preuve de départ attendue pour P1.

## Garde de cible

Avant toute mutation de VM : elle figure dans `labctl list`, son origine et son
gabarit sont confirmés, puis son adresse est différente de `192.168.122.123` et
`10.66.66.1`. Le moindre doute signifie production et interdit le geste.

`labctl` applique également cette garde aux commandes mutantes. Cette défense
ne remplace pas la lecture humaine de `labctl list` avant une intervention.

Le contrôleur génère une clé SSH synthétique dédiée dans son cache local et
l'utilise exclusivement pour les VM du LAB. Cette clé ne doit jamais entrer
dans le dépôt ni être remplacée par une clé personnelle d'administration.

Seuls des secrets synthétiques entrent dans le LAB. Un playbook réel reçoit
d’abord un `--syntax-check`, puis son re-run doit donner `changed=0`, toujours
dans une VM appropriée.

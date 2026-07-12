# LAB de développement V1

> État : conception P0. Aucun gabarit ci-dessous n’est encore attesté par une
> exécution de la nouvelle lignée.

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
| `console` | 2 | 2048 Mio | 20 Gio | Debian 13 amd64 épinglée |
| `machine` | 1 | 1024 Mio | 10 Gio | Debian 13 amd64 épinglée |
| `coordinateur` | 1 | 1024 Mio | 10 Gio | Debian 13 amd64 épinglée |
| `passerelle` | 1 | 512 Mio | 5 Gio | Debian 13 amd64 épinglée |

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

## Évolution attendue de `labctl`

P0 adaptera l’outil existant au lieu de copier son état historique :

1. remplacer les gabarits Debian 12 par la table Debian 13 ci-dessus ;
2. conserver l’image par nom daté, URL et SHA512 vérifiés ;
3. gérer explicitement les trois réseaux du LAB complet ;
4. ajouter les topologies nommées `quick` et `v1-full` avec création,
   inspection et destruction bornées ;
5. inscrire l’origine et le gabarit dans les métadonnées libvirt afin que la
   garde de cible puisse les établir sans supposition ;
6. ne créer une nouvelle golden base que si un coût réel et mesuré la justifie.

## Garde de cible

Avant toute mutation de VM : elle figure dans `labctl list`, son origine et son
gabarit sont confirmés, puis son adresse est différente de `192.168.122.123` et
`10.66.66.1`. Le moindre doute signifie production et interdit le geste.

Seuls des secrets synthétiques entrent dans le LAB. Un playbook réel reçoit
d’abord un `--syntax-check`, puis son re-run doit donner `changed=0`, toujours
dans une VM appropriée.

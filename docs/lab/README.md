# LAB de développement V1

> État : topologie `quick` utilisée pour P1 à P4, puis topologie `v1-full`
> créée et utilisée pour le réseau distant, la migration progressive et la
> reconstruction P5 le 2026-07-12.

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
[sécurisation sans perte d'accès](securiser-une-machine.md), puis
[l'observation continue locale](p4-observation-continue-locale.md) sont prouvés.

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

`labctl topology prepare v1-full` configure idempotemment les deux interfaces
supplémentaires de la passerelle, les routes IPv4 et IPv6 ULA, le DNS du réseau
public simulé, le forwarding et le NAT sortant. Sa politique nftables refuse le
forwarding par défaut, autorise le chemin d'administration et ne crée aucune
redirection du réseau public vers le site privé. `nftables` 1.1.3-1 et sa
bibliothèque directe sont épinglés dans le contrôleur.

La [preuve P5](p5-mode-distant.md) a utilisé cette topologie. `site-a` et
`site-b` sont deux infrastructures logiques mais partagent volontairement le
même réseau privé de LAB : cette topologie ne les présente donc pas comme deux
domaines de panne indépendants. Le schéma 2 et la détection runtime issue des
métadonnées `labctl` les confirment tous deux dans `lab-site-private`.

## Contrôleur `labctl`

[`tools/labctl`](../../tools/labctl) adapte les mécanismes utiles de l’ancien
outil sans reprendre ses gabarits Debian 12 ni son réseau unique. Il fournit :

- l’image Debian 13 par nom daté, URL et SHA512 épinglés ;
- les quatre gabarits de la table ci-dessus ;
- les topologies nommées `quick` et `v1-full` ;
- la création reprenable, l’inspection et la destruction bornée de ces
  topologies ;
- la préparation réseau idempotente de `v1-full`, refusée pour toute autre
  topologie ;
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
labctl topology prepare v1-full
labctl topology destroy v1-full

labctl stop lab-console
labctl start lab-console
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

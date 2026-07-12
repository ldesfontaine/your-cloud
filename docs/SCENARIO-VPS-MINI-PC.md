# Scénario simple — un VPS et un mini-PC à la maison

Ce scénario est cohérent pour commencer sans OPNsense, Proxmox ni autre
passerelle gérée par le produit. Il correspond au mode distant minimal de la V1.

## Où tourne chaque composant

```mermaid
flowchart LR
    Laptop["Laptop de l'opérateur\nconsole your-cloud"]
    Internet((Internet))
    VPS["VPS Debian 13\ncoordinateur"]
    Mini["Mini-PC Debian 13\ndaemon d'observation\n+ futurs services"]
    Router["Routeur domestique\nNAT existant"]

    Laptop -->|"lecture mTLS sortante"| VPS
    Laptop -.->|"SSH d'administration\nchemin séparé"| Mini
    Mini -->|"télémétrie mTLS sortante :8443"| Router
    Router --> Internet
    Internet --> VPS
    Mini --- Services["Services du mini-PC\nindépendants du pilotage"]
```

| Machine | Composant nécessaire | Pourquoi |
|---|---|---|
| laptop | console Python | présente les plans, garde les autorités et administre par SSH |
| VPS | coordinateur Go | reste joignable et conserve l'état lorsque le laptop est éteint |
| mini-PC | daemon Go | observe localement et initie la connexion vers le VPS |

Le routeur domestique n'ouvre aucun port de télémétrie vers le mini-PC. Il doit
seulement autoriser ses connexions sortantes. Le VPS publie le port mTLS choisi,
`8443` dans la preuve, et refuse les clients sans certificat approuvé.

Le chemin SSH est indépendant. Depuis l'extérieur, il vaut mieux le porter par
un WireGuard d'administration déjà maîtrisé plutôt que publier directement SSH
du mini-PC. La V1 utilise ce chemin mais ne prétend pas encore installer toute
la topologie WireGuard ou gérer OPNsense.

## Le coordinateur peut-il cohabiter avec un daemon ?

Oui. Une même machine Debian peut porter les deux binaires, mais ils restent
deux composants séparés :

| Aspect | Coordinateur | Daemon d'observation |
|---|---|---|
| compte | `your-cloud-coordinator` | `your-cloud-observer` |
| données | `/var/lib/your-cloud/coordinator` | `/var/lib/your-cloud/observer` |
| réseau | écoute mTLS bornée | aucun port entrant |
| autorité | conserve la télémétrie | observe seulement sa machine |
| secrets | identité serveur mTLS | identité machine et client mTLS |

Sur le VPS, ajouter un daemon permet d'observer la santé du VPS lui-même. Ce
n'est pas nécessaire au fonctionnement du coordinateur. Pour une première
installation facile à comprendre, la recommandation est donc : coordinateur
seul sur le VPS, daemon seul sur le mini-PC. Le daemon du VPS pourra être enrôlé
ensuite comme une machine ordinaire, sans fusionner les deux rôles.

Sur un homelab sans VPS, le coordinateur et le daemon peuvent aussi cohabiter
sur le mini-PC en mode local. Dans ce cas la console ne retrouve l'observation
continue depuis Internet que si un chemin réseau privé rend ce mini-PC
joignable ; ce n'est pas le scénario distant recommandé ici.

## Correspondance avec le LAB

| Installation réelle | Simulation `v1-full` |
|---|---|
| VPS | `lab-coordinateur` sur `lab-public` |
| routeur/NAT domestique | `lab-gateway` |
| mini-PC local | `lab-machine-1` sur `lab-site-private` |
| laptop | `lab-console` |

La lecture ciblée P6 a reçu un état récent de `lab-machine-1` à la séquence 200
via `lab-coordinateur`, avec provenance `coordinateur-mtls +
signature-ed25519-verified`. Le coordinateur a consommé moins de 6 Mio au pic et
le daemon environ 8 Mio, tous deux sous leurs budgets systemd. La preuve P5 a
déjà montré qu'aucune connexion de télémétrie entrante n'atteignait les machines
du site privé.

Ce scénario ne valide pas encore OPNsense, la gestion d'un hyperviseur, les
services applicatifs ni leur exposition. Ces sujets peuvent former le palier
suivant sans remettre en cause cette base.

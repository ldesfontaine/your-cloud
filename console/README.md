# Console P2

La console conserve le premier contact P1 strictement en lecture seule avec une
machine Debian 13 amd64 : déclaration versionnée, registre de clés d'hôte SSH
séparé, audit de compatibilité et API HTTP locale sur socket Unix.

Elle n'utilise jamais les fichiers SSH personnels. La première clé d'hôte doit
être acceptée explicitement par TOFU visible ou correspondre à une empreinte
fournisseur passée sur la ligne de commande. Une différence ultérieure est un
refus.

P2 ajoute un plan d'enrôlement explicitement approuvé, un registre public des
identités de machines et l'inspection ponctuelle d'enveloppes Protobuf signées.
La clé privée Ed25519 reste sur la machine. Une séquence rejouée, une signature
modifiée ou une identité révoquée est refusée avant affichage de l'état.

## Développement dans le LAB

Depuis la racine de `console/`, dans `lab-console` uniquement :

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m your_cloud_console --help
```

Les parcours de preuve sont documentés dans `docs/lab/p1-premier-contact.md` et
`docs/lab/p2-machine-observable.md`.

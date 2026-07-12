# Console d'infrastructure

La console conserve le premier contact P1 strictement en lecture seule avec une
machine Debian 13 amd64 : déclaration versionnée, registre de clés d'hôte SSH
séparé, audit de compatibilité et API HTTP locale sur socket Unix.

Elle n'utilise jamais les fichiers SSH personnels. La première clé d'hôte doit
être acceptée explicitement par TOFU visible ou correspondre à une empreinte
fournisseur passée sur la ligne de commande. Une différence ultérieure est un
refus.

La machine observable ajoute un plan d'enrôlement explicitement approuvé, un registre public des
identités de machines et l'inspection ponctuelle d'enveloppes Protobuf signées.
La clé privée Ed25519 reste sur la machine. Une séquence rejouée, une signature
modifiée ou une identité révoquée est refusée avant affichage de l'état.

La sécurisation prépare ensuite un compte d'administration distinct et une clé
OpenSSH chiffrée avec son kit de récupération. Un second plan conserve une
session existante, prépare le rollback, puis applique SSH key-only, nftables et
les réglages système. L'audit et l'inspection utilisent automatiquement ce
nouveau chemin lorsque la clé chiffrée existe.

## Développement dans le LAB

Depuis la racine de `console/`, dans `lab-console` uniquement :

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m your_cloud_console --help
```

Les parcours de preuve sont documentés dans `docs/lab/p1-premier-contact.md` et
`docs/lab/p2-machine-observable.md`.

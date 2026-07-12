# Console P1

La console P1 fournit un premier contact strictement en lecture seule avec une
machine Debian 13 amd64 : déclaration versionnée, registre de clés d'hôte SSH
séparé, audit de compatibilité et API HTTP locale sur socket Unix.

Elle n'utilise jamais les fichiers SSH personnels. La première clé d'hôte doit
être acceptée explicitement par TOFU visible ou correspondre à une empreinte
fournisseur passée sur la ligne de commande. Une différence ultérieure est un
refus.

## Développement dans le LAB

Depuis la racine de `console/`, dans `lab-console` uniquement :

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m your_cloud_console --help
```

Le parcours de preuve P1 est documenté dans `docs/lab/p1-premier-contact.md`.

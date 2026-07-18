# Preuve LAB de `v0.0.2`

Ce dossier contient les auxiliaires de preuve de l'observation authentifiée et
bornée. `pki/` génère dans `lab-console` deux autorités et des feuilles
synthétiques propres à un run. Les clés d'autorité restent dans cette VM et ne
font partie d'aucun rapport.

Le fichier `pki/main.go` porte la directive de construction `ignore` : il ne
devient donc jamais un second artefact du produit. Dans `lab-console`, la
preuve l'appelle explicitement avec :

```text
go run tests/lab/v0.0.2/pki/main.go <répertoire-vide-absolu>
```

La preuve actuelle est une orchestration assistée, consignée dans
[`docs/lab/v0.0.2-observation.md`](../../../docs/lab/v0.0.2-observation.md) avec
ses préconditions, commandes, résultats et incidents. La présence de ces
sources ne constitue pas, à elle seule, une preuve.

Lorsqu'un pilote en une commande sera décidé puis implémenté, chacun de ses
rejeux devra produire sous `artifacts/proofs/v0.0.2/` un résultat structuré et
explicitement vert. Ce pilote est seulement enregistré comme automatisation
restante ; il ne fait pas partie de `v0.0.2`.

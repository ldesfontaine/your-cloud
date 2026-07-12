# Preuve LAB P5 — mode distant et multi-infrastructures

> Preuve produite le 2026-07-12 dans la topologie `v1-full`, depuis la base
> locale `bad861f` et avant tout commit P5. Aucun composant, build, test,
> playbook ou import du projet n'a été exécuté sur le laptop.

## Cibles et garde préalable

`tools/labctl list` a confirmé l'origine `your-cloud/labctl`, les gabarits et
les adresses avant les mutations :

| VM | Gabarit | Adresse IPv4 | Réseau principal |
|---|---|---|---|
| `lab-console` | `console` | `192.168.241.193` | `lab-operator` |
| `lab-coordinateur` | `coordinateur` | `192.168.242.103` | `lab-public` |
| `lab-gateway` | `passerelle` | `192.168.241.151` | trois réseaux |
| `lab-machine-1` | `machine` | `192.168.243.153` | `lab-site-private` |
| `lab-machine-2` | `machine` | `192.168.243.158` | `lab-site-private` |

Toutes diffèrent de `192.168.122.123` et `10.66.66.1`. Seuls des secrets
synthétiques ont été créés dans `lab-console`, sans afficher leur valeur.

## Frontières réseau

La création réelle a révélé que cloud-init ne configurait que la première des
trois interfaces de la passerelle. `labctl topology prepare v1-full` corrige ce
manque de manière idempotente : routes IPv4, IPv6 ULA, DNS public simulé,
forwarding et NAT sortant. La politique nftables refuse le forwarding par
défaut, autorise le plan d'administration, limite le site privé vers le public
à DNS, HTTP, HTTPS et 8443, et ne crée aucune redirection entrante.

Le NAT et le DNS ont été prouvés depuis une machine privée. Les connexions
IPv6 depuis la console vers le coordinateur et les deux machines ont réussi.
Le profil permet de borner séparément les sources du port mTLS sans élargir les
CIDR SSH ; dans ce LAB, la source IPv4 NATée appartient à `lab-public`.
Depuis le réseau public, les tentatives vers 8443 sur les deux machines privées
ont échoué. En fin de preuve, aucun daemon privé ni ancien coordinateur local
n'avait de listener de télémétrie actif.

## Builds et validations

Dans `lab-console` :

- `go test ./...` a réussi ;
- les binaires daemon et coordinateur 0.5.0 ont été construits avec
  `-trimpath` ;
- les 34 tests Python ont réussi ;
- tous les playbooks ont réussi leur `--syntax-check` ;
- Go 1.24, Ansible 2.19.4, protoc 3.21.12 et les dépendances Python épinglées
  ont été exécutés uniquement dans la VM.

## Deux infrastructures et migration progressive

Les trois machines ont été auditées, enrôlées et sécurisées depuis une image
Debian 13 neuve. `lab-machine-1` appartient à `site-a`, `lab-machine-2` à
`site-b`, tandis que le coordinateur public reste une machine gérée disponible.
Les nouvelles connexions d'administration IPv4 et IPv6 ont été prouvées.

Chaque site a d'abord publié vers un point local P4. Le même coordinateur Go a
ensuite été installé sur `lab-coordinateur` à l'adresse IP
`192.168.242.103:8443`, sans DNS obligatoire et sans migrer implicitement une
machine. Chaque pilote a reçu ce nouveau point en première position tout en
gardant son ancien endpoint comme secours. Les re-runs des deux migrations ont
donné `changed=0`.

Le coordinateur public a servi des enveloppes originales signées pour les deux
infrastructures. La console read-only les a revérifiées avec le registre
Ed25519 de référence. Un mouvement logique de `lab-machine-1` de `site-a` vers
`site-b`, puis son retour, n'a déplacé aucun service et n'a changé ni son
identité ni son historique. Une lecture immédiate de la même séquence a été
refusée comme rejeu, conformément au contrat.

## Coupure, fallback et reconstruction

Le coordinateur public a été arrêté puis les daemons redémarrés pour forcer une
tentative immédiate. La lecture distante a affiché exactement :

```text
REFUS : pilotage indisponible : coordinateur injoignable ; état de la machine et des services inconnu
```

Les services et SSH sont restés actifs. Les anciens points locaux ont reçu les
nouveaux états aux séquences 12 et 13. La base `telemetry.db` du coordinateur
public, donnée dérivée, a ensuite été supprimée dans le LAB pendant son arrêt.
Après reconstruction et redémarrage des daemons, les deux états sont revenus
aux séquences 13 et 14 sans réenrôlement.

Après plusieurs échanges, un plan séparé a retiré chaque ancien endpoint ; son
re-run a donné `changed=0`. Les profils privés ont refermé 8443, les anciens
services locaux ont été arrêtés et les lectures finales distantes ont atteint
les séquences 17 et 18. Une requête sans certificat client a été refusée par le
serveur public.

## Schéma 2 et domaine de panne partagé

La déclaration de la preuve était encore au schéma 1. Une lecture normale l'a
refusée en demandant `declaration migrate`. Sans `--approve`, le plan a affiché
les trois machines et deux infrastructures conservées, puis le SHA-256 du
fichier est resté identique. L'application approuvée a ajouté uniquement
`failure_domain: null` aux infrastructures, sans mutation distante ni runtime.

Avant déclaration, `site-a` et `site-b` étaient affichés comme `unknown`. Un
plan sans approbation n'a rien changé. L'opérateur a ensuite déclaré
`lab-site-private` pour les deux. Le contrôleur de LAB a enregistré séparément
la même détection avec la source `labctl:metadata` et la preuve de topologie
vérifiée. Les deux vues finales étaient `confirmed`.

Ces infrastructures restent deux regroupements logiques, mais partagent un seul
domaine de panne. Le produit ne les présente donc ni comme indépendantes ni
comme hautement disponibles. Une divergence future entre déclaration et
détection serait affichée comme `conflict`, sans correction silencieuse.

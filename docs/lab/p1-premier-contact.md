# Preuve LAB P1 — premier contact

> Preuve produite le 2026-07-12 dans la topologie `quick`. Aucun composant du
> projet n'a été exécuté sur le laptop de développement.

## Cibles vérifiées

La lecture préalable par `tools/labctl list` a confirmé :

| VM | Gabarit | Adresse observée | Topologie | Origine |
|---|---|---|---|---|
| `lab-console` | `console` | `192.168.240.174` | `quick` | `your-cloud/labctl` |
| `lab-machine-1` | `machine` | `192.168.240.126` | `quick` | `your-cloud/labctl` |

Les deux adresses appartiennent à `192.168.240.0/24` et diffèrent de
`192.168.122.123` et `10.66.66.1`. Les deux VM possèdent un snapshot `clean`.
Une clé bootstrap synthétique du LAB a été copiée dans `lab-console` ; aucune
clé personnelle ou valeur réelle n'a été utilisée.

## Tests de la console

La suite a été exécutée dans `lab-console` avec Python 3.13 :

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Résultat : 12 tests réussis. Ils couvrent le schéma, les doublons de cible, le
registre privé et son refus de corruption, le TOFU explicite, le changement de
clé d'hôte, Debian incompatible, l'audit éligible et l'API locale en lecture
seule.

## Premier contact et audit

Sans option de confiance, le premier audit a refusé la connexion et affiché
l'empreinte Ed25519 présentée. Après accord explicite avec
`--accept-host-key`, la console a épinglé cette clé dans son registre propre,
sans utiliser les fichiers SSH personnels.

L'audit réel de `lab-machine-1` a établi :

- Debian 13 `trixie`, `amd64` / `x86_64` ;
- systemd actif, `sudo` présent et élévation de bootstrap disponible ;
- espace disque et horloge acceptables ;
- sources SSH, nftables et sysctl recensées ;
- sockets en écoute affichés ;
- aucun gestionnaire de configuration persistant ni ruleset nftables ambigu ;
- décision `eligible`, zéro mutation distante ;
- P2 possible et P3 maintenu comme plan séparé.

SSH et le système peuvent naturellement journaliser une connexion d'audit.
« Zéro mutation » signifie ici qu'aucune configuration, paquet, compte,
service, règle réseau ou fichier administré n'est modifié par la console.

## Répétabilité et refus

Deux audits consécutifs ont produit exactement la même sortie :

```text
642e1f920b848d99f0a0ee758bf1567658af82d80148d5cbdfe7b3bdd21d5713
```

Une seconde machine déclarée sur `192.168.240.126:22` a été refusée avant
connexion avec le message `cible SSH ambigu ou dupliqué`. Le test unitaire de
compatibilité refuse Debian 12, et le test de confiance refuse une clé d'hôte
différente après épinglage.

## API locale

La console a servi `/v1/status` sur un socket Unix de mode `0600`. La réponse
annonçait le schéma 1, le transport `unix-socket` et
`mutation_capable: false`. Une requête POST a reçu `405 Method Not Allowed`.

## Limites restantes

- La preuve incompatible réelle utilise l'ambiguïté de cible ; Debian 12 est
  couvert par un test isolé, pas par une troisième VM.
- Le LAB `v1-full`, l'enrôlement, le daemon et toute mutation appartiennent aux
  paliers suivants.
- Cette preuve ne constitue ni une installation publiée ni une release.

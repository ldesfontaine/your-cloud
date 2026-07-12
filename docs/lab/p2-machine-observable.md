# Preuve LAB P2 — machine observable

> Preuve produite le 2026-07-12 dans la topologie `quick`, depuis le commit de
> référence `46ef38e`. Aucun composant, build, test, playbook ou import du projet
> n'a été exécuté sur le laptop de développement.

## Cibles et garde préalable

`tools/labctl list` a confirmé avant les mutations :

| VM | Gabarit | Adresse observée | Topologie | Origine |
|---|---|---|---|---|
| `lab-console` | `console` | `192.168.240.174` | `quick` | `your-cloud/labctl` |
| `lab-machine-1` | `machine` | `192.168.240.126` | `quick` | `your-cloud/labctl` |

Les deux adresses diffèrent de `192.168.122.123` et `10.66.66.1`. La
déclaration et la clé bootstrap synthétique de P1 ont été réutilisées sans lire
ni afficher la valeur de cette clé.

## Génération, tests et build

Le contrat a été généré dans `lab-console` avec `protoc` 3.21.12 et
`protoc-gen-go` v1.36.6. Le module Go 1.24 a ensuite été verrouillé par
`go.mod` et `go.sum`.

Résultats dans le LAB :

- `go test ./...` réussi pour le daemon et le contrat généré ;
- build natif `your-cloud-observer` réussi avec `-trimpath` ;
- 15 tests Python réussis avec Python 3.13 ;
- refus vérifiés d'un payload modifié, d'une séquence rejouée et d'une identité
  révoquée ;
- test de débordement SQLite réussi avec émission d'une lacune et base sous sa
  limite réduite de test.

## Plan, enrôlement et idempotence

Sans `--approve`, la console a affiché le compte, le binaire, la file de 10 Mio,
les unités choisies et l'absence de port, puis a quitté sans mutation.
`ansible-playbook --syntax-check` a réussi avant l'application réelle.

L'enrôlement de `lab-machine-1` a créé une identité Ed25519 individuelle et
accepté un premier état signé. Le re-run final du playbook a donné :

```text
ok=9 changed=0 unreachable=0 failed=0
```

## État signé et persistance

L'inspection finale a affiché :

- machine `lab-machine-1`, affectation `available` ;
- provenance `signature-ed25519-verified` ;
- séquence persistante 7, après une première acceptation à la séquence 2 ;
- Debian 13, noyau, `boot_id`, instant du dernier démarrage et uptime ;
- charge, mémoire, espace de `/`, besoin de redémarrage et `ssh.service`
  explicitement choisi.

Deux inspections immédiates du même état ont produit le refus :

```text
REFUS : enveloppe rejouée ou en retour arrière : séquence 2, dernière acceptée 2
```

Après redémarrage du daemon, l'identifiant public est resté identique et la
séquence est passée de 2 à 4. La clé privée n'a jamais été lue : seul son mode
`0600`, son propriétaire `your-cloud-observer` et la stabilité de l'identifiant
public ont été contrôlés.

## Moindre privilège, stockage et réseau

Le daemon est `active` et `enabled` sous `your-cloud-observer`, compte système
`nologin` sans groupe privilégié. L'unité impose notamment :

```text
NoNewPrivileges=yes
ProtectSystem=strict
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/your-cloud/observer
```

Le répertoire privé est en `0700`, la clé et `telemetry.db` en `0600`. La base
observée occupait 16 Kio pour une limite dure annoncée de 10 485 760 octets.
La liste TCP/UDP de la VM ne contenait aucun processus `your-cloud-observer` ;
le daemon ne peut ouvrir ni IPv4 ni IPv6 à P2.

## Désenrôlement sans effet distant

Pour conserver la machine observable en fin de preuve, le désenrôlement a été
exercé sur une copie isolée du registre public de la console. Le même chemin de
code a révoqué l'identité et annoncé `Aucune mutation distante effectuée`.
`ssh.service` et `your-cloud-observer.service` étaient `active` avant et après.

## Limites restantes

- P2 fournit une inspection ponctuelle via le chemin d'administration ; il ne
  promet pas d'observation continue lorsque la console est éteinte.
- Le coordinateur, HTTPS/mTLS, les accusés durables et la reprise après coupure
  appartiennent à P4.
- Cette preuve LAB n'est ni une installation publiée ni une release.

# Preuve LAB P4 — observation continue locale

> Preuve produite le 2026-07-12 dans la topologie `quick`, depuis la base
> locale `adf21a6` et avant tout commit P4. Aucun composant, build, test,
> playbook ou import du projet n'a été exécuté sur le laptop.

## Cibles et garde préalable

`tools/labctl list` a confirmé avant les mutations :

| VM | Gabarit | Adresse | Topologie | Origine |
|---|---|---|---|---|
| `lab-console` | `console` | `192.168.240.174` | `quick` | `your-cloud/labctl` |
| `lab-machine-1` | `machine` | `192.168.240.126` | `quick` | `your-cloud/labctl` |

Les adresses diffèrent de `192.168.122.123` et `10.66.66.1`. La machine était
déjà enrôlée, sécurisée et administrable. Seuls les secrets synthétiques du LAB
ont été utilisés, sans afficher leur valeur.

## Génération, tests et builds isolés

Le contrat a été régénéré dans `lab-console` avec `protoc` 3.21.12 et
`protoc-gen-go` v1.36.6. Les résultats dans le runner LAB sont :

- `go test ./...` réussi pour le daemon, le coordinateur et le protocole ;
- builds natifs du daemon et du coordinateur réussis avec `-trimpath` ;
- 21 tests Python réussis, dont les identités X.509 chiffrées, leur ajout au
  kit de récupération et les événements signés ;
- `--syntax-check` réussi pour le profil Linux et l'installation locale ;
- re-run final de l'installation : `ok=17 changed=0 failed=0`.

## Frontières et transport

Le profil nftables possédé a ouvert TCP 8443 uniquement depuis les réseaux
d'administration déclarés, tout en reprouvant les nouvelles connexions SSH
IPv4 et IPv6 et le rollback dédié. Le coordinateur écoute explicitement sur
`192.168.240.126:8443` ; le daemon ne possède toujours aucun socket entrant.

Les comptes `your-cloud-observer` et `your-cloud-coordinator` sont distincts,
`nologin` et sans `sudo`. Leurs clés, certificats, répertoires et bases sont
séparés. L'autorité privée de transport reste chiffrée dans la console ; le
coordinateur reçoit seulement son certificat, sa clé de service, l'autorité
publique et une copie dérivée du registre public des machines actives. Le kit
de récupération a été migré puis revérifié au schéma 2 avec l'autorité privée
de transport toujours chiffrée.

Une lecture sans identité cliente est refusée. Une identité `console:local`
peut lire l'état et le journal, mais les routes de publication exigent
`daemon:lab-machine-1`. Après relais, la console a revérifié la signature
Ed25519 originale de chaque enveloppe.

## Durabilité, coupure et reprise

La base du coordinateur occupait 16 Kio pour une limite dure de 64 Mio. L'état
relayé a progressé de la séquence 97 à 101 après une coupure contrôlée du
coordinateur. Pendant cette coupure, le daemon et SSH sont restés `active`.
Après reprise, les événements signés 2 à 4 ont été retrouvés dans l'ordre, sans
page suivante ni lacune inventée.

`lab-console` a ensuite été arrêtée proprement pendant plus de deux cycles
complets. `lab-machine-1` est restée active seule. Après redémarrage de la
console, celle-ci a retrouvé via mTLS l'état signé à la séquence 119 ainsi que
le journal déjà conservé. Aucun arrêt du coordinateur, du daemon, de SSH ou
d'un service hébergé n'a été causé par l'absence de la console.

Le déploiement final du daemon `0.4.0` a ensuite été relayé à la séquence 123.

Cette extinction a aussi révélé que la persistance du domaine libvirt devait
être vérifiée. `labctl` rend désormais les domaines persistants, redémarre une
VM gérée sans recréer son disque et refuse toute extinction forcée.

## Limites restantes

- P4 prouve le mode local colocalisé dans le LAB `quick`, pas un coordinateur
  public ni plusieurs infrastructures.
- La topologie `v1-full`, le VPS simulé, le passage NAT et la migration par
  machine pilote appartiennent à P5.
- La base du coordinateur reste une donnée dérivée : sa sauvegarde n'est pas
  présentée comme une autorité ni comme une preuve de haute disponibilité.
- Cette preuve n'est ni une installation publiée ni une release.

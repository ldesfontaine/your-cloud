# Preuve LAB — sécuriser une machine sans perdre l'accès

> Preuve produite le 2026-07-12 dans la topologie `quick`. Aucun composant,
> test, build, playbook ou import du projet n'a été exécuté sur le laptop.

## Cibles et filet de récupération

`tools/labctl list` a confirmé avant chaque série de mutations :

| VM | Gabarit | Adresse | Topologie | Origine |
|---|---|---|---|---|
| `lab-console` | `console` | `192.168.240.174` | `quick` | `your-cloud/labctl` |
| `lab-machine-1` | `machine` | `192.168.240.126` | `quick` | `your-cloud/labctl` |

Les adresses diffèrent de `192.168.122.123` et `10.66.66.1`. Le snapshot
`observable` a été posé avant la sécurisation. Le gabarit `machine` a servi de
confirmation dédiée et `libvirt-console` d'accès hors bande. Seuls des secrets
synthétiques ont été utilisés sans jamais afficher leur valeur.

## Stockage chiffré et nouveau compte

Sans approbation, le premier plan a annoncé la clé, le kit, le compte et les
preuves attendues, puis n'a rien appliqué. Après approbation :

- une clé Ed25519 propre à `lab-machine-1` a été écrite en OpenSSH chiffré ;
- le kit de récupération `0600`, hors dépôt, a été rouvert avec succès ;
- `your-cloud-admin` a été créé non-root avec sa clé dédiée ;
- une nouvelle connexion et `sudo -n` vers root ont été prouvés ;
- le re-run a donné `ok=6 changed=0 failed=0` ;
- l'accès bootstrap root est resté ouvert pendant ce premier plan.

## Profil et maintien de l'accès

Le second plan a confirmé la machine dédiée, l'accès hors bande, les réseaux
`192.168.240.0/24` et `fe80::/10`, ainsi que nftables `1.1.3-1` épinglé. Avant
les changements risqués, il a conservé une session root et préparé un rollback
borné.

Après application :

- de nouvelles connexions administratives ont réussi en IPv4 et en IPv6
  link-local, avec `sudo` ;
- `PasswordAuthentication` et `KbdInteractiveAuthentication` valent `no` ;
- `PermitRootLogin` vaut `no` et `PubkeyAuthentication` vaut `yes` ;
- une nouvelle connexion root a reçu `Permission denied (publickey)` ;
- le ruleset `inet your_cloud` refuse `input` et `forward` par défaut, garde
  `output` ouverte et autorise SSH uniquement depuis les deux réseaux déclarés ;
- les redirections IPv4 et IPv6 valent `0` ;
- SSH, nftables et le daemon d'observation sont restés `active` ;
- le rollback est privé, exécutable et indépendant du snapshot LAB.

Le re-run final du profil a donné :

```text
ok=22 changed=0 unreachable=0 failed=0
```

## Dérive et continuité d'observation

Un commentaire a été ajouté manuellement au fichier sysctl possédé. Le plan a
répondu `REFUS : dérive sur un fichier possédé, aucune correction automatique`
et n'a rien appliqué. Le fichier a ensuite été restauré explicitement depuis la
copie de preuve ; le plan est revenu à `profil déjà possédé et sans dérive`.

Après fermeture de root, l'inspection signée a encore fonctionné par le compte
administratif et accepté l'état à la séquence 50. L'audit a vu 18 lignes
nftables possédées, zéro conflit, zéro limite et une décision `eligible`. Il a
aussi rendu visibles, sans lire leur contenu, les fichiers `authorized_keys` du
compte géré et le résidu root désormais inactif pour les nouvelles connexions.

## Validations isolées

Dans `lab-console` :

- 18 tests Python couvrent aussi le kit, le mauvais mot de passe et les
  permissions du fichier de mot de passe ;
- les tests Go restent réussis ;
- les deux playbooks passent `--syntax-check` avant application ;
- aucun redémarrage automatique ni politique de correctifs n'a été activé.

Cette preuve ferme la première sécurisation. Elle ne vaut ni profil universel,
ni sécurisation d'une machine réelle, ni release.

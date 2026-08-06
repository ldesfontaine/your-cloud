# Plan OCI contrôlé et sonde de validation

> Statut : proposition de contrat pour le palier `#14`, suivie par `#81`.
> Elle fixe ce que `plan_sha256` et `rollback_sha256` de l'enveloppe
> d'approbation attestent, la liste fermée des champs qu'un plan de ce palier
> peut porter, et l'image de la sonde épinglée. Rien ici n'est implémenté tant
> que ce contrat n'est pas validé.

## Rôle du plan dans la chaîne existante

L'enveloppe d'approbation prouvée au palier `#13` signe deux hachages,
`plan_sha256` et `rollback_sha256`, sans dire ce qu'ils recouvrent : son unique
opération (`diagnose_protocol_read_only`) ne mute rien. Ce contrat donne à ces
deux hachages leur premier contenu réel.

Le partage d'autorité ne change pas :

- le **Controller** construit le plan et son rollback, les fige et les
  transporte ; il ne peut fabriquer aucune approbation ;
- la **Console** présente les deux documents, recueille la confirmation native
  et signe l'enveloppe qui nomme leurs hachages exacts ;
- l'**Auxiliaire** revérifie tout localement : signature contre l'ancre
  root-owned, époque, expiration, séquence anti-rejeu, puis conformité des
  documents reçus aux hachages signés, avant la moindre mutation.

Un plan n'est jamais un script : c'est une description fermée d'un état
demandé. Aucun champ ne porte de commande, de chemin, de playbook ni
d'inventaire.

## Document de plan

Un plan est un document JSON strict au sens de `internal/strictjson` : une
seule valeur, aucune clé dupliquée, aucun champ inconnu, chaque champ sous son
nom canonique exact. Il est borné à **4096 octets** avant analyse.

Champs — c'est la liste fermée du schéma `1`, aucun autre champ n'existe :

| Champ | Forme | Sens |
|---|---|---|
| `schema_version` | entier, `1` | version du schéma de plan |
| `infrastructure_id` | UUIDv4 canonique minuscule | même règle que l'enveloppe |
| `machine_id` | `[a-z0-9][a-z0-9-]{2,62}` | la seule machine cible |
| `operation` | `deploy_oci_probe` ou `remove_oci_probe` | l'état demandé |
| `image_reference` | chaîne | référence sans tag, registre inclus |
| `image_digest` | `sha256:` + 64 hexadécimaux minuscules | digest épinglé |
| `local_port` | entier, `1024..65535` | port d'écoute sur `127.0.0.1` |

Décisions portées par cette forme :

- **Pas de champ tag.** Le tag est une indication humaine que le plan affiché
  peut mentionner, mais l'identité exécutable est le digest. Un champ tag
  offrirait une seconde vérité contournable ; il n'existe pas.
- **Pas de champ volume, réseau, privilège conteneur ou variable.** La sonde
  n'en a besoin d'aucun. Un plan qui en porterait un est un champ inconnu,
  refusé par le décodage strict avant toute lecture de son contenu — c'est la
  forme la plus forte du refus demandé par `#14`.
- **`127.0.0.1` est une constante du contrat**, pas un champ. Aucune valeur
  approuvable ne peut exposer la sonde au-delà de la machine.
- **`remove_oci_probe` porte les mêmes champs** que le déploiement : le retrait
  vise une instance exacte, pas « ce qui se trouve là ».

## Hachage canonique

`plan_sha256` est le SHA-256 d'un **transcript binaire à domaine séparé**,
reconstruit depuis les champs analysés et jamais depuis les octets reçus — le
même procédé que le transcript de l'enveloppe, tenu entre Go et Rust par des
vecteurs déterministes des deux côtés.

```text
domaine  "your-cloud/oci-plan.v1\0"
puis     schema_version   sur 1 octet
         infrastructure_id, machine_id, operation,
         image_reference             en champs préfixés par longueur uint32
         image_digest (32 octets décodés)  en champ préfixé
         local_port                  en uint32 big-endian
```

Deux implémentations qui analysent le même document produisent ainsi le même
hachage, et un transport qui réindente ou réordonne le JSON transporte le même
plan, tandis qu'un transport qui change une valeur change le hachage et
invalide l'approbation.

`rollback_sha256` est le hachage, par le même transcript, d'un **second
document de plan complet** : pour un déploiement, le retrait exact de la même
instance ; pour un retrait, le redéploiement exact. Le rollback est donc lu,
affiché, approuvé et vérifié comme un plan — jamais une promesse implicite.

## Opérations et privilèges

Chaque opération exige exactement sa liste de privilèges, en égalité stricte
comme aujourd'hui :

| Opération | Privilèges exacts |
|---|---|
| `deploy_oci_probe` | `mutate_local_state`, `read_local_state` |
| `remove_oci_probe` | `mutate_local_state`, `read_local_state` |

C'est la première utilisation réelle de `mutate_local_state`, jusqu'ici nommé
seulement pour être refusé. `diagnose_protocol_read_only` continue de le
refuser.

## Sonde de validation épinglée

L'image retenue pour la sonde du palier `#14` est **`traefik/whoami`,
version `v1.11.0`** :

```text
docker.io/traefik/whoami@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab
```

Ce digest est celui de la liste de manifestes de `v1.11.0`. L'image `amd64`
qu'elle résout — la seule que `v0.1.0` prouve — est
`sha256:4f90b33ddca9c4d4f06527070d6e503b16d71016edea036842be2a84e60c91cb`.

Motifs du choix : binaire Go statique d'environ 3 Mo, serveur HTTP qui ne fait
que décrire la requête reçue, aucune donnée persistante, aucun privilège,
publié par l'organisation Traefik déjà présente dans le scénario de référence,
et disponible en `arm64` pour une preuve future sans changer de sonde.

La sonde reste ce que la roadmap en dit : un service jetable de validation,
accessible uniquement sur `127.0.0.1`, retiré à la fin de la preuve. **Elle
n'est pas un composant de Your Cloud** : aucune infrastructure utilisateur ne
la reçoit sans plan approuvé, et aucun composant du produit ne dépend d'elle.

Ce palier n'accepte qu'elle : `image_reference` doit valoir exactement
`docker.io/traefik/whoami` et `image_digest` exactement le digest ci-dessus.
Tout autre registre, dépôt ou digest est refusé avant mutation. Élargir la
liste des images acceptables sera une décision d'un palier ultérieur, pas une
généralisation silencieuse de celle-ci.

## Ce que l'Auxiliaire vérifie avant de muter

Dans l'ordre, et sans effet partiel :

1. l'approbation elle-même, comme aujourd'hui : signature contre l'ancre,
   cible, époque, expiration, privilèges exacts, séquence consommée
   durablement avant mutation ;
2. que les documents de plan et de rollback reçus correspondent octet pour
   octet, via leur transcript, aux deux hachages signés ;
3. que le plan cible cette machine et cette infrastructure ;
4. que le contenu reste dans les bornes de ce contrat : opération connue,
   image et digest exacts, port dans sa plage ;
5. que la machine est capable : systemd et cgroup v2 présents, Podman rootless
   utilisable — sinon refus avant toute écriture.

L'idempotence se calcule contre l'état réel : premier déploiement
`changed=true` ; nouveau plan demandant le même état `changed=false` sans
réécriture ni redémarrage ; retrait d'une sonde absente `changed=false` ; toute
dérive constatée exige un nouveau plan et n'est jamais corrigée en silence.

## Bornes reprises des contrats existants

- L'enveloppe garde sa durée de vie maximale de 900 secondes ; ce contrat n'y
  ajoute rien.
- Une coupure pendant la mutation produit un résultat inconnu : la séquence
  déjà consommée reste refusée après redémarrage, aucun rejeu automatique,
  observation exigée avant tout nouveau plan
  (`docs/architecture/CYCLE-DE-VIE-DES-SERVICES.md`).
- Le Controller transporte des octets ; tout ce qu'un plan signifie est
  re-dérivé sur la machine depuis ses propres ancres, comme pour l'enveloppe.

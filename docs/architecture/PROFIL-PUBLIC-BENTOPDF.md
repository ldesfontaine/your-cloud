# Profil public BentoPDF et point d'entrée Traefik

> Statut : contrat d'architecture validé (`#87`) pour le palier `#15`.
> Il étend le contrat du plan (`PLAN-OCI-CONTROLE.md`) aux opérations de
> service et de publication, fixe l'édition, la licence et les images
> épinglées du profil, et décrit ce que la preuve devra constater. Les
> implémentations le suivent depuis `#88` (plans et surface du Controller) et
> `#90` (service géré côté Auxiliaire) ; la preuve LAB du palier reste `#92`.

## Ce que ce profil est, et n'est pas

BentoPDF est la charge de référence du parcours « service web OCI publié en
HTTPS ». Ni BentoPDF, ni Traefik, ni un VPS ne sont des composants de Your
Cloud ou des installations par défaut : chaque instance exige une
déclaration, un placement, un plan et une approbation explicites. La
topologie de ce palier tient sur **une seule machine publique** — Traefik et
BentoPDF sur le VPS de référence, le service joint par le loopback. Le LAN,
WireGuard et Vaultwarden appartiennent aux paliers suivants.

## Édition et licence

L'édition retenue est **`bentopdf`** (complète), image
`ghcr.io/alam00000/bentopdf`, licence **AGPL-3.0**. Justifications :

- l'AGPL convient à une exposition réseau d'une image officielle non
  modifiée : l'obligation de source est satisfaite par l'amont lui-même ;
- l'édition complète est celle qui exerce `SharedArrayBuffer`, donc les
  en-têtes d'isolation que le palier veut prouver ; l'édition `simple` ferait
  passer la preuve en affaiblissant ce qu'elle prouve ;
- le traitement est entièrement côté client : le conteneur sert des fichiers
  statiques et ne reçoit aucun document — le profil public le plus sûr que ce
  palier puisse choisir.

## Images épinglées

```text
ghcr.io/alam00000/bentopdf@sha256:a4ed090f29823da5e296e2c2f8603664da71676156ea47c3f186cc73eec38db0
docker.io/library/traefik@sha256:9c3b91d5fb7770853ca5c1124a23c34bf2d9b47ffaebeab2614cbaf410dcb2ac
```

Les digests ci-dessus sont les listes de manifestes de `bentopdf v1.9.0` et
`traefik v3.7.10`. Comme pour la sonde : les tags sont une indication humaine,
l'identité exécutable est le digest, et aucun champ de plan ne porte de tag.
Une mise à jour est un **nouveau plan** dont le digest diffère — jamais une
mutation silencieuse, jamais un `latest`.

## Schéma de plan v2

Le schéma `2` conserve tout le procédé du schéma `1` — document JSON strict
borné à 4096 octets, transcript binaire à domaine séparé
(`your-cloud/oci-plan.v2\0`), rollback comme document complet inverse, paire
gelée par le Controller, signature par la Console, revérification par
l'Auxiliaire — et ajoute six opérations, en trois paires inverses, aux
listes de champs fermées :

| Opération | Champs propres (au-delà de `schema_version`, `infrastructure_id`, `machine_id`, `operation`) |
|---|---|
| `deploy_web_service` / `remove_web_service` | `service_profile`, `image_reference`, `image_digest`, `local_port` |
| `deploy_entrypoint` / `remove_entrypoint` | `image_reference`, `image_digest` |
| `publish_route` / `retire_route` | `route_host`, `backend_port` |

Décisions portées par cette forme :

- **`service_profile` est une liste fermée à une entrée : `bentopdf`.**
  Le profil décide de tout ce que le plan n'énonce pas (compte, fiche,
  en-têtes) ; un profil inconnu est refusé avant lecture du reste. Élargir la
  liste sera une décision d'un palier ultérieur.
- **`image_reference` et `image_digest` restent dans le plan** bien que le
  profil les épingle aussi : le palier #15 exige que l'origine, la version et
  le digest apparaissent dans ce que l'humain approuve. L'Auxiliaire refuse
  tout couple qui n'est pas exactement celui du profil — le champ rend le
  plan lisible, il n'ouvre aucun choix.
- **L'entrée n'a ni port ni hôte dans son plan** : `443` public, `80` limité
  à la redirection, adresses d'écoute et répertoire du file provider sont des
  constantes du contrat. Un point d'entrée n'a rien d'approuvable au-delà de
  son existence et de son image.
- **`route_host` est borné** : minuscules, chiffres, tirets et points,
  3 à 253 caractères, sans joker. `backend_port` reprend la plage
  `1024..65535` et doit nommer le port loopback d'un service géré présent.
- **Le rollback reste l'inverse exact** : retrait pour un déploiement,
  redéploiement pour un retrait, `retire_route` pour `publish_route`.

## Surface du Controller étendue de trois routes

`PLAN-OCI-CONTROLE.md` avait étendu la surface métier du Controller d'exactement
une route, `POST /v0/probe-plans`. Le présent contrat l'étend de trois, et
d'aucune autre :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/service-plans` | construire et geler la paire plan/rollback d'un service géré pour une machine de l'inventaire, sans muter aucune machine |
| `POST /v0/entrypoint-plans` | construire et geler la paire plan/rollback du point d'entrée pour une machine de l'inventaire, sans muter aucune machine |
| `POST /v0/route-plans` | construire et geler la paire plan/rollback d'une route publiée pour une machine de l'inventaire, sans muter aucune machine |

Décisions attachées à ces routes :

- **Trois routes sœurs plutôt qu'une route à discriminant.** Une route unique
  aurait exigé un schéma de requête portant les champs des trois groupes, donc
  une lecture avant refus ; séparées, chaque requête est une liste fermée et un
  champ d'un autre groupe est refusé par le décodage strict avant que sa valeur
  soit lue. C'est la décision que prennent déjà les documents eux-mêmes.
- Elles empruntent la **même authentification de session** que les routes métier
  existantes : aucun nouveau chemin d'autorité, aucun nouveau code d'erreur. Une
  machine hors inventaire reçoit `422 machine_not_active`, dans la liste fermée
  existante.
- L'appartenance à l'inventaire reste une **preuve passée** d'enrôlement, pour
  la même raison qu'au palier précédent : un plan décrit sans muter, et
  l'Auxiliaire re-dérive localement toute autorité avant d'agir.
- Les deux documents voyagent comme **chaînes JSON portant leurs octets
  canoniques exacts**, accompagnés de leurs digests — la seule forme de
  transport, il n'en existe pas de seconde.
- La Console ne choisit **ni l'infrastructure, ni l'image, ni le digest** :
  l'infrastructure est celle dont ce Controller est l'autorité, et l'image est
  celle que le profil épingle. Elle choisit le profil, et un profil inconnu est
  refusé avant que le reste de la requête compte.

La borne de `route_host` se lit exactement ainsi : minuscules, chiffres, tirets
et points ; 3 à 253 caractères ; premier et dernier caractère lettre ou chiffre —
donc ni point ni tiret en tête ou en fin ; aucun label vide, donc aucun point
consécutif. Les tirets consécutifs restent acceptés parce qu'un label punycode en
porte. Le joker n'a pas de refus propre : il n'appartient pas au jeu de
caractères.

## Comptes et placement

Chaque service géré court sous son propre compte système sans shell, créé
comme au palier #14 (plages subordonnées allouées explicitement, linger,
fiche Quadlet root-owned sous son `$HOME`) :

```text
your-cloud-svc-bentopdf    le service, port privé sur 127.0.0.1
your-cloud-entrypoint      Traefik, seul autorisé à écouter publiquement
```

La fiche de BentoPDF reprend tous les contrôles de la sonde (`Pull=never`,
`ReadOnly=true`, `NoNewPrivileges=true`, `DropCapability=ALL`, publication sur
le loopback uniquement, et le sysctl des ports bas borné à l'espace de noms
quand — et seulement quand — l'image en a besoin).

### Le port du conteneur est une constante du profil

Le plan d'un service géré choisit le port de loopback que la machine publie ;
l'image décide de ce qui écoute derrière. Pour l'édition épinglée cette valeur
est **`8080`** : la configuration de l'image ne déclare que `8080/tcp`, et le
NGINX non privilégié dont elle hérite y écoute sous un compte ordinaire. C'est
donc une constante du profil, au même titre que le compte et la fiche, et
jamais un champ approuvable — comme le `80` de la sonde en est une.

Une conséquence borne la phrase ci-dessus sur les contrôles repris : le sysctl
des ports bas n'a de sens que pour une image qui écoute **sous 1024**. C'est le
cas de la sonde, ce ne l'est pas de BentoPDF. La fiche du profil reprend donc
tous les autres contrôles à l'identique et **ne porte pas** cette ligne : un
contrôle qui n'ouvre rien se lirait comme un contrôle dont on a eu besoin.

## Le point d'entrée : Traefik sans socket de moteur

- **Aucun provider Docker/Podman.** Traefik ne voit aucun socket de moteur :
  ses routes viennent exclusivement du **file provider**, dont le répertoire
  root-owned n'est inscriptible que par l'Auxiliaire. Le compte de l'entrée
  lit les fragments, il ne les écrit jamais — la même séparation que la
  fiche Quadlet.
- **Un fragment par route**, écrit par `publish_route` : un routeur sur le
  `Host()` exact déclaré, TLS, le service backend `127.0.0.1:backend_port`,
  et le middleware d'en-têtes du profil. Retirer la route retire le fragment
  et rien d'autre : l'entrée devient muette pour ce nom, le service continue.
- **`443` et `80` en rootless** : la publication des ports passe par le
  sysctl hôte `net.ipv4.ip_unprivileged_port_start=80`, appliqué comme
  **effet déclaré du plan d'entrée** et retiré avec lui. C'est un
  assouplissement borné à la machine d'entrée — une machine dont c'est le
  rôle — et il est écrit dans le plan que l'humain approuve plutôt que fait
  en silence. Une capacité par service a été écartée : elle voyagerait dans
  la fiche, que ce contrat veut garder sans élargissement.
- **Refus par défaut** : pas de routeur par défaut, pas de certificat de
  complaisance signé pour un nom non déclaré. Une requête par IP directe ou
  un `Host` inconnu reçoit le refus générique de l'entrée, jamais une route
  applicative.

## TLS de la preuve

Le palier prouve **HTTPS sur un nom déclaré dans le LAB**, pas une émission
publique : une autorité synthétique créée par le harnais signe le certificat
du nom déclaré ; le client de la preuve épingle cette autorité. ACME et un
nom public appartiennent à l'infrastructure réelle, pas à ce palier — la
mécanique de route et de TLS prouvée ici ne change pas quand le certificat
change de source.

## En-têtes d'isolation et dépendances runtime

La route du profil ajoute, comme middleware nommé du fragment :

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

Ils conditionnent `SharedArrayBuffer`, que l'édition complète exerce. La
preuve devra constater les deux en-têtes sur la réponse HTTPS **et** le
fonctionnement d'une fonction représentative qui en dépend, servie depuis la
seule origine déclarée : l'image auto-héberge ses outils WASM, et le constat
« aucune origine externe requise » fait partie de la preuve de sortie.

## Ce que la preuve devra constater

Chaque critère de `#15` correspond à un constat pris depuis **l'extérieur de
la machine** (un client du LAB, pas la machine elle-même) :

1. rien n'existe avant l'approbation ; chaque ressource naît d'un plan ;
2. `https://<nom-déclaré>/` répond 200 avec les deux en-têtes d'isolation ;
3. le port applicatif n'est pas joignable depuis l'extérieur ;
4. l'IP directe et un nom inconnu n'obtiennent aucune route applicative ;
5. `http://` sur `80` ne fait que rediriger vers `443` ;
6. une fonction `SharedArrayBuffer` représentative fonctionne sous HTTPS ;
7. redémarrage machine : tout revient sans action ; mise à jour : nouveau
   plan au digest changé, `changed=true`, puis idempotence ; retrait :
   l'état annoncé, le port public fermé en dernier ;
8. le démontage rend la machine à un état de clôture nommé.

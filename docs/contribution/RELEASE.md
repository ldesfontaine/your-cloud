# Signer le lot serveur, et ce que cette signature protège

L'installateur de la Console porte le paquet serveur plutôt que d'aller le
chercher : la raison est au [contrat d'amorçage](../architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md).
Cette page décrit le geste qui rend cet embarquement vérifiable, et **rien
d'autre** — elle ne décrit pas la publication d'une release.

## Ce que la signature est, et ce qu'elle n'est pas

| | |
| --- | --- |
| **C'est** | un mécanisme du produit : l'Assistant refuse d'installer un lot que l'ancre scellée dans son propre binaire n'a pas signé |
| **Ce n'est pas** | une attestation de provenance. Celle-ci lierait un build à une porte d'intégration continue, reste différée (`#140`), et ne remplacerait pas celle-ci |

**La clé n'est jamais dans l'intégration continue.** La porte hébergée atteste
une révision ; elle ne signe pas. Une clé de signature dans un secret
d'hébergement ramènerait la racine de confiance exactement là où le contrat
d'amorçage refuse de la mettre — auprès d'un compte, à l'instant du build.

La moitié privée vit **hors ligne**, dans le gestionnaire de mots de passe du
mainteneur. Elle n'existe sur aucune machine du LAB, dans aucune session
d'agent, et dans aucun fichier de ce dépôt.

## Pourquoi Ed25519 brut, et pas `minisign`

Le format n'est pas un goût : il est imposé par la fonction qui vérifie.
`installation::bundle::verify` lit l'ancre par
`VerifyingKey::from_bytes(&[u8; 32])` puis appelle `key.verify(manifest_bytes,
&signature)` — donc **Ed25519 pur, sur les octets du manifeste tels quels, avec
une signature détachée de 64 octets**.

`minisign` pré-hache le message (BLAKE2b) et enveloppe la signature dans son
propre format, avec identifiant de clé et commentaire signé. L'y adapter
demanderait de modifier une fonction de sécurité déjà prouvée pour qu'elle
convienne à un outil — l'inverse de l'ordre des priorités.

`openssl` produit exactement les octets attendus, et il est déjà sur le poste.

## Générer la paire — geste du mainteneur, une seule fois

À exécuter **sur votre poste**, hors LAB, hors session d'agent.

```bash
umask 077 && openssl genpkey -algorithm ed25519 -out your-cloud-release.pem
```

```bash
openssl pkey -in your-cloud-release.pem -pubout -outform DER | tail -c 32 > release-anchor.pub
```

La seconde commande extrait les 32 octets bruts de la clé publique de son
enveloppe DER. Vérifiez la taille — c'est le seul contrôle qui compte ici :

```bash
stat -c %s release-anchor.pub
```

`32`, et rien d'autre. Ensuite :

- **`your-cloud-release.pem` part dans le gestionnaire de mots de passe**, puis
  est effacé du disque. C'est la moitié privée ;
- **`release-anchor.pub` est committé** dans les sources, à l'emplacement que le
  binaire scelle. C'est l'ancre.

## Signer un lot, à chaque release

Le lot est produit par [`tools/build-server-bundle`](../../tools/build-server-bundle),
qui écrit le `.deb` et le manifeste liant sa version, sa cible, sa taille et son
empreinte. Il **ne signe rien**, délibérément. La signature est votre geste, au
même moment que le tag :

```bash
openssl pkeyutl -sign -rawin -inkey your-cloud-release.pem -in bundle-manifest.json -out bundle-manifest.sig
```

`-rawin` est essentiel : il signe les octets du fichier tels quels, sans
pré-hachage. Le manifeste est écrit compact et **sans saut de ligne final**,
parce que la signature couvre ce qui est sur le disque — un ré-rendu en aval
casserait la signature qu'il vient de recevoir.

Contrôle avant de committer quoi que ce soit :

```bash
stat -c %s bundle-manifest.sig
```

`64`, et rien d'autre.

## Où le couple signé vit, et ce qui le re-vérifie

Le manifeste et sa signature sont committés dans
[`packaging/server-bundle/manifest/`](../../packaging/server-bundle/manifest/).
Le `.deb` du lot, lui, n'entre jamais au dépôt : chaque build de la Console le
**reconstruit** depuis les sources avec l'outillage épinglé, confronte le
manifeste produit octet pour octet au manifeste signé, et refuse toute dérive
par son nom (`console/tools/prepare-server-bundle.mjs`). La porte hébergée fait
la même reconstruction dans un conteneur `debian:13` épinglé par digest — le
seul environnement CI dont l'outillage est celui du verrou.

Le paquet Debian de la Console livre alors les trois fichiers sous
`/usr/lib/your-cloud-console/server-bundle/`, et l'Assistant installé les
retrouve **depuis sa propre position attestée** (`/proc/self/exe`), jamais
depuis un argument ni un environnement. Son verdict se relit à tout moment sur
une machine où la Console est installée :

```bash
/usr/bin/your-cloud-native-bootstrap-assistant --verify-embedded-server-bundle
```

`VERIFIED version=… target=debian-13-amd64 size=… sha256=…`, ou un refus nommé.
C'est la porte du produit — `bundle::verify` contre l'ancre scellée — pas un
outil de diagnostic séparé.

## Rotation, et perte

Il n'y a pas de révocation : l'ancre est scellée dans un binaire déjà installé,
et rien ne peut la joindre après coup. **Une nouvelle ancre est donc une
nouvelle release**, et les installations existantes continuent de faire
confiance à l'ancienne jusqu'à ce que leur humain installe la nouvelle Console.

C'est une propriété, pas une lacune : l'ancre ne peut pas être changée à
distance, donc elle ne peut pas être changée par quelqu'un d'autre.

En cas de perte de la moitié privée, ou de doute sur elle : générer une nouvelle
paire, committer la nouvelle ancre, publier une nouvelle release, et le dire
dans ses notes.

## Ce que la chaîne refuse — mesuré, pas supposé

Les commandes ci-dessus ont été éprouvées contre la porte réelle du produit
— `verify-bundle` de l'Assistant, construit depuis ces sources — avec une paire
synthétique jetable. Elle accepte le lot intact et refuse chacune des trois
attaques par son propre nom :

```text
lot intact                     VERIFIED version=0.1.0 target=debian-13-amd64
artefact altéré d'un octet     REFUSED DigestMismatch
signature d'une autre clé      REFUSED SignatureNotByAnchor
version attendue différente    REFUSED UnexpectedVersion
```

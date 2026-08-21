# Contrat exécutable de `v0.0.2`

> Statut : contrat décidé, implémenté et prouvé dans le LAB le 18 juillet 2026.
> La preuve multi-VM reste assistée ; ses résultats et incidents sont conservés
> dans le [rapport LAB](../../lab/v0.0.2-observation.md).

Ce contrat ouvre uniquement le palier « observation authentifiée et bornée »
de la [roadmap de v0.1.0](ROADMAP.md). Il transforme cette intention en comportements
mesurables sans introduire l'App ni un chemin d'action vers les machines.

## Résultat observable

Deux Daemons enrôlés relèvent le profil fixe `host-health.v1`, conservent les
observations non confirmées dans un tampon local borné et les envoient par une
connexion sortante mTLS vers l'unique Relay candidat. Le Relay authentifie le
certificat et l'enrôlement de chaque machine, enregistre durablement une
observation avant de l'accuser et conserve visibles l'âge, les séquences et les
lacunes reçues.

Le Daemon n'écoute aucun port réseau. Le Relay ne renvoie aucun ordre, profil,
chemin ou demande de collecte. Une commande locale en lecture seule rend l'état
du Daemon et de son tampon sans ouvrir d'API réseau.

## Placement LAB

```text
lab-app
|- construit et teste l'exécutable unique
|- crée deux autorités de certification synthétiques séparées
`- conserve seul leurs clés privées pendant la preuve

lab-machine-1 / LAN privé
`- Daemon non-root -- HTTPS mTLS sortant --> Relay

lab-coordinateur / VPS simulé / seule candidate Relay
|- Relay non-root :8443
`- Daemon non-root -- HTTPS mTLS local --> Relay
```

Les clés privées des autorités ne quittent pas `lab-app`. Chaque Daemon
reçoit uniquement sa clé client, son certificat et le certificat public de
l'autorité Relay. Le Relay reçoit uniquement sa clé serveur, son certificat,
le certificat public de l'autorité Daemon et son registre d'enrôlement. Les
secrets sont synthétiques et propres au scénario ; `keys.txt` et
`/srv/infra/secrets/` ne sont jamais lus.

## Profil fixe `host-health.v1`

Un **collecteur** est une lecture locale intégrée et versionnée dont l'entrée,
la sortie et les droits sont connus avant exécution. Ce palier active exactement
trois collecteurs sans paramètre libre :

| Collecteur | Lecture | Champs produits | Exclusions |
|---|---|---|---|
| `host.uptime.v1` | temps écoulé depuis le démarrage fourni par le noyau | `uptime_seconds` entier positif ou nul | aucune heure civile fournie par la machine pour décider de la fraîcheur |
| `host.memory.v1` | compteurs mémoire totaux et disponibles du noyau | `total_bytes`, `available_bytes` | aucun contenu de processus, swap détaillé ou chemin |
| `host.rootfs.v1` | statistiques du système de fichiers monté sur `/` | `total_bytes`, `available_bytes` | aucun autre volume, parcours ou motif global |

Le profil ne lit ni log, ni contenu de fichier arbitraire, ni variable
d'environnement, ni liste de processus, ni unité systemd, ni voisin réseau. Il
refuse tout collecteur, champ, version, cible ou argument inconnu. Une erreur
d'un collecteur produit un état borné pour ce collecteur sans transformer le
Daemon en shell et sans supprimer les résultats valides des autres collecteurs.

La cadence candidate est de trente secondes. La preuve mesure la taille
encodée, le coût CPU, mémoire et disque ainsi que la durée d'écriture avant de
figer la valeur définitive. Aucun résultat ne peut réduire la cadence sous dix
secondes sans nouvelle validation du contrat.

## Identités, certificats et endpoint

Le **mTLS** est une connexion TLS dans laquelle le Daemon vérifie le certificat
du Relay et le Relay vérifie celui du Daemon. Il protège le trajet ; il ne prouve
pas qu'une machine compromise dit vrai.

Deux autorités X.509 Ed25519 distinctes sont créées pour le scénario :

- l'autorité Relay signe uniquement un certificat `serverAuth` pour l'identité
  DNS exacte `relay.v0-0-2.your-cloud.test` ;
- l'autorité Daemon signe uniquement des certificats `clientAuth`, un par
  machine, dont l'identité machine figure dans un `subjectAltName` dédié ;
- les certificats d'autorité portent les contraintes CA et usages de signature
  adaptés ; les certificats feuilles ne peuvent pas signer d'autres
  certificats ;
- TLS 1.3 est le seul protocole accepté et les bibliothèques standard Go
  réalisent la validation de chaîne, de période, de nom et d'usage ;
- aucun contournement de validation, suite cryptographique maison, redirection
  HTTP ou repli vers HTTP n'est admis.

L'endpoint approuvé est une origine HTTPS canonique composée du schéma, du nom
DNS, du port `8443` et de l'identité cryptographique attendue. Utilisateur,
chemin, query, fragment, port implicite ou autre nom sont refusés avant la
connexion. Un changement d'un de ces éléments exige un nouveau provisionnement,
jamais une découverte ou une poursuite automatique.

## Enrôlement et révocation

L'enrôlement de `v0.0.2` est un provisionnement manuel hors réseau dans le LAB.
Il n'ajoute aucun endpoint d'inscription, jeton bootstrap, renouvellement
automatique ou App.

Le registre Relay associe exactement :

- l'identifiant de la machine ;
- l'identité portée par le certificat client ;
- son numéro de série et son empreinte cryptographique ;
- son état `active` ou `revoked`.

Le Relay exige la chaîne X.509 valide puis cette association positive. Un
certificat signé par la bonne autorité mais absent du registre reste inconnu et
refusé. La révocation est une décision d'autorisation locale, atomiquement
rechargeable ; elle est revérifiée à chaque requête afin qu'une connexion TLS
réutilisée ne contourne pas le nouvel état. Ce palier ne simule ni CRL, ni OCSP,
ni service de renouvellement.

## Message, séquence et accusé durable

Chaque observation possède un schéma strict, l'identifiant machine, la version
du Daemon, le profil et sa version, une séquence persistante, l'heure locale de
collecte et les trois résultats typés. Le Relay utilise sa propre heure de
réception pour calculer l'âge.

Le Relay accepte une séquence nouvelle ou le rejeu octet pour octet d'une
séquence déjà enregistrée. Une même séquence avec un contenu différent est une
collision refusée. L'accusé contient l'identité et la séquence exactes et n'est
émis qu'après publication atomique et durable de l'état Relay. Un accusé
incohérent, trop grand, mal formé ou reçu d'un mauvais endpoint ne retire rien
du tampon local.

## Tampon local et lacunes

Le Daemon conserve séparément :

- le dernier état courant, qui remplace sa version précédente ;
- les observations non confirmées, ordonnées par séquence ;
- la prochaine séquence persistante ;
- les lacunes encore à transmettre.

Les plafonds de sécurité absolus sont `16 MiB`, `10 000` observations et
`24 h`. Les limites d'exploitation fixées après la première mesure réelle sont
`64 KiB`, `120` observations et `1 h`, la première atteinte l'emportant. Un
état vide mesuré occupait environ `588` octets et chaque observation en attente
ajoutait environ `375` octets ; la limite d'une heure correspond à 120 périodes
de trente secondes tout en conservant de la marge pour les lacunes. La
configuration ne peut pas dépasser les plafonds absolus.

Les `588` octets mesurent le fichier d'état complet lorsqu'il ne contient aucune
attente. Ils ne sont pas annoncés comme des données en attente : le diagnostic
additionne uniquement les enveloppes de la file et rend donc `0` octet lorsque
leur nombre est nul. La limite de `64 KiB`, elle, continue de porter sur l'état
persisté complet afin de borner réellement l'espace disque.

Lorsqu'une limite impose une suppression, les plus anciennes observations en
attente partent d'abord, l'état courant reste disponible et une lacune persistée
indique l'intervalle de séquences, les heures et le nombre supprimé. Une lacune
est livrée avec la reprise ; ni le Daemon ni le Relay ne reconstruisent une
continuité fictive. Les écritures, suppressions et reprises après crash doivent
laisser un état lisible ou échouer fermé sans purger silencieusement le tampon.

## Diagnostic local administratif

```text
your-cloud diagnose observation [--format=json]
```

Cette commande lit un état local au chemin fixe et protégé. Elle n'ouvre aucune
connexion, ne collecte rien et ne modifie pas le tampon. Elle affiche sous forme
humaine ou JSON strict : identité machine, profil, dernière collecte, dernière
livraison, état du Relay, endpoint approuvé, expiration du certificat, nombre
et taille des éléments en attente, âge du plus ancien, prochaine séquence et
lacunes. Elle n'affiche aucune clé, contenu de certificat privé ou donnée hors
profil. Tout argument, format ou chemin supplémentaire est refusé.

Dans le lot systemd de `v0.0.2`, le tampon appartient au compte dynamique du
Daemon sous `/var/lib/private`. La commande est donc une opération
administrative locale exécutée ponctuellement par `root`. Cela ne rend pas le
Daemon root, n'ajoute aucune unité permanente et n'accorde aucun accès réseau au
diagnostic.

## Preuves de sortie

La preuve LAB doit au minimum :

1. construire et tester un seul exécutable dans `lab-app`, puis comparer
   son SHA-256 sur les deux machines ;
2. montrer les trois collecteurs et leurs mesures de coût, taille et cadence ;
3. établir deux connexions mTLS valides sans listener Daemon ;
4. refuser certificat inconnu, révoqué, expiré, mauvaise autorité, mauvais
   usage, mauvais nom Relay et mauvaise association machine-certificat ;
5. refuser HTTP, mauvais hôte, mauvais port, chemin, query, fragment et toute
   redirection ;
6. refuser profil, collecteur, champ, version, chemin ou entrée libre inconnus ;
7. arrêter le Relay, remplir puis saturer le tampon sans remplir le disque ni
   arrêter les Daemons ;
8. montrer que la saturation conserve l'état courant et crée une lacune exacte ;
9. redémarrer les Daemons pendant l'indisponibilité et retrouver séquences,
   tampon et lacune ;
10. redémarrer le Relay, reprendre dans l'ordre, accepter un rejeu identique,
    refuser une collision et ne retirer localement qu'après accusé durable ;
11. exécuter en `root` le diagnostic administratif local pendant les états
    nominal, indisponible, saturé et repris sans réseau local supplémentaire ;
12. redémarrer chaque rôle, retirer puis réinstaller les composants sans
    processus, listener, clé ou fichier orphelin hors de l'état annoncé.

Chaque refus vérifie que le Relay et les Daemons légitimes restent disponibles,
que leur PID et leurs autorités n'ont pas changé et qu'aucun secret n'apparaît
dans les logs ou artefacts.

## Justification de sécurité proportionnée

Les actifs sont les identités privées, l'intégrité de la source affichée, la
confidentialité du trajet et la disponibilité du disque. Les menaces traitées
sont l'usurpation d'une machine ou du Relay, la réutilisation d'une identité
révoquée, la dérive silencieuse d'endpoint, l'injection d'une collecte libre,
le rejeu divergent et le remplissage du disque pendant une panne.

Les deux autorités séparent les rôles de transport. Les listes positives,
schémas stricts, sorties bornées, connexions sortantes, stockage limité et
lacunes visibles appliquent valeur sûre par défaut, moindre privilège,
réduction de surface et défense en profondeur. Les preuves de révocation,
continuité, cryptographie et mesure d'efficacité contribuent de manière
proportionnée aux mesures NIS2 pertinentes sans constituer une déclaration de
conformité.

Risques résiduels : root peut remplacer les fichiers locaux ; une machine
compromise peut mentir dans les champs qu'elle est autorisée à produire ; un
Relay compromis voit les observations en clair ; les autorités de test ne
constituent pas une PKI de production ; aucun renouvellement automatique ou
réponse à incident complète n'est fourni.

## Hors périmètre absolu

App, Ansible métier, commande distante, canal d'action, Auxiliaire local,
WireGuard, service OCI, proxy Web, scan ou découverte du LAN, haute
disponibilité Relay, remplacement automatique, Proxmox, OpenStack, worker
d'automatisation et projet IaC restent absents. Les ajouter exige un autre
contrat ; aucune difficulté rencontrée ici ne les autorise implicitement.

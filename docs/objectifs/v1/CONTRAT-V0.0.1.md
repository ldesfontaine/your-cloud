# Contrat exécutable de `v0.0.1`

> Statut : contrat implémenté et prouvé dans le LAB le 16 juillet 2026, y compris
> l'artefact unique, la cohabitation isolée et le refus Relay par défaut. Voir le
> [rapport LAB](../../lab/v0.0.1-presence.md).

Ce contrat transforme le résultat attendu par la roadmap en comportements
mesurables. Il ne définit aucune capacité des paliers suivants.

## Placement LAB

```text
lab-machine-1 / lab-site-private          lab-coordinateur / lab-public
exécutable your-cloud                     même exécutable your-cloud
`- Daemon non-root ---- HTTP JSON ------> |- Relay non-root :8443
                                           `- Daemon non-root --> Relay local
```

`lab-coordinateur` est le VPS simulé et la seule candidate Relay. Il exécute en
parallèle les modes Daemon et Relay depuis les mêmes octets, sous deux comptes
distincts. `lab-machine-1` représente la machine du LAN et exécute seulement le
Daemon. Le gateway autorise sa sortie vers le réseau public synthétique et
n'ajoute aucune redirection entrante vers le site privé.

Le build et les tests ont lieu dans `lab-app`. Le laptop sert seulement à
éditer, inspecter Git et piloter `labctl`.

## Transport minimal confiné

Le Daemon envoie une requête `POST /v0/presence` en HTTP/1.1 vers le Relay sur
le port `8443`. Le binaire et le script d'installation imposent tous deux
l'origine exacte `http://192.168.242.103:8443` et refusent utilisateur, chemin,
partie query ou fragment. Ce port haut est déjà le seul port applicatif borné
autorisé de `lab-site-private` vers `lab-public` par la topologie. Il n'implique
aucun TLS : le transport reste explicitement non chiffré dans cet incrément. Le
corps JSON ne dépasse pas 512 octets et contient exactement :

```json
{
  "machine_id": "lab-machine-1",
  "daemon_version": "v0.0.1",
  "sent_at": "2026-07-16T12:00:00Z"
}
```

| Champ | Origine | Destination | Limite |
|---|---|---|---|
| `machine_id` | configuration locale du Daemon | liste positive du Relay | exactement `lab-coordinateur` ou `lab-machine-1` |
| `daemon_version` | binaire du Daemon | contrôle de compatibilité du Relay | exactement `v0.0.1` |
| `sent_at` | horloge de la VM du Daemon | information affichée par le Relay | horodatage RFC 3339 valide, jamais utilisé pour décider de la fraîcheur |

Le binaire Relay refuse toute écoute différente de
`192.168.242.103:8443`, même en présence d'un manifeste candidat valide. Tout
champ inconnu, absent, dupliqué, écrit avec une casse différente, toute valeur
mal formée, second objet JSON ou corps trop grand est refusé. Une présence valide
reçoit `204 No Content`. Les erreurs de schéma reçoivent `400`, un corps trop
grand `413`, une méthode interdite `405` et un chemin inconnu `404`.

`QUERY /v0/machines` consulte l'état sans le modifier. `QUERY`, standardisée
par la RFC 10008, porte une opération sûre et idempotente dont le corps décrit
la requête. Le corps `application/json` de `v0.0.1` est exactement `{}` : il
signifie « toutes les machines autorisées », sans introduire de filtre ou
langage d'interrogation d'un palier futur. Le Relay annonce
`Accept-Query: "application/json"`, interdit la mise en cache avec
`Cache-Control: no-store` et refuse un corps absent, non JSON, non vide ou
supérieur à 32 octets. Les deux routes refusent toute partie query de l'URI, y
compris un `?` vide : le corps JSON reste l'unique contrat de consultation.

La réponse rend toujours les deux identifiants autorisés, triés. Pour chaque
machine, le Relay expose la version et l'horodatage déclarés, son propre
horodatage de réception et un état parmi :

- `absent` : aucun signal reçu depuis le démarrage du Relay ;
- `recent` : dernier signal reçu il y a moins de 4 secondes ;
- `old` : dernier signal reçu il y a au moins 4 secondes.

Le Daemon envoie toutes les secondes avec un délai réseau maximal de 2 secondes.
Le Relay borne aussi la lecture des en-têtes, du corps, l'écriture de la réponse
et les connexions inactives. Son état reste volontairement en mémoire : après
son redémarrage, les deux machines redeviennent `absent`, puis `recent` au
prochain signal. Aucun tampon, historique ou stockage durable n'entre dans cet
incrément. Un signal accepté ne produit pas un log par envoi ; le Daemon
journalise seulement le passage en indisponibilité et le retour à la normale,
pas chaque nouvelle tentative.

## Cycle de vie

Le builder LAB produit un seul exécutable Go sans dépendance externe. Les deux
cibles installent exactement ce fichier sous
`/usr/local/lib/your-cloud/your-cloud`. Chaque rôle conserve sa configuration et
son unité systemd dédiées.

Installer l'Agent vérifie que l'identifiant autorisé correspond exactement au
nom d'hôte LAB, puis active uniquement le Daemon. Activer le Relay est une seconde
opération explicite qui crée un manifeste candidat root-owned. Le mode Relay
refuse avant toute écoute si ce manifeste manque, est un lien symbolique, est
modifiable par un autre compte ou ne respecte pas le schéma positif attendu.

Un remplacement du lot prépare le nouvel artefact avant sa bascule et conserve
les fichiers ainsi que les états actifs précédents. Daemon puis Relay
colocalisé doivent garder le même PID actif pendant trois contrôles de
stabilité au démarrage. Si une étape échoue, `install-agent` restaure l'ancien lot,
réinitialise un éventuel `start-limit-hit` et relance seulement les rôles qui
étaient actifs. L'injection de `/bin/false` doit donc échouer tout en rendant
l'état absent lors d'une première installation, ou l'ancienne empreinte et les
deux rôles actifs lors d'un remplacement.

Le Relay et les Daemons utilisent des comptes système distincts, sans shell,
sans capacité Linux, sans accès en écriture au système et sans privilège
d'administration. Le Daemon n'écoute aucun port. Arrêt et retrait doivent
laisser zéro processus actif, zéro unité chargée, zéro binaire et zéro fichier
de configuration du composant retiré. Toute erreur d'arrêt ou d'inspection,
ainsi que tout PID ou listener restant hors de l'unité attendue, bloque la
suppression des fichiers.

## Justification de sécurité proportionnée

Les actifs concernés sont la disponibilité du Relay et l'intégrité de l'état
de présence affiché. Les menaces traitées maintenant sont un message mal formé
qui ferait tomber le Relay, une entrée non bornée qui consommerait sa mémoire et
un processus recevant des droits inutiles.

HTTP/JSON via la bibliothèque standard est retenu devant un protocole TCP
maison ou gRPC : il fournit des limites et erreurs visibles sans parseur réseau
propriétaire ni chaîne de génération. `POST` exprime l'écriture de présence ;
`QUERY` exprime la consultation sûre et répétable avec un corps JSON. Une liste
positive, des schémas stricts,
des délais et des comptes non-root appliquent les valeurs sûres par défaut, la
réduction de surface et le moindre privilège recommandés par OWASP. Les tests
hostiles, le cycle de retrait et la mesure de leur efficacité contribuent de
façon proportionnée aux mesures NIS2 de développement sûr, contrôle d'accès,
gestion des risques et continuité.

Le risque résiduel est volontairement important et visible : HTTP ne chiffre
ni n'authentifie le signal. Tout pair capable d'atteindre ce port LAB peut lire
le trafic ou usurper un identifiant autorisé. La topologie isolée est donc une
condition du scénario, pas une défense finale. `v0.0.1` ne revendique ni
conformité OWASP/NIS2, ni transport utilisable hors du LAB.

## Preuves de sortie

1. construire l'exécutable unique et exécuter tous les tests dans `lab-app` ;
2. prouver son empreinte identique sur les deux machines ;
3. lancer Daemon et Relay en parallèle sur le VPS sous deux comptes distincts,
   puis le Daemon seul sur la machine du LAN et montrer deux états `recent` ;
4. refuser le mode Relay sur la machine non candidate avant toute écoute ;
5. arrêter un Daemon et montrer uniquement sa transition vers `old` après
   4 secondes ;
6. refuser identifiant absent, mal formé, non autorisé, champ inconnu et corps
   supérieur à 512 octets, puis refuser les corps `QUERY` invalides et montrer
   le Relay toujours actif ;
7. redémarrer le Relay et observer `absent`, puis le retour des deux signaux ;
8. redémarrer les Daemons sans processus orphelin ;
9. retirer les trois processus et vérifier l'absence de processus, unité,
   binaire et configuration ;
10. réinstaller une dernière fois pour laisser un état annoncé et reproductible.

## Hors périmètre

Interface, métrique système, mTLS, HTTPS, enrôlement, certificat, tampon,
historique, base de données, App, Auxiliaire, Ansible métier, conteneur, service
utilisateur, WireGuard et tout détail d'un palier suivant restent absents.
`v0.0.1` compare les octets par SHA-256, mais ne revendique pas encore signature,
SBOM ou provenance de release : ces garanties restent exigées avant la preuve
finale de `v0.1.0`.

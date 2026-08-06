# Profil privé Vaultwarden : données, sauvegardes et trajet par le passage

> Statut : contrat d'architecture validé (`#99`) pour le palier `#17`.
> Il étend le schéma 2 au premier service à données du produit, fixe ses
> sauvegardes, son confinement et la route qui le publie par le seul passage
> privé. Les implémentations le suivent depuis `#100` (plans et surface du
> Controller) ; la preuve LAB du palier reste `#104`.

## Ce que ce profil est, et n'est pas

Vaultwarden est la charge de référence du parcours « service privé
persistant » : déployé sur la machine du LAN, publié en HTTPS par le point
d'entrée du VPS, joint **uniquement** par le passage privé du palier `#16`.
Ni Vaultwarden, ni cette topologie ne sont imposés à une infrastructure.
C'est le premier profil dont les données survivent au conteneur — tout ce
que les paliers précédents interdisaient aux services sans état reste
interdit ; ce qui change est nommé ici, et rien d'autre ne change.

## Image épinglée

```text
docker.io/vaultwarden/server@sha256:ebdfe70701c60ac0c28c697e787cea767d7972940b786037b29fe0d507f821e8
```

Liste de manifestes de `1.37.1` (variante Debian). L'image `amd64` qu'elle
résout est `sha256:e9efdf001bf0d68c21f2cbfb8e1d9b5961a7ca9c85e0a7e58bf51a13b997d744` ;
l'`arm64` existe (`sha256:2bfaa5744f8bf4b407145cf698405372057091958e9508887746f279df522219`),
ce qui laisse une preuve future changer d'architecture sans changer de
profil. Constaté sur le registre plutôt que cru : port interne **80**
(`ExposedPorts 80/tcp` — la fiche porte donc le sysctl des ports bas borné à
l'espace de noms, comme la sonde), volume **`/data`** déclaré par l'image.

## Les opérations : quatre paires de plus au schéma 2

| Opération | Champs propres (au-delà de la tête commune) |
|---|---|
| `deploy_private_service` / `remove_private_service` | `service_profile`, `image_reference`, `image_digest`, `local_port`, `origin_host` |
| `publish_link_route` / `retire_link_route` | `route_host`, `backend_port` |
| `snapshot_service` / `discard_snapshot` | `service_profile`, `snapshot_slot` |
| `restore_service` / — (voir le retour) | `service_profile`, `snapshot_slot` |

- **`origin_host`** (borne des hôtes, réutilisée) est l'origine exacte que
  Vaultwarden exige (`DOMAIN`). Elle est un champ parce qu'elle lie le
  service à la route qui le publiera : l'humain approuve un service qui ne
  fonctionnera correctement que sous ce nom, et le nom est sous ses yeux.
  **Publier est un plan séparé et optionnel** : un service privé déployé
  sans route vit sur le seul loopback de sa machine — c'est l'état d'un
  utilisateur sans domaine, et il est licite indéfiniment. L'origine reste
  exigée parce que l'instance doit savoir qui elle est le jour où la route
  arrive ; un usage sérieux du coffre demande de toute façon un contexte
  sécurisé, donc HTTPS derrière un nom, fût-il purement interne.
- **`snapshot_slot`** : étiquette bornée (`[a-z0-9][a-z0-9-]{0,31}`).
  L'emplacement `previous` est **réservé** : aucun plan ne peut le nommer,
  il appartient au mécanisme de retour.
- **Le profil `vaultwarden` rejoint la liste fermée** de `service_profile`
  (deux entrées désormais). Un profil décide de tout ce que le plan
  n'énonce pas ; `deploy_web_service` continue de refuser `vaultwarden`
  comme `deploy_private_service` refuse `bentopdf` — un service à données
  ne passe pas par la porte des services sans état.

## La fiche du profil privé

Elle reprend chaque contrôle des fiches de service (`Pull=never`,
`ReadOnly=true`, `NoNewPrivileges=true`, `DropCapability=ALL`, publication
loopback, sysctl d'espace de noms pour le port 80) et ajoute exactement
deux choses, toutes deux nommées :

- **Le volume persistant est une constante de placement** :
  `/var/lib/your-cloud-svc-vaultwarden/data`, monté sur le `/data` que
  l'image déclare, en écriture. C'est le seul chemin d'écriture durable du
  profil, il vit sous le foyer du compte dédié, et aucun champ de plan ne
  peut en décrire un autre — la règle des fiches sans état reste : pas de
  champ volume.
- **Les lignes d'environnement sont fermées** : les constantes de
  durcissement du profil (`SIGNUPS_ALLOWED=false`,
  `INVITATIONS_ALLOWED=false`, `SHOW_PASSWORD_HINT=false`) et une seule
  valeur approuvée, `DOMAIN=https://<origin_host>`. Les fiches sans état
  continuent d'interdire toute ligne d'environnement ; celle-ci en porte
  exactement quatre, et un test la tient aux octets près.

## Confinement de sortie : le service ne parle à personne

Le service n'a besoin d'aucune sortie réseau (pas d'icônes distantes, pas
de SMTP dans ce profil). Une table `inet your-cloud-egress` est posée avec
le déploiement : **tout trafic sortant émis par le compte du service est
refusé**, hors loopback et réponses établies. C'est ce qui rend constatable
« aucun voisin du LAN n'est joignable depuis le service » — le refus
latéral vaut pour tout le monde, voisins synthétiques compris. Le tirage
d'image précède la pose de la table ; une mise à jour la dépose, tire,
la repose — trois effets visibles, jamais une exception silencieuse.

## Sauvegardes : des emplacements nommés, immuables, hachés

- `snapshot_service` arrête proprement le service, archive `/data` daté et
  haché dans l'emplacement nommé (`/var/lib/your-cloud-svc-vaultwarden/
  snapshots/<slot>.tar.gz`), redémarre, et **le rapport porte le digest**.
  Un emplacement existant est refusé : les sauvegardes sont immuables,
  écraser exige un `discard_snapshot` explicite — deux plans visibles.
- `restore_service` : le flux écrit **d'abord** l'état courant dans
  l'emplacement réservé `previous` (le seul mutable, propriété du
  mécanisme), puis remplace `/data` par l'archive de l'emplacement nommé,
  redémarre et vérifie. **Le rollback signé de `restore_service` est
  `restore_service` visant `previous`** : un document complet, lisible,
  déterministe — le retour restaure ce que `previous` détient, et
  l'Auxiliaire garantit que `previous` détient l'état d'avant.
- L'inverse de `snapshot_service` est `discard_snapshot` du même
  emplacement ; l'inverse de `discard_snapshot` est refusé à la
  construction — détruire une archive n'a pas d'inverse honnête, son
  rollback est un plan que le Controller ne peut pas geler, et le contrat
  préfère le dire : le rollback signé d'un `discard_snapshot` est un
  document `snapshot_service` du même emplacement, qui recrée une archive
  de l'état **courant**, pas de l'archive détruite — la Console l'affiche
  en ces termes.
- La sauvegarde **hors machine** reste hors `v0.1.0` : l'utilisateur
  l'organise avec ses propres outils, et une version ultérieure décidera si
  et comment Your Cloud la représente.

## La route de lien : publiée par le seul passage

`publish_link_route` écrit un fragment du point d'entrée dont le backend
est **la constante du pair du tunnel** (`10.66.66.2`) sur le
`backend_port` approuvé — jamais une adresse de plan. Sa règle de présence
se vérifie sur le VPS : une jonction d'écouteur existe **et** son
`service_port` approuvé au palier `#16` est égal au `backend_port` — un
fragment vers un port que le tunnel ne borne pas est refusé avant tout
effet. Les en-têtes d'isolation du profil public ne s'appliquent pas ici ;
le fragment porte les en-têtes que Vaultwarden attend d'un proxy
(`X-Real-IP` transmis par défaut par Traefik). Retirer la route rend le nom
muet sans toucher au tunnel ni au service.

**Panne du passage** : si le tunnel tombe, le point d'entrée continue de
répondre et le nom déclaré rend l'erreur de passerelle du point d'entrée —
jamais un faux succès, jamais une route de repli. L'état est observable
(la jonction manque), la reprise est une nouvelle jonction approuvée, et
la preuve constate les trois temps : panne, état honnête, reprise.

## Surface du Controller étendue de quatre routes

`PROFIL-PUBLIC-BENTOPDF.md` avait étendu la surface métier du Controller de
trois routes, `PASSAGE-PRIVE-WIREGUARD.md` de trois autres. Le présent contrat
l'étend de quatre, et d'aucune autre :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/private-service-plans` | construire et geler la paire plan/rollback d'un service à données sur une machine de l'inventaire — profil, port de loopback, origine —, sans muter aucune machine |
| `POST /v0/link-route-plans` | construire et geler la paire plan/rollback de la route publiée par le seul passage, sans muter aucune machine |
| `POST /v0/snapshot-plans` | construire et geler la paire plan/rollback d'une archive nommée, sans muter aucune machine |
| `POST /v0/restore-plans` | construire et geler le retour et le document qui revient de lui, sans muter aucune machine |

Décisions attachées à ces routes :

- **Quatre routes sœurs plutôt qu'une route à discriminant**, pour la raison
  déjà retenue aux deux paliers précédents : une route unique aurait exigé un
  schéma de requête déclarant les champs des quatre groupes, donc une lecture
  avant refus. Séparées, chaque requête est une liste fermée, et un champ d'un
  autre groupe est refusé par le décodage strict avant que sa valeur soit lue.
- **Deux groupes portent exactement les champs d'un groupe plus ancien** : une
  route de lien nomme un hôte et un port comme une route publique, un retour
  nomme un profil et un emplacement comme une sauvegarde. Ce sont malgré tout
  des routes distinctes, parce qu'elles construisent des plans distincts : les
  documents décrivent des états différents et se hachent différemment, et une
  route qui trancherait entre eux sur un drapeau ferait du choix de l'humain une
  valeur qu'il faut lire correctement. Un test tient les digests deux à deux
  écartés à champs identiques.
- **La route du retour ne porte pas d'opération.** Un `restore_service` n'a
  qu'une direction : un champ pour elle serait une valeur approuvable qui ne
  peut prendre qu'une valeur. Et le document qui l'annule n'en est pas une
  seconde — c'est un `restore_service` visant `previous`, que le paquet `plan`
  construit et qu'aucune requête ne peut nommer.
- Elles empruntent la **même authentification de session** que les routes métier
  existantes : aucun nouveau chemin d'autorité, aucun nouveau code d'erreur. Une
  machine hors inventaire reçoit `422 machine_not_active`, dans la liste fermée
  existante.
- Les deux documents voyagent comme **chaînes JSON portant leurs octets
  canoniques exacts**, accompagnés de leurs digests, dans la même vue que les
  routes des paliers précédents ; son `schema_version` vaut `2` et dit sous quel
  contrat les deux documents ont été écrits.
- La Console ne choisit **ni l'infrastructure, ni l'image, ni le digest, ni le
  volume persistant, ni les lignes d'environnement, ni la table de sortie, ni
  l'adresse du pair du tunnel** : l'infrastructure est celle dont ce Controller
  est l'autorité, et le reste est une constante que le profil ou le passage
  décide. Aucune de ces valeurs n'est un champ, donc aucune requête ne peut
  déplacer un chemin d'écriture ni élargir le passage.

Ce que le schéma fixe autour de ces routes :

- **Les deux listes de profils sont fermées l'une contre l'autre.**
  `deploy_web_service` ne connaît que `bentopdf`, `deploy_private_service` que
  `vaultwarden`, et le refus croisé est une recherche qui échoue plutôt qu'une
  comparaison qu'il faut penser à écrire. Les sauvegardes se ferment sur la
  liste privée : un profil sans volume n'a rien à archiver.
- **`previous` n'apparaît que dans un document du produit**, le rollback signé
  d'un `restore_service`. La validation le refuse dans `snapshot_service` et
  dans `discard_snapshot` ; elle l'accepte dans `restore_service`, parce qu'un
  rollback est un plan à part entière, affiché, haché, transporté et décodé
  comme les autres — et c'est le constructeur, seul à l'écrire, qui refuse qu'un
  humain le soumette comme direction avant.
- **`snapshot_service` mute.** Il arrête le service, écrit une archive et le
  redémarre : l'enveloppe lui exige `mutate_local_state` autant qu'à un
  déploiement, malgré ce que le mot « sauvegarde » suggère.
- L'Auxiliaire **lit ces quatre formes de document et n'en exécute aucune** :
  chacune est refusée en la nommant, avant tout effet et avant toute lecture de
  la machine, jusqu'aux paliers qui les appliquent. La fenêtre est délibérée et
  un test la tient sur des paires réelles, gelées comme la Console les remettra.

## Ce que la preuve devra constater

1. rien — ressource, donnée, route — n'existe avant approbation ;
2. `vault.<domaine>` et `pdf.<domaine>` répondent sur la **même IP
   publique et le même 443** ; le backend n'est joignable que par le
   tunnel ; le port applicatif est muet depuis l'hostile et depuis le VPS
   hors tunnel ;
3. des secrets synthétiques écrits par l'API du service survivent au
   redémarrage des deux machines et à une **recréation contrôlée** du
   conteneur (mêmes données, nouveau conteneur) ;
4. sauvegarde vers un emplacement nommé, corruption volontaire des
   données, restauration : les secrets synthétiques reviennent, le digest
   du rapport correspond ; `previous` détient l'état corrompu — le retour
   du retour reste possible ;
5. le service confiné ne joint ni un voisin synthétique du LAN, ni
   l'extérieur ; le VPS ne joint par le tunnel que le couple approuvé ;
6. panne du passage : jonction retirée → le nom rend l'erreur honnête du
   point d'entrée ; nouvelle jonction → le service revient sans autre
   action ;
7. idempotence de chaque plan rejoué ; digest flottant, volume, port,
   pair ou trajet non approuvés refusés ; le démontage rend les machines à
   leur état de clôture nommé.

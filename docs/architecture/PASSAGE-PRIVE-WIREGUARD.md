# Passage privé WireGuard borné au service

> Statut : proposition de contrat pour le palier `#16`, suivie par `#93`.
> Il étend le contrat du plan aux opérations de lien entre deux machines
> enrôlées, fixe le sort des clés, les constantes du scénario de référence et
> les règles qui bornent le passage au seul service approuvé. Rien ici n'est
> implémenté tant que ce contrat n'est pas validé.

## Ce que ce passage est, et n'est pas

Le passage privé du scénario de référence relie le VPS public à la machine du
LAN **sans ouverture entrante vers le LAN** : la machine du LAN initie le
tunnel vers le VPS, et le seul flux applicatif autorisé va du VPS vers le
service approuvé du LAN. WireGuard, ce VPS et cette topologie sont le
scénario LAB qui rend la preuve reproductible — jamais un prérequis produit.
Une infrastructure peut employer un autre placement, garder son passage en
mode externe ou ne rien publier de privé.

## Deux machines, quatre plans, aucune clé en voyage

Un passage est établi par **quatre plans, chacun ciblant une seule machine**,
dans un ordre que le Controller séquence et que chaque Auxiliaire revérifie :

```text
1. prepare_link (écouteur, VPS)     génère les clés, crée l'interface fermée
2. prepare_link (initiateur, LAN)   idem, aucun port n'écoute
3. attach_link_peer (écouteur)      joint le pair LAN, pose les bornes
4. join_link_peer (initiateur)      joint le pair VPS, pose les bornes
```

- **Les clés privées naissent sur leur machine et n'en sortent jamais** :
  générées par l'Auxiliaire, root-owned en `0600` sous
  `/etc/your-cloud/link/`, absentes de tout rapport, plan ou journal.
- **Seule la clé publique voyage** : le rapport de `prepare_link` la porte,
  le Controller la lit comme une observation, et elle entre — lisible — dans
  le plan de jonction de l'autre machine. L'humain approuve donc un plan qui
  nomme exactement le pair qu'il accepte.
- La jonction avant préparation est refusée sur la machine (pas de clé, pas
  d'interface) ; la préparation est idempotente et **ne régénère jamais** une
  clé existante — remplacer une clé est un retrait puis une préparation,
  deux plans visibles.

## Opérations du schéma 3

Le schéma `3` conserve tout le procédé (document strict borné à 4096 octets,
transcript à domaine séparé `your-cloud/oci-plan.v3\0`, rollback comme
document complet inverse, même chaîne gel → signature → revérification) et
ajoute six opérations en trois paires inverses :

| Opération | Champs propres (au-delà de la tête commune) |
|---|---|
| `prepare_link` / `withdraw_link` | `link_role` |
| `attach_link_peer` / `detach_link_peer` | `peer_public_key`, `service_port` |
| `join_link_peer` / `leave_link_peer` | `peer_public_key`, `peer_endpoint_host`, `service_port` |

Décisions portées par cette forme :

- **`link_role` est une liste fermée à deux entrées** : `listener` (le VPS,
  qui écoute sur le port du contrat) et `initiator` (le LAN, qui sort et
  maintient le tunnel). Le rôle décide des constantes ; aucun champ ne les
  rouvre.
- **L'asymétrie est dans les opérations, pas dans des champs optionnels** :
  l'écouteur n'a pas d'endpoint à joindre, donc `attach_link_peer` n'a pas le
  champ — un champ vide n'existe pas, un champ d'un autre groupe est un champ
  inconnu, refusé avant lecture.
- **`peer_public_key`** : base64 standard canonique de 44 caractères décodant
  exactement 32 octets (le ré-encodage doit reproduire la chaîne).
- **`peer_endpoint_host`** reprend la borne de `route_host` (minuscules,
  chiffres, tirets, points, 3..253, premier et dernier alphanumériques) — un
  littéral IPv4 s'y écrit naturellement. Le port d'endpoint n'est pas un
  champ : c'est le port d'écoute du contrat.
- **`service_port`** (1024..65535) est le seul port que les règles
  autoriseront à travers le tunnel. Sur la machine du service, il doit nommer
  le port loopback d'un service géré présent — même règle de présence que la
  route du palier `#15`. Changer de pair, d'endpoint ou de port est un
  nouveau plan ; rien ne se modifie en place.
- **Les rollbacks sont les inverses exacts** : `withdraw_link` pour
  `prepare_link`, `detach_link_peer` pour `attach_link_peer`,
  `leave_link_peer` pour `join_link_peer`.

## Constantes du scénario de référence

```text
sous-réseau du lien   10.66.66.0/24 — réservé ; la garde labctl refuse déjà
                      de muter une machine portant 10.66.66.1
écouteur              10.66.66.1/32
initiateur            10.66.66.2/32
interface             yc-link0 (les noms d'interface sont bornés à 15 octets)
port d'écoute (UDP)   51820, sur l'écouteur seulement
keepalive             25 s, sur l'initiateur seulement (il traverse le NAT)
clés                  /etc/your-cloud/link/, root-owned, privée en 0600
```

Aucune de ces valeurs n'est un champ de plan. `AllowedIPs` est le `/32` du
pair et rien d'autre : le sous-réseau du LAN n'est jamais annoncé, jamais
routé, et le VPS ne connaît du LAN qu'une adresse de tunnel.

## Le passage est borné par nftables, des deux côtés

Une table nommée `inet your-cloud-link` est posée par la jonction et retirée
avec elle. Ses règles ne portent que des constantes du contrat et les valeurs
du plan approuvé :

- **Écouteur (VPS)** : en entrée publique, seul l'UDP du port d'écoute est
  accepté pour le tunnel — il rejoint 443 et la redirection 80 dans la liste
  fermée de ce que le VPS écoute. Sur `yc-link0` : en sortie, uniquement TCP
  vers `10.66.66.2` sur le `service_port` approuvé ; en entrée, uniquement
  les réponses des connexions établies. Aucun forward. SSH, tout autre port
  et tout autre destinataire sont refusés par défaut.
- **Initiateur (LAN)** : aucun port entrant depuis Internet, le tunnel sort.
  Sur `yc-link0` : en entrée, uniquement TCP depuis `10.66.66.1` vers le
  `service_port` ; en sortie, uniquement les réponses établies. Aucun
  forward, aucun accès au reste du LAN par le tunnel — la machine du LAN ne
  relaie rien.
- La dérive des règles est un changement réappliqué par un nouveau plan,
  jamais une réparation silencieuse ; retirer la jonction retire la table et
  rien d'autre ; retirer le lien (`withdraw_link`) pendant qu'une jonction
  existe est refusé en la nommant — l'ordre du retrait est une affaire de
  séquence de plans, comme au palier `#15`.

## Ce que la preuve devra constater

Le service de référence joint par le tunnel est la **sonde du palier `#14`**,
déployée sur la machine du LAN par le chemin déjà prouvé — le passage borne
un service géré existant, il n'en invente pas. Chaque critère de `#16`
correspond à un constat :

1. rien n'existe avant l'approbation : ni pair, ni route, ni règle, ni clé ;
2. après les quatre plans : le tunnel est établi, et depuis le VPS le
   `service_port` de `10.66.66.2` répond ;
3. depuis le VPS, par le tunnel : SSH refusé, tout autre port refusé, toute
   adresse du sous-réseau LAN réel refusée — seul le couple approuvé passe ;
4. depuis la machine hostile (le pilote ou `lab-console`) : la machine du
   LAN n'expose **aucun** port entrant ; le VPS n'expose que 443, 80 et
   l'UDP du tunnel ;
5. idempotence : rejouer les quatre plans rend `changed=false` sans
   rétablissement ni régénération de clé ;
6. modification = nouveau plan : un pair, un endpoint ou un port différent
   n'est jamais une mutation en place ;
7. redémarrage des deux machines : le tunnel revient sans action et les
   règles avec lui ; révocation (`detach`/`leave`) : le flux cesse, l'état
   est vérifiable ; retrait complet : interfaces, clés et tables absentes ;
8. le rapport qualifie la topologie de scénario de référence, pas de
   prérequis produit, et le démontage rend les machines à leur état de
   clôture nommé.

# Profil Linux V1

> État : profil confirmé dans le LAB `quick` le 2026-07-12.

## Préflight

Le profil exige Debian 13 amd64, systemd, une connexion SSH épinglée, une
élévation `sudo`, un espace disque et une horloge acceptables, ainsi que la
confirmation explicite que la machine est dédiée.

Il refuse avant toute mutation une autorité concurrente ou ambiguë sur SSH,
nftables ou les paramètres `sysctl`. Il ne fusionne, ne vide et ne remplace
jamais silencieusement une configuration qu’il ne possède pas.

Le gabarit LAB `machine` vaut confirmation de machine dédiée et la console
libvirt vaut accès hors bande. Une machine réelle exige ces deux confirmations
explicites adaptées à son contexte.

## Administration SSH

Le parcours crée ou adopte un compte non-root propre à la machine. Sa clé est
distincte pour chaque machine, chiffrée par la console et absente des fichiers
SSH personnels de l’opérateur.

La clé Ed25519 est conservée au format OpenSSH chiffré par mot de passe avec le
KDF bcrypt fourni par `cryptography`. Le kit JSON contient cette clé encore
chiffrée, la déclaration et les registres publics, jamais le mot de passe. Il
est écrit en `0600` dans un répertoire privé et réellement rouvert avant toute
mutation distante.

Après preuve d’une nouvelle connexion et de `sudo`, le profil fixe :

- `PasswordAuthentication no` ;
- `KbdInteractiveAuthentication no` ;
- `PermitRootLogin no`.

Il ne supprime aucun compte ou clé d’origine incertaine. Les accès résiduels
sont visibles et leur révocation forme un plan séparé. La configuration passe
`sshd -t`, puis SSH est rechargé sans couper la session de bootstrap.

Le compte V1 est `your-cloud-admin`. Le fichier possédé
`/etc/ssh/sshd_config.d/10-your-cloud.conf` précède le résidu cloud-init sans le
supprimer. Une nouvelle connexion root est refusée après preuve du compte
administratif. Les trois commandes de lecture du daemon sont les seules
commandes explicitement autorisées sous son compte d'observation.

Le premier contact peut employer un TOFU visible lorsque aucune empreinte
fiable n’est disponible. Toute connexion suivante exige l’empreinte épinglée ;
une rotation passe par un plan appuyé sur un ancien chemin valide ou un canal
hors bande.

## Pare-feu et système

Le ruleset nftables couvre IPv4 et IPv6. Il refuse par défaut les nouveaux flux
entrants et le forwarding, autorise les sorties en V1 et conserve ICMP/ICMPv6
nécessaire au réseau. SSH n’est ouvert que sur le chemin d’administration
déclaré ; aucun port applicatif n’est ouvert par le profil générique.

Les paramètres `sysctl` sont peu nombreux, justifiés individuellement et
prouvés avec IPv4 et IPv6. Ils ne modifient aucun réglage propre à WireGuard ;
la preuve d'un chemin WireGuard appartient à une topologie ultérieure. Le
profil ne reprend aucune checklist historique en bloc.

Le paquet `nftables` est épinglé à `1.1.3-1` pour la preuve Debian 13. Le
ruleset `inet` autorise les connexions établies, la boucle locale, ICMP et
ICMPv6, puis SSH depuis les réseaux d'administration IPv4 et IPv6 déclarés. Les
chaînes `input` et `forward` refusent par défaut ; `output` reste ouverte.

Les seuls réglages sysctl possédés désactivent l'acceptation des redirections
IPv4 et IPv6 pour les interfaces présentes et futures. La politique de
correctifs de sécurité reste proposée, sans activation ni redémarrage implicite.

## Retour et dérive

Avant une modification SSH ou pare-feu, l’ancien état est préparé, la session
courante est conservée et l’opérateur confirme un accès hors bande. Une seconde
connexion indépendante prouve le nouvel état. En cas d’échec, la session
conservée restaure uniquement les fichiers et règles possédés par le plan.

Une dérive est affichée, jamais corrigée silencieusement. Sa correction exige
un nouveau plan approuvé et reste interdite si l’autorité de configuration est
devenue ambiguë.

Le manifeste SHA-256 couvre SSH, nftables, sysctl et sudoers. Le rollback
initial conserve le ruleset et les valeurs sysctl précédents ainsi que les
fichiers réellement présents avant le profil. Il est préparé une seule fois et
reste exécutable en `0700` par la session conservée.

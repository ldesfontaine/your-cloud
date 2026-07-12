# Profil Linux V1

> État : cible P3, non encore implémentée ni prouvée.

## Préflight

Le profil exige Debian 13 amd64, systemd, une connexion SSH épinglée, une
élévation `sudo`, un espace disque et une horloge acceptables, ainsi que la
confirmation explicite que la machine est dédiée.

Il refuse avant toute mutation une autorité concurrente ou ambiguë sur SSH,
nftables ou les paramètres `sysctl`. Il ne fusionne, ne vide et ne remplace
jamais silencieusement une configuration qu’il ne possède pas.

## Administration SSH

Le parcours crée ou adopte un compte non-root propre à la machine. Sa clé est
distincte pour chaque machine, chiffrée par la console et absente des fichiers
SSH personnels de l’opérateur.

Après preuve d’une nouvelle connexion et de `sudo`, le profil fixe :

- `PasswordAuthentication no` ;
- `KbdInteractiveAuthentication no` ;
- `PermitRootLogin no`.

Il ne supprime aucun compte ou clé d’origine incertaine. Les accès résiduels
sont visibles et leur révocation forme un plan séparé. La configuration passe
`sshd -t`, puis SSH est rechargé sans couper la session de bootstrap.

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
prouvés avec IPv4, IPv6 et WireGuard. Le profil ne reprend aucune checklist
historique en bloc.

## Retour et dérive

Avant une modification SSH ou pare-feu, l’ancien état est préparé, la session
courante est conservée et l’opérateur confirme un accès hors bande. Une seconde
connexion indépendante prouve le nouvel état. En cas d’échec, la session
conservée restaure uniquement les fichiers et règles possédés par le plan.

Une dérive est affichée, jamais corrigée silencieusement. Sa correction exige
un nouveau plan approuvé et reste interdite si l’autorité de configuration est
devenue ambiguë.

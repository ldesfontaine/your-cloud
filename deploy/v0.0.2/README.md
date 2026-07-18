# Déploiement de `v0.0.2`

Ce lot installe uniquement le Daemon d'observation et, séparément sur
`lab-coordinateur`, le Relay candidat. Il utilise systemd et ses credentials ;
il ne contient ni App, ni Ansible métier, ni canal d'action, ni Auxiliaire,
WireGuard, service OCI, Proxmox, OpenStack, worker d'automatisation ou projet
IaC.

- `install-daemon` reçoit l'exécutable, l'identité machine et les trois fichiers
  mTLS provisionnés hors réseau ;
- `install-relay` reçoit l'exécutable, l'identité serveur, l'autorité publique
  Daemon et le registre d'enrôlement ;
- `remove` retire les processus et fichiers installés sans effacer les états
  persistants systemd sous `/var/lib/private/your-cloud-*`, qui restent une
  décision explicite.

Les deux unités fixent l'endpoint, le listener et les noms de credentials. La
ligne DNS synthétique ajoutée à `/etc/hosts` est marquée et retirée avec le lot.

Les deux installateurs sauvegardent d'abord les fichiers gérés et l'état des
unités, publient l'artefact commun depuis un fichier temporaire, puis exigent un
PID stable lié à cet artefact. Lorsqu'un autre rôle est déjà actif sur la même
machine, il est redémarré afin de ne pas conserver l'ancien inode. Si
l'activation ou cette vérification échoue, le lot précédent et ses états
systemd sont restaurés ; un rollback incomplet reste une erreur visible.

`remove` échoue fermé : il ne supprime aucun fichier tant que l'arrêt des
unités, l'absence de PID ou de processus hors unité et l'absence de listener sur
`:8443` ne sont pas toutes établies. Les états durables ne sont jamais inclus
dans les cibles de suppression. L'inspection des processus compare leur
exécutable réel sous `/proc/<pid>/exe` avec l'artefact installé ; changer le nom
affiché dans `argv[0]` ne masque donc pas un processus encore vivant.

Le même exécutable fournit enfin le diagnostic administratif local, sans unité
supplémentaire :

```text
/usr/local/lib/your-cloud/your-cloud diagnose observation [--format=json]
```

Cette commande est exécutée ponctuellement par `root`, car l'état du Daemon est
protégé sous `/var/lib/private/your-cloud-daemon`. Elle reste en lecture seule
et n'ouvre aucun accès réseau.

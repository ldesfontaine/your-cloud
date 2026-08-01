# Déploiement `v0.0.1`

Ces fichiers matérialisent le cycle de vie minimal du palier dans le LAB. Les
scripts Bash existent parce que `v0.0.1` doit prouver précisément les effets
systemd sans introduire encore une couche Ansible ou un installateur général.

| Fichier | Responsabilité |
|---|---|
| [`install-agent`](install-agent) | valider le binaire, l'hôte, l'identifiant et l'origine Relay, puis installer ou restaurer transactionnellement le Daemon |
| [`enable-relay`](enable-relay) | créer la configuration et le manifeste de candidature, puis activer le Relay sur `lab-coordinateur` uniquement |
| [`disable-relay`](disable-relay) | arrêter et retirer le seul rôle Relay sans toucher au Daemon ni à l'artefact commun |
| [`remove-agent`](remove-agent) | arrêter les rôles puis retirer unités, configurations et artefact, en refusant si un processus reste indéterminé ou hors unité |
| [`your-cloud-daemon.service`](your-cloud-daemon.service) | modèle systemd durci du Daemon |
| [`your-cloud-relay.service`](your-cloud-relay.service) | modèle systemd durci du Relay |

Ces scripts s'exécutent en root uniquement dans les VM du LAB et restent bornés
aux noms d'hôte, identifiants et adresses de `v0.0.1`. Ils ne constituent pas
une procédure de production générale.

Les scénarios qui tentent de les mettre en défaut vivent sous
[`remote/`](../remote/). Garder les deux
dossiers distincts évite de livrer un pilote hostile comme s'il faisait partie
du déploiement.

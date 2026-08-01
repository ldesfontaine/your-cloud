# Déploiement du Controller et du reader Relay `v0.0.3`

Ce dossier ne déploie que le Controller privé et strictement en lecture envers
les machines et le Relay. Il n'ajoute aucun frontend, serveur local de Console,
canal d'action, Ansible métier ou liaison réseau future.

L'unité [`your-cloud-relay.service`](your-cloud-relay.service) prolonge le
Relay d'observation avec son listener reader privé `8444`. Ses autorités
d'ingestion et de lecture restent séparées ; ses six credentials sont des
sources persistantes root-owned remises à un utilisateur dynamique par
systemd. Un arrêt puis redémarrage ne dépend donc d'aucune unité transitoire ni
d'une copie de credential limitée à `/run`.

L'unité [`your-cloud-controller.service`](your-cloud-controller.service) lance
le processus sous l'utilisateur dynamique non privilégié
`your-cloud-controller`. systemd possède seul son état persistant sous
`/var/lib/private/your-cloud-controller/`, fournit les trois credentials du
lecteur Relay et retire toutes les capacités Linux.

Le fichier root-owned `/etc/your-cloud/controller.env`, non secret et de mode
`0644`, fixe exactement :

```text
CONTROLLER_LISTEN=192.0.2.10:9443
CONTROLLER_ALLOWED_SOURCE=192.0.2.1/32
CONTROLLER_RELAY_ENDPOINT=192.0.2.20:8444
```

Ces valeurs d'exemple doivent être remplacées par l'adresse privée exacte du
Controller, l'unique source routée du segment d'administration et l'adresse
privée exacte du Relay de la même infrastructure. Le binaire refuse les
adresses non privées, imprécises ou les ports différents de `9443` et `8444`.
Le filtrage réseau reste une seconde barrière : l'autorisation d'une IP ne
remplace jamais le certificat d'appareil et la preuve humaine.

L'initialisation et l'ouverture d'une fenêtre temporaire restent des opérations
locales explicites. Elles ne sont pas réalisées automatiquement par cette unité
et n'ouvrent pas `9444` hors de la fenêtre bornée.

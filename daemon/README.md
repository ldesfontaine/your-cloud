# Daemon d’observation

Le daemon Go observe un état borné toutes les 60 secondes, conserve son état
courant et ses événements significatifs dans SQLite, puis signe les payloads
Protobuf avec l'identité Ed25519 propre à la machine.

Il tourne sous `your-cloud-observer`, compte `nologin` sans `sudo`, avec une
unité systemd durcie. Il n'ouvre aucun port et ne reçoit aucune commande. À P4,
il publie d'abord l'état courant puis les événements en attente vers au plus
deux coordinateurs explicitement autorisés, avec reprise exponentielle bornée.
Une donnée locale n'est purgée qu'après un accusé mTLS durable et cohérent.

À P5, un nouveau point est placé avant l'ancien pendant la migration d'un
pilote. Deux points au plus sont acceptés ; leur découverte reste interdite et
le retrait de l'ancien endpoint forme un plan SSH/Ansible séparé.

Voir l'[Anatomie du projet](../docs/ANATOMIE-DU-PROJET.md) pour suivre la
collecte, la signature, la file locale, la publication et la reprise.

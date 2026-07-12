# Daemon d’observation

Le daemon Go P2 observe un état borné toutes les 60 secondes, conserve son état
courant et ses événements significatifs dans SQLite, puis signe les payloads
Protobuf avec l'identité Ed25519 propre à la machine.

Il tourne sous `your-cloud-observer`, compte `nologin` sans `sudo`, avec une
unité systemd durcie et sans famille réseau IP à P2. Il n'ouvre aucun port et ne
reçoit aucune commande. La publication sortante vers un coordinateur appartient
à P4.

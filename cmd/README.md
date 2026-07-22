# Points d’entrée du produit

`your-cloud/` assemble l’unique exécutable Go installé sur les machines :

- `your-cloud daemon` collecte l’état local autorisé et le publie vers le Relay ;
- `your-cloud relay` reçoit les observations et sert le lecteur privé ;
- `your-cloud controller` porte l’inventaire, les sessions et l’API de lecture ;
- `your-cloud diagnose` rend un diagnostic local borné sans ouvrir de réseau.

Ces rôles partagent un fichier exécutable, pas un processus, un compte, des
secrets ou une configuration. `cmd/` valide les arguments, assemble les
packages métier et gère le cycle de vie du processus. La logique métier reste
dans [`internal/`](../internal/) et les commandes de preuve restent dans
[`tests/`](../tests/).

# Protocole de télémétrie V1

> État : messages et signatures confirmés par P2 ; transport et accusés à
> confirmer par P4.

## Transport

Le daemon initie des requêtes HTTPS avec mTLS vers un coordinateur autorisé.
Il n’ouvre aucun port entrant et le protocole ne dépend pas d’une connexion
permanente. Le coordinateur termine lui-même le mTLS ; aucun reverse proxy ou
runtime de conteneurs n’est requis par la V1.

Les délais, tailles, nombres d’éléments et connexions sont bornés. Une réponse
absente, tardive ou invalide ne purge aucune donnée locale.

## Messages et signatures

Les fichiers `.proto` versionnés constituent le contrat entre Go et Python.
Les messages Protobuf sont transportés dans des requêtes HTTPS ordinaires,
sans gRPC ni seconde représentation JSON sur le réseau.

Une enveloppe contient le payload exact produit par le daemon, l’identifiant
public permettant de choisir une clé candidate et la signature de ces octets
avec séparation de domaine. Le coordinateur conserve l’enveloppe originale ;
la console vérifie à nouveau la signature avec son registre de référence.

Les outils de génération sont épinglés et le code généré est versionné. La
génération et les tests ont lieu dans le LAB, jamais sur le laptop de
développement.

P2 fixe la signature à Ed25519. La clé publique brute de 32 octets est encodée
en base64 dans le registre de la console ; son identifiant est son SHA-256
hexadécimal. Les octets signés sont exactement la concaténation du domaine
ASCII `your-cloud.telemetry.v1`, d'un octet nul, de l'octet numérique du flux,
puis du payload Protobuf exact. Le flux fait donc partie de la signature et une
enveloppe d'état ne peut pas être réinterprétée comme événement.

Le contrat source est généré avec `protoc` 3.21.12 et `protoc-gen-go` v1.36.6.
Les runtimes restent épinglés par `go.mod`, `go.sum` et le `pyproject.toml` de
la console.

## Séquences et accusés

Les états et les événements possèdent des séquences persistantes distinctes.
Le coordinateur valide sa transaction SQLite avant d’émettre un accusé durable.
Une retransmission de la même identité, du même flux et de la même séquence est
idempotente et ne produit pas une seconde insertion logique.

Après un échec, le daemon applique une temporisation exponentielle bornée avec
une part aléatoire, puis peut essayer un autre coordinateur préautorisé. Aucun
daemon ne découvre ou n’autorise seul un nouveau point de coordination.

## API de console

Une identité mTLS de console peut uniquement lire des pages bornées de
télémétrie autorisée. Elle ne peut ni enrôler, ni révoquer, ni modifier le
registre, la déclaration ou une machine. Les mutations du coordinateur passent
en V1 par le chemin d’administration SSH et Ansible.

Avant P4, P2 fournit uniquement une inspection ponctuelle : la console récupère
l'enveloppe originale par le chemin SSH déjà vérifié, puis applique exactement
la même vérification de provenance et de séquence que celle qui sera utilisée
après relais par un coordinateur.

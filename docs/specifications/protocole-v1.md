# Protocole de télémétrie V1

> État : contrat cible, primitives précises à choisir pendant P2 et P4.

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

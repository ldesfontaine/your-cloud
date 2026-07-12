# Protocole

`v1/telemetrie.proto` est le contrat versionné de l'état, des événements et des
enveloppes signées. Les sorties Go et Python sont générées dans le LAB avec
`protoc` 3.21.12 et `protoc-gen-go` v1.36.6, puis versionnées.

Le protocole ne transporte aucune commande V1. P2 prouve la signature et
l'inspection ponctuelle ; le transport HTTPS/mTLS et les accusés durables du
coordinateur appartiennent à P4.

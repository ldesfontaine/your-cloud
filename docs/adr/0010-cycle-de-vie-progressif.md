# Piloter mises à jour et bascules progressivement

Statut : accepté · ratification P0 du 2026-07-12

## Contexte

Un auto-update ou une reconfiguration simultanée de la flotte transformerait
une erreur de distribution ou de réseau en incident généralisé. Daemons et
coordinateurs ne doivent pas acquérir une autorité supplémentaire pour se
mettre eux-mêmes à jour.

## Décision

- La console applique par le chemin d’administration une version précise dont
  origine et intégrité ont été vérifiées. Aucun composant distribué ne
  s’auto-met à jour.
- Une version précédente et son retour sont préparés avant remplacement.
- Les coordinateurs compatibles sont mis à jour avant les daemons.
- Une mise à jour ou une nouvelle coordination commence par une machine pilote
  dans chaque site ou chemin réseau distinct.
- L’ancien point reste autorisé comme secours jusqu’à plusieurs échanges et
  accusés valides. Le premier échec arrête le plan et laisse les machines
  suivantes intactes.
- Le retrait de l’ancien point forme un plan séparé.
- La version du protocole est distincte de celle des binaires et une matrice de
  compatibilité est vérifiée avant toute mutation.

## Conséquences

Les migrations prennent plus de temps et maintiennent temporairement plusieurs
versions ou points autorisés. En échange, une erreur affecte d’abord un pilote
et ne se propage pas automatiquement. Cette redondance temporaire n’est pas
présentée comme de la haute disponibilité.

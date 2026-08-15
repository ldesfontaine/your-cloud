# Chiffrer ce que délibérer coûte — protocole d'essai humain (`#133`)

`#133` demande **deux** durées et interdit de les fixer sur un avis. Elles ne
sont pas de même nature, et c'est la première chose que ce protocole établit :

| Borne | Ce qu'elle mesure | Comment on la chiffre |
| --- | --- | --- |
| **délibération** | le temps donné à un humain pour lire un plan et répondre dans la fenêtre native | cet essai, lecture chronométrée |
| **autorité confirmée** | l'intervalle entre « la fenêtre a rendu une confirmation » et « la signature part » | **le même essai** : cet intervalle contient lui aussi un geste humain |

**Les deux intervalles sont humains, et le second l'est parce que le contrat le
veut.** Le sondage du frontend s'arrête à l'état `answered` et ne soumet rien :
`submit_plan_decision` n'a qu'un appelant, le bouton **« Signer et lancer »** de
`console/src/product/plans-view.tsx`. C'est une décision de contrat, écrite à
côté de l'appel — une soumission qui suivrait la fermeture de la fenêtre ferait
de la fenêtre le déclencheur d'un effet, quand le contrat en fait un recueil de
consentement, et `TRAJET-DE-COMMANDE.md` le dit aussi : « aucun déclencheur
automatique n'est posé ; le contrat n'en a aucun ».

La conséquence est une contrainte sur le chiffre, pas une nuance de vocabulaire :
**une borne calée à l'échelle d'un enchaînement de messages rendrait tout humain
réel expiré à son propre clic.** Après la fenêtre, l'humain revient à la Console,
lit le paragraphe qui lui dit que rien n'est encore parti, et décide. Cette borne
doit être humaine et généreuse.

Une durée de vie d'autorité se change avec une justification, jamais pour
débloquer un harnais : tant que ces chiffres n'existent pas, les deux constantes
de `plan_consent.rs` restent celles du plafond du protocole, et l'issue reste
ouverte.

## Ce que l'essai fait

```bash
tests/lab/v0.1.2/consent-window-timing/mesurer private_service
```

Trois lectures chronométrées, environ cinq minutes en tout. Chaque lecture mesure
**deux intervalles**, l'un après l'autre :

1. **délibérer.** La feuille affiche les deux empreintes *telles que la Console
   les montre à côté de la fenêtre*, puis le plan *tel que la fenêtre le rend*.
   Le chronomètre part à votre Entrée et s'arrête quand vous avez répondu si les
   deux empreintes correspondent — c'est ce que la fenêtre native recueille ;
2. **signer.** La feuille affiche alors le panneau que la Console rend une fois
   la fenêtre refermée sur une confirmation, avec son bouton. Le second
   chronomètre s'arrête à votre « clic ».

Le second intervalle n'est mesuré que sur les lectures où vous avez répondu que
les empreintes correspondaient : une lecture qui a repéré une altération
n'atteindrait jamais le bouton, et la chronométrer mesurerait un geste qu'un
humain réel n'aurait pas fait.

**Une lecture sur les trois porte une empreinte altérée d'un caractère**, tirée
au sort et jamais annoncée. Sans elle, l'essai mesurerait un temps passé devant
un texte ; avec elle, il dit aussi si ce temps achète quelque chose. Une lecture
qui ne repère pas l'altération est un fait à porter au dossier avant d'en tirer
une durée.

Les deux familles ne demandent pas le même effort, et ce sont les deux bornes du
problème :

| Famille | Phrases | Caractères | Ce qu'elle représente |
| --- | --- | --- | --- |
| `user_service` | 12 | 962 | le cas courant, celui que la preuve `#128` a réellement affiché |
| `private_service` | 16 | 993 | **la fenêtre la plus large que le produit écrit** — quatre lignes d'environnement et une ligne de confinement de sortie en plus |

C'est `private_service` qui doit fixer la borne : une borne calée sur la fenêtre
courante coupe la fenêtre la plus large.

## Ce que la copie est, et ce qu'elle n'est pas

`copie.tsv` porte les lignes que
`PresentedPublicationPlan::confirmation_lines()` produit sur les vecteurs
épinglés de `console/src-tauri/src/publication_plan.rs`, extraites du produit
lui-même. Ce ne sont pas des phrases réécrites pour l'occasion.

Le panneau du second intervalle est lui aussi la copie du produit : ce sont les
phrases et le libellé de bouton que `plans-view.tsx` rend quand une session est
confirmée.

Trois limites, portées ici plutôt qu'en note de bas de page :

- **le terminal n'est pas la fenêtre GTK.** L'essai mesure le temps de lire ce
  texte et de comparer ces empreintes, pas l'ergonomie de la fenêtre. Le sens de
  lecture, la police et l'espacement changeraient le chiffre à la marge ;
- **le second intervalle est mesuré sans le changement de fenêtre.** Un humain
  réel doit revenir de la fenêtre native à la Console — le geste que cette
  feuille ne reproduit pas est justement celui qui allonge cet intervalle. Ce
  qu'elle en donne est donc un **plancher**, et la borne se pose au-dessus, avec
  de la marge ;
- **les valeurs sont celles des vecteurs épinglés** — `lab-machine-1`,
  `lab.your-cloud.test`. C'est la copie du produit avec des valeurs de test, et
  c'est ce qui rend l'essai reproductible d'une fois sur l'autre.

Une copie qui change rend cette feuille périmée : elle se régénère depuis le
produit.

## Ce que les chiffres décident

Les deux bornes se posent **au-dessus du maximum observé**, jamais de la
médiane : une borne calée sur le lecteur moyen coupe le lecteur attentif, c'est-
à-dire exactement celui pour qui la fenêtre existe. Et la borne de l'autorité
confirmée se pose au-dessus du maximum **augmenté de la marge du changement de
fenêtre** que cette feuille ne mesure pas : le coût d'une borne trop généreuse
est qu'une autorité déjà lue reste vivante un peu plus longtemps sur la machine
de son propre humain ; le coût d'une borne trop courte est qu'un humain qui a
lu, compris et accepté voit son geste refusé — et recommence, ce qui use
précisément l'attention que la fenêtre existe pour obtenir.

Reportez, pour chaque lecture, les **deux** durées, leurs médianes, leurs maxima
et le sort de la lecture altérée dans `#133`. C'est sur eux que les deux
constantes se fixent, et c'est à ce moment-là seulement que l'issue se ferme.

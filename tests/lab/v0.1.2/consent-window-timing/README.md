# Chiffrer ce que délibérer coûte — protocole d'essai humain (`#133`)

`#133` demande **deux** durées et interdit de les fixer sur un avis. Elles ne
sont pas de même nature, et c'est la première chose que ce protocole établit :

| Borne | Ce qu'elle mesure | Comment on la chiffre |
| --- | --- | --- |
| **délibération** | le temps donné à un humain pour lire un plan et répondre | cet essai, chronométré |
| **autorité confirmée** | l'intervalle entre « un humain a confirmé » et « la signature part » | **pas un chronomètre humain** : ce trajet ne contient aucun geste humain — le sondage voit `answered` et soumet. Il se mesure au harnais |

Une durée de vie d'autorité se change avec une justification, jamais pour
débloquer un harnais : tant que ces chiffres n'existent pas, les deux constantes
de `plan_consent.rs` restent celles du plafond du protocole, et l'issue reste
ouverte.

## Ce que l'essai fait

```bash
tests/lab/v0.1.2/consent-window-timing/mesurer private_service
```

Trois lectures chronométrées, environ cinq minutes en tout. À chaque lecture, la
feuille affiche d'abord les deux empreintes **telles que la Console les montre à
côté de la fenêtre**, puis le plan **tel que la fenêtre le rend**. Le chronomètre
part à votre Entrée et s'arrête quand vous avez répondu si les deux empreintes
correspondent.

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

Deux limites, portées ici plutôt qu'en note de bas de page :

- **le terminal n'est pas la fenêtre GTK.** L'essai mesure le temps de lire ce
  texte et de comparer ces empreintes, pas l'ergonomie de la fenêtre. Le sens de
  lecture, la police et l'espacement changeraient le chiffre à la marge ;
- **les valeurs sont celles des vecteurs épinglés** — `lab-machine-1`,
  `lab.your-cloud.test`. C'est la copie du produit avec des valeurs de test, et
  c'est ce qui rend l'essai reproductible d'une fois sur l'autre.

Une copie qui change rend cette feuille périmée : elle se régénère depuis le
produit.

## Ce que les chiffres décident

La borne de délibération se pose **au-dessus du maximum observé**, jamais de la
médiane : une borne calée sur le lecteur moyen coupe le lecteur attentif, c'est-
à-dire exactement celui pour qui la fenêtre existe.

Reportez les trois durées, la médiane, le maximum et le sort de la lecture
altérée dans `#133`. C'est sur eux que les deux constantes se fixent, et c'est à
ce moment-là seulement que l'issue se ferme.

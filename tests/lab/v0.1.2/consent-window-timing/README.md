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

## L'essai du 15 août 2026, et ce qu'il a décidé

Exécuté par le mainteneur sur `private_service`, trois lectures.

| Lecture | Délibérer | Signer | Plan | Verdict sur les empreintes |
| ---: | ---: | ---: | --- | --- |
| 1 | **20,8 s** | **8,7 s** | intact | juste |
| 2 | 2,6 s | 0,9 s | **altéré** | **manquée** |
| 3 | 2,9 s | 0,8 s | intact | juste |
| médianes | 2,9 s | 0,9 s | | |
| maxima | 20,8 s | 8,7 s | | |

**Une seule lecture sur trois constitue une vérification.** En 2,7 s on ne
compare pas 993 caractères et deux empreintes de 64 caractères hexadécimaux : on
suppose. La lecture 3 porte un verdict juste **par chance** — le plan était
intact —, pas par vérification ; un verdict juste sur un plan intact, rendu sans
comparer, est indiscernable d'une vérification. Deux lectures sur trois n'ont pas
vérifié, et c'est l'une d'elles qui portait l'altération.

### La justification, en huit points

1. **La mesure porte sur la fenêtre la plus large que le produit écrit** :
   `private_service`, 16 phrases, 993 caractères, deux empreintes de
   64 caractères hexadécimaux. Une borne calée sur une fenêtre plus courte
   couperait celle-ci.
2. **Une seule lecture est une vérification réelle** : la lecture 1, 20,8 s de
   délibération et 8,7 s jusqu'au clic. Les deux autres sont des suppositions.
3. **La médiane est écartée**, et pas par prudence rhétorique : 2,9 s est la
   médiane de deux non-vérifications et d'une vérification. Une borne calée là
   **bornerait l'inattention**, c'est-à-dire garantirait au lecteur attentif
   qu'il n'a pas le temps de vérifier.
4. **Les bornes se posent donc sur la lecture 1** — 20,8 s et 8,7 s — et
   au-dessus.
5. **Décision : les deux constantes restent au plafond du protocole,
   300 000 ms.** La mesure ne sert pas à resserrer ; elle sert à établir que ce
   plafond est **généreux plutôt que supposé** : ≈ 14× la délibération réelle
   mesurée, ≈ 34× le plancher de signature.
6. **La marge du changement de fenêtre n'est pas mesurée.** Cette feuille ne fait
   pas revenir de la fenêtre native à la Console, donc 8,7 s est un plancher et
   non l'intervalle complet. C'est l'ampleur du rapport — 34× — qui autorise à
   trancher sans avoir mesuré ce retour ; à un rapport de 2× ou 3×, il aurait
   fallu le mesurer.
7. **Ce que la valeur coûte est nommé** : une autorité confirmée et non employée
   vit au plus cinq minutes sur la machine de son propre humain, puis refuse de
   signer et le dit. Avant ce palier, elle ne s'éteignait jamais — c'est le
   défaut que `#133` a corrigé, et le chiffre ne fait que le borner.
8. **Limite de l'échantillon : n = 1 lecture valide.** C'est **suffisant à cette
   échelle de marge** — un facteur 14 et un facteur 34 ne se retournent pas sur
   une seconde observation — et **insuffisant pour resserrer** : resserrer
   exigerait un échantillon de lectures ayant réellement vérifié, que cet essai
   n'a pas produit.

### Ce que l'essai a trouvé en plus, et qui n'est pas une durée

La lecture 2 portait une empreinte altérée d'un caractère, et **l'altération n'a
pas été vue**. Ce constat ne concerne pas les bornes : il concerne la valeur du
contrôle que la fenêtre existe pour rendre possible. Il est porté par une issue
de palier distincte plutôt que par ce dossier.

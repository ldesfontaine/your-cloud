# Piloter le travail avec GitHub Issues

## Rôle des issues

La roadmap de `v0.1.0` reste la source canonique de l'ordre des preuves et des limites du
produit. Une issue GitHub est un **contrat d'exécution** : elle transforme une
partie suffisamment décidée de cette roadmap en travail borné, attribuable et
vérifiable. Fermer une issue ne modifie pas à lui seul l'état documenté,
implémenté ou prouvé du projet.

Les issues servent à savoir quoi attaquer maintenant, à rattacher les branches,
pull requests et preuves, et à conserver les blocages visibles. Elles ne servent
ni à décider silencieusement le produit, ni à dupliquer toute la roadmap.

## Niveau de découpage

Le suivi jusqu'à `v0.1.0` utilise cette hiérarchie :

1. la [roadmap de v0.1.0](../objectifs/v1/ROADMAP.md) fixe l'ordre canonique ;
2. l'[issue de suivi de v0.1.0](https://github.com/ldesfontaine/your-cloud/issues/20)
   relie les paliers qui contribuent réellement à cette ligne d'arrivée ;
3. chaque palier ou étape décidé possède une issue de suivi ;
4. une issue parente représente ce palier lorsqu'il exige plusieurs
   résultats indépendants ;
5. une sous-issue représente un résultat qui peut être réalisé et vérifié sans
   fermer artificiellement tout le palier ;
6. une pull request livre par défaut une seule issue et la relie explicitement.

Un tableau GitHub Project peut être ajouté si le volume rend la liste d'issues
difficile à lire. Il reste une vue : ni ses colonnes, ni un milestone, ni une
issue parente ne deviennent une nouvelle source produit.

Inscrire un palier décidé dans la roadmap implique donc de créer ou relier son
issue dans le même travail. Un palier futur peut rester une issue de suivi
macroscopique. Avant de commencer son implémentation, il est découpé en
sous-issues actionnables dont chacune connaît les quatre éléments suivants :

- un résultat observable ;
- un périmètre et un hors-périmètre ;
- des critères d'acceptation ;
- une preuve proportionnée et son environnement d'exécution.

Une incertitude qui doit être levée avant ce découpage reçoit une issue de
décision séparée. Elle annonce la question à trancher et ne mélange pas étude et
implémentation.

## Milestone active de `v0.1.0`

La milestone [v0.1.0](https://github.com/ldesfontaine/your-cloud/milestone/1)
est la vue de suivi de toute la release. Elle regroupe les décisions de
distribution bloquantes #11 et #12, les paliers #13 à #19, le suivi transversal
[#20](https://github.com/ldesfontaine/your-cloud/issues/20), les sous-issues
#34 à #45, les sous-issues #51 à #54 de l'accès personnel et les futures
sous-issues exécutables de ces paliers. Le
routage CI #10 reste hors de la milestone parce que #20 le classe comme travail
transverse non bloquant.

Terminer cette milestone signifie que chacun de ces contrats est réellement
satisfait et fermé avec ses preuves et sa propagation documentaire. Sa simple
fermeture administrative ne constitue pas une preuve supplémentaire.

Dans #35, la décision documentaire #44 ferme d'abord le canal natif des
secrets. Elle bloque le bornage IPC #43 et le consentement natif #45 ; leur
intégration permet ensuite l'accès SSH personnel borné #42. La fermeture de #35
exige ces quatre résultats et leurs preuves, dans l'ordre
`#44 → (#43 + #45) → #42 → #35` ; une seule sous-issue verte ne suffit pas.
Le gate ELF Linux du 2 août 2026 a activé le repli prévu par #44 : #45 doit
livrer un binaire helper distinct dont le graphe exclut la Console, Tauri, Wry,
Tao, WebKit et JavaScriptCore. Cette décision ne change pas l'ordre des issues
et ne vaut pas à elle seule preuve du helper. Sa fondation fail-closed et ses
gates Linux sont exécutés ; le lancement parent et le premier consentement
GTK3 sans secret sont également prouvés dans le LAB. La saisie GTK3 et Win32,
l'effacement des secrets, l'annulation coopérative, `mlock`,
`MADV_DONTDUMP`, `VirtualLock` et l'enregistrement Windows Error Reporting en
défense en profondeur possèdent maintenant une implémentation et une preuve
fonctionnelle. Les
runs `30768351689` et `30768749538` sont rouges sous l'ancien oracle, mais
caractérisent `LocalDumps` administrateur hors garantie avec contrôle et canari
présents ; le
[rapport #45](../lab/v0.1.0-native-secret-consent-linux-windows.md) conserve les
tentatives sans fermer l'issue. `ae550470` corrige l'observation de l'oracle,
mais reste intermédiaire : même observation, dump supprimé, répertoire prouvé
vide et deux inscriptions de registre prouvées absentes avant verdict, puis
retrait du répertoire seulement par `Drop`. Son run `30769440106` a réussi ses
quatre jobs et prouve cette étape intermédiaire, mais ne ferme pas #45.
`c8643b0` emploie ensuite `remove_and_prove_absent` pour exiger l'absence du
répertoire avant verdict. Le run `30770893733` réussit les quatre jobs sur
`b76ded8`, valide cette séquence et publie trois artefacts inspectés. L'issue
#45 doit conserver l'ultime matrice verte du SHA de propagation documentaire ; aucune
modification ne suit ce run avant fusion. Sa fermeture débloque #51, puis
#52, #53 et #54 dans cet ordre.
Pour #43, la récolte Linux autonome, le Job Object Windows avec racine et vrai
descendant, les branches hostiles avant reprise et le dispatch Tauri vivant ont
réussi sur le candidat exact `f3fef79` dans le run manuel `30753216798` : cette
intégration ferme #43. La garde des futurs
descendants SSH ou privilégiés appartient encore à #42.

#42 est maintenant une parente exécutable, découpée sans élargir sa portée :

1. [#51](https://github.com/ldesfontaine/your-cloud/issues/51) ferme les bornes
   KDF et la politique de journalisation `sudo` avant toute saisie distante ;
2. [#52](https://github.com/ldesfontaine/your-cloud/issues/52) authentifie une
   cible exacte par l'agent SSH personnel ;
3. [#53](https://github.com/ldesfontaine/your-cloud/issues/53) ouvre la clé
   OpenSSH chiffrée de repli dans la même session native ;
4. [#54](https://github.com/ldesfontaine/your-cloud/issues/54) vérifie
   l'élévation et termine `access_verified`.

`access_verified` signifie seulement que l'adresse résolue puis figée, la clé
d'hôte exacte, l'identité choisie et la commande fixe `/usr/bin/id -u` ont
vérifié l'accès direct `root` ou le chemin `sudo` autorisé. Il ne signifie ni
audit Debian, ni installation, ni mutation, ni Controller autonome, ni succès
d'amorçage. #42 ne se ferme qu'après #51, #52, #53 et #54 ; #35 se ferme après
#42 et l'intégration avec #43/#45. La séquence de fermeture du sous-palier est
`#45 → #51 → #52 → #53 → #54 → #42 → #35`. Une fois #45 fermée, la prochaine
issue est #51 ; #13 et la milestone demeurent ouverts jusqu'à leurs propres
preuves, tandis que `v0.1.0` reste à atteindre.

Aucune date d'échéance arbitraire ne lui est attachée. La preuve globale #41,
la propagation documentaire et la fermeture de #13 terminent seulement le
palier d'amorçage et permettent d'ouvrir #14. La milestone reste ouverte jusqu'à
la preuve finale #19, la fermeture des décisions #11 et #12, la propagation de
l'état final et la fermeture du suivi #20. Une fois toutes ses issues réellement
fermées, son achèvement devient équivalent à la ligne d'arrivée de `v0.1.0`,
sans remplacer les preuves qui la justifient.

## Convention de titre

Le titre reprend la grammaire des commits sans prétendre étendre la
spécification Conventional Commits aux issues :

```text
type(scope): résultat observable
```

Types usuels :

- `feat` pour une capacité produit ;
- `fix` pour un comportement incorrect ;
- `docs` pour une source documentaire ;
- `test` pour une preuve ou un refus hostile ;
- `ci` pour l'automatisation et les runners ;
- `refactor` pour une transformation sans changement de contrat ;
- `chore` pour un travail d'entretien borné.

Le `scope` nomme le domaine stable le plus étroit, par exemple `console`,
`controller`, `agent`, `relay`, `lab` ou `ci`. Le reste du titre décrit le
résultat, pas l'action vague « travailler sur ».

Exemples :

```text
ci(console): router les contrôles selon les chemins modifiés
test(windows): prouver le lancement du MSI sans listener local
docs(v0.1.0): propager le contrat d'amorçage dans la roadmap
```

## Contenu obligatoire

Le modèle [`.github/ISSUE_TEMPLATE/01-travail.md`](../../.github/ISSUE_TEMPLATE/01-travail.md)
demande :

- les sources canoniques et le contexte factuel ;
- le résultat observable ;
- le périmètre et le hors-périmètre ;
- les critères d'acceptation ;
- les preuves attendues, avec leur environnement ;
- les dépendances, blocages et décisions encore ouvertes.

Les critères décrivent ce qui doit être vrai. La section de preuve indique
comment l'observer. Une liste d'étapes d'implémentation ne remplace aucun des
deux.

## Ouverture, branche et pull request

L'auteur visible d'une issue est le compte GitHub authentifié qui l'ouvre. Toute
ouverture automatisée doit être explicitement autorisée et interrompue si
l'identité authentifiée n'est pas celle du mainteneur attendu. Le contenu public
ne reçoit ni signature d'outil, ni mention décorative sans rapport avec le
travail.

Une ouverture groupée définit au préalable les titres, relations parent-enfant,
dépendances et milestone. Elle ne publie ni données personnelles, ni secrets,
ni chemins locaux, ni notes de réflexion : seulement les faits et contrats
nécessaires à un développeur pour réaliser le travail.

Par défaut :

- la branche se nomme `type/numero-resume-court` ;
- les commits gardent la forme `type(scope): action` ;
- la pull request référence l'issue et utilise `Closes #numero` seulement si
  elle satisfait réellement tous ses critères ;
- un nouveau besoin hors périmètre devient une autre issue au lieu d'élargir la
  pull request en silence.

## Fermeture

Une issue est fermée lorsque ses critères sont satisfaits, les vérifications
annoncées sont exécutées, les limites restantes sont nommées et les documents
canoniques concernés sont propagés. Une preuve manuelle indique ses
préconditions, son action, son résultat attendu et son résultat observé.

Un blocage externe ne transforme pas un travail non prouvé en travail terminé.
L'issue reste ouverte ou porte explicitement son blocage et la prochaine action
sûre. Une issue parente n'est fermée que lorsque toutes les sous-issues exigées
par son résultat le sont et que la preuve globale du palier existe.

## Références

- [GitHub — planifier et suivre le travail](https://docs.github.com/en/issues/tracking-your-work-with-issues/learning-about-issues/planning-and-tracking-work-for-your-team-or-project) ;
- [GitHub — issues, sous-issues, dépendances et métadonnées](https://docs.github.com/en/issues/tracking-your-work-with-issues/learning-about-issues/about-issues) ;
- [GitHub — modèles et formulaires d'issue](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/about-issue-and-pull-request-templates).

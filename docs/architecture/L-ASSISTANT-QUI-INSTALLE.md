# L'Assistant qui installe : du lot vérifié au Controller qui tourne

> **Statut :** contrat d'architecture de la milestone `v0.1.3`, rédigé le
> 15 août 2026 sur le patron de l'issue `#122`. Les issues d'implémentation et
> l'issue de preuve sont numérotées à l'ouverture de la milestone et référencées
> ici dans le même changement. Ce document est une source canonique inscrite à
> [`docs/projet/COHERENCE.md`](../projet/COHERENCE.md) ; il ne redécide rien de
> [`AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md`](AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md),
> qui reste l'autorité du contrat d'amorçage — il fixe **l'exécution** de ce que
> ce contrat décide.

## Ce que ce palier ajoute, et ce qu'il n'ajoute pas

Toutes les portes existent, et aucune main ne les franchit. Le module
`installation` de l'Assistant juge un lot (`bundle::verify` contre l'ancre
scellée), résout son emplacement depuis la position attestée
(`installation::embedded`), refuse un placement exposé, exige l'élévation
prouvée et le prévol, ordonne les étapes (`plan::authorize`) et sait ce qu'un
échec doit rendre (`rollback::Ledger`). Mais rien dans le produit n'exécute :
aucun `dpkg`, aucun `systemctl` dans le code livré, et l'écran « Créer une
infrastructure » n'existe pas.

Ce palier ajoute exactement la moitié qui agit : l'Assistant exécute
l'installation que les portes jugent, vérifie **l'état constaté** après chaque
acte, tient le registre de ce qu'il a réellement fait, et l'IHM conduit ce
parcours jusqu'au Controller qui tourne. Il n'ajoute **aucune autorité
nouvelle** : le seul privilège est l'élévation que `#52`–`#54` ont prouvée, la
seule racine de confiance est l'ancre scellée, la seule source du lot est le
paquet que l'humain a lui-même installé.

Il n'ajoute pas non plus : de mise à jour automatique, de reprise autonome
après coupure, de rejeu d'un plan interrompu, de gestion des cibles autres que
la machine du Controller, ni de transfert d'autorité — ces sujets restent aux
contrats qui les portent.

## L'état de départ : la carte, constatée le 15 août 2026

| Constat | Où |
|---|---|
| `BootstrapAction` n'a qu'une variante, `AuditTargetReadOnly` | `console/src-tauri/crates/bootstrap-protocol/src/lib.rs:152-154` |
| la moitié qui juge existe entière : `anchor`, `embedded`, `bundle`, `preflight`, `association`, `plan`, `rollback` | `crates/native-bootstrap-assistant/src/installation.rs` |
| `plan::authorize` exige les quatre témoins par type et n'est appelé par aucun code de production | `installation/plan.rs:179-184`, appelants : fixtures LAB seules |
| aucun `dpkg`, aucun `systemctl` exécuté par le produit | grep du crate : commentaires et fixtures seulement |
| la fixture d'installation le dit elle-même : « it performs no installation and it holds no privilege » | `src/controller_install_fixture.rs:1-14` |
| le lot serveur est embarqué, signé, et l'Assistant le retrouve depuis sa position attestée | `installation/embedded.rs`, mode `--verify-embedded-server-bundle` |
| l'IHM ne propose qu'« Associer » ; `start_bootstrap` est déclaré et jamais appelé | `console/src/product/access-views.tsx:207-214`, `native.ts:136-141` |
| `bootstrap_status` efface le succès sans le nommer au frontend | `console/src-tauri/src/lib.rs:369-375` |

C'est la dette que la règle de preuve de
[`QUALITE.md`](../contribution/QUALITE.md) nomme : chaque preuve
d'installation passée a traversé ce trajet par une fixture, et la moitié
commande du produit restait non construite derrière des preuves vertes.

## Les variantes que `BootstrapAction` gagne

Le vocabulaire du protocole dit ce que l'humain approuve, jamais comment
l'Assistant s'y prend. Deux variantes s'ajoutent à `AuditTargetReadOnly` :

| Variante | Ce que l'humain approuve | Étapes du plan couvertes |
|---|---|---|
| `InstallServerBundle` | poser le lot vérifié sur la machine choisie : le paquet par `dpkg`, la configuration de cette machine, l'état privé, les sources de credentials. **Rien n'écoute encore** : les trois unités restent livrées inactives | `InstallPackage` → `InstallCredentialSources` |
| `ActivateApprovedController` | activer la seule unité approuvée, associer cette Console, jouer le prévol depuis le Controller | `ActivateController` → `Preflight` |

### Décision tranchée : deux variantes, pas une et pas sept

Une seule variante « installer et activer » ferait approuver en un geste deux
choses de natures différentes — poser des fichiers inertes et mettre un
service en écoute. Sept variantes calquées sur les sept étapes de
`plan::STEPS` feraient de l'ordre d'exécution un choix de l'appelant, ce que
`plan.rs` refuse par construction (« an installation whose order could be
chosen is an installation whose ordering guarantees are the caller's
problem »). Deux variantes séparent ce qui doit l'être — l'inerte et l'actif —
et chacune couvre une tranche contiguë du plan constant. La fenêtre native
montre l'une puis l'autre par des phrases, comme le parcours utilisateur de
`#122` l'exige.

## L'exécution privilégiée réelle

L'Assistant exécute, et il exécute comme il s'élève déjà : par des commandes
**fixes**, bornées, jamais composées depuis un document. La discipline de
`personal_access::elevation` (`FixedCommand`, constructeur `pub(crate)`,
vocabulaire clos) s'étend aux actes d'installation : `dpkg --install` sur le
chemin du lot que `embedded` a résolu et que `bundle::verify` a jugé,
`systemctl daemon-reload`, `systemctl enable --now` sur la seule unité que le
plan nomme. Aucun shell, aucun chemin venu du protocole, aucune option venue
d'un champ.

**Rien de privilégié ne court sans le plan.** La fonction qui exécute prend
`InstallPlan` — le témoin que seul `plan::authorize` rend, contre les quatre
témoins que l'architecture exige. La question « un `dpkg` peut-il partir sans
que le lot ait été jugé, le placement approuvé, root réellement atteint et
chaque endpoint entendu » se répond en lisant une signature, pas en auditant
des sites d'appel.

### La vérification vient après la pose, et c'est l'état constaté

Chaque étape se conclut par une observation, jamais par un code de sortie :

- après `InstallPackage` : `dpkg-query` dit `installed` à la version exacte du
  manifeste ; les chemins possédés sont ceux de la distribution bornée,
  `root:root`, sans setuid, setgid ni capacité de fichier ;
- après `WriteMachineConfiguration`, `CreateState`,
  `InstallCredentialSources` : les fichiers existent avec les modes exacts que
  `plan.rs` fixe en constantes, et `dpkg` n'en inventorie aucun ;
- après `ActivateController` : l'unité est `active`, sous compte dynamique,
  avec les budgets déclarés, à l'écoute de l'adresse privée déclarée — les
  valeurs que la preuve `#38` relevait au harnais, relevées désormais par le
  produit ;
- après `AssociateConsole` et `Preflight` : l'association existe et chaque
  endpoint déclaré a répondu sa clé confirmée **depuis le Controller**.

Ce qui est constaté entre au registre ; ce qui n'a pas été constaté y entre
comme `Unknown`. Un succès est une suite d'observations, pas une absence
d'erreur.

## Le rollback : approuvé avec le plan, exact, jamais flatteur

Le registre de démontage existant **s'étend, il ne se réinvente pas**.
`rollback::Ledger` et ses règles restent le contrat : seul ce que cette
exécution a créé est retiré, en ordre inverse de création ; un état `Unknown`
n'est jamais retiré et dégrade le déroulé en `Incomplete` ; `Incomplete` n'est
jamais rapporté comme succès ; après transfert d'autorité le module refuse de
répondre. Ce palier ne transfère aucune autorité : la borne `AfterTransfer`
existe pour être des paliers suivants, pas pour être franchie ici.

Ce qui s'ajoute : le rollback est **approuvé avec le plan**. La fenêtre native
qui montre ce qui va être fait montre du même geste ce qu'un échec rendra —
retour à la version antérieure exacte si le paquet existait, à l'absence s'il
n'existait pas, et la liste close de ce qui serait retiré. Un humain qui
approuve une installation approuve aussi la forme de son échec ; un rollback
surprise est une autorité que personne n'a donnée.

### Décision tranchée : l'état partiel se montre, il ne se répare pas seul

Une coupure au milieu d'une étape laisse un registre et une machine. Le palier
en rend compte — chaque entrée, sa provenance, ce que le déroulé a pu prouver
absent — et s'arrête. Reconstruire depuis un état partiel est un geste
explicite de l'humain (rejouer une création sur une machine assainie), jamais
une initiative de l'Assistant : une reprise autonome rejouerait des actes
privilégiés sur un état que personne n'a relu.

## Aucune autorité nouvelle : l'élévation de `#52`–`#54`, réutilisée

Le privilège de ce palier est celui qui existe : la session d'accès personnel
prêtée, l'élévation consentie dans la fenêtre native, le témoin `Elevation`
que seul `elevation::elevated` construit. L'exécution privilégiée dépense
cette session-là — même canal, mêmes commandes fixes, même expiration, même
refus d'un consentement re-signé. Il n'y a ni règle sudo nouvelle, ni démon
root, ni binaire setuid, ni élévation persistante : quand la session se ferme,
l'Assistant ne peut plus rien, et c'est la propriété recherchée.

## L'IHM qui conduit : « Créer une infrastructure » aboutit

Le parcours existe de bout en bout ou il n'existe pas. Ce palier livre
l'écran que l'état des lieux montre absent : depuis la vue Infrastructures,
« Créer une infrastructure » déclare la cible, prête l'accès personnel,
audite en lecture seule, montre le placement et son approbation, puis conduit
les deux approbations d'installation — poser, activer — et se termine sur un
Controller joignable et associé. `start_bootstrap`, `bootstrap_status` et
`cancel_bootstrap` cessent d'être des déclarations sans appelant ; la clôture
d'affaires que `bootstrap_status` diffère aujourd'hui (« naming that outcome
to the frontend belongs to the business closure of the palier ») est ce
palier : le verdict de chaque session se nomme au frontend par une phrase,
jamais par du JSON, et chaque refus est une phrase actionnable — la contrainte
de `#122`, reprise ici comme critère.

## Ce que ce palier ne fait pas

- il n'installe rien sur les cibles autres que la machine du Controller — les
  identités par machine, la commande forcée et l'Auxiliaire appartiennent au
  trajet de commande déjà contracté ;
- il ne met pas à jour un Controller existant : la distinction absence /
  version antérieure exacte / état ambigu est jugée, et un état ambigu refuse
  l'installation au lieu d'une migration improvisée ;
- il ne transfère pas l'autorité et ne remplace pas un Controller ;
- il ne reprend pas seul un état partiel et ne rejoue rien aveuglément ;
- il n'élargit pas le vocabulaire du Relay, du Daemon ni des services.

## Ce que la preuve devra constater

La preuve de ce palier est sous la règle de
[`QUALITE.md`](../contribution/QUALITE.md) : **aucune fixture ne remplace un
composant du produit sur ce trajet**, et le rapport LAB liste ce que les
preuves passées y remplaçaient — `controller_install_fixture.rs` en tête — et
cette liste ferme vide. La fixture sort du trajet prouvé ; si elle survit,
c'est hors trajet et nommée.

1. la vraie Console installée, pilotée à l'écran, déroule « Créer une
   infrastructure » jusqu'au Controller actif sur `lab-machine-1` — chaque
   maillon exercé par les binaires livrés ;
2. le lot installé est le lot embarqué : la version, la taille et l'empreinte
   constatées après pose sont celles du manifeste signé, jugées par l'ancre
   scellée avant le premier acte privilégié ;
3. un lot altéré est refusé **avant** tout `dpkg`, par le nom de son refus ;
4. l'élévation dépensée est celle de la session consentie : aucun processus
   privilégié ne survit à la fermeture de la session, et aucune règle sudo,
   aucun setuid, aucune capacité de fichier n'apparaît sur la machine ;
5. après pose : l'inventaire `dpkg`, les modes, l'absence de setuid et le
   compte dynamique sont **constatés par le produit** et le rapport les
   confronte à un relevé indépendant du harnais ;
6. l'arrêt forcé à chaque étape nommée du plan laisse un registre que le
   déroulé du produit rend exactement — `Complete` sur les étapes propres,
   `Incomplete` dès qu'un `Unknown` existe — et la machine revient à son état
   initial prouvé, version antérieure ou absence ;
7. un état partiel n'est jamais annoncé comme succès à l'écran : la phrase
   montrée nomme ce qui reste et ce qui a été rendu ;
8. l'approbation d'activation ne porte que l'unité du plan : les deux autres
   unités restent inactives et le rapport le constate ;
9. le prévol final est collecté depuis le Controller, pas depuis le poste de
   pilotage ;
10. le rapport nomme le mécanisme de pilotage employé et ce qu'il n'atteste
    pas, et chaque limite restante de ce palier par son nom.

## Justification de sécurité

- **Scénario et actifs.** Un humain installe, depuis sa Console, un Controller
  sur une machine privée qu'il possède. Actifs : l'accès root temporaire prêté,
  le lot serveur, l'état et les credentials naissants du Controller, la machine
  elle-même.
- **Menaces traitées.** Substitution du lot au moment où l'Assistant tient le
  plus d'autorité (jugement scellé avant tout privilège) ; exécution
  privilégiée sans porte (un seul constructeur de plan, quatre témoins par
  type) ; commande composée depuis un document (commandes fixes) ; rollback
  destructeur sur une machine qui n'a fait qu'échouer (registre, `Unknown`
  jamais retiré) ; succès partiel annoncé comme succès (`Incomplete` incompressible).
- **Alternatives considérées.** Un démon root résident (écartée : autorité
  persistante là où le contrat veut une élévation qui meurt avec la session) ;
  un script d'installation shell livré dans le paquet (écartée : l'ordre et
  les portes sortiraient du type système pour entrer dans du texte) ; une
  variante d'action unique « installer et activer » (écartée : deux natures
  d'actes sous une seule approbation) ; sept variantes calquées sur les étapes
  (écartée : l'ordre deviendrait un choix de l'appelant).
- **Portée accordée et moindre privilège.** La session élevée existante,
  dépensée sur des commandes fixes vers des chemins constants ; aucune
  autorité nouvelle, aucune persistance, budgets et compte dynamique du
  Controller inchangés.
- **OWASP.** Valeur sûre par défaut (tout refus arrête avant le privilège),
  réduction de surface (vocabulaire clos, commandes fixes), séparation des
  responsabilités (juger / planifier / exécuter / défaire, chacun son module),
  défense en profondeur (signature puis empreinte puis inventaire constaté).
- **NIS2, lecture proportionnée.** Chaîne d'approvisionnement (lot signé
  reproductible, ancre scellée), gestion d'incident (registre et déroulé
  exacts), continuité (retour prouvé à l'état antérieur), développement sûr
  (témoins par type, preuve sans fixture).
- **Risque résiduel.** Une compromission complète de la machine cible ou du
  poste de la Console reste hors de portée de ce contrat ; l'humain qui
  approuve reste l'autorité que rien ne double-vérifie ; la reprise après
  coupure demande un geste humain informé, et un attaquant tenant la session
  élevée pendant sa durée de vie peut ce que la session peut.

# Contrat de CI générique

Cette CI sépare la validation rapide de chaque pull request de la matrice native
Linux/Windows réservée à un candidat final explicitement déclenché. Elle ne
déploie rien, ne pilote pas le LAB et ne publie aucun artefact produit. Son
rôle est borné à ce que ni le poste de développement ni le LAB ne produisent :
Windows et l'attestation d'un candidat de palier.

Une **CI générique** exécute des contrôles reproductibles dans une machine
jetable fournie par GitHub. Un **runner LAB dédié** serait au contraire une
machine administrée pour piloter KVM/libvirt et la topologie `v1-full`. Une
image CI préconstruite fournit des outils, pas cette topologie ni son autorité.

## Placement des preuves

Une preuve vit là où seul cet environnement peut la produire ; tout le reste
descend à l'endroit le moins cher et le plus reproductible. La décision
[`#67`](https://github.com/ldesfontaine/your-cloud/issues/67), prise le 3 août
2026 après l'épuisement du quota Actions, fixe ce placement en trois étages.

| Étage | Preuves | Coût |
|---|---|---|
| poste de développement | contrôles statiques : `tools/check-docs`, contrat des sources App, `cargo fmt --check`, garde de politique du workflow | secondes, aucune minute facturée |
| LAB | tout le fonctionnel Linux : compilation, tests du helper, paquet `.deb`, garde ELF, installation, smoke, scénarios multi-VM | aucune minute facturée ; le LAB est ici plus capable que la CI |
| CI hébergée | ce que ni le poste ni le LAB ne produisent : Windows, et l'attestation du candidat de palier — matrice complète, signature, artefacts | environ 98 minutes facturées par matrice |

Le LAB Windows local ouvert par la même décision sert la validation continue du
helper Windows ; il ne déplace pas l'attestation. La CI hébergée reste
l'autorité qui atteste un candidat de palier et la porte native
`workflow_dispatch` reste exigée pour fermer un palier. Les
[règles LAB](../lab/README.md) décrivent sa forme manuelle et ses limites.

Descendre une preuve d'un étage ne consiste jamais à la retirer. Aucune garde,
aucun refus hostile et aucun contrôle statique n'est affaibli pour réduire un
coût ; le garde versionné `tests/checks/ci-workflow-policy.py` en particulier
reste intégral.

### Deux rythmes de validation

- **À chaque changement.** Les contrôles statiques s'exécutent sur le poste et
  la preuve fonctionnelle dans le LAB : Linux, et Windows local pour le helper.
  Ce rythme est quotidien et ne consomme aucune minute hébergée.
- **À chaque candidat de palier.** Une seule matrice native `workflow_dispatch`
  est déclenchée sur le candidat de fusion, précédée de
  `tools/ci-usage --guard 100`. Jamais de matrice par pull request, jamais par
  fusion intermédiaire.

### Ce qu'une fusion intermédiaire doit prouver

Une fusion intermédiaire prouve deux choses : les contrôles statiques verts sur
le poste, et une preuve LAB enregistrée avec le SHA qu'elle couvre réellement.
Elle a le droit de ne pas repayer une matrice native : la preuve native
appartient au candidat de palier, et le SHA attesté est noté explicitement,
comme pratiqué depuis
[`#45`](https://github.com/ldesfontaine/your-cloud/issues/45). Une preuve ne
s'hérite pas d'un SHA à l'autre ; ne pas rejouer la matrice n'autorise donc pas
à attribuer une preuve native à un SHA qu'elle n'a pas couvert.

## Le dépôt est public : la rareté des minutes est levée

Le dépôt est passé public le 12 août 2026. Les runners standard de GitHub
Actions n'y sont plus décomptés, et la contrainte qui gouvernait le rythme
depuis le 3 août — un quota épuisé, une matrice à environ 98 minutes, une seule
fenêtre par palier — cesse d'exister.

Cette décision est du même genre que [`#67`](https://github.com/ldesfontaine/your-cloud/issues/67) :
elle change le **coût** d'une preuve, jamais sa **valeur**.

### Ce qui change

| Avant | Après |
|---|---|
| `tools/ci-usage --guard 100` **bloque** avant toute matrice | il **informe** : la mesure reste enregistrée, elle n'interdit plus |
| une seule matrice par candidat de palier, cumulant la dette de plusieurs issues | autant d'itérations que le vert en demande |
| un rouge de matrice coûtait la fenêtre du palier | un rouge se diagnostique, se corrige et se relance sans cérémonie |
| « le budget du projet reste nul » s'appliquait aussi à la CI | la règle du budget nul ne concerne plus la CI hébergée |

Un rouge reste un rouge : il se **mesure** avant d'être corrigé. La gratuité
retire la pression de la fenêtre, pas l'exigence d'établir une cause.

### Ce qui ne change pas

Rien de ce qui fait la valeur d'une preuve ne dépendait du quota, et rien n'est
desserré ici :

- **le placement des preuves** reste à trois étages — contrôles statiques au
  poste, fonctionnel au LAB, attestation à la CI hébergée. Une matrice gratuite
  n'autorise pas à y remonter ce que le LAB prouve mieux ;
- **mesurer avant d'affirmer** : une cause s'établit, elle ne se suppose pas ;
- **aucune fixture ne remplace un composant du produit** sur un trajet prouvé ;
- **les trois états** — documenté, implémenté, prouvé — restent distingués ;
- **un tag ne se pose que sur un SHA attesté** par une matrice entièrement
  verte ; une preuve ne s'hérite toujours pas d'un SHA à l'autre ;
- **aucune donnée personnelle** n'entre au dépôt, dont les règles d'exclusion
  restent la garde.

## État actuel

| Élément | État | Autorité |
|---|---|---|
| porte rapide de pull request | workflow configuré pour exécuter automatiquement les contrôles génériques et Plumber, sans matrice native ; contrôles du candidat et contrôle avant intégration verts dans `30709932309` et `30710949974`. Le contrat des sources App y est exécuté depuis #60, afin qu'une violation échoue en secondes plutôt qu'après la matrice native | états des jobs `Contrôles génériques` et `Politique Plumber` |
| matrice App Linux/Windows | déclenchement manuel configuré sur `ubuntu-24.04` et `windows-2025` pour un candidat exact ; porte finale entièrement verte dans `30710037004` sur `3b8f81f` | codes de sortie des tests, builds, installations et lancements natifs |
| bornage IPC #43 | porte rapide `30753208857` puis matrice manuelle `30753216798` entièrement vertes sur le candidat produit exact `f3fef79` ; Linux et Windows exécutent le helper compagnon, Windows ajoute son Job Object, son paquet, son gate PE et le dispatch Tauri vivant | états des jobs, journaux et artefact expurgé liés depuis le rapport #43 |
| consentement et mémoire secrète #45 | preuve fonctionnelle acquise dans `30770893733` sur `b76ded8` ; `30775430141` valide le garde raster Linux, puis `30777209723` valide la correction `EBWebView` et tout le job Windows mais échoue sous Linux sur le réglage de timeout WebDriver, avant l'appel async mutant ; le candidat ne rejoue que ce réglage idempotent et doit être rejoué sur son SHA exact | états des quatre jobs, ordre bloquant du test WER, validation machine des rasters, attribution du listener et inspection des artefacts expurgés |
| analyse Plumber | binaire épinglé exécuté dans le LAB ; action GitHub et garde indépendant exécutés avec succès sur la révision de référence | sortie de Plumber puis garde indépendant |
| frontière du garde Plumber | 23 cas unitaires — 20 refus et 3 acceptations contrôlées — plus un refus Plumber intégré exécutés dans le LAB | rapports structurés et codes de sortie |
| exécution GitHub Actions réelle | [run final `30710037004`](https://github.com/ldesfontaine/your-cloud/actions/runs/30710037004) entièrement vert sur le candidat produit exact `3b8f81f`, avec les deux gardes et les variantes natives ; l'issue `#9` conserve le SHA, les liens et les empreintes | états des jobs, journaux et artefact de smoke du run |
| preuve fonctionnelle multi-VM | exécutée dans le LAB Linux et volontairement hors de cette CI | rapport LAB, résultats structurés et assertions machine |

### Fermeture prouvée de `v0.0.3`

La condition est satisfaite pour le candidat produit
`3b8f81f8a1ab4e000da7271bbd22544999c9d0f1`. L'[issue `#9`](https://github.com/ldesfontaine/your-cloud/issues/9)
lie le run `workflow_dispatch` `30710037004`, entièrement vert, à ce SHA et à
son intégration par fast-forward. Les deux gardes rapides et les variantes
natives Linux et Windows ont réussi : `v0.0.3` est fermée pour ce candidat.
Tout nouveau candidat modifiant le contenu couvert par cette porte exige son
propre run ; aucun changement ultérieur n'hérite de cette preuve.

### Preuve exacte du bornage IPC #43

La porte rapide
[`30753208857`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753208857)
puis le run manuel
[`30753216798`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798)
ont entièrement réussi sur le candidat produit exact
`f3fef79b74a5e3115fb5fe93f21c6380ad116582`. Le run manuel relie les jobs
[`Contrôles génériques` `91510826593`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510826593),
[`Politique Plumber` `91510826335`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510826335),
[`Windows` `91510938793`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510938793)
et
[`Linux` `91510938804`](https://github.com/ldesfontaine/your-cloud/actions/runs/30753216798/job/91510938804),
tous verts.

La variante Linux a réussi les tests, les scénarios GTK isolés, le build,
l'installation du `.deb` et l'absence de listener. La variante Windows a
réussi les branches hostiles du Job Object avant reprise et après vraie
terminaison, la récolte d'une racine et d'un descendant, le `.msi`, son image
administrative contenant exactement les deux exécutables installables, le gate
PE et l'IPC Tauri vivant. Les trois commandes `start_bootstrap`,
`bootstrap_status` et `cancel_bootstrap` exercent `create` et `replace` ; les
identifiants forgés, la concurrence, les champs inconnus ou sensibles et les
rejeux sont refusés avec des erreurs publiques réduites à leur code. Aucun
succès métier n'est inventé et aucun listener TCP produit ne subsiste.

L'artefact `app-windows-webview2-smoke` d'identifiant `8835381252` contient
uniquement un JSON et neuf PNG. Son digest vaut
`sha256:2e9db85120dbc86a5b7dd278630a4bbe064637173b35c15d92c8d68298345cdb`
et le JSON vaut
`ee2f2345ceae81efabf8d748f043ed4992a419750804a34439bd4931e3447088`.
Le certificat synthétique prouve la mécanique Authenticode, pas une identité
publique. Le gate PE analyse les tables d'imports normales et différées ; il ne
prouve pas l'absence universelle de chargement dynamique. Le
[rapport dédié](../lab/v1-bootstrap-ipc-windows.md) conserve les empreintes, le
nettoyage et les limites. Cette porte et sa propagation ferment #43, sans fermer
#45, #42, #35, le palier #13 ou `v0.1.0`.

### Consentement natif #45 — preuve fonctionnelle acquise

Le helper possède maintenant une implémentation des fenêtres GTK3 et
Win32, du périmètre immuable lié au véritable parent et au pair IPC, de
l'échéance monotone non renouvelable de 300 secondes et du tampon
`ProtectedSecret` borné à 4096 octets. Linux emploie
`mmap`/`mlock`/`MADV_DONTDUMP` ; Windows
`VirtualAlloc`/`VirtualLock` et `WerRegisterExcludedMemoryBlock` en défense en
profondeur. `LocalDumps` configuré par un administrateur reste hors garantie. Après
acceptation, le secret est détruit et l'événement public reste `Unavailable` :
aucune capacité SSH, `sudo`, `root` ou métier n'est simulée.

Les runs manuels
[`30764166496`](https://github.com/ldesfontaine/your-cloud/actions/runs/30764166496),
[`30764301331`](https://github.com/ldesfontaine/your-cloud/actions/runs/30764301331),
[`30765033336`](https://github.com/ldesfontaine/your-cloud/actions/runs/30765033336),
[`30766208361`](https://github.com/ldesfontaine/your-cloud/actions/runs/30766208361),
[`30767224411`](https://github.com/ldesfontaine/your-cloud/actions/runs/30767224411)
et
[`30767609914`](https://github.com/ldesfontaine/your-cloud/actions/runs/30767609914),
puis
[`30768351689`](https://github.com/ldesfontaine/your-cloud/actions/runs/30768351689)
sont diagnostiques, jamais des preuves de fermeture. Les deux premières
tentatives ont révélé le garde Plumber puis des erreurs de compilation ; les
trois suivantes n'ont pas obtenu de dump WER inspectable ; la dernière s'est
arrêtée au formatage avant le test. `30768351689` produit ensuite un `MDMP`
contenant contrôle et canari. Il reste rouge sous l'ancien oracle, mais cette
observation caractérise la frontière `LocalDumps` administrateur. Le
[rapport dédié](../lab/v0.1.0-native-secret-consent-linux-windows.md) conserve
les SHA, les causes, les sous-cas Linux exécutés et les limites exactes.

Le candidat `5cceb783` remplace la configuration précédente par `DumpType=0` et
`CustomDumpFlags=0x321`, soit un dump WER personnalisé incluant les régions
`PAGE_READWRITE` sans `MiniDumpWithFullMemory`. Son run
[`30768749538`](https://github.com/ldesfontaine/your-cloud/actions/runs/30768749538)
produit un `MDMP` personnalisé stable avec le contrôle du tas et le canari
protégé. Il reste rouge parce que l'ancien oracle exige l'inverse et le panic
précède le nettoyage explicite ; seuls le `Drop` best effort et le runner
éphémère bornent alors les restes. Cette présence n'est pas une garantie produit
violée : `LocalDumps` administrateur est hors contrat et l'enregistrement WER
reste une défense en profondeur.

Le candidat intermédiaire `ae550470` corrige l'observation de l'oracle. Son run
[`30769440106`](https://github.com/ldesfontaine/your-cloud/actions/runs/30769440106)
a entièrement réussi ses quatre jobs entre `2026-08-02T22:08:15Z` et
`2026-08-02T22:36:00Z` : Plumber `91553861038`, contrôles génériques
`91553861065`, Windows `91553980937` en 26 min 27 s et Linux `91553980938` en
15 min 24 s. Il observe le `MDMP`, le contrôle et le canari présents, puis
prouve le dump supprimé, son répertoire vide et les inscriptions `LocalDumps`
et `AeDebug` absentes. Le `Drop` ne retire toutefois le répertoire qu'après le
verdict : ce succès constitue une preuve intermédiaire, pas la porte finale.
`c8643b0` ajoute ensuite `remove_and_prove_absent`, qui retire le répertoire et
le prouve absent avant verdict.

Le workflow place la preuve de crash tôt dans chaque variante afin qu'un défaut
de collecte ou d'exclusion n'attende pas le build des paquets. Sous Linux, le
contrôle ordinaire doit rester visible dans un `gcore` par défaut tandis que le
canari protégé en est absent, puis un `abort` durci ne produit aucun core. Sous
Windows, la fixture lancée avec `CREATE_DEFAULT_ERROR_MODE` refuse
`SEM_NOGPFAULTERRORBOX`, configure WER par exécutable, exige un dump `MDMP`
personnalisé incluant `PAGE_READWRITE`, avec contrôle ordinaire et canari
protégé présents. Elle caractérise ainsi l'autorité administrateur hors
garantie, puis doit retirer et prouver absents avant verdict le dump, son
répertoire et les deux inscriptions de registre propres au test. `ae550470` ne
satisfait pas cette séquence pour le répertoire ; `c8643b0` introduit la preuve
manquante. Le run `30770893733` réussit ce test sur `b76ded8`. Aucun résultat
n'est accepté si l'observation ou l'un des quatre nettoyages manque.

La matrice manuelle
[`30770893733`](https://github.com/ldesfontaine/your-cloud/actions/runs/30770893733)
réussit les deux gardes, Linux, Windows, paquets, dialogues, nettoyages et
artefacts sur `b76ded8`, qui inclut `c8643b0` et le contrat documentaire. Trois
corrections du harnais de captures la suivent ; seul le run `30779157351` sur
`c0569d0` ferme finalement `#45`.

Le premier rejeu exact
[`30772674819`](https://github.com/ldesfontaine/your-cloud/actions/runs/30772674819)
sur `028a459` échoue et ne remplit pas cette porte. Les gardes réussissent, de
même que le test WER Windows. Linux publie l'artefact `8841198084` avec un job
vert, mais deux de ses dix PNG sont invalides : la vue locale `1280x800` ne
contient qu'une couleur et la vue `640x560` contient 42,857 % de noir. Le JSON
reste identique à celui de `30770893733`, donc le DOM seul ne détecte pas la
divergence entre le DOM et le compositing WebKitGTK/Xvfb. Windows s'arrête
ensuite avant le smoke : l'ancien harnais avait libéré le port de débogage avant
le lancement et attribuait son listener depuis un inventaire de processus pris
plus tôt. Le run ne distingue pas lequel de ces deux défauts a provoqué le
refus. Aucun artefact Windows n'est publié. Ce run est conservé comme
diagnostic, jamais comme preuve partielle de fermeture.

Le correctif candidat valide chaque raster WebDriver avant écriture : PNG RGB
ou RGBA opaque, dimensions et CRC exacts, au moins 256 couleurs, dominante au
plus à 99,5 % et noir exact au plus à 10 %. Il attend les dimensions, les
fontes et deux frames, avec cinq tentatives et un délai total borné. Le cas
hostile standard-library reproduit les défauts sans dépendance d'image. Sous
Windows, le runtime suit le
[mécanisme documenté par Microsoft](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/devtools-mcp-server) :
`--remote-debugging-port=0`, puis lecture de `DevToolsActivePort` dans le dossier
de données WebView2. Le fichier direct non-reparse, son port, son chemin
WebSocket, le listener loopback, l'exécutable du runtime et le SID éphémère sont
tous vérifiés. Cette mécanique supprime le free-then-use du port sans accepter
un listener étranger.

La matrice
[`30775430141`](https://github.com/ldesfontaine/your-cloud/actions/runs/30775430141)
sur `233c92c` valide les gardes et Linux, mais reste diagnostique. Son artefact
Linux `8842095823` contient neuf rasters WebDriver acceptés dès la première
tentative, de 808 à 925 couleurs, avec une dominante maximale de 88,4156 % et
aucun noir exact ; les dix PNG et le JSON expurgé ont été inspectés. Cette
inspection ne transforme pas le zoom 200 % en preuve responsive exhaustive :
la navigation compacte reste horizontalement défilable et son dernier libellé
dépasse le bord de deux captures. Windows construit, signe et installe le MSI,
mais ne trouve pas `DevToolsActivePort`. Le harnais fournissait déjà le suffixe
`EBWebView` à `WEBVIEW2_USER_DATA_FOLDER`, alors que WebView2 ajoute ce suffixe
au dossier hôte. Le correctif suivant fournit le parent éphémère et dérive
séparément l'UDF `EBWebView` où le fichier est lu. Il restait alors à le prouver
par une nouvelle matrice exacte.

La matrice
[`30777209723`](https://github.com/ldesfontaine/your-cloud/actions/runs/30777209723)
sur `d7232fe` prouve cette correction sous Windows : WER, scénarios hostiles,
construction, signature, installation, découverte du fichier exact,
attribution du listener et smoke réussissent. L'artefact Windows `8842782989`,
de digest
`sha256:281eedc9e12bdf6038810955966585c9c0d324906beea9bacddc12c12a03fff9`,
et les dix PNG sont inspectés. Le run reste invalide pour fermer #45 : Linux
perd la connexion WebDriver pendant le `POST /timeouts` de préparation, avant
le `POST /execute/async` qui pourrait muter l'état, puis refuse de déclarer son
nettoyage complet. Aucun artefact Linux n'est publié. Le candidat autorise deux
essais seulement pour ce réglage idempotent ; la requête async suivante reste
unique et toute déconnexion après son envoi demeure terminale. Deux cas
synthétiques verrouillent cette frontière.

La matrice
[`30779157351`](https://github.com/ldesfontaine/your-cloud/actions/runs/30779157351)
sur `c0569d0` ferme enfin la porte : ses quatre jobs sont verts, les deux
smokes publient chacun un JSON et dix PNG, et le rapport Plumber vaut `A`,
`100/100` sans finding. Les trois artefacts et leurs 23 fichiers sont inspectés
sans secret, dump, paquet ni binaire. C'est le run que l'issue `#45` enregistre
avant sa fermeture et la fusion par fast-forward de la PR #50. Cette porte ne
couvre toujours pas la preuve responsive exhaustive à 200 %, suivie par #56 :
elle ne capture que trois vues, et sa moitié Linux est prouvée ailleurs, dans le
LAB, par [`v0.1.0` — reflow sans coupe au zoom texte 200 %](../lab/v0.1.0-console-reflow-200.md).

Plumber complète les contrôles du projet ; il ne remplace ni les tests Go, ni
les scénarios hostiles, ni la preuve LAB. Son score n'est pas une attestation
de conformité.

## Budget des runners hébergés

Le quota mensuel inclus a été épuisé le 3 août 2026, sans avertissement : la
dépense n'était visible qu'après coup. Les mesures ci-dessous existent pour que
cela ne se reproduise pas.

**Le coût est dominé par Windows.** Sur le mois, 1469 des 2129 minutes
facturées viennent du runner Windows, facturé au double. Depuis l'ajout de
`russh`, une matrice native complète coûte environ 98 minutes facturées : 21
sous Linux et 38 sous Windows doublées. À 2000 minutes incluses, cela plafonne
à une vingtaine de matrices par cycle.

**Une matrice par palier, pas par pull request.** La décision de réserver les
builds natifs au candidat final vaut aussi entre les sous-issues d'un même
palier. Une fusion intermédiaire s'appuie sur sa preuve LAB et enregistre
explicitement quel SHA porte la dernière preuve native. Ce que la preuve ne
s'hérite pas d'un SHA à l'autre n'implique pas que chaque fusion exige sa
propre matrice : cela impose seulement de ne jamais attribuer une preuve à un
SHA qu'elle n'a pas couvert. C'est le second des deux rythmes fixés plus haut
par [`#67`](https://github.com/ldesfontaine/your-cloud/issues/67).

**Mesurer avant de dépenser.** [`tools/ci-usage`](../../tools/ci-usage) calcule
les minutes réellement facturées du cycle et refuse en dessous d'une marge
donnée :

```text
tools/ci-usage --guard 100
```

Cette commande précède tout `workflow_dispatch` de la matrice native. Elle
n'exécute rien et ne consomme aucune minute.

**Ce qu'une preuve LAB ne remplace pas.** Le LAB couvre Linux : compilation,
tests, paquet `.deb`, garde ELF, installation, smoke et scénarios multi-VM. Le
LAB Windows minimal y ajoute une évaluation manuelle et un smoke scripté du
helper. Aucun des deux ne produit le `.msi`, sa signature Authenticode, le gate
PE ni l'attestation d'un candidat de palier : ces preuves restent hébergées.
Une fusion sur preuve LAB seule reste donc intermédiaire et le déclare.

## Menaces prises en compte

Le contenu d'une pull request est considéré comme non fiable. Il peut modifier
du Go, des scripts, un workflow ou même un test qui prétend le contrôler. Les
actifs à protéger sont le dépôt, les secrets, les autres branches, le LAB, les
artefacts publiés et les runners suivants.

La première couche applique donc les choix suivants :

- seulement des runners GitHub hébergés et jetables pour une pull request ;
- aucun secret du projet, aucune clé LAB et aucun accès libvirt ;
- jeton `GITHUB_TOKEN` limité à `contents: read` ;
- déclencheur automatique `pull_request` et déclencheur manuel
  `workflow_dispatch`, jamais `push` général ni `pull_request_target` ;
- actions tierces épinglées à un SHA de commit, dépôt extrait sans conserver
  les identifiants Git ;
- aucun cache restauré depuis une branche non fiable ;
- délais maximaux et annulation du run de pull request devenu obsolète ; un run
  manuel final n'est pas annulé par un nouveau déclenchement ;
- aucun binaire produit archivé par la CI générique ; le build de contrôle vit
  dans un répertoire temporaire supprimé en sortie ;
- la porte rapide conserve seulement le rapport Plumber validé ; le run manuel
  Windows conserve en plus son rapport et ses captures expurgées, pendant sept
  jours, sans paquet ni matériel de signature.

Ces mesures limitent l'impact d'un contenu hostile, mais ne peuvent pas rendre
un workflow auto-modifiable digne de confiance par lui-même. `CODEOWNERS` nomme
donc `@ldesfontaine` pour l'ensemble du dépôt afin que toute pull request
externe lui demande une relecture sans laisser de nouveau chemin hors du
routage. Comme le dépôt n'a pas de second mainteneur de confiance, ce routage
reste informatif : une règle GitHub ne doit pas exiger l'approbation du
propriétaire du code, car Lucas ne peut pas approuver sa propre pull request.
Les checks CI peuvent en revanche rester obligatoires avant fusion.

## Jobs et résultat attendu

### Découpage, déclenchement et relance

Le même workflow expose deux modes explicites. Une pull request exécute
automatiquement les contrôles génériques et la politique Plumber. Un
`workflow_dispatch` sur la référence candidate lance d'abord ces deux gardes en
parallèle ; la matrice App Linux/Windows ne démarre qu'après leur réussite.
Une erreur rapide bloque ainsi les runners natifs avant qu'ils consomment du
temps. Les deux plateformes sont ensuite des variantes parallèles du même
contrat natif ; elles ne forment pas deux chaînes de déploiement.

La concurrence groupe les pull requests par numéro afin qu'un nouveau commit
annule leur run devenu obsolète. Chaque déclenchement manuel est au contraire
isolé par `github.run_id` et n'est pas annulé. Le garde versionné
`tests/checks/ci-workflow-policy.py` vérifie les deux déclencheurs, les
permissions en lecture, cette concurrence, les trois jobs attendus et la
matrice native manuelle dans le même workflow.

Le découpage suit ces règles :

- un job porte un résultat bloquant identifiable et peut être diagnostiqué
  sans parcourir les logs d'un autre domaine ;
- `needs` exprime uniquement une dépendance de données ou une porte réelle ;
  des jobs sans dépendance s'exécutent en parallèle ;
- une matrice couvre plusieurs plateformes soumises au même contrat et reste
  réservée au candidat final ;
- un nouveau fichier de workflow est justifié par un déclencheur, un niveau de
  permission, un environnement ou un cycle d'artefact différent ;
- un workflow réutilisable sert à supprimer une duplication réelle entre
  plusieurs appelants, pas à cacher quelques étapes locales ;
- la relance normale cible les jobs en échec ou le job précis à diagnostiquer,
  sans relancer volontairement les jobs déjà réussis.

La porte rapide ne porte aucun filtre `paths` au niveau du workflow : chaque
pull request rend donc toujours les deux checks attendus et aucun check requis
ne reste en attente faute de déclenchement. Un futur routage interne plus fin
devra conserver ce résultat stable, traiter tout chemin inconnu comme
transverse et couvrir sa table chemins-vers-jobs par des cas nominaux et
hostiles avant activation.

Le job `Contrôles génériques` fait d'abord analyser le script Windows par le
parseur PowerShell de l'image Linux, sans exécuter la preuve native, puis isole
et exerce le contrat de son agrégateur de nettoyage avec une liste vide et une
erreur synthétique. Il exécute ensuite le contrat des sources App avec le
Node.js déjà présent sur le runner : le script n'importe que des modules Node
natifs et un module local, donc ni installation, ni dépendance frontend ne sont
nécessaires. Ce placement est délibéré. Ce contrat était auparavant exercé
seulement dans la matrice native, si bien qu'une violation rendue en quelques
secondes n'était découverte qu'après avoir consommé les deux jobs natifs, dont
Windows facturé au double. Il installe ensuite Go `1.26.5` et appelle
`tests/checks/source-v0.0.1 ci` sous une identité non root. Cette entrée vérifie
formatage, syntaxe, schémas structurés, documentation, tests Go, `go vet` et
build statique, ainsi que le garde de politique du workflow. Le binaire
temporaire est vérifié puis supprimé ; il n'est ni déployé ni publié.

Le job matriciel `App`, exécuté seulement sur déclenchement manuel, fixe
Node.js `24.18.0` LTS et Rust `1.94.1`, désactive le cache automatique et lance
au plus deux variantes en parallèle avec `fail-fast: false`. Les deux variantes
exécutent le même verrou npm, l'audit des dépendances frontend, le contrat
visuel, le build embarqué et le formatage Rust. Elles exécutent ensuite tôt la
fixture de crash secrète propre à leur plateforme, avant les tests release du
workspace, afin qu'un dump absent ou mal expurgé arrête le candidat sans
attendre les paquets. La variante Linux éprouve aussi le parent, le pair IPC,
l'échéance, l'annulation et les scénarios GTK3 isolés, puis construit le `.deb`,
l'installe, le lance sous affichage virtuel et refuse tout listener TCP du
processus. La variante Windows exécute en plus les dialogues Win32, les tests
d'ACL et du Job Object, y compris les branches hostiles de création,
d'affectation et de récolte. Elle construit le `.msi` sous MSVC/WiX, vérifie que
son image administrative possède exactement l'ensemble des deux exécutables
installables, signe l'exécutable App, le helper et l'installateur, puis les
vérifie, installe et lance. Son gate PE inspecte les imports normaux et différés
du helper installé exact. Enfin, le pilote WebView2 appelle réellement les trois
commandes Tauri d'amorçage et refuse tout listener du processus ou de ses
descendants au lancement normal.

Cette matrice prouve les différences natives des deux plateformes. Elle ne
démarre aucun Controller, Relay ou Daemon, ne crée aucune fausse topologie et
ne simule pas la preuve fonctionnelle multi-VM. Les API, le réseau, mTLS, les
pannes, reprises et scénarios hostiles restent prouvés dans le LAB Linux.

Le certificat Authenticode de CI est synthétique, auto-signé, valable deux
jours, créé dans le magasin de l'utilisateur jetable puis supprimé avec sa clé
privée. Son horodatage RFC 3161 prouve le mécanisme de signature, pas l'identité
publique de Your Cloud. Aucun `.deb`, `.msi`, exécutable ou certificat n'est
archivé. Les archives Linux et Windows bornées contiennent seulement un rapport
JSON et dix captures PNG : neuf vues de l'interface et un consentement natif,
soit exactement onze fichiers par plateforme. Le rapport Windows sérialise
`github.sha`, `github.run_id`, `source_locks`, `verified_artifacts` et
`cleanup`. Le JSON Linux ne sérialise aucun de ces champs : la métadonnée de
l'artefact GitHub le relie au run, et le nettoyage est bloquant par le code de
sortie du job. Il ne faut pas lui attribuer la structure du rapport Windows.

Le run intermédiaire `30769440106` publie exactement trois artefacts inspectés :

| Artefact | ID | Taille | Empreinte GitHub | Empreinte du JSON |
|---|---:|---:|---|---|
| smoke Windows | `8840335490` | 288462 octets | `sha256:4d88cb47143c921e9ae6bd12f07387ea92eda78b5ea1b69fa01b0bca4056d24e` | `b33189dfaab1c971222a3ccc65b5ef2532657e5ba7c7ae185be74c7a01281900` |
| smoke Linux | `8840204853` | 296937 octets | `sha256:f2694d8ec926d92e085327ffcb76e862687160f0da9d0c326319e8545dce4936` | `ab150f2527a35633196c2e4cef15d2cb90fb8ef78c2a366dd4cbb7873f3e3303` |
| rapport Plumber | `8840019185` | 1855 octets | `sha256:9b007bb48ff01347f42b204900d071b976fdcad6f069e84fc846eb68f44f1ba2` | `339c545d3f8bdc0e9109ef76d38a592e069d9ce4a7e570ab700beb539c39a747` |

Chaque smoke contient bien un JSON et dix PNG. Les vingt captures ont été
inspectées visuellement : elles sont cohérentes et sans secret. Le scan des
trois archives ne retrouve ni `MDMP`, core, clé, paquet, binaire, canari ou
sentinelle. Le JSON Windows lie le SHA et le run, consigne les verrous sources
— avec les empreintes CRLF Windows cohérentes —, les MSI, helper et exécutable
vérifiés, puis un nettoyage `pass`. Le JSON Linux rend `pass` et reste relié au
run par la métadonnée GitHub.

Le run fonctionnel de référence `30770893733` publie à son tour exactement
trois artefacts inspectés :

| Artefact | ID | Taille | Empreinte GitHub | Empreinte du JSON |
|---|---:|---:|---|---|
| smoke Windows | `8840757379` | 288424 octets | `sha256:8ee952ba6a265e4ad94289eb265cd19ab4ab5bef472f4d4d2dcbb6d56c38b973` | `a2efa0a548d131e1000b4f03b7a7a6a511f45f2ec42e39640f2148dc32a8dfe0` |
| smoke Linux | `8840658837` | 296937 octets | `sha256:56e904626e35c06fefe4966850b307f2dbc97eb075b83831f5fa15845e4cf58f` | `ab150f2527a35633196c2e4cef15d2cb90fb8ef78c2a366dd4cbb7873f3e3303` |
| rapport Plumber | `8840483746` | 1854 octets | `sha256:98499038c307b2d3dddeca46fc4195dbbf51b50a27cbe1a33b03609cfef95763` | `629dc3b0e73b192b92b9b89fe5d4bd9cce6ce18041cd3c8283a27511ed0c5ff2` |

L'inventaire rend 23 fichiers réguliers non vides : 20 PNG et 3 JSON. Les
vingt captures ont été décodées et inspectées, sans secret ; le scan ciblé ne
retrouve ni clé, token, certificat, canari, sentinelle, `MDMP`, paquet ou
binaire. Le JSON Windows lie exactement `b76ded8` et `30770893733`, les verrous
concordent avec la matérialisation CRLF des blobs Git et le nettoyage bloquant
rend `pass` avec les huit catégories attendues absentes. Il agrège cependant le matériel WER sous
`temporary-security-material` : l'absence distincte du répertoire, de
`LocalDumps` et d'`AeDebug` avant verdict est attribuée au code et au test vert,
pas au seul artefact. Linux rend `pass` sans simuler de Controller ou de succès
métier ; Plumber rend `A`, `100/100`, sans finding.

Sous Windows, `verified_artifacts` relie le `.msi`, l'exécutable signé extrait
de son image administrative et l'exécutable installé, dont l'égalité est
vérifiée. La sortie Cargo restaurée par Tauri après le bundling n'est pas
confondue avec l'exécutable signé réellement placé dans le paquet. Enfin, le
champ Windows `cleanup` rend
bloquante l'absence de l'installation, du certificat et de sa clé privée, du
compte et profil éphémères, des fichiers temporaires, des processus, du port de
debugger WebView2 et des données applicatives. La signature publique de
distribution et la preuve visuelle WebView2 restent des portes distinctes.
Les processus à retirer sont attribués positivement au SID du compte éphémère
ou aux chemins exacts de l'App et de ses pilotes ; une WebView2 étrangère
n'est jamais ciblée d'après son seul chemin. Avant chaque arrêt, le PID, l'heure
de création et l'attribution sont relus, puis un handle lié à cette instance est
utilisé ; aucun nouvel arrêt n'est engagé après l'échéance globale de quinze
secondes. Le profil est ensuite supprimé par
le service de profils Windows, sous l'autorité `SYSTEM` déjà admise par la DACL
privée du coffre. Le runner ne reprend pas possession des données et n'élargit
pas leurs permissions pour les effacer.
Ce schéma enrichi appartient au candidat fermé : le run historique
`30700406219` prouve le smoke antérieur, pas ces nouveaux champs. Le run final
`30710037004` les a exécutés sur le candidat produit exact `3b8f81f` selon la
preuve liée depuis l'issue `#9`.

La première tentative finale, le run `30705241755` sur `46b05ce`, a validé les
deux gardes rapides et la variante Linux. La variante Windows a construit et
signé le MSI, puis a révélé deux défauts de la preuve : elle contrôlait la
sortie Cargo que Tauri restaure volontairement non signée après le bundling,
puis son agrégateur refusait la liste vide normale au début du nettoyage et
masquait cette première erreur. Ce run reste un incident diagnostique, jamais
une preuve de fermeture. Le contrôle rapide de l'agrégateur et l'extraction
administrative du MSI empêchent désormais ces deux confusions avant le nouveau
candidat natif.

La seconde tentative finale, le run `30706885722` sur `eb34fc1`, a de nouveau
validé les deux gardes et Linux. Sous Windows, la construction, les signatures,
l'image administrative, l'installation, l'égalité des exécutables, le coffre
réel et le smoke WebView2 ont réussi. Le nettoyage final a ensuite révélé deux
défauts supplémentaires du harnais : son attribution globale considérait toute
WebView2 apparue après le démarrage comme appartenant à la preuve, puis le
compte administrateur du runner tentait d'effacer directement un coffre dont la
DACL autorise volontairement seulement l'utilisateur éphémère et `SYSTEM`.
Aucun artefact Windows n'a été publié. Le drain borné, réattribué par SID et
protégé contre la réutilisation d'un PID, puis la suppression du profil par le
service Windows corrigent ces deux défauts sans affaiblir la
DACL. Ce run reste diagnostique et ne ferme pas `v0.0.3`.

La troisième tentative finale, le run `30708995783` sur `c302a39`, a validé
les deux gardes, Linux et toutes les assertions produit Windows : MSI et
exécutable signés et horodatés, installation, égalité des exécutables, coffre
réel et smoke WebView2. Le nettoyage a ensuite compté comme processus restant
le résultat nul produit pour chaque processus volontairement non attribué.
Cette valeur nulle a interrompu le drain avant les processus réellement
attribués ; aucun artefact Windows n'a été publié. La collecte construit
désormais explicitement une liste sans résultat nul, tandis que le contrat
rapide couvre une collection entièrement étrangère puis un mélange étranger et
attribué. Ce run reste diagnostique et ne ferme pas `v0.0.3`.

La porte finale, le run `30710037004` sur `3b8f81f`, a ensuite réussi les deux
gardes, Linux et Windows. Le MSI a été construit, signé, installé et lancé ; le
coffre réel, le smoke WebView2, l'attribution des processus et le nettoyage ont
réussi. L'artefact expurgé `app-windows-webview2-smoke` contient uniquement
le rapport JSON et neuf PNG, avec le digest
`sha256:6a5256654742f4950cf9e7108542efb27014a8b5c78c5d6971c033b534642f3d`.
L'issue `#9` relie cette porte au candidat intégré par fast-forward et conserve
ses limites ; ce run ferme `v0.0.3` sans devenir une preuve fonctionnelle
multi-VM.

Le job `Politique Plumber` exécute Plumber `v0.4.8`. L'action GitHub est fixée
au commit `7970e5df1e7d217de41b2880832b63a6f2152b97`, vérifie le checksum et
l'attestation du binaire — une déclaration signée de sa provenance —, n'envoie
aucun score public et ne demande ni SARIF ni permission d'écriture.

La politique sélectionne uniquement des contrôles lisibles depuis le contenu
versionné : SHA des actions, sources autorisées, traces de
debug, Docker-in-Docker, héritage ou export global de secrets, scripts
distants non vérifiés, injections de contexte, déclencheurs dangereux et
permissions excessives. Les contrôles de protection de branche, de CVE, de
référence amont et de collision tag/branche restent exclus de ce premier lot :
ils demanderaient une autorité API supplémentaire ou introduiraient un résultat
partiel dépendant du réseau.

Après Plumber, `tests/checks/plumber-report.py` échoue fermé si l'action n'a pas
réussi ou si sa sortie `passed` n'est pas exactement vraie. Il refuse aussi un
rapport absent, symbolique, non régulier, supérieur à 8 Mio, non JSON, à clés
dupliquées, partiel, averti ou dégradé. Il exige `ciValid=true`,
`ciMissing=false`, `minPoints=100`, le score A à 100 points, aucun constat,
aucun contrôle sélectionné sauté et exactement trois définitions de jobs de
sécurité évaluées.
Le rapport doit aussi correspondre à l'identité source attendue, au dépôt
`ldesfontaine/your-cloud`, au hash canonique de `.plumber.yaml`, à trois jobs,
un workflow et neuf références d'action. Un rapport propre mais ancien ne peut
donc pas satisfaire ce garde.
Les futures clés racine restent acceptées afin qu'une extension compatible du
rapport ne devienne pas un faux échec.

Le rapport n'est archivé qu'après ce garde. Les logs et artefacts ne doivent
jamais contenir `keys.txt`, `/srv/infra/secrets/`, un jeton ou une clé réelle.

Dependabot vérifie chaque semaine les actions GitHub épinglées et ouvre au plus
deux pull requests simultanées. Aucun mécanisme d'auto-fusion n'est configuré
dans le dépôt : chaque nouveau SHA reste soumis aux checks et à une revue
manuelle de Lucas. Dependabot ne maintient pas la version de Go déclarée dans le
workflow ; celle-ci doit être revue séparément selon la politique de support
officielle.

## Observation puis blocage

L'action Plumber produit d'abord son observation structurée. Le garde
indépendant est exécuté avec `if: always()`, y compris lorsque l'action échoue,
puis son propre code de sortie rend le job bloquant. Les 20 cas hostiles parmi
les 23 tests de frontière ont prouvé les refus de rapport absent ou
surdimensionné, lien symbolique, JSON
ambigu, contrat obligatoire manquant, contrôle partiel ou sauté, avertissement,
collecte dégradée, CI invalide, score incomplet et résultat d'action non réussi.
Le prochain rejeu du test d'intégration LAB remplacera temporairement les trois
SHA de `actions/checkout` par le tag `v7` et devra produire trois `ISSUE-701`.
Le rejeu historique à deux jobs en avait produit deux, abaissé
le score à 77,5, quitté en échec, puis le garde a vérifié la cause avant la
restauration exacte du workflow.

Une capture, un score ou un rapport lisible ne remplace jamais ces assertions.

## Automatisation LAB différée

`labctl` reste utilisable depuis le poste de développement pour une preuve
autorisée. Il pourra aussi être appelé par une CI seulement lorsqu'un
contrôleur dédié réunira toutes les propriétés suivantes :

1. aucune charge ni route de production ;
2. accès KVM/libvirt et gabarits `labctl` maîtrisés ;
3. identité dédiée, concurrence exclusive et répertoire jetable par run ;
4. `tools/labctl list` puis validation de l'origine, du gabarit, de la
   topologie et des adresses avant toute mutation ;
5. secrets uniquement synthétiques et aucune exposition aux pull requests non
   fiables ;
6. délais bornés, publication du résultat expurgé et nettoyage vérifié même en
   cas d'échec ;
7. état final nommé et contrôlé avant de libérer le runner.

Tant que ce contrôleur n'existe pas, ajouter un job LAB à GitHub Actions serait
une fausse automatisation. La preuve reste lancée volontairement avec
`tests/lab/v0.0.1/prove` et son inventaire préalable.

`tests/lab/v0.0.1/prove-generic-ci` ne constitue pas ce contrôleur futur. Il
sert seulement à reproduire le mode non privilégié de la CI générique dans
`lab-app`, sans accès aux machines produit, à exécuter Plumber avec le
SHA-256 publié, puis à vérifier son nettoyage. Cette vérification LAB ancre le
transit au checksum connu ; l'action GitHub épinglée ajoute la vérification de
l'attestation SLSA, indisponible sur le runner LAB actuel faute de CLI `gh`.
Une doublure Git bornée fournit seulement les trois métadonnées en lecture que
Plumber demande avant de lire les vrais workflows du lot ; son identifiant de
quarante caractères est dérivé du SHA-256 complet du lot, pas du HEAD Git du
worktree. Le runner GitHub utilisera le vrai checkout et le vrai Git.
Le lot est construit depuis la liste positive des fichiers Git suivis ou non
ignorés, puis son SHA-256 est revérifié dans la VM avant extraction sous l'UID
`65534`. Le rapport nominal et le rapport hostile sont copiés dans un dossier
temporaire, hachés, puis publiés ensemble seulement après disparition vérifiée
du répertoire et de l'archive distants.

La simulation historique `20260717T103459Z-1580819` a réussi sous l'UID
`65534` avant la liaison finale du rapport au lot et l'archivage atomique du
rapport hostile, avec :

```text
source_lot_sha256=a6d558affe8fffc102cc91d06a4084767dec8feed335b84f7e39e2ea1a8f1255
plumber_report_sha256=54f537331b0e403ccd08048e5b42666cc126977594e843cdab31d583c8d4552a
artifact_sha256=4d58798e7c0f1440af22f631b24f6b99c34491765bb41d1c6fc1f46c365f0d41
```

Le répertoire et l'archive distants ont été vérifiés absents après le run. Deux
tentatives antérieures, `20260717T101222Z-1560131` et
`20260717T101401Z-1562452`, s'étaient arrêtées parce que `git` manquait dans la
VM ; leurs chemins distants ont également été nettoyés. La doublure bornée a
ensuite remplacé uniquement ces lectures de métadonnées. La sortie Plumber
indique encore « degraded mode » en l'absence d'authentification GitHub : les
contrôles qui exigent des métadonnées API sont donc exclus de ce lot au lieu
d'être présentés comme verts.

Limite Plumber `v0.4.8` : ses métriques d'affichage comptent encore quatre
actions officielles comme « exemptées », alors que la politique effective
porte `trustedOwners: []`. Cette métrique n'est pas utilisée par le garde. Le
rapport hostile conservé, qui montre deux `ISSUE-701` après remplacement des
deux SHA officiels par `v7`, reste l'autorité de cette non-exemption.

## Réglages GitHub externes à appliquer ou vérifier

Ces réglages vivent hors du dépôt et ne sont donc pas prouvés par le workflow.
Dans le contexte d'accès actuel du dépôt privé, les endpoints de rulesets et de
protection de branche répondent `403` : leur état effectif n'est pas observable
ici. Le mainteneur doit donc les appliquer ou les vérifier lors du passage
public :

- permissions par défaut de GitHub Actions en lecture seule ;
- approbation préalable des workflows provenant de forks ;
- règle de branche à appliquer ou vérifier : exiger les contrôles génériques et
  Plumber avec une branche à jour ; la revue du candidat final doit en plus
  lier le run manuel natif de sa révision exacte ;
- `CODEOWNERS` utilisé pour router toute revue vers Lucas, sans approbation
  obligatoire tant qu'un second mainteneur de confiance n'existe pas ;
- interdiction de fusion lorsqu'une conversation de revue reste ouverte ;
- politique de conservation et visibilité des logs adaptée au dépôt.

Une étape ultérieure, avec un contexte de lecture dédié, pourra observer les
rulesets et métadonnées amont sans donner de droits d'écriture au scanner. Cette
observation externe ne remplace ni les contrôles versionnés, ni la preuve native
manuelle ; sa limite reste visible.

## Références de conception

- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) ;
- [OWASP GitHub Actions Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html) ;
- [GitHub — Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) ;
- [GitHub — runners hébergés](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) ;
- [GitHub — matrice de jobs](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) ;
- [GitHub — relancer des workflows et des jobs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs) ;
- [GitHub — réutiliser des configurations de workflow](https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations) ;
- [GitHub — effet d'un workflow ignoré sur les checks requis](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs) ;
- [GitHub — maintenir les actions avec Dependabot](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/auto-update-actions) ;
- [Go — politique et historique des versions](https://go.dev/doc/devel/release) ;
- [Node.js — versions](https://nodejs.org/en/about/previous-releases) ;
- [Tauri — installateur Windows](https://v2.tauri.app/distribute/windows-installer/) ;
- [Tauri — signature Windows](https://v2.tauri.app/distribute/sign/windows/) ;
- [Microsoft — SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool) ;
- [Plumber — GitHub Actions scanning](https://getplumber.io/docs/cli/github).

Ces sources guident le moindre privilège, l'isolation, l'épinglage et la
défense en profondeur. Elles ne permettent pas d'affirmer que le projet est
« conforme OWASP » ou « conforme NIS2 » ; cette conclusion exige une démarche
organisationnelle et une revue humaine plus large.

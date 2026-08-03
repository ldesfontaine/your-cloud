# Tests et preuves

Ce dossier sépare trois notions qui répondent à des questions différentes.

Un **contrôle générique** vérifie une propriété des sources ou d'un outil sans
dépendre de la topologie métier complète. Un **contrôle natif** construit,
installe et lance l'application sur le système ciblé sans inventer son
infrastructure. Une **preuve LAB** exécute le produit sur les VM identifiées,
observe ses frontières réelles et conserve un résultat relié au lot exact qui
a été exécuté.

| Couche | Contenu | Runner attendu | Autorité |
|---|---|---|---|
| porte rapide sous [`checks/`](checks/) | format, syntaxe, contrat PowerShell de nettoyage attribué par SID, chemins bornés et collecte sans faux candidat nul, cas hostiles du raster PNG, documentation, tests Go, build temporaire, contrats `labctl list`/`assert-clean` et politique CI | runner GitHub Linux jetable sur chaque pull request | codes de sortie et assertions |
| matrice native sous [`checks/`](checks/) | tests frontend et Rust, consentement GTK3/Win32, fixture de crash avec contrôle ordinaire et canari protégé, paquets `.deb`/`.msi`, signature Authenticode synthétique Windows, installation, lancement, absence de listener, captures validées après peinture et smoke de la WebView installée | runners GitHub Linux et Windows jetables, déclenchés manuellement sur le candidat exact | codes de sortie, dumps synthétiques bornés puis nettoyés et, par plateforme, artefact expurgé de onze fichiers : un JSON, neuf vues et un consentement natif PNG |
| [`lab/v0.0.1/`](lab/v0.0.1/) | préparation, déploiement, scénarios hostiles multi-VM, nettoyage et restitution P2 | topologie KVM/libvirt `v1-full` pilotée par `labctl` | `result.json` et assertions machine |
| [`lab/v0.1.0/`](lab/v0.1.0/) | périmètre à deux VM de l'accès personnel : `ssh-agent` et `sshd` réels, comptes et commandes forcées synthétiques, montage, suite `personal-access-contract`, démontage prouvé | topologie KVM/libvirt `quick` pilotée par `labctl` | codes de sortie de la suite et assertions machine |
| [`artifacts/`](artifacts/) | convention et sorties locales non versionnées des preuves | poste de pilotage après rapatriement d'un résultat LAB | résultat structuré du run exact |

Cette séparation prépare une CI propre sans prétendre qu'un conteneur standard
équivaut au LAB :

1. une pull request exécute automatiquement les contrôles génériques et la
   politique CI dans une image isolée ;
2. le candidat final exécute manuellement les différences natives Linux et
   Windows sans Controller, Relay, Daemon ou topologie simulée ;
3. la preuve multi-VM demande un runner dédié, sans charge de production, avec
   libvirt et les gabarits `labctl` ;
4. ce runner doit commencer par l'inventaire en lecture seule, borner ses
   délais, publier les résultats puis vérifier le nettoyage même en cas
   d'échec.

L'entrée [`checks/source-v0.0.1`](checks/source-v0.0.1) rend le placement
explicite : le mode `lab` exige `lab-console` et root isolé pour produire
`dist/your-cloud`, tandis que le mode `ci` exige un runner distant déclaré et
non privilégié, puis construit dans un répertoire temporaire. Aucun mode
n'autorise l'exécution sur le laptop.

Une suite peut exiger un périmètre qu'aucun test unitaire ne synthétise. La
suite `personal-access-contract` de l'assistant natif est dans ce cas : elle
demande un `ssh-agent` détenant réellement des clés et un `sshd` sur une autre
machine, puisque le garde de cible refuse les adresses locales. Elle est donc
fermée derrière la feature `personal-access-contract-test` plutôt qu'ignorée, et
son périmètre est monté, exercé puis retiré par
[`lab/v0.1.0/personal-access/prove`](lab/v0.1.0/personal-access/prove). Ce
harnais ne prouve rien à lui seul : seule une exécution identifiée le fait.

Les sous-dossiers `lab/<version>/deploy/` figent les unités et scripts
effectivement exercés par la preuve de ce palier. Ils ne constituent ni un
installateur général, ni le packaging de production courant. Les futures
définitions d'installation produit seront introduites avec leur propre contrat
et leur propre preuve au lieu de réutiliser implicitement ces fixtures LAB.

Les contrôles sont maintenus avec le code : tout défaut corrigé reçoit le cas
hostile proportionné dans la couche la plus petite capable de le reproduire,
puis une preuve LAB seulement lorsque la frontière réelle est nécessaire. Une
capture ou une page HTML ne remplace jamais une assertion machine.

Pour #45, Linux vérifie qu'un `gcore` par défaut conserve un contrôle ordinaire
mais pas le canari d'un `ProtectedSecret`, puis qu'un `abort` durci ne produit
aucun core. Windows configure un dump WER personnalisé incluant
`PAGE_READWRITE` avec `DumpType=0` et `CustomDumpFlags=0x321`. La fixture exige
la signature `MDMP`, le contrôle et le canari présents : elle caractérise
`LocalDumps` administrateur hors garantie, tandis que
`WerRegisterExcludedMemoryBlock` reste une défense en profondeur. Elle doit
ensuite prouver avant verdict la suppression du dump, l'absence de son
répertoire et celle des deux inscriptions de registre. Les flags incluent
`PAGE_READWRITE` sans
`MiniDumpWithFullMemory` ; le contrôle et la zone `VirtualAlloc` restent donc
observables.
`30768351689` et `30768749538` sont rouges sous l'ancien oracle qui exigeait le
canari absent. Le dernier panic précède le nettoyage explicite ; seuls le
`Drop` best effort et le runner éphémère bornent alors les restes. Le candidat
intermédiaire `ae550470` corrige l'oracle, supprime le dump et prouve le
répertoire vide ainsi que les inscriptions absentes, mais ne retire le
répertoire que par `Drop` après verdict. `30769440106` a entièrement réussi ses
quatre jobs et prouve cette étape intermédiaire, sans fermer #45. `c8643b0`
emploie ensuite `remove_and_prove_absent` pour prouver le répertoire absent
avant verdict. Le run `30770893733` réussit les quatre jobs sur `b76ded8`, avec
les deux inscriptions de registre absentes et trois artefacts inspectés. Le
[rapport dédié](../docs/lab/v0.1.0-native-secret-consent-linux-windows.md)
conserve les jobs, empreintes et limites. L'issue #45 doit enregistrer l'ultime run du
SHA de propagation documentaire avant fermeture ; #42 et #35 restent hors de
cette preuve.

La tentative `30772674819` montre pourquoi le vert d'un job ne suffit pas :
une capture Linux est uniforme et une autre partiellement noire alors que les
métriques DOM et le JSON restent au vert ; Windows refuse ensuite l'attribution
du port avant son smoke. Le garde raster décode et contrôle donc chaque PNG
WebDriver avant écriture, et le smoke Windows découvre le port lié atomiquement
par WebView2 via `DevToolsActivePort`, puis attribue le listener au runtime et
au SID exacts. Une nouvelle matrice doit encore exécuter ces gardes sur leur
SHA.

`30775430141` confirme ensuite le garde raster réel sous Linux : neuf captures
valides dès la première tentative et dix PNG inspectés. Le run reste rouge sous
Windows, car le harnais fournissait déjà `EBWebView` dans la racine que WebView2
suffixe lui-même. Le candidat suivant transmet le parent au runtime et lit le
fichier dans l'UDF suffixé exact. Cette correction devait alors encore être
rejouée ; le résultat Linux ne revendique pas la comparaison responsive
exhaustive à 200 %.

`30777209723` valide le modèle corrigé sous Windows jusqu'au smoke et au
nettoyage, mais reste rouge sous Linux. La coupure survient sur le réglage
idempotent du timeout de script, avant l'appel async qui peut lancer une action.
Le candidat suivant permet donc au seul réglage d'être retenté une fois. Deux
fixtures synthétiques doivent vérifier qu'une coupure à cet endroit produit
deux réglages identiques puis un seul appel async, et qu'une coupure de l'appel
async est propagée sans aucun rejeu. Une nouvelle matrice exacte reste
nécessaire.

Le registre détaillé reste
[`docs/contribution/TESTS.md`](../docs/contribution/TESTS.md). Le placement, les
permissions et les limites de la couche distante sont fixés par le
[`contrat CI`](../docs/contribution/CI.md).

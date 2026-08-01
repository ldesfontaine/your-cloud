# Contrat de CI générique

Cette CI sépare la validation rapide de chaque pull request de la matrice native
Linux/Windows réservée à un candidat final explicitement déclenché. Elle ne
déploie rien, ne pilote pas le LAB et ne publie aucun artefact produit.

Une **CI générique** exécute des contrôles reproductibles dans une machine
jetable fournie par GitHub. Un **runner LAB dédié** serait au contraire une
machine administrée pour piloter KVM/libvirt et la topologie `v1-full`. Une
image CI préconstruite fournit des outils, pas cette topologie ni son autorité.

## État actuel

| Élément | État | Autorité |
|---|---|---|
| porte rapide de pull request | workflow configuré pour exécuter automatiquement les contrôles génériques et Plumber, sans matrice native ; son rejeu sur la révision qui introduit ce découpage reste attendu | états des jobs `Contrôles génériques` et `Politique Plumber` |
| matrice Console Linux/Windows | déclenchement manuel configuré sur `ubuntu-24.04` et `windows-2025` pour un candidat exact ; un run antérieur au découpage a déjà exécuté les deux variantes avec succès, mais le run manuel final reste attendu | codes de sortie des tests, builds, installations et lancements natifs |
| analyse Plumber | binaire épinglé exécuté dans le LAB ; action GitHub et garde indépendant exécutés avec succès sur la révision de référence | sortie de Plumber puis garde indépendant |
| frontière du garde Plumber | 23 cas unitaires — 20 refus et 3 acceptations contrôlées — plus un refus Plumber intégré exécutés dans le LAB | rapports structurés et codes de sortie |
| exécution GitHub Actions réelle | [run `30700406219`](https://github.com/ldesfontaine/your-cloud/actions/runs/30700406219) entièrement vert sur `9c6f14f`, avec les deux variantes natives ; il prouve leur contenu à cette révision, pas encore le nouveau déclenchement manuel | états des jobs, journaux et artefact de smoke du run |
| preuve fonctionnelle multi-VM | exécutée dans le LAB Linux et volontairement hors de cette CI | rapport LAB, résultats structurés et assertions machine |

Plumber complète les contrôles du projet ; il ne remplace ni les tests Go, ni
les scénarios hostiles, ni la preuve LAB. Son score n'est pas une attestation
de conformité.

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
parallèle ; la matrice Console Linux/Windows ne démarre qu'après leur réussite.
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
parseur PowerShell de l'image Linux, sans l'exécuter, puis installe Go `1.26.5`
et appelle `tests/checks/source-v0.0.1 ci` sous une identité non root. Cette
entrée vérifie formatage, syntaxe, schémas structurés, documentation, tests Go,
`go vet` et build statique, ainsi que le garde de politique du workflow. Le
binaire temporaire est vérifié puis supprimé ; il n'est ni déployé ni publié.

Le job matriciel `Console`, exécuté seulement sur déclenchement manuel, fixe
Node.js `24.18.0` LTS et Rust `1.94.1`, désactive le cache automatique et lance
au plus deux variantes en parallèle avec `fail-fast: false`. Les deux variantes
exécutent le même verrou npm, l'audit des dépendances frontend, le contrat
visuel, le build embarqué, le formatage Rust et les tests natifs. La variante
Linux construit le `.deb`, l'installe, le lance sous affichage virtuel puis
refuse tout listener TCP du processus. La variante Windows exécute en plus les
tests d'ACL sur Windows, construit le `.msi` sous MSVC/WiX, signe l'exécutable
et l'installateur, les vérifie, installe, lance et refuse tout listener du
processus ou de ses descendants.

Cette matrice prouve les différences natives des deux plateformes. Elle ne
démarre aucun Controller, Relay ou Daemon, ne crée aucune fausse topologie et
ne simule pas la preuve fonctionnelle multi-VM. Les API, le réseau, mTLS, les
pannes, reprises et scénarios hostiles restent prouvés dans le LAB Linux.

Le certificat Authenticode de CI est synthétique, auto-signé, valable deux
jours, créé dans le magasin de l'utilisateur jetable puis supprimé avec sa clé
privée. Son horodatage RFC 3161 prouve le mécanisme de signature, pas l'identité
publique de Your Cloud. Aucun `.deb`, `.msi`, exécutable ou certificat n'est
archivé. L'archive Windows bornée contient seulement un rapport JSON et des
captures PNG. Le rapport lie `github.sha`, `github.run_id`, le checkout et la
propreté initiale du worktree ; `source_locks` conserve les SHA-256 des verrous
npm et Cargo. `verified_artifacts` relie le `.msi`, l'exécutable construit et
l'exécutable installé, dont l'égalité est vérifiée. Enfin, `cleanup` rend
bloquante l'absence de l'installation, du certificat et de sa clé privée, du
compte et profil éphémères, des fichiers temporaires, des processus, du port de
debugger WebView2 et des données applicatives. La signature publique de
distribution et la preuve visuelle WebView2 restent des portes distinctes.
Ce schéma enrichi appartient au candidat courant : le run historique
`30700406219` prouve le smoke antérieur, pas encore ces nouveaux champs. Le run
manuel final doit les produire sur sa révision exacte.

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
un workflow et huit références d'action. Un rapport propre mais ancien ne peut
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
`lab-console`, sans accès aux machines produit, à exécuter Plumber avec le
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

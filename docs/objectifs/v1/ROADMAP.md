# Roadmap vers `v0.1.0`

> Statut : `v0.0.1` et `v0.0.2` sont décidées, implémentées et prouvées dans le
> LAB. Les huit paramètres de `v0.0.3` sont validés. Sa
> [preuve fonctionnelle Linux](../../lab/v0.0.3-console-controller-linux.md), réussie une
> première fois sur `afb31e8`, a été revalidée après review le 22 juillet 2026
> sur le commit produit exact `02fe4f5`. La porte native Linux/Windows finale a
> ensuite réussi dans le
> [run `30710037004`](https://github.com/ldesfontaine/your-cloud/actions/runs/30710037004)
> sur le candidat produit exact
> `3b8f81f8a1ab4e000da7271bbd22544999c9d0f1`. L'[issue `#9`](https://github.com/ldesfontaine/your-cloud/issues/9)
> relie ce SHA, le run entièrement vert et son intégration par fast-forward :
> `v0.0.3` est fermée pour ce candidat. Les commits documentaires ou de rangement
> ultérieurs ne déplacent pas l'autorité de cette preuve vers un autre candidat
> produit.

Une [édition HTML autonome et visuelle](../../html/roadmap-v1.html) accompagne cette source
Markdown.

## Rôle de cette roadmap

Le [cap du projet](../../projet/CAP.md) décrit la destination à long terme et
l'[objectif v0.1.0](README.md) fixe la première ligne d'arrivée. Cette roadmap
ne remplace aucun des deux : elle ordonne seulement les preuves nécessaires
pour atteindre `v0.1.0`.

Il n'existe volontairement pas de roadmap globale découpant aujourd'hui toutes
les versions futures. Les idées postérieures restent dans le cap et seront
cadrées lorsqu'elles deviendront le prochain objectif réel.

## Règle de progression

- Un palier doit être **décidé**, puis **implémenté**, puis **prouvé** dans le
  LAB avant d'ouvrir le suivant.
- Seul le prochain incrément reçoit un numéro, un périmètre de code et des
  critères détaillés. Les numéros suivants ne sont pas réservés à l'avance.
- Un palier peut être découpé en plusieurs micro-versions si sa première étude
  montre qu'une preuve serait trop large.
- Chaque incrément produit un résultat visible, un test nominal, un refus
  hostile et une limite explicitement annoncée.
- Chaque choix technique respecte la [politique de qualité](../../contribution/QUALITE.md) :
  menace, alternatives, moindre privilège, recommandations OWASP, mesures NIS2
  pertinentes, preuve attendue et risque résiduel restent visibles sans être
  transformés en déclaration de conformité.
- Une faiblesse temporaire n'est admise que dans un LAB isolé, clairement
  signalée et fermée avant d'exposer le composant ou de lui donner une autorité
  supplémentaire.
- Une nouvelle capacité ne peut pas entrer par simple modification de roadmap :
  si elle change la ligne d'arrivée, le contrat de `v0.1.0` doit être rediscuté et
  revalidé d'abord.

## Suivi d'exécution par issues

Chaque palier ou étape décidé possède désormais une issue GitHub. La présente
roadmap reste l'autorité de l'ordre et du contrat ; l'issue suit l'exécution,
les dépendances et les preuves. L'[issue de suivi #20 pour v0.1.0](https://github.com/ldesfontaine/your-cloud/issues/20)
relie l'ensemble. Avant d'implémenter un palier macroscopique, son issue est
découpée en sous-issues exécutables.

| Travail | Issue |
|---|---|
| Fermer les preuves finales de `v0.0.3` | [`#9`](https://github.com/ldesfontaine/your-cloud/issues/9) |
| Amorcer et remplacer un Controller | [`#13`](https://github.com/ldesfontaine/your-cloud/issues/13) |
| Appliquer un premier plan OCI contrôlé | [`#14`](https://github.com/ldesfontaine/your-cloud/issues/14) |
| Prouver le profil BentoPDF optionnel | [`#15`](https://github.com/ldesfontaine/your-cloud/issues/15) |
| Limiter le passage privé au service approuvé | [`#16`](https://github.com/ldesfontaine/your-cloud/issues/16) |
| Prouver le profil privé Vaultwarden optionnel | [`#17`](https://github.com/ldesfontaine/your-cloud/issues/17) |
| Rendre la responsabilité externe visible | [`#18`](https://github.com/ldesfontaine/your-cloud/issues/18) |
| Prouver le scénario complet et les artefacts de `v0.1.0` | [`#19`](https://github.com/ldesfontaine/your-cloud/issues/19) |

L'issue `#9` est le registre unique de la preuve finale. Elle lie désormais le
run manuel `30710037004`, entièrement vert, au candidat produit exact
`3b8f81f`, fusionné par fast-forward. Sa fermeture seule n'aurait pas valu
preuve : ce sont ce lien et les résultats du run qui ferment `v0.0.3`. Tout
nouveau candidat modifiant le contenu couvert par la porte native exige un
nouveau `workflow_dispatch` avant fusion ; un changement ultérieur ne reçoit
jamais rétroactivement la preuve de ce SHA.

La licence du dépôt public ([`#11`](https://github.com/ldesfontaine/your-cloud/issues/11))
et la signature Windows publique gratuite
([`#12`](https://github.com/ldesfontaine/your-cloud/issues/12)) peuvent avancer
en parallèle, mais doivent être fermées avant la release `v0.1.0`. Le routage CI par
domaines ([`#10`](https://github.com/ldesfontaine/your-cloud/issues/10)) reste
un chantier transverse non bloquant pour le contrat produit.

Dans l'amorçage, l'accès personnel `#42` est désormais découpé en quatre
contrats exécutables : [`#51`](https://github.com/ldesfontaine/your-cloud/issues/51)
ferme les bornes KDF et la politique `sudo`,
[`#52`](https://github.com/ldesfontaine/your-cloud/issues/52) authentifie une
cible exacte par l'agent personnel,
[`#53`](https://github.com/ldesfontaine/your-cloud/issues/53) ouvre la clé
OpenSSH chiffrée de repli dans la même session, puis
[`#54`](https://github.com/ldesfontaine/your-cloud/issues/54) vérifie
l'élévation et termine l'état `access_verified`. Cet état signifie uniquement
que l'adresse figée, la clé d'hôte, l'identité choisie et la sonde fixe
`/usr/bin/id -u` ont vérifié un accès direct `root` ou le chemin `sudo`
autorisé. Il ne vaut ni audit, ni installation, ni succès d'amorçage. La
séquence de fermeture est
`#45 → #51 → #52 → #53 → #54 → #42 → #35`. `#45` est fermée depuis le 3 août
2026 : la prochaine issue est donc `#51`.

## État de départ

Le développement produit se poursuit avec l'incrément ouvert décrit ci-dessous.
`tools/labctl` contrôle le LAB sans constituer une capacité de Your Cloud.

| Élément | Décidé | Implémenté | Prouvé |
|---|---:|---:|---:|
| Cap global | oui | sans objet | sans objet |
| Contrat de `v0.1.0` | oui | non | non |
| `v0.0.1` | oui | oui | oui — artefact unique, cohabitation isolée et refus Relay inclus |
| `v0.0.2` | oui | oui | oui — mTLS, profil borné, saturation, lacune et reprise |
| `v0.0.3` | oui — architecture, paramètres et placement des preuves validés | oui — candidat produit Linux/Windows `3b8f81f` | oui — fonctionnel LAB Linux ; porte native finale verte dans `30710037004`, liée au SHA exact par `#9` |
| Amorçage et remplacement du Controller | oui — prochain contrat de `v0.1.0` ouvert après `v0.0.3` | partiel — #43 et #45 acquises et fusionnées ; #42 et #35 ouverts | partiel — #43 et #45 prouvés et fermés, #45 sur `c0569d0` dans `30779157351` ; #42 reprend par #51 |
| Autres paliers de `v0.1.0` | proposés, à relire | non | non |

## Couverture des décisions validées

Cette table sert d'index de contrôle. Elle ne transforme pas les décisions
postérieures en backlog et ne leur attribue aucune version : elle empêche
simplement la roadmap de `v0.1.0` d'oublier la direction déjà validée.

| Sujet | Avant la fin de `v0.1.0` | Direction conservée après `v0.1.0` | Source détaillée |
|---|---|---|---|
| Produit | Représenter l'infrastructure de référence, observer deux machines et déployer deux profils de service explicitement sélectionnés depuis une interface qui montre les opérations réelles | Étendre progressivement l'observation, les opérations et les plateformes sans retirer les parcours externes ni imposer cette topologie | [Cap](../../projet/CAP.md) |
| Machines | Partir de machines Linux déjà installées | Provisionner plus tard par des intégrations OpenStack et Terraform/OpenTofu explicites | [Cap](../../projet/CAP.md) |
| Amorçage | Assistant natif temporaire ; secrets hors WebView, endpoints déclarés sans scan, route SSH vérifiée depuis le Controller, artefact avant accès forcé, état temporaire détruit après transfert et accès utilisateur conservé | Réutiliser le parcours pour remplacer toutes les autorités du Controller sans ajouter une troisième autorité SSH ; sauvegarder son état reste un sujet séparé | [Contrat d'amorçage](../../architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md) |
| Agent | Un exécutable `your-cloud` identique par version sur chaque machine ; Daemon actif après enrôlement, Relay refusé sans activation et Auxiliaire lancé seulement pour un plan approuvé | Conserver un cycle de vie unique avec des capacités optionnelles explicitement activées et des processus isolés | [Glossaire](../../../CONTEXT.md) et [cap](../../projet/CAP.md) |
| Daemon | Processus permanent Go, non-root, sans port entrant ; collecteurs nommés, tampon borné et communications sortantes vers son Relay approuvé | Rester consacré à l'observation, sans connaître le Controller ni transporter de plan ; le chemin d'action reste distinct | [Cap](../../projet/CAP.md) |
| Relay | Mode du même exécutable, activé seulement sur le VPS candidat ; processus, compte, identité, secrets et stockage séparés du Daemon ; aucun ordre retour | Rester une frontière d'observation explicitement provisionnée : le Controller peut obtenir son dernier état d'observation validé, mais le Relay ne porte ni utilisateur, ni inventaire métier, ni statut d'interface, ni canal d'action | [Objectif v0.1.0](README.md) et [cap](../../projet/CAP.md) |
| Auxiliaire local | Mode ponctuel du même artefact, lancé par commande SSH forcée root-owned pour une enveloppe signée ; aucun listener, accès réseau général ou shell | Garder cette autorité pour les opérations Linux locales et utiliser une API ou un runner isolé pour les autres plateformes | [Cap](../../projet/CAP.md) |
| Chemin d'action | Plan et rollback exacts → confirmation et signature natives → transport Controller → clé publique, époque et anti-rejeu local → Auxiliaire → vérification | Garder le même plan approuvé mais choisir l'autorité adaptée : Auxiliaire pour Linux local, API OpenStack, runner IaC isolé ou API K3s | [Cap](../../projet/CAP.md) et [objectif v0.1.0](README.md) |
| App | Console cliente installée et signée sur Linux et Windows, frontend embarqué sans serveur local ; Controller backend d'une infrastructure sans frontend | Controller privé derrière WireGuard, clé de pair et identité distinctes par appareil administrateur, authentification humaine et fournisseur central d'identité facultatif ; téléphone puis navigateur public seulement comme modes futurs séparés | [Objectif v0.1.0](README.md) et [cap](../../projet/CAP.md) |
| Chiffrement et identités | mTLS séparés pour l'observation, identité SSH par machine, approbation signée et anti-rejeu local, HTTPS pour le Web ; l'accès SSH personnel reste indépendant | Ajouter l'accès WireGuard borné des appareils administrateurs sans confondre possession de la clé du pair, authentification humaine et autorisation du Controller | [Objectif v0.1.0](README.md) |
| Exposition des services | Scénario LAB de référence avec Traefik sur le VPS, file provider sans socket de moteur et deux profils optionnels sur la même IP et `443` ; BentoPDF local et Vaultwarden atteint uniquement par WireGuard | Accepter d'autres placements pris en charge ou externes et représenter plus tard une vraie DMZ seulement si des frontières réseau indépendantes sont appliquées et vérifiées | [Objectif v0.1.0](README.md) et [cap](../../projet/CAP.md) |
| Exécution OCI | Podman rootless et Quadlet uniquement sur un hôte systemd avec cgroup v2 ; prérequis contrôlés avant mutation, images, versions et digests épinglés | Un hôte incompatible est refusé pour le déploiement géré ou reste externe ; aucun adaptateur d'init alternatif n'est planifié | [Objectif v0.1.0](README.md) |
| Responsabilité | Mode géré pour ce que Your Cloud applique ; mode externe pour les services ou passages installés manuellement, avec état déclaré distinct de l'état vérifié | Découverte future uniquement en lecture seule sur les machines enrôlées, jamais par scan du LAN ; toute adoption reste auditée et approuvée | [Cap](../../projet/CAP.md) et [objectif v0.1.0](README.md) |
| Sécurité et preuves | Justification OWASP et NIS2 proportionnée, refus hostiles, secrets synthétiques, artefacts épinglés, rapport visuel et aucune revendication de conformité | Conserver le moindre privilège, les mises à jour séparées, la révocation, les SBOM, la provenance et les risques résiduels visibles | [Qualité](../../contribution/QUALITE.md) et [cap](../../projet/CAP.md) |
| Premier jalon après `v0.1.0` | Hors de `v0.1.0` | `v0.1.1` : petit parcours SSO OpenID Connect pour Vaultwarden ; fournisseur, placement et récupération seront cadrés seulement après la preuve de `v0.1.0` | [Cap](../../projet/CAP.md) |

## Incrément prouvé : `v0.0.1`

Le comportement mesurable de ce palier est figé dans son
[contrat exécutable](CONTRAT-V0.0.1.md).

### Résultat

Le même exécutable Go `your-cloud` est installé sur les deux machines cibles du
LAB. Sur le VPS simulé, deux unités lancent en parallèle les modes `daemon` et
`relay` sous des comptes distincts. Sur la machine du LAN, seul le mode `daemon`
est activé et le mode `relay` refuse de démarrer sans manifeste candidat local.
Le Relay conserve le dernier signal reçu et permet de distinguer une machine
vue récemment d'une machine devenue ancienne. Aucun Auxiliaire local n'est
installé ou simulé.

Le message contient uniquement :

- l'identifiant synthétique de la machine ;
- la version du Daemon ;
- l'heure du signal de présence.

### Preuve de sortie

- le placement des trois processus est visible dans le rapport LAB ;
- l'empreinte du même exécutable est identique sur les deux machines ;
- le VPS exécute simultanément Daemon et Relay depuis ce fichier, mais sous deux
  comptes, configurations et politiques systemd séparés ;
- la machine non candidate refuse un lancement direct du Relay avant toute
  écoute réseau ;
- le Relay reçoit un signal des deux machines ;
- l'arrêt d'un Daemon rend uniquement sa machine ancienne après la durée
  annoncée ;
- un identifiant absent ou mal formé et un message dépassant le schéma sont
  refusés sans faire tomber le Relay ;
- redémarrer le Relay et les Daemons produit l'état annoncé, sans processus
  orphelin ;
- l'installation, le démarrage, l'arrêt et le retrait des composants produisent
  l'état annoncé sans reste actif ;
- le code, les tests et le rapport expliquent l'origine, la destination et la
  limite de chaque donnée.

### Limites assumées

`v0.0.1` ne revendique ni interface graphique, ni métrique système, ni mTLS, ni
déploiement, ni WireGuard. Son transport non sécurisé reste strictement confiné
au LAB. Aucune installation ou exécution du produit n'a lieu sur le laptop.

## Paliers nécessaires après `v0.0.1`

<!-- coherence: SERVICE-LIFECYCLE:start -->
Les paliers ci-dessous fixent un ordre de dépendance, pas encore des numéros de
version ni un dessin détaillé de leur code. Cet ordre construit progressivement
les capacités de Your Cloud ; il ne décrit pas l'ordre d'une opération sur une
infrastructure réelle. Une opération suit le
[cycle de vie sûr validé](../../architecture/CYCLE-DE-VIE-DES-SERVICES.md) :
préparer un réseau fermé, déployer sans exposition, vérifier, autoriser le flux
exact, publier ou basculer, observer, puis retirer l'ancien état.
<!-- coherence: SERVICE-LIFECYCLE:end -->

<!-- coherence: V1-OBSERVATION:start -->
### Incrément prouvé : `v0.0.2` — observation authentifiée et bornée

Le comportement mesurable, les paramètres décidés et les exclusions de ce
palier sont figés dans son
[contrat exécutable](CONTRAT-V0.0.2.md) et exécuté dans son
[rapport LAB](../../lab/v0.0.2-observation.md).

**Résultat :** enrôler explicitement les deux machines, donner une identité
distincte à chaque Daemon, protéger le transport Daemon–Relay par mTLS, puis
introduire le premier profil d'observation utile composé de collecteurs nommés.
Le plan du profil montre les champs, lectures locales, privilèges, fréquence et
coûts. Les observations en attente restent dans un tampon local borné. Chaque
Daemon reçoit un endpoint Relay approuvé comprenant route, port et identité ;
cet endpoint peut être privé. L'élection ou le remplacement automatique d'un
Relay reste hors de ce palier tant que candidature, détection de panne,
autorité active unique, redistribution et reprise d'état ne sont pas définies.

**Preuve de sortie :** un Daemon inconnu, révoqué ou utilisant la mauvaise
identité est refusé ; une panne du Relay ne remplit pas le disque ; le retour du
Relay reprend la livraison sans inventer de continuité ; le Daemon n'accepte
aucune connexion réseau entrante et le Relay ne peut transmettre aucun ordre.
Une commande locale en lecture seule affiche le dernier état et la santé du
tampon sans ouvrir d'API réseau. Commande shell, chemin libre, collecteur inconnu,
plugin téléchargé et scan du LAN sont refusés. Ce palier mesure dans le LAB la
taille et la fréquence réelles, fixe les limites d'âge et de taille, puis prouve
qu'une saturation conserve l'état courant et crée une lacune visible.

**Dépendance validée :** ce palier précède l'App. L'interface ne commence pas
par afficher un transport provisoire : l'identité de la source, l'âge de la
donnée et les lacunes éventuelles sont déjà définis et vérifiables.
<!-- coherence: V1-OBSERVATION:end -->

<!-- coherence: V1-APP-ACCESS:start -->
### Incrément fermé — preuves attribuées au candidat exact : `v0.0.3` — Console cliente et Controller de lecture

**Résultat :** installer une Console signée fonctionnelle sur Linux et Windows,
créer une infrastructure dans un Controller, y rattacher les deux machines et
voir leur présence récente, ancienne ou absente. La Console embarque son frontend
responsive et son client réseau : elle n'ouvre aucun serveur local, n'affiche pas
une page `localhost` et ne télécharge aucun code depuis le Controller. Le
Controller reste un backend d'une infrastructure et obtient le dernier état
d'observation validé par le Relay au travers d'une frontière privée authentifiée.
La Console ne contacte jamais le Relay et les Daemons ne connaissent aucun
Controller.

Le Controller possède la liste des machines attendues et la politique qui
transforme l'heure locale de réception du Relay, la dernière séquence et les
lacunes en états d'interface. Le Relay reste limité à l'identité machine, au
schéma, à l'empreinte, aux séquences, à son heure locale de réception, aux
lacunes cumulées, à la persistance du dernier état validé et à son accusé
durable.

**Cadrage validé :** la Console utilise Tauri 2 avec React, TypeScript et Vite.
Son frontend est embarqué, sans serveur local, réseau libre ou code distant. La
distribution initiale produit un `.deb` Linux et un `.msi` Windows natifs,
signés et reliés au même commit, au même verrou frontend, à un manifeste, des
empreintes, une SBOM et leur provenance ; la mise à jour reste manuelle.

L'API Console–Controller est REST JSON sur une origine HTTPS TLS 1.3 exacte.
L'enveloppe présente une identité d'appareil mTLS et une session humaine opaque,
puis expose seulement l'initialisation unique de l'infrastructure, sa lecture,
la lecture des machines et le rattachement idempotent d'une machine déjà
enrôlée. Schémas, tailles, délais, concurrence et erreurs sont bornés. Un
Controller porte un identifiant d'infrastructure immuable et refuse toute
machine que le Relay authentifié ne rattache pas à cette même infrastructure.

Linux et Windows utilisent le même coffre Tauri Stronghold, déverrouillé par
une phrase secrète locale dérivée avec Argon2id. Les clés d'appareil et humaines
restent distinctes par Controller. Le frontend voit brièvement la phrase saisie
puis l'efface ; il ne reçoit aucune clé dérivée, clé privée, donnée du coffre ou
session. La phrase contient six mots français aléatoires. Un listener TLS
épinglé `9444`, réellement temporaire, permet l'appairage ou la récupération
après ouverture par l'autorité locale du Controller ; il ferme après dix
minutes, un succès ou cinq échecs et n'expose aucune route métier.

Chaque Controller accepte un humain et un appareil actifs dans ce palier. Le
certificat P-256 vaut 180 jours et se remplace manuellement en deux phases sans
intervalle de double autorité ni verrouillage si une réponse se perd. Le
Controller vérifie les révocations à chaque requête, y compris sur une connexion
réutilisée. La preuve humaine Ed25519 ouvre une session opaque liée au
certificat et à l'infrastructure, limitée à 30 minutes d'inactivité et huit
heures absolues sans refresh token. Un code global de récupération de 256 bits,
jamais sauvegardé, dérive une clé publique différente par Controller ; son
incident se traite par rotation visible sur chaque association.

Le Relay ouvre en plus de l'ingestion `8443` un lecteur `8444` lié à son adresse
privée exacte. Le filtre d'entrée refuse par défaut et n'autorise que l'IP privée
provisionnée du Controller, supprime les autres paquets et borne les nouveaux
TCP autorisés ; TLS 1.3 mTLS, deux autorités Ed25519 dédiées par infrastructure
et un manifeste revérifié à chaque requête restent nécessaires derrière ce
filtre. Le Controller génère les UUID immuables importés par le manifeste et le
registre Daemon schéma 2. Seul `GET /v0/snapshot`, sans corps ni query, rend de
zéro à 64 derniers états dans une réponse de 2 Mio. Les dates sont normalisées
en UTC ; le Controller calcule l'âge depuis l'heure de réception du Relay et
exige `snapshot_at` dans `[fin - 30 s, départ + 30 s]`. Le dernier snapshot est
conservé atomiquement comme `indisponible` après panne puis repris avec un
backoff borné.

Le Controller sépare désormais l'autorité métier `inventory.json` du cache de
transport `relay-cache.json`. Les deux fichiers JSON privés sont bornés,
validés et publiés atomiquement sous un compte non-root ; une régression du
cache ne peut ni remplacer l'inventaire ni autoriser un rattachement. La
projection rend uniquement les zéro à 64 machines attendues sous 128 Kio. Une
observation fiable est `recent` jusqu'à 90 secondes incluses puis `old` ; panne,
horloge non fiable, enrôlement et lacunes restent des dimensions séparées. Les
plages de lacunes sont résumées exactement sans transmettre les 2 Mio bruts.
Les libellés UTF-8 sont normalisés en NFC, bornés avant et après normalisation
et limités à une liste positive Unicode ; ils ne servent jamais d'identité ou
d'autorisation.

**Système visuel Linux implémenté et éprouvé :** l'interface claire et sombre emploie
des tokens sémantiques, Inter et IBM Plex Mono embarquées, les icônes Lucide et
une mise en page relative. La fenêtre standard vaut `1280 x 800`, avec un
minimum `640 x 560`. Le sélecteur d'infrastructure précède exactement
`Synthèse`, `Parc` et `Observations` ; le Controller reste une liaison
contextuelle, la sécurité locale reste sous `Profil et sessions` et aucun Relay
n'est inventé comme machine dédiée. Les sept vues n'effectuent aucun polling de
fond et rendent les données Controller comme texte inerte.

**Preuve fonctionnelle LAB et matrice native exécutées :** les six VM
Debian `v1-full` ont construit, installé, attaqué et piloté le candidat Linux
selon le [rapport LAB](../../lab/v0.0.3-console-controller-linux.md). Après la
preuve complète initiale, le commit produit `02fe4f5` issu de la review a
repassé les gates, le `.deb`, le coffre, l'appairage, les deux machines, la
panne/reprise Relay et les sept vues. L'orchestration complète reste assistée.
Le run historique `30700406219` a exécuté sur `9c6f14f` les builds,
installations et smokes natifs Linux et Windows. Après le durcissement du
workflow, la porte native finale `30710037004` a entièrement réussi sur le
candidat produit exact `3b8f81f`. Elle ne rejoue ni ne simule la topologie
`v1-full`. L'issue `#9` relie ce SHA et ce run puis enregistre son intégration
par fast-forward : le palier est fermé pour ce candidat exact.

**Précondition validée :** le chemin Daemon–Relay authentifié, le tampon borné
et la représentation des données anciennes ou lacunaires ont franchi leur
preuve de sortie.

**Preuve de sortie :** les artefacts Linux et Windows proviennent des mêmes
sources et vérifient leur signature ; la Console fonctionne sans frontend
hébergé ni listener sur l'appareil administrateur ; un Controller ne peut pas lui substituer du code ;
une identité d'appareil, une session, un Controller ou une infrastructure
inconnus sont refusés. Une donnée non reçue n'est jamais présentée comme
actuelle. Un certificat, une identité, un hôte ou un port Relay non approuvé est
refusé. Le frontend ne reçoit aucune clé SSH, identité de runner, secret de
machine ou secret long terme de session. Le Controller reste en lecture seule :
aucun Ansible, SSH, plan appliqué ou canal d'action n'entre dans ce palier.

Une VM hostile distincte, placée sur le même réseau LAB, doit vérifier que
`8444` est filtré depuis sa source, puis tenter dans une phase isolée d'atteindre
la frontière depuis l'IP autorisée mais sans le certificat lecteur. Elle croise
ensuite certificats Daemon et Controller, CA, noms, infrastructures, registres,
méthodes, routes, queries, corps, schémas, tailles, concurrence et horloges. Elle
tente aussi l'accès Console–Controller sans certificat, avec une identité
inconnue, révoquée ou issue de l'autre
Controller, avec une session ou une infrastructure croisée et avec une machine
de l'autre infrastructure. Elle attaque aussi les fichiers d'état, les
publications interrompues, le cache régressif, la fraîcheur aux bornes, la
projection surdimensionnée, les libellés Unicode hostiles, le port temporaire
fermé, les codes faux, expirés, rejoués ou concurrents, les challenges croisés, les
certificats candidats et les pertes de réponse pendant chaque activation.
Chaque refus doit laisser l'API nominale disponible, l'autorité active unique et
l'inventaire inchangé. Cette matrice est décidée, mais elle n'est pas encore
entièrement exécutée ni rejouable en une commande.

La preuve s'exécute dans le LAB et les runners isolés, jamais sur le laptop de
développement. WireGuard, téléphone, navigateur public, SSO obligatoire et
passerelle Web restent hors de `v0.0.3`. La cible finale conserve l'API du
Controller privée derrière WireGuard avec une clé de pair révocable par appareil
administrateur. Un futur palier postérieur à `v0.1.0` devra rendre cette liaison manipulable
depuis la Console par une opération nommée, bornée au Controller, avec
déverrouillage, timeout et déconnexion explicite sans exposer la clé au
frontend ; son mécanisme reste ouvert. Les services publics gardent leur accès
HTTPS normal.
<!-- coherence: V1-APP-ACCESS:end -->

<!-- coherence: BOOTSTRAP-RECOVERY:start -->
### Palier ouvert — amorçage réutilisable

Ce palier est suivi par l'issue `#13`. La condition de fermeture `#9` de
`v0.0.3` est satisfaite sur le candidat produit `3b8f81f` effectivement
fusionné : l'amorçage est donc le palier ouvert. Son contrat est décidé afin que
l'implémentation ne réinvente pas l'autorité initiale. Le socle helper/IPC
`#43` est prouvé. `#45` est prouvée sur `c0569d0` puis fermée le 3 août 2026.
La séquence de ce sous-palier plaçait #45 avant les sous-issues
`#51 → #52 → #53 → #54`, la fermeture de leur parente `#42`, puis celle de
l'intégration `#35`. Le travail reprend donc à #51 avant le reste du palier
`#13`.

**Résultat :** depuis une Console installée, choisir `Créer une infrastructure`,
déclarer les endpoints sans scan, prêter temporairement un accès SSH personnel,
auditer les machines en lecture seule, approuver le placement puis installer un
Controller autonome et les rôles approuvés. Avant de modifier les autres
machines, le nouveau Controller prouve qu'il joint leurs endpoints SSH. Le même
Assistant natif fournit `Remplacer un Controller` après une perte ou l'isolement
d'un Controller compromis, sans dépendre de lui.

L'enveloppe serveur initiale est un unique paquet `.deb` Debian 13 `amd64`.
L'installateur de Console embarque l'Assistant, ce paquet, ses définitions
statiques et le manifeste signé qui lie version, cible, taille et empreinte.
L'Assistant vérifie le lot avant tout privilège, garde les dépendances hors
ligne et orchestre installation, vérification et retour à la version ou à
l'absence antérieure. Le paquet possède seulement le binaire root-owned sous
`/usr/lib/your-cloud` et les unités Controller, Daemon et Relay livrées
inactives sous `/usr/lib/systemd/system` ; il ne porte ni secret, ni
configuration propre à une machine, ni activation de rôle ou transfert
d'autorité. Aucun binaire privilégié n'est téléchargé dynamiquement.
Le Controller réside sur une machine privée et normalement
allumée. La cohabitation isolée est permise pour une petite infrastructure, une
machine ou VM dédiée est recommandée lorsque taille ou sensibilité augmentent.
Cette cohabitation partage la panne matérielle : perdre ou isoler l'hôte peut
interrompre ses services locaux, tandis que les services des autres hôtes
continuent.

**Socle déjà prouvé (`#43`) :** sur le commit `f3fef79`, le run
`30753216798` a exécuté sous Linux et Windows les modes `create` et `replace`,
les commandes Tauri positives sans champ secret, l'identifiant natif
anti-rejeu, l'absence de listener et les gates de packaging natif. Sous Windows,
la création suspendue, la liste exacte de handles et le Job Object bornent aussi
les descendants et les branches d'échec. Voir le
[rapport du runner Windows](../../lab/v1-bootstrap-ipc-windows.md).

**Implémentation prouvée et fermée (`#45`) :** le helper lie le véritable parent et
son pair IPC au périmètre public immuable, fixe une échéance monotone de 300
secondes non renouvelable et ouvre directement les fenêtres GTK3 ou Win32. Un
`ProtectedSecret` borné à 4096 octets est détruit avant la sortie ; Linux
emploie `mmap`, `mlock` et `MADV_DONTDUMP`, Windows `VirtualAlloc`,
`VirtualLock` et l'enregistrement Windows Error Reporting en défense en
profondeur. Le
[rapport dédié](../../lab/v0.1.0-native-secret-consent-linux-windows.md)
conserve les sous-cas Linux exécutés et les tentatives diagnostiques Windows.
Les runs `30768351689` et `30768749538` sont rouges sous l'ancien oracle, qui
exigeait le canari absent. Ils caractérisent désormais la frontière
`LocalDumps` administrateur hors garantie : contrôle et canari sont présents,
tandis que `WerRegisterExcludedMemoryBlock` reste une défense en profondeur. Le
candidat intermédiaire `ae550470` exige cette observation, supprime le dump,
prouve son répertoire vide et les deux inscriptions de registre absentes, mais
ne retire le répertoire que par `Drop` après verdict. Son run `30769440106` a
entièrement réussi ses quatre jobs et prouve cette étape intermédiaire, mais ne
ferme pas #45. `c8643b0` ajoute `remove_and_prove_absent`, qui exige le
répertoire absent avant verdict. Le run `30770893733` réussit ensuite ses
quatre jobs sur `b76ded8`, valide cette séquence et publie trois artefacts
inspectés. Après trois corrections du harnais de captures, le run
`30779157351` réussit ses quatre jobs sur `c0569d0` : l'issue #45 lie ce run et
ce SHA, fusionné par fast-forward, puis se ferme. Après
acceptation, l'événement terminal public reste `Unavailable` : cette
frontière n'exécute ni SSH, ni `sudo`, ni `root`, ni audit ou installation.

**Preuve de sortie :**

- le frontend, le Controller, les fichiers persistants et les journaux ne
  reçoivent jamais la clé personnelle ou le mot de passe `sudo` ;
- sous Linux comme sous Windows, le prompt natif lie passphrase, mot de passe
  et consentement `root` aux cibles, actions et expiration exactes sans
  primitive SSH libre pour la WebView ;
- `root` n'est utilisé qu'après ce consentement explicite ;
- l'audit refuse une clé d'hôte non confirmée, une cible incompatible, un rôle
  non approuvé, tout scan implicite et toute cible non joignable depuis le
  Controller choisi ;
- le manifeste signé, la version, la cible, la taille, l'empreinte et les
  dépendances hors ligne du `.deb` sont vérifiés avant privilège ; un échec
  restaure l'état absent ou la version antérieure, tandis qu'un état inconnu
  interdit tout retrait aveugle ;
- seuls le binaire sans setuid, setgid ou capacité de fichier et les trois
  unités statiques inactives occupent les chemins paquet root-owned décidés ;
  configuration, secret et identité propres à une machine restent hors du
  `.deb` ;
- le lot serveur est installé avant la commande forcée ; l'entrée Auxiliaire
  initiale est en lecture seule et refuse toute mutation inconnue ;
- chaque machine reçoit une identité SSH Your Cloud différente, restreinte par
  commande forcée vers l'Auxiliaire ; fichier, parents et binaire sont
  root-owned, tandis que shell, PTY, SFTP, rc, X11, environnement et transferts
  échouent ;
- fermer l'Assistant et éteindre la Console n'arrêtent ni le Controller ni les
  services ;
- l'accès personnel reste intact ;
- un remplacement explicite crée une nouvelle association Console, limite le
  lecteur Relay au nouveau Controller, tourne toute autorité exposée, réutilise
  les Agents compatibles et retire seulement les anciennes identités marquées
  Your Cloud après vérification ;
- une suspicion de compromission exige l'isolement de l'ancien hôte ; une
  coupure à chaque étape rend un état partiel reconstructible et jamais un
  succès global ;
- la perte du Controller n'est pas confondue avec la récupération d'association
  d'une Console vers un Controller encore vivant ; si cette récupération
  remplace la clé humaine, l'action reste verrouillée jusqu'à une rotation via
  l'accès personnel.

Le socle `#43` ci-dessus est exécuté dans des runners isolés avec des données
sentinelles synthétiques et aucun secret réel. La preuve de sortie globale reste
incomplète : `#45` a réussi sa matrice native finale et est fermée ; l'accès SSH
personnel avance maintenant par `#51`, `#52`, `#53` et `#54` avant la fermeture
de `#42`, puis l'intégration `#35` reste à prouver. La signature Windows
synthétique valide la mécanique de build du candidat, pas une identité
publique ; une distribution publique attend toujours une signature reconnue et
gratuite réellement opérationnelle.

Le contrat complet est
[Amorçage et remplacement du Controller](../../architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md).
<!-- coherence: BOOTSTRAP-RECOVERY:end -->

### Palier dépendant — premier plan appliqué de manière contrôlée

**Résultat :** le Controller construit un plan lisible que la Console présente
avec son rollback exact. Après confirmation, le cœur natif signe leur enveloppe
canonique ; le Controller la transporte sans pouvoir fabriquer l'approbation,
puis utilise l'identité SSH Your Cloud propre au VPS et sa commande forcée pour
lancer l'Auxiliaire. Celui-ci déploie une **sonde OCI de validation** avec
Podman rootless et Quadlet. Cette sonde est un petit service HTTP jetable, sans
donnée persistante et accessible uniquement localement sur la machine. Son
image est choisie à ce palier, puis épinglée par version et digest ; elle ne
devient pas un composant de Your Cloud.

**Précondition d'autorité :** avant toute mutation, le Controller authentifie
l'humain, l'appareil et la session, puis l'Auxiliaire vérifie indépendamment la
signature de la Console, la clé publique et l'époque root-owned de la cible, la
successeur exact de la séquence anti-rejeu et l'expiration. La séquence est
consommée durablement avant la mutation et reste refusée après redémarrage.
L'accès au réseau privé ne remplace aucun de ces contrôles et une session de
lecture `v0.0.3` ne reçoit pas implicitement le droit d'agir. Le palier
d'amorçage précédent a déjà prouvé l'identité par machine, la commande forcée
et l'absence de shell général.

**Preuve de sortie :** aucun playbook, inventaire, argument, chemin ou commande
libre ne vient du frontend ; l'Auxiliaire refuse une cible inconnue, un plan
altéré, expiré ou rejoué, un digest flottant, un registre, volume, port ou
privilège non approuvé. Une cible sans systemd ou cgroup v2 est refusée avant
mutation. La première application rend `changed=true` ; un nouveau plan
demandant le même état rend `changed=false` sans réécriture ni redémarrage,
tandis que rejouer l'ancienne enveloppe est refusé. Une dérive exige un nouveau
plan ; retirer une sonde déjà absente rend `changed=false`. Un échec contrôlé
tente le rollback exact approuvé ; une coupure rend le résultat inconnu, ne
déclenche aucun rejeu et impose une observation avant un nouveau plan. Une
requête locale obtient la réponse attendue ; redémarrage et retrait produisent
l'état annoncé sans port public ni donnée restante.

**Dépendance validée :** ce mécanisme générique est prouvé avant BentoPDF. Le
palier suivant réutilise donc un chemin de plan, d'approbation et d'exécution
déjà compris au lieu de déboguer simultanément l'action, le proxy, TLS et le
premier véritable service.

<!-- coherence: V1-NETWORK:start -->
### Palier dépendant — premier véritable service public

**Résultat :** prouver le parcours générique d'un service web OCI public avec le
profil BentoPDF explicitement sélectionné dans le scénario LAB de référence :
déploiement sur le VPS, Traefik sans socket de moteur, route générée avec le
file provider et HTTPS sur un nom déclaré. Ce profil n'est jamais installé par
défaut dans une infrastructure utilisateur.

**Preuve de sortie :** seul `443` est nécessaire publiquement, avec `80`
éventuellement limité à la redirection ; le port interne de BentoPDF reste
privé ; une requête directe par l'IP ou un nom inconnu n'obtient aucune route
applicative ; l'image, la configuration et les dépendances sont épinglées et
vérifiées.

### Palier dépendant — passage privé limité au service

**Résultat :** Your Cloud prépare, fait approuver puis applique le passage
WireGuard entre les deux machines enrôlées, avec adresses `/32`, routes et règles
`nftables` limitées au service prévu.

**Preuve de sortie :** la machine du LAN n'a aucun port Internet entrant ; le
VPS ne peut joindre ni SSH, ni les autres ports, ni le sous-réseau du LAN ; une
modification de pair, destination ou port produit un nouveau plan au lieu d'une
mutation silencieuse.

### Palier dépendant — véritable service privé publié par le VPS

**Résultat :** prouver le parcours générique d'un service privé persistant avec
le profil Vaultwarden explicitement sélectionné dans le scénario LAB de
référence : déploiement avec Podman rootless sur la machine du LAN, stockage
persistant, puis seconde route HTTPS Traefik qui le rejoint uniquement par
WireGuard. Ce profil et cette topologie ne sont jamais imposés à une
infrastructure utilisateur.

**Preuve de sortie :** `pdf.<domaine>` et `vault.<domaine>` utilisent la même IP
publique et `443` sans exposer leurs ports internes ; Vaultwarden survit aux
redémarrages et à une recréation contrôlée ; sauvegarde et restauration avec des
secrets synthétiques sont prouvées ; le service ne peut joindre aucun voisin
synthétique du LAN sans flux approuvé.

Le VPS ainsi durci reste une zone d'exposition, pas une DMZ revendiquée. Une
future DMZ exigera un segment dédié et des frontières filtrantes indépendantes
vers Internet, les zones privées et le plan d'administration.
<!-- coherence: V1-NETWORK:end -->

<!-- coherence: OWNERSHIP-MODES:start -->
### Palier dépendant — responsabilité externe visible

**Résultat :** déclarer dans l'App un service ou un passage installé à la main,
sans transférer son autorité à Your Cloud, et distinguer l'état déclaré de ce
qu'un adaptateur en lecture seule sait réellement vérifier.

La présence d'un profil de service pris en charge ne crée aucune ressource et
n'impose aucun placement : chaque instance gérée exige une déclaration, un
placement, un plan et une approbation explicites, tandis qu'un autre service
peut rester externe.

**Preuve de sortie :** un élément inconnu n'est ni découvert par scan, ni adopté
silencieusement, ni présenté comme géré ; l'App annonce clairement ce qu'elle ne
peut ni mettre à jour, ni restaurer, ni supprimer.
<!-- coherence: OWNERSHIP-MODES:end -->

### Preuve complète de `v0.1.0`

**Résultat :** rejouer depuis une base LAB propre le scénario complet de
l'[objectif v0.1.0](README.md), puis produire les artefacts et preuves de
release.

**Preuve de sortie :** deux machines observées, deux véritables services
de référence accessibles en HTTPS depuis leur navigateur normal, Console native
installable sur Linux et Windows, Controller privé autonome, plans approuvés,
second passage sans changement, redémarrages, sauvegarde/restauration, retrait
propre, refus hostiles réseau et autorisation, secrets expurgés, versions
épinglées, SBOM, provenance et rapport visuel. La preuve confirme que les
profils peuvent être sélectionnés ; elle n'en fait pas des installations par
défaut. Une signature Windows synthétique ne suffit pas à une distribution
publique. Toute capacité non prouvée reste annoncée comme telle et bloque `v0.1.0`.

<!-- coherence: AGENT-AUTHORITY:start -->
## Frontières d'autorité conservées au-delà de `v0.1.0`

La roadmap s'arrête à la preuve complète précédente. Les frontières suivantes
s'appliquent déjà au chemin de `v0.1.0` et empêchent une future roadmap de repartir
d'une architecture contradictoire :

- l'Agent reste une installation unique ; son Daemon permanent non-root et son
  Auxiliaire local ponctuel conservent des autorités différentes ; le Relay
  optionnel utilise le même artefact mais un processus et une identité séparés ;
- l'Auxiliaire n'est ni un second Daemon permanent, ni un listener, ni un shell
  général. Une identité SSH propre à la machine et une commande forcée le
  lancent pour une opération connue, puis il s'arrête ;
- le chemin des plans reste séparé du Daemon et du Relay d'observation.
  L'Auxiliaire revérifie indépendamment origine, cible, empreinte, approbation,
  expiration, anti-rejeu et limites sémantiques locales ;
- une coupure rend le résultat inconnu ; `v0.1.0` n'ajoute ni rejeu aveugle, ni
  journal local permettant une continuation autonome ;
- une action OpenStack, Terraform/OpenTofu, Ansible ou K3s utilise l'API ou le
  runner adapté au lieu de détourner artificiellement l'Agent d'une machine ;
- Ansible reste un outil du mode externe et une intégration future possible,
  pas une dépendance du Controller ou des machines de `v0.1.0` ;
- le Controller final reste privé derrière WireGuard, chaque appareil
  administrateur est enrôlé séparément et l'authentification humaine reste
  nécessaire ; une passerelle Web publique demeure une option distincte ;
- la découverte assistée reste locale aux machines enrôlées, en lecture seule,
  et ne transforme jamais un appareil voisin en élément de confiance ;
- une vraie DMZ n'est revendiquée qu'après preuve de frontières filtrantes
  indépendantes ; le VPS de `v0.1.0` reste seulement une zone d'exposition durcie.

Cette section ne planifie ni OpenStack, ni Terraform/OpenTofu, ni K3s, ni
runner Ansible, ni découverte assistée, ni haute disponibilité. Elle fixe leurs
frontières avant leur futur cadrage.
<!-- coherence: AGENT-AUTHORITY:end -->

Le seul jalon déjà noté après cette limite est la demande d'une `v0.1.1` pour un
petit parcours SSO OpenID Connect de Vaultwarden. Son fournisseur, son placement
et sa récupération seront cadrés après la preuve de `v0.1.0` ; ils ne font pas partie de
la présente roadmap.

## Points volontairement non décidés

- Les numéros et le découpage exacts des paliers postérieurs à `v0.0.3`.
- Le dispositif gratuit de signature Windows et la preuve d'éligibilité du
  projet. Le dépôt ne contient actuellement aucune licence ; son choix reste
  une décision explicite du mainteneur et ne sera pas déduit uniquement pour
  obtenir une signature.
- Windows Hello, passkeys, FIDO2 et SSO/OIDC restent postérieurs à `v0.1.0` ; la phrase, le
  coffre, l'appairage, les certificats, sessions, rotations, révocations et la
  récupération locale de `v0.1.0` sont décidés et ne sont plus des points ouverts.
- Le placement et le protocole d'une éventuelle passerelle Web publique après la
  `v0.1.0` ; le Controller privé derrière WireGuard et le SSO facultatif sont décidés.
- Le fournisseur, le placement et la récupération du SSO `v0.1.1` de
  Vaultwarden ; ce jalon de service ne rend pas le SSO obligatoire pour le
  Controller.

## Point d'arrêt

`v0.0.1` et `v0.0.2` restent fermées par leurs contrats et rapports LAB. Les
paramètres 1 à 8 de `v0.0.3` sont fermés et la preuve fonctionnelle Linux de la
branche `console-controller` a été revalidée après review sur le commit produit
exact `02fe4f5`. La porte native Linux/Windows finale a réussi sur le candidat
produit `3b8f81f` dans le run `30710037004`, sans prétendre rejouer la topologie
multi-VM. L'issue `#9` relie cette preuve au SHA intégré par fast-forward :
`v0.0.3` est fermée. Le budget du projet reste nul. L'amorçage et le
remplacement du Controller appartiennent au contrat de `v0.1.0` et restent ouverts, mais
leur socle helper/IPC `#43` est implémenté et prouvé sous Linux et Windows sur
`f3fef79` par le run `30753216798`. `#45` est désormais prouvée et fermée ; les
runs `30768351689` et `30768749538` sont restés
rouges sous l'ancien oracle de dump. `ae550470` corrige cette frontière, mais ne prouve que le
répertoire vide avant verdict et ne le retire qu'au `Drop` ; son run
`30769440106` a réussi ses quatre jobs, mais reste une preuve intermédiaire qui
ne ferme pas #45. `c8643b0` exige le répertoire absent avant verdict ;
`30770893733` réussit les quatre jobs sur `b76ded8` et ses trois artefacts sont
inspectés. Après trois corrections du harnais de captures, le run
`30779157351` réussit ses quatre jobs sur `c0569d0` : l'issue #45 lie ce run et
ce SHA, la PR #50 est fusionnée par fast-forward et #45 est fermée le 3 août
2026. Ces
résultats ne ferment ni `#35`, ni le palier `#13`, ni son milestone : l'ordre
reprend par `#51 → #52 → #53 → #54 → #42 → #35`, puis les autres issues
du palier. Ansible intégré, WireGuard, OCI, téléphone, navigateur public,
Proxmox, OpenStack, worker d'automatisation et projet IaC restent hors du
périmètre de code actuellement prouvé.

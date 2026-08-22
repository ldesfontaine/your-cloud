# Amorçage et remplacement du Controller

> **Ce document fixe l'autorité SSH initiale, son transfert et le remplacement
> explicite du Controller** : ce que l'Assistant temporaire obtient, ce qu'il
> rend, et ce qu'une machine exige avant d'accepter un successeur. Ce qu'il fixe
> engage le produit — une autorité conservée au-delà de ce qu'il décrit est un
> défaut, pas une variante.
>
> Il est la source canonique de la décision transverse `BOOTSTRAP-RECOVERY` au
> sens du [registre de cohérence](../projet/COHERENCE.md). L'**exécution** de ce
> qu'il décide est fixée par
> [l'Assistant qui installe](L-ASSISTANT-QUI-INSTALLE.md).

Une [édition HTML autonome et visuelle](../html/amorcage-controller.html)
accompagne cette source Markdown.

<!-- coherence: BOOTSTRAP-RECOVERY:start -->

## Résultat recherché

L'utilisateur installe uniquement l'App sur son appareil
d'administration. Depuis cette interface, il déclare les machines Linux déjà
installées, prête temporairement un accès SSH existant, fait auditer leur
compatibilité, approuve le placement proposé, puis laisse Your Cloud installer
le premier Controller et enrôler les machines.

Le même parcours sert plus tard à remplacer explicitement un Controller perdu.
Il ne dépend donc ni du Controller à créer, ni du Controller disparu. Une fois
l'opération terminée, le Controller est autonome : éteindre le laptop ou fermer
l'App n'arrête ni l'administration future ni les services déployés.

Ce contrat ne crée aucune troisième autorité SSH ou autorité de secours. Il
distingue deux accès SSH et une authentification produit séparée :

1. l'accès d'administration personnel que l'utilisateur possède déjà ;
2. l'identité d'administration Your Cloud propre à chaque machine ;
3. l'authentification App–Controller, qui autorise l'humain et son appareil
   dans le produit mais ne constitue pas un accès SSH aux machines.

## Assistant natif temporaire

L'**Assistant d'amorçage** appartient à l'installation signée de l'App,
mais reste distinct du frontend. Il est lancé seulement pour `Créer une
infrastructure` ou `Remplacer un Controller`, ne fournit aucun service réseau
permanent et ne conserve aucune clé SSH personnelle après l'opération.

### Processus et canal natif

L'App lance le binaire compagnon distinct
`your-cloud-native-bootstrap-assistant` avec l'unique garde fixe
`--native-bootstrap-assistant`. Il est versionné, livré et signé avec la
App, mais son graphe de production ne dépend ni de l'App, ni de Tauri,
Wry, Tao, WebKitGTK ou JavaScriptCoreGTK. Chaque consentement crée un nouveau
processus helper éphémère ; aucun helper, état secret ou enfant n'est réutilisé
entre deux opérations. Le cœur résout seulement ce nom fixe depuis
l'installation vérifiée et n'enregistre aucun plugin ou appel shell général
auprès du frontend.

Ce découpage est désormais obligatoire. Le gate ELF exécuté dans le LAB le 2
août 2026 a montré que le binaire App déclare directement
`libwebkit2gtk-4.1.so.0` et `libjavascriptcoregtk-4.1.so.0` dans `DT_NEEDED` :
un branchement avant `main` dans ce même exécutable ne peut donc pas constituer
une absence de WebKit. La mesure, ses préconditions et ses limites sont
conservées dans le
[rapport IPC et gate helper Linux](../lab/v1-bootstrap-ipc-linux.md).

### Socle IPC et cycle de vie Windows acquis

Le palier #43 livre désormais le helper distinct avec l'App et borne son
lancement natif sous Windows. Le candidat MSI inspecté place les deux
exécutables installables dans une même image administrative et les signe avec
la même identité Authenticode synthétique. Le parent crée le helper suspendu, ne
rend héritables que ses poignées d'entrée-sortie exactes via
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, l'assigne à un Job Object, vérifie cette
appartenance, puis seulement reprend son thread principal.

Le Job suit les descendants du helper. Une session native n'est considérée
nettoyée qu'après la fin de la racine et la preuve que le Job est vide. Une
annulation ou une sortie en échec arrête la racine et ses descendants, puis en
vérifie l'absence. Si ce nettoyage ne peut pas être prouvé, l'état natif devient
définitivement indisponible pour le processus App courant et tout nouveau
lancement est refusé : l'interface ne peut pas continuer sur une incertitude de
confinement.

L'IPC vivant entre WebView et Tauri expose exactement les parcours `create` et
`replace` par les commandes `start_bootstrap`, `bootstrap_status` et
`cancel_bootstrap`. Les schémas positifs ne possèdent aucun champ secret. Le
frontend ne fixe ni l'étape, ni l'action, ni l'échéance, ni le succès. Le cœur
natif génère un identifiant non rejouable ; demande forgée, seconde demande
concurrente et rejeu sont refusés. Annulation, expiration et fermeture de la
fenêtre produisent des états terminaux. Aucune commande SSH, d'agent ou de
signature générale n'est exposée et les erreurs publiques restent limitées à un
code.

La portée et les artefacts exacts sont conservés dans le
[rapport IPC, paquet et confinement Windows](../lab/v1-bootstrap-ipc-windows.md).
Cette preuve concerne l'image administrative MSI et son ensemble de fichiers
exécutables installables, pas chaque octet possible du conteneur MSI. La
signature synthétique prouve la mécanique Authenticode, pas une identité de
publication reconnue. Le gate PE analyse les tables d'imports normaux et
retardés ; il ne prouve pas l'absence universelle de tout chargement dynamique
de module.

Ce socle ne ferme pas le contrat global. #45 est maintenant implémentée,
prouvée et fermée pour les dialogues GTK3 et Win32, la
zéroïsation,
`mlock`, `MADV_DONTDUMP`, `VirtualLock` et l'enregistrement Windows Error
Reporting en défense en profondeur.
`30768351689` et `30768749538` sont rouges sous l'ancien oracle qui exigeait le
canari absent ; ils caractérisent désormais `LocalDumps` administrateur, hors
garantie, avec contrôle et canari présents. `ae550470` corrige cet oracle, mais
reste intermédiaire : la fixture supprime le contenu du dump, prouve le
répertoire vide et les deux inscriptions de registre absentes, puis ne retire
le répertoire lui-même qu'avec son `Drop`, après le verdict. Son run
`30769440106` a réussi ses quatre jobs et prouve ce contrat intermédiaire, mais
ne ferme donc pas #45. `c8643b0` remplace ensuite ce nettoyage par
`remove_and_prove_absent` afin de prouver le répertoire absent avant verdict.
Le run `30770893733` réussit ses quatre jobs sur `b76ded8`, valide cette
séquence et publie trois artefacts inspectés. Le
[rapport de consentement natif](../lab/v0.1.0-native-secret-consent-linux-windows.md)
conserve les tentatives, preuves, artefacts et limites. Après trois corrections
du harnais de captures, `30779157351` réussit ses quatre jobs sur `c0569d0` :
l'issue #45 lie ce run et ce SHA, puis se ferme. #42 doit
encore fournir l'agent SSH, la clé chiffrée, SSH, `sudo`, le repli `root`, les
vrais descendants de ces parcours métier et leur arrêt. Aucun audit de machine,
Controller installé, succès métier ou signature Windows publique n'est donc
revendiqué ici.

Le parent et le helper communiquent uniquement par des pipes anonymes, typés et
bornés. Le parent fournit un périmètre public immuable : identifiant de demande,
parcours, endpoints, clés d'hôte attendues, étape, action exacte et expiration.
Le helper ne rend que des états expurgés. Il ne renvoie jamais au parent le
secret saisi, une clé privée, un contenu d'agent ou une primitive de signature.
Un secret n'entre ni dans les arguments ou l'environnement du processus, ni
dans une URL, un fichier, un journal ou une réponse IPC. La mort du parent,
l'EOF du pipe, l'annulation ou le timeout ferment le helper et ses enfants.
Le premier incrément fixe cette expiration à cinq minutes depuis une horloge
monotone native ; le frontend ne peut ni choisir cette durée, ni la prolonger.

L'implémentation prouvée par #45 rend cette durée non renouvelable, vérifie le
véritable parent et le pair IPC, et refuse la substitution du parent ou du
périmètre. Elle réserve chaque secret dans un `ProtectedSecret` de 4096 octets
au maximum, non clonable, non sérialisable et expurgé au débogage. Après
acceptation, ce secret est détruit et l'événement terminal public reste
`Unavailable` : aucune utilisation SSH, privilégiée ou métier
n'est simulée avant #42.

Sous Linux, la saisie emploie directement un dialogue GTK3 avec entrée masquée
et usage `Password`. Sous Windows, elle emploie directement un dialogue Win32
modal et un contrôle `EDIT` avec le style `ES_PASSWORD`. Ces deux surfaces sont
créées par le helper, sans HTML, JavaScript, Tauri ou WebView. Elles répètent les
empreintes des machines, l'étape, les actions et l'expiration exactes avant de
recueillir la passphrase, le mot de passe `sudo` ou le consentement `root`.

Le frontend transmet uniquement des demandes typées et affiche les cibles, les
constats et les changements. Il ne reçoit jamais :

- une clé privée SSH ;
- le contenu d'un agent SSH ;
- un mot de passe SSH ou `sudo` ;
- une identité d'administration Your Cloud ;
- un shell, un playbook, un inventaire ou des arguments libres.

Une demande du frontend peut seulement ouvrir ce parcours nommé. Elle ne donne
pas accès à une primitive SSH ou de signature générale. Après la confirmation
native, l'Assistant borne l'utilisation de `ssh-agent` à la connexion SSH exacte
vers les hôtes affichés et refuse toute cible, action ou durée différente. Un
nouvel hôte, une nouvelle étape privilégiée ou une expiration impose une
nouvelle confirmation native.

### Moteur SSH et accès personnel

Le helper embarque le client Rust `russh` épinglé exactement ainsi :

```toml
russh = { version = "=0.62.4", default-features = false, features = ["ring", "rsa"] }
```

Ses algorithmes sont choisis par une liste positive. DSA, DES, la compression
et la signature RSA `ssh-rsa` fondée sur SHA-1 sont refusés. `Preferred::DEFAULT`
n'est jamais réutilisé : il offre encore ECDSA, les courbes NIST et
`Algorithm::Rsa { hash: None }`, qui désigne précisément la signature SHA-1.
Les cinq champs négociés — échange de clés, clés, chiffrement, MAC et
compression — sont donc reconstruits explicitement. La liste d'échange de clés
conserve obligatoirement les pseudo-algorithmes `ext-info` et strict key
exchange d'OpenSSH : `russh` les filtre par rôle mais ne les ajoute jamais
lui-même, si bien qu'une liste écrite à la main qui les omettrait perdrait
silencieusement l'atténuation de Terrapin.

**Risque résiduel de chaîne d'approvisionnement.** La résolution réelle de
`russh 0.62.4` fait entrer 108 paquets supplémentaires dans le graphe du
helper, qui passe de 71 à 179, ainsi qu'un runtime asynchrone `tokio`. Cinq
d'entre eux sont des versions préliminaires : `ssh-key 0.7.0-rc.11`,
`rsa 0.10.0-rc.18`, `pkcs1 0.8.0-rc.4`, `blake2 0.11.0-rc.6` et
`argon2 0.6.0-rc.8`. L'analyse de la clé personnelle et le traitement des
paquets d'un serveur distant reposent donc sur des candidates de publication
issues de RustCrypto. Ce choix est assumé faute d'alternative meilleure —
déléguer au binaire `ssh` sortirait la passphrase de la mémoire protégée et
retirerait le contrôle du budget de signatures, tandis qu'une bibliothèque en C
déplacerait la surface distante hors de la sûreté mémoire. Cette limite est
nommée au même titre que la signature Windows synthétique : elle n'est pas
prouvée absente, elle est déclarée.

Ces versions préliminaires restent confinées au sous-arbre du helper. La
vérification du lockfile montre qu'un seul paquet est réellement remplacé dans
tout le workspace : `zeroize`, porté de `1.8.2` à `1.9.0` parce que
`ssh-key 0.7.0-rc.11` l'exige. Tous les autres coexistent en deux versions, si
bien que l'App conserve intacte la crypto de son coffre déjà prouvée —
notamment `argon2 0.5.3`, `ed25519-dalek 2.2.0`, `sha2 0.10.9` et `rand 0.8.5`.
Le helper compile sa propre pile ; il ne déplace pas celle de l'App. La clé d'hôte est
comparée exactement à celle du périmètre approuvé : le client ne décide jamais
la confiance au premier contact (`TOFU`) et n'écrit pas implicitement dans
`known_hosts`. Il n'expose ni shell, ni PTY, ni redirection, ni SFTP, X11,
transfert d'agent ou commande générale.

L'Assistant préfère un agent SSH déjà déverrouillé et lui demande de signer sans
extraire la clé privée. Sous Linux, il accepte seulement le chemin absolu lu une
fois depuis `SSH_AUTH_SOCK`, vérifié comme socket Unix appartenant à
l'utilisateur courant. Le helper est lancé avec un environnement vidé, si bien
que cette variable n'existe pour lui que si l'App la lui transmet. Elle la
transmet **seulement** pour l'étape d'accès personnel : un agent est un oracle
de signature, et une fenêtre qui demande un mot de passe `sudo`, une passphrase
ou une confirmation `root` n'en a aucun usage. L'App ne juge pas la valeur,
elle ne fait que la porter ; l'admissibilité — chemin absolu et borné, socket
réel appartenant à l'utilisateur, répertoire parent que personne d'autre ne peut
réarranger — est décidée par le helper, seul à observer le système de fichiers
auquel il va ensuite se connecter. Sous Windows, `v0.1.0` accepte seulement le pipe OpenSSH
`\\.\pipe\openssh-ssh-agent`. Ce nom ne protège rien : n'importe quel
processus peut le prendre. Le helper atteste donc l'objet lui-même, dont le
noyau porte le créateur, et exige qu'il appartienne au compte du service. Il
lit en supplément le fichier exécuté et le compte du serveur lorsque ce
processus peut être ouvert, ce qu'un utilisateur non administrateur ne peut pas
faire pour un service système — exiger cette lecture rendrait l'accès personnel
inutilisable pour l'usage courant, alors que l'agent, lui, le sert. Limite
assumée et non refermée : là où le processus reste inobservable, l'attestation
distingue le compte créateur, pas le programme, et un autre service du même
compte qui prendrait le nom en premier passerait ce contrôle. Une seule clé est sélectionnée et un budget fini
de signatures est limité à l'authentification SSH de cette opération ; une
deuxième signature ou un message hors de cette capacité est refusé. Les logs du
client d'agent restent désactivés afin qu'aucun tampon de protocole n'y entre.

La sélection de cette clé appartient à la fenêtre native, des deux côtés :
liste GTK3 sous Linux, liste déroulante Win32 sous Windows. Les deux montrent
les identités que l'agent détient réellement, chacune nommée par sa propre
empreinte — celle à laquelle le budget de signature sera ensuite lié, si bien
que ce qui est lu et ce qui est signé ne peuvent pas diverger. Un certificat
n'y est jamais proposé, puisque ce palier refuse de signer avec. Et
l'acceptation reste indisponible tant qu'aucune identité n'est nommée : un
consentement ne peut pas être donné sans dire à quelle clé il s'applique. Le
pas produit lui-même est un seul chemin partagé : toute l'observation — une
résolution, les adresses gelées, l'endpoint de l'agent, les identités — précède
la fenêtre, rien n'est redérivé après le consentement, et chaque refus est
expurgé dans le même événement terminal `Unavailable`.

En solution de repli, le sélecteur natif ouvre seulement une clé au format
`OPENSSH PRIVATE KEY` réellement chiffrée par bcrypt et `aes256-ctr`. Ed25519
est accepté ; RSA ne l'est qu'à partir de 3072 bits pour compatibilité. Les clés
en clair et les formats PKCS#1, PKCS#8, SEC1 et PPK sont refusés, sans détection
implicite d'un autre format. L'ouverture est bornée et ne réécrit pas le fichier.
Les octets lus, la passphrase et la clé déchiffrée sont zéroïsés sur les sorties
contrôlées.

Deux limites de ce repli sont mesurées et assumées plutôt que supposées. La
dérivation, une fois lancée, n'est pas interruptible : un bail relâché pendant
qu'elle travaille ne la coupe pas, il la laisse finir dans la borne la plus
courte entre ce qui reste de la session et le plafond du pas. La clé produite
n'est alors portée par aucun transport, aucune connexion n'est ouverte et la
session se termine sur l'annulation expurgée ordinaire : l'état est donc bien
détruit, dans une borne, et non à l'instant de la demande. Et un arrêt brutal
n'exécute aucun effacement : ce qui rend le secret introuvable après un tel
arrêt n'est pas une zéroïsation mais l'absence d'écriture durable — mémoire
verrouillée hors de l'espace d'échange, clichés interdits. Cette protection
couvre tout cliché produit par un débogueur ou par le noyau ; elle ne couvre
pas un lecteur privilégié qui va directement à la mémoire d'un processus
vivant, exposition dont la borne est la durée de l'opération elle-même.

**Amendement du 16 août 2026 — ce que « la durée de l'opération » veut dire
depuis l'installation.** Jusqu'ici cette durée était celle d'une commande : le
mot de passe `sudo` était dépensé une fois puis effacé, et `-k` détruisait même
l'horodatage. Une installation enchaîne plusieurs actes privilégiés, et les deux
propriétés ne tiennent plus ensemble. La règle est donc **relative à la posture
de la machine**, et le meilleur cas reste le cas strict :

| Posture du compte prêté | Ce qui est retenu |
|---|---|
| `root` direct, ou `sudo` sans mot de passe | **rien** — aucun secret n'existe à retenir |
| `sudo` avec mot de passe | le secret vit dans son allocation protégée le temps de la **séquence approuvée**, et pas au-delà |

Le choix inverse — exiger `NOPASSWD` pour installer — a été écarté pour une
raison qui vaut d'être écrite : il ferait **affaiblir durablement** la machine
de l'humain (une entrée `NOPASSWD: ALL` est une configuration permanente, et un
shell obtenu sous ce compte par n'importe quel vecteur donnerait `root` sans
mot de passe) afin de préserver une propriété **transitoire** de notre
processus. L'issue réaliste est connue : ajoutée pour l'amorçage, jamais
retirée — le produit aurait causé l'affaiblissement. Le produit s'adapte donc à
la posture de la machine au lieu d'en exiger une.

La borne du secret retenu est nommée et tenue : il meurt à la fin de la
séquence sur **toute** sortie — succès, échec, annulation, expiration — ou à
l'échéance de session, le premier des deux, jamais « quand le processus se
termine ». Les protections de l'allocation (`mlock`, exclusion des clichés, et
leur équivalent Windows) sont des propriétés de la cartographie et non du
temps : elles couvrent la durée étendue par construction, ce qui a été vérifié
plutôt que supposé. Chaque acte porte son secret explicitement ; rien ne
s'appuie sur l'horodatage de `sudo`, dont le réglage est invisible et dont
l'expiration au milieu d'une séquence serait précisément le mur que ce palier
élimine.

Le format, le chiffrement, le KDF et le nombre de rounds sont lus **avant**
toute dérivation. Une enveloppe hors contrat est donc refusée sans demander de
passphrase et sans dépenser de temps. Le nombre de rounds accepté est borné à
2048 : la [calibration LAB](../lab/v0.1.0-personal-access-bounds.md) mesure
environ 4,6 ms par round sur l'hôte App de référence, soit 9,4 s à cette
borne contre les 300 s de l'échéance, tout en restant très au-dessus du défaut
OpenSSH de 16. Cette borne est un garde-fou : la garantie reste l'échéance
monotone appliquée pendant la dérivation. Aucun minimum de politique n'est
imposé, seul le chiffrement effectif est exigé.

Un préflight non secret `sudo -N -n -l -l`, sans PTY, entrée fermée, sous
`LC_ALL=C` et à sortie bornée, doit produire un listing **attestable** : une
sortie absente, tronquée, traduite ou non reconnue échoue fermé. Ces refus
portent sur la confiance accordée au listing, jamais sur le secret.

**Amendement du 22 août 2026 — la journalisation d'entrée cesse d'être un
refus, et la garde change de côté.** Ce paragraphe affirmait que `log_input` et
`log_stdin` étaient des refus durs, au motif que le mot de passe voyage sur
l'entrée standard de la commande distante et atterrirait donc en clair dans
`/var/log/sudo-io`. **Ce mécanisme a été mesuré, et il est faux pour la forme
de commande du produit** : sans PTY et avec `-S`, `sudo` consomme la ligne du
secret pendant l'authentification, avant que le journal d'E/S de la commande
n'existe. Un témoin placé derrière le secret se retrouve dans le journal ; le
secret, jamais.

Le refus regardait donc la politique d'une machine tierce pour se prémunir d'un
défaut qui naîtrait ici — il était du mauvais côté de la frontière, et refusait
du service à un utilisateur dont la machine est correctement configurée. **Ce
qui le remplace est un invariant local et exerçable** : aucun acte ne porte de
matériau produit, ni sur son entrée, ni sur sa sortie. La table des actes est
close et sa classification est exhaustive, si bien qu'un acte ajouté ne compile
pas sans être relu.

**Bornes de la mesure, et ce qui ramènerait le refus.** Elle vaut pour
Debian 13, `sudo` 1.9.16p2, sans PTY, et la forme `-S` sans rien piper derrière
le secret. Un acte futur qui allouerait un PTY, ou une version de `sudo` qui
lirait le secret autrement, rouvrirait la question. La mesure est donc rejouée
plutôt que racontée : `tests/lab/v0.3.0/sudo-io-logging/prove` justifie
l'**absence** de ce refus et rougit le jour où elle cesse d'être vraie.

La décision ne s'appuie jamais sur le masquage de mot de passe de `sudo`, dont
la regex de prompt est configurable : le prompt sentinelle du produit n'est pas
celui que la regex par défaut décrit. Le prompt sentinelle **reste** — il
protège de l'usurpation d'invite, ce qu'aucune regex configurable ne fait, et
l'échanger contre du masquage troquerait une garde forte contre une garde que
la machine d'en face peut désactiver.

#### Justification de sécurité du retrait du refus de journalisation

- **Scénario et actifs** : le mot de passe `sudo` d'un compte d'administration
  ordinaire, et les sorties des huit actes privilégiés, sur une machine cible
  dont la politique `sudo` journalise les entrées et les sorties.
- **Menace ou échec traité** : qu'un secret du produit soit conservé en clair
  dans le journal d'E/S d'une machine tierce.
- **Alternatives réellement considérées** : *maintenir le refus* — écarté, sa
  raison écrite est mesurée fausse et il refusait du service à une machine
  correctement configurée ; *transformer le refus en refus de `log_output`* —
  écarté, rien de mesuré ne le demande, les huit sorties étant publiques ;
  *adopter le prompt par défaut de `sudo` pour bénéficier de son masquage* —
  écarté, cela troquerait une protection contre l'usurpation d'invite contre
  une réduction par regex que la machine d'en face configure.
- **Portée d'accès accordée et moindre privilège** : inchangés. Le retrait
  n'ouvre aucune commande, n'élargit aucune portée et ne change pas la borne de
  vie du secret.
- **OWASP** : séparation des responsabilités — la garde passe du jugement de la
  configuration d'autrui à un invariant de nos propres actes ; réduction de
  surface — un refus de moins à maintenir juste ; valeur sûre par défaut — la
  classification des actes est exhaustive, un acte non relu ne compile pas.
- **NIS2** : analyse des risques fondée sur une mesure plutôt que sur une
  croyance ; développement sûr — l'invariant est un test, pas un commentaire ;
  mesure d'efficacité — le contrôle rejouable atteste dans la durée.
- **Tests normaux et hostiles** : la mesure LAB avec son témoin de contrôle
  (`tests/lab/v0.3.0/sudo-io-logging/prove`), qui échoue si le témoin manque
  comme si le secret apparaît ; l'invariant de la table des actes ; le compte
  du périmètre portant `log_input`, passé de cas hostile à cas nominal dans la
  suite `personal-access-contract`.
- **Risque résiduel, assumé et nommé** : sur une machine qui journalise, **les
  sorties des actes sont capturées** — c'est mesuré, témoin à l'appui. Ce qui
  garantit qu'elles ne portent rien de sensible n'est plus un refus mais
  l'invariant local, et il ne vaut que tant que la table des actes reste close
  et relue. Restent explicitement non garantis : le comportement d'une version
  de `sudo` autre que 1.9.16p2, et tout acte futur qui allouerait un PTY.

L'exécution de #42 suit quatre contrats successifs. #51 mesure et ferme les
bornes du KDF ainsi que la politique de journalisation `sudo` ; #52
authentifie une cible exacte par l'agent personnel ; #53 ouvre le seul format
de clé chiffrée ci-dessus dans la même session ; #54 vérifie l'élévation et
termine `access_verified`. Cet état public signifie uniquement que l'adresse
résolue puis figée, la clé d'hôte, l'identité choisie et la commande fixe
`/usr/bin/id -u` ont vérifié l'accès direct `root` ou le chemin `sudo`
autorisé. Il ne prouve ni audit de machine, ni installation, ni transfert
d'autorité ou succès d'amorçage. La parente #42 se ferme après ces quatre
preuves, puis #35 porte leur intégration avec #43 et #45.

### Élévation, arrêt et risque résiduel

Avec un compte non-root, le helper lit d'abord la politique sans rien dépenser
— `sudo -N -n -l -l`, sans PTY, sous `LC_ALL=C` et à sortie bornée. Si `sudo`
exige une authentification, le mot de passe est recueilli dans le dialogue natif
puis envoyé une seule fois, sans PTY, sur l'entrée chiffrée de la session SSH
vers une commande fixe `sudo -k -S -p <sentinelle> -- <chemin absolu autorisé>`.
Il n'existe ni relance automatique, ni shell, ni interpolation de commande.
L'opération est refusée si la politique distante ne permet pas d'établir cette
capacité exacte.

Sur une machine dont la politique n'autorise pas à lire le listing des droits
sans mot de passe — **ce qui est la configuration par défaut de Debian** —
l'établissement de la capacité exacte exige d'envoyer le secret. **Ce contrat
l'autorise**, à l'intérieur de la séquence approuvée et sous les bornes déjà
posées : le secret a été prêté par l'humain dans le dialogue natif pour cette
séquence, et il meurt avec elle.

**Amendement du 22 août 2026 — la lecture payée, et ce qui la borne.** Ce
paragraphe disait ce que le contrat autorise ; voici la forme sous laquelle le
produit le fait. La politique est relue par une commande fixe de plus,
`sudo -k -S -p <sentinelle> -l -l`, qui demande **le même listing** que le
prévol non secret et le remet **au même juge** : seule la façon de l'obtenir
change, jamais ce qui est jugé. Ses drapeaux sont ceux de l'élévation, et pour
les mêmes raisons — `-k` jette l'horodatage, donc la lecture s'authentifie
réellement au lieu de profiter de celle d'un autre ; `-S` lit le secret sur le
canal ; `-p` impose la sentinelle, qui est ce qui rend toute autre invite
reconnaissable.

Quatre bornes, et aucune n'est nouvelle sauf la dernière :

- **un seul envoi** — le secret part une fois pour la lecture, et l'élévation
  qui suit dépense le même, jamais un second recueilli ailleurs ;
- **pas de troisième tour** — une politique qui réclame encore une
  authentification *après* avoir reçu le secret est un refus dur, nommé comme
  tel ; il n'existe aucune boucle ;
- **le terminal reste un refus** — une politique qui exige un tty est refusée
  **avant** que le secret ne parte, parce qu'aucun secret n'en fabrique un.
  C'est un refus voisin du précédent, et il ne tombe pas avec lui ;
- **le budget de canaux passe de trois à quatre**, ce qui est le compte exact
  de la conversation la plus longue : la sonde d'identité, le prévol non
  secret, le prévol payé, et une des deux élévations. Un budget qui aurait pris
  une marge cesserait de dire ce qu'il dit.

**Ce que la lecture payée retire à un audit.** Le budget d'une session servait
aussi une seconde garantie : une session d'audit dépensait exactement ses trois
canaux d'observation, si bien qu'il ne lui en restait aucun pour élever. Cette
garantie reposait sur une **égalité de chiffres** entre deux conversations sans
rapport, et l'ajout d'un canal l'a défaite. Ce qui la remplace est plus faible
et se tient seul : ce qui reste après un audit est plus court que la plus courte
élévation. Un audit ne peut donc toujours pas élever — non plus par épuisement,
mais par insuffisance — et c'est exercé en essayant plutôt qu'en comptant.

Un état antérieur de ce contrat refusait ce pas — « ne pas envoyer un secret
pour savoir si l'on a le droit de l'envoyer » — et en assumait la conséquence :
le compte d'administration ordinaire d'une Debian était refusé. **Ce refus était
prudent d'un cran de trop**, et sa justification est ci-dessous.

L'établissement de la capacité reste **un acte de la séquence**, pas un
préalable qui s'en affranchirait : il est soumis aux mêmes bornes que l'acte
qu'il prépare, et un refus de la politique distante se nomme au lieu de se
tenter à l'aveugle.

#### Justification de sécurité de la lecture authentifiée de la politique

- **Scénario et actifs** : le mot de passe `sudo` d'un compte d'administration
  ordinaire, prêté pour une séquence d'amorçage, sur une machine cible dont
  l'empreinte de clé d'hôte a été relevée hors bande.
- **Menace traitée** : envoyer un secret à une machine dont on n'aurait pas
  établi qu'elle a le droit de le recevoir.
- **Pourquoi le refus était d'un cran de trop** : **l'identité de la machine est
  déjà établie** — l'empreinte de clé d'hôte relevée hors bande sur le serveur
  la fixe avant toute connexion. Ce qui restait inconnu n'était donc pas *à qui
  l'on parle*, mais *quel privilège possède le compte prêté*. Et le secret
  partait de toute façon vers cette même machine à l'acte suivant : le refus
  déplaçait l'envoi d'un acte, il ne l'évitait pas.
- **Alternatives considérées** : exiger `NOPASSWD` — **écarté** et il le reste,
  pour la raison écrite plus haut : affaiblir durablement la machine de l'humain
  au profit d'une propriété transitoire de notre processus. Tenter l'action à
  l'aveugle sans établir la capacité — écarté, un échec sans cause nommée ne dit
  rien à l'utilisateur.
- **Portée accordée et moindre privilège** : inchangés. Le secret voyage sur
  l'entrée chiffrée d'une session SSH déjà authentifiée, vers une commande fixe,
  sans PTY, sans shell, sans relance automatique.
- **OWASP** : défense en profondeur (l'identité de l'hôte précède le secret),
  séparation des responsabilités (le dialogue natif recueille, le helper
  transmet, ni l'un ni l'autre ne conserve), réduction de surface (une commande
  fixe, un envoi).
- **NIS2** : contrôle d'accès, cryptographie, gestion d'incident — un refus de
  politique se nomme et son geste correcteur aussi.
- **Preuves attendues** : le compte d'administration ordinaire d'une Debian
  installée par défaut mène au Controller actif ; une politique restrictive
  exotique reçoit un refus qui nomme sa cause ; aucun secret ne survit à la fin
  de la séquence, sur toute sortie.
- **Risque résiduel, assumé et nommé** : une machine légitime mais **déjà
  compromise** verra ce secret. Elle l'aurait vu à l'acte suivant — le refus ne
  protégeait pas de cela. La borne de vie du secret est **inchangée** : il meurt
  à la fin de la séquence, sur succès comme sur échec.

#### Justification de sécurité de la séparation des refus et du budget

Cette seconde justification ne recouvre pas la précédente : celle-ci porte sur
la **décision** d'autoriser la lecture payée, celle-là sur ce que sa mise en
œuvre a dû séparer pour ne pas emporter autre chose avec elle.

- **Scénario et actifs** : le mot de passe `sudo` d'un compte d'administration
  ordinaire, et le nombre de commandes qu'une session d'accès personnel peut
  faire exécuter sur la machine cible.
- **Menace ou échec traité** : deux, distinctes. Qu'un refus rendu franchissable
  en rende un autre franchissable **par la même ligne de code** — les deux
  partageaient une table de marqueurs. Et qu'un budget desserré pour la
  conversation nouvelle laisse à une conversation ancienne — l'audit — de quoi
  faire ce qu'elle ne devait pas pouvoir faire.
- **Alternatives réellement considérées** : *laisser les quatre marqueurs
  ensemble et lever le refus commun* — écarté, il aurait envoyé le secret à une
  politique qui exige un terminal, c'est-à-dire une dépense sans contrepartie
  possible ; *garder un seul refus et le franchir seulement si aucun marqueur de
  terminal n'est présent* — écarté, la condition aurait vécu chez l'appelant, où
  rien ne la rend exerçable, alors qu'un nom de refus se teste ; *donner au
  budget une marge plutôt qu'un compte exact* — écarté, un budget avec marge
  cesse d'être le compte de ce qui peut s'ouvrir, et c'est cela seul qui en fait
  une borne.
- **Portée d'accès accordée et moindre privilège** : la portée des commandes est
  **inchangée** — les cinq commandes fixes restent des constantes du crate, dont
  le constructeur est interne, et la nouvelle demande le même listing que
  l'ancienne. Le budget augmente d'exactement un, qui est le canal ajouté.
- **OWASP** : valeur sûre par défaut — le marqueur de terminal est lu **avant**
  celui du secret, si bien qu'une politique qui répond les deux reçoit celui
  qu'aucun secret ne lève ; séparation des responsabilités — le module de
  politique juge un listing, l'appelant décide seul si un prix se paie ;
  réduction de surface — un refus reconnu par le message de `sudo` retombe sur
  la garde d'invite si ce message change, plutôt que de s'ouvrir.
- **NIS2** : contrôle d'accès — la conversation maximale est énumérée et non
  dérivée d'une arithmétique ; développement sûr — les deux propriétés sont des
  tests, pas des commentaires ; gestion d'incident — quatre refus nomment
  désormais leur cause et leur geste correcteur, là où deux se taisaient.
- **Tests normaux et hostiles** : la table des refus nommés, exercée hors LAB ;
  les trois issues du prévol non secret sur les octets que `sudo` écrit
  réellement ; le compte `requiretty` du périmètre, refusé **sans qu'aucun
  secret ne parte** — deux canaux dépensés, aucune décision de mot de passe
  prise ; le compte Debian ordinaire mené au terme en quatre canaux ; l'audit
  qui essaie d'élever et se voit refuser.
- **Risque résiduel, assumé et nommé** : le refus « mot de passe refusé » se
  reconnaît sur un message de `sudo` qu'une configuration peut renommer. Dans ce
  cas, le refus **subsiste** sous le nom d'invite inattendue et perd seulement sa
  phrase ; il ne s'ouvre pas. Reste explicitement non garanti : qu'un audit
  laissant un canal libre ne serve jamais à rien d'autre — ce qui est établi
  est seulement qu'il ne suffit pas à élever.

**Le nominal est le compte que Debian crée à son installation, tel quel** :
membre du groupe `sudo`, protégé par mot de passe, sans aucune préparation. Le
préflight reste le gardien — une politique `sudo` restrictive exotique reçoit un
refus qui nomme sa cause et le geste qui la lève — mais la politique standard
d'une Debian installée par défaut passe.

Les autres postures restent **servies sans être demandées** : un accès `root`
direct, pour les hébergeurs qui ne donnent que cela, et une entrée `NOPASSWD`
pour qui en possède déjà une. Le produit s'adapte à la machine ; il n'exige pas
qu'on l'affaiblisse pour lui.

**Servir `root` sans le demander n'est pas l'accepter silencieusement.** Quatre
bornes le disent, et aucune n'est nouvelle — elles étaient éparses, elles sont
réunies ici parce que c'est là qu'on vient les chercher :

- chaque usage de l'accès personnel est un **prêt ponctuel consenti** : la clé
  sort de la fenêtre au moment de l'approbation, pour cette séquence ;
- l'Assistant **ne conserve jamais** cet accès. Il s'arrête et oublie ; rien
  n'est rejouable sans la clé et une nouvelle approbation ;
- après l'installation, le produit **n'utilise plus jamais** l'accès personnel :
  il travaille avec les identités de commande dédiées à chaque machine ;
- le produit **ne crée ni ne renforce jamais** un accès `root` : il ne touche
  pas à la configuration SSH, n'ajoute aucune clé, ne désactive aucun mot de
  passe.

> **Intervalle entre ce contrat et le produit.** Ce contrat fixe la cible. Le
> `README` de la `v0.2.0` décrit ce que le produit exige **aujourd'hui** —
> préparer le compte hors du groupe `sudo` avec une entrée `NOPASSWD`. L'écart
> est connu, porté par
> [#158](https://github.com/ldesfontaine/your-cloud/issues/158), et il se ferme
> à la preuve LAB rejouée depuis la page : compte Debian nu jusqu'au Controller
> actif. **La section de préparation du README disparaît dans la pull request
> qui apporte cette preuve** — jamais avant, ce serait promettre ce que le
> produit refuse ; jamais après, ce serait faire taper des commandes devenues
> inutiles.

L'utilisateur peut fournir :

- le compte d'administration ordinaire, non-root, avec clé SSH et élévation
  `sudo` protégée par mot de passe ;
- si l'environnement l'exige, un accès SSH `root`, prêté explicitement pour
  cette opération précise.

L'accès `root` n'est jamais tenté implicitement. L'App nomme les machines,
les actions et la durée avant de le demander. Chaque nouvelle utilisation
exige un nouveau consentement et une nouvelle mise à disposition de l'accès.

Le helper zéroïse ses propres buffers sur chaque sortie contrôlée. Sous Linux,
il meurt avec son parent, désactive les dumps de processus avec
`PR_SET_DUMPABLE=0` et `RLIMIT_CORE=0`, puis emploie `mmap`, `mlock` et
`MADV_DONTDUMP`. La fixture synthétique exige qu'un `gcore` ordinaire conserve
un contrôle du tas mais pas le canari protégé, puis qu'un `abort` durci ne
produise aucun core. Ces sous-cas Linux ont réussi sur des candidats
intermédiaires, puis dans la matrice complète `30770893733` sur `b76ded8`.

Sous Windows, le Job Object ferme désormais la racine et ses descendants selon
le socle prouvé ci-dessus. L'implémentation alloue avec `VirtualAlloc`,
verrouille avec `VirtualLock` et inscrit la zone auprès de Windows Error
Reporting avec `WerRegisterExcludedMemoryBlock`. La fixture WER doit retrouver
un contrôle ordinaire dans un dump `MDMP` personnalisé incluant les régions
`PAGE_READWRITE` et y retrouver aussi le canari protégé. La fixture configure
`DumpType=0` et `CustomDumpFlags=0x321`, soit `DataSegs`, `UnloadedModules`,
`ProcessThreadData` et `PrivateReadWriteMemory`. Elle caractérise ainsi une
collecte administrateur capable de retrouver le contrôle et le canari placé
dans la zone `VirtualAlloc`,
hors de la garantie produit. `WerRegisterExcludedMemoryBlock` reste actif en
défense en profondeur, sans promesse contre `LocalDumps`. Après l'observation,
le test final doit prouver avant verdict la suppression du dump, l'absence de
son répertoire, celle de la clé `LocalDumps` et celle de l'exclusion `AeDebug`
propres à la fixture. `ae550470` ne prouve que le répertoire vide avant verdict
et le retire ensuite par `Drop` : son run `30769440106` a entièrement réussi
ses quatre jobs et constitue une preuve intermédiaire utile, sans pouvoir
fermer #45. `c8643b0` porte `remove_and_prove_absent` ; `30770893733` valide
ensuite sur `b76ded8` le répertoire et les deux inscriptions absents avant
verdict, dans la matrice Linux/Windows complète.

Cette destruction reste une mesure **best effort**, pas une promesse d'absence
universelle de copie. GTK, Win32 et le système peuvent posséder des copies
internes ; `root`, un administrateur local ou distant, `SeDebugPrivilege`, une
IME ou couche d'accessibilité hostile, les dumps noyau et une machine déjà
compromise restent hors de la garantie.

### Justification et alternatives

Ce choix garde une release et un installateur cohérents, mais assume deux
exécutables afin de séparer réellement le secret du processus WebView et de
donner au helper seulement la capacité SSH exacte approuvée. Les deux binaires
ont chacun leur empreinte, leur graphe, leur SBOM et leur vérification de
signature ; sous Windows, le helper doit porter la même identité Authenticode
que l'App. La vérification du verrou de dépendances, des licences, des
imports natifs et du fonctionnement hors ligne appartient à la preuve de chaîne
d'approvisionnement ; ce design ne suffit pas à déclarer une conformité OWASP
ou NIS2.

Un second `WebviewWindow` reste un WebView ; une fenêtre Tauri/Tao brute ne
fournit pas le widget secret et conserve le secret dans le processus App ;
Slint ajoute un second event loop et une surface de dépendances, licence et
paquet disproportionnée ; l'exécutable `ssh` externe laisse varier version,
configuration et commandes ; `libssh2` ajoute une chaîne C/OpenSSL. Ces options
ne sont pas retenues pour `v0.1.0`. Le même exécutable Tauri utilisé comme helper
est également écarté : la preuve ELF montre que WebKit et JavaScriptCore sont
chargés par sa liaison native avant que le code Rust puisse sélectionner un
mode.

Les bindings Rust GTK3 `0.18.2` sont déjà présents dans le graphe Tauri mais ne
constituent plus une base activement développée. Leur épinglage évite un nouveau
graphe implicite sans supprimer ce risque de maintenance : le verrou, les avis
de sécurité, la licence LGPL du composant système et le contenu réel du paquet
restent contrôlés à chaque candidat. Une incompatibilité ou un avis non
maîtrisable impose une autre surface native avant release.

Your Cloud ne supprime ni la clé personnelle de l'utilisateur, ni son compte,
ni son droit d'administration. Cet accès reste le chemin indépendant qui
permettra de remplacer le Controller. La vérification de la clé d'hôte SSH est
explicite : l'empreinte vient d'une source de confiance ou d'une étape
d'observation séparée, affichée et confirmée avant la construction du périmètre.
Le client qui authentifie ne transforme jamais lui-même un premier contact en
confiance et n'accepte aucune clé silencieusement.

## Audit puis proposition

L'utilisateur déclare chaque machine une par une avec un nom, une adresse IP ou
DNS, un port SSH et son caractère privé ou exposé. L'Assistant ne scanne ni le
LAN, ni une plage d'adresses, ni un compte fournisseur.

Avant toute mutation, il effectue un audit SSH en lecture seule et rapporte au
minimum :

- l'identité et la clé d'hôte observées ;
- la distribution et l'architecture ;
- la présence de Debian 13 `amd64`, seule cible serveur prise en charge par
  `v0.1.0` ;
- systemd et cgroup v2 lorsque la machine doit héberger un service OCI géré ;
- les ressources utiles au placement ;
- une installation Your Cloud existante et ses rôles actifs ;
- les incompatibilités et les faits qu'il n'a pas pu vérifier.

L'App propose ensuite :

- un Controller sur une machine privée, de confiance et normalement allumée ;
- un Relay seulement sur une machine explicitement déclarée candidate ;
- un Agent et son Daemon sur chaque machine enrôlée ;
- l'Auxiliaire seulement comme autorité ponctuelle d'une machine placée en mode
  géré.

Pour une petite infrastructure, le Controller peut cohabiter avec d'autres
rôles sur une machine privée si ses processus, comptes, secrets, fichiers et
budgets restent séparés. Une machine ou VM dédiée est recommandée lorsque la
taille ou le risque le justifie. L'App ne propose pas par défaut le
Controller sur le VPS public qui porte le Relay et les services exposés.

Cette cohabitation partage néanmoins le domaine de panne matériel. La perte ou
l'isolement de l'hôte peut interrompre les services placés sur ce même hôte ;
Your Cloud doit l'annoncer avant le placement. La continuité du plan de données
signifie seulement que la perte du Controller n'arrête pas, par elle-même, les
services hébergés sur les autres machines. Une continuité face à la perte de
l'hôte exige donc un placement dédié ou une redondance qui n'appartient pas à
ce palier.

Une recommandation n'est pas une installation. L'utilisateur voit et approuve
le placement, les artefacts, les comptes, les flux et les privilèges exacts
avant la première mutation.

## Ressources et taille de l'infrastructure

Your Cloud ne suppose ni une flotte homogène, ni des machines rapides. L'audit
rend les ressources observées et chaque rôle annonce son coût mesuré. CPU,
mémoire, nombre de processus et espace disque sont bornés par les unités
systemd, cgroup v2 et les quotas réellement disponibles sur la cible. Le réseau
est borné séparément par les listeners, destinations, tailles, concurrences,
délais et limites de débit propres au rôle ; systemd n'est pas présenté comme
une limite réseau générique. Une cohabitation ne doit pas consommer
silencieusement toute la machine. Les délais et files sont bornés, mais une
machine lente n'est pas déclarée en échec uniquement parce qu'elle ne ressemble
pas au LAB ; les bornes retenues sont mesurées sur un profil de petite machine
et rendues visibles.

Aucun logiciel ne peut fonctionner sans minimum matériel. Lorsque les
ressources ne suffisent pas au rôle demandé, l'Assistant refuse ce placement et
explique la ressource manquante au lieu d'installer un ensemble instable. Il
peut encore proposer un rôle plus léger, une cohabitation différente ou une
machine dédiée sans modifier silencieusement les choix de l'utilisateur.

La borne actuelle de 64 machines appartient au format et aux preuves du
Controller de cette version. Elle permet une version `v0.1.0` finie et
vérifiable ; elle n'est pas une limite générale de Your Cloud. Les relèvements
futurs partiront de mesures de l'inventaire, de l'observation et des actions concurrentes avant
d'introduire pagination, partitionnement ou plusieurs Controllers. `v0.1.0` ne
préconçoit pas ces mécanismes, mais ne présente jamais 64 comme un plafond
durable du produit.

## Ce que l'humain approuve, et combien de fois

**Deux consentements, pas trois.**

1. **« Se connecter et examiner la machine »** — lecture seule, rien n'est
   écrit. Cette étape reste séparée parce que c'est le **premier usage de
   l'accès SSH personnel prêté** : consentir à regarder n'est pas consentir à
   agir, et l'humain doit pouvoir s'arrêter là.
2. **« Installer et mettre en service le Controller »** — la pose et le
   démarrage en une seule approbation, dont le détail se déplie.

**C'est le consentement qui fusionne, pas la séquence.** La mécanique interne ne
change pas d'un acte : transfert non privilégié d'abord, vérification du lot,
actes joués un à un, rapport de la machine. Demander deux fois à l'humain de
consentir à ce qu'il a déjà compris comme un seul geste n'ajoute aucune
protection — cela fabrique l'habitude d'approuver sans lire, qui en retire une.

**Une action, une approbation.** La double confirmation est réservée à
l'irréversible : supprimer un service avec ses données, retirer une machine. Le
reste possède un filet mécanique — instantané préalable, fenêtre de retour — et
le doubler serait un rituel, pas une sécurité.

### Les trois questions d'adresses disparaissent

L'amorçage ne demande plus l'adresse d'écoute, la source autorisée en `/32` ni
l'endpoint du Relay. **Le produit les dérive** du plan d'adressage de
l'infrastructure, fixé par le [réseau](RESEAU.md) : le Controller n'écoute que
sur son adresse du réseau d'accès, et les autorisations en découlent.

Il reste donc à l'humain **deux choses à fournir** : un compte pour se
connecter, et l'empreinte de clé d'hôte relevée sur le serveur. La seconde n'est
pas une commodité qu'on pourrait dériver — c'est ce qui distingue la machine
attendue d'un imposteur, et elle doit venir hors bande.

## Création d'une infrastructure

Après approbation, l'Assistant :

1. revérifie les cibles, clés d'hôte et préconditions observées ;
2. installe le lot serveur et le Controller sur la machine privée choisie ;
3. associe l'App à ce Controller par le mécanisme App–Controller ;
4. fait générer sur le Controller une identité SSH différente par cible et
   obtient de l'App la clé publique qui vérifiera les approbations ;
5. vérifie depuis le Controller que chaque endpoint SSH déclaré est joignable
   et présente la clé d'hôte déjà confirmée ; si cette précondition échoue,
   aucune autre machine n'est modifiée ;
6. installe sur chaque cible l'artefact `your-cloud`, le compte technique, la
   clé publique d'approbation, l'état anti-rejeu initial et la clé SSH publique
   propre à la machine ;
7. fait vérifier depuis le Controller le nouvel accès et l'entrée ponctuelle
   de l'Auxiliaire avant d'activer l'Agent, le Daemon et l'éventuel Relay
   approuvés ;
8. détruit tout état temporaire permettant d'utiliser l'accès SSH personnel,
   sans modifier cet accès qui reste sous le contrôle de l'utilisateur, puis
   rend le résultat exact de chaque machine.

Le lot installe donc le binaire avant de rendre sa commande forcée joignable.
Dans ce palier, `your-cloud auxiliary` sait uniquement valider son enveloppe et rendre
un diagnostic de protocole en lecture seule ; toute opération de mutation est
refusée par défaut. Le palier suivant ajoute explicitement la première
opération, la sonde OCI jetable. L'amorçage ne préautorise aucune action future.

La clé Your Cloud d'une machine ne peut ouvrir ni shell, ni PTY, ni SFTP, ni
transfert de port ou d'agent. Son entrée `authorized_keys` lance uniquement
l'Auxiliaire pour un plan typé, ciblé, approuvé et encore valide. Chaque
machine reçoit une paire différente : compromettre une identité ne donne pas
l'identité SSH des autres machines.

Sur une machine gérée, cette clé est liée à un compte technique verrouillé,
distinct des comptes Daemon et Relay et sans authentification par mot de passe.
Le fichier de clés se trouve hors d'un répertoire modifiable par ce compte :
fichier et parents appartiennent à `root` et ne sont inscriptibles ni par le
compte ni par un groupe. L'entrée emploie les restrictions OpenSSH équivalentes
à `restrict`, refuse aussi fichier rc, X11, environnement, shell, PTY, SFTP et
transferts, puis impose le chemin absolu du binaire et de ses parents
root-owned.

Une règle d'élévation possédée par `root`, avec environnement réinitialisé et
sans `SETENV`, autorise seulement l'invocation exacte de `your-cloud auxiliary` sans
argument libre. Le plan typé arrive sur son entrée standard et est revérifié
avant que le processus ponctuel agisse avec les privilèges nécessaires. Aucune
règle `sudo` générale n'est créée.

Les clés privées opérationnelles restent sur le Controller. Leurs sources sont
des fichiers root-owned fournis en lecture au seul service Controller par les
credentials systemd ; elles ne sont copiées ni dans l'App, ni dans le
frontend, ni dans l'Agent. Le service et `root` peuvent nécessairement les lire
à l'exécution : cette protection réduit l'exposition aux autres comptes, mais
ne protège pas contre une compromission complète du Controller.

Concrètement, `root-owned` signifie que `root` possède le fichier source avec
des permissions restrictives, par exemple `0600`. Au démarrage, systemd expose
le credential dans le répertoire privé du service au lieu de placer la clé dans
la ligne de commande ou une variable d'environnement ; cette copie de runtime
disparaît avec le service. La clé opérationnelle n'attend pas une passphrase
humaine, car le Controller doit rester autonome lorsque l'App est fermée.
Sa protection repose donc sur ce stockage borné, le compte du service, les
permissions, la rotation et la sécurité de la machine Controller.

## Approbation indépendante du Controller

Le Controller construit et transporte le plan, mais ne peut pas fabriquer
l'approbation humaine. Après déverrouillage et confirmation native du contenu
affiché, le cœur de l'App signe une enveloppe canonique avec la clé humaine
Ed25519 de son association au Controller. Il n'expose au frontend aucune
opération de signature libre.

L'enveloppe versionnée lie au minimum l'infrastructure, la machine, l'époque
d'autorité, le successeur exact de la séquence propre à cette machine, le
condensat du plan et de son rollback, les privilèges, l'heure d'émission et
l'expiration. L'Assistant installe seulement la clé publique d'approbation,
liée à cette infrastructure et à cette machine, dans un fichier root-owned que
l'Auxiliaire peut lire. La clé privée reste dans le coffre natif de l'App.

Avant la première mutation, l'Auxiliaire vérifie localement la signature, tous
les liens de l'enveloppe et les contraintes de l'opération, puis consomme
atomiquement la séquence dans un état anti-rejeu root-owned. Seul le successeur
exact est accepté ; une séquence sautée, déjà consommée ou plus ancienne est
refusée, y compris après redémarrage. Cet état minimal ne contient ni secret ni
historique général des actions ; il est l'exception nécessaire à l'absence de
journal local de l'Auxiliaire. Une coupure après consommation exige une
observation puis un nouveau plan signé : le plan interrompu n'est jamais
relancé.

Le remplacement crée une nouvelle époque et, si l'association change, une
nouvelle clé publique d'approbation. Activer cette époque sur une machine
invalide l'ancienne au lieu de maintenir deux signataires. Ce contrôle empêche
un Controller compromis de forger seul une nouvelle approbation ; il ne protège
pas une App déverrouillée compromise ni une cible dont `root` est
compromis.

La même règle ferme le cycle d'une App récupérée sur un autre appareil. Une
rotation du seul certificat d'appareil qui conserve la clé humaine ne change
pas les ancres des machines. Si la récupération remplace la clé humaine, elle
rétablit l'API du Controller mais le chemin d'action reste verrouillé.
L'Assistant redemande alors l'accès SSH personnel et remplace, machine par
machine, la clé publique et l'époque d'approbation. Le Controller vivant ne
peut pas effectuer seul cette rotation et le code de récupération ne devient
pas une autorité d'action hors ligne.

## Remplacement explicite d'un Controller

Une indisponibilité ne déclenche jamais un remplacement automatique : une panne
réseau, une machine arrêtée et une perte définitive ne sont pas équivalentes.
L'App informe l'utilisateur, puis celui-ci choisit explicitement
`Remplacer un Controller`.

Avant toute mutation, l'utilisateur qualifie l'incident. Une perte matérielle
confirmée n'est pas une compromission. Si une compromission est soupçonnée,
l'ancien hôte doit d'abord être isolé du réseau et le nouveau Controller doit
vivre sur un hôte sain ou réinstallé depuis une base de confiance. Tant que
l'ancien Controller reste actif ou que son isolement n'est pas vérifiable,
Your Cloud affiche `remplacement non sécurisé` et ne prétend pas avoir restauré
l'autorité.

L'Assistant redemande l'accès SSH personnel et :

1. audite les machines redéclarées et leurs marqueurs gérés, sans scan réseau ;
2. refuse d'écraser silencieusement un Controller encore sain et recoupe
   l'`infrastructure_id` sur les états indépendants disponibles ;
3. installe le nouveau Controller avec un nouveau `controller_id` ; il ne
   conserve l'`infrastructure_id` que si les machines et le Relay concordent ;
4. crée une nouvelle association App–Controller, épingle la nouvelle
   autorité TLS et démarre sans importer aucun appareil, certificat ou session
   de l'ancienne association ;
5. reprovisionne l'identité cliente Controller–Relay, l'adresse source et le
   manifeste du lecteur ; `8444` reste fermé pendant la bascule et n'accepte
   jamais simultanément les deux Controllers ;
6. réutilise les Daemons et le Relay d'ingestion compatibles, dont les
   identités ne dépendaient pas du Controller perdu ;
7. crée une nouvelle époque d'approbation et de nouvelles identités SSH propres
   à chaque machine, installe et vérifie les nouveaux accès, puis retire
   seulement les anciennes clés et ancres Your Cloud identifiées par empreinte
   et marqueur géré ;
8. vérifie qu'aucun secret, certificat, session, filtre réseau ou manifeste que
   l'ancien Controller pouvait utiliser ne lui donne encore d'autorité ;
9. archive l'ancienne association dans l'App ; si l'ancien Controller est
   encore sain et joignable, révoque explicitement son appareil et ses sessions
   avant son arrêt, puis laisse intacts les comptes, clés et accès personnels
   de l'utilisateur.

Les autorités TLS serveur et d'émission des appareils du nouveau Controller
sont nouvelles ; ses certificats d'appareil et sessions ne sont jamais copiés
depuis l'ancien. La clé privée cliente du lecteur Relay et les clés SSH
opérationnelles sont tournées parce que l'ancien Controller pouvait les lire.
Les autorités privées qui n'ont jamais résidé sur l'ancien hôte ne sont pas
renouvelées sans motif, mais chaque feuille ou manifeste qui autorisait
l'ancien `controller_id` est révoqué ou remplacé.

Le remplacement n'est pas atomique à l'échelle de plusieurs machines. Pour
chaque cible, l'Assistant rend l'un des états `ancien seul`, `chevauchement
borné`, `nouveau seul` ou `inconnu`. Une coupure peut donc laisser une flotte
partielle, mais jamais un succès inventé : au prochain lancement, l'utilisateur
reprête son accès personnel et l'Assistant reconstruit l'état depuis les
empreintes root-owned et des tests directs avant de proposer une nouvelle
étape. Il ne retire rien dans un état inconnu et ne conserve pour cette reprise
aucun secret personnel.

La création suit la même règle. Avant l'enrôlement d'une cible, un échec peut
retirer seulement les éléments nouvellement installés dont l'absence est
prouvée sans danger. Après un premier transfert d'autorité, tout arrêt rend un
état partiel machine par machine ; aucun rollback global aveugle n'est tenté.
Le succès final exige le nouveau Controller joignable, l'App associée, le
lecteur Relay limité au nouveau Controller, chaque cible en `nouveau seul` et,
en cas d'incident hostile, l'ancien hôte isolé.

Si l'inventaire de l'ancien Controller est perdu, l'utilisateur redéclare les
endpoints. Un futur plan de sauvegarde pourra réduire ce travail, mais
l'amorçage ne dépend pas d'une nouvelle autorité de récupération. Le code de
récupération de l'App conserve un autre sens : il associe une nouvelle
App à un Controller encore vivant ; il ne restaure ni l'inventaire, ni les
identités SSH, ni un Controller détruit. Lorsqu'il remplace la clé humaine, les
actions restent verrouillées jusqu'à la rotation personnelle décrite plus haut.

Le remplacement restaure l'autorité de gestion, pas les données applicatives.
Sauvegarder et restaurer Vaultwarden, un drive ou des photos appartient au
cycle de sauvegarde des services et reste obligatoire indépendamment de la
santé du Controller.

## Distribution bornée

**Pourquoi l'installateur porte les Agents plutôt que d'aller les chercher.** La
question a été posée et tranchée : le lot reste embarqué. Trois raisons, dans
l'ordre où elles pèsent.

**La racine de confiance, au moment où elle compte.** L'Assistant tient l'accès
personnel et s'apprête à élever ses privilèges : c'est l'instant du parcours où
il possède le plus d'autorité. Aller chercher un binaire à ce moment-là
déplacerait la racine de confiance vers un compte d'hébergement à l'instant T —
la classe d'attaque que ce contrat exclut, et qu'aucune vérification postérieure
ne rattrape, puisque c'est la source elle-même qui serait choisie par un tiers.
Un lot embarqué est jugé contre une ancre scellée dans le binaire que l'humain a
lui-même installé.

**Un seul produit, une seule révision.** La version de l'installateur est celle
des Agents qu'il pose (`#55`). Une cadence de publication séparée pour les
daemons créerait des combinaisons de versions que rien ne prouve, et un parc
dont on ne saurait plus dire ce qu'il porte.

**Le chemin est celui que les preuves parcourent.** `#13` et `#41` ont exercé
l'amorçage sur des machines réelles ; un téléchargement en ferait un chemin
différent de celui qui a été prouvé.

Conséquence directe sur ce que le projet publie : **aucun artefact de daemon
séparé, et aucune signature de binaire serveur par une porte d'intégration
continue.** L'intégration continue atteste une révision ; elle ne signe pas. Le
paquet de l'App est la distribution.

L'installateur de l'App pour `v0.1.0` contient l'Assistant et un unique
paquet serveur `.deb` pour Debian 13 `amd64`. Ce paquet livre le binaire Go `your-cloud` et ses
définitions d'installation statiques. Il ne porte ni configuration propre à une
machine, ni secret, ni identité, ni activation de rôle, ni transfert d'autorité :
ces effets restent des opérations typées de l'Assistant après approbation. Les
éventuels scripts mainteneur du paquet restent minimaux, non interactifs et
idempotents ; ils ne téléchargent rien, ne génèrent aucun secret, n'activent
aucun rôle et ne suppriment aucun état persistant.

L'ensemble possédé par le paquet est fermé : le répertoire
`/usr/lib/your-cloud` et le binaire `/usr/lib/your-cloud/your-cloud` sont
`root:root` en `0755`, sans bit setuid, setgid ni capacité de fichier ; les
seules unités livrées sont `your-cloud-controller.service`,
`your-cloud-daemon.service` et `your-cloud-relay.service` sous
`/usr/lib/systemd/system`, `root:root` en `0644`. Leur installation ne les
active ni ne les démarre. Les chemins historiques `/usr/local/lib/your-cloud`
et `/etc/systemd/system` des preuves antérieures restent des faits de ces
paliers, pas les chemins du paquet de `v0.1.0`.

Le manifeste signé du lot App relie la version, la cible, la taille et le
SHA-256 exact du `.deb`. L'Assistant vérifie cette signature et ces valeurs avant
toute opération privilégiée : un paquet `.deb` isolé n'est pas traité comme une
preuve d'authenticité.

L'Assistant **trouve** le lot comme il atteste son parent : par sa propre
position. Le chemin des trois fichiers embarqués est dérivé de
`/proc/self/exe` — le binaire installé sous `/usr/bin` remonte à son préfixe et
descend vers l'arborescence que le paquet de l'App livre — jamais d'un
argument, d'une variable d'environnement ni d'un chemin qu'un parent aurait
choisi. Un binaire recopié hors de sa position installée ne résout rien et
refuse par son nom ; c'est le refus d'être enrobé, prolongé au lot. La
dérivation ne crée aucune confiance : quel que soit le chemin résolu, l'ancre
scellée reste l'autorité finale sur ce qui est trouvé. Ses dépendances forment un ensemble hors ligne fermé :
elles appartiennent au socle Debian 13 exigé ou sont embarquées et authentifiées
dans le lot, sans résolution réseau pendant l'amorçage. `dpkg` inventorie les
fichiers immuables, leurs propriétaires et leurs permissions ; chaque fichier
généré par l'Assistant reste inventorié et géré séparément par celui-ci.

Avant un changement, l'Assistant distingue l'absence du paquet, une version
antérieure exacte et un état ambigu. Il conserve le `.deb` précédent et l'état
géré nécessaire au retour, installe le candidat, puis vérifie fichiers, unités
et processus avant d'activer les rôles approuvés ou de transférer l'autorité. Un
échec contrôlé avant ce transfert restaure la version antérieure ou l'absence
initiale. Un paquet à demi configuré, une coupure ou un état inconnu restent
visibles et interdisent tout retrait ou rejeu aveugle. Après transfert, les
règles d'état partiel machine par machine s'appliquent. Retirer le paquet
n'efface jamais implicitement configurations, secrets ou identités : leur
retrait appartient à une opération explicite qui connaît l'autorité active.

Le paquet Debian est retenu plutôt qu'une archive signée parce que la cible
`v0.1.0` est exclusivement Debian et que réimplémenter extraction privilégiée,
inventaire, permissions, mise à niveau et retrait élargirait inutilement la
surface root de l'Assistant. Ce choix applique moindre privilège, séparation des
responsabilités et défense en profondeur, et contribue aux mesures de chaîne
d'approvisionnement et de continuité attendues par le projet. Il ne garantit ni
l'authenticité du lot sans le manifeste signé, ni un rollback transactionnel de
toute l'infrastructure, ni une conformité OWASP ou NIS2 à lui seul.

Cette enveloppe rend le parcours initial et le remplacement reproductibles avec
le même lot. La mise à jour reste manuelle dans `v0.1.0`. Une architecture ou
distribution supplémentaire n'est annoncée comme prise en charge qu'après une
preuve LAB dédiée ; `arm64` reste le premier incrément de portabilité envisagé
après stabilisation.

La signature synthétique Windows prouve seulement le mécanisme de build et
d'installation. La distribution Windows publique reste bloquée tant qu'une
identité de signature reconnue et gratuite n'est pas réellement opérationnelle ;
le projet ne transforme pas un certificat de test en promesse publique.

## Limites de `v0.1.0`

La première version ne fournit :

- ni bascule ou réplication automatique du Controller ;
- ni troisième autorité SSH ou autorité de secours hors ligne ;
- ni inventaire retrouvé par scan réseau ;
- ni conservation de la clé SSH personnelle par l'App ;
- ni reprise autonome d'une action interrompue ;
- ni transaction atomique de remplacement sur toute la flotte ;
- ni shell d'administration général par l'Auxiliaire ;
- ni Ansible obligatoire dans le Controller ou sur les machines.

Une coupure pendant une action produit `résultat inconnu`. Le Controller
n'effectue aucun rejeu aveugle : après reconnexion, il observe l'état réel puis
propose seulement une réparation ou un retrait compatible avec cet état.

## Preuves acquises et encore attendues

Le rapport Windows établit le socle #43 décrit plus haut : paquetage des deux
exécutables, lancement suspendu avec héritage exact, Job vérifié avant reprise,
arrêt borné de l'arbre, refus après nettoyage incertain et IPC WebView/Tauri
hostile. Il ne transforme ni un état natif terminal en succès métier, ni une
signature synthétique en distribution publique.

Le palier d'amorçage global ne sera prouvé qu'après avoir aussi montré dans le
LAB :

- audit sans mutation et absence de scan ;
- refus d'une clé d'hôte non confirmée, d'une cible incompatible et d'un rôle
  non approuvé ;
- chaîne de production complète du helper distinct dont le graphe, le
  `DT_NEEDED`, les dépendances transitives et les mappings vivants excluent
  Tauri, Wry, Tao, WebKit et JavaScriptCore sur chaque cible publiée, avec un
  processus par consentement et aucun descendant après annulation, timeout,
  EOF, mort du parent ou crash ;
- absence de clé ou mot de passe personnel dans le frontend, le Controller,
  l'IPC, les arguments, l'environnement, les descripteurs inattendus, les
  fichiers persistants ou temporaires, les journaux et les artefacts ;
- dialogues GTK3 et Win32 réellement hors WebView, avec refus d'une cible,
  d'une action ou d'une expiration différente de ce qui a été confirmé ; leur
  implémentation et leur matrice Linux/Windows appartiennent à la preuve #45 ;
- clé d'hôte exacte, algorithmes obsolètes, autre endpoint d'agent, seconde
  signature et message hors authentification refusés par le client SSH borné ;
- acceptation du seul format de clé chiffrée décidé et refus des clés en clair,
  formats implicites, RSA trop courte et fichiers hostiles ;
- `sudo -n` nominal, unique envoi sans PTY si nécessaire, puis refus d'une
  relance, d'un prompt, d'une commande ou d'une politique de journalisation
  hors contrat ;
- zéroïsation contrôlée, protections anti-dump disponibles et limites publiées
  après sortie, crash et dump synthétiques ; sous Windows, `LocalDumps`
  administrateur reste hors garantie, contrôle et canari doivent être présents,
  puis dump, répertoire et deux inscriptions de registre doivent être absents
  et vérifiés avant verdict ;
  les sous-cas Linux intermédiaires ne remplacent pas le rejeu final ;
- dépendances, licences, verrou, SBOM, imports PE et chargement éventuel de
  WebKit audités pour les deux paquets natifs et leur fonctionnement hors ligne ;
- installation du Controller, fermeture de l'Assistant puis fonctionnement
  lorsque l'App et le laptop sont arrêtés ;
- refus avant mutation lorsqu'une cible n'est pas joignable en SSH depuis le
  Controller choisi ;
- artefact installé avant la commande forcée, entrée Auxiliaire de bootstrap en
  lecture seule et refus de toute mutation encore inconnue ;
- une identité SSH différente par machine et l'impossibilité d'ouvrir un shell,
  un PTY, SFTP ou un transfert ;
- répertoire de clés, chemin du binaire, environnement et élévation
  non modifiables par le compte technique ;
- refus de la clé d'une machine sur une autre ;
- plan signé par le cœur natif, Controller incapable de le modifier ou d'en
  forger un nouveau, puis refus du rejeu avant et après redémarrage ;
- récupération d'une App avec nouvelle clé humaine laissant les actions
  verrouillées jusqu'à rotation des ancres par l'accès personnel ;
- maintien de l'accès personnel après création et remplacement ;
- remplacement explicite du Controller, nouvelle association App,
  nouvelle identité lecteur Relay, rotation de toutes les autorités exposées,
  vérification des nouvelles clés puis retrait des seules anciennes identités
  Your Cloud ;
- isolement obligatoire d'un Controller soupçonné compromis et refus d'un
  succès sécurisé tant qu'il peut encore agir ;
- injection d'une coupure à chaque étape de création et de remplacement,
  reconstruction des états partiels et absence de retrait aveugle ;
- réutilisation d'un Agent compatible et refus d'un état altéré ou ambigu ;
- budgets respectés sur une petite machine, cohabitation isolée et comportement
  mesuré avec 1, 2 puis 64 machines ;
- aucune interruption due à la seule perte de l'App ou du processus
  Controller pour les services hébergés sur d'autres machines ; un service
  colocalisé est annoncé comme interruptible si l'hôte est perdu ou isolé.

Ces preuves emploient uniquement des identités et secrets synthétiques. Elles
ne rendent pas le Controller invulnérable et ne remplacent pas les sauvegardes
des services.

<!-- coherence: BOOTSTRAP-RECOVERY:end -->

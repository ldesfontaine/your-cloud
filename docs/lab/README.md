# LAB de développement

`labctl` est le contrôleur borné des VM KVM/libvirt utilisées pour le
développement et les preuves. Il appartient à l'outillage de développement,
pas au produit.

## Règle de placement

Le laptop sert uniquement à éditer, inspecter Git et contrôler le LAB. Aucun
composant, test, build, serveur, playbook ou import exécutable du projet n'y est
lancé. Le code produit s'exécute dans une VM LAB ou un runner distant isolé.

## Capacités du contrôleur

[`tools/labctl`](../../tools/labctl) fournit notamment :

- une image Debian 13 datée et vérifiée par SHA512 ;
- la création et l'inspection de VM libvirt sans `sudo` ;
- des métadonnées d'origine et de gabarit contrôlées avant mutation ;
- des réseaux LAB séparés ;
- les snapshots et retours à un état propre ;
- des commandes SSH et de copie qui utilisent une identité synthétique dédiée.

Les noms de gabarits et de topologies tels que `console`, `coordinateur`,
`quick` ou `v1-full` décrivent uniquement l'outillage LAB. Ils ne constituent
ni l'architecture du produit ni une preuve fonctionnelle. Toute évolution de
ces profils suit le besoin du scénario concerné sans réutiliser implicitement
un ancien rôle.

## Garde obligatoire

Avant toute mutation de VM :

1. exécuter `tools/labctl list` pour une lecture humaine ou
   `tools/labctl list --format=tsv` pour une garde automatisée ;
2. confirmer l'origine et le gabarit de chaque cible ;
3. vérifier que son adresse diffère de `192.168.122.123` et `10.66.66.1` ;
4. arrêter immédiatement au moindre doute, en traitant la cible comme une
   production possible.

Une cible réelle ou une production exige une autorisation explicite qui nomme
la machine et le geste. Cette autorisation ne se déduit jamais d'un accès
technique existant.

`labctl` applique également ces gardes aux commandes mutantes. Cela ne remplace
pas le contrôle humain préalable.

## Fermeture obligatoire

Une VM arrêtée reste définie avec ses volumes et snapshots ; un réseau libvirt
persistant peut également rester actif sans VM connectée. La fin d'une tâche
LAB exige donc l'un des deux états explicites suivants :

1. chaque topologie devenue inutile est retirée avec
   `tools/labctl topology destroy <topologie>`, puis
   `tools/labctl assert-clean` réussit ;
2. une topologie est volontairement conservée pour une reprise identifiée :
   le compte rendu nomme la topologie, la raison, la prochaine tâche responsable
   et le résultat rouge attendu de `tools/labctl assert-clean`.

Une simple série de `stop` ne constitue pas une fermeture. La commande
`assert-clean` ne modifie rien : elle refuse les VM et réseaux portant
l'origine `your-cloud/labctl`, ainsi que les noms `lab-*` suspects. Elle échoue
également si l'inventaire libvirt est inaccessible, afin qu'une erreur de
contrôle ne puisse jamais être confondue avec un LAB vide.

Le contenu de `keys.txt` et de `/srv/infra/secrets/` ne doit jamais être lu,
affiché ou copié. Seuls des secrets synthétiques générés pour le scénario
entrent dans le LAB.

Un playbook réel reçoit d'abord un `--syntax-check`, puis un second passage doit
produire `changed=0`, entièrement dans le LAB. Une preuve non exécutée reste
annoncée comme telle.

## Commandes disponibles

```text
tools/labctl list [--format=tsv]
tools/labctl topology create <quick|v1-full>
tools/labctl topology inspect <quick|v1-full>
tools/labctl topology prepare v1-full
tools/labctl topology destroy <quick|v1-full>
tools/labctl revert <vm> [snapshot]
tools/labctl assert-clean
tools/labctl start <vm>
tools/labctl stop <vm>
tools/labctl ssh <vm> [commande...]
tools/labctl copy-to <vm> <source> <destination>
tools/labctl copy-from <vm> <source> <destination>
```

La sortie TSV possède les colonnes fixes `vm`, `state`, `ips`, `template`,
`topology` et `origin`. Plusieurs adresses sont séparées par une virgule ; une
VM arrêtée sans adresse rend `-`. Une erreur d'inspection d'une VM active reste
bloquante.

## Provisionnement des machines

`labctl topology create` rend des machines Debian **nues**. Les chaînes d'outils
que les preuves compilent sont posées par
[`tools/provision-lab`](../../tools/provision-lab) :

```text
tools/labctl topology create quick
tools/provision-lab [lab-console | lab-machine-1 | lab-vps | all]
```

`lab-console` reçoit le swap, les dépendances de construction GTK et la chaîne
Rust ; `lab-machine-1` et `lab-vps` reçoivent la chaîne Go et le sol de
conteneurs sans privilèges. `lab-vps` reçoit en plus **`slirp4netns`**, que la
fiche du point d'entrée nomme à la main : sans lui l'entrée ne démarre pas, et
elle ne se rabat pas sur `pasta`. Chaque étape est idempotente : ce qui est déjà
en place est laissé tel quel et nommé comme tel.

Les deux machines du passage privé reçoivent enfin un **sol du passage**, et ce
qu'il contient vaut d'être séparé en trois, parce que ce ne sont pas les mêmes
affirmations :

- le **noyau** n'installe rien. WireGuard est dans l'arbre de Debian 13 ; le
  provisionnement vérifie seulement que le module est là, parce qu'une machine
  dont le noyau n'en a pas décrit une interface qui n'apparaît jamais, et une
  preuve lirait cela comme un échec du produit ;
- le **produit** n'ajoute rien non plus sur une machine d'origine : `nftables`
  et `procps` portent `/usr/sbin/nft` et `/usr/sbin/sysctl`, que l'unité écrite
  par une jonction nomme par leur chemin absolu, et l'image cloud les livre
  déjà. Les deux chemins sont donc **vérifiés** plutôt que supposés — un chemin
  absolu qu'une unité nomme est une promesse sur la machine, pas sur un paquet.
  Le groupe `systemd-network` est vérifié pour la même raison : c'est de lui que
  dépend toute l'arithmétique du mode `0640` de la clé ;
- le seul paquet réellement ajouté est **`wireguard-tools`**, et il l'est pour
  la *preuve* et non pour le produit. Les clés sont générées par le produit avec
  le X25519 de la bibliothèque standard et jamais en appelant `wg` ; ce qui a
  besoin de `wg` est le harnais, qui relit du noyau le pair, ses `AllowedIPs` et
  la dernière poignée de main plutôt que le fichier que le produit a écrit.

La topologie `quick` compte donc trois machines, et elles ne sont pas
interchangeables. `lab-console` porte la Console ; `lab-machine-1` tient le rôle
du mini-PC domestique ; `lab-vps` tient celui du VPS public — c'est la seule
machine qui écoute publiquement, et les preuves du profil public la lisent
**depuis l'extérieur**, depuis le poste ou depuis une autre VM. Elle rejoint le
réseau `lab-quick` plutôt que de recevoir un réseau public à elle : `lab-public`
existe dans `v1-full` pour séparer un segment public d'un segment opérateur et
d'un site privé, séparation que `quick` n'a pas à faire, et un second réseau NAT
y serait joignable exactement depuis les mêmes endroits que le premier.

**Les versions ne sont pas écrites dans cette recette.** Elles sont lues dans le
workflow de la porte hébergée, si bien qu'une machine du LAB et un runner
hébergé ne peuvent pas diverger. Une recette qui recopierait les numéros
créerait un second endroit à mettre à jour, et celui qu'on oublie est toujours
celui que personne ne lance. Une version illisible est un arrêt franc :
deviner reviendrait à provisionner un LAB qui prouve quelque chose d'un
compilateur que la porte n'exécute jamais.

Deux points que le provisionnement ne règle pas seul :

- le swapfile est **délibérément absent de `/etc/fstab`**. Sans lui la
  compilation du crate de la Console est tuée par l'OOM sur cette machine, et
  [`tests/lab/v0.1.0/prove`](../../tests/lab/v0.1.0/prove) le remonte après
  chaque démarrage — ce chemin reste ainsi éprouvé plutôt que de devenir du code
  mort ;
- `gdb` n'est pas facultatif : la suite `secret-crash-contract` lance `gcore`.

Une fermeture par `topology destroy` emporte tout ce provisionnement ; seul
`labctl stop` le conserve. Rejouer `provision-lab` est donc le prix d'une
fermeture, et c'est précisément pour que ce prix soit une commande et non une
procédure de mémoire que ce fichier existe.

Pour `v0.0.1`,
[`tests/lab/v0.0.1/prove`](../../tests/lab/v0.0.1/prove) est l'entrée
d'orchestration. Le poste de développement ne fait qu'empaqueter le lot non
sensible, calculer ses empreintes et appeler `labctl`.
[`tests/checks/source-v0.0.1`](../../tests/checks/source-v0.0.1) s'exécute en
mode `lab` dans `lab-console` ou en mode `ci` dans un runner CI distant isolé ;
aucun de ces contrôles ni aucun build ne s'exécute sur le laptop. HTTP et
systemd restent propres à la preuve dans les VM LAB. Une erreur après mutation
sélectionne et vérifie l'état absent ; un succès réinstalle l'état final
documenté.

Pour `v0.1.0`,
[`tests/lab/v0.1.0/personal-access/prove`](../../tests/lab/v0.1.0/personal-access/prove)
est l'entrée d'orchestration du périmètre de l'accès personnel. Elle applique la
même garde d'inventaire, monte les deux côtés du périmètre sur `lab-console` et
`lab-machine-1`, exécute la suite `personal-access-contract`, puis démonte et
prouve l'absence de ce qu'elle a créé, même lorsque la suite échoue. Les
comptes, clés et agents sont synthétiques et générés au montage ; les deux VM
restent démarrées et aucune topologie n'est créée ni détruite.

Pour le palier du profil public (`#15`),
[`tests/lab/v0.1.0/public-profile/prove`](../../tests/lab/v0.1.0/public-profile/prove)
est l'entrée d'orchestration. Elle monte son périmètre sur `lab-vps`, applique
les plans approuvés un à un, et lit depuis le poste — c'est-à-dire depuis
l'extérieur de la machine publiée — ce que chaque plan est censé avoir rendu
vrai. Elle ne crée ni ne détruit aucune topologie, ne parle jamais à
`lab-machine-1`, et retire ce qu'elle a monté même quand une étape échoue.

Pour le palier du passage privé (`#16`),
[`tests/lab/v0.1.0/private-passage/prove`](../../tests/lab/v0.1.0/private-passage/prove)
est l'entrée d'orchestration. C'est la première preuve LAB qui **monte un
périmètre sur deux machines à la fois** : `lab-machine-1` tient le rôle
`initiator` — la machine du LAN, qui porte le service borné et ne gagne aucun
port entrant — et `lab-vps` le rôle `listener`. Elle applique les quatre plans
dans l'ordre du contrat, porte la clé publique rapportée par la préparation de
chaque machine dans le plan de jonction de l'autre, redémarre réellement les
deux machines, puis démonte tout même quand une étape échoue. `lab-console` n'y
reçoit rien du produit : elle sert d'**observateur hostile**, à qui la preuve
donne à la main les routes qu'un attaquant se donnerait, et qui les rend. Le
poste, lui, scanne les deux machines avant et après pour que « aucun port
entrant de plus » soit une comparaison et non une affirmation. Aucune topologie
n'est créée ni détruite.

Deux limites d'honnêteté sont portées par le rapport de cette preuve plutôt que
par une note de bas de page : la topologie `quick` est **plate**, donc l'hôte
hostile atteint déjà l'adresse propre de `lab-machine-1` avant que le passage
existe — ce que la preuve constate est qu'il n'en atteint **pas un port de
plus** ; et un poste pilote peut lui-même porter une adresse de `10.66.66.0/24`
pour des raisons étrangères au LAB, auquel cas il le dit et laisse
`lab-console` faire l'observation à sa place.

Pour le palier du profil privé (`#17`),
[`tests/lab/v0.1.0/private-service/prove`](../../tests/lab/v0.1.0/private-service/prove)
est l'entrée d'orchestration, et c'est la première preuve qui joue le **scénario
de référence entier d'un seul tenant** : `lab-machine-1` tient le service à
données, son volume, ses archives et son confinement de sortie ; `lab-vps` tient
le point d'entrée, le profil sans état du palier précédent, les deux noms
déclarés et l'écouteur du passage ; `lab-console` sert à la fois d'observateur
hostile et de **voisin synthétique du LAN** — un vrai serveur HTTP que la preuve
démarre et arrête, sans quoi « le service confiné ne joint aucun voisin » ne se
distinguerait pas d'une adresse morte. Le poste pilote épingle l'autorité
synthétique de la course et lit de l'extérieur ce que le palier revendique :
`vault.` et `pdf.` répondent 200 sur **la même IP publique et le même 443**, le
coffre sans en-tête d'isolation et le PDF avec les deux. Les deux machines sont
réellement redémarrées, aucune topologie n'est créée ni détruite, et tout est
retiré même quand une étape échoue.

Quatre actes du harnais sortent d'un plan approuvé et se nomment eux-mêmes :
poser les certificats qu'aucun plan ne décrit ; **planter les secrets
synthétiques** — la fiche du profil ferme les inscriptions, donc ce palier n'a
aucun chemin d'API vers une ligne de coffre, et ce qui est suivi de bout en bout
est l'octet exact du répertoire durable, base de données du service comprise ;
produire deux conditions d'hôte réelles pendant la panne du passage et les
reprendre ; et détruire, à la fin, les données que le produit a délibérément
conservées. Le rapport de la preuve porte ces limites plutôt qu'une note de bas
de page, avec deux autres : le refus d'une route *publique* visant le port d'un
service privé est prouvé par la suite unitaire et non par la machine — il ne
s'atteint que sur une machine tenant à la fois une entrée et le coffre, et la
topologie ne donne pas à `lab-machine-1` la pile réseau que la fiche de l'entrée
nomme —, et `retire_route` du genre public peut encore éteindre un fragment du
genre lien, ce que le contrat n'interdit pas et que cette preuve n'exerce pas.

Pour le palier de la responsabilité externe (`#18`),
[`tests/lab/v0.1.0/external-element/prove`](../../tests/lab/v0.1.0/external-element/prove)
est l'entrée d'orchestration, et c'est la première preuve LAB qui **monte la
chaîne d'observation entière** plutôt que de la remplacer par une fiction :
`lab-machine-1` tient le Daemon et le Relay, `lab-vps` tient le Controller — un
vrai `controller init`, un vrai inventaire déclaré, ses propres identifiants et
ses propres dates —, et `lab-console` tient le client qui parle à sa surface.
Chaque état, chaque date et chaque mot d'ancienneté que le rapport cite sort de
ce Controller-là.

Le scénario est celui que le contrat annonce, en onze étapes : un service que
Your Cloud n'a jamais installé est **posé à la main** sur un port de loopback,
déclaré externe — sans que rien ne s'installe et sans qu'aucune lecture n'existe
encore —, puis la fiche root-owned `/etc/your-cloud/external-targets.json` est
provisionnée et la chaîne le rend `vérifié` avec sa date. Le service est arrêté
à la main et la lecture suivante rend `contredit` ; le Daemon est arrêté et le
constat **vieillit** au-delà des 90 secondes annoncées sans que son état bouge ;
un voisin que personne ne déclare n'apparaît nulle part et n'est nommé dans
aucune enveloppe ; un port qu'un service **géré** publie est rendu
`invérifiable` pour le motif `port_is_managed` sans qu'aucune connexion ne lui
soit adressée ; un libellé hostile reste inerte et les libellés hors bornes sont
refusés ; aucun plan n'est constructible et `/v0/external-elements/{id}`
n'existe sous aucune méthode ; enfin la déclaration est retirée par `POST` sur
sa propre route et **le service continue de tourner**, que le harnais retire
ensuite comme son propre acte.

Cinq actes du harnais sortent de ce que le produit décide et se nomment
eux-mêmes : poser puis retirer les deux écouteurs qu'aucun plan ne décrit ;
provisionner la fiche de cibles à la place de root ; emprunter le fixture de
[`oci-plan`](../../tests/lab/v0.1.0/oci-plan/) pour placer le service géré de la
collision ; poser un compteur `nftables` purement observateur, parce que
« rien ne s'est connecté à ce port » doit être un nombre et non une absence de
preuve ; et **placer deux adresses**, `192.168.243.153` et `192.168.242.103`,
que le Relay et son lecteur exigent et que la topologie `quick` ne porte pas.
Cette dernière est une contrainte du produit lue par le LAB, jamais un
comportement du produit modifié pour lui plaire. Le rapport porte aussi la dette
que `#108` a nommée : **la Console n'est pas exercée par ce harnais** — elle lit
l'inventaire et retire une déclaration, elle n'a pas de formulaire de
déclaration, et c'est sa propre suite Rust et TypeScript qui la prouve.

### La course complète : `tests/lab/v0.1.0/prove complete`

Le palier `#19` demande que toutes ces preuves tiennent **ensemble, dans
l'ordre, sur des machines qui ne gardaient rien**. C'est ce que fait le mode
`complete` de [`tests/lab/v0.1.0/prove`](../../tests/lab/v0.1.0/prove), et c'est
un **mode de cet orchestrateur** plutôt qu'un second orchestrateur : le contrat
demande un ordre et un rapport, pas deux fichiers qui pourraient diverger.

```text
tests/lab/v0.1.0/prove complete
```

Les modes existants ne changent pas. `guard`, `run`, `close` et `all` gardent
exactement leur comportement, et chaque preuve de palier reste lançable seule
par sa propre entrée — c'est la condition pour qu'une preuve de palier continue
de prouver son palier.

Ce que `complete` ajoute tient en cinq choses.

**Une base réellement propre.** `Propre` n'est pas « les harnais ont nettoyé
derrière eux ». Ce sont les trois commandes du contrat, jouées une fois, avant
la première passe :

```text
tools/labctl topology destroy quick     la topologie cesse d'exister
tools/labctl topology create quick      les machines renaissent de l'image de base
tools/provision-lab all                 le sol est reposé par la recette
```

La destruction n'est pas conditionnée à une topologie que l'inventaire
montrerait : elle est exactement l'inventaire que cette étape existe pour ne pas
croire. Le coût est de vingt à trente minutes, la chaîne Rust de `lab-console`
en tenant l'essentiel.

**Onze passes, chacune rejouée telle quelle.** Les six passes du palier `#13`,
puis les cinq harnais de palier dans l'ordre du produit : `oci-plan` (`#14`),
`public-profile` (`#15`), `private-passage` (`#16`), `private-service` (`#17`),
`external-element` (`#18`). Chacun est appelé par sa propre entrée avec son
propre `all`, donc fait son propre montage, ses propres redémarrages et son
propre démontage, dans son propre ordre. Rien n'est réordonné ni modifié : un
harnais retouché pour l'occasion prouverait autre chose que ce que son palier a
fermé. Un harnais qui échoue **arrête la séquence**.

Chaque passe porte une borne d'horloge murale — un plafond, jamais une attente.
Elles sont généreuses parce que ces harnais compilent du Rust et du Go sur les
machines et les redémarrent vraiment ; elles existent pour qu'une passe bloquée
finisse en échec nommé plutôt qu'en nuit sans surveillance. Une passe tuée sur
sa borne est forcée à travers son propre `remove` avant la suivante.

**Les artefacts, et deux commandes plutôt que deux intentions.**
[`tools/release-artifacts`](../../tools/release-artifacts) écrit les quatre
fichiers déterministes de la liste close ; la course lance ensuite
`check-determinism`, qui produit deux fois et compare octet pour octet, puis
`sha256sum -c checksums.txt` dans le répertoire, c'est-à-dire la vérification
d'un tiers. L'étape ne s'exécute **que si toutes les passes sont vertes** : des
artefacts de release taillés à côté d'un rouge se liraient comme un candidat que
nulle course ne soutient.

**Un rapport unique, scellé par sa propre course.** `report.txt` est le
cinquième artefact. Le manifeste le **nomme sans l'empreindre** — les quatre
autres parlent d'une révision, lui parle d'une course — et il est scellé par un
`proof-checksum.txt` écrit à côté de lui, au format exact de `checksums.txt`,
couvrant le seul rapport (décision `#111`). Deux portées, deux fichiers :

```text
sha256sum -c checksums.txt        les quatre fichiers sont ceux de cette révision
sha256sum -c proof-checksum.txt   le rapport lu est celui que cette course a produit
```

Le rapport nomme la topologie **scénario LAB de référence** et jamais
infrastructure imposée, porte nommément les six limites déjà connues du contrat,
et pointe le rapport propre à chaque harnais plutôt que de le résumer : un
résumé de résumé est l'endroit où une limite disparaît.

**Une fermeture qui est verte pour la bonne raison.** `labctl assert-clean`
refuse toute VM d'origine `your-cloud/labctl` et tout nom `lab-*` suspect : il
est donc **rouge tant que la topologie existe**, quoi que les harnais aient
nettoyé, puisque ce sont les machines elles-mêmes qu'il nomme. « `assert-clean`
vert à la fin » exige par conséquent que la topologie soit détruite en dernier
acte, et `complete` la détruit. Aucune exception n'est ajoutée à la main.

Deux ordonnancements sont des décisions et le rapport les porte : les artefacts
ne sont produits qu'après une séquence entièrement verte, et le rapport est
**écrit après la fermeture** — `assert-clean` est le dernier constat de la
course sur des machines, et un rapport taisant sa propre fermeture serait un
rapport troué. Son sceau est donc pris une fois, sur un document entier, et
jamais rouvert.

Deux risques d'une course de plusieurs heures sont traités plutôt que subis :
une horloge qui **bouge** en cours de route — plusieurs harnais refusent
d'émettre une approbation contre une horloge en train d'être recalée, et
l'orchestrateur classe ce rouge `clock_step_during_run` plutôt que de le laisser
porter la classe d'un défaut produit —, et un arbre de travail modifié, que le
rapport annonce comme une limite supplémentaire : `+worktree` nomme un état que
personne d'autre ne peut récupérer, et une telle course est une répétition
générale de la preuve complète, pas la course qui rattache des artefacts à une
révision annoncée.

Les sorties vont sous
`tests/artifacts/proofs/v0.1.0-complete/<run>/` — répertoire distinct de
`v0.1.0/<run>`, pour qu'un lecteur n'ait pas à deviner si la course qu'il ouvre
a jugé six passes ou onze. On y trouve `result.json`, les journaux expurgés
`pass-<nom>.log`, et `artifacts/` avec les six fichiers : `manifest.json`,
`checksums.txt`, `sbom.json`, `provenance.json`, `report.txt` et
`proof-checksum.txt`.

Enfin, ce que cette course ne fait pas : elle est **nécessaire et non
suffisante**. Trois exigences de `v0.1.0` nomment un SHA attesté par la porte
hébergée, qu'aucune exécution locale ne produit.

## La preuve de la milestone `v0.1.1` : `tests/lab/v0.1.1/user-service/prove`

[`tests/lab/v0.1.1/user-service/prove`](../../tests/lab/v0.1.1/user-service/prove)
est l'entrée d'orchestration de la milestone « Services utilisateur » (`#121`).
Elle ne prouve pas une application : elle prouve le **moteur** de la troisième
porte, une seule fois, avec une **application synthétique écrite pour
l'exercer entièrement** — deux volumes, un `tmpfs` sans lequel elle refuse de
démarrer, un environnement interpolé, un secret généré, un contenu vérifiable de
l'extérieur — et aucune application du monde réel n'entre dans le dépôt ni dans
la preuve.

Les trois machines de `quick` ont chacune un rôle qui n'est pas
interchangeable : `lab-machine-1` tient le service sous preuve, ses deux
volumes, ses archives, sa valeur générée et son confinement, **le coffre
`vaultwarden` à côté de lui** et l'initiateur du passage ; `lab-vps` tient
l'entrée, l'écouteur du passage, un **second service utilisateur qui ne garde
rien** et les deux noms déclarés ; `lab-console` tient l'**origine de l'image**
et, par le même écouteur, le voisin synthétique du LAN.

**La décision centrale de ce harnais est l'acheminement de l'image, parce
qu'aucun registre n'existe dans le LAB et qu'aucune image tierce ne peut entrer
dans cette preuve.** L'image est construite sur place à partir du binaire Go
statique de l'application synthétique — une couche `tar.gz`, une configuration
et un manifeste OCI écrits par la fixture, sans date, donc de digest
reproductible — puis servie depuis `lab-console` par la moitié en lecture de
l'API de distribution : `GET /v2/`, un manifeste **par digest** et ses blobs, en
TLS sous l'autorité synthétique de la course. Le tirage est donc un vrai tirage
— moteur rootless, réseau, autre machine, par empreinte — et l'origine ne sait
répondre à **aucun tag**, ce qui fait de « un tag n'est une identité nulle part »
une propriété de l'origine plutôt qu'une règle à respecter. Faire de cette
origine **le voisin synthétique** est ce qui donne au confinement son contrôle
positif le plus fort : l'hôte d'où le moteur a réellement tiré cette image est
celui que le compte du service ne peut plus joindre cinq étapes plus tard, alors
que root le joint toujours.

Trois actes du harnais sortent d'un plan approuvé et se nomment eux-mêmes :
placer l'autorité de la course dans le magasin de confiance des deux machines et
le nom de l'origine dans leur fichier `hosts` — sans quoi un moteur rootless ne
tire rien, et déclarer l'origine *non sécurisée* aurait affaibli la machine au
lieu de l'outiller ; placer les certificats qu'aucun plan ne décrit ; et
**retirer, puis planter, une valeur générée**, pour produire les deux phrases de
l'addendum `#119` — une valeur disparue est une dérive régénérée, une valeur que
la machine n'a pas générée est refusée à la relecture par sa propre grammaire.
Aucune valeur générée n'entre jamais dans un document ni dans un journal : ce
qui circule est une attestation à clé que le conteneur et la fixture calculent
chacun de leur côté sur un message fixe.

Une limite est structurelle et le rapport la nomme plutôt qu'une note de bas de
page : **une jonction borne exactement un port** — la décision de `#103`, que ce
palier ne change pas —, donc le coffre et le service utilisateur ne peuvent pas
être publiés par le même passage en même temps. Le coffre est déployé, confiné
dans la même table et jamais publié ici ; le second nom de la course est le
second service utilisateur, publié par une **route locale** sur l'autre machine.
Les deux genres de route que l'addendum ouvre à la troisième porte sont donc
exercés tous les deux, et les deux noms répondent sur la même IP publique et le
même `443`.

Les **contrôles génériques** sous [`tests/checks/`](../../tests/checks/) portent
sur les sources et contrats réutilisables. La **preuve LAB** sous
[`tests/lab/`](../../tests/lab/) ajoute le placement réel, les processus,
systemd, le réseau et le nettoyage multi-VM. Une CI classique peut accueillir
la première couche dans une image isolée. La seconde exige un runner dédié avec
libvirt et les gabarits `labctl` ; une image préconstruite ne fournit pas à elle
seule cette topologie.

`labctl` reste donc utile dans deux contextes : pilotage autorisé depuis le
poste de développement et pilotage depuis un futur runner CI dédié. Dans les
deux cas, la même garde d'inventaire précède toute mutation.

L'existence d'une topologie dans `labctl` signifie uniquement que l'outil sait
la créer. Une capacité devient prouvée seulement après une exécution réelle,
documentée et reproductible dans le LAB approprié.

## Rapports exécutés

- [`v0.1.1` — le moteur des services utilisateur, prouvé une fois](v0.1.1-user-service.md) :
  passage `quick` du 8 août 2026 pour #121, **vert après deux rouges produit**.
  Une application synthétique écrite pour exercer le moteur entièrement — deux
  volumes, un `tmpfs` sans lequel elle refuse de démarrer, une origine
  interpolée, un secret généré, un contenu lisible de l'extérieur — est gelée en
  définition, déployée à côté du coffre `vaultwarden` sur la machine du LAN,
  publiée par le passage, archivée, corrompue, restaurée, retirée puis
  redéployée ; un second service utilisateur qui ne garde rien tient le côté
  absence de chaque dérivation sur l'autre machine et y est publié par une
  **route locale**, si bien que les deux genres de route ouverts à la troisième
  porte sont exercés et que les deux noms répondent sur la même IP publique et le
  même `443`. L'image est servie **par digest seul** depuis `lab-console` par la
  moitié en lecture de l'API de distribution, en TLS sous l'autorité de la course :
  faire de cette origine le **voisin synthétique** donne au confinement son
  contrôle positif — l'hôte d'où le moteur a réellement tiré cette image est celui
  que le compte du service ne peut plus joindre, et son moteur ne peut plus
  retirer l'image qu'il exécute. Les deux rouges étaient **silencieux** : un
  répertoire intermédiaire de volume laissé `root:root 0700`, qui empêchait tout
  service dont un chemin conteneur a plus d'un segment de démarrer ; et une valeur
  approuvée **tronquée à sa première espace** dans la fiche, sans erreur, le
  conteneur tournant sur une valeur que personne n'avait écrite. Limites qui
  commandent la lecture du reste : la révision porte `+worktree`, une jonction
  borne exactement un port — donc le coffre est déployé, confiné et jamais publié
  ici —, la surface HTTP du Controller n'est pas montée et les machines ne sont
  pas redémarrées.
- [`v0.1.0` — reflow sans coupe au zoom texte 200 %](v0.1.0-console-reflow-200.md) :
  passage `quick` du 7 août 2026 pour la moitié Linux de #56. Les neuf états du
  frontend — les sept vues contractuelles, l'affichage des deux secrets locaux
  et les éléments externes — sont mesurés à `1280 x 800` et `640 x 560`, texte à
  100 % puis à 200 %, sur des libellés hostiles de 236 caractères dont 118 sans
  une espace : 36 cas, 324 contrôles parcourus au clavier, 18 captures. Le
  défaut enregistré par #45 est **rejoué avant d'être corrigé** — l'oracle
  nomme la barre de navigation retenant `1799px` dans `576px` et le garde raster
  voit l'encre tranchée sur sa frontière — puis une coupe introduite
  volontairement fait rougir les deux gardes séparément. La cause était une
  requête de média : ses unités relatives sont mesurées sur la taille de texte
  initiale du navigateur, jamais sur celle de la page, donc le seuil compact ne
  suivait pas le zoom. Le 10 août 2026, le même harnais construit en plus le
  `.deb` hors ligne sur la machine, l'installe et mesure **le processus réel**
  par `tauri-driver` sur les états d'avant l'association — 16 cas, vraie
  création de coffre par l'interface comprise, onze états et 44 cas côté
  bundle au même run. Limite qui commande la lecture du reste : **les vues
  d'après l'association restent mesurées sur le bundle, hors du processus
  installé**, et Windows n'est pas mesuré.
- [`v0.1.0` — audit d'endpoints déclarés, sans mutation et sans scan](v0.1.0-endpoint-audit.md) :
  passage `quick` du 6 août 2026 pour #36, à la révision `aac5d843`. La lecture
  seule est **prouvée et non affirmée** : l'empreinte de la machine auditée —
  chemins, tailles, dates de modification et modes — est identique avant et
  après sept audits, si bien qu'un fichier réécrit à longueur égale serait vu
  par sa date. L'endpoint canari est un vrai `sshd` portant la même clé d'hôte,
  les mêmes comptes et les mêmes algorithmes que l'endpoint déclaré, et ne
  déviant que sur un point : personne ne le déclare jamais. Il ne gagne pas une
  connexion — et son **contrôle positif appartient au cas**, une session
  délibérée y étant ouverte à la fin, sans quoi un journal vide n'aurait rien
  dit de l'audit et tout du journal. Chaque incompatibilité est assertée par
  égalité : la machine qui ne dévie que d'un point produit exactement ce
  refus-là, et celle qui dévie deux fois les nomme tous les deux. Une machine
  muette est refusée pour n'avoir **pas répondu**, pas pour avoir répondu faux.
  Une session d'audit ne garde aucun canal pour s'élever, et une recommandation
  n'installe rien — seule l'approbation exacte en est une. Limite qui commande
  la lecture du reste : **les machines déviantes sont synthétiques**, aucune
  vraie Ubuntu ni `aarch64` n'existant dans ce LAB, et le canari vit sur la
  machine auditée plutôt que sur une troisième machine du réseau.
- [`v0.1.0` — remplacement explicite d'un Controller, et retrait de ses autorités](v0.1.0-controller-replacement.md) :
  passage `quick` du 5 août 2026 pour #40, le seul palier dont le sujet est ce
  qui se passe **quand on ne sait pas**. `lab-console` est **réellement
  arrêtée** : la panne jugée est une vraie panne, observée depuis deux postes
  indépendants d'espèces différentes — une tentative TCP depuis `lab-machine-1`
  et l'état du domaine rapporté par l'hyperviseur — et les 310 secondes de
  silence qui qualifient la perte sont des secondes qui se sont écoulées. Rien
  ne bascule sans que l'utilisateur le demande ; un Controller qui répond encore
  rend `ControllerStillAnswering` alors qu'il écoutait vraiment ; un silence
  plus jeune que la borne rend `Ambiguous(SilenceTooYoung)`. La perte matérielle
  et la suspicion de compromission sont **deux séquences** que la porte rend
  elle-même, la seconde commençant par l'isolement et le refusant absent. Le
  socket du lecteur est relevé fermé à chacune des quatre transitions, et un
  manifeste nommant deux Controllers est refusé. L'ancienne identité n'est
  retirée qu'après que la nouvelle a répondu **sur la même machine**, le retrait
  exigeant par signature le témoin de #39 ; ensuite un vrai `sshd` répond
  `Permission denied (publickey)` à l'ancienne autorité sur les deux machines.
  La clé personnelle d'un vrai compte est **nommée parmi les conservées**. Les
  quatre états sont reconstruits depuis la machine après coupure, et le
  désaccord entre le fichier `root` et le fil rend `unknown` plutôt que la plus
  commode des deux lectures. Trois épreuves par mutation font rougir la suite.
  Aucun Controller Go ne tourne, aucun vrai lecteur Relay n'est servi,
  l'isolement n'est pas exécuté et il n'y a pas de VM hostile distincte.
- [`v0.1.0` — identité SSH bornée par machine, et activation des rôles approuvés](v0.1.0-machine-identity.md) :
  passage `quick` du 5 août 2026 pour #39. Chaque machine reçoit une paire qui
  n'est la sienne que sur elle : un **vrai `sshd`** refuse l'identité de
  `lab-machine-1` sur `lab-console` et l'inverse, et la porte compilée rend
  `ForeignIdentity`, `Unattributed` et `SharedIdentity` sous leur propre nom. La
  commande forcée n'ouvre ni shell, ni PTY, ni SFTP, ni fichier rc, ni X11, ni
  transfert de port ou d'agent, ni argument libre, chaque capacité étant refusée
  **à côté de son contrôle positif** sur le même serveur au même instant ; la
  règle `sudo` n'autorise qu'une invocation exacte, sans `SETENV`. Le Controller
  parcourt lui-même le nouveau chemin avant toute activation, et l'Auxiliaire
  reste un diagnostic en lecture seule (`changed: false`). Ce passage inclut
  l'arbitrage sur la frontière laissée ouverte par la passe précédente : **#36
  place désormais le rôle Agent**, avec ses exigences propres — aucun critère de
  confidentialité de placement, un plancher de ressources dérivé de sa propre
  unité — et l'activation d'un Agent explicitement approuvé est prouvée avec son
  contrôle négatif et le refus d'un chemin non vérifié. Six points d'arrêt
  rendent un registre que le déroulé reconstruit, une coupure rend `INCOMPLETE`
  et nomme ce qui reste. Deux épreuves par mutation font rougir la suite. Aucune
  unité n'est réellement démarrée : l'activation est une décision typée.
- [`v0.1.0` — installation d'un Controller depuis le lot embarqué](v0.1.0-controller-install.md) :
  passage `quick` du 5 août 2026 pour #38, premier palier qui **mute réellement**
  une machine. Le lot Debian 13 `amd64` est construit par la preuve, son
  manifeste signé lie version, cible, taille et SHA-256, et l'Assistant le juge
  avant tout privilège : artefact altéré d'un octet, artefact tronqué, manifeste
  réécrit, manifeste signé par une autre clé, `arm64`, autre version et autre
  genre sont refusés chacun par sa propre raison, avec leurs contrôles positifs.
  Le paquet ne possède que `/usr/lib/your-cloud/your-cloud` `root:root` `0755`
  et trois unités `root:root` `0644` livrées inactives, sans setuid, setgid ni
  capacité ; une seule unité est activée. Le Controller tourne sous un compte
  dynamique sans capacité, avec `TasksMax=128` et `MemoryMax=384 Mio`, ses
  secrets `root:root` `0600` remis par systemd seul. `lab-console` est
  **réellement arrêtée** après extinction des processus de l'Assistant : le
  Controller garde le **même PID** et écoute toujours. Un arrêt à chacune des
  quatre premières étapes rend un registre que le déroulé reconstruit
  exactement, et la machine revient à son état initial à chaque fois. Trois
  épreuves par mutation font rougir la suite. Le lot n'est pas encore embarqué
  dans l'installateur de la Console et l'ancre n'y est pas scellée.
- [`v0.1.0` — approbation signée vérifiée sans faire confiance au Controller](v0.1.0-signed-approval.md) :
  passage `quick` du 5 août 2026 pour #37. Le cœur natif signe une enveloppe
  canonique versionnée qui lie infrastructure, machine, époque, séquence, plan,
  rollback, privilèges, émission, expiration et clé d'approbation ; l'Auxiliaire
  de diagnostic la vérifie contre sa propre ancre `root`, consomme
  atomiquement la séquence avant tout traitement et refuse rejeu, séquence
  ancienne, sautée ou concurrente. Un vecteur déterministe unique est épinglé
  côté Console et côté Auxiliaire : la signature produite par le code Rust est
  vérifiée par le code Go. `lab-machine-1` est **réellement arrêtée puis
  redémarrée** par le contrôleur du LAB ; la position anti-rejeu est retrouvée
  octet pour octet et les mêmes refus tiennent. Une nouvelle clé humaine laisse
  l'action verrouillée jusqu'à la rotation de l'ancre par l'accès personnel.
  Trois épreuves par mutation font rougir la suite. Aucune mutation n'est
  exécutée : le rapport de l'Auxiliaire porte `changed: false`.
- [`v0.1.0` — plan OCI contrôlé : ce que la machine a réellement fait](v0.1.0-oci-plan.md) :
  passage `quick` du 6 août 2026 pour #86, palier #14, **rouge et rouge du
  produit**. Le rejeu, neuf documents hostiles à effet nul et l'échec contrôlé
  qui tente exactement le rollback approuvé sont prouvés contre une vraie
  machine, et la suite du produit est enfin jouée **en root**, ce que #85 avait
  laissé en dette. Le déploiement, lui, n'aboutit sur aucune Debian 13 neuve :
  trois défauts indépendants de l'Auxiliaire sont nommés avec leur emplacement
  et leur trace — le répertoire courant hérité par un moteur rootless, la course
  entre `enable-linger` et `/run/user/<uid>`, et `DropCapability=ALL` face à une
  sonde qui écoute sur `:80`. Un passage de diagnostic, sur une copie corrigée
  dans la VM et jamais dans le dépôt, montre que le scénario entier passe une
  fois ces trois-là levés. Le palier #14 n'est pas prouvé.
- [`v0.1.0` — bornes KDF et politique `sudo` de l'accès personnel](v0.1.0-personal-access-bounds.md) :
  passage `quick` du 3 août 2026 pour #51. La calibration `bcrypt_pbkdf` sur
  `lab-console` rend environ 4,6 ms par round, identiques pour Ed25519 et RSA
  3072, et fixe `MAX_BCRYPT_ROUNDS = 2048`, vérifié à 9355 ms sur les 300 s de
  l'échéance. La matrice `sudo` réelle sur Debian 13 valide les refus de
  `log_input` et `log_stdin` et révèle que les entrées Defaults sont réparties
  sur plusieurs lignes ; les cinq captures sont figées comme fixtures. 65 tests
  verts, secrets exclusivement synthétiques, compte et politiques retirés. Un
  second passage y ajoute les décisions pures de #52 : cible résolue une seule
  fois puis gelée contre le rebinding DNS, refus du lien-local et donc de
  l'endpoint de métadonnées cloud, normalisation des adresses IPv4 encapsulées
  et admissibilité de l'endpoint d'agent. L'observation d'un vrai `ssh-agent` y
  révèle que le socket `0600` est protégé par son répertoire parent `0700`, et
  non par son propre mode ; la règle vérifie désormais le parent. 86 tests
  verts. Ces passages ne prouvent ni connexion SSH, ni signature d'agent, ni
  envoi de mot de passe : ils restent à #52, #53 et #54.
- [`v0.1.0` — consentement natif et mémoire secrète Linux/Windows](v0.1.0-native-secret-consent-linux-windows.md) :
  #45 prouvée sur `c0569d0` par `30779157351` puis fermée le 3 août 2026 ;
  `ae550470bcff08c08624988c17d16db6cb62070a` reste un candidat intermédiaire et
  `c8643b0903aee8ad194fb7c34ae6e459c52550a3` ajoute la preuve de retrait
  manquante.
  `30768351689` et `30768749538` sont rouges sous l'ancien oracle ; ils
  caractérisent `LocalDumps` administrateur hors garantie avec contrôle et
  canari présents. `30769440106` a réussi ses quatre jobs sur `ae550470` et
  prouve cette observation, la suppression du dump, le répertoire vide et les
  deux inscriptions de registre absentes ; le répertoire n'est retiré
  qu'ensuite par `Drop`. Cette preuve reste intermédiaire et ne ferme pas #45.
  `c8643b0` exige désormais son absence avant verdict avec
  `remove_and_prove_absent`. `30770893733` réussit ensuite ses quatre jobs sur
  `b76ded8`, avec matrice native, paquets et trois artefacts inspectés. Le
  rapport distingue les sous-cas Linux exécutés, les limites
  Windows et l'enregistrement WER en défense en profondeur. Après trois
  corrections du harnais de captures, `30779157351` réussit ses quatre jobs sur
  `c0569d0` : ce run et ce SHA ferment #45. Cette
  preuve ne ferme ni #42, ni #35, ni le palier #13 ou `v0.1.0`.
- [`v0.1.0` — bornage IPC et helper Windows](v1-bootstrap-ipc-windows.md) : run
  GitHub Actions manuel `30753216798` entièrement vert sur le candidat produit
  exact `f3fef79` ; tests Linux et Windows, Job Object et arbre de processus,
  branches hostiles avant reprise, `.deb`, `.msi`, gates ELF/PE, installation,
  dispatch Tauri vivant depuis WebView2, refus forge/concurrence/rejeu, absence
  de listener et nettoyage exécutés le 2 août 2026. Cette intégration ferme
  #43 ; elle ne ferme ni #45, ni #42, ni #35, ni le palier #13 ou `v0.1.0`.
- [`v0.1.0` — bornage IPC et gate du helper Linux](v1-bootstrap-ipc-linux.md) :
  passage LAB Linux historique du 2 août 2026 ; WebKitGTK et JavaScriptCoreGTK
  sont des dépendances directes du binaire Console, ce qui impose le helper
  compagnon distinct prévu par #44. Le premier consentement GTK3 sans secret et
  la récolte autonome y sont prouvés. Les manques #43 Windows et Tauri vivant
  sont traités par le rapport Windows ci-dessus ; les secrets de #45 et l'accès
  SSH de #42 restent ouverts.
- [`v0.0.3` — porte Linux Console–Controller](v0.0.3-console-controller-linux.md) :
  `.deb` signé et installé, coffre et appairage, deux Controllers séparés,
  matrice hostile depuis une seconde VM, frontière réseau privée, Relay
  indisponible, donnée ancienne, lacune, reprise, redémarrages et sept vues
  claires/sombres exécutés le 20 juillet 2026 puis parcours critique revalidé le
  22 juillet. Après une matrice historique, la porte native Linux/Windows finale
  `30710037004` a entièrement réussi dans GitHub Actions sur le candidat produit
  exact `3b8f81f`. Elle reste une preuve hébergée distincte et ne modifie pas les
  faits du rapport LAB Linux. L'issue `#9` relie le run et le SHA intégré par
  fast-forward : `v0.0.3` est fermée pour ce candidat exact.
- [`v0.0.2` — observation authentifiée et bornée](v0.0.2-observation.md) :
  mTLS, enrôlement et révocation, profil fixe, tampon saturé avec lacune,
  reprise, redémarrages et cycle retrait-réinstallation exécutés dans
  `v1-full` le 18 juillet 2026 ; orchestration encore assistée.
- [`v0.0.1` — un artefact, trois processus isolés](v0.0.1-presence.md) : build
  Go unique, Daemon et Relay parallèles sur le VPS, Daemon seul sur le LAN,
  refus candidat et HTTP, transitions `recent`/`old`/`absent`, retrait et
  réinstallation dans `v1-full`, preuve initiale le 16 juillet puis référence
  automatisée propre le 17 juillet 2026, puis revalidation historique depuis
  les chemins réorganisés avec le run `20260717T100150Z-1543398`, antérieur aux
  derniers durcissements du banc et de la CI.

## Point d'arrêt avant la prochaine preuve

La preuve fonctionnelle `v0.0.3` a employé les six VM Debian de `v1-full` et son
résultat Linux reste conservé dans le rapport ci-dessus. Le runner Windows
hébergé porte uniquement la différence native : tests propres à la plateforme,
build et signature synthétique du `.msi`, installation, lancement, absence de
listener et smoke WebView2. Il ne reçoit aucune VM, route ou doublure de
Controller, Relay ou Daemon. Les flux, identités distribuées, pannes, reprises
et scénarios multi-VM restent sous l'autorité du LAB Linux.

## LAB Windows

Ce document n'ouvrait auparavant un LAB Windows que pour un défaut fonctionnel
réellement propre à Windows. Cette position reposait sur une prémisse devenue
fausse le 3 août 2026, jour de l'épuisement du quota Actions : la CI hébergée
ne couvre pas Windows sans contrainte. La décision de placement des preuves
[`#67`](https://github.com/ldesfontaine/your-cloud/issues/67) remplace donc
cette position.

Ce LAB Windows minimal existe depuis le 4 août 2026. Il tient dans un seul
domaine libvirt, `windows-eval` : Windows Server 2025 Standard Évaluation avec
interface graphique — le même système que le runner `windows-2025` de la porte
native, délibérément —, 6 Gio de mémoire, 4 processeurs virtuels, un disque de
80 Gio alloué à la demande et le réseau libvirt `default`. Il porte
l'outillage épinglé que la porte native emploie : les outils de build MSVC x64
et le SDK Windows, `rustc` et `rustfmt` `1.94.1` en `x86_64-pc-windows-msvc`,
Node.js `24.18.0`, le runtime WebView2 Evergreen et OpenSSH.

Cette VM est provisionnée **manuellement** et reste hors `labctl`, qui ne
connaît aujourd'hui qu'une image Debian datée et vérifiée par SHA512 ; une
automatisation complète attend que sa valeur soit démontrée. Elle sert la
validation continue du helper Windows pendant le développement, au même titre
que le LAB Linux pour sa moitié :
[`tests/lab/v0.1.0/windows-helper/prove`](../../tests/lab/v0.1.0/windows-helper/prove)
y synchronise les sources natives de la Console et y exécute les suites de
contrat propres à Windows — Job Object et handles suspendus, pipe nommé et
parent déclaré, dialogue Win32 vivant, crash et dump du secret — avec les
invocations exactes de la porte native. Son adresse et sa clé viennent de
l'environnement ; aucune ne vit dans le dépôt.

**Deux suites ne s'y observent pas, et le harnais le dit plutôt que de rougir.**
Une session ouverte par OpenSSH est la session 0, dont la station de fenêtres
est un `Service-0x0-…$` et non la `WinSta0` interactive : une fenêtre qui y est
montrée est une vraie fenêtre — l'enfant du helper crée bien son dialogue
`#32770`, titré, et il a été observé le faisant — mais `IsWindowVisible` y
répond zéro, mesuré le 9 août 2026 sur une fenêtre que .NET déclarait pourtant
visible. Toute suite qui cherche une fenêtre *visible* est donc inobservable par
ce transport, quel que soit l'état du produit ; `windows-live-prompt-contract`
est déclarée **non jouée avec sa raison**, jamais verte et jamais rouge. De
même, `windows-personal-transport-contract` exige un périmètre `YOUR_CLOUD_LAB_*`
nommant une cible réelle. Nommer une suite sur la ligne de commande la joue
malgré tout : demander une suite par son nom, c'est demander à la voir essayer.

**Ce que la session 0 empêche est plus étroit qu'il n'y paraît, et cela aussi
est mesuré.** Le 10 août 2026, la même session SSH — station
`Service-0x0-61163$`, `SessionId` 0 — a rendu un raster parfaitement composé :
`msedge` `151.0.4129.72` en `--headless=new` a peint une page aux trois bandes
franches, et la capture rapatriée porte exactement ces trois couleurs, aucun
pixel noir, une dominante à `0,35`. Le pilote aussi répond : `msedgedriver`
`151.0.4129.72` démarre, ouvre une session, accepte `window/rect`, navigue,
exécute du script et rend une capture de `616 x 421` où les trois bandes se
retrouvent. Ce qu'une session 0 refuse est donc de déclarer une fenêtre
*visible*, jamais de composer ni de capturer un rendu — la distinction décide
ce qu'une future mesure de reflow sous WebView2 peut atteindre par ce
transport, et évite d'attribuer à la station de fenêtres un empêchement
qu'elle n'oppose pas. La correction de viewport que l'oracle Linux applique
déjà reste nécessaire ici : `window/rect` pose la fenêtre et non la zone
peinte.

Elle ne devient pas une autorité d'attestation. La CI hébergée conserve ce
rôle : la porte native `workflow_dispatch` sur le candidat de palier reste
exigée pour fermer un palier, selon le [contrat CI](../contribution/CI.md). Une
observation faite dans ce LAB Windows ne ferme donc rien à elle seule, et elle
ne simule jamais la topologie multi-VM, qui reste propre au LAB Linux. Elle ne
produit ni `.msi`, ni signature Authenticode, ni gate PE, ni smoke WebView2
archivé.

**Sa fermeture est explicite.** `tools/labctl assert-clean` ne voit pas ce
domaine : il refuse les VM portant l'origine `your-cloud/labctl` et les noms
`lab-*` suspects, or `windows-eval` n'a été créée ni par le contrôleur, ni avec
ses métadonnées, ni sous son préfixe. Un `assert-clean` vert ne dit donc rien de
six gibioctets encore alloués. La fin d'une tâche qui l'emploie exige la
commande suivante, nommée dans le compte rendu :

```text
virsh -c qemu:///system shutdown windows-eval
```

**Le nom est la moitié de cette propriété.** Ce domaine s'est d'abord appelé
`lab-windows`, et sous ce nom la garde le retenait : le préfixe `lab-*` est un
filet volontairement large, qui rattrape une VM que le contrôleur aurait créée
puis dont les métadonnées auraient disparu. Une machine manuelle portant ce
préfixe rendait donc `assert-clean` **rouge par construction et pour toujours**,
c'est-à-dire inutilisable comme critère de fermeture. Elle a été renommée le
6 août 2026 par `virsh domrename`, disques et configuration inchangés. Les
rapports LAB antérieurs à cette date la nomment encore `lab-windows` : ce sont
des relevés d'exécution, et ils ne sont pas réécrits.

Pour la même raison de mémoire, cette VM et les VM Debian de `labctl` ne
tournent jamais ensemble sur le poste ; le harnais refuse de démarrer lorsque
c'est le cas.

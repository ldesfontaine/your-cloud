# Service utilisateur : la définition inerte et la troisième porte

> Statut : brouillon de contrat d'architecture proposé pour `#115`, milestone
> `v0.1.1` « Services utilisateur ». Il fixe l'objet « définition de service
> utilisateur », ses bornes, la dérivation du placement, le trajet du document,
> la troisième porte des opérations et le contrat d'éligibilité d'image. Les
> implémentations prévues le suivront depuis `#116` (document Go et miroir
> Rust), `#117` (gel et service par le Controller), `#118` (la paire de plans),
> `#119` (dérivation et pose par l'Auxiliaire) et `#120` (vue Services de la
> Console) ; la preuve LAB de la milestone reste `#121`.

## Ce que ce palier ajoute, et ce qu'il n'ajoute pas

Les profils livrés jusqu'ici sont des constantes du produit : `bentopdf` et
`vaultwarden` décident de tout ce que leurs plans n'énoncent pas, et élargir la
liste demandait un contrat par application. Ce palier renverse la charge : le
moteur que `#14` à `#17` ont prouvé — compte dédié, fiche durcie, confinement de
sortie, archives immuables — devient paramétrable par un document que
**l'utilisateur** rédige, dans des bornes que **le produit** fixe. La dixième
application d'un utilisateur ne coûtera ni un contrat, ni une preuve nouvelle :
la preuve porte sur le moteur, une fois.

Ce que ce palier n'ajoute pas est nommé aussi : **aucun catalogue**. Le produit
ne fournit, ne recommande et n'héberge aucune liste d'applications ; une
définition est écrite, gelée et déployée sous l'autorité de son utilisateur, et
sa disponibilité ne crée aucune ressource — la règle des profils de service,
inchangée.

## La levée de la réserve du contrat `v0.1.0`

`docs/objectifs/v1/README.md` place « fournir un catalogue générique acceptant
arbitrairement tout service » hors du contrat de `v0.1.0`, et exige pour tout
ajout « une modification explicite et une nouvelle validation du contrat,
jamais un simple changement de roadmap ». **Le présent contrat est cette
modification explicite et cette revalidation**, et il en tient les deux bornes :

- la capacité arrive dans `v0.1.1`, jamais dans `v0.1.0`, dont le contrat et la
  preuve restent ce qu'ils sont ;
- ce qui est validé n'est **pas** « arbitrairement tout service » : c'est une
  définition fermée sous les limites nommées plus bas, et une image qui ne les
  accepte pas est refusée ou échoue de façon contrôlée — le mot « générique »
  qualifie le moteur, pas l'admission.

## La définition : un document inerte

Une définition de service utilisateur est un document JSON strict aux champs
fermés, canonisé et haché comme les plans le sont : transcript binaire à
domaine séparé propre — `your-cloud/service-definition.v1\0` — tenu entre Go et
Rust par des vecteurs déterministes croisés. Elle est bornée à **8192 octets**
avant analyse : une définition porte des listes qu'aucun plan n'a jamais
portées, et la borne, double de celle des plans, reste assez petite pour que la
Console affiche toujours le document entier. La borne est propre pour qu'aucun
des deux documents ne grandisse un jour parce que l'autre l'a fait.

Sa propriété structurante tient en une phrase : **une définition n'a aucun
effet.** Geler une définition ne crée aucune ressource, ne produit aucun plan,
ne contacte aucune machine. Seuls des plans approuvés et signés — le procédé
existant, inchangé — l'épinglent par son digest, et chaque effet continue de
naître d'une approbation humaine.

| Champ | Forme | Sens |
|---|---|---|
| `schema_version` | entier, `1` | version du schéma de définition |
| `slug` | `[a-z0-9][a-z0-9-]{0,15}`, hors liste réservée | le nom du service, et la seule valeur dont tout le reste dérive |
| `image_repository` | référence de dépôt, sans tag ni digest | d'où les images de ce service viennent — jamais laquelle |
| `container_port` | entier, `1..65535` | le port que l'image écoute dans son propre espace de noms |
| `volumes` | 0 à 8 chemins conteneur absolus normalisés | ce qui doit survivre au conteneur |
| `tmpfs` | 0 à 8 chemins conteneur absolus normalisés | le brouillon en mémoire que l'image exige sous lecture seule |
| `environment` | 0 à 32 lignes `CLÉ=valeur` | la configuration inerte, affichée partout où la définition l'est |
| `secret_keys` | 0 à 16 clés | les noms des secrets que la machine générera — jamais une valeur |

Décisions portées par cette forme :

- **La grammaire du slug est celle de `snapshot_slot`, resserrée à 16
  caractères.** Le resserrement n'est pas un goût : le compte dérivé
  `your-cloud-user-<slug>` doit tenir dans la borne des noms d'utilisateur de la
  machine (32 caractères), le préfixe en consomme exactement 16, et la
  dérivation ne tronque jamais — deux slugs distincts sont deux comptes
  distincts, par construction et non par vigilance.
- **Quatre slugs sont réservés et refusés : `bentopdf`, `vaultwarden`, `probe`,
  `entrypoint`.** La raison est plus forte qu'une collision de noms : les
  opérations d'archive nomment un service par le champ `service_profile`, et la
  troisième porte partage cet espace de noms avec les profils livrés. Réserver
  leurs noms à la source garantit qu'un nom désigne toujours exactement une
  porte — une recherche qui réussit d'un seul côté, jamais une comparaison
  qu'il faut penser à écrire.
- **Le dépôt d'image vit dans la définition ; le digest vit dans chaque plan.**
  La définition dit d'où les images viennent, un plan de déploiement dit
  laquelle court — et une mise à jour reste ce qu'elle a toujours été : un
  nouveau plan au digest changé, jamais une mutation silencieuse. Le tag est
  refusé à la grammaire des deux côtés : la forme du dépôt refuse `@` et tout
  suffixe `:tag`, et le champ de plan garde sa borne existante.
- **Les chemins sont des chemins conteneur, et rien d'autre.** Absolus,
  normalisés (aucun segment `.` ou `..`, aucune barre double, aucune barre
  finale, jamais `/` seul), segments en minuscules, chiffres, `.`, `_` et `-`,
  253 octets au plus — le jeu de caractères exclut d'office `:`, le
  séparateur des montures, sans qu'aucun échappement existe. Aucune entrée des
  deux listes réunies n'est égale à une autre ni ne la préfixe segment par
  segment : deux montures qui se chevauchent seraient deux écritures dont
  l'ordre déciderait, et l'ordre n'est pas un champ.
- **Les lignes d'environnement sont inertes et une seule interpolation
  existe : `{origin_host}`.** Une clé suit `[A-Z][A-Z0-9_]{0,63}`, unique dans
  le document et disjointe des clés de secrets ; une valeur est de l'ASCII
  imprimable borné à 512 octets, où `{` et `}` n'apparaissent que dans la
  séquence exacte `{origin_host}`, remplacée à la dérivation par l'origine que
  le plan approuve. Aucun autre gabarit, aucun échappement : une accolade
  ailleurs est un refus nommé, pas une syntaxe future.
- **Les clés de secrets sont des clés.** Même grammaire que les clés
  d'environnement, uniques, disjointes des lignes d'environnement. Aucune
  valeur de secret n'entre jamais dans un document de ce produit — ni dans une
  définition, ni dans un plan, ni dans un rapport. Une valeur d'environnement,
  elle, est affichée partout où la définition l'est : un secret n'y a pas sa
  place, et les clés de secrets existent exactement pour cela.
- **Tout champ inconnu est refusé avant que sa valeur soit lue**, par le
  décodage strict que chaque document de ce produit subit déjà.

Les bornes de cardinal (8 volumes, 8 tmpfs, 32 lignes, 16 clés) et d'octets
sont des constantes contestables au premier besoin réel prouvé — comme la
borne des plans l'a toujours été — et jamais des valeurs approuvables.

## Tout le reste est dérivé, jamais un champ

Une définition ne nomme rien de ce que la machine possède. Tout ce qui touche
l'hôte dérive du slug, mécaniquement :

```text
compte     your-cloud-user-<slug>
foyer      /var/lib/your-cloud-user-<slug>/
             volumes/<chemin conteneur>   les données, un sous-arbre par volume déclaré
             snapshots/                   les archives immuables, root, 0700
             secrets/<CLÉ>                une valeur générée par clé, compte, 0600
             secrets.env                  dérivé des clés déclarées à chaque déploiement
```

- **Le préfixe `your-cloud-` du compte n'est pas un style.** C'est lui qui
  conserve la protection d'observation existante : une déclaration externe ne
  peut pas pointer un port qu'un compte du produit détient, et cette règle
  reconnaît les comptes à leur préfixe. Le segment `user` tient la troisième
  famille à l'écart des deux autres (`svc`, `entrypoint`) : un lecteur de
  `/etc/passwd` sait qui a écrit quoi.
- **Le chemin hôte d'un volume est le chemin conteneur lui-même, enraciné sous
  le foyer.** `/srv/data` déclaré par la définition du slug `blog` vit à
  `/var/lib/your-cloud-user-blog/volumes/srv/data`. La dérivation est injective
  sans échappement, sans repli et sans empreinte — les chemins sont absolus et
  normalisés, donc la concaténation ne fabrique jamais deux fois le même
  répertoire — et elle est stable d'une révision à l'autre : l'identité des
  données est le chemin conteneur. Il en découle une conséquence dite plutôt
  que découverte : **renommer un chemin conteneur dans une révision, c'est
  monter un répertoire neuf et vide** ; l'ancien sous-arbre survit sous le
  foyer comme un retrait préserve les données, et le déplacer est une affaire
  de l'utilisateur, jamais une inférence du moteur.
- **`Sysctl=` est un dérivé mécanique du port conteneur.** La fiche porte le
  sysctl des ports bas borné à l'espace de noms exactement quand
  `container_port < 1024`, comme la sonde ; au-delà, la ligne est absente,
  parce qu'un contrôle qui n'accorde rien se lit comme un contrôle qui était
  nécessaire. La règle cesse d'être une constante par profil pour devenir une
  fonction du document — le même fait, calculé au lieu d'énuméré.
- **La propriété des répertoires reprend les décisions prouvées du profil
  privé** : les données au compte du service (un conteneur rootless dont le
  répertoire reste à root démarre et ne peut pas écrire), les archives à root
  seul (une évasion qui atteint le compte n'atteint pas l'historique des
  données dont elle sort).

La struct `placement` de l'Auxiliaire est déjà ce moteur : un compte, un foyer,
une fiche, une image, des chemins inscriptibles, des répertoires de données et
d'archives, des lignes d'environnement, un confinement. Ce palier ne l'élargit
pas — il la **remplit depuis une définition** au lieu de l'énumérer par profil,
et un critère de fermeture le tient : les fiches des profils livrés ne bougent
pas d'un octet.

## Les secrets : générés, gardés, jamais transportés

- **La machine génère, au premier déploiement, une valeur par clé déclarée** :
  32 octets de l'aléa du noyau, rendus en hexadécimal — un alphabet qui ne
  peut heurter ni une ligne d'environnement ni un shell — écrits dans
  `secrets/<CLÉ>` en création exclusive, comme la clé du passage l'a prouvé.
  Une valeur générée ne quitte jamais la machine et n'entre dans aucun
  document, aucun rapport, aucune observation.
- **Un redéploiement ne régénère rien.** Une clé dont le fichier existe est
  gardée telle quelle ; seule une clé nouvelle d'une révision reçoit une
  valeur. `secrets.env` est réécrit à chaque déploiement depuis les fichiers
  des seules clés que la révision déployée déclare — la fiche le lit par
  `EnvironmentFile=`, et ne porte cette ligne que si des clés existent.
- **Rien ne détruit une valeur.** Une clé retirée d'une révision sort de
  `secrets.env` — le conteneur ne la reçoit plus — mais son fichier survit
  sous le foyer, comme les données et les archives survivent à un retrait :
  aucun plan de ce produit ne décrit la destruction d'un secret, donc aucune
  opération n'en exécute une.

## Révision : un nouveau gel, jamais un remplacement

Une **révision** est un nouveau document gelé sous le même slug. Elle coexiste
avec toutes les précédentes : le Controller ne remplace ni ne supprime jamais
une définition gelée, et relire un digest rend exactement les octets gelés sous
ce digest. Chaque plan épingle la révision qu'il vise par `definition_digest`,
si bien que chaque instance déployée sait — et montre — la révision exacte
qu'elle exécute. Passer une instance à une révision plus récente est un nouveau
plan de déploiement approuvé, jamais une conséquence du gel.

## Le trajet du document

1. **La Console rédige, le Controller gèle.** `POST /v0/service-definitions`
   valide le document, le canonise, le hache et le gèle ; `GET` rend les
   définitions gelées, octets canoniques et digests. Geler n'a aucun effet —
   c'est la propriété structurante, tenue par une route qui ne sait pas muter.
2. **Un plan l'épingle.** `POST /v0/user-service-plans` construit et gèle la
   paire plan/rollback d'un `deploy_user_service` ou d'un
   `remove_user_service` ; un `definition_digest` que le Controller n'a pas
   gelé est refusé à la construction. La paire est affichée, approuvée et
   signée par la Console comme toutes les autres — aucun nouveau chemin
   d'autorité.
3. **Les octets voyagent à côté du plan signé.** L'Auxiliaire reçoit la
   définition avec la paire signée, **rehache et revalide avant toute lecture
   de la machine** : un digest qui ne correspond pas au `definition_digest` du
   plan est un refus avant tout effet. L'Auxiliaire ne fait confiance ni au
   transport ni au Controller — il re-dérive localement, comme il l'a toujours
   fait pour l'autorité.
4. **Il dérive un placement et exécute les effets existants.** Fiche durcie
   aux contrôles inchangés (`Pull=never`, `ReadOnly=true`,
   `NoNewPrivileges=true`, `DropCapability=ALL`, publication loopback),
   volumes et tmpfs déclarés, environnement interpolé, secrets, et le compte
   rejoint la table unique `inet your-cloud-egress` — tout trafic sortant du
   compte refusé, hors loopback et réponses établies, reposé au démarrage par
   l'unité que le profil privé a léguée.

## Les opérations : une paire nouvelle, une porte de plus aux existantes

| Opération | Champs propres (au-delà de la tête commune) |
|---|---|
| `deploy_user_service` / `remove_user_service` | `definition_slug`, `definition_digest`, `image_reference`, `image_digest`, `local_port`, `origin_host` (exactement quand la définition l'interpole) |

- **`image_reference` doit être exactement le dépôt de la définition** ; le
  digest est celui de l'instance. Le champ rend le plan lisible — l'humain
  approuve une origine et une identité exécutable sous ses yeux — il n'ouvre
  aucun choix, comme au profil public.
- **`origin_host` est présent exactement quand la définition l'interpole.**
  Une définition qui nomme `{origin_host}` fait de l'origine une valeur
  consommée : l'humain approuve un service qui ne fonctionnera correctement
  que sous ce nom, et le nom est sous ses yeux — la raison du profil privé,
  inchangée. Une définition qui ne l'interpole pas rend le champ **refusé** :
  une valeur approuvée qu'aucune ligne ne consomme serait une intention sans
  conséquence, et l'humain de ce produit approuve des conséquences. La règle
  est un contrôle croisé entre le plan et la définition épinglée — le patron
  du dépôt d'image, appliqué à la présence d'un champ —, tenue à la
  construction par le Controller et revérifiée par l'Auxiliaire, définition
  en main. Publier reste un plan séparé et optionnel — un service utilisateur
  sans route vit sur le seul loopback de sa machine, licite indéfiniment.
- **Le rollback reste l'inverse exact** : un document `remove_user_service`
  complet pour un déploiement, et réciproquement. Un retrait garde les
  données, les archives et les secrets — le rapport nomme ce qui survit.
- **Une image qui ne démarre pas sous `ReadOnly=true` est un échec contrôlé
  avec rollback**, jamais un assouplissement : le précédent BentoPDF a montré
  que les brouillons d'une image se constatent puis se déclarent en `tmpfs` —
  ici, c'est l'utilisateur qui complète sa définition et gèle une révision.

**Les archives s'ouvrent à la troisième porte sans changer de forme.**
`snapshot_service`, `discard_snapshot` et `restore_service` acceptent, dans
`service_profile`, le slug d'une définition à données — c'est la réservation
des quatre noms qui rend cette lecture sans ambiguïté. L'archive couvre le
répertoire `volumes/` **entier** : un seul instantané cohérent de tous les
volumes, service arrêté, jamais un archivage par morceaux dont l'ordre
mentirait. Les secrets n'y entrent pas — ils survivent à part et un retour ne
les touche pas. Une définition sans volume n'a rien à archiver, et l'opération
le lit sur la machine : un foyer sans répertoire de volumes est un refus avant
tout effet. `previous`, l'échange atomique et l'immuabilité des emplacements
restent lettre pour lettre le contrat du profil privé.

**La publication s'ouvre de même, forme inchangée.** `publish_route` et
`publish_link_route` gardent leurs octets : ce qui apprend la troisième porte
est la lecture « un service géré de cette machine publie ce port », qui
connaissait deux portes depuis le profil privé et en connaît trois. **Les deux
genres de route restent ouverts à un service utilisateur** — une route locale
sur la machine qui le tient, ou le passage depuis une autre — parce que le
choix du trajet appartient au placement que l'humain approuve, et non à la
nature du service : le refus du profil privé (« un coffre est publié par le
passage, pas par une route locale ») était une décision de ce profil, pas une
loi des portes. La règle « un nom est une seule revendication » et le refus
croisé des genres sur un même nom valent inchangés.

## Surface du Controller étendue de trois routes

`PLAN-OCI-CONTROLE.md`, `PROFIL-PUBLIC-BENTOPDF.md`,
`PASSAGE-PRIVE-WIREGUARD.md`, `PROFIL-PRIVE-VAULTWARDEN.md` puis
`RESPONSABILITE-EXTERNE.md` ont étendu la surface métier du Controller d'une,
trois, trois, quatre puis trois routes. Le présent contrat l'étend de trois,
et d'aucune autre — une seule construit des plans :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/service-definitions` | valider, canoniser, hacher et geler une définition de service utilisateur, sans créer aucune ressource, sans produire aucun plan et sans contacter aucune machine |
| `GET /v0/service-definitions` | lire les définitions gelées — octets canoniques exacts et digests — sans jamais en muter ni en omettre une |
| `POST /v0/user-service-plans` | construire et geler la paire plan/rollback d'un service utilisateur sur une machine de l'inventaire, sans muter aucune machine |

Décisions attachées à ces routes :

- Elles empruntent la **même authentification de session** que les routes
  métier existantes : aucun nouveau chemin d'autorité, aucun nouveau code
  d'erreur. Une machine hors inventaire reçoit `422 machine_not_active`, dans
  la liste fermée existante.
- La définition voyage comme les plans voyagent : **une chaîne JSON portant
  ses octets canoniques exacts, accompagnée de son digest** — la seule forme
  de transport, il n'en existe pas de seconde.
- L'état du Controller suit le patron des éléments externes : un fichier
  root-owned à écriture atomique, où les révisions s'ajoutent et où rien ne
  s'efface.
- La Console ne choisit **ni l'infrastructure, ni le compte, ni le foyer, ni
  un chemin hôte, ni une valeur de secret, ni la table de sortie** : tout ce
  qui touche la machine est dérivé du slug par l'Auxiliaire, et aucune requête
  ne peut le déplacer. Elle rédige la définition — c'est le seul document de ce
  produit qu'un utilisateur écrit — et les bornes ci-dessus décident de ce
  qu'une définition ne peut pas dire.
- **Les portes se refusent mutuellement.** Une définition ne passe par aucune
  route des profils livrés, un profil livré ne passe pas par
  `/v0/user-service-plans`, et le refus est une recherche qui échoue — la
  réservation des slugs à la source rend l'ambiguïté inconstructible.

## Les limites nommées du palier

Quatre limites sont des décisions de ce contrat, écrites pour être lues avant
d'être rencontrées :

- **Un conteneur par service.** Une définition décrit un processus servi par
  une image ; ni side-car, ni composition multi-services. Un collage
  `docker-compose.yml` dans la Console ne préremplit que depuis un service, et
  le dit.
- **Aucune sortie réseau, sans exception déclarable à ce palier.** Le compte
  rejoint la table de sortie commune, et il n'existe aucun champ pour y percer
  un trou. Une application qui exige de joindre l'extérieur — relais SMTP,
  API tierce — n'est pas éligible aujourd'hui ; l'exception, quand elle
  viendra, sera un champ déclaré d'un contrat futur, jamais une exception
  écrite dans la table.
- **Secrets générés seulement.** Aucun transport de valeur existante : une
  application qui exige un secret d'un tiers (jeton d'API, mot de passe
  externe) attend le même contrat futur. Ce que la machine génère, la machine
  le garde.
- **`ReadOnly=true` n'est pas négociable.** Aucune révision, aucun plan,
  aucun échec ne le relâche. Ce que l'image veut écrire hors données se
  déclare en `tmpfs` ; ce qu'elle veut garder se déclare en volume ; le reste
  est un échec contrôlé qui se lit.

## Ce qu'une image doit accepter : le contrat d'éligibilité

Ce contrat est affiché à l'utilisateur — dans la vue Services, avant le
premier gel — en phrases, pas en options. Une application est éligible si son
image :

1. court **rootless**, sous un compte ordinaire, sans capacité ni privilège ;
2. écoute sur **un seul port**, celui que la définition déclare ;
3. écrit ses **données durables uniquement sous les chemins déclarés en
   volumes**, et ses brouillons sous les chemins déclarés en `tmpfs` ;
4. **sert sous lecture seule** — tout le reste de son système de fichiers est
   figé, et une image qui refuse de démarrer ainsi échoue de façon contrôlée ;
5. **ne sort pas sur le réseau** : pas de téléchargement au démarrage, pas de
   télémétrie, pas de relais — ce qui tourne est ce que l'image contient ;
6. se configure par **lignes d'environnement inertes** et reçoit ses secrets
   par **clés générées sur la machine**, jamais par des valeurs transportées ;
7. est joignable **par digest** depuis la machine — un tag n'est une identité
   nulle part dans ce produit.

Une application qui ne tient pas ces phrases n'est pas condamnée : elle attend
un contrat futur qui nommera l'élargissement, ou reste un élément externe que
le produit représente sans le posséder.

## Addendum `#119` : ce que poser la troisième porte sur une machine a exigé de décider

Le contrat ci-dessus dit quoi. Poser la dérivation et les sept opérations sur
une machine a demandé des décisions qu'il ne nommait pas, et elles sont ici
plutôt que seulement dans le code. La fenêtre ouverte par `#118` est close :
chaque forme de la troisième porte atteint les effets de son propre genre et
d'aucun autre, et le test qui tenait la fenêtre a été remplacé par celui qui
tient cette propriété.

- **La définition voyage par sa propre porte, dans les deux sens.** L'entrée
  de l'Auxiliaire gagne un troisième champ à côté du plan et du rollback, qui
  porte les octets canoniques exacts de la définition. Une forme de service
  utilisateur sans définition est refusée en nommant la révision manquante ;
  une définition à côté de toute autre forme — sonde, route, passage, et
  **archive** — est refusée avant toute lecture de la machine. Les opérations
  d'archive n'en portent pas : tout ce qu'elles touchent dérive du slug seul,
  et la présence de volumes se lit sur la machine, comme le port se lit dans
  la fiche.
- **`secrets.env` appartient au compte, pas à root.** C'est le gestionnaire
  systemd du compte qui lit `EnvironmentFile=`, et un fichier root dans un
  foyer que le compte possède revendiquerait une protection que le répertoire
  ne peut pas tenir. Le reste de la propriété suit le contrat : `volumes/` et
  `secrets/` au compte en `0700`, les archives à root seul.
- **La table de sortie devient multi-comptes, et c'était sa dette.** Le
  profil privé avait légué la décision « au palier qui ajoute un second
  profil confiné » : c'est celui-ci. La table unique rend un bloc de règles
  par compte confiné ; à un seul compte, ses octets sont exactement ceux que
  `#102` a prouvés. Il suit que déployer ou retirer n'importe quel service
  confiné pose la table de **tous** les comptes confinés de la machine, que
  seul le retrait du dernier emporte les fichiers, et que le tirage d'image
  pose pendant le fetch la table de **tous les autres** — déployer un service
  utilisateur ne déconfine jamais le coffre, fût-ce le temps d'un tirage.
- **Les comptes confinés se découvrent sur la machine, jamais dans un
  registre.** Une lecture bornée énumère les foyers `your-cloud-user-*` dont
  la fiche existe ; elle sert aussi la lecture « un service géré de cette
  machine publie ce port », qui connaît désormais les trois portes.
- **Des secrets disparus sont une dérive, jamais une continuité** — la règle
  des données disparues, mot pour mot : la valeur manquante est régénérée et
  le rapport dit que la machine a changé. « Jamais régénéré » vaut pour une
  clé dont le fichier existe. Et une valeur que la machine n'a pas générée
  est refusée à la relecture par sa propre grammaire : un fichier posé à la
  main n'injectera pas de ligne d'environnement arbitraire par la porte des
  secrets.
- **Une restauration ne connaît que la racine des volumes.** L'archive
  couvre `volumes/` entier et l'échange atomique le rend entier ; la liste
  des volumes d'une révision appartient à la définition, que les opérations
  d'archive ne portent pas. C'est dit ici pour qu'un lecteur ne cherche pas
  une garantie sous-arbre par sous-arbre que rien ne promet.

## Addendum `#120` : ce qu'écrire une définition dans la Console a exigé de décider

Le contrat dit ce qu'une définition est. Offrir de l'écrire à un humain a
demandé des décisions qu'il ne nommait pas, et elles sont ici.

- **Geler n'est pas signer, et la vue le tient par sa construction.** La
  définition est inerte, donc le gel n'emprunte aucune enveloppe, ne mint aucune
  approbation et n'ouvre pas la fenêtre native : c'est une route métier de plus,
  authentifiée par la session ordinaire. La conséquence pratique est que la
  trame de consentement de l'assistant n'est pas sur ce chemin, et que la dette
  connue « trame 4096 < définition 8192 » ne le touche pas. Ce que la borne du
  document a réellement coûté est ailleurs : la requête de gel est la seule de
  la Console dont la borne n'est pas les quatre kilobytes communs, et elle est
  dérivée de la borne du document — `2 × 8192 + 512` — exactement comme celle du
  Controller.
- **Le formulaire ne borne rien lui-même.** Les grammaires, les cardinaux, les
  noms réservés, la règle de chevauchement et l'unique interpolation viennent du
  miroir Rust par commande Tauri. Pour que la validation en ligne puisse dire
  *où* et *pourquoi*, le miroir gagne une énumération fermée de refus nommés par
  champ, construite sur les mêmes prédicats que la validation ; un test tient
  l'équivalence — une définition n'a aucun refus exactement quand elle décode —
  sur chaque sujet du module. La Console ne rend jamais un code au visage d'un
  humain : une phrase par nom, et le contrat de source rougit si un nom perd la
  sienne.
- **Le panneau de conséquences est la seule porte du gel.** Il suit le patron
  des `confirmation_lines` : des phrases qu'un humain approuve comme des
  conséquences — compte dérivé, foyer, chemin hôte de chaque volume, lignes
  exactes de la fiche, règle de sortie, contenu d'un futur instantané, sort des
  secrets à un redéploiement — et jamais des champs qu'il approuverait comme des
  intentions. Les deux valeurs qu'une définition ne décide pas, l'empreinte de
  l'image et le port local, sont nommées comme appartenant à un plan plutôt
  qu'omises. Structurellement, la commande de gel ne peut recevoir que ce que la
  relecture a produit, et la relecture produit toujours les lignes avec les
  octets.
- **Un collage est un clavier.** Le parseur d'une commande `docker run` et d'un
  sous-ensemble borné de `docker-compose.yml` est local et pur : il n'ouvre rien,
  n'exécute rien, ne lit aucun fichier et ne soumet rien. Il rend un brouillon et
  des notes nommées sur ce qu'il a écarté — le tag ou l'empreinte du dépôt, le
  côté hôte d'une monture ou d'un port, les directives sans champ, les entrées
  d'environnement sans valeur inerte —, et un compose à plusieurs services ne
  préremplit que depuis un seul en nommant les autres, comme la limite « un
  conteneur par service » l'exige. Il est écrit en Rust plutôt qu'en JavaScript
  pour la même raison que le reste : ce qui est testé dans le LAB est ce qui
  tourne.
- **La Console rehache chaque révision avant de l'afficher.** Le Controller
  garde des octets et une empreinte ; il n'est pas l'autorité sur ce que dit une
  définition. Chaque entrée d'une liste est vérifiée par la fonction du miroir
  que l'Auxiliaire utilisera le jour où un plan épingle ce digest, et une liste
  dont une entrée échoue est refusée entière — en montrer une de moins ferait
  croire qu'une révision n'a jamais été gelée.
- **« Profil de service » devient « Service défini » pour un slug
  utilisateur.** C'était la première dette de présentation de `#118`. Le champ
  `service_profile` est partagé par deux portes et la réservation des quatre noms
  suffit à les distinguer : un profil livré est un profil du produit, tout le
  reste est un document qu'un utilisateur a écrit, et le nommer « profil »
  l'attribuait à la porte dont il ne vient pas. Les lignes d'archive et de retour
  disent désormais ce que la vue Services dit ; les profils livrés gardent leur
  étiquette, et aucune ligne n'est ajoutée ni retirée.
- **`RequireDefinitionAgreement` n'est pas encore miroité, et la condition est
  désormais nommée.** C'était la seconde dette de `#118`, conditionnée à ce que
  la Console tienne une définition à côté d'un plan. Cette vue ne la tient pas :
  elle écrit et gèle des définitions, et n'affiche aucun plan. Le contrôle croisé
  reste où il peut être fait — construction par le Controller, revérification par
  le Controller à la soumission depuis `v0.1.2`, revérification par l'Auxiliaire,
  définition en main — et le miroir Rust rejoindra la fenêtre d'approbation avec
  `#123`–`#124`, où les deux documents se rencontrent enfin. Le contrat de ce
  trajet est [`TRAJET-DE-COMMANDE.md`](TRAJET-DE-COMMANDE.md).
- **Les instances sont affichées depuis `v0.1.2`, et de deux provenances
  distinctes.** La lecture qui manquait est `GET /v0/plan-dispatches` : le
  Controller rend l'histoire bornée de chaque lancement — état, instants,
  empreintes, la révision que le plan approuvé épinglait, et ce que la machine a
  conclu. La vue Services rend donc, pour chaque instance : **la révision, qui
  vient du plan approuvé — vérifiée deux fois, par ce Controller à la
  soumission et par l'Auxiliaire avant toute mutation — et le fait qu'elle
  court, qui vient du rapport.** Les deux origines restent lisibles séparément :
  l'écran ne les fusionne pas en une affirmation unique. Une instance dont le
  dernier dispatch n'a pas été rapporté, ou dont l'enregistrement est sorti de
  l'histoire bornée, est affichée avec son incertitude plutôt qu'avec un état
  inventé.
  
  La limite, écrite plutôt que découverte : **une modification faite hors du
  produit après le dispatch n'est visible ni par l'une ni par l'autre**, et ne
  le serait pas davantage si la révision venait du rapport — celui-ci est émis
  au moment de l'application et ne fait que répéter le plan qu'il vient de
  vérifier. Seule une observation la verrait, et ce palier n'en ajoute aucune ;
  c'est la distinction `déclaré` contre `vérifié` que ce produit fait déjà
  ailleurs, et la vue accueillera une colonne observée le jour venu sans que
  rien de celle-ci soit réécrit. Le câblage plan → UI que `v0.1.0` avait laissé
  ouvert se ferme avec la vue Plans de `#124` ; le contrat est
  [`TRAJET-DE-COMMANDE.md`](TRAJET-DE-COMMANDE.md).

## Ce que la preuve devra constater

La preuve (`#121`) exerce le moteur avec une **application synthétique
construite pour lui** — deux volumes, environnement interpolé, un secret
généré, un `tmpfs`, une vérification de contenu — et aucune application du
monde réel n'entre dans le dépôt ni dans la preuve :

1. rien — compte, foyer, fiche, table — n'existe avant approbation ; geler
   une définition, en particulier, ne crée rien ;
2. relire une définition gelée rend ses octets exacts ; une définition
   altérée d'un octet change de digest, est refusée par l'Auxiliaire avant
   toute lecture de la machine, et l'originale reste lisible ;
3. le service déployé court sous `your-cloud-user-<slug>`, ses données vivent
   sous le foyer aux chemins dérivés, son environnement porte l'origine
   interpolée, son secret existe en `0600` et sa valeur n'apparaît dans aucun
   document, rapport ni observation ;
4. publié par le passage à côté du coffre, le nom du service répond sur la
   même IP publique et le même `443` — les plans de route sont, aux octets de
   forme près, ceux d'aujourd'hui ;
5. retrait puis redéploiement : mêmes données, mêmes secrets, nouveau
   conteneur ;
6. sauvegarde de tous les volumes en un emplacement nommé, corruption
   volontaire, restauration : le contenu revient, le digest du rapport
   correspond, `previous` détient l'état corrompu ;
7. le service confiné ne joint ni un voisin synthétique du LAN ni
   l'extérieur ;
8. les refus se constatent depuis l'extérieur : tag dans le dépôt d'image,
   slug réservé, définition altérée, tentative de chemin hôte, port bas non
   déclaré, chevauchement de montures, origine approuvée qu'aucune ligne
   n'interpole ;
9. idempotence de chaque plan rejoué ; les fiches des profils livrés n'ont
   pas bougé d'un octet ; le démontage rend les machines à leur état de
   clôture nommé.

Le rapport nomme ce que le moteur ne prouve pas : une application réelle
donnée n'est pas rendue éligible par cette preuve — elle le devient en tenant
le contrat d'éligibilité, et c'est un constat que chaque utilisateur fait sur
sa propre image.

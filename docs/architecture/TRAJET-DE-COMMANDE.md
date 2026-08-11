# Trajet de commande : de l'humain qui approuve à la machine qui rapporte

> Statut : contrat d'architecture de `#122`, milestone `v0.1.2` « La Console aux
> commandes ». Ses neuf décisions restées ouvertes ont été tranchées le
> 11 août 2026 et sont écrites ici, chacune à sa place, avec l'invariant qui la
> force et la mesure dont elle est dérivée ; la section
> [« Les neuf décisions »](#les-neuf-décisions-tranchées-le-11-août-2026) les
> récapitule. Il fixe les cinq maillons du chemin
> « un humain déploie depuis la Console » : la construction d'une paire, sa
> lecture et son consentement dans une fenêtre séparée, la soumission de
> l'approbation signée, le lancement de l'Auxiliaire par l'identité de la
> machine, et le rapport lu jusqu'à l'humain. Les implémentations prévues le
> suivront depuis `#123` (fenêtre native d'approbation), `#124` (commandes de
> plan et vue Plans), `#125` (réception de l'approbation et consommation
> durable), `#126` (identité de commande et lancement par SSH) et `#127`
> (rapport remonté jusqu'à l'humain) ; la preuve LAB de la milestone est `#128`.

## Ce que ce palier ajoute, et ce qu'il n'ajoute pas

Tout ce que Your Cloud sait faire sur une machine est prouvé, et rien de ce
qu'il sait faire n'est **commandé** depuis la Console. Les plans se
construisent, les documents se hachent, l'enveloppe se signe, l'Auxiliaire
vérifie et applique — et entre la Console et la machine, le chemin réel n'a
jamais existé : chaque preuve passée l'a franchi par une fixture, et chaque
harnais le dit lui-même. Ce palier construit ce chemin, une fois, avec les
seules pièces du produit.

Ce qu'il n'ajoute pas est nommé aussi : **aucune nouvelle autorité**. Pas de
troisième accès SSH, pas de shell d'administration, pas de reprise autonome,
pas de file d'attente d'actions, pas de rejeu. Le compte technique, la commande
forcée, la règle d'élévation et l'état anti-rejeu de la machine ne bougent pas
d'un octet : ce palier apprend à s'en servir, il ne les élargit pas. Et il
n'ajoute aucune autorité à la Console : elle ne choisit ni une adresse, ni un
port SSH, ni une clé, ni un ordre d'exécution — elle rédige des demandes et
présente des phrases.

## L'état de départ : la carte des cinq maillons, constatée le 8 août 2026

Ce contrat part d'un audit fichier par fichier, et le consigne pour qu'un
lecteur sache ce qui existait avant lui.

| Maillon | Ce qui existe | Ce qui manque | Où cela se lit |
|---|---|---|---|
| 1. Construire | les douze routes `POST /v0/*-plans` construisent et gèlent des paires | aucune commande Tauri, aucune vue : la Console ne peut appeler aucune d'elles | `internal/controller/http.go:726-768` |
| 2. Lire et consentir | le sidecar natif ne connaissait que l'amorçage (`AssistantScopeV1`, trame 4096) | aucune forme d'approbation n'existait — décision tranchée et testée depuis, consacrée plus bas | `console/src-tauri/crates/bootstrap-protocol/src/approval_consent.rs` |
| 3. Soumettre | `sign_approval` est prouvé (`#37`) : le cœur natif signe, l'Auxiliaire vérifie | aucune route du Controller ne reçoit une approbation ; aucun fichier de production de `internal/controller` n'importe `internal/approval` | absence constatée par recherche ; gardes d'imports dans `service_definitions_test.go` et `external_test.go` |
| 4. Lancer | compte `your-cloud-auxiliary`, commande forcée `/usr/bin/sudo -n /usr/lib/your-cloud/your-cloud auxiliary approve`, règle `sudo`, entrée `applyWrapper` | personne ne génère l'identité SSH d'une machine, aucun client SSH n'existe en Go, l'unité du Controller ne charge que trois credentials TLS | `machine_identity/identity.rs:22-24`, `internal/auxiliary/input.go:129`, `packaging/server-bundle/units/your-cloud-controller.service` |
| 5. Rapporter | l'Auxiliaire rend un rapport structuré, complet, fermé | il meurt sur la sortie standard ; le seul retour vers l'humain est une observation passive | `cmd/your-cloud/auxiliary.go:41` et `:348` |

Le maillon 4 est le trou réel : la frontière est **écrite** — « the private
material of the operational identities stays on the Controller » — et personne
n'a jamais généré ce matériel. Le module qui juge les identités par machine ne
voit que des empreintes, et il a raison ; il n'existe simplement rien en amont
qui en produise.

## Une autorité par maillon, et jamais deux

| Maillon | Qui décide | Qui détient | Ce qui traverse |
|---|---|---|---|
| Construire | le Controller | rien de durable | une paire gelée, rendue à la Console |
| Consentir | l'humain | la fenêtre native, hors de la surface WebView | des phrases et deux empreintes |
| Signer | le cœur natif de la Console | la clé humaine, dans le coffre natif | une enveloppe canonique |
| Soumettre | le Controller | le registre de dispatch, durable | l'approbation, la paire, la définition quand la porte l'exige |
| Lancer | le Controller | l'identité de commande de **cette** machine | le wrapper sur l'entrée standard de la commande forcée |
| Appliquer | l'Auxiliaire | l'ancre et l'état anti-rejeu de sa machine | rien : les effets restent sur la machine |
| Rapporter | la machine | le rapport, conclusion de la machine | un document fermé, lu par le Controller, rendu en phrases |

Aucune ligne de ce tableau ne fait confiance à la précédente. Le Controller
revérifie ce que la Console lui remet ; l'Auxiliaire revérifie ce que le
Controller lui porte ; la Console revérifie ce que le Controller lui rend. Le
transport est un transport, jamais une attestation.

## Maillon 2 — Ce que la fenêtre montre, et ce qu'elle prouve

La décision est tranchée et testée ; ce contrat la consacre plutôt que de la
rouvrir. Elle tient en quatre phrases.

- **La fenêtre rend des phrases, jamais des documents.** Ce qui traverse la
  trame est la liste des `confirmation_lines` que le cœur a dérivées des deux
  documents qu'il avait déjà tenus contre leurs propres empreintes, à côté des
  **deux empreintes** elles-mêmes. La paire ne traverse pas. Faire de la
  fenêtre un second vérificateur exigerait d'y porter toute la grammaire des
  plans, dans un binaire dont le graphe de production est tenu à un simple
  programme GTK ou Win32 — et surtout, cela produirait **deux dérivations des
  mêmes phrases**, dont chaque divergence serait une fenêtre montrant autre
  chose que ce qui se signe. Une seule dérivation, dans le processus qui
  détient la clé, est la propriété. Contre un cœur compromis, deux copies
  tombent ensemble : une seconde copie n'achète rien et coûte une divergence.
- **Ce que la fenêtre prouve est énoncé honnêtement : l'humain a lu et accepté
  ces phrases.** Que ces phrases décrivent la paire est prouvé ailleurs et deux
  fois — par le cœur, qui a reconstruit les deux empreintes depuis les champs
  qu'il a analysés, et par l'Auxiliaire, qui les re-dérive des octets reçus
  avant de toucher la machine. Le produit dit cela plutôt que de laisser croire
  davantage.
- **Les deux dernières phrases *sont* les empreintes.** L'avant-dernière se
  termine par l'empreinte du plan, la dernière par celle du retour. C'est ce
  qui rend l'écho signifiant : la fenêtre rend des valeurs que l'humain avait
  sous les yeux sur les deux dernières lignes qu'il a lues, jamais des valeurs
  qu'on lui a passées à côté.
- **Un refus ne nomme aucune paire ; une confirmation ne peut pas voyager sans
  la nommer.** Le document de sortie est plat et fermé, et le couplage est
  refusé dans les deux sens. Le cœur tient ensuite ces deux valeurs contre les
  deux qu'il a calculées lui-même : un consentement recueilli sur un plan ne
  peut jamais être présenté pour un autre.

**La trame est dérivée, jamais choisie.** `MAX_APPROVAL_CONSENT_FRAME_BYTES` vaut
`24 × (384 + 3) + 640 = 9928`, et chacun de ses termes se lit contre une borne
du produit : 24 phrases parce que la présentation la plus large qu'il sache
écrire en fait 16, et qu'une fenêtre qu'un humain doit faire défiler est une
fenêtre que personne n'a lue ; 384 octets parce que la phrase la plus large
reconstructible aujourd'hui — l'origine d'un service utilisateur — en fait 331,
et parce qu'une trame se borne en octets. Ce n'est **pas** la trame de
l'amorçage : élargir celle-ci pour y loger un consentement relâcherait une
borne sur un document qui n'a jamais besoin de la place. Les deux trames
portent deux documents et chacune est bornée par ce que ses propres champs
peuvent atteindre.

**Aucun caractère de contrôle, aucune marque bidirectionnelle.** Une phrase qui
peut réordonner son propre affichage est une phrase dont ce qu'un humain lit et
ce qu'il signe divergent. Le refus est en amont, dans la validation du
document, jamais dans le dessin.

### Décision tranchée : la moitié Win32 est différée, et la dette est écrite

La fenêtre d'approbation est livrée en GTK, prouvée sur `lab-console`. **La
moitié Win32 est différée après ce palier**, et ce n'est pas un oubli : le
dialogue Win32 de l'amorçage est une implémentation complète — classe de
fenêtre, boucle de messages, disposition et accessibilité propres — et écrire
son équivalent sans pouvoir le compiler ni l'exécuter produirait du code non
prouvé, ce que la discipline de ce dépôt refuse.

**L'état honnête, écrit tel quel : la Console Windows observe, elle n'approuve
pas encore de plans.** Elle construit un plan et le lit ; elle ne recueille pas
de signature. L'arme Windows de la fenêtre répond `unavailable` — la seule
réponse qui ne nomme aucune paire, et qui ne prétend pas qu'un humain a décliné
alors que personne n'a été interrogé. Un refus aurait menti sur les deux points.

Ce que cela ne change pas : rien n'est retiré du Windows déjà prouvé, et la
matrice de septembre reste ce qu'elle est — deux systèmes, une passe, attestant
l'existant. Aucun déclencheur automatique n'est posé ; le contrat n'en a aucun.

Ce qui reste dû est nommé dans une issue de rattrapage dédiée : le dialogue
Win32 d'approbation, sa preuve dans `windows-eval`, et la levée de cette dette
`unavailable`.

### Décision tranchée : deux invocations nommées, et le compilateur qui l'atteste

La Console possède **un seul chemin qui lance un processus**, et jusqu'ici il ne
savait lancer qu'une chose : la fenêtre d'amorçage, avec son argument de mode et
sa trame de portée. La fenêtre d'approbation en demande une seconde. La façon
dont ce chemin se généralise est une décision d'autorité, pas de confort.

**Le superviseur est paramétré par une énumération fermée de deux invocations
nommées, jamais par un couple `(mode, trame)` libre.** Chaque variante *porte* le
document que son propre mode lit :

| Invocation | Argument de mode | Document qui entre | Document qui sort |
|---|---|---|---|
| amorçage | `--native-bootstrap-assistant` | `AssistantScopeV1` | un événement terminal |
| consentement | `--native-approval-consent` | `ApprovalConsentV1` | une réponse fermée |

Le croisement — un consentement écrit sur la trame d'amorçage, une portée remise
à la fenêtre d'approbation — n'est pas *refusé à l'exécution* : **il ne peut pas
s'écrire**. Un mode et un document nommables séparément seraient un mode et un
document croisables ; portés par une même valeur, ils décrivent nécessairement la
même chose. Et une troisième invocation ne s'obtient pas en passant une chaîne de
plus : il faudrait une troisième variante, et chaque `match` du chemin cesserait
de compiler jusqu'à ce qu'elle soit traitée. La généralisation a d'ailleurs été
faite ainsi : le compilateur a exigé, en deux erreurs, que le site de lancement
nomme sa variante et que la lecture du verdict d'amorçage réponde à la nouvelle.

**Les gardes ne se dédoublent pas.** L'alternative — un second superviseur dédié
— aurait mis en deux exemplaires la politique de lancement : validation de
l'exécutable installé, `env_clear`, groupe de processus propre, échéance
échantillonnée sur l'horloge partagée avant l'instant local, nettoyage réconcilié,
refus si un helper est déjà actif. Deux copies d'une politique de sécurité
divergent ; c'est la panne que ce dépôt refuse partout ailleurs, et qui a fait
déplacer le document de rapport dans son propre paquet au maillon 5. **Un test
unique traverse les deux variantes contre la même liste de gardes.**

**L'exclusion « un seul helper actif » est globale aux deux modes.** Un amorçage
en cours bloque un consentement, et inversement. Ce n'est pas une commodité
d'implémentation : deux fenêtres natives ouvertes en même temps sont deux fenêtres
dont un humain ne sait plus laquelle répond à quoi, et le produit n'a aucun moyen
de le lui dire. Une seule fenêtre à la fois est ce qui rend une réponse
attribuable.

**Le superviseur change de nom.** Il ne lance plus l'Assistant : il lance un
helper natif, et il en connaît deux. Le nom dit désormais ce qu'il est devenu,
plutôt que ce qu'il était quand il n'y en avait qu'un.

**L'agent de signature reste interdit à la fenêtre d'approbation, et
structurellement.** L'endpoint de l'agent personnel n'est accordé que par un pas
qui ne peut pas s'en passer, et cette autorisation se lit sur le genre de fenêtre
demandé. La variante consentement **ne porte aucun genre de fenêtre** : elle ne
décline pas l'octroi, il n'existe aucune valeur qu'elle pourrait porter qui le
demanderait. Un agent est un oracle de signature ; une fenêtre qui recueille une
approbation n'en a aucun besoin, et n'en reçoit aucun.

**Décision tranchée : une seconde borne, celle des lignes *repliées*, et elle
est refusée dans `validate`.** Les 24 phrases sont des phrases *logiques* ; la
fenêtre les replie à sa propre largeur, et le produit en possède déjà une,
mesurée et livrée : `MAX_PUBLIC_LINE_CHARACTERS = 72`, la largeur à laquelle la
fenêtre d'amorçage replie déjà ses lignes. Vingt-quatre phrases bornées à
384 octets peuvent donc atteindre bien plus de vingt-quatre lignes à l'écran, et
c'est le nombre de lignes affichées — jamais le nombre de phrases — qui décide
si un humain doit faire défiler.

`MAX_APPROVAL_CONSENT_FOLDED_LINES` vaut **32**, et ce nombre est mesuré sur les
présentations que le produit écrit réellement, repliées à 72 caractères :

| Présentation la plus large | Phrases logiques | Lignes repliées **mesurées** |
|---|---|---|
| service privé (schéma 2) | 16 | **30** |
| service utilisateur avec origine | 12 | **25** |

La plus longue phrase du produit — l'origine d'un service utilisateur, qui porte
un hôte pouvant atteindre `MAX_ROUTE_HOST_BYTES = 253` — se replie à elle seule
en cinq lignes ; les deux empreintes en deux chacune. Trente-deux est la
puissance de deux au-dessus de cette mesure, et elle tient dans une fenêtre
qu'aucun écran n'oblige à défiler.

**La marge est de deux lignes, et c'est la décision plutôt qu'un oubli.**
Ajouter une phrase à une fenêtre d'approbation doit être une décision prise
contre cette borne, jamais une dérive découverte devant un humain ; un palier
qui aurait besoin d'une présentation plus large devra dire ce qu'il abandonne,
exactement comme le contrat le dit déjà pour la trame. Les deux bornes mordent
dans deux régimes différents et aucune n'est morte : vingt-quatre phrases
courtes se replient en vingt-quatre lignes et sont refusées par
`MAX_APPROVAL_CONSENT_LINES`, tandis que seize phrases larges sont refusées par
celle-ci.

*(La mesure initiale de la séance annonçait ≈25 lignes pour le service privé ;
l'implémentation, qui replie réellement les phrases construites depuis leurs
constantes, en donne 30. Le nombre retenu ne change pas, la marge oui, et elle
est écrite.)*

La borne est **refusée à la validation du document de consentement**, jamais au
dessin : une présentation qui la dépasserait rendrait un test rouge avant qu'un
humain rencontre une fenêtre qui défile ou, pire, une fenêtre qui tronque. Comme
`MAX_APPROVAL_CONSENT_FRAME_BYTES`, elle est **dérivée** plutôt que choisie : la
suite de tests replie les présentations les plus larges depuis les constantes
dont elles sont formatées, si bien qu'un hôte, un slug ou une phrase qui
grandirait rougirait ici.

### La décision en suspens, tranchée : l'écran d'un service utilisateur nomme la révision par son empreinte

**L'écran d'approbation d'un service utilisateur affiche l'ardoise du plan —
slug, révision par son empreinte, image et son empreinte, port local, origine —
et ne re-rend pas les conséquences de la définition.** Ce contrat consacre
cette position, pour quatre raisons dont trois sont structurelles.

1. **La définition a déjà été lue, à son gel.** Le panneau de conséquences est
   la seule porte du gel, et il rend précisément ces phrases : compte dérivé,
   foyer, chemin hôte de chaque volume, lignes exactes de la fiche, règle de
   sortie, contenu d'un futur instantané, sort des secrets à un redéploiement.
   L'empreinte est ce qui lie ce plan à ces octets-là.
2. **Les re-rendre serait la seconde dérivation que la fenêtre refuse.** Les
   mêmes phrases seraient produites à deux endroits — le panneau de gel et la
   fenêtre d'approbation — et chaque divergence entre les deux serait un humain
   approuvant autre chose que ce qu'il a gelé.
3. **La trame ne le supporterait pas, et le nombre n'est pas le problème.** Une
   définition peut déclarer 8 volumes, 8 `tmpfs`, 32 lignes d'environnement et
   16 clés de secrets : au-delà de 64 phrases de conséquences, plus les
   en-têtes. Porter cela exigerait de faire passer `MAX_APPROVAL_CONSENT_LINES`
   de 24 à plus de 80 et la trame de 9928 à plus de 31 000 octets — et surtout,
   exigerait une fenêtre **qui défile**. L'autre voie n'est donc pas un nombre
   plus grand : c'est une autre fenêtre, dont la propriété centrale (« aucune
   phrase cachée ») serait perdue. C'est la conséquence à écrire si le
   mainteneur tranche l'inverse.
4. **Le contre-argument est nommé plutôt qu'évité** : l'humain qui approuve un
   déploiement peut ne pas être celui qui a gelé la révision, ou l'avoir gelée
   il y a des semaines, et une empreinte n'est pas une mémoire. La réponse
   n'est pas d'allonger la fenêtre : c'est que **la Console sache montrer la
   révision à côté du plan, avant que la fenêtre s'ouvre**. Lire est un geste de
   la Console ; approuver est un geste de la fenêtre ; la fenêtre ne porte que
   ce que la signature doit lier.

**Conséquence tenue ici plutôt qu'ailleurs : la Console tient enfin une
définition à côté d'un plan, donc `RequireDefinitionAgreement` est miroité.**
C'était la seconde dette de `#118`, explicitement conditionnée à ce que ces deux
documents se rencontrent dans la Console. Ils s'y rencontrent : la Console lit
la paire, lit la révision épinglée, et **soumet les deux**. Le contrôle croisé
reste tenu là où il peut l'être — construction par le Controller, revérification
par le Controller à la soumission, revérification par l'Auxiliaire, définition
en main — et le miroir Rust le tient désormais aussi, avant que la fenêtre
s'ouvre.

## Maillon 3 — Soumettre : une route fermée, une séquence dépensée avant tout octet

**Le Controller ne garde rien d'une paire construite.** Les routes de
construction gèlent des octets et les rendent ; elles n'écrivent aucun état, et
ce contrat ne leur en donne pas. La paire voyage donc **avec** l'approbation à
la soumission, sous la seule forme de transport que ce produit décrit : des
chaînes JSON portant leurs octets canoniques exacts. Le Controller recanonise,
rehache et tient les deux empreintes contre celles que l'enveloppe signe. Un
magasin de plans serait une seconde copie susceptible de diverger de celle que
l'humain a signée, et l'identité d'un plan dans ce produit est son empreinte,
jamais une clé de rangement.

**La définition voyage avec sa porte, dans les deux sens.** La requête porte la
définition exactement quand l'opération de la paire est l'une des deux de la
troisième porte ; une définition à côté de toute autre opération est refusée, et
une opération de cette porte sans définition est refusée en nommant la révision
manquante. C'est la règle de l'entrée de l'Auxiliaire, mot pour mot, tenue une
deuxième fois — le Controller ne se croit pas lui-même, et son gel antérieur
n'est pas une preuve.

**La séquence est consommée durablement avant qu'un octet parte.** C'est la
propriété centrale du maillon, et elle est écrite en une phrase : un
redémarrage entre la réception et le lancement ne rejoue rien. Le
Controller écrit son enregistrement de dispatch — écriture atomique dans un
état root-owned de son répertoire d'état, sur le patron des états existants —
puis ouvre la connexion, jamais l'inverse.

Ce registre **n'est pas une copie de l'état anti-rejeu de la machine**, et les
deux répondent à deux questions différentes :

- l'état de la machine répond « cette machine a-t-elle déjà dépensé cette
  séquence ? » et il est l'autorité, parce qu'il vit à côté des effets ;
- le registre du Controller répond « ces octets signés ont-ils déjà été
  lancés ? » et il est nécessaire parce que sans lui, un Controller qui
  redémarre entre la réception et l'écriture du wrapper relancerait légitimement
  la même intention humaine. Une approbation est une autorité à un coup, sur le
  Controller comme sur la machine.

**Le registre est indexé par l'identité de l'approbation signée**, c'est-à-dire
l'empreinte de ses octets, et jamais par le numéro de séquence. La distinction
est utile plutôt que subtile : rejouer les mêmes octets est refusé, tandis que
**réapprouver le même numéro** après un lancement qui n'a rien atteint reste
possible — et c'est exactement ce qu'un humain doit pouvoir faire quand la
machine n'a rien consommé.

**Rien n'est consommé par une soumission refusée.** Le registre s'écrit après
la vérification complète et avant la connexion ; une requête refusée n'y laisse
aucune trace, sans quoi un attaquant sans clé pourrait brûler les séquences
d'une machine en soumettant des ordures.

Les refus de cette route forment une liste fermée. Chacun est un nom, et chaque
nom porte une phrase dans la Console :

| Refus | Ce qu'il constate |
|---|---|
| `invalid_request` | la requête n'est pas la forme fermée : champ inconnu, borne dépassée, document illisible |
| `machine_not_active` | la machine n'est pas attachée à l'inventaire de ce Controller |
| `approval_signature_invalid` | la signature ne vérifie pas sous la clé publique d'approbation de cette association |
| `approval_expired` | l'enveloppe a dépassé sa durée de vie |
| `approval_pair_mismatch` | les octets de la paire ne rendent pas les deux empreintes que l'enveloppe signe |
| `approval_definition_mismatch` | la définition manque, est en trop, ou ne rend pas l'empreinte que le plan épingle |
| `approval_already_dispatched` | ces octets signés ont déjà été lancés une fois |
| `approval_sequence_invalid` | la séquence n'est pas celle que ce Controller peut attester comme successeur |

Le dernier refus mérite sa précision : le Controller vérifie ce qu'il **sait**,
et la machine reste seule autorité. Un désaccord entre les deux n'est jamais
résolu par le Controller ; il est rapporté.

### Décision tranchée : les statuts viennent de la taxonomie existante, pas d'une convention nouvelle

La question n'était pas « quel statut est joli » mais « qu'est-ce que ce paquet
dit déjà ». La réponse a été relue route par route dans
`internal/controller`, et elle est régulière :

| Classe | Statut existant | Ce que le paquet en fait déjà |
|---|---|---|
| requête malformée, champ inconnu, borne dépassée | `400 invalid_request` | 39 emplois, toutes routes |
| requête bien formée dont la **sémantique** est refusée | `422` | `machine_not_active`, `label_invalid` |
| conflit avec un **état durable** | `409` | `state_conflict` |

Les refus de cette route s'y rangent sans inventer :
`approval_signature_invalid`, `approval_expired`, `approval_pair_mismatch`,
`approval_definition_mismatch` et `approval_sequence_invalid` sont des requêtes
bien formées dont l'autorité échoue à sa propre vérification, donc `422` ;
`approval_already_dispatched` est le seul conflit qu'un état durable puisse
nommer, donc `409`. Il porte un **nom propre** plutôt que le `state_conflict`
générique, parce que le parcours utilisateur exige que chaque refus soit une
phrase actionnable qui nomme la suite — et « ces octets ont déjà été lancés »
ne se dit pas comme « l'inventaire a bougé sous vos pieds ».

**La clé publique humaine n'est pas relue depuis le document.** Elle vient de
l'enregistrement d'appareil du magasin d'autorité, où sa forme canonique est
déjà tenue à l'enrôlement : `validateDeviceRecord` refuse tout enregistrement
dont `human_public_key` n'est pas exactement une clé Ed25519 encodée. Un
enregistrement actif porte donc toujours une clé décodable, et la branche qui
répond `503 controller_state_unavailable` si le décodage échoue est une garde de
cohérence d'état, pas un chemin métier : elle est conservée parce qu'une
autorité illisible ne doit jamais se lire comme une signature invalide.

**La liste fermée est celle des refus *métier* ; les codes de transport
existants la complètent sans l'élargir.** Cette route peut aussi répondre
`401 authentication_failed`, `403 scope_forbidden`, `405 method_not_allowed`,
`406 not_acceptable`, `413 request_too_large`, `415 unsupported_media_type`,
`429 rate_limited` et `503 controller_state_unavailable` — tous déjà servis par
les routes métier existantes, aucun nouveau. C'est la même phrase que
`SERVICE-UTILISATEUR.md` : « aucun nouveau code d'erreur ».

### Décision tranchée : sans moteur, la porte n'existe pas

`#125` livre la réception, la vérification et la consommation durable ; le
lancement est `#126`. Un Controller qui recevrait une approbation qu'il ne peut
pas lancer **dépenserait durablement une autorité humaine pour rien** — ce que
le contrat n'accepte que pour une clé d'hôte changée, que le Controller a
*observée*, jamais comme condition permanente d'un binaire.

La garde est donc structurelle plutôt que documentaire : le moteur est **attaché
explicitement** (`AttachAuxiliaryDispatcher`, une fois, jamais `nil`), et tant
qu'aucun ne l'est, **les deux routes n'existent pas** — ni dans le routage, ni
dans la table des méthodes, qui lisent le même champ et ne peuvent donc pas
annoncer une porte qui ne s'ouvre pas. Un Controller sans moteur répond
`404 route_not_found`, jamais `405`, et n'écrit pas un octet dans le registre.

Conséquence tenue : le moteur immobile qui conclut `non lancé` est une **couture
de test**, il vit dans un fichier de test, et aucun fichier de production ne peut
le nommer. `#126` attache le lancement OpenSSH borné à la ligne exacte où rien
n'est attaché aujourd'hui, et les deux routes apparaissent avec lui.

## Maillon 4 — Lancer : l'identité de commande, l'hôte épinglé, le client borné

### L'identité de commande est l'identité d'administration Your Cloud, et elle naît sur le Controller

Le glossaire nomme déjà cette autorité — **identité d'administration Your
Cloud** : un accès SSH opérationnel propre à une machine, détenu par son
Controller, limité au lancement de l'Auxiliaire pour un plan approuvé. Ce
contrat ne crée pas un terme de plus ; il tranche **qui la fabrique** et **où
elle vit**.

- **Le Controller la génère, à l'enrôlement, une paire par machine.** Le
  contrat d'amorçage l'écrit déjà (« fait générer sur le Controller une identité
  SSH différente par cible ») et la moitié qui juge le résultat existe : elle ne
  reçoit que des empreintes, refuse une empreinte que personne n'a frappée, et
  refuse la clé d'une machine sur une autre. Ce qui manquait est la frappe
  elle-même.
- **Les alternatives sont écartées pour la même raison.** Que l'Assistant
  génère la paire mettrait la moitié privée sur le portable d'administration, à
  côté d'un accès personnel que le produit s'interdit justement de conserver ;
  que la machine la génère et remonte sa moitié privée est le contraire d'une
  identité. Le Controller la génère, garde la moitié privée, et ne remet à
  l'Assistant que la moitié publique et son empreinte.
- **Ed25519 et rien d'autre.** C'est déjà le seul algorithme que l'entrée
  `authorized_keys` accepte : le Controller frappe ces paires lui-même, il n'y a
  aucune clé héritée à accommoder, et un second algorithme accepté ne serait
  qu'une seconde chose à rater.

### Où la moitié privée vit : un credential, comme les trois credentials TLS

L'unité du Controller charge aujourd'hui trois credentials TLS root-owned et
tourne sous `DynamicUser=yes` avec `ProtectHome=yes`. **Les identités de
commande empruntent le même chemin, par une seule ligne de plus, qui nomme un
répertoire et jamais une machine** :

```text
LoadCredential=command-identities:/etc/your-cloud/command-identities
```

- **Un répertoire plutôt qu'une ligne par machine, parce que l'unité est
  livrée par le paquet et que le paquet ne connaît aucune machine.** Le paquet
  ne porte « ni configuration propre à une machine, ni secret, ni identité » :
  une unité qui nommerait 64 machines violerait cette phrase. Un répertoire
  root-owned dont chaque entrée est nommée par un identifiant de machine la
  respecte, et l'ensemble est copié dans le répertoire privé de credentials du
  service à son démarrage, puis disparaît avec lui.
- **`DynamicUser` et `ProtectHome` sont ici une propriété, pas une
  contrainte.** Le Controller n'a ni foyer, ni `~/.ssh`, ni configuration
  utilisateur : chaque entrée du client SSH doit être un chemin explicite sous
  le répertoire de credentials ou sous le répertoire d'exécution. Il n'existe
  aucun endroit d'où une identité pourrait être ramassée par défaut.
- La moitié privée **ne quitte jamais le Controller** et n'entre dans aucun
  document, aucun rapport, aucune observation. Le service et `root` peuvent
  nécessairement la lire ; cette protection réduit l'exposition aux autres
  comptes, elle ne protège pas d'une compromission complète du Controller — la
  limite déjà écrite pour les clés opérationnelles, inchangée.

### Où l'adresse et la clé d'hôte vivent : une fiche d'endpoint, hors de l'inventaire

L'inventaire du Controller ne porte aujourd'hui qu'un identifiant et une
étiquette par machine. Ce contrat **ne l'élargit pas** : l'adresse, le port SSH,
le compte et la clé d'hôte attendue d'une machine vivent dans une **fiche
d'endpoint de commande** root-owned, écrite par l'Assistant à l'enrôlement — au
même endroit et sous la même propriété que le fichier d'environnement de la
machine et que les credentials.

La raison est une frontière et non un rangement : **l'inventaire est lisible et
modifiable par la Console**, et une adresse que la Console pourrait réécrire
serait une Console qui choisit où part une commande. La Console nomme une
machine ; elle ne nomme jamais un endpoint.

- **La clé d'hôte est épinglée à l'enrôlement, jamais apprise du réseau.**
  Elle vient de l'étape d'observation que l'humain a confirmée pendant l'audit,
  exactement comme pour l'accès personnel : le client qui authentifie ne
  transforme jamais un premier contact en confiance.
- **Le fichier `known_hosts` est dérivé de la fiche à chaque lancement**, écrit
  dans le répertoire d'exécution du service (`0700`, effacé avec le service), et
  il ne contient que la machine visée. Rien ne l'écrit à part le Controller, et
  rien n'y ajoute une ligne apprise.
- **Une clé d'hôte qui a changé est un refus nommé avant tout octet de
  wrapper.** Le dispatch est enregistré `non lancé`, la séquence est dépensée,
  aucun effet n'a eu lieu, et la reprise appartient à l'humain — jamais à une
  réparation.

### Le client : le client OpenSSH, borné option par option

**Le Controller lance le client OpenSSH de la distribution plutôt qu'une pile
SSH embarquée en Go.** Le choix mérite sa justification, parce que le contrat
d'amorçage a écarté l'exécutable `ssh` pour l'Assistant.

- Ce qui a écarté `ssh` là-bas ne s'applique pas ici : la passphrase serait
  sortie de la mémoire protégée et le budget de signatures aurait été perdu.
  Ici, **aucun secret ne traverse la ligne de commande**, aucune passphrase
  n'existe — la clé opérationnelle n'attend pas d'humain, parce que le
  Controller doit rester autonome quand la Console est fermée — et il n'y a
  aucun budget d'agent à tenir, puisqu'il n'y a pas d'agent.
- Embarquer une bibliothèque SSH en Go ferait porter au composant qui détient
  **toutes** les identités de la flotte une implémentation de protocole et une
  politique de clé d'hôte que le produit devrait posséder et prouver.
- L'autre extrémité est déjà OpenSSH : `sshd`, la commande forcée et les
  restrictions de l'entrée ont été prouvées contre un vrai `sshd`, et les
  options du client de la même suite sont celles que le LAB sait relire.
- **Risque résiduel nommé** : la version du client et ses défauts compilés
  appartiennent à la distribution. Le produit borne ce qu'il passe, pas ce
  qu'OpenSSH est ; `-F /dev/null` écarte la configuration de l'utilisateur *et*
  celle du système, et l'absence de foyer écarte le reste.

Les options sont une liste positive, et chacune retire quelque chose :

| Option | Ce qu'elle retire |
|---|---|
| `-F /dev/null` | toute configuration lue ailleurs que dans cette ligne |
| `-o IdentitiesOnly=yes` | toute identité que le produit n'a pas nommée |
| `-o IdentityAgent=none` | tout agent, donc tout oracle de signature |
| `-o BatchMode=yes` | toute question posée à un humain qui n'est pas là |
| `-o StrictHostKeyChecking=yes` | toute confiance au premier contact |
| `-o UserKnownHostsFile=<runtime>`, `-o GlobalKnownHostsFile=/dev/null` | tout hôte connu d'ailleurs |
| `-o NumberOfPasswordPrompts=0` | tout repli sur un mot de passe |
| `-o ClearAllForwardings=yes`, `-o RequestTTY=no` | tout transfert et tout terminal |
| `-o ConnectTimeout=10` | l'attente indéfinie d'une machine éteinte |
| aucune commande distante | tout choix de ce qui s'exécute : la commande forcée décide |

**Les deux attentes sont bornées séparément, et la seconde est dérivée.**

- La connexion et l'authentification sont bornées serré, à dix secondes : rien
  n'a encore été écrit, et dépasser signifie une machine injoignable — un refus
  avant octets.
- L'exécution n'est pas bornée par un nombre choisi : elle est bornée par **la
  durée de vie restante de l'approbation qui la permet**, dont le plafond est
  déjà une constante du produit (`approval.MaxLifetimeSeconds = 900`). Un
  lancement qui courrait plus longtemps que l'autorité qui l'a permis n'aurait
  plus rien pour se justifier. La borne est donc dérivée d'un fait existant,
  jamais d'un goût.

**Décision tranchée : le plafond contractuel est l'autorité, tout délai interne
en est dérivé et lui est strictement inférieur.** La règle tient en trois
phrases et elle est vérifiable :

1. **L'échéance de tout le lancement est `expires_at` de l'enveloppe**, pas une
   durée. La soumission n'a été acceptée que parce que `maintenant <
   expires_at`, et la durée de vie de l'enveloppe est elle-même bornée à 900 s à
   sa construction : le reste à courir est donc au plus 900 s, et strictement
   moins dès qu'une seconde s'est écoulée entre la signature et la soumission.
   Aucun nombre n'est écrit à côté du plafond : c'est le plafond, moins ce qui a
   déjà été consommé.
2. **`ConnectTimeout` est un sous-délai de celui-là**, jamais un délai qui s'y
   ajoute : il vaut `min(10, reste à courir)`. Une approbation dont il reste
   quatre secondes ne s'autorise pas dix secondes de connexion — l'attente ne
   dépasse jamais l'autorité, même dans le cas de bord.
3. **L'expiration rend « lancé, non rapporté », jamais un échec et jamais un
   retry.** Le canal fermé n'arrête pas la machine : l'Auxiliaire est un
   processus `root` sur sa propre machine, il finit ou échoue seul. Renoncer à
   attendre, c'est renoncer à *entendre*. Seule l'expiration **avant le premier
   octet du wrapper** rend `non lancé`, parce que là le Controller a réellement
   observé qu'il n'avait rien envoyé.

Aucun délai de ce chemin ne peut donc être relevé sans relever le plafond
contractuel, et relever le plafond contractuel est une décision d'un autre
document.
- **Fermer le canal n'arrête pas la machine, et le contrat le dit.**
  L'Auxiliaire est un processus `root` sur sa propre machine : il finit ou il
  échoue tout seul. Renoncer à l'attendre, c'est renoncer à *entendre*, jamais
  défaire. L'état produit est donc « lancé, non rapporté », et surtout pas un
  échec qui laisserait croire que rien n'a eu lieu.

### Ce qui part sur l'entrée standard

Le wrapper existant, inchangé : `signed_approval`, `plan`, `rollback`, et
`definition` quand la porte l'exige. Il est borné par le paquet qui le possède —
`1024 + 2 × 4096 + 8192 + 1024 = 18432` octets — et le Controller n'écrit jamais
au-delà : une entrée que la machine refusera par sa borne est un octet qu'il ne
sert à rien d'envoyer.

**L'ordre des effets est le contrat**, et il se lit de haut en bas :

1. vérifier entièrement la soumission ;
2. écrire durablement l'enregistrement de dispatch, en `en cours` ;
3. dériver le `known_hosts` et ouvrir la connexion bornée ;
4. écrire le wrapper sur l'entrée standard ;
5. lire le rapport, la sortie d'erreur bornée et le code de sortie ;
6. écrire durablement l'état terminal.

Rien de cette liste n'est réessayé, et le point 2 précède le point 3 pour la
raison écrite plus haut.

## Maillon 5 — Rapporter : le rapport est la conclusion de la machine

**Le rapport revient par le canal que le Controller a ouvert**, sur la sortie
standard de la commande forcée. Il n'existe donc **aucune route entrante
nouvelle** et aucun écouteur de plus sur une machine : ce qui manquait n'était
pas un chemin de retour, c'était quelqu'un pour lire celui qui existait déjà.

**Le rapport voyage en JSON, et c'est ce que la commande forcée impose.**
L'entrée `authorized_keys` est comparée octet pour octet et n'accepte aucun
argument libre : le Controller ne peut pas demander un format. Or un rapport
que doit lire un autre programme ne peut pas être un rendu destiné aux yeux
d'un humain, et analyser une présentation serait précisément le couplage que ce
produit évite partout ailleurs. **Le format par défaut de l'Auxiliaire devient
donc JSON** ; le rendu en lignes survit derrière `--format=text` pour l'humain
qui lance l'Auxiliaire à la main sur sa machine, et les deux rendus restent la
même structure fermée, si bien qu'aucun champ ne peut exister dans l'un et
manquer dans l'autre. La commande forcée, la règle `sudo` et le compte ne
bougent pas d'un octet — c'est tout l'intérêt de déplacer le défaut plutôt que
l'invocation.

**La bascule a été tranchée sur une mesure, avant `#127` et non après.** Deux
faits ont été relus dans le dépôt plutôt que supposés :

- **la commande forcée ne porte aucun format** : `forced_command()` rend
  exactement `/usr/bin/sudo -n /usr/lib/your-cloud/your-cloud auxiliary approve`,
  la règle `sudo` autorise cette invocation-là et le module de jugement refuse
  toute entrée qui ne lui est pas égale octet pour octet — les variantes portant
  `--format=json` sont d'ailleurs des cas *hostiles* de sa suite de tests. Le
  Controller ne peut donc pas demander JSON ; le défaut est le seul levier ;
- **aucun harnais existant ne consomme le rendu en lignes.** Les vingt-quatre
  invocations de `auxiliary approve` des suites LAB passent `--format=json`
  partout où un rapport est lu ; les rares invocations sans `--format` sont
  toutes des cas de **refus**, où l'Auxiliaire sort en échec avant tout rendu et
  n'écrit qu'une phrase sur le canal d'erreur, que les harnais filtrent par
  sous-chaîne. Basculer le défaut ne change donc la sortie d'aucune preuve
  existante, et le contraire aurait été une raison de repousser la bascule.

**Un refus ne rend aucun rapport, et c'est ce qui l'empêche de se lire comme une
opération qui a agi.** Une machine qui refuse sort en échec et écrit une phrase
sur le canal d'erreur. Le Controller lit cette phrase, bornée et expurgée, la
conserve telle quelle et **ne la paraphrase pas** : une phrase que le produit
n'a pas écrite n'est jamais réécrite en une phrase qu'il aurait écrite. Elle est
montrée à l'humain entre guillemets, à côté de la phrase du produit qui dit quoi
faire.

**L'ingestion refuse tout ce qui ne nomme pas ce dispatch.** Les refus sont
nommés et l'état reste honnête :

| Refus du rapport | Conséquence |
|---|---|
| l'infrastructure ou la machine ne sont pas celles du dispatch | rapport écarté ; état `lancé, non rapporté` |
| l'opération n'est pas celle de l'enveloppe | rapport écarté ; état `lancé, non rapporté` |
| la séquence consommée n'est pas celle de l'enveloppe | rapport écarté ; état `lancé, non rapporté` |
| les deux empreintes ne sont pas celles de la paire | rapport écarté ; état `lancé, non rapporté` |
| aucun rapport, ou un document illisible, ou un dépassement de borne | état `lancé, non rapporté` |

Un rapport écarté ne devient jamais un échec : le Controller ne sait pas ce que
la machine a fait, et il le dit. C'est la règle du produit — « après une
coupure, rendre `résultat inconnu`, ne rien rejouer et observer avant tout
nouveau plan » — appliquée au maillon qui lui manquait.

### Les états d'un dispatch, et ce qu'ils valent

| État | Ce qu'il constate | Transition de `QUALITE.md` |
|---|---|---|
| `en cours` | l'enregistrement est écrit ; le reste est en train de se produire | `en cours` |
| `non lancé` | la connexion a échoué avant le premier octet du wrapper, et le Controller l'a **observé** | `échoué`, sans effet |
| `refusé par la machine` | sortie en échec sans rapport : la machine a refusé et dit pourquoi ; elle n'a rien changé | `échoué`, sans effet |
| `rapporté` | un rapport valide a été lu ; il porte `changed`, l'issue, le rollback éventuel et ce qui survit | `réussi` ou `échoué`, selon le rapport |
| `lancé, non rapporté` | tout le reste | `résultat inconnu` |

Deux décisions se lisent dans ce tableau.

- **`en attente` n'est pas un état du Controller.** Une paire construite et pas
  encore approuvée vit dans la Console, et le Controller n'en garde rien —
  conséquence directe du fait qu'il ne stocke aucune paire. L'histoire d'un plan
  commence à son approbation.
- **Un enregistrement trouvé en `en cours` au démarrage devient
  `lancé, non rapporté`, durablement, avant que le Controller serve quoi que ce
  soit.** Il n'est jamais repris, jamais relancé. Après une coupure, le
  Controller ne peut pas distinguer « rien n'est parti » de « quelque chose est
  parti » : il dit donc le plus faible des deux. `non lancé` est réservé à ce
  qu'il a réellement vu.

### La position de commande d'une machine, et son incertitude

La Console doit signer le **successeur exact** de la séquence de la machine.
Elle l'apprend du Controller : la vue des machines gagne deux champs en lecture
seule — la dernière position que la machine a elle-même **rapportée**, et si
cette position est certaine. Aucune route nouvelle.

Après un dispatch non rapporté, la position est **incertaine**, et le produit le
dit plutôt que de deviner : la machine peut avoir consommé ou non.

**Décision tranchée, et c'est bien le contrat : la reprise coûte au plus une
approbation humaine *gaspillée*, en plus de celle que l'opération demandait de
toute façon.** Le compte se fait pas à pas :

1. l'humain approuve à la position que le Controller connaît — celle qu'un
   rapport valide a nommée, et rien d'autre ;
2. si la machine n'était pas passée, cette approbation est la bonne : le coût
   supplémentaire est **nul** ;
3. si la machine était déjà passée, elle refuse en nommant **sa** position dans
   sa propre phrase, cette phrase est montrée sans être réécrite, et l'humain
   réapprouve à la position nommée. Cette seconde approbation aboutit, parce que
   la position n'est plus une supposition.

Le coût est donc borné à **une** approbation perdue, jamais deux, et la borne
tient à une propriété précise : le refus de la machine *nomme* sa position. Elle
ne tiendrait plus si le refus disait seulement « non ». C'est aussi pourquoi la
limite honnête écrite plus bas — le Controller n'analyse pas cette phrase — est
supportable : elle coûte une approbation dans un cas rare, pas une divergence.

L'approbation perdue est **dépensée des deux côtés** et cela est voulu : sur le
Controller, son enregistrement conclut `refusé par la machine` ; sur la machine,
rien n'a été consommé et rien n'a changé. Rien n'est deviné, rien n'est réessayé
automatiquement, et un refus de séquence n'a jamais d'effet.

C'est aussi une limite honnête de ce palier : le Controller **n'analyse pas** la
phrase de refus de la machine. Rendre ce refus lisible par un programme
demanderait à l'Auxiliaire un document de refus fermé, ce que ce palier
n'ajoute pas — le coût actuel, une approbation supplémentaire dans un cas rare,
ne le justifie pas encore.

### La projection : l'histoire d'un plan, et la dette « instances » soldée

La Console lit l'histoire bornée des dispatchs et la rend en phrases :
**construit → approuvé → lancé → rapporté**, avec ses instants, son état et ce
que la machine a répondu. Un état `lancé, non rapporté` est affiché comme tel,
jamais comme un échec ni comme un succès.

**Décision tranchée : le texte de la rétro-référence est fixé maintenant, déposé
à l'atterrissage de `#127`.** `SERVICE-UTILISATEUR.md` porte deux constats
d'absence que ce palier lève ; le jour où `#127` atterrit, ses deux puces
« limites nommées » sont remplacées par celles-ci, mot pour mot, et par rien
d'autre :

> - **`RequireDefinitionAgreement` est miroité depuis `v0.1.2`.** C'était la
>   seconde dette de `#118`, conditionnée à ce que la Console tienne une
>   définition à côté d'un plan. Elle la tient depuis `#123`–`#124` : la Console
>   lit la paire, lit la révision épinglée et soumet les deux. Le contrôle
>   croisé est désormais tenu quatre fois — construction par le Controller,
>   miroir Rust avant l'ouverture de la fenêtre, revérification par le Controller
>   à la soumission, revérification par l'Auxiliaire — et le contrat de ce
>   trajet est [`TRAJET-DE-COMMANDE.md`](TRAJET-DE-COMMANDE.md).
> - **Les instances sont affichées depuis `v0.1.2`, et depuis un rapport.** La
>   projection que ce palier n'avait pas écrite est
>   `GET /v0/plan-dispatches` : un rapport de `deploy_user_service` nomme la
>   machine, le slug et la révision que le plan approuvé épingle, un rapport de
>   `remove_user_service` nomme ce qui survit. La vue Services rend donc la
>   révision que chaque instance court **depuis ce que la machine a rapporté**,
>   jamais depuis une supposition ; une instance dont le dernier dispatch n'a pas
>   été rapporté, ou dont l'enregistrement est sorti de l'histoire bornée, est
>   affichée avec son incertitude et non avec un état inventé. Le câblage
>   plan → UI que `v0.1.0` avait laissé ouvert est fermé par la vue Plans de
>   `#124`.

**La dette « instances » de la vue Services se solde ici, et sa phrase est
amendée pour dire exactement ce qu'elle fait.** `SERVICE-UTILISATEUR.md`
constatait que rien ne projette quelle machine exécute quelle révision.

La formulation initiale — « la révision vient du rapport » — décrivait quelque
chose qui n'existe pas : **le rapport de l'Auxiliaire ne nomme ni le slug ni la
révision**, vérifié champ par champ. La phrase juste est celle-ci :

> **La révision vient du plan approuvé, et le fait que l'instance la court vient
> du rapport.**

Les deux provenances sont distinctes et le restent à l'écran. Ce que chacune
vaut :

- **la révision** est enregistrée à la soumission, prise dans le plan que ce
  Controller vient de parser, jamais dans la requête. Le couple (définition,
  empreinte que le plan épingle) est tenu deux fois avant d'être stocké — par ce
  Controller à la soumission, par l'Auxiliaire depuis les octets de la
  définition avant de toucher la machine. C'est un fait vérifié, pas une
  déclaration ;
- **le fait qu'elle court** vient du rapport, et de lui seul : une instance dont
  le dernier dispatch n'a pas été rapporté est affichée avec son incertitude
  plutôt qu'avec un état inventé.

**Pourquoi la révision ne vient pas du rapport, alors que ce serait « plus
fort ».** Elle ne le serait pas. Le rapport est émis au moment de l'application :
il ne ferait que répéter la révision du plan qu'il vient lui-même de vérifier.
Ce n'est pas une observation indépendante. Élargir le document le plus sensible
du produit — celui que l'Auxiliaire écrit, déjà contracté et prouvé — pour une
valeur probante quasi nulle de plus serait payer cher une illusion.

**La limite, en toutes lettres, avec sa porte de sortie.** Une modification faite
hors du produit après le dispatch n'est visible par **aucune** de ces deux
provenances, et ne le serait pas davantage par un rapport. Seule une
**observation** la verrait, et ce palier n'en ajoute aucune. C'est la distinction
`déclaré` contre `vérifié` que le produit fait déjà ailleurs : la vue accueillera
une colonne observée le jour où un palier en apportera une, sans qu'une ligne de
celle-ci soit réécrite.

**L'écran ne fusionne jamais les deux en une seule affirmation.** La révision et
le fait qu'elle court gardent chacune leur origine lisible ; un écran qui les
mélangerait laisserait croire qu'une machine a été observée alors qu'elle a été
approuvée.

## Le parcours utilisateur est un critère de ce contrat

La contrainte « user-friendly » de la milestone n'est pas un vœu : ce sont cinq
phrases, et chacune est vérifiable.

1. **L'humain lit des phrases, jamais un document.** Chaque écran du trajet
   rend les phrases dérivées ; les octets canoniques restent atteignables
   derrière un geste explicite (« voir les octets exacts »), jamais comme forme
   par défaut. Vérifiable par le contrat de source de la Console.
2. **Aucune empreinte sans la phrase qui la porte.** Une empreinte affichée est
   la fin d'une phrase. La fenêtre native le tient déjà par construction, et
   `validate` le refuse autrement.
3. **Chaque refus est une phrase actionnable qui nomme la suite.** Chaque nom
   de la liste fermée des refus possède sa phrase, et le contrat de source
   rougit si un nom perd la sienne — le patron déjà tenu pour les refus de
   définition.
4. **Déployer depuis une définition gelée n'exige d'assembler aucun document.**
   Depuis la vue Services, « Déployer » mène au plan construit, puis à la
   fenêtre, puis à la signature : sans un collage, sans une empreinte tapée,
   sans un champ recopié. C'est un parcours que la preuve exécute, pas une
   intention.
5. **Ce que la machine a répondu est montré, jamais paraphrasé.** La phrase du
   produit dit quoi faire ; la phrase de la machine est citée à côté.

## Surface du Controller étendue de deux routes

`PROFIL-PUBLIC-BENTOPDF.md`, `PASSAGE-PRIVE-WIREGUARD.md`,
`PROFIL-PRIVE-VAULTWARDEN.md`, `RESPONSABILITE-EXTERNE.md` puis
`SERVICE-UTILISATEUR.md` ont étendu la surface métier du Controller de trois,
trois, quatre, trois puis trois routes. Le présent contrat l'étend de **deux**,
et d'aucune autre — une seule peut faire partir un octet vers une machine :

| Méthode et route | Effet autorisé |
|---|---|
| `POST /v0/plan-approvals` | recevoir une approbation signée avec les octets de sa paire, et la définition quand la porte l'exige ; la revérifier entièrement, consommer durablement le dispatch, puis lancer l'Auxiliaire de la machine visée et lire ce qu'il répond |
| `GET /v0/plan-dispatches` | lire l'histoire bornée des dispatchs — état, instants, empreintes, ce que la machine a rapporté ou répondu — sans en muter ni en omettre un |

**Décision tranchée : ces deux noms sont confirmés, et la régularité est le
motif.** Le contrat proposait `POST /v0/plan-approvals` et
`GET /v0/plan-dispatches` ; la relecture de la surface existante les confirme
plutôt que de les amender.

- **Ils sont orientés ressource, au pluriel, sans verbe**, comme les vingt et
  une routes déjà livrées : `/v0/machines`, `/v0/external-elements`,
  `/v0/service-definitions`, les douze `*-plans`. Une approbation de plan et un
  dispatch de plan sont deux ressources, nommées par ce qu'elles sont.
- **Nominaliser un acte est déjà la maison** : `/v0/external-element-withdrawals`
  est un retrait devenu ressource, et non un `DELETE` sur la collection voisine.
  Ce dépôt donne à chaque acte son propre chemin nominal plutôt que d'empiler
  les méthodes sur une collection, et ces deux noms suivent cette règle.
- **L'alternative sérieuse a été considérée** : `POST` *et* `GET` sur la seule
  collection `/v0/plan-dispatches`, puisque ce qu'une soumission crée est un
  dispatch. Elle est écartée pour la raison qui compte ici : la porte qui fait
  sortir un octet doit se **compter** dans la table des chemins, pas se déduire
  d'une table de méthodes. Deux chemins disent « POST seul lance, GET seul
  lit » dans le routage lui-même ; un seul chemin l'aurait dit dans le
  gestionnaire.
- **Ils restent réguliers avec ce qui vient** : `/v0/dns-records` visé en
  `v0.1.3+` et les sauvegardes gérées visées en `v0.2.0` se rangent dans le même
  espace `/v0/` sans lui imposer une convention nouvelle.

Décisions attachées à ces routes :

- Elles empruntent la **même authentification de session** que les routes
  métier existantes : aucun nouveau chemin d'autorité, aucun nouveau code
  d'erreur hors de la liste fermée nommée plus haut et des codes de transport
  partagés énumérés avec elle.
- **`POST /v0/plan-approvals` est la seule route du produit dont l'effet sort de
  la machine du Controller.** Elle est unique volontairement : une seconde route
  capable de lancer serait une seconde politique à tenir, et la première chose
  qu'un lecteur doit pouvoir compter est le nombre de portes.
- **Aucune route ne relance, ne réessaye ni n'annule un dispatch.** Il n'existe
  pas de `DELETE`, pas de `retry`, pas de `resume` : la reprise après un
  résultat inconnu est une observation puis un nouveau plan signé, et une route
  qui prétendrait faire mieux serait une route qui ment.
- **La Console ne choisit ni l'adresse, ni le port, ni la clé d'hôte, ni
  l'identité, ni l'ordre.** Elle nomme une machine et remet des octets signés ;
  tout le reste est un fait de l'enrôlement que le Controller lit sur son
  disque.
- **Les gardes d'imports existants ne sont pas relâchés.** Deux tests tiennent,
  fichier par fichier, que le chemin d'une définition gelée et celui d'un
  élément externe ne peuvent atteindre ni `internal/plan`, ni
  `internal/approval`, ni `internal/auxiliary` : geler et déclarer n'ont aucun
  effet, et la façon la plus forte de le dire est que le code qui gèle ne peut
  pas atteindre ce qui agit. Le fichier de la nouvelle route est le **seul** du
  paquet à qui `internal/approval` est ouvert, et les deux gardes restent en
  place tels quels.
- L'état des dispatchs suit le patron des états existants : un fichier
  root-owned à écriture atomique, où les enregistrements s'ajoutent et où rien
  ne s'efface. Il est borné, et **la borne est dérivée d'une mesure** plutôt
  que choisie ronde ; elle est détaillée juste après.

### Décision tranchée : la borne de l'historique, dérivée d'une mesure

Trois bornes, et chacune se lit contre un fait mesuré du dépôt.

| Borne | Valeur | Ce dont elle est dérivée |
|---|---|---|
| phrase d'une machine | 512 octets | le plus long refus littéral de `internal/approval` et `internal/auxiliary` mesure 103 octets ; une chaîne enveloppée portant une erreur système qui nomme un chemin du produit reste sous 400. Puissance de deux au-dessus |
| observation du Controller | 256 octets | le produit les écrit lui-même, depuis un ensemble fermé ; la plus large mesure 94 octets |
| enregistrements par machine | 32 | la machine la plus chargée de la preuve `v0.1.1` traverse une trentaine de dispatchs en une exécution (`play-removal` en conduit 11, `play-refusals` 8, `play-lifecycle` 7). Puissance de deux au-dessus |
| fichier entier | 8 Mio | 64 machines — la borne de l'inventaire — × 32 enregistrements × **2 220 octets**, taille mesurée du pire enregistrement encodé, plus l'en-tête : 4 546 707 octets. Puissance de deux au-dessus |

Quatre propriétés sont attachées à ces nombres, et chacune est une décision :

- **la borne du fichier ne peut jamais refuser un historique légitime.** Elle
  est au-dessus du produit complet des bornes précédentes, si bien qu'une
  approbation valide ne peut pas être refusée parce qu'une histoire était
  pleine. Une borne de fichier plus serrée que son propre contenu maximal
  serait un refus qui n'a rien à voir avec l'autorité soumise ;
- **elle est vérifiée plutôt qu'affirmée.** La suite de tests construit
  l'historique le plus plein que l'élagage puisse conserver — toutes les
  machines, tous les enregistrements, les deux champs libres à leur borne et
  composés du caractère que l'encodage double — puis l'encode contre la borne.
  Une arithmétique de commentaire qui dériverait deviendrait rouge ;
- **les deux champs libres sont refusés dans `validate`**, jamais tronqués au
  rendu, et un enregistrement ne peut pas porter les deux à la fois : l'un est
  une phrase que le produit n'a pas écrite, l'autre est son propre compte rendu
  de sa propre tentative, et un lecteur doit pouvoir dire lequel il lit ;
- **la limite est nommée plutôt qu'évitée.** Une machine qui dépasse 32
  dispatchs perd ses plus anciens de l'histoire que la Console lit ; les effets,
  eux, restent sur la machine. Une instance dont le dernier dispatch rapporté
  est sorti de l'histoire est affichée **révision inconnue**, jamais avec une
  révision devinée. Aucun enregistrement non terminal ne sort jamais : un
  dispatch ouvert ne peut pas être oublié.

Enfin, ces nombres sont faits pour être **relevés par mesure sans changer de
format** : ce sont des constantes du document, pas des champs ; une observabilité
qui grandira demain (fraîcheur, historique plus long) relèvera la rétention et la
borne du fichier sans qu'un seul lecteur existant cesse de lire.

## Ce que ce palier ne fait pas

- **Aucune reprise, aucune continuation.** Un dispatch interrompu n'est jamais
  relancé, ni par le Controller, ni par la machine, ni par un redémarrage.
- **Aucune concurrence sur une machine.** Une machine a une position de
  séquence, donc une commande à la fois. Deux soumissions concurrentes pour la
  même machine sont deux approbations, et une seule peut être le successeur —
  la seconde est refusée sans effet, comme l'Auxiliaire refuse déjà deux
  processus simultanés.
- **Aucun ordonnancement, aucune planification.** Il n'existe ni file, ni
  différé, ni fenêtre de maintenance. Un plan part quand un humain vient de
  l'approuver.
- **Aucune rotation d'identité de commande.** Frapper de nouvelles identités
  appartient au remplacement du Controller, contrat existant et inchangé.
- **Aucun accès réseau général du Controller vers les machines.** Une seule
  destination, un seul compte, une seule commande, et rien qui ressemble à un
  shell.

## Ce que la preuve devra constater

La preuve (`#128`) est la première sous la règle inscrite à
`docs/contribution/QUALITE.md` : **aucune fixture ne remplace un composant du
produit sur ce trajet.** Elle constate :

1. **chaque maillon est exercé par le binaire du produit** : la Console réelle
   construit la paire, la vraie fenêtre native recueille le consentement, le
   cœur natif signe, le Controller réel reçoit, consomme, lance par SSH, et
   l'Auxiliaire réel applique sur l'autre machine ; le rapport LAB liste ce que
   les preuves passées remplaçaient par une fixture, et cette liste est **vide**
   sur le trajet de commande ;
2. **le parcours entier se fait en phrases** : une définition est gelée, un plan
   `deploy_user_service` est construit depuis la vue Services par « Déployer »,
   approuvé dans la fenêtre, et le service est posé — sans qu'un document soit
   collé, une empreinte tapée ou un champ recopié ;
3. **le rejeu est refusé après un redémarrage** : la même approbation
   resoumise après un redémarrage du Controller est refusée en nommant le
   dispatch déjà consommé, et la machine n'a reçu aucun octet ;
4. **une clé d'hôte changée est refusée avant octets** : le dispatch est
   `non lancé`, aucun wrapper n'est parti, et la machine est inchangée ;
5. **un rapport forgé est refusé** : un rapport pour une autre séquence, une
   autre machine ou une autre opération est écarté, et l'état du dispatch reste
   `lancé, non rapporté` plutôt que de devenir un succès ;
6. **l'état « lancé, non rapporté » est constaté pour de vrai** : une coupure du
   canal après l'écriture du wrapper laisse cet état, la Console l'affiche en
   ces termes, et le produit ne rejoue rien ;
7. **la position incertaine se résout par un geste humain** : la Console nomme
   l'incertitude, la machine refuse une séquence dépassée en le disant, et la
   phrase de la machine est montrée sans être réécrite ;
8. **rien n'est consommé par un refus** : une soumission refusée, quelle qu'en
   soit la raison, ne laisse aucun enregistrement et ne dépense aucune séquence ;
9. **la moitié privée d'une identité de commande n'apparaît nulle part** : ni
   dans un document, ni dans un rapport, ni dans une observation, ni dans un
   argument de processus, ni dans un artefact de la preuve ;
10. **idempotence et démontage** : rejouer le même plan par une nouvelle
    approbation rend `changed=false`, et le démontage rend les machines à leur
    état de clôture nommé.

Le rapport nommera aussi ce que ce trajet ne prouve pas : le pilotage de la
Console réelle atteste ce que le moteur de pilotage peut atteindre, et la
confirmation de la fenêtre native est faite par le mécanisme le plus honnête
disponible — le rapport dit lequel, et ce qu'il ne remplace pas.

## Les neuf décisions tranchées le 11 août 2026

Chacune est écrite à sa place dans ce contrat ; ce tableau sert à les
reconnaître et à retrouver ce qui les force. Aucune n'est un goût : elles
dérivent d'un invariant du cap ou d'une mesure faite dans le dépôt.

| # | Décision | Ce qui la force | Où elle est écrite |
|---|---|---|---|
| 1 | `POST /v0/plan-approvals` et `GET /v0/plan-dispatches`, confirmés | régularité de la surface `/v0/` existante ; le nombre de portes doit se compter dans le routage | « Surface du Controller étendue de deux routes » |
| 2 | Format par défaut de l'Auxiliaire en JSON, `--format=text` conservé | la commande forcée est comparée octet pour octet et ne porte aucun argument ; mesure : aucun harnais ne consomme le rendu en lignes | maillon 5 |
| 3 | Une reprise coûte au plus **une** approbation gaspillée | le refus de la machine nomme sa position ; aucune reprise autonome | « La position de commande d'une machine » |
| 4 | 512 / 256 octets, 32 enregistrements par machine, fichier 8 Mio | toute borne est dérivée d'une mesure, refusée dans `validate`, jamais de croissance silencieuse | « La borne de l'historique, dérivée d'une mesure » |
| 5 | Texte de la rétro-référence `SERVICE-UTILISATEUR.md`, déposé avec `#127` | une dette nommée se solde à la source qui l'a nommée | « La projection : l'histoire d'un plan » |
| 6 | Tout délai interne dérivé de `expires_at`, strictement sous 900 s | le plafond contractuel est l'autorité ; une expiration rend « lancé, non rapporté » | maillon 4, « les deux attentes » |
| 7 | `422` pour une autorité refusée, `409` pour les octets déjà lancés | taxonomie **existante** du Controller, relue route par route ; liste fermée | maillon 3, « les statuts viennent de la taxonomie existante » |
| 8 | Sans moteur attaché, les deux routes n'existent pas | une approbation ne se dépense jamais pour rien ; garde structurelle plutôt que documentaire | maillon 3, « sans moteur, la porte n'existe pas » |
| 9 | 32 lignes repliées, refusées dans `validate` | aucune phrase cachée, aucune fenêtre qui défile ; mesure à 72 caractères | maillon 2 |

## Ambiguïté documentaire tranchée : le numéro `#54`

Deux lectures de `#54` coexistaient. `ROADMAP.md`, `ISSUES.md`, `TESTS.md` et
`AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md` en font le quatrième contrat
exécutable de l'accès personnel `#42` : vérifier l'élévation et terminer
`access_verified`, dans la séquence `#45 → #51 → #52 → #53 → #54 → #42 → #35`.
`docs/lab/v0.1.0-signed-approval.md` lui attribuait, lui, « la commande forcée
SSH qui lancera l'Auxiliaire » et « l'installation de la commande forcée SSH et
l'invocation de l'Auxiliaire à travers elle ».

**La première lecture est la juste**, et la seconde est une erreur d'attribution
que ce contrat corrige à la source :

- l'**installation** de la commande forcée appartient à `#39`, qui l'a posée et
  prouvée sur une vraie machine — compte verrouillé, entrée `authorized_keys`
  comparée octet pour octet, règle `sudo` bornée, `sshd -T` relu — le même jour
  que le rapport fautif ;
- son **invocation depuis le Controller** appartient à ce palier, `#126`, et
  c'est précisément le maillon que le présent contrat fixe.

La correction est portée dans `docs/lab/v0.1.0-signed-approval.md` et dans
`docs/contribution/TESTS.md`, avec sa date : un rapport LAB reste le récit de ce
qui a été exécuté, et corriger un renvoi d'issue n'y touche aucune mesure.

## Justification de sécurité

- **Scénario et actifs.** Un humain commande une mutation sur une machine
  enrôlée depuis la Console. Actifs : la clé humaine d'approbation, les
  identités de commande par machine, les positions anti-rejeu, et l'intégrité de
  ce qui s'exécute réellement sur la machine.
- **Menaces traitées.** Un Controller compromis qui forge, rejoue ou redirige
  une intention humaine ; une surface WebView compromise qui affiche autre chose
  que ce qui se signe ; un rejeu après coupure ou redémarrage ; une machine
  substituée par une clé d'hôte changée ; un rapport forgé faisant passer une
  absence d'effet pour un succès.
- **Alternatives considérées.** Faire de la fenêtre un second vérificateur
  (écartée : deux dérivations, aucun gain contre un cœur compromis) ; stocker
  les paires sur le Controller (écartée : seconde copie susceptible de diverger
  de ce qui a été signé) ; embarquer une pile SSH en Go (écartée : protocole et
  politique de clé d'hôte à posséder sur le composant qui détient tout) ;
  indexer le registre de dispatch par numéro de séquence (écartée : empêcherait
  un humain de réapprouver légitimement une position que la machine n'a jamais
  consommée) ; analyser la phrase de refus de la machine (écartée : coupler un
  programme à une présentation) ; une seule collection `/v0/plan-dispatches`
  portant `POST` et `GET` (écartée : la porte qui fait sortir un octet doit se
  compter dans la table des chemins) ; laisser un moteur immobile conclure
  `non lancé` sur le trajet produit (écartée : un binaire qui dépenserait
  systématiquement des autorités humaines pour rien — la garde est structurelle,
  et sans moteur attaché les deux routes n'existent pas) ; borner l'historique
  par un nombre rond (écartée : la rétention est dérivée de la machine la plus
  chargée des preuves du produit, et le fichier du pire enregistrement mesuré) ;
  demander le format JSON dans l'invocation distante (écartée : la commande
  forcée est comparée octet pour octet, et l'élargir d'un argument serait élargir
  la seule règle que ce produit s'autorise sur une machine gérée).
- **Portée accordée et moindre privilège.** Le Controller reçoit exactement une
  destination, un compte, une commande sans argument et une entrée standard
  bornée par machine ; aucune capacité de shell, de transfert ou de terminal
  n'existe sur ce chemin, et la moitié privée d'une identité ne quitte pas le
  service qui la charge.
- **OWASP.** Valeur sûre par défaut (aucune confiance au premier contact,
  aucune reprise implicite), réduction de surface (deux routes, une seule
  émettrice), séparation des responsabilités (construire, consentir, signer,
  lancer, appliquer, rapporter sont six autorités), défense en profondeur
  (double vérification Controller puis Auxiliaire, double anti-rejeu), Zero
  Trust (aucun maillon ne croit le précédent).
- **NIS2, lecture proportionnée.** Contrôle d'accès et cryptographie (identité
  par machine, approbation signée liée à une époque et à une séquence), gestion
  d'incident et continuité (états honnêtes, `résultat inconnu` jamais transformé
  en succès), développement sûr et mesure d'efficacité (la règle de preuve sans
  fixture, inscrite à `QUALITE.md`), gestion des actifs (chaque identité est
  nommée, détenue et révoquée par le remplacement du Controller).
- **Risque résiduel.** Un Controller entièrement compromis peut lancer une
  approbation qu'un humain a signée pour une machine, au moment où il veut, dans
  la limite de la durée de vie de l'enveloppe et une seule fois ; une machine
  dont `root` est compromis peut mentir dans son rapport ; la version et les
  défauts compilés du client OpenSSH appartiennent à la distribution ; le
  pilotage de la Console réelle dans la preuve atteste moins qu'un humain
  devant l'écran, et le rapport LAB dira quoi.

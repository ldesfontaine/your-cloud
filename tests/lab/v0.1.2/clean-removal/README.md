# La preuve du retrait propre de la Console Linux

Après une désinstallation, que reste-t-il sur la machine ? La question n'avait
jamais été posée pour la Console elle-même. Ce harnais y répond par des
**différences entre recensements du disque**, jamais par une inspection de ce
qu'on s'attend à trouver : chercher ce qu'on attend est la façon de ne pas voir
ce qu'on n'attend pas.

```text
CANDIDATE=/chemin/vers/your-cloud_0.1.0_amd64.deb \
TAURI_DRIVER=/chemin/vers/tauri-driver \
tests/lab/v0.1.2/clean-removal/prove
```

La preuve ne crée ni ne détruit de topologie et ne parle qu'à `lab-console`,
qu'elle rend d'abord à son instantané `clean`.

## Les sept états

| État | Ce qu'il constate |
| --- | --- |
| `pristine` | la machine rendue à `clean`, avant tout sol |
| `base` | le sol posé : dépendances du paquet, sol du pilote, le compte de l'humain |
| `control` | la même machine relevée une seconde fois, sans que rien n'arrive entre les deux |
| `installed` | le `.deb` installé |
| `used` | la Console lancée, un coffre créé, le formulaire d'association atteint |
| `removed` | après `dpkg --remove` |
| `purged` | après `apt-get purge` |

`remove` et `purge` sont **deux mesures séparées** parce que ce sont deux
constats : dpkg garde délibérément au premier ce qu'il n'efface qu'au second, et
un rapport qui ne mesurerait que le second tairait exactement cette différence.

`control` n'est pas une redondance : c'est le **plancher de bruit**. Il dit
combien d'entrées bougent toutes seules sur une machine où rien ne se passe, et
donc à partir de combien une différence veut dire quelque chose. Sans lui, les
exclusions du recensement seraient des affirmations ; avec lui, elles sont
vérifiées.

## Trois choix de méthode, et ce qu'ils décident

**Les dépendances sont installées avant la base.** Le `.deb` déclare
`libwebkit2gtk-4.1-0` et `libgtk-3-0`, dont la fermeture apt compte des milliers
de fichiers. Les poser après la base ferait entrer cette fermeture dans la
différence, et « ce que le paquet a posé » se lirait au milieu de ce que Debian
a posé pour lui. Elles sont donc dans la base, et la différence isole le paquet.
En contrepartie, ce que ces dépendances laissent après un `apt autoremove` n'est
pas mesuré ici : c'est une autre question, et elle n'est pas celle du paquet.

**L'usage tourne sous un vrai compte non privilégié.** La Console d'un humain
écrit sous son `$HOME` ; mesurer sous `/root` répondrait à une autre question que
« que reste-t-il des données de l'humain ». Le compte est créé avant la base,
pour que le compte lui-même ne soit pas attribué au paquet.

**Aucune variable `XDG_*` n'est posée.** C'est la seule différence qui compte
avec le patron d'oracle dont `inside` descend : le harnais du trajet de commande
déplace l'état de la Console sous un répertoire à lui pour pouvoir le remettre à
zéro entre deux étapes, alors que cette preuve-ci mesure justement **où le
produit écrit quand personne ne le lui dit**.

## Ce que l'oracle fait, et où il s'arrête

Il conduit le produit installé — `/usr/bin/your-cloud-console`, par
`tauri-driver` devant WebKitWebDriver — jusqu'au formulaire d'association :
génération des deux secrets, création réelle du coffre, puis la vue
d'association. Il s'arrête là volontairement. Le coffre, ses clés et la
configuration existent dès l'écran précédent, tandis qu'aller au-delà exigerait
un Controller vivant, c'est-à-dire un tout autre périmètre.

Rien n'est semé : un coffre semé serait un coffre que cette preuve n'a pas fait
naître, donc des traces dont elle ne saurait pas dire qui les a écrites.

## Le seul verdict que les données rendent seules

`compare` ne décide pas si un résidu est acceptable — c'est un jugement, et un
jugement se pose dans un rapport signé par quelqu'un. Il tranche un seul fait
vérifiable : un chemin **livré par le paquet**, reconnu comme tel parce qu'il
figure dans la table du `.deb` lue par `dpkg-deb -c`. Un fichier du paquet
encore présent après un retrait est le seul verdict que des données suffisent à
rendre.

## Ce que la preuve porte sur le paquet

Le `.deb` est construit depuis le tag `v0.1.0` sur `lab-console`, puis rapatrié.
**Il n'existe aucun paquet livré** : ce dépôt ne publie pas de release, la
matrice hébergée construit et installe le `.deb` sans jamais l'archiver, et
« attesté » y désigne un SHA passé au vert, pas un binaire signé. Le `.deb`
n'étant pas non plus reproductible octet pour octet — `dpkg-deb` inscrit les
horodatages —, son empreinte identifie **ce build-là** et rien de plus. Ce que
cette preuve mesure est donc la **recette d'empaquetage à la révision attestée**,
et une preuve de recette suit sa recette : si l'empaquetage change — fichiers
installés, unités, chemins —, elle se rejoue.

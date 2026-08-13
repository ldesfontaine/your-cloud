# Your Cloud

> ## ⚠️ En cours de développement — non fonctionnel pour un usage réel.
>
> **Aucune release publiée. Ne pas utiliser pour héberger quoi que ce soit.**
>
> Ce dépôt est ouvert pour être lu, pas pour être installé. Les capacités
> décrites plus bas sont à des états différents, et le tableau dit lequel pour
> chacune, sans arrondir.

## Ce que Your Cloud veut être

Héberger soi-même demande aujourd'hui de tenir dans sa tête ce que font une
douzaine d'outils. Your Cloud vise l'inverse : **représenter son infrastructure,
observer ses machines et déployer des services depuis une interface qui montre
les opérations réellement exécutées** — jamais un bouton qui cache ce qu'il
déclenche.

Concrètement, une personne déclare ses machines, les voit rapporter leur état,
choisit un service, lit en phrases ce que la machine recevra, approuve, et
regarde le résultat que la machine a réellement rapporté. Ce que l'écran
affiche est ce qui s'est produit, pas une promesse d'interface.

C'est un projet pour qui veut héberger ses propres services — un serveur loué,
un mini-PC, une machine au grenier — et refuse d'échanger la simplicité contre
l'opacité. Ce n'est pas une plateforme d'entreprise, ni un orchestrateur
généraliste.

## La philosophie : la construction vérifiable est le produit

Chaque capacité passe par trois états, dans cet ordre, et la documentation les
distingue explicitement : **définie**, puis **implémentée**, puis **prouvée**
dans un environnement isolé.

« Prouvée » a un sens strict ici. Une preuve exécute les binaires réels du
produit sur de vraies machines, traverse le chemin d'échec avant le chemin de
succès, et affronte des cas hostiles — une clé d'hôte changée, une machine qui
ment sur ce qu'elle a fait, une autorité rejouée. Chaque preuve écrit aussi ce
qu'elle **ne** prouve pas.

Cette exigence est ce qui rend le tableau ci-dessous lisible : une ligne
« prouvée » signifie qu'un rapport daté relie une capacité à un commit exact.

## Capacités et leur état

| Capacité | État |
|---|---|
| Amorçage, enrôlement d'une machine, remplacement du Controller | prouvée par des tests (LAB) |
| Observation du parc : la machine rapporte, le Controller enregistre | prouvée par des tests (LAB) |
| Déploiement de services par plans signés — profils de référence | prouvée par des tests (LAB) |
| Définitions de service utilisateur — image, volumes, secrets déclarés | prouvée par des tests (LAB) |
| Publication HTTPS par point d'entrée Traefik | prouvée par des tests (LAB) |
| Passage privé WireGuard entre deux machines | prouvée par des tests (LAB) |
| Trajet de commande complet depuis la Console : fenêtre native, signature, lancement SSH, rapport | prouvée par des tests (LAB) |
| Instantanés et restauration de volumes | prouvée par des tests (LAB) |
| Mode externe : déclarer un service sans le gérer | prouvée par des tests (LAB) |
| Mise en page sans coupe au zoom texte 200 % sous Windows | écrite, preuve en cours |
| Approbation de plans depuis la Console Windows | prévue |
| Signature Windows publiquement reconnue | prévue |

## Les limites, dites franchement

- **La Console Windows est en retrait.** Elle observe et lit un plan ; elle ne
  recueille pas encore de signature — la moitié Win32 de la fenêtre
  d'approbation est différée. Approuver un plan se fait depuis Linux.
- **Les sauvegardes sont locales et à la demande.** Un instantané est déclenché
  par un plan approuvé et reste sur la machine. Il n'y a ni planification, ni
  copie hors machine : emporter une archive ailleurs relève des outils de la
  personne qui héberge.
- **DNS et TLS restent manuels.** Le nom de domaine, ses enregistrements et
  l'obtention des certificats publics ne sont pas automatisés.
- **Aucun SHA n'est encore attesté** par la matrice de construction hébergée
  pour le travail récent : les preuves ci-dessus ont été exécutées depuis
  l'arbre de travail. C'est écrit dans chaque rapport concerné.
- **Debian 13 seulement**, sur `amd64`. Les autres distributions et
  architectures attendent une preuve séparée.

## Pour lire plus loin

La [carte documentaire](docs/README.md) est le point d'entrée : elle donne le
chemin de lecture selon le sujet — le [cap du projet](docs/projet/CAP.md) et ses
limites durables, l'[anatomie](docs/architecture/ANATOMIE.md) du placement et des
flux, les [rapports de preuve](docs/lab/README.md), et les
[règles de qualité](docs/contribution/QUALITE.md) appliquées à chaque changement.

[`tools/labctl`](tools/labctl) contrôle les machines de l'environnement isolé.
Sa présence ne prouve aucune capacité du produit.

## Licence

Your Cloud est distribué sous licence
[GNU Affero General Public License, version 3](LICENSE), et sous elle seule.

Le copyleft réseau est un choix de destination plutôt qu'une préférence :
ce produit sert à héberger soi-même, et l'AGPL est la licence qui garde ce
sens quand quelqu'un d'autre en fait un service — celui qui propose Your
Cloud à des tiers par un réseau doit leur en offrir la source, modifications
comprises. Une licence permissive aurait laissé refermer ce que ce dépôt
ouvre.

Les profils de service que la `v0.1.0` prend en charge sont eux-mêmes sous
AGPL — BentoPDF, Vaultwarden — et ne sont ni redistribués, ni modifiés, ni
liés par ce dépôt : Your Cloud les déploie par leur image officielle
épinglée, ce que le contrat de chaque profil écrit.

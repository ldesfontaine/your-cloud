# Direction — les chantiers, dans l'ordre

Ce document dit **dans quel ordre le produit avance**, et pourquoi cet ordre.
Il complète le [cap](CAP.md), qui dit où l'on va : le cap fixe la destination,
celui-ci fixe la route.

> **Les paliers ne sont pas arrêtés.** Aucune version n'est promise ici, et
> aucun découpage global en `v0.x` ne fait autorité. **Seul le prochain palier
> fixe son numéro, à son ouverture**, et reçoit alors son dossier `objectifs/`
> borné par une ligne d'arrivée vérifiable. Un chantier n'est pas un palier :
> c'est une unité de travail cohérente, dont le regroupement en versions se
> décide au moment de l'ouvrir.

## Ce que chaque chantier rend vrai

Le produit se juge sur un parcours en cinq étapes. Chacune devient réelle après
un chantier précis — c'est la mesure de l'avancement, plus honnête qu'un
pourcentage.

| Étape du parcours | Réelle après |
|---|---|
| 1. Installer l'app | **déjà vrai** — prouvé depuis la page Releases |
| 2. Créer une infrastructure, importer les machines | chantiers 1-2 pour la première machine, **3** pour les suivantes |
| 3. Vérifier que tout va bien | chantier **3**, puis **9** en continu |
| 4. Installer un service sur la machine choisie | chantier **4** |
| 5. Publier avec un domaine, et exiger une connexion si c'est privé | chantiers **6** et **7** |

## Les chantiers

### 1. L'installation sans préparation

Le compte Debian ordinaire suffit ; les commandes sudoers disparaissent du
README ; l'amorçage passe à deux approbations.

**Ce qu'on gagne** : « télécharger, installer, créer son infrastructure » sans
jamais taper une commande sur le serveur.

*Ferme #158. Contrat : A9. Dépend de : rien.*

### 2. Le pilotage à distance

L'app devient un pair du réseau d'accès : au clic sur une infrastructure, le
tunnel monte ; le Controller n'écoute que sur son adresse interne ; les trois
questions d'adresses disparaissent de l'amorçage.

**Ce qu'on gagne** : piloter depuis n'importe où, sans rien exposer.

*Contrat : A4. Dépend de : rien — mais touche les mêmes écrans que le
chantier 1. Les fusionner en une seule refonte de l'amorçage est probablement
plus économique.*

### 3. Le parc

Enrôler les machines suivantes **depuis l'app**, et voir ce qui tourne dessus :
inventaire découvert par le Daemon, ports en écoute, identité stable.

**Ce qu'on gagne** : les étapes 2 et 3 du parcours deviennent réelles.

*Contrats : A1, A3. Dépend de : 2 — les machines ont besoin d'adresses.*

### 4. Les services

Déployer depuis les écrans, **reprendre** un service existant, mettre à jour
avec snapshot et retour, cloisonnement loopback posé automatiquement.

**Ce qu'on gagne** : l'étape 4, et la fin du « code qui sait mais que l'écran ne
demande pas ».

*Contrats : A3, A8. Dépend de : 3.*

### 5. Le réseau interne

Mesh entre N machines aux adresses stables, flux nommés ouverts par les actions,
carte des liens et liste des flux à l'écran.

**Ce qu'on gagne** : des services qui se parlent, et la preuve visible que rien
d'autre ne circule.

*Contrat : A4. Dépend de : 3.*

### 6. La publication

Publier un service sur son domaine en HTTPS : DNS géré ou manuel guidé,
certificat wildcard renouvelé tout seul, route posée.

**Ce qu'on gagne** : l'étape 5, moitié web.

*Contrats : A5, A6. Dépend de : 5.*

### 7. Les humains

Portail d'authentification posé automatiquement au premier « Exiger une
connexion » ; écran Personnes ; headers écrasés au proxy.

**Ce qu'on gagne** : l'étape 5, moitié privée — la famille sur ses services sans
rien installer.

*Contrats : A5, A7. Dépend de : 6.*

### 8. L'exposition L4

Exposer un service non-HTTP, IP source préservée — **à prouver en LAB avant
d'être promise**, repli documenté sinon.

*Contrat : A5. Dépend de : 5.*

### 9. La vue globale

Ligne de santé en phrases, badges d'attention, carte de l'infrastructure.

**Itérative par nature** : le contrat fixe l'information, la présentation se
retouche librement sans le rouvrir.

*Avance en continu à partir du chantier 3.*

## Ce que cet ordre respecte

- **Rien n'est promis avant d'être prouvé.** Un chantier ne se ferme pas sur du
  code écrit, mais sur une preuve LAB réellement exécutée.
- **Les dépendances sont réelles, pas décoratives** : le parc a besoin
  d'adresses, les services ont besoin du parc, la publication a besoin du
  réseau.
- **Un contrat se rédige et se valide avant d'être codé.** Les neuf textes de la
  partie A précèdent les chantiers qu'ils bornent.

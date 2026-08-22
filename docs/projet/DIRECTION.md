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
| 3. Vérifier que tout va bien | chantier **3**, puis **10** en continu |
| 4. Installer un service sur la machine choisie | chantier **5** |
| 5. Publier avec un domaine, et exiger une connexion si c'est privé | chantiers **7** et **8** |

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

Une action **facultative** s'y attache, « Vérifier cette machine » : elle pose
puis retire la sonde épinglée sur `127.0.0.1`. C'est la seule façon de constater
qu'un enrôlement a produit une machine qui reçoit, vérifie et rend un plan
approuvé — ce qu'une garde de capacité ne peut pas dire, puisqu'elle lit des
capacités déclarées sans rien exécuter. L'enrôlement se termine sans elle, et
rien ne casse si elle n'est jamais demandée.

**Ce qu'on gagne** : les étapes 2 et 3 du parcours deviennent réelles.

*Contrats : A1, A3, `PLAN-OCI-CONTROLE.md`. Dépend de : 2 — les machines ont
besoin d'adresses.*

### 4. Le remplacement du Controller

Remplacer **depuis l'app** un Controller perdu ou compromis : chaque autorité
que l'ancien exerçait est renouvelée, et l'état de chaque cible est visible —
`ancien seul`, `chevauchement borné`, `nouveau seul` ou `inconnu`, jamais un
succès global.

**Ce qu'on gagne** : le parc survit à la perte de sa tête. La logique de
décision existe déjà et **aucun binaire du produit ne l'atteint** : le module
`replacement` n'a qu'une fixture LAB pour appelant. Ce chantier lui donne le
sien.

*Contrat : A9. Dépend de : 3 — le remplacement existe pour ne pas perdre le
parc, et n'a de sens qu'une fois qu'il y a un parc à préserver.*

### 5. Les services

Déployer depuis les écrans, **reprendre** un service existant, mettre à jour
avec snapshot et retour, cloisonnement loopback posé automatiquement.

**Ce qu'on gagne** : l'étape 4, et la fin du « code qui sait mais que l'écran ne
demande pas ».

*Contrats : A3, A8. Dépend de : 3.*

### 6. Le réseau interne

Mesh entre N machines aux adresses stables, flux nommés ouverts par les actions,
carte des liens et liste des flux à l'écran. Les six plans du passage privé sont
lus, consentis et signés depuis l'app comme n'importe quel autre plan.

**Ce qu'on gagne** : des services qui se parlent, et la preuve visible que rien
d'autre ne circule.

*Contrats : A4, `PASSAGE-PRIVE-WIREGUARD.md`. Dépend de : 3.*

### 7. La publication

Publier un service sur son domaine en HTTPS : DNS géré ou manuel guidé,
certificat wildcard renouvelé tout seul, route posée.

**Ce qu'on gagne** : l'étape 5, moitié web.

*Contrats : A5, A6. Dépend de : 6.*

### 8. Les humains

Portail d'authentification posé automatiquement au premier « Exiger une
connexion » ; écran Personnes ; headers écrasés au proxy.

**Ce qu'on gagne** : l'étape 5, moitié privée — la famille sur ses services sans
rien installer.

*Contrats : A5, A7. Dépend de : 7.*

### 9. L'exposition L4

Exposer un service non-HTTP, IP source préservée — **à prouver en LAB avant
d'être promise**, repli documenté sinon.

*Contrat : A5. Dépend de : 6.*

### 10. La vue globale

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

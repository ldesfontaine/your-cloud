# Cohérence documentaire

## Pourquoi ce document existe

Une décision validée ne doit pas rester seulement dans une conversation ni être
recopiée différemment dans plusieurs fichiers. Chaque sujet possède donc une
source canonique. Lorsqu'une décision influence plusieurs vues, le registre
ci-dessous nomme les projections qui doivent être relues et mises à jour dans le
même changement.

Ce mécanisme reste volontairement plus léger qu'une collection d'ADR. Une
décision locale à un seul document n'entre pas dans le registre. Un identifiant
n'est créé que lorsque la même frontière doit rester cohérente dans plusieurs
sources.

## Rôle des sources

| Source | Autorité |
|---|---|
| `CONTEXT.md` | Le vocabulaire et les relations du domaine, sans choix d'implémentation |
| `docs/README.md` | La carte de navigation, jamais une décision produit |
| `docs/projet/CAP.md` | La destination à long terme et les contraintes durables |
| `docs/objectifs/v1/README.md` | Ce qui doit être vrai pour déclarer la version `v0.1.0` atteinte |
| `docs/objectifs/v1/ROADMAP.md` | L'ordre des preuves jusqu'à `v0.1.0` et le prochain incrément détaillé |
| `docs/contribution/QUALITE.md` | Les règles de conception, développement et validation |
| `docs/contribution/CI.md` | Les déclenchements, permissions, placements et limites des contrôles GitHub Actions |
| `docs/contribution/TESTS.md` | Le registre des contrôles, incidents et écarts à automatiser, jamais une preuve par lui-même |
| `docs/architecture/ANATOMIE.md` | La projection visuelle des placements, flux, autorités et états |
| `docs/architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md` | Le contrat de l'autorité SSH initiale, de son transfert et du remplacement explicite du Controller |
| `docs/architecture/CHAINE-D-OBSERVATION.md` | La projection détaillée des rôles Daemon/Relay, du signal de présence et de leur coordination |
| `docs/architecture/CYCLE-DE-VIE-DES-SERVICES.md` | Le cycle sûr validé du déploiement, de la publication, de la migration et du retrait d'un service |
| `docs/architecture/SERVICE-UTILISATEUR.md` | Le contrat de la définition de service utilisateur : ce qu'elle peut dire, ce qui la gèle et ce qu'elle n'autorise jamais |
| `docs/architecture/TRAJET-DE-COMMANDE.md` | Le contrat des cinq maillons entre l'humain qui approuve et la machine qui rapporte, et des bornes de ce trajet |
| `docs/architecture/L-ASSISTANT-QUI-INSTALLE.md` | Le contrat d'exécution privilégiée de l'installation par l'Assistant : ce qu'il pose, constate et défait, et l'autorité qu'il réutilise sans l'étendre |
| `docs/lab/` | Les preuves réellement exécutées, jamais une décision par elles-mêmes |
| `docs/html/` | Des vues visuelles dérivées de leur Markdown, jamais une source indépendante |

Lorsqu'une contradiction apparaît, le document canonique du sujet indique
l'intention, mais la contradiction reste un défaut à corriger avant de
poursuivre. Une vue dérivée ne doit pas simplement être ignorée parce qu'elle
n'est pas canonique.

Un routeur local et non versionné peut aider un agent à charger seulement les
sources utiles à sa tâche. Il ne constitue jamais une source du produit : un
clone du dépôt doit pouvoir comprendre le cap, l'objectif actif et la
propagation documentaire, puis exécuter le contrôle sans posséder ce fichier
privé.

## Cycle d'une décision

1. Pendant la réflexion, le point reste explicitement ouvert et n'est pas
   présenté comme décidé.
2. Après validation explicite, la source canonique est mise à jour dans le même
   travail.
3. Si la décision est transverse, son identifiant est ajouté au registre ou ses
   projections existantes sont relues.
4. Chaque projection obligatoire et chaque miroir HTML concerné sont mis à
   jour. Les marqueurs de cohérence entourent le bloc qui exprime réellement la
   décision ; ils ne servent pas de décoration en tête de fichier.
5. `tools/check-docs` est exécuté avant de passer au code ou d'ouvrir un autre
   sujet.
6. Le compte rendu nomme les sources modifiées, les choix encore ouverts et ce
   que le contrôle automatique ne sait pas prouver.

Le validateur prouve la présence des blocs attendus, les liens et quelques
invariants critiques. Il ne comprend pas le sens des paragraphes : une relecture
humaine ou par l'agent reste obligatoire.

## Propagation selon le type de décision

| Changement validé | Source à modifier d'abord | Projections habituelles |
|---|---|---|
| Terme ou relation métier | `CONTEXT.md` | Cap, objectif ou interface qui emploie ce terme |
| Direction durable ou limite finale | `docs/projet/CAP.md` | Roadmap et anatomie si la trajectoire ou les flux changent |
| Condition de réussite d'un objectif | `docs/objectifs/<objectif>/README.md` | Roadmap et anatomie concernées |
| Ordre ou périmètre du prochain palier | `docs/objectifs/<objectif>/ROADMAP.md` | Carte documentaire et rapport LAB concerné |
| Technologie ou règle de développement | Objectif concerné ou qualité selon sa portée | Roadmap, anatomie et HTML concernés |
| Déclenchement ou placement d'une preuve CI | `docs/contribution/CI.md` | Registre de tests, contrat du palier concerné et routeur `tests/README.md` |
| Résultat réellement exécuté | Rapport sous `docs/lab/` | Anatomie et état décidé/implémenté/prouvé |

## Registre des décisions transverses actives

La colonne « source canonique » indique où lire la décision complète. Le résumé
ci-dessous sert seulement à reconnaître son sujet.

<!-- coherence-registry:start -->
| Identifiant | Frontière suivie | Source canonique | Projections obligatoires |
|---|---|---|---|
| `AGENT-AUTHORITY` | Un artefact Agent par version, rôles en processus isolés, Daemon non-root, Relay explicitement activé, Auxiliaire ponctuel et autorités adaptées | `docs/projet/CAP.md` | `CONTEXT.md`, `docs/objectifs/v1/README.md`, `docs/objectifs/v1/ROADMAP.md`, `docs/architecture/ANATOMIE.md`, `docs/architecture/CHAINE-D-OBSERVATION.md`, `docs/contribution/QUALITE.md` |
| `BOOTSTRAP-RECOVERY` | Assistant temporaire, accès personnel conservé, approbation signée, identités par machine et remplacement explicite de toutes les autorités du Controller | `docs/architecture/AMORCAGE-ET-REMPLACEMENT-DU-CONTROLLER.md` | `CONTEXT.md`, `docs/projet/CAP.md`, `docs/objectifs/v1/README.md`, `docs/objectifs/v1/ROADMAP.md`, `docs/architecture/ANATOMIE.md` |
| `V1-OBSERVATION` | Collecteurs nommés, sortie mTLS, Relay sans ordre, tampon borné et lacunes visibles | `docs/architecture/CHAINE-D-OBSERVATION.md` | `CONTEXT.md`, `docs/projet/CAP.md`, `docs/architecture/ANATOMIE.md` |
| `V1-APP-ACCESS` | App cliente installée et signée, Controller backend sans frontend qui n'écoute que sur son adresse du réseau d'accès, pair WireGuard par appareil et services publiés indépendants | `docs/projet/CAP.md` | `CONTEXT.md`, `docs/architecture/ANATOMIE.md`, `docs/architecture/CHAINE-D-OBSERVATION.md` |
| `INTERNAL-NETWORK` | Machines enrôlées seules pairs, transport qui n'autorise rien, flux nommés et bornés, aucune route générale vers le LAN | `docs/architecture/RESEAU.md` | `CONTEXT.md` |
| `PUBLIC-EXPOSURE` | Point d'entrée unique, expositions nommées, en-têtes d'identité écrasés, zone d'exposition sans fausse DMZ | `docs/architecture/POINT-D-ENTREE.md` | `CONTEXT.md`, `docs/projet/CAP.md` |
| `SERVICE-LIFECYCLE` | Réseau préparé fermé, service vérifié avant publication, bascule observable et retour honnête | `docs/architecture/CYCLE-DE-VIE-DES-SERVICES.md` | `CONTEXT.md`, `docs/projet/CAP.md`, `docs/objectifs/v1/ROADMAP.md`, `docs/architecture/ANATOMIE.md` |
<!-- coherence-registry:end -->

Le registre reste limité aux sept frontières dont une divergence changerait le
modèle de confiance ou le parcours utilisateur. Les choix de déploiement, la
discipline LAB, la portée de la roadmap et les notes hors de l'objectif actif
suivent la table de propagation précédente, mais ne reçoivent pas de marqueurs
automatiques tant qu'une divergence réelle ne justifie pas ce coût.

## Marqueurs

Une projection déclarée contient exactement une paire :

```text
<!-- coherence: <IDENTIFIANT>:start -->
bloc qui exprime la décision
<!-- coherence: <IDENTIFIANT>:end -->
```

Ajouter un marqueur sans relire le texte ne constitue pas une synchronisation.
Si une décision change de sens, toutes ses projections déclarées sont relues,
même lorsqu'une formulation peut rester identique.

## Utilisation du contrôle

```text
tools/check-docs
```

Le contrôle échoue notamment lorsqu'une source manque, qu'une décision
transverse n'est pas projetée partout où elle est annoncée, qu'un marqueur est
orphelin ou croisé, qu'un lien local est cassé, qu'un miroir HTML requis manque
ou qu'une formulation contradictoire réapparaît.

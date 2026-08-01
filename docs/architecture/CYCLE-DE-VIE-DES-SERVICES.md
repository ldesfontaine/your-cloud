# Cycle de vie sûr d'un service

> Statut : contrat d'architecture validé. Il s'applique aux opérations gérées
> qui déploient, publient, déplacent ou retirent un service.

Ce contrat ne prescrit ni un service, ni un placement. BentoPDF et Vaultwarden
sont des profils de référence ; le VPS et le mini-PC sont les machines du
scénario LAB qui rend les preuves lisibles. Aucune ressource n'est créée sans
déclaration, placement, plan et approbation explicites.

<!-- coherence: SERVICE-LIFECYCLE:start -->

## Deux ordres à ne pas confondre

La roadmap V1 décrit **l'ordre de construction du produit**. Elle peut prouver
le profil BentoPDF sur le VPS de référence avant d'introduire WireGuard, car ce
premier service permet de comprendre séparément le déploiement OCI, Traefik et
HTTPS. Cette séquence de preuve ne devient pas l'ordre obligatoire d'une
infrastructure réelle.

Une opération réelle décrit **l'ordre de changement d'une infrastructure**.
Pour un service privé, « préparer le réseau avant le service » ne signifie
jamais « ouvrir son port avant qu'il soit prêt ». Le cycle retenu est :

```text
inventorier et attribuer les responsabilités
                |
                v
planifier, approuver et préparer la reprise
                |
                v
préparer identités, secrets et réseau privé fermé
                |
                v
déployer sans exposition, puis vérifier localement
                |
                v
autoriser le seul flux nécessaire
                |
                v
publier ou basculer, observer, puis retirer l'ancien
```

WireGuard peut ainsi être établi avec des pairs et routes `/32` pendant que
`nftables` refuse encore le trafic applicatif. Le port exact n'est autorisé
qu'après une vérification du service. La route publique Traefik arrive en
dernier.

## Contrat d'une opération

| Phase | Ce que la Console doit rendre visible | Comportement sûr en cas d'échec |
|---|---|---|
| Inventaire | cible, propriétaire, état observé et âge de la preuve | refuser une cible ou une autorité ambiguë |
| Plan | changements, privilèges, flux, interruption et conséquences | aucune mutation avant approbation liée au plan exact |
| Reprise | sauvegarde, restauration prouvée et chemin d'administration indépendant | bloquer si le retour annoncé n'est pas crédible |
| Préparation | identités, secrets, destination et règles encore fermées | retirer les éléments temporaires sans exposer le service |
| Déploiement | version, digest, volumes, état local et tests | conserver la route actuelle et ne rien publier |
| Ouverture ou bascule | source, destination, flux exact et détenteur des écritures | appliquer une bascule atomique ou annoncer un résultat inconnu |
| Observation | santé du service, refus hostiles et fraîcheur de chaque preuve | ne pas confondre panne de la Console, du Controller, du Relay et du service |
| Retrait | ancienne instance, règles, secrets et date de fin de rétention | conserver ce qui est encore nécessaire au retour |

Un rollback n'est jamais une promesse vague. Le plan nomme les opérations
exactes de retour, les borne aux ressources gérées par Your Cloud et soumet ce
contenu à la même approbation. Le cœur natif de la Console signe l'enveloppe
canonique après confirmation ; le Controller la transporte et l'Auxiliaire
revérifie localement la clé publique, l'époque et la séquence root-owned. Après
un échec contrôlé, l'Auxiliaire tente ce rollback tant qu'il garde la maîtrise ;
son propre échec produit un état partiel. Le premier changement rend
`changed=true`, un nouveau plan demandant le même état et un retrait déjà
effectif rendent `changed=false` sans réécriture ni redémarrage. Une dérive
exige un nouveau plan.

Une coupure au milieu d'une mutation ne déclenche aucun rejeu aveugle. Le
Controller marque `résultat inconnu`, la Console l'affiche, puis le Controller
observe le système par un chemin indépendant et propose seulement les actions
compatibles avec l'état réellement constaté. La V1 ne promet ni rollback, ni
continuation autonome lorsque l'Auxiliaire n'est plus joignable. La séquence
consommée avant mutation reste refusée après redémarrage : reprendre exige
toujours une nouvelle approbation.

## Scénario de référence homelab : VPS public et mini-PC privé

Exemple optionnel : Traefik sur le VPS publie le profil Vaultwarden, installé
sur un mini-PC derrière une box sans redirection entrante.

1. Observer les deux machines et confirmer le chemin d'administration.
2. Préparer et restaurer une sauvegarde synthétique de Vaultwarden.
3. Faire approuver le pair WireGuard, les deux `/32`, le port applicatif et la
   future route HTTPS.
4. Établir WireGuard en refusant le reste du LAN et tous les ports non prévus.
5. Déployer Vaultwarden sans route publique et sans écoute sur le LAN.
6. Vérifier le service localement sur la machine privée.
7. Autoriser uniquement le couple destination-port approuvé, puis vérifier ce
   chemin depuis le VPS.
8. Ajouter la route Traefik, vérifier HTTPS, puis tester le refus du port direct,
   de SSH et d'un voisin synthétique du LAN.
9. Observer avant de retirer les autorisations temporaires.

Avant la publication, le retrait de la destination est simple. Après la
création de données utiles, retirer la route peut contenir un incident, mais la
restauration des données exige un plan séparé : elle ne doit jamais être
déclenchée automatiquement.

## Scénario PME : proxy en DMZ et service en zone privée

Exemple : un proxy réside dans une vraie DMZ, l'application dans un VLAN serveur
et le plan d'administration dans une troisième zone.

1. Inventorier les dépendances, responsables, flux actuels et actifs affectés.
2. Fixer la fenêtre de changement, les critères d'arrêt et le responsable du
   retour.
3. Préparer comptes nominatifs, secrets, certificats, sauvegarde et accès
   d'urgence indépendant.
4. Créer les objets réseau et politiques en état fermé ou désactivé.
5. Déployer le service sans trafic utilisateur et le vérifier depuis les seules
   zones autorisées.
6. Activer ensemble la règle strictement nécessaire et la route du proxy.
7. Observer disponibilité, erreurs, journaux et refus latéraux depuis plusieurs
   points, puis fermer les anciennes règles après la fenêtre de retour.

Ce scénario ajoute des besoins absents d'un petit homelab : demandeur et
approbateur distincts lorsque le risque le justifie, identités nominatives,
expiration des accès temporaires, créneau annoncé et journal d'audit exploitable
sans secret.

## Migration sans données persistantes

Pour un service sans état, Your Cloud peut préparer la destination et la tester
sans trafic, puis basculer atomiquement la route. L'ancienne instance reste
disponible pendant la fenêtre de retour et n'est retirée qu'après observation.

```text
destination privée prête -> test -> bascule de route -> observation -> retrait
                                  `-> échec : route précédente conservée
```

Une bascule progressive peut être ajoutée seulement si le proxy et le service
la prennent réellement en charge. Elle ne doit pas être simulée par des
changements DNS supposés instantanés.

## Migration avec données persistantes

Pour un service avec écritures, tel que le profil optionnel Vaultwarden :

1. Vérifier les versions, formats, volumes, clés et tâches planifiées.
2. Produire une sauvegarde cohérente et prouver sa restauration.
3. Préparer la destination, son stockage et son réseau sans l'exposer.
4. Déployer une version compatible, effectuer une première synchronisation et
   tester sans trafic utilisateur.
5. Geler les écritures sur la source, effectuer la synchronisation finale et
   vérifier la cohérence.
6. Faire approuver le point de bascule, changer la route, puis tester lecture et
   écriture.
7. Garder la source isolée et en lecture seule pendant la fenêtre de retour.
8. La retirer seulement après une validation explicite.

```text
avant la première écriture sur la destination
`-> retour généralement simple vers la source

après la première écriture sur la destination
`-> retour conditionnel : resynchronisation, RPO accepté ou réparation avant
```

Après de nouvelles écritures, remettre simplement l'ancienne route peut perdre
des données ou créer deux sources d'autorité. La Console doit donc nommer le
détenteur actuel des écritures, la fraîcheur de la synchronisation et un retour
`disponible`, `conditionnel` ou `indisponible`.

## Panne pendant une bascule

Si le Controller perd sa connexion après avoir demandé une nouvelle route :

1. bloquer toute nouvelle mutation et tout rejeu automatique ;
2. annoncer un résultat inconnu ;
3. observer indépendamment la route active, le backend et l'autorité d'écriture ;
4. remettre la route précédente seulement si la destination n'a reçu aucune
   écriture incompatible ;
5. sinon, empêcher les deux côtés d'écrire et demander une décision de reprise ;
6. conserver la chronologie et les preuves avant toute nouvelle opération.

Le service déjà en fonctionnement ne dépend pas de la disponibilité de la
Console, du Controller ou du Relay. Une panne du plan de contrôle arrête les
nouvelles actions, pas les charges utiles déjà déployées.

## Lecture OWASP et NIS2

L'ordre retenu applique les valeurs sûres, le moindre privilège, la défense en
profondeur, la réduction de surface et l'échec sûr de
[l'OWASP Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html).
La préparation fermée, le flux exact et les refus latéraux suivent également le
principe de segmentation défensive décrit par
[OWASP Network Segmentation](https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html).

L'[article 21 de NIS2](https://eur-lex.europa.eu/legal-content/FR/TXT/?uri=CELEX:32022L2555)
ne prescrit pas cet ordre ni une technologie particulière. Il demande des
mesures appropriées et proportionnées couvrant notamment l'analyse de risque,
la gestion des incidents, la continuité et la reprise, le développement sûr,
l'évaluation de l'efficacité, la cryptographie, le contrôle d'accès et, lorsque
pertinent, l'authentification multifacteur.

| Risque | Mesure proposée | Preuve attendue | Risque résiduel |
|---|---|---|---|
| exposition prématurée | réseau préparé fermé et publication en dernier | backend inaccessible avant la bascule | erreur dans la route finale |
| mouvement latéral | destination, port et identité explicitement bornés | refus SSH, autres ports et voisins du LAN | compromission d'un flux autorisé |
| perte pendant une migration | restauration prouvée, gel des écritures et point de non-retour visible | scénario de restauration et panne en bascule | RPO ou interruption annoncés |
| rejeu après une coupure | état inconnu et observation indépendante | aucun second effet après perte du contrôle | diagnostic manuel nécessaire |

Ces choix peuvent contribuer à une démarche OWASP et NIS2 ; ils ne constituent
pas à eux seuls une déclaration de conformité.
<!-- coherence: SERVICE-LIFECYCLE:end -->

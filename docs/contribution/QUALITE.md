# Qualité du code

Ces règles s'appliquent à tout code produit, outil et automatisation du projet.
Un changement temporaire ne justifie jamais une base illisible qu'une autre
personne ne pourrait pas reprendre.

## Résultat recherché

Une personne qui ne maîtrise pas encore le code doit pouvoir ouvrir un petit
ensemble de fichiers et comprendre :

- où chaque composant s'exécute ;
- quelles données il reçoit et envoie ;
- ce qu'il a le droit de modifier ;
- comment il échoue et redémarre ;
- comment son comportement est vérifié dans le LAB.

Une explication extérieure au code ne compense pas une structure confuse.

## Règles non négociables

- Employer des noms métier explicites et une structure prévisible.
- Donner à une fonction, un type ou un module une responsabilité cohérente.
- Appliquer KISS et YAGNI : aucune abstraction, option ou extension « au cas
  où » sans besoin actuel démontré.
- Appliquer DRY aux règles qui doivent évoluer ensemble, sans fusionner trop
  tôt des cas seulement ressemblants.
- Réduire les conditions imbriquées avec des gardes précoces et nommer les
  décisions importantes.
- Isoler les accès disque, réseau, processus et système du calcul de décision.
- Rendre chaque effet de bord explicite, borné, observable et testable.
- Produire des erreurs précises et actionnables, préserver leur cause et ne
  jamais inclure de secret.
- Écrire les commentaires et docstrings pour le contrat, l'invariant, l'origine
  ou la destination d'une donnée et les limites de sécurité.
- Ne retirer une branche prétendument morte qu'après avoir prouvé qu'aucune
  compatibilité, garde de sécurité ou trajectoire de reprise n'en dépend.

Une fonction concise est souhaitable, mais aucune limite arbitraire de lignes
n'est imposée. Un découpage n'est utile que si les sous-fonctions possèdent un
nom, un contrat et une responsabilité plus clairs que le flux initial.

## Lisibilité des fonctions

Par défaut, une fonction d'entrée ou d'orchestration doit pouvoir se lire de
haut en bas comme une suite courte d'étapes métier nommées. Lorsqu'elles ont un
contrat propre, séparer la validation, la construction des données, l'effet de
bord, l'interprétation du résultat et la transition d'état dans des fonctions
auxiliaires privées.

- Nommer chaque fonction auxiliaire par l'intention qu'elle porte, pas par son
  mécanisme interne.
- Lui donner des entrées et une sortie aussi étroites que sa responsabilité,
  sans lui transmettre un objet général uniquement par commodité.
- Préférer les gardes précoces afin que le chemin nominal reste visible.
- Garder l'ordre réel des opérations et les frontières de sécurité apparents
  dans la fonction d'orchestration.
- Ne pas extraire une fonction si elle ne fait que déplacer une expression sans
  clarifier un contrat, une décision ou un effet de bord.
- Lors d'un refactor de lisibilité, préserver les comportements observables,
  notamment les erreurs, logs, formats, délais et effets réseau, puis rejouer
  les tests normaux et hostiles qui couvrent ces contrats.

Ce découpage reste proportionné : une fonction courte et déjà linéaire n'a pas
à être fragmentée pour respecter un style uniforme.

## Justification de sécurité obligatoire

Chaque choix technique ou de développement est accompagné, dans sa source
canonique ou son rapport de preuve, d'une justification courte contenant :

1. le scénario et les actifs concernés ;
2. la menace ou l'échec traité ;
3. les alternatives réellement considérées ;
4. la portée d'accès accordée et le moindre privilège obtenu ;
5. les recommandations OWASP pertinentes : valeur sûre par défaut, réduction
   de surface, séparation des responsabilités, défense en profondeur, Zero
   Trust ou segmentation selon le cas ;
6. les mesures NIS2 pertinentes dans une lecture proportionnée au risque :
   analyse des risques, gestion d'incident, continuité, chaîne
   d'approvisionnement, développement sûr, mesure d'efficacité,
   cryptographie, contrôle d'accès ou gestion des actifs ;
7. les tests normaux et hostiles qui apporteront la preuve ;
8. le risque résiduel et ce qui reste explicitement non garanti.

OWASP fournit des recommandations de conception, et NIS2 impose une démarche
globale de gestion des risques aux organisations concernées. Aucun composant,
algorithme ou test isolé ne permet d'affirmer que Your Cloud ou son utilisateur
est « conforme OWASP » ou « conforme NIS2 ».

Références de départ :

- [OWASP Secure Product Design](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html) ;
- [OWASP Network Segmentation](https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html) ;
- [Directive NIS2, article 21](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex%3A32022L2555).

## Go

- Conserver les retours `error` explicites, les enrichir avec du contexte et
  préserver leur chaîne.
- Ajouter une erreur sentinelle ou typée seulement lorsqu'un appelant doit
  réellement la distinguer.
- Définir les petites interfaces du côté du consommateur et ne pas créer une
  interface pour chaque structure.
- Garder les packages centrés sur une capacité cohérente.
- Documenter avec GoDoc les API et invariants importants sans paraphraser les
  évidences.

<!-- coherence: AGENT-AUTHORITY:start -->
## Auxiliaire et actions locales

- Implémenter l'Auxiliaire comme un mode ponctuel du même artefact Go, jamais
  comme un service permanent, un listener ou un shell général. Son premier
  palier n'expose qu'un diagnostic de protocole en lecture seule et refuse toute
  mutation avant l'ajout d'une opération contractée.
- Accepter uniquement une opération versionnée et des paramètres typés par une
  liste positive ; refuser champ, comportement, chemin, destination, capacité
  ou ressource inconnus avant mutation.
- Garder Daemon, Relay et Auxiliaire dans des processus, comptes, identités,
  secrets, fichiers et budgets distincts. Le Daemon et le Relay ne transportent
  jamais de plan.
- Lancer l'Auxiliaire par une identité SSH propre à la machine et une commande
  forcée qui interdit shell, PTY, SFTP, rc utilisateur, X11, environnement,
  transfert de port et transfert d'agent.
- Lier cette clé à un compte technique verrouillé distinct ; garder
  `authorized_keys`, ses parents, le chemin absolu du binaire et l'élévation
  possédés par `root` et non inscriptibles par ce compte. Borner l'élévation à
  l'invocation exacte de l'Auxiliaire, environnement réinitialisé, sans argument,
  `SETENV` ou règle `sudo` générale.
- Faire signer l'enveloppe canonique du plan et de son rollback par le cœur
  natif de l'App après confirmation explicite ; ne fournir au frontend
  aucune primitive de signature libre.
- Revérifier localement signature, clé publique d'approbation, infrastructure,
  machine, époque, successeur exact de la séquence, action, version, expiration
  et préconditions sans faire confiance au Controller qui transporte le plan.
- Consommer atomiquement la séquence avant la première mutation dans un état
  anti-rejeu root-owned minimal. Refuser les séquences anciennes ou déjà
  consommées avant et après redémarrage.
- Après une récupération de App qui remplace la clé humaine, refuser toute
  action jusqu'à la rotation des ancres par l'Assistant et l'accès SSH
  personnel ; ne jamais laisser le Controller tourner seul cette confiance.
- Ne donner aucun accès réseau général à l'Auxiliaire. Une opération OCI peut
  seulement faire utiliser par Podman rootless le registre autorisé et le
  digest exact présents dans le plan.
- Rendre `changed=true` pour la première mutation réelle. Le même état demandé
  sans dérive et le retrait d'un élément déjà absent rendent `changed=false`
  sans réécriture ni redémarrage.
- Signaler une dérive et exiger un nouveau plan au lieu de la corriger
  silencieusement.
- Décrire un rollback exact dans le plan et le couvrir par son approbation.
  Après un échec contrôlé, le tenter tant que l'Auxiliaire garde la maîtrise ;
  annoncer un état partiel s'il échoue.
- Après une coupure, rendre `résultat inconnu`, ne rien rejouer et observer
  avant tout nouveau plan. `v0.1.0` n'ajoute ni historique local général, ni
  continuation autonome de l'Auxiliaire ; seul l'état anti-rejeu minimal
  persiste.

## Ansible externe ou futur

- Ansible n'est ni une dépendance du Controller, ni le runtime d'action de
  `v0.1.0`. L'utilisateur peut conserver ses playbooks en mode externe.
- Une intégration future exige son propre contrat et un runner isolé ; elle
  n'est pas préconçue dans le cœur ou l'Auxiliaire actuel.
- Lorsqu'un playbook existe pour le LAB, un parcours externe ou une future
  intégration, nommer chaque tâche par l'état recherché et préférer les modules
  déclaratifs.
- Réserver le shell aux cas justifiés, bornés et vérifiés.
- Garder variables, conditions et inclusions explicites.
- Refuser tôt avec un message précis lorsque les préconditions ou les chemins
  ne correspondent pas au plan approuvé.
- Exécuter `--syntax-check`, puis le scénario LAB et un second passage attendu à
  `changed=0` avant de parler d'idempotence.

## Plans et adaptateurs d'action

Ces règles s'appliquent seulement lorsqu'un changement introduit réellement une
action ; elles ne justifient aucune abstraction anticipée :

- l'approbation est liée au plan exact et l'application refuse tout artefact,
  cible ou paramètre qui ne correspond plus à son empreinte ;
- l'interface ne fournit jamais directement un playbook, une commande, un
  script, un chemin, un inventaire ou des arguments libres ;
- chaque adaptateur accepte un schéma positif puis valide aussi la portée
  sémantique des volumes, destinations, ports, capacités et ressources ;
- une autorité privilégiée revérifie localement le plan sans faire confiance au
  composant qui l'a transporté et reçoit seulement les droits de l'opération ;
- les transitions `en attente`, `en cours`, `réussi`, `échoué` et `résultat
  inconnu` sont persistées par le Controller et aucun retry d'une mutation non
  idempotente n'est implicite ;
- les résultats sont structurés, bornés, expurgés et reliés à l'identifiant du
  plan sans transporter de secret persistant ;
- mise à jour de l'Agent, politiques privilégiées et actions métier utilisent
  des autorités distinctes.
<!-- coherence: AGENT-AUTHORITY:end -->

## Shell et `labctl`

- Ne pas faire croître un script monolithique par accumulation aveugle de
  branches.
- Séparer progressivement les données de topologie, les gardes, le moteur
  libvirt, le transport de fichiers et le rendu CLI lorsque la modification en
  cours le justifie.
- Citer les expansions, borner les entrées et éviter les commandes distantes
  construites par concaténation.
- Garder une interface humaine claire et, si nécessaire, une sortie machine
  stable distincte.

## Documentation

- Conserver une source canonique courte pour chaque sujet.
- Appliquer `docs/projet/COHERENCE.md` dès qu'une décision transverse est
  validée : source canonique, projections obligatoires et vues HTML changent
  dans le même travail.
- Exécuter `tools/check-docs` après cette propagation. Ses marqueurs prouvent
  que les vues attendues ont été traitées, jamais qu'elles disent exactement la
  même chose ; relire leur sens reste obligatoire.
- Garder `CONTEXT.md` comme glossaire uniquement.
- Ne créer un ADR que pour une décision difficile à renverser, surprenante et
  issue d'un véritable compromis.
- Mettre à jour la source Markdown et son édition HTML lorsque le flux visuel
  correspondant change.
- Faire évoluer `docs/architecture/ANATOMIE.md` et son édition HTML dès qu'un
  changement ajoute ou modifie un composant, un placement, une autorité ou un
  flux réseau.
- Représenter visuellement les machines, les protections et les limites, puis
  distinguer ce qui est décidé, implémenté et réellement prouvé dans le LAB.
- Lors de la première utilisation d'une technologie nouvelle dans le projet,
  expliquer avant la preuve pourquoi elle existe, quelle autorité elle reçoit,
  quel principe OWASP ou mesure NIS2 elle aide concrètement à appliquer et ce
  qu'elle ne garantit pas.
- Distinguer explicitement ce qui est documenté, implémenté et réellement
  prouvé.

## Preuves et fixtures

Une fixture est légitime pour isoler un contrat, provoquer un cas hostile
impossible à obtenir autrement ou remplacer une dépendance extérieure au
produit. Elle cesse de l'être dès qu'elle remplace **un composant du produit
sur le trajet que la preuve prétend prouver** : la preuve devient alors verte
sur un chemin que personne n'a construit, et l'absence se découvre au palier
suivant plutôt qu'à celui qui l'a créée.

- **Nommer chaque fixture qui remplace un composant du produit.** Le rapport
  LAB dit lequel, pourquoi, et ce que la preuve cesse de couvrir de ce fait ; le
  commentaire de fermeture de l'issue reprend cette dette au lieu de la laisser
  dans le seul rapport. Une fixture nommée est une dette ; une fixture tue est
  une fausse preuve.
- **Chaque milestone porte au moins une preuve à trajet produit complet, sans
  fixture.** Tous les maillons du parcours qu'elle prouve y sont exercés par les
  binaires réellement livrés. Son rapport liste ce que les preuves antérieures
  remplaçaient par une fixture sur ce même trajet, et cette liste doit être
  vide à la fermeture.
- **Une fixture qui remplace un composant du produit ne se substitue jamais à
  la preuve de ce composant.** Elle peut précéder cette preuve dans le temps ;
  elle ne peut ni la remplacer, ni justifier de la reporter indéfiniment.
- **Nommer aussi ce que le pilotage lui-même ne prouve pas.** Un harnais qui
  conduit une interface, un dialogue natif ou une machine atteste ce que son
  mécanisme peut atteindre : le rapport dit lequel a été employé et ce qu'il ne
  remplace pas.

## Condition de sortie d'un changement

Un changement est terminé seulement lorsque :

1. son résultat observable correspond exactement au périmètre annoncé ;
2. son code et ses données peuvent être expliqués sans dépendre d'une future
   fonctionnalité ;
3. ses erreurs et cas hostiles importants sont vérifiés ;
4. les validations adaptées sont exécutées dans le LAB ou le runner approprié ;
5. le second passage attendu est stable lorsque l'opération doit être
   idempotente ;
6. la documentation décrit encore le placement, les commandes, les preuves et
   les limites réelles ;
7. la justification OWASP et NIS2 proportionnée est relue avec ses tests
   hostiles et son risque résiduel ;
8. le changement est compréhensible avant l'ouverture du chantier suivant ;
9. toute fixture qui remplace un composant du produit sur le trajet prouvé est
   nommée comme dette dans le rapport LAB et dans le commentaire de fermeture.

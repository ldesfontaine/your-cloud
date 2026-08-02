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
et scénarios multi-VM restent sous l'autorité du LAB Linux. Un nouveau LAB
Windows ne serait ouvert que pour un défaut fonctionnel réellement propre à
Windows, jamais pour simuler la topologie dans la CI générique.

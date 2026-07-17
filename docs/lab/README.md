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

Pour `v0.0.1`, `tools/prove-v0.0.1` est l'entrée d'orchestration. Le poste de
développement ne fait qu'empaqueter le lot non sensible, calculer ses empreintes
et appeler `labctl`. `tools/test-v0.0.1`, le build, le binaire, HTTP et systemd
s'exécutent uniquement dans les VM LAB. Une erreur après mutation sélectionne
et vérifie l'état absent ; un succès réinstalle l'état final documenté.

L'existence d'une topologie dans `labctl` signifie uniquement que l'outil sait
la créer. Une capacité devient prouvée seulement après une exécution réelle,
documentée et reproductible dans le LAB approprié.

## Rapports exécutés

- [`v0.0.1` — un artefact, trois processus isolés](v0.0.1-presence.md) : build
  Go unique, Daemon et Relay parallèles sur le VPS, Daemon seul sur le LAN,
  refus candidat et HTTP, transitions `recent`/`old`/`absent`, retrait et
  réinstallation dans `v1-full`, le 16 juillet 2026.

# Séparer strictement observation et administration

Statut : proposé · consolidation P0 du 2026-07-12

## Contexte

Un composant de télémétrie exposé ou compromis ne doit pas devenir un chemin de
commande vers les machines. La simplicité d’un agent unique serait attractive,
mais elle réunirait observation et privilèges d’administration dans la même
surface d’attaque.

## Décision

- La console possède les déclarations, secrets et accès d’administration. Elle
  présente les plans et atteint directement les machines par SSH et Ansible.
- Le daemon observe sous un compte sans connexion interactive ni `sudo`. Il ne
  reçoit aucune commande et ne transporte aucun secret de mutation.
- Le coordinateur conserve et sert la télémétrie. Il ne possède ni clé SSH, ni
  secret d’infrastructure, ni autorité d’enrôlement ou de révocation.
- L’identité distante de console ne donne qu’un droit de lecture de la
  télémétrie autorisée.
- Un éventuel exécuteur futur sera un composant séparé avec son propre compte,
  son identité et un protocole d’actions structurées ; jamais du shell libre.

## Conséquences

Une compromission du chemin d’observation peut affecter la disponibilité ou la
confidentialité de la télémétrie sans fournir volontairement un accès
d’administration. La console reste une autorité sensible à protéger et à
restaurer. Certaines actions distantes resteront impossibles en V1 lorsque le
chemin SSH direct n’est pas disponible.

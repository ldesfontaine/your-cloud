# Séparer bootstrap, administration et mutation risquée

Statut : accepté · ratification P0 du 2026-07-12

## Contexte

Créer un nouvel accès puis fermer l’ancien dans une seule opération opaque peut
verrouiller l’opérateur hors de la machine. Un rollback universel demanderait
un composant privilégié supplémentaire dont la V1 n’a pas démontré le besoin.

## Décision

- La préparation du chemin d’administration et le profil de sécurisation sont
  deux plans distincts avec approbations et retours séparés.
- Le compte normal d’administration est non-root et propre à chaque machine.
  Sa clé privée, équivalente à root par `sudo`, reste chiffrée dans la console.
- La console conserve son propre registre de clés d’hôte, séparé de
  l’environnement SSH personnel. Le premier contact peut utiliser un TOFU
  visible ; toute connexion suivante exige l’empreinte épinglée.
- L’ancien accès reste ouvert jusqu’à la preuve d’une nouvelle connexion et de
  `sudo` par une session réellement distincte.
- Avant une mutation SSH ou pare-feu, l’ancien état est préparé, la session
  courante est conservée et l’opérateur confirme un accès hors bande.
- En cas d’échec, la session conservée restaure uniquement les éléments possédés
  par le plan. La perte simultanée de cette session exige le canal hors bande.

## Conséquences

Le parcours expose deux frontières de risque au lieu de promettre une mutation
atomique fictive. Il demande un accès hors bande pour les machines réelles et
un stockage sûr des clés, mais n’installe pas de minuteur root ou de mécanisme
commit-confirm tant qu’un besoin réel ne le justifie pas.

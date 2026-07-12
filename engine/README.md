# Engine Ansible

L'engine contient le playbook P2 qui installe le daemon via le chemin SSH direct
après audit, plan visible, approbation et `--syntax-check`. Le daemon et le
coordinateur ne peuvent pas invoquer cet engine. Toute exécution reste confinée
au LAB prévu par l’ADR 0011.

Le re-run de l'enrôlement doit rester à `changed=0`.

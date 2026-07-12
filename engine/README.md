# Engine Ansible

L'engine contient le playbook qui installe le daemon via le chemin SSH direct
après audit, plan visible, approbation et `--syntax-check`. Le daemon et le
coordinateur ne peuvent pas invoquer cet engine. Toute exécution reste confinée
au LAB prévu par l’ADR 0011.

Deux playbooks séparés préparent ensuite le compte d'administration, puis le
profil SSH, nftables et sysctl. Le second conserve une session existante et
prépare un rollback avant les changements qui pourraient couper l'accès.
Chaque re-run doit rester à `changed=0`.

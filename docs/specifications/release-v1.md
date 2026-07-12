# Contrat de release V1

> État : lot stable `1.0.0` construit deux fois à l'identique, installé à neuf
> et mis à niveau depuis RC2 dans le LAB.

La matrice V1 lie la console, le daemon et le coordinateur `1.0.0` au
protocole 1, à la déclaration 2 et au registre d'identités 2. Debian 13 amd64
est la seule plateforme prouvée.

Voir la [preuve d'adoption RC2](../lab/rc2-adoption.md).
La [preuve finale stable](../lab/v1-stable.md) ferme la reproductibilité,
l'installation neuve, la mise à niveau et l'idempotence du lot `1.0.0`.

Une release stable contient des noms versionnés, des sommes SHA-256, une
signature Ed25519 produite par OpenSSL et les instructions de vérification. La
preuve LAB utilise une clé synthétique. Une publication publique exige une clé et
une empreinte approuvées hors du lot publié.

Les candidates ne reçoivent ni tag ni release GitHub. Le tag `v1.0.0` et toute release GitHub exigent une approbation explicite de la
référence exacte par la personne responsable de la publication, même lorsque
toutes les preuves LAB sont vertes.

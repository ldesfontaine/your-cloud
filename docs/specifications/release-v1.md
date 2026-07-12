# Contrat de release V1

> État : release candidate `1.0.0-rc.2` construite, signée et vérifiée dans
> le LAB, puis installée et enrôlée depuis son seul lot distribuable.

La matrice V1 lie la console, le daemon et le coordinateur `1.0.0-rc.2` au
protocole 1, à la déclaration 2 et au registre d'identités 2. Debian 13 amd64
est la seule plateforme prouvée.

Voir la [preuve d'adoption RC2](../lab/rc2-adoption.md).

Une release candidate contient des noms versionnés, des sommes SHA-256, une
signature Ed25519 produite par OpenSSL et les instructions de vérification. La
preuve LAB utilise une clé synthétique. Une publication réelle exige une clé et
une empreinte approuvées hors du lot publié.

Le tag `v1.0.0` et toute release GitHub restent interdits avant le GO explicite
de Lucas pour cette référence exacte, même lorsque toutes les preuves LAB sont
vertes.

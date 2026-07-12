"""Erreurs métier traduites en refus lisibles par la console."""

class ConsoleError(Exception):
    """Refus attendu, affichable sans trace Python."""


class DeclarationError(ConsoleError):
    """Déclaration absente, ambiguë ou incompatible avec le schéma."""

    pass


class HostKeyError(ConsoleError):
    """Échec de la chaîne de confiance de la clé d'hôte SSH."""

    pass


class AuditError(ConsoleError):
    """Audit distant impossible, ambigu ou incompatible."""

    pass


class EnrollmentError(ConsoleError):
    """Enrôlement non autorisé ou impossible à prouver."""

    pass


class TelemetryError(ConsoleError):
    """Télémétrie invalide, rejouée ou issue d'une identité refusée."""

    pass


class SecurityError(ConsoleError):
    """Plan de sécurisation ou accès de récupération non sûr."""

    pass


class CoordinationError(ConsoleError):
    """Installation ou échange mTLS avec le coordinateur refusé."""

    pass


class FailureDomainError(ConsoleError):
    """Domaine de panne détecté ou preuve runtime invalide."""

    pass

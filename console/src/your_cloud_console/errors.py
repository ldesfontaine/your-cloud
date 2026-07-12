class ConsoleError(Exception):
    """Refus attendu, affichable sans trace Python."""


class DeclarationError(ConsoleError):
    pass


class HostKeyError(ConsoleError):
    pass


class AuditError(ConsoleError):
    pass


class EnrollmentError(ConsoleError):
    pass


class TelemetryError(ConsoleError):
    pass

"""Exception hierarchy for privkit.

Every error raised deliberately by the library derives from :class:`PrivkitError`
so pipeline code can catch library failures with a single ``except`` clause.
Error messages never include the sensitive value that caused them.
"""

from __future__ import annotations


class PrivkitError(Exception):
    """Base class for all privkit errors."""


class InvalidInputError(PrivkitError, ValueError):
    """An argument or input value is malformed (wrong alphabet, length, range...)."""


class DomainTooSmallError(InvalidInputError):
    """The format-preserving domain is below the NIST minimum of one million values."""


class KeyMaterialError(PrivkitError):
    """Key material is missing, malformed or has an unsupported length."""


class BudgetExceededError(PrivkitError):
    """A differentially private release would exceed the remaining privacy budget."""


class ConfigurationError(PrivkitError):
    """Mutually incompatible or unsupported configuration options."""


class OptionalDependencyError(PrivkitError, ImportError):
    """An optional extra (for example spaCy for NER) is not installed."""

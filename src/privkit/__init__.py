"""privkit: a privacy toolkit for data pipelines.

Subpackages:

* :mod:`privkit.pii` - PII detection (regex + checksums, optional spaCy NER) and anonymization.
* :mod:`privkit.fpe` - NIST SP 800-38G FF1 / FF3-1 format-preserving encryption.
* :mod:`privkit.tokens` - vaultless reversible format-preserving tokenization.
* :mod:`privkit.kanon` - k-anonymity, l-diversity, t-closeness; generalization and Mondrian.
* :mod:`privkit.dp` - differential privacy mechanisms, budget accountant, bounded aggregation.
"""

from privkit.dp import DPAggregator, PrivacyAccountant
from privkit.errors import (
    BudgetExceededError,
    ConfigurationError,
    DomainTooSmallError,
    InvalidInputError,
    KeyMaterialError,
    OptionalDependencyError,
    PrivkitError,
)
from privkit.pii import Detector, anonymize
from privkit.tokens import Tokenizer, TokenPolicy

__version__ = "0.1.0"

__all__ = [
    "BudgetExceededError",
    "ConfigurationError",
    "DPAggregator",
    "Detector",
    "DomainTooSmallError",
    "InvalidInputError",
    "KeyMaterialError",
    "OptionalDependencyError",
    "PrivacyAccountant",
    "PrivkitError",
    "TokenPolicy",
    "Tokenizer",
    "__version__",
    "anonymize",
]

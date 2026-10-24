"""k-anonymity assessment and anonymization (generalization, suppression, Mondrian)."""

from privkit.kanon.generalize import GeneralizationResult, generalize_to_k
from privkit.kanon.hierarchy import (
    SUPPRESSED,
    Hierarchy,
    IntervalHierarchy,
    MappingHierarchy,
    MaskingHierarchy,
    SuppressionHierarchy,
    parse_hierarchy,
)
from privkit.kanon.metrics import RiskReport, SensitiveReport, assess, equivalence_classes
from privkit.kanon.mondrian import MondrianResult, mondrian

__all__ = [
    "SUPPRESSED",
    "GeneralizationResult",
    "Hierarchy",
    "IntervalHierarchy",
    "MappingHierarchy",
    "MaskingHierarchy",
    "MondrianResult",
    "RiskReport",
    "SensitiveReport",
    "SuppressionHierarchy",
    "assess",
    "equivalence_classes",
    "generalize_to_k",
    "mondrian",
    "parse_hierarchy",
]

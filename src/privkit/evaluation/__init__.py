"""Synthetic labeled corpus generation and detector evaluation."""

from privkit.evaluation.corpus import Document, Span, SyntheticValues, generate_corpus
from privkit.evaluation.metrics import EntityScore, EvalReport, evaluate

__all__ = ["Document", "EntityScore", "EvalReport", "Span", "SyntheticValues", "evaluate", "generate_corpus"]

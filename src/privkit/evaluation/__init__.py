"""Synthetic labeled corpus generation and detector evaluation."""

from privkit.evaluation.corpus import Document, Span, generate_corpus
from privkit.evaluation.metrics import EntityScore, EvalReport, evaluate

__all__ = ["Document", "EntityScore", "EvalReport", "Span", "evaluate", "generate_corpus"]

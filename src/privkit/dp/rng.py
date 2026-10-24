"""Randomness for DP mechanisms.

Production code uses :func:`secure_rng` (``secrets.SystemRandom``, backed by the
OS CSPRNG). A seeded ``random.Random`` is accepted for reproducible tests and
demos only: seeded noise is predictable and voids the privacy guarantee.
"""

from __future__ import annotations

import logging
import random
import secrets

logger = logging.getLogger(__name__)


def secure_rng() -> random.Random:
    return secrets.SystemRandom()


def insecure_seeded_rng(seed: int) -> random.Random:
    """Deterministic RNG for tests and demos. Never use it for real releases."""
    logger.warning("using a seeded RNG: DP noise is reproducible and offers NO privacy")
    return random.Random(seed)

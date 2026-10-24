"""Core data types of the PII detector."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Entity(StrEnum):
    """Entity types privkit can detect."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    US_SSN = "US_SSN"
    IBAN = "IBAN"
    IP_ADDRESS = "IP_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"
    US_ABA_ROUTING = "US_ABA_ROUTING"
    IN_AADHAAR = "IN_AADHAAR"
    UK_NHS = "UK_NHS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    PERSON = "PERSON"
    LOCATION = "LOCATION"


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected PII span. ``text`` is the matched value itself.

    ``repr()`` deliberately hides ``text`` so that findings can be logged or
    printed in tracebacks without leaking the value they describe.
    """

    entity: str
    start: int
    end: int
    score: float
    recognizer: str
    text: str
    evidence: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return (
            f"Finding(entity={self.entity!r}, start={self.start}, end={self.end}, "
            f"score={self.score:.2f}, recognizer={self.recognizer!r}, text=<redacted len={len(self.text)}>)"
        )

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Finding) -> bool:
        return self.start < other.end and other.start < self.end

    def to_dict(self, *, include_text: bool = False) -> dict[str, object]:
        out: dict[str, object] = {
            "entity": self.entity,
            "start": self.start,
            "end": self.end,
            "score": round(self.score, 4),
            "recognizer": self.recognizer,
            "evidence": list(self.evidence),
        }
        if include_text:
            out["text"] = self.text
        return out

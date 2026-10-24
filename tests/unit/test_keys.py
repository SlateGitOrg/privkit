from __future__ import annotations

import base64

import pytest

from privkit.errors import KeyMaterialError
from privkit.keys import derive_key, generate_key_hex, key_from_env, parse_key


def test_parse_hex_and_base64() -> None:
    raw = bytes(range(32))
    assert parse_key(raw.hex()) == raw
    assert parse_key(base64.b64encode(raw).decode()) == raw
    assert parse_key(base64.urlsafe_b64encode(raw).decode().rstrip("=")) == raw
    with pytest.raises(KeyMaterialError):
        parse_key("abcd")
    with pytest.raises(KeyMaterialError):
        parse_key("!!!not a key!!!")


def test_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PK_TEST", "00" * 32)
    assert key_from_env("PK_TEST") == bytes(32)
    monkeypatch.delenv("PK_TEST")
    with pytest.raises(KeyMaterialError):
        key_from_env("PK_TEST")


def test_derive_key_is_purpose_bound() -> None:
    m = bytes(32)
    assert derive_key(m, "a") == derive_key(m, "a")
    assert derive_key(m, "a") != derive_key(m, "b")
    assert len(derive_key(m, "a", 16)) == 16
    with pytest.raises(KeyMaterialError):
        derive_key(b"x", "a")


def test_generate_key() -> None:
    k = generate_key_hex()
    assert len(parse_key(k)) == 32 and k != generate_key_hex()
    with pytest.raises(KeyMaterialError):
        generate_key_hex(7)

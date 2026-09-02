"""Strict schema validation for SimpleFin v2 /accounts responses.

`response.json()` (or `json.loads`) only proves the bytes were syntactically
valid JSON. It says nothing about types, bounds, or semantics -- and a
SimpleFin bridge, or anyone able to influence its response, is untrusted
input regardless of TLS. Every value here is validated before it becomes
part of this application's trusted data model; nothing downstream should
ever call `.get()` on a raw SimpleFin dict again.

Design choices:

* `extra="ignore"` on every model: unknown fields (the protocol may grow
  new ones) are dropped rather than trusted or dynamically mapped into
  behavior, per the OWASP Input Validation Cheat Sheet's allowlist stance.
* Money is parsed through `decimal.Decimal`, never `float()`, so a
  malicious amount string (an oversized exponent, "inf", "nan", garbage)
  is rejected outright instead of silently producing a non-finite or
  imprecise value. `simplefin.py` rounds to 2dp for the existing
  float-based JSON pipeline only *after* this validation.
* Free-text fields (names, descriptions, org names, error strings) are
  bounded in length and checked for embedded NUL bytes, but are otherwise
  preserved as opaque text -- they are not sanitized into "safe HTML".
  Output encoding at render time (Jinja autoescape server-side,
  `escapeHtml` / `textContent` client-side) is what makes them safe to
  display, not a stripped-down allowlist of characters here.
* Lists are bounded so a hostile or buggy upstream cannot force this
  process to allocate unbounded memory from one response.
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_ACCOUNTS = 200
MAX_TRANSACTIONS_PER_ACCOUNT = 20_000
MAX_ERRORS = 200
MAX_ID_LENGTH = 300
MAX_NAME_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 4000
MAX_CURRENCY_LENGTH = 16
MAX_AMOUNT_MAGNITUDE = Decimal("1000000000000")  # 1e12; pathological-input guard, not a business rule
MIN_TIMESTAMP = 0  # 1970-01-01
MAX_TIMESTAMP = 4102444800  # 2100-01-01


class SchemaValidationError(RuntimeError):
    """SimpleFin returned a response that does not conform to the v2
    protocol shape this application understands. Callers must fail closed:
    no partial data is extracted from a response that fails validation."""


def _no_nul(value: str) -> str:
    if "\x00" in value:
        raise ValueError("embedded NUL byte")
    return value


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore", str_max_length=MAX_NAME_LENGTH)


class Org(_Base):
    name: str | None = Field(default=None, max_length=MAX_NAME_LENGTH)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v):
        return _no_nul(v) if v is not None else v


class Transaction(_Base):
    id: str = Field(max_length=MAX_ID_LENGTH)
    posted: int | None = None
    transacted_at: int | None = None
    amount: str = Field(max_length=64)
    description: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    payee: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    memo: str | None = Field(default=None, max_length=MAX_DESCRIPTION_LENGTH)
    pending: bool = False

    @field_validator("id", "description", "payee", "memo")
    @classmethod
    def _check_text(cls, v):
        return _no_nul(v) if isinstance(v, str) else v

    @field_validator("posted", "transacted_at")
    @classmethod
    def _check_timestamp(cls, v):
        if v is None:
            return v
        if not (MIN_TIMESTAMP <= v <= MAX_TIMESTAMP):
            raise ValueError("timestamp out of plausible range")
        return v

    @field_validator("amount")
    @classmethod
    def _check_amount(cls, v):
        try:
            parsed = Decimal(v)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError("amount is not a valid decimal number") from exc
        if not parsed.is_finite():
            raise ValueError("amount must be finite")
        if abs(parsed) > MAX_AMOUNT_MAGNITUDE:
            raise ValueError("amount magnitude out of bounds")
        return v

    def decimal_amount(self) -> Decimal:
        return Decimal(self.amount)


class Account(_Base):
    id: str = Field(max_length=MAX_ID_LENGTH)
    name: str | None = Field(default=None, max_length=MAX_NAME_LENGTH)
    currency: str | None = Field(default=None, max_length=MAX_CURRENCY_LENGTH)
    org: Org | None = None
    transactions: list[Transaction] = Field(default_factory=list, max_length=MAX_TRANSACTIONS_PER_ACCOUNT)

    @field_validator("id", "name")
    @classmethod
    def _check_text(cls, v):
        return _no_nul(v) if isinstance(v, str) else v


class AccountSet(_Base):
    accounts: list[Account] = Field(default_factory=list, max_length=MAX_ACCOUNTS)
    errors: list[str] = Field(default_factory=list, max_length=MAX_ERRORS)

    @field_validator("errors")
    @classmethod
    def _check_errors(cls, v):
        return [_no_nul(e)[:MAX_DESCRIPTION_LENGTH] for e in v if isinstance(e, str)]


def parse_account_set(raw_body: bytes) -> AccountSet:
    """Parse and fully validate a SimpleFin /accounts response body.
    Raises SchemaValidationError for anything that doesn't conform --
    malformed JSON, wrong top-level shape, wrong field types, oversized
    strings/arrays, unparsable/non-finite/oversized amounts, or
    out-of-range timestamps. Never returns partial data."""
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SchemaValidationError("response body is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise SchemaValidationError("top-level JSON value must be an object")
    try:
        return AccountSet.model_validate(payload)
    except Exception as exc:  # pydantic.ValidationError plus any coercion errors above
        raise SchemaValidationError("response did not match the expected SimpleFin schema") from exc

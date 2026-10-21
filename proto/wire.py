#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reference codec for the TorusSQL wire protocol v0.1 (canonical JSON form).

Pure-Python, zero-dependency. Encodes/decodes the messages defined in
`torussql.proto` to the canonical JSON encoding of `torussql-wire-v0.1.md`.

Ciphertext is OPAQUE here: `Ciphertext.body` is raw octets the engine
produced. This codec only base64s them — it never inspects their structure.
That is the whole point: an open driver moves ciphertext without
understanding it.

Run `python wire.py` to execute a round-trip self-test.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Union


# ── Opaque ciphertext ────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Ciphertext:
    scheme: int
    body: bytes                      # opaque engine octets

    def to_json(self) -> dict:
        return {"scheme": self.scheme,
                "body": base64.b64encode(self.body).decode("ascii")}

    @staticmethod
    def from_json(d: dict) -> "Ciphertext":
        return Ciphertext(scheme=int(d["scheme"]),
                          body=base64.b64decode(d["body"]))


@dataclass(frozen=True)
class Rational:
    num: int
    den: int

    def to_json(self) -> dict:
        return {"num": self.num, "den": self.den}

    @staticmethod
    def from_json(d: dict) -> "Rational":
        return Rational(num=int(d["num"]), den=int(d["den"]))


# ── Value (oneof) ────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Value:
    """Exactly one of the fields is non-None (the present oneof arm)."""
    int_val: int | None = None
    str_val: str | None = None
    rat_val: Rational | None = None
    cipher: Ciphertext | None = None
    is_null: bool = False

    def to_json(self) -> dict:
        if self.is_null:
            return {"is_null": True}
        if self.int_val is not None:
            return {"int_val": self.int_val}
        if self.str_val is not None:
            return {"str_val": self.str_val}
        if self.rat_val is not None:
            return {"rat_val": self.rat_val.to_json()}
        if self.cipher is not None:
            return {"cipher": self.cipher.to_json()}
        raise ValueError("Value has no arm set")

    @staticmethod
    def from_json(d: dict) -> "Value":
        if d.get("is_null"):
            return Value(is_null=True)
        if "int_val" in d:
            return Value(int_val=int(d["int_val"]))
        if "str_val" in d:
            return Value(str_val=str(d["str_val"]))
        if "rat_val" in d:
            return Value(rat_val=Rational.from_json(d["rat_val"]))
        if "cipher" in d:
            return Value(cipher=Ciphertext.from_json(d["cipher"]))
        raise ValueError(f"Value has no recognized arm: {d}")


# ── Handshake ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Hello:
    client_name: str
    max_dialect_version: int = 1

    def to_json(self) -> dict:
        return {"client_name": self.client_name,
                "max_dialect_version": self.max_dialect_version}

    @staticmethod
    def from_json(d: dict) -> "Hello":
        return Hello(client_name=d["client_name"],
                     max_dialect_version=int(d.get("max_dialect_version", 1)))


@dataclass(frozen=True)
class Welcome:
    dialect_version: int
    scheme: int
    decode_range_additive: int
    decode_range_product: int
    capabilities: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"dialect_version": self.dialect_version,
                "scheme": self.scheme,
                "decode_range_additive": self.decode_range_additive,
                "decode_range_product": self.decode_range_product,
                "capabilities": list(self.capabilities)}

    @staticmethod
    def from_json(d: dict) -> "Welcome":
        return Welcome(dialect_version=int(d["dialect_version"]),
                       scheme=int(d["scheme"]),
                       decode_range_additive=int(d["decode_range_additive"]),
                       decode_range_product=int(d["decode_range_product"]),
                       capabilities=list(d.get("capabilities", [])))


# ── Execute ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ExecuteRequest:
    sql: str
    params: list[Value] = field(default_factory=list)

    def to_json(self) -> dict:
        return {"sql": self.sql, "params": [p.to_json() for p in self.params]}

    @staticmethod
    def from_json(d: dict) -> "ExecuteRequest":
        return ExecuteRequest(sql=d["sql"],
                              params=[Value.from_json(p)
                                      for p in d.get("params", [])])


@dataclass(frozen=True)
class Row:
    cells: list[Value]

    def to_json(self) -> dict:
        return {"cells": [c.to_json() for c in self.cells]}

    @staticmethod
    def from_json(d: dict) -> "Row":
        return Row(cells=[Value.from_json(c) for c in d["cells"]])


@dataclass(frozen=True)
class ResultSet:
    columns: list[str]
    rows: list[Row]

    def to_json(self) -> dict:
        return {"columns": list(self.columns),
                "rows": [r.to_json() for r in self.rows]}

    @staticmethod
    def from_json(d: dict) -> "ResultSet":
        return ResultSet(columns=list(d["columns"]),
                         rows=[Row.from_json(r) for r in d["rows"]])


ERROR_KINDS = ("PARSE", "POLICY", "UNSUPPORTED", "RANGE", "INTERNAL")


@dataclass(frozen=True)
class Error:
    kind: str
    message: str

    def __post_init__(self):
        if self.kind not in ERROR_KINDS:
            raise ValueError(f"unknown ErrorKind {self.kind!r}")

    def to_json(self) -> dict:
        return {"kind": self.kind, "message": self.message}

    @staticmethod
    def from_json(d: dict) -> "Error":
        return Error(kind=d["kind"], message=d.get("message", ""))


@dataclass(frozen=True)
class ExecuteResponse:
    """Exactly one of result / affected / error is set."""
    result: ResultSet | None = None
    affected: int | None = None
    error: Error | None = None

    def to_json(self) -> dict:
        if self.error is not None:
            return {"error": self.error.to_json()}
        if self.affected is not None:
            return {"affected": self.affected}
        if self.result is not None:
            return {"result": self.result.to_json()}
        raise ValueError("ExecuteResponse has no arm set")

    @staticmethod
    def from_json(d: dict) -> "ExecuteResponse":
        if "error" in d:
            return ExecuteResponse(error=Error.from_json(d["error"]))
        if "affected" in d:
            return ExecuteResponse(affected=int(d["affected"]))
        if "result" in d:
            return ExecuteResponse(result=ResultSet.from_json(d["result"]))
        raise ValueError(f"ExecuteResponse has no recognized arm: {d}")


# ── Frame helpers (one JSON object per message) ──────────────────────────────
def dumps(msg: Any) -> str:
    return json.dumps(msg.to_json(), separators=(",", ":"), sort_keys=True)


def _roundtrip(msg: Any, cls: type) -> Any:
    return cls.from_json(json.loads(dumps(msg)))


# ── Self-test ────────────────────────────────────────────────────────────────
def _selftest() -> None:
    # Opaque ciphertext survives a round-trip byte-for-byte.
    ct = Ciphertext(scheme=1, body=bytes(range(256)))
    assert _roundtrip(ct, Ciphertext) == ct

    hello = Hello(client_name="torusctl", max_dialect_version=1)
    assert _roundtrip(hello, Hello) == hello

    welcome = Welcome(dialect_version=1, scheme=1,
                      decode_range_additive=10_000_000,
                      decode_range_product=1_000_000,
                      capabilities=["sum", "scalar_mul", "ct_mul", "dot"])
    assert _roundtrip(welcome, Welcome) == welcome

    # INSERT with a plaintext id and two opaque encrypted params.
    req = ExecuteRequest(
        sql="INSERT INTO payroll (id, rate, hours) VALUES (?, ?, ?)",
        params=[Value(int_val=1),
                Value(cipher=Ciphertext(scheme=1, body=b"\x01\x02opaque")),
                Value(cipher=Ciphertext(scheme=1, body=b"\xff\xfehours"))])
    assert _roundtrip(req, ExecuteRequest) == req

    # SELECT result with one encrypted cell.
    resp = ExecuteResponse(result=ResultSet(
        columns=["dot(x,y)"],
        rows=[Row(cells=[Value(cipher=Ciphertext(scheme=1, body=b"prod"))])]))
    assert _roundtrip(resp, ExecuteResponse) == resp

    # INSERT/CREATE/DROP response.
    assert _roundtrip(ExecuteResponse(affected=1), ExecuteResponse).affected == 1

    # Error response with a valid kind; bad kinds are rejected.
    err = ExecuteResponse(error=Error(kind="RANGE", message="too big"))
    assert _roundtrip(err, ExecuteResponse) == err
    try:
        Error(kind="NOPE", message="x")
        raise AssertionError("bad ErrorKind should have raised")
    except ValueError:
        pass

    # Plaintext NULL and rational arms.
    for v in (Value(is_null=True), Value(rat_val=Rational(2, 3)),
              Value(str_val="alice")):
        assert _roundtrip(v, Value) == v

    print("wire.py self-test: all round-trips OK")


if __name__ == "__main__":
    _selftest()

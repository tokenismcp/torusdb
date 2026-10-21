# SPDX-License-Identifier: Apache-2.0
"""Public key material and per-custodian secret shares."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from . import laurent, seal as _seal
from .group import CustodyError, Group, get_group


class ShareError(CustodyError):
    pass


@dataclass(frozen=True)
class PublicKey:
    """Everything public about a threshold key. Safe to publish and to give to
    anyone who needs to *encrypt* to the key — it contains no secret.

    ``commitments`` are the aggregated Feldman commitments C̄₀…C̄_t of the
    sharing series; ``X = C̄₁`` is the public key (the commitment to the
    residue). Per-custodian verification keys ``Yᵢ = yᵢ·G`` are derived from
    them, which is what lets anyone check a custodian's partial result.
    """
    group: str
    k: int                      # quorum
    n: int                      # custodians
    commitments: tuple          # C̄₀ … C̄_t
    epoch: int = 0

    @property
    def g(self) -> Group:
        return get_group(self.group)

    @property
    def X(self):
        return self.commitments[1]

    @property
    def params(self) -> laurent.Params:
        return laurent.Params(self.k, self.n, self.g.order)

    @property
    def key_id(self) -> str:
        """Stable across refreshes (depends only on the public key X)."""
        return hashlib.sha256(b"torussql/custody/key_id\x00" + self.group.encode()
                              + self.g.encode(self.X)).hexdigest()[:32]

    def verification_key(self, x: int):
        g = self.g
        w = laurent.commit_check_weights(x, self.k - 1, g.order)
        return g.msm(zip(w, self.commitments))

    def check_share(self, x: int, y: int) -> bool:
        g = self.g
        return g.eq(g.mul(g.G, y), self.verification_key(x))

    def to_json(self) -> dict:
        g = self.g
        return {"v": 1, "group": self.group, "k": self.k, "n": self.n,
                "epoch": self.epoch, "key_id": self.key_id,
                "public_key": g.hex(self.X),
                "commitments": [g.hex(c) for c in self.commitments]}

    @staticmethod
    def from_json(d: dict) -> "PublicKey":
        g = get_group(d["group"])
        pk = PublicKey(d["group"], int(d["k"]), int(d["n"]),
                       tuple(g.from_hex(c) for c in d["commitments"]),
                       int(d.get("epoch", 0)))
        if len(pk.commitments) != pk.k:
            raise ShareError("commitment count does not match the quorum")
        if "key_id" in d and d["key_id"] != pk.key_id:
            raise ShareError("public key file is inconsistent (key_id)")
        return pk

    def save(self, path: str) -> None:
        _atomic(path, json.dumps(self.to_json(), indent=2).encode(), 0o644)

    @staticmethod
    def load(path: str) -> "PublicKey":
        return PublicKey.from_json(json.loads(Path(path).read_text()))


@dataclass
class KeyShare:
    """A custodian's SECRET share. ``index`` is also its evaluation point."""
    index: int
    y: int
    public: PublicKey

    @property
    def epoch(self) -> int:
        return self.public.epoch

    def verify(self) -> bool:
        return self.public.check_share(self.index, self.y)

    def to_json(self) -> dict:
        return {"v": 1, "index": self.index, "y": hex(self.y),
                "public": self.public.to_json()}

    @staticmethod
    def from_json(d: dict) -> "KeyShare":
        ks = KeyShare(int(d["index"]), int(d["y"], 16), PublicKey.from_json(d["public"]))
        if not ks.verify():
            raise ShareError("share does not match its public commitments")
        return ks

    # — at rest: sealed under a passphrase (scrypt), file mode 0600 —
    def save(self, path: str, passphrase: str | None) -> None:
        body = json.dumps(self.to_json()).encode()
        if passphrase is None:
            blob = b"TORUSSHARE1 plain\n" + body
        else:
            salt = os.urandom(16)
            blob = (b"TORUSSHARE1 sealed " + salt.hex().encode() + b"\n"
                    + _seal.seal(_seal.passphrase_key(passphrase, salt), body))
        _atomic(path, blob, 0o600)

    @staticmethod
    def load(path: str, passphrase: str | None) -> "KeyShare":
        raw = Path(path).read_bytes()
        head, _, rest = raw.partition(b"\n")
        parts = head.split()
        if not parts or parts[0] != b"TORUSSHARE1":
            raise ShareError(f"{path}: not a custodian share file")
        if parts[1] == b"plain":
            body = rest
        else:
            if passphrase is None:
                raise ShareError("share file is sealed — passphrase required")
            try:
                body = _seal.unseal(_seal.passphrase_key(passphrase, bytes.fromhex(parts[2].decode())), rest)
            except ValueError:
                raise ShareError("wrong passphrase or corrupted share file") from None
        return KeyShare.from_json(json.loads(body))


def _atomic(path: str, data: bytes, mode: int) -> None:
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

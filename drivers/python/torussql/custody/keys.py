# SPDX-License-Identifier: Apache-2.0
"""Public key material and per-custodian secret shares."""
from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import laurent, seal as _seal
from ..recordlog import _create_exclusive, _fsync_dir
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
        """Identity of the KEY, stable across refresh and reshare: it covers ONLY
        the group and the public key X. It deliberately does not cover epoch, k,
        n or the non-X commitments (those change on refresh, while envelopes and
        daemons must keep recognising the same key). Use ``digest`` to pin the
        exact public-key file (epoch + parameters + all commitments)."""
        return hashlib.sha256(b"torussql/custody/key_id\x00" + self.group.encode()
                              + self.g.encode(self.X)).hexdigest()[:32]

    @property
    def digest(self) -> str:
        """Binds group, k, n, epoch and EVERY commitment (changes on refresh)."""
        h = hashlib.sha256(b"torussql/custody/pubdigest/v1\x00" + self.group.encode()
                           + b"\x00" + struct.pack(">QQQ", self.k, self.n, self.epoch))
        for c in self.commitments:
            h.update(self.g.encode(c))
        return h.hexdigest()[:32]

    @property
    def fingerprint(self) -> str:
        """The TRUST ANCHOR of a public.json: a full SHA-256 over group, k, n, epoch and EVERY
        commitment (the verification keys of all custodians derive from them), printed by
        ``public-show``; pin it with ``--expect-fingerprint``. Unlike ``key_id`` (X only) it
        changes at refresh/reshare, so re-pin after those."""
        h = hashlib.sha256(b"torussql/custody/pubfingerprint/v1\x00" + self.group.encode()
                           + b"\x00" + struct.pack(">QQQ", self.k, self.n, self.epoch))
        for c in self.commitments:
            h.update(self.g.encode(c))
        d = h.hexdigest()
        return "-".join(d[i:i + 8] for i in range(0, 64, 8))

    def check_fingerprint(self, expected: str | None) -> None:
        """Raise ``ShareError`` unless ``expected`` (spaces/dashes/colons/case ignored) is this
        key file's fingerprint."""
        if expected is None:
            return
        norm = "".join(ch for ch in expected.lower() if ch not in " -:\n\t")
        if norm != self.fingerprint.replace("-", ""):
            raise ShareError("public key file does not match the expected fingerprint "
                             f"(file: {self.fingerprint}) — refusing to use it")

    def verification_key(self, x: int):
        g = self.g
        w = laurent.commit_check_weights(x, self.k - 1, g.order)
        return g.msm(zip(w, self.commitments))

    def check_share(self, x: int, y: int) -> bool:
        g = self.g
        return g.eq(g.mul_blinded(g.G, y), self.verification_key(x))

    def to_json(self) -> dict:
        g = self.g
        return {"v": 1, "group": self.group, "k": self.k, "n": self.n,
                "epoch": self.epoch, "key_id": self.key_id, "digest": self.digest,
                "public_key": g.hex(self.X),
                "commitments": [g.hex(c) for c in self.commitments]}

    @staticmethod
    def from_json(d: dict) -> "PublicKey":
        try:
            if not isinstance(d, dict) or d.get("group") not in ("secp256k1", "bn254", "bn254g2"):
                raise ShareError("public key file: unknown or missing group")
            g = get_group(d["group"])
            k, n, epoch = d["k"], d["n"], d.get("epoch", 0)
            if any(type(v) is not int for v in (k, n, epoch)):
                raise ShareError("public key file: k, n, epoch must be integers")
            if not (2 <= k <= n <= laurent.MAX_N):
                raise ShareError(f"public key file: need 2 <= k <= n <= {laurent.MAX_N}")
            if not 0 <= epoch < 2 ** 63:
                raise ShareError("public key file: epoch out of range")
            comms = d["commitments"]
            if not isinstance(comms, list) or len(comms) != k:
                raise ShareError("commitment count does not match the quorum")
            pk = PublicKey(d["group"], k, n, tuple(g.from_hex(c) for c in comms), epoch)
        except ShareError:
            raise
        except CustodyError as exc:                      # InvalidPoint
            raise ShareError(f"public key file: {exc}") from None
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ShareError(f"malformed public key file ({type(exc).__name__})") from None
        if g.is_identity(pk.X):
            raise ShareError("public key is the identity")
        if "key_id" in d and d["key_id"] != pk.key_id:
            raise ShareError("public key file is inconsistent (key_id)")
        if "digest" in d and d["digest"] != pk.digest:
            raise ShareError("public key file is inconsistent (digest)")
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
    y: int = field(repr=False)         # SECRET: never in repr/logs/tracebacks
    public: PublicKey

    def __repr__(self) -> str:
        return f"KeyShare(index={self.index}, epoch={self.epoch}, y=<secret>)"

    # Secret material must never be pickled / copied implicitly.
    def __reduce__(self):
        raise TypeError("KeyShare holds secret key material and cannot be pickled or "
                        "copied; use save()/load()")

    def __getstate__(self):
        raise TypeError("KeyShare holds secret key material and cannot be pickled or copied")

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
        try:
            pub = PublicKey.from_json(d["public"])
            index, y = int(d["index"]), int(d["y"], 16)
        except ShareError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ShareError(f"malformed share file ({type(exc).__name__})") from None
        if not (1 <= index <= pub.n and 0 < y < pub.g.order):
            raise ShareError("share index or value out of range")
        ks = KeyShare(index, y, pub)
        if not ks.verify():
            raise ShareError("share does not match its public commitments")
        return ks

    # — at rest: sealed under a passphrase (scrypt), file mode 0600 —
    # The passphrase key is derived under a per-file-type label and the header
    # line is authenticated as AAD, so a share file, an identity file and a vault
    # can never be confused for one another.
    _MAGIC = b"TORUSSHARE2"
    _LABEL = b"torussql/custody/file/share/v2"

    def save(self, path: str, passphrase: str | None) -> None:
        body = json.dumps(self.to_json()).encode()
        if passphrase is None:
            blob = self._MAGIC + b" plain\n" + body
        else:
            salt = os.urandom(16)
            head = self._MAGIC + b" sealed " + salt.hex().encode()
            blob = head + b"\n" + _seal.seal(
                _seal.passphrase_key(passphrase, salt, self._LABEL), body, aad=head)
        _atomic(path, blob, 0o600)

    @staticmethod
    def load(path: str, passphrase: str | None) -> "KeyShare":
        raw = Path(path).read_bytes()
        head, _, rest = raw.partition(b"\n")
        parts = head.split()
        if parts and parts[0] == b"TORUSSHARE1":
            raise ShareError(f"{path}: old share-file format (v1); re-create it with this version")
        if len(parts) < 2 or parts[0] != KeyShare._MAGIC:
            raise ShareError(f"{path}: not a custodian share file")
        try:
            if parts[1] == b"plain":
                body = rest
            elif parts[1] == b"sealed" and len(parts) == 3:
                if passphrase is None:
                    raise ShareError("share file is sealed — passphrase required")
                try:
                    key = _seal.passphrase_key(passphrase, bytes.fromhex(parts[2].decode()),
                                               KeyShare._LABEL)
                    body = _seal.unseal(key, rest, aad=head)
                except ValueError:
                    raise ShareError("wrong passphrase or corrupted share file") from None
            else:
                raise ShareError(f"{path}: bad share-file header")
            return KeyShare.from_json(json.loads(body))
        except ShareError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError, UnicodeError) as exc:
            raise ShareError(f"{path}: malformed share file ({type(exc).__name__})") from None


def _atomic(path: str, data: bytes, mode: int) -> None:
    """Write ``path`` atomically: a fresh O_EXCL|O_NOFOLLOW temp file created with
    ``mode`` from the start (a planted ``.tmp``/symlink is never reused), fsync,
    rename, then fsync the directory."""
    path = str(path)
    tmp = path + ".tmp"
    fd = _create_exclusive(tmp, mode)
    try:
        try:
            os.fchmod(fd, mode)                       # exact mode regardless of umask
        except (AttributeError, OSError):             # pragma: no cover
            pass
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(path)

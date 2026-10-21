# SPDX-License-Identifier: Apache-2.0
"""Durable mask vault for the data owner (client side only).

The mask vault is the owner's one long-lived secret: every blinded cell on the
server is unrecoverable without its mask, so losing this file loses the data
and leaking it breaks confidentiality. The server never sees it.

Storage is an append-only, checksummed log so that

  * a statement costs O(1) to persist (no whole-vault rewrite per INSERT);
  * a crash can tear at most the last record, which load discards;
  * the file is created ``0600``;
  * optionally every record is sealed under a key derived from a passphrase
    (scrypt -> HMAC-SHA256 encrypt-then-MAC, stdlib only; the same ``seal``
    construction as the LSS key-custody module).

For quorum recovery and offsite escrow use the LSS custody export in
``ecfhe_query.keymgmt`` — this log is the *working copy*.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import zlib
from contextlib import contextmanager
from typing import Any

_MAGIC = b"TORUSVAULT1\n"
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


_MISSING = object()


class VaultError(Exception):
    pass


class VaultLocked(VaultError):
    """The vault is sealed and no/incorrect passphrase was supplied."""


def _kdf(passphrase: str, salt: bytes) -> int:
    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                         maxmem=64 * 1024 * 1024, **_SCRYPT)
    return int.from_bytes(key, "big")


class _LoggedDict(dict):
    """A dict that reports every mutation to its vault."""

    def __init__(self, vault: "VaultLog", kind: str, *args):
        super().__init__(*args)
        self._vault = vault
        self._kind = kind

    def __setitem__(self, key, value):
        old = self.get(key, _MISSING)
        super().__setitem__(key, value)
        self._vault._on_set(self._kind, key, value, old)

    def __delitem__(self, key):
        old = self[key]
        super().__delitem__(key)
        self._vault._on_del(self._kind, key, old)


class VaultLog:
    """Append-only mask-vault log bound to one NoKeyClient."""

    def __init__(self, path: str | None = None, passphrase: str | None = None,
                 custody=None):
        # path=None -> in-memory vault: no file, but still tracks transaction
        # undo so a client-side ROLLBACK can restore the mask state.
        self.path = path
        if passphrase and custody is not None:
            raise VaultError("use either a passphrase or threshold custody, not both")
        self._pass = passphrase
        self._custody = custody          # torussql.custody.ThresholdCustody | None
        self._thr: dict | None = None    # threshold envelope header of this vault
        self._head_override: bytes | None = None   # set by reseal() for one rebase
        self._k: int | None = None
        self._f = None
        self._dirty = False
        self._seq = 0                    # next record number (gap/reorder check)
        self._tx_undo: list | None = None
        self.records = 0

    # ── record codec ─────────────────────────────────────────────────────────
    def _encode(self, rec: dict) -> bytes:
        body = json.dumps(rec, separators=(",", ":")).encode()
        if self._k is not None:
            from .seal import seal
            return b"S " + seal(self._k, body).hex().encode() + b"\n"
        return b"P %08x " % zlib.crc32(body) + body + b"\n"

    def _decode(self, line: bytes) -> dict:
        line = line.rstrip(b"\n")
        if line.startswith(b"S "):
            if self._k is None:
                raise VaultLocked("vault is sealed — supply a passphrase")
            from .seal import unseal
            try:
                body = unseal(self._k, bytes.fromhex(line[2:].decode()))
            except Exception as exc:                  # noqa: BLE001
                raise ValueError("bad sealed record") from exc
            return json.loads(body)
        if line.startswith(b"P "):
            crc, _, body = line[2:].partition(b" ")
            if int(crc, 16) != zlib.crc32(body):
                raise ValueError("bad crc")
            return json.loads(body)
        raise ValueError("bad record")

    # ── open / load ──────────────────────────────────────────────────────────
    def open_into(self, client) -> bool:
        """Attach to ``client``: replay an existing vault into it (returns
        True) or start a new one. Afterwards every mutation is logged."""
        if self.path is None:
            self._wrap(client)
            return False
        existing = os.path.exists(self.path) and os.path.getsize(self.path) > 0
        if existing:
            with open(self.path, "rb") as f:
                head = f.readline()
                if not head.startswith(_MAGIC.rstrip(b"\n")):
                    raise VaultError(f"{self.path}: not a TorusDB vault")
                toks = head.strip().split(b" ")[1:]
                if toks and toks[0] == b"thr":                 # threshold-sealed
                    if self._custody is None:
                        raise VaultLocked("vault is sealed under a threshold key — "
                                          "supply vault_custody")
                    self._thr = json.loads(base64.urlsafe_b64decode(toks[1]))
                    try:
                        self._k = self._custody.unwrap(self._thr)
                    except VaultError:
                        raise
                    except Exception as exc:                 # noqa: BLE001
                        raise VaultLocked(f"cannot open the vault: {exc}") from exc
                elif toks:
                    if not self._pass:
                        raise VaultLocked("vault is sealed — supply a passphrase")
                    self._k = _kdf(self._pass, bytes.fromhex(toks[0].decode()))
                elif self._pass or self._custody is not None:
                    raise VaultError("vault is not sealed but a passphrase/"
                                     "custody was given")
                good = f.tell()
                state = _State()
                n = 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    try:
                        state.apply(self._decode(line))
                    except VaultLocked:
                        raise
                    except ValueError:
                        if n == 0:                      # never truncate on this
                            raise (VaultLocked("wrong passphrase or corrupt vault")
                                   if self._k is not None
                                   else VaultError(f"{self.path}: corrupt vault"))
                        if f.read(1):
                            raise VaultError(
                                f"{self.path}: corrupt record before end of "
                                f"file — refusing to truncate")
                        break                          # torn final record
                    n += 1
                    good = f.tell()
            if good < os.path.getsize(self.path):          # drop torn tail
                with open(self.path, "r+b") as f:
                    f.truncate(good)
            state.install(client)
            self._seq = state.seq
            self._f = open(self.path, "ab")
        else:
            self._init_file()
            self._write(self._hdr(client))
            self.sync()
        self._wrap(client)
        return existing

    def _init_file(self) -> None:
        salt = os.urandom(16)
        head = _MAGIC.rstrip(b"\n")
        if self._custody is not None:
            self._k, self._thr = self._custody.wrap(b"vault\x00" + salt)
            head += self._thr_head(self._thr)
        elif self._pass:
            self._k = _kdf(self._pass, salt)
            head += b" " + salt.hex().encode()
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(head + b"\n")
            f.flush()
            os.fsync(f.fileno())
        self._f = open(self.path, "ab")

    @staticmethod
    def _thr_head(hdr: dict) -> bytes:
        return b" thr " + base64.urlsafe_b64encode(json.dumps(hdr).encode())

    @staticmethod
    def _hdr(client) -> dict:
        return {"k": "hdr", "auth": bool(client.authenticated),
                "alpha": str(client._alpha)}

    def _wrap(self, client) -> None:
        client._masks = _LoggedDict(self, "m", client._masks)
        client._coltype = _LoggedDict(self, "ct", client._coltype)
        client._colpolicy = _LoggedDict(self, "cp", client._colpolicy)

    # ── logging ──────────────────────────────────────────────────────────────
    def _write(self, rec: dict) -> None:
        rec["q"] = self._seq
        self._seq += 1
        self._f.write(self._encode(rec))
        self._dirty = True
        self.records += 1

    def _on_set(self, kind: str, key, value, old) -> None:
        if self._tx_undo is not None:
            self._tx_undo.append((kind, key, old))
        if self._f is None:
            return
        if kind == "m":
            t, i, c = key
            self._write({"k": "m", "t": t, "i": i, "c": c, "r": str(value)})
        else:
            t, c = key
            self._write({"k": kind, "t": t, "c": c, "v": value})

    def _on_del(self, kind: str, key, old) -> None:
        if self._tx_undo is not None:
            self._tx_undo.append((kind, key, old))
        if self._f is None:
            return
        if kind == "m":
            t, i, c = key
            self._write({"k": "md", "t": t, "i": i, "c": c})
        else:
            t, c = key
            self._write({"k": kind + "d", "t": t, "c": c})

    # ── client-side transactions: undo log over the three dicts ─────────────
    def tx_begin(self, client) -> None:
        self._tx_undo = []
        self._tx_schema = {t: list(cols) for t, cols in client._schema.items()}

    def tx_commit(self) -> None:
        self._tx_undo = None
        self.sync()

    def tx_rollback(self, client) -> None:
        undo, self._tx_undo = self._tx_undo or [], None
        dicts = {"m": client._masks, "ct": client._coltype, "cp": client._colpolicy}
        for kind, key, old in reversed(undo):
            d = dicts[kind]
            if old is _MISSING:
                dict.pop(d, key, None)
            else:
                dict.__setitem__(d, key, old)
        client._schema = self._tx_schema
        if self._f is not None:
            self.rebase(client)           # log has records of undone writes

    def sync(self) -> None:
        """Make everything logged so far durable (fsync)."""
        if self._f and self._dirty and self._tx_undo is None:
            self._f.flush()
            os.fsync(self._f.fileno())
            self._dirty = False

    # ── compaction / rebase (after a client-side rollback) ───────────────────
    def rebase(self, client) -> None:
        """Rewrite the log to exactly ``client``'s current state, atomically,
        and re-attach logging. Used after rollback and for compaction."""
        masks = dict(client._masks)
        ct, cp = dict(client._coltype), dict(client._colpolicy)
        tmp = self.path + ".tmp"
        old_f, self._f = self._f, None
        old_k, old_thr = self._k, self._thr
        self._seq = 0
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            head = _MAGIC.rstrip(b"\n")
            if self._head_override is not None:
                head = self._head_override           # reseal(): new protection mode
            elif self._thr is not None:
                # rotate the sealing key: a fresh envelope needs only the
                # PUBLIC key, no quorum
                ctx = bytes.fromhex(self._thr["ctx"])
                self._k, self._thr = self._custody.wrap(ctx)
                head += self._thr_head(self._thr)
            elif self._k is not None:
                with open(self.path, "rb") as src:
                    head = src.readline().rstrip(b"\n")
            f.write(head + b"\n")
            self._f = f
            self._write(self._hdr(client))
            for (t, c), v in ct.items():
                self._write({"k": "ct", "t": t, "c": c, "v": v})
            for (t, c), v in cp.items():
                self._write({"k": "cp", "t": t, "c": c, "v": v})
            for (t, i, c), r in masks.items():
                self._write({"k": "m", "t": t, "i": i, "c": c, "r": str(r)})
            f.flush()
            os.fsync(f.fileno())
        if old_f:
            old_f.close()
        os.replace(tmp, self.path)
        self._f = open(self.path, "ab")
        self._dirty = False
        client._masks = _LoggedDict(self, "m", masks)
        client._coltype = _LoggedDict(self, "ct", ct)
        client._colpolicy = _LoggedDict(self, "cp", cp)

    def reseal(self, client, *, custody=None, passphrase: str | None = None) -> None:
        """Re-protect the whole vault under a different key or mode — e.g.
        passphrase → threshold custody, or onto a brand-new threshold key after
        a custodian compromise. Atomic: the old file stays valid until the new
        one is fully written; on failure nothing changes."""
        if custody is not None and passphrase:
            raise VaultError("use either a passphrase or threshold custody, not both")
        if self.path is None:
            raise VaultError("an in-memory vault has nothing to reseal")
        saved = (self._k, self._thr, self._custody, self._pass, self._head_override)
        try:
            self._custody, self._pass = custody, passphrase
            if custody is not None:
                self._thr = {"ctx": (b"vault\x00" + os.urandom(16)).hex()}   # rebase() wraps
                self._head_override = None
            elif passphrase:
                salt = os.urandom(16)
                self._thr, self._k = None, _kdf(passphrase, salt)
                self._head_override = _MAGIC.rstrip(b"\n") + b" " + salt.hex().encode()
            else:
                self._thr, self._k = None, None
                self._head_override = _MAGIC.rstrip(b"\n")
            self.rebase(client)
        except BaseException:
            self._k, self._thr, self._custody, self._pass, self._head_override = saved
            raise
        finally:
            self._head_override = None

    def close(self) -> None:
        if self._f:
            try:
                self.sync()
            finally:
                self._f.close()
                self._f = None


class _State:
    """Accumulates replayed records, then installs them into a client."""

    def __init__(self) -> None:
        self.masks: dict = {}
        self.ct: dict = {}
        self.cp: dict = {}
        self.auth = False
        self.alpha = 0
        self.seq = 0

    def apply(self, r: dict) -> None:
        q = r.get("q")
        if q is not None:
            if q != self.seq:
                raise VaultError(
                    f"vault record out of sequence (expected {self.seq}, got "
                    f"{q}) — records were deleted, duplicated or reordered")
            self.seq += 1
        k = r["k"]
        if k == "hdr":
            self.auth, self.alpha = bool(r["auth"]), int(r["alpha"])
        elif k == "m":
            self.masks[(r["t"], r["i"], r["c"])] = int(r["r"])
        elif k == "md":
            self.masks.pop((r["t"], r["i"], r["c"]), None)
        elif k == "ct":
            self.ct[(r["t"], r["c"])] = r["v"]
        elif k == "cp":
            self.cp[(r["t"], r["c"])] = r["v"]
        elif k == "ctd":
            self.ct.pop((r["t"], r["c"]), None)
        elif k == "cpd":
            self.cp.pop((r["t"], r["c"]), None)

    def install(self, client) -> None:
        client._masks = dict(self.masks)
        client._coltype = dict(self.ct)
        client._colpolicy = dict(self.cp)
        client.authenticated = self.auth
        client._alpha = self.alpha
        client._schema = {}
        for (t, c), typ in self.ct.items():
            client._schema.setdefault(t, []).append((c, typ, self.cp[(t, c)]))

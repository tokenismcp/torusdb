# SPDX-License-Identifier: Apache-2.0
"""Durable mask vault for the data owner (client side only).

The mask vault is the owner's one long-lived secret: every blinded cell on the
server is unrecoverable without its mask, so losing this file loses the data
and leaking it breaks confidentiality. The server never sees it.

Storage is a :class:`~torussql.recordlog.RecordLog` — append-only, checksummed,
``0600``, optionally sealed under a passphrase or a *threshold* key — so that

* a statement costs O(1) to persist (no whole-vault rewrite per INSERT);
* a torn final record is dropped, but corruption anywhere else (or a record
  that fails its MAC) makes loading **refuse** instead of truncating;
* a sealed vault rejects unsealed records, and every record is bound to the
  header (salt / key envelope) and its position, so records cannot be spliced
  between files or generations;
* a **transaction** is bracketed by ``txb`` / ``txc`` / ``txa`` markers. Masks
  written inside it are provisional until ``txc``; ``txa`` (or a crash with no
  marker followed by "server says aborted") discards them. Rollback is therefore
  O(1), and a lost COMMIT reply is *resolved* by asking the server what
  happened rather than guessed.

For quorum recovery and offsite escrow use the LSS custody export in
``ecfhe_query.keymgmt`` or seal the vault under a threshold key
(``torussql.custody``); the masks themselves can be secret-shared with
``torussql.custody.masks`` so that no local vault is needed at all.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any

from .errors import CustodyError
from .recordlog import LogCorrupt, LogLocked, RecordLog

try:
    import fcntl
except ImportError:                                           # pragma: no cover
    fcntl = None                                              # type: ignore[assignment]

_MAGIC = b"TORUSVAULT2"
_MISSING = object()


class VaultError(CustodyError):
    pass


class VaultLocked(VaultError):
    """The vault is sealed and no/incorrect passphrase or quorum was supplied."""


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
    """Mask-vault log bound to one NoKeyClient."""

    def __init__(self, path: str | None = None, passphrase: str | None = None,
                 custody=None):
        # path=None -> in-memory vault: no file, but it still tracks transaction
        # undo so a client-side ROLLBACK can restore the mask state.
        self.path = path
        if passphrase is not None and not passphrase:
            raise VaultError("an empty passphrase is not accepted")
        if passphrase and custody is not None:
            raise VaultError("use either a passphrase or threshold custody, not both")
        self._pass = passphrase
        self._custody = custody          # torussql.custody.ThresholdCustody | None
        self._thr: dict | None = None    # threshold envelope header of this vault
        self._log: RecordLog | None = None
        self._lockfd: int | None = None
        self._tx_undo: list | None = None
        self._tx_schema: dict | None = None
        self._txid: str | None = None
        self._client = None
        self._dirty = False
        self.in_doubt: dict[str, list] = {}      # txid -> provisional records

    # ── open / load ──────────────────────────────────────────────────────────
    def open_into(self, client) -> bool:
        """Attach to ``client``: replay an existing vault into it (returns True)
        or start a new one. Afterwards every mutation is logged."""
        self._client = client
        if self.path is None:
            self._wrap(client)
            return False
        self._acquire_lock()
        try:
            existing = self._open_log()
        except BaseException:
            self._release_lock()
            raise
        if existing:
            state = _State()
            try:
                for rec in self._records:
                    state.apply(rec)
            except VaultError:
                self._abort_open()
                raise
            state.install(client)
            self.in_doubt = ({state.pending["id"]: state.pending["recs"]}
                             if state.pending else {})
        else:
            self._log_write(self._hdr(client))
            self.sync()
        self._wrap(client)
        return existing

    def _abort_open(self) -> None:
        if self._log:
            self._log.close()
        self._release_lock()

    def _open_log(self) -> bool:
        toks = RecordLog.peek_header(self.path, _MAGIC)
        try:
            if toks is None:                                  # new vault
                if self._custody is not None:
                    ctx = b"vault\x00" + os.urandom(16)
                    key, self._thr = self._custody.wrap(ctx)
                    self._log = RecordLog(self.path, _MAGIC, fsync="never", key=key,
                                          extra=self._thr_extra(self._thr))
                else:
                    self._log = RecordLog(self.path, _MAGIC, self._pass, fsync="never",
                                          label=b"vault")
                self._records = list(self._log.open())
                return False
            if toks and toks[0] == b"thr":                    # threshold-sealed
                if self._custody is None:
                    raise VaultLocked("vault is sealed under a threshold key — "
                                      "supply vault_custody")
                self._thr = json.loads(base64.urlsafe_b64decode(toks[1]))
                try:
                    key = self._custody.unwrap(self._thr)
                except Exception as exc:                      # noqa: BLE001
                    raise VaultLocked(f"cannot open the vault: {exc}") from exc
                self._log = RecordLog(self.path, _MAGIC, fsync="never", key=key,
                                      extra=b" ".join(toks))
            elif toks:                                        # passphrase-sealed
                if not self._pass:
                    raise VaultLocked("vault is sealed — supply a passphrase")
                if self._custody is not None:
                    raise VaultLocked("vault is sealed with a passphrase, not a threshold key")
                self._log = RecordLog(self.path, _MAGIC, self._pass, fsync="never",
                                      label=b"vault")
            else:                                             # unsealed
                if self._pass or self._custody is not None:
                    raise VaultError("vault is not sealed but a passphrase/custody was given")
                self._log = RecordLog(self.path, _MAGIC, fsync="never", label=b"vault")
            self._records = list(self._log.open())
            return True
        except LogLocked as exc:
            raise VaultLocked(str(exc)) from None
        except LogCorrupt as exc:
            raise VaultError(str(exc)) from None

    @staticmethod
    def _thr_extra(hdr: dict) -> bytes:
        return b"thr " + base64.urlsafe_b64encode(json.dumps(hdr).encode())

    def _acquire_lock(self) -> None:
        if fcntl is None:                                     # pragma: no cover
            return
        fd = os.open(self.path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise VaultError(f"{self.path} is in use by another process "
                             f"(one writer per vault)") from None
        self._lockfd = fd

    def _release_lock(self) -> None:
        if self._lockfd is not None:
            os.close(self._lockfd)
            self._lockfd = None

    @staticmethod
    def _hdr(client) -> dict:
        return {"k": "hdr", "auth": bool(client.authenticated), "alpha": str(client._alpha)}

    def _wrap(self, client) -> None:
        client._masks = _LoggedDict(self, "m", client._masks)
        client._coltype = _LoggedDict(self, "ct", client._coltype)
        client._colpolicy = _LoggedDict(self, "cp", client._colpolicy)

    # ── logging ──────────────────────────────────────────────────────────────
    def _log_write(self, rec: dict) -> None:
        if self._log is None:
            raise VaultError("vault log is closed or unusable — refusing to continue "
                             "without persisting masks")
        self._log.append(rec)
        self._dirty = True

    def _on_set(self, kind: str, key, value, old) -> None:
        if self._tx_undo is not None:
            self._tx_undo.append((kind, key, old))
        if self.path is None:
            return
        if kind == "m":
            t, i, c = key
            self._log_write({"k": "m", "t": t, "i": i, "c": c, "r": str(value)})
        else:
            t, c = key
            self._log_write({"k": kind, "t": t, "c": c, "v": value})

    def _on_del(self, kind: str, key, old) -> None:
        if self._tx_undo is not None:
            self._tx_undo.append((kind, key, old))
        if self.path is None:
            return
        if kind == "m":
            t, i, c = key
            self._log_write({"k": "md", "t": t, "i": i, "c": c})
        else:
            t, c = key
            self._log_write({"k": kind + "d", "t": t, "c": c})

    def sync(self) -> None:
        """Make everything logged so far durable (fsync)."""
        if self._log is not None and self._dirty and self._tx_undo is None:
            self._log.sync()
            self._dirty = False

    # ── client-side transactions ─────────────────────────────────────────────
    def tx_begin(self, client, txid: str) -> None:
        if self.path is not None:
            self._log_write({"k": "txb", "id": txid})
            self._log.sync()
        self._txid = txid
        self._tx_undo = []
        self._tx_schema = {t: list(cols) for t, cols in client._schema.items()}

    def tx_commit(self) -> None:
        txid, self._tx_undo, self._txid = self._txid, None, None
        if self.path is not None and txid:
            self._log_write({"k": "txc", "id": txid})
            self._log.sync()
            self._dirty = False

    def tx_rollback(self, client) -> None:
        """Definitive abort: restore the in-memory state and discard the
        provisional records (an O(1) marker — no rewrite)."""
        undo, self._tx_undo = self._tx_undo or [], None
        txid, self._txid = self._txid, None
        dicts = {"m": client._masks, "ct": client._coltype, "cp": client._colpolicy}
        for kind, key, old in reversed(undo):
            d = dicts[kind]
            if old is _MISSING:
                dict.pop(d, key, None)
            else:
                dict.__setitem__(d, key, old)
        if self._tx_schema is not None:
            client._schema = self._tx_schema
        self._tx_schema = None
        if self.path is not None and txid:
            self._log_write({"k": "txa", "id": txid})
            self._log.sync()
            self._dirty = False

    def tx_in_doubt(self) -> None:
        """The outcome of COMMIT is unknown. Keep the log's open ``txb`` (the
        next session resolves it against the server) and stop tracking."""
        self._tx_undo = None
        self._txid = None

    def resolve_in_doubt(self, client, txid: str, committed: bool) -> None:
        """Settle a transaction left open by a crash / lost commit reply, using
        the server's answer."""
        recs = self.in_doubt.pop(txid, None)
        if recs is None:
            return
        if committed:                                         # adopt the new masks
            st = _State()
            st.masks, st.ct, st.cp = (dict.copy(client._masks), dict.copy(client._coltype),
                                      dict.copy(client._colpolicy))
            for r in recs:
                st.apply_one(r)
            for src, dst in ((st.masks, client._masks), (st.ct, client._coltype),
                             (st.cp, client._colpolicy)):
                for k, v in src.items():
                    dict.__setitem__(dst, k, v)
                for k in [k for k in dst if k not in src]:
                    dict.pop(dst, k, None)
            client._schema = {}
            for (t, c), typ in client._coltype.items():
                client._schema.setdefault(t, []).append((c, typ, client._colpolicy[(t, c)]))
        if self.path is not None:
            self._log_write({"k": "txc" if committed else "txa", "id": txid})
            self._log.sync()

    # ── rewrite: compaction, key rotation, re-sealing ────────────────────────
    def _records_of(self, client):
        yield self._hdr(client)
        for (t, c), v in client._coltype.items():
            yield {"k": "ct", "t": t, "c": c, "v": v}
        for (t, c), v in client._colpolicy.items():
            yield {"k": "cp", "t": t, "c": c, "v": v}
        for (t, i, c), r in client._masks.items():
            yield {"k": "m", "t": t, "i": i, "c": c, "r": str(r)}

    def _check_idle(self) -> None:
        if self._tx_undo is not None or self.in_doubt:
            raise VaultError("finish (or resolve) the open transaction first")

    def rebase(self, client) -> None:
        """Rewrite the log to exactly ``client``'s current state, atomically
        (compaction / key rotation). A passphrase vault gets a fresh salt; a
        threshold vault a fresh envelope — needing only the PUBLIC key."""
        if self.path is None:
            return
        self._check_idle()
        masks, ct, cp = dict(client._masks), dict(client._coltype), dict(client._colpolicy)
        if self._thr is not None:
            ctx = bytes.fromhex(self._thr["ctx"])
            key, thr = self._custody.wrap(ctx)
            self._log.rewrite(self._records_of(client), key=key, extra=self._thr_extra(thr))
            self._thr = thr
        else:
            self._log.rewrite(self._records_of(client))
        self._dirty = False
        client._masks = _LoggedDict(self, "m", masks)
        client._coltype = _LoggedDict(self, "ct", ct)
        client._colpolicy = _LoggedDict(self, "cp", cp)

    def reseal(self, client, *, custody=None, passphrase: str | None = None) -> None:
        """Re-protect the whole vault under a different key or mode — e.g.
        passphrase → threshold custody, or onto a brand-new threshold key after a
        custodian compromise. Atomic: the old file stays valid until the new one
        is fully written; on failure nothing (file or memory) changes."""
        if custody is not None and passphrase:
            raise VaultError("use either a passphrase or threshold custody, not both")
        if passphrase is not None and not passphrase:
            raise VaultError("an empty passphrase is not accepted")
        if self.path is None:
            raise VaultError("an in-memory vault has nothing to reseal")
        self._check_idle()
        masks, ct, cp = dict(client._masks), dict(client._coltype), dict(client._colpolicy)
        thr = None
        if custody is not None:
            key, thr = custody.wrap(b"vault\x00" + os.urandom(16))
            self._log.rewrite(self._records_of(client), key=key, extra=self._thr_extra(thr))
        elif passphrase:
            salt = os.urandom(16)
            from . import seal
            key = seal.passphrase_key(passphrase, salt, b"vault")
            self._log.rewrite(self._records_of(client), key=key, extra=salt.hex().encode())
        else:
            self._log.rewrite(self._records_of(client), key=None, extra=None)
        self._custody, self._pass, self._thr = custody, passphrase, thr
        self._log._pass, self._log._label = passphrase, b"vault"
        self._dirty = False
        client._masks = _LoggedDict(self, "m", masks)
        client._coltype = _LoggedDict(self, "ct", ct)
        client._colpolicy = _LoggedDict(self, "cp", cp)

    def maybe_compact(self, client) -> bool:
        """Compact when the log is mostly superseded records."""
        if self.path is None or self._log is None or self._tx_undo is not None or self.in_doubt:
            return False
        live = len(client._masks) + len(client._coltype) + len(client._colpolicy) + 1
        if self._log.records > max(20000, 4 * live):
            self.rebase(client)
            return True
        return False

    def close(self) -> None:
        if self._log is not None:
            try:
                if self._client is not None and self._tx_undo is None:
                    try:
                        self.maybe_compact(self._client)
                    except Exception:                         # noqa: BLE001
                        pass                                  # compaction is optional
                self._log.close()
            finally:
                self._log = None
        self._release_lock()


class _State:
    """Accumulates replayed records, then installs them into a client."""

    def __init__(self) -> None:
        self.masks: dict = {}
        self.ct: dict = {}
        self.cp: dict = {}
        self.auth = False
        self.alpha = 0
        self.pending: dict | None = None

    def apply(self, r: dict) -> None:
        k = r["k"]
        if k == "txb":
            if self.pending is not None:
                raise VaultError("vault log is damaged: a transaction starts inside another")
            self.pending = {"id": r["id"], "recs": []}
        elif k in ("txc", "txa"):
            if self.pending is None or self.pending["id"] != r["id"]:
                raise VaultError("vault log is damaged: transaction end without a start")
            recs, self.pending = self.pending["recs"], None
            if k == "txc":
                for x in recs:
                    self.apply_one(x)
        elif self.pending is not None:
            self.pending["recs"].append(r)
        else:
            self.apply_one(r)

    def apply_one(self, r: dict) -> None:
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
        else:
            raise VaultError(f"vault log is damaged: unknown record {k!r}")

    def install(self, client) -> None:
        client._masks = dict(self.masks)
        client._coltype = dict(self.ct)
        client._colpolicy = dict(self.cp)
        client.authenticated = self.auth
        client._alpha = self.alpha
        client._schema = {}
        for (t, c), typ in self.ct.items():
            client._schema.setdefault(t, []).append((c, typ, self.cp[(t, c)]))

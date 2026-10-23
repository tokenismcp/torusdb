# SPDX-License-Identifier: Apache-2.0
"""Asynchronous WAL-shipping replication for ``torusdb-server``.

A **primary** keeps its recent commits (the same records it writes to its journal)
in an in-memory :class:`WalRing`. A **replica** (``--replica-of HOST:PORT``)
long-polls ``repl_fetch(position)``, applies each commit through the normal
mutation path, journals it locally and serves read-only queries. ``promote``
turns a replica into a writable primary.

Positions are ``(generation, seq)`` pairs of the *primary's* journal: ``seq`` counts
the commits of one checkpoint generation. A replica that falls behind the ring (or
whose primary was promoted away) re-bootstraps from a consistent snapshot file
streamed with ``repl_snapshot_*``.

Guarantees and limits (also in docs/replication.md):

* asynchronous: a primary crash can lose commits the replica never received;
* a replica only ever sees commits that are durable in the primary's journal;
* no automatic fail-over — an operator promotes (and fences the old primary);
* ``cluster_id`` + ``timeline`` stop a replica from following a node of another
  database or an older timeline.

Like everything in the server this carries only blinded scalars and plaintext
columns — never keys or masks.
"""
from __future__ import annotations

import base64
import bisect
import logging
import os
import threading
import time
import uuid

log = logging.getLogger("torusdb.repl")

SNAP_CHUNK = 512 * 1024
MAX_FETCH_BYTES = 8 * 1024 * 1024


class TooFarBehind(Exception):
    """The requested position is no longer available — re-bootstrap."""


class WalRing:
    """Recent commits of the primary, addressable by ``(gen, seq)``."""

    def __init__(self, capacity: int = 200_000):
        self.capacity = max(100, capacity)
        self._keys: list[tuple[int, int]] = []
        self._recs: list[tuple[dict, int]] = []          # (record, approx bytes)
        self.gen_len: dict[int, int] = {}                # finished generations -> record count
        self.end: tuple[int, int] = (0, 0)               # next position to be written
        self.cv = threading.Condition()

    def reset(self, gen: int, seq: int, gen_len: dict | None = None) -> None:
        with self.cv:
            self._keys.clear(); self._recs.clear()
            self.end = (gen, seq)
            if gen_len:
                self.gen_len.update({int(k): int(v) for k, v in gen_len.items()})

    def append(self, gen: int, seq: int, rec: dict, size: int) -> None:
        with self.cv:
            self._keys.append((gen, seq))
            self._recs.append((rec, size))
            self.end = (gen, seq + 1)
            if len(self._keys) > self.capacity:
                cut = self.capacity // 10 or 1
                del self._keys[:cut]
                del self._recs[:cut]
            self.cv.notify_all()

    def new_generation(self, old_gen: int, count: int, new_gen: int) -> None:
        with self.cv:
            self.gen_len[old_gen] = count
            for g in sorted(self.gen_len)[:-16]:
                self.gen_len.pop(g, None)
            self.end = (new_gen, 0)
            self.cv.notify_all()

    def known_gen_len(self) -> dict:
        with self.cv:
            return dict(self.gen_len)

    def _normalise(self, pos: tuple[int, int]) -> tuple[int, int]:
        g, s = pos
        while g < self.end[0] and self.gen_len.get(g) == s:
            g, s = g + 1, 0
        return g, s

    def fetch(self, pos: tuple[int, int], max_records: int, wait: float):
        """-> (records, next_position). Blocks up to ``wait`` seconds when the
        replica is caught up. Raises :class:`TooFarBehind`."""
        deadline = time.monotonic() + wait
        with self.cv:
            while True:
                pos = self._normalise(pos)
                if pos > self.end:
                    raise TooFarBehind("replica is ahead of this primary (diverged)")
                if pos == self.end:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return [], pos
                    self.cv.wait(remaining)
                    continue
                i = bisect.bisect_left(self._keys, pos)
                if i >= len(self._keys) or self._keys[i] != pos:
                    raise TooFarBehind(f"position {pos} is no longer in the WAL ring")
                out, size, j = [], 0, i
                while j < len(self._keys) and len(out) < max_records:
                    rec, nb = self._recs[j]
                    if out and size + nb > MAX_FETCH_BYTES:
                        break
                    out.append({"g": self._keys[j][0], "q": self._keys[j][1], **rec})
                    size += nb
                    j += 1
                nxt = (self._keys[j - 1][0], self._keys[j - 1][1] + 1)
                return out, self._normalise(nxt) if nxt != self.end else nxt


class SnapshotStore:
    """Consistent snapshot files offered to bootstrapping replicas."""

    def __init__(self, dirpath: str):
        self.dir = dirpath
        self._open: dict[str, str] = {}

    def create(self) -> tuple[str, str]:
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        sid = uuid.uuid4().hex
        path = os.path.join(self.dir, sid + ".snap")
        self._open[sid] = path
        return sid, path

    def read(self, sid: str, offset: int, length: int) -> dict:
        path = self._open.get(sid)
        if path is None:
            raise KeyError("unknown snapshot id")
        length = max(1, min(int(length), SNAP_CHUNK))
        size = os.path.getsize(path)
        if offset < 0 or offset > size:
            raise ValueError("offset out of range")
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
        return {"data": base64.b64encode(data).decode(), "size": size,
                "eof": offset + len(data) >= size}

    def done(self, sid: str) -> None:
        path = self._open.pop(sid, None)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass

    def cleanup(self) -> None:
        for sid in list(self._open):
            self.done(sid)


def new_cluster_id() -> str:
    return uuid.uuid4().hex


# ── the replica side ─────────────────────────────────────────────────────────
class Follower(threading.Thread):
    """Pulls commits from the primary and applies them via ``engine``."""

    def __init__(self, engine, host: str, port: int, conn_kwargs: dict,
                 poll: float = 5.0, batch: int = 2000):
        super().__init__(daemon=True, name="torusdb-follower")
        self.engine, self.host, self.port = engine, host, port
        self.kw, self.poll, self.batch = conn_kwargs, poll, batch
        self.stop_event = threading.Event()
        self.last_error: str | None = None
        self.last_contact = 0.0
        self.applied = 0
        self.primary_end: tuple[int, int] | None = None
        self.fatal: str | None = None
        self.rid = uuid.uuid4().hex                        # stable id for this replica process

    def run(self) -> None:
        from torussql.nokey import _Conn, Error
        backoff = 1.0
        conn = None
        while not self.stop_event.is_set():
            try:
                if conn is None:
                    conn = _Conn(self.host, self.port, timeout=self.poll + 30, **self.kw)
                    backoff = 1.0
                eng = self.engine
                resp = conn.call("repl_fetch", [eng.cluster_id, eng.timeline,
                                                list(eng.repl_pos), self.batch,
                                                int(self.poll * 1000), self.rid])
                self.last_contact = time.time()
                self.primary_end = tuple(resp["end"])
                if resp["records"]:
                    eng.apply_replicated(resp["records"], tuple(resp["next"]))
                    self.applied += len(resp["records"])
                self.last_error = None
            except Error as exc:
                msg = str(exc)
                self.last_error = msg
                if "too far behind" in msg or "diverged" in msg or "timeline" in msg:
                    self.fatal = msg
                    log.critical("replication cannot continue: %s — re-bootstrap this "
                                 "replica (remove its data and restart)", msg)
                    return
                if conn is not None:
                    conn.close(); conn = None
                self.stop_event.wait(min(backoff, 30.0)); backoff *= 2
            except Exception as exc:                          # noqa: BLE001
                self.fatal = f"{type(exc).__name__}: {exc}"
                log.critical("replication stopped: %s", self.fatal)
                return
        if conn is not None:
            conn.close()

    def stop(self) -> None:
        self.stop_event.set()

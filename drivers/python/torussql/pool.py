# SPDX-License-Identifier: Apache-2.0
"""A small, thread-safe connection pool.

    pool = torussql.pool.ConnectionPool(8, host="db", token=tok,
                                        mask_cluster=lambda: make_cluster())
    with pool.connection() as conn:
        conn.execute("SELECT SUM(salary) FROM emp")

A **vault is a single owner's state**: its masks live in one process and one file,
so a vault-backed pool can only have ``size == 1``. For real pooling use the
stateless owner (``mask_cluster``): pass a *callable* that builds a fresh
``ThresholdMaskStore`` per connection (stores are not shared between connections).
"""
from __future__ import annotations

import queue
import threading
import time
from contextlib import contextmanager

from . import nokey
from .nokey import Error, InterfaceError, OperationalError


class PoolTimeout(OperationalError):
    pass


class ConnectionPool:
    def __init__(self, size: int, *, acquire_timeout: float = 30.0,
                 max_age: float | None = 3600.0, **connect_kwargs):
        if size < 1:
            raise ValueError("pool size must be at least 1")
        has_vault = any(connect_kwargs.get(k) for k in
                        ("vault_path", "vault_custody", "vault_passphrase"))
        if size > 1 and has_vault:
            raise InterfaceError(
                "a mask vault has a single owner — a pool of more than one connection "
                "must use a stateless owner: pass mask_cluster=<callable returning a "
                "ThresholdMaskStore> instead of vault_*")
        if size > 1 and connect_kwargs.get("mask_cluster") is not None \
                and not callable(connect_kwargs["mask_cluster"]):
            raise InterfaceError("mask_cluster must be a callable that builds a store "
                                 "per connection when pooling")
        self._kw = connect_kwargs
        self._size, self._timeout, self._max_age = size, acquire_timeout, max_age
        self._idle: queue.LifoQueue = queue.LifoQueue()
        self._lock = threading.Lock()
        self._created = 0
        self._closed = False

    def _new(self):
        kw = dict(self._kw)
        mc = kw.get("mask_cluster")
        if callable(mc):
            kw["mask_cluster"] = mc()
        return nokey.connect(**kw), time.monotonic()

    def _acquire(self):
        deadline = time.monotonic() + self._timeout
        while True:
            if self._closed:
                raise InterfaceError("pool is closed")
            try:
                conn, born = self._idle.get_nowait()
            except queue.Empty:
                with self._lock:
                    if self._created < self._size:
                        self._created += 1
                        make = True
                    else:
                        make = False
                if make:
                    try:
                        return self._new()
                    except BaseException:
                        with self._lock:
                            self._created -= 1
                        raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PoolTimeout(f"no free connection within {self._timeout}s")
                try:
                    conn, born = self._idle.get(timeout=min(remaining, 0.5))
                except queue.Empty:
                    continue
            if self._healthy(conn, born):
                return conn, born
            self._discard(conn)

    def _healthy(self, conn, born) -> bool:
        if conn._closed or (self._max_age and time.monotonic() - born > self._max_age):
            return False
        try:
            conn._wire.call("ping", [])
            return True
        except Exception:                                    # noqa: BLE001
            return False

    def _discard(self, conn) -> None:
        try:
            conn.close()
        except Exception:                                    # noqa: BLE001
            pass
        with self._lock:
            self._created -= 1

    @contextmanager
    def connection(self):
        conn, born = self._acquire()
        ok = True
        try:
            yield conn
        except BaseException:
            ok = False
            raise
        finally:
            try:
                if conn.in_transaction:
                    conn.rollback()                          # never leak an open tx
                ok = ok or not conn._closed
            except Error:
                ok = False
            if self._closed or conn._closed or not ok and not self._reusable(conn):
                self._discard(conn)
            else:
                self._idle.put((conn, born))

    @staticmethod
    def _reusable(conn) -> bool:
        return not conn._closed

    def close(self) -> None:
        self._closed = True
        while True:
            try:
                conn, _ = self._idle.get_nowait()
            except queue.Empty:
                break
            self._discard(conn)

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

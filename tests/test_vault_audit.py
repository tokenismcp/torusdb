# SPDX-License-Identifier: Apache-2.0
"""Audit tests for the client-side mask vault log (sealing, tamper evidence)."""
from __future__ import annotations

import os

import pytest

from ecfhe_query.nokey_engine import NoKeyClient, NoKeyServer
from torussql.vault import VaultError, VaultLocked, VaultLog


def test_sealed_vault_detects_bit_flips_and_reordering(tmp_path):
    path = str(tmp_path / "v")
    cli = NoKeyClient(NoKeyServer())
    v = VaultLog(path, "pw-correct-horse")
    v.open_into(cli)
    cli.execute("CREATE TABLE t (id INT PLAIN, s INT ENC)")
    for i in range(5):
        cli.execute(f"INSERT INTO t (id, s) VALUES ({i}, {i})")
    v.close()
    raw = open(path, "rb").read()
    lines = raw.split(b"\n")
    # 1. flip one bit in a record -> authentication failure, never a silent skip
    flipped = bytearray(raw)
    pos = raw.index(b"\n", 100) + 40
    flipped[pos] ^= 0x01
    open(path, "wb").write(bytes(flipped))
    with pytest.raises((VaultError, VaultLocked)):
        VaultLog(path, "pw-correct-horse").open_into(NoKeyClient(NoKeyServer()))
    assert open(path, "rb").read() == bytes(flipped)          # not "repaired"
    # 2. swap two records -> sequence check refuses
    swapped = lines[:]
    swapped[3], swapped[4] = swapped[4], swapped[3]
    open(path, "wb").write(b"\n".join(swapped))
    with pytest.raises(VaultError, match="sequence|refusing"):
        VaultLog(path, "pw-correct-horse").open_into(NoKeyClient(NoKeyServer()))
    # 3. delete a record in the middle -> refused
    gone = lines[:3] + lines[4:]
    open(path, "wb").write(b"\n".join(gone))
    with pytest.raises(VaultError):
        VaultLog(path, "pw-correct-horse").open_into(NoKeyClient(NoKeyServer()))


def test_vault_file_is_not_world_readable(tmp_path):
    p = str(tmp_path / "v")
    VaultLog(p).open_into(NoKeyClient(NoKeyServer()))
    assert os.stat(p).st_mode & 0o077 == 0

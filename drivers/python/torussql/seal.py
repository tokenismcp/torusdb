# SPDX-License-Identifier: Apache-2.0
"""Authenticated encryption used for shares and vault records (stdlib only).

Same construction and byte layout as ``ecfhe_query.keymgmt.seal`` (HMAC-SHA256
keystream, encrypt-then-MAC, ``nonce(16) ‖ tag(32) ‖ ct``), re-implemented here
so key custody does not depend on the engine package. It is sound but not a
standard AEAD — see the review packet, finding F-10.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

KEYLEN = 32


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + struct.pack(">Q", counter),
                            hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _kdf(k_int: int, label: bytes) -> bytes:
    return hmac.new(k_int.to_bytes(KEYLEN, "big"), label, hashlib.sha256).digest()


def seal(k_int: int, plaintext: bytes) -> bytes:
    enc_key, mac_key = _kdf(k_int, b"enc"), _kdf(k_int, b"mac")
    nonce = secrets.token_bytes(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def unseal(k_int: int, sealed: bytes) -> bytes:
    if len(sealed) < 48:
        raise ValueError("sealed blob too short")
    nonce, tag, ct = sealed[:16], sealed[16:48], sealed[48:]
    expect = hmac.new(_kdf(k_int, b"mac"), nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expect):
        raise ValueError("MAC verification failed (wrong key or tampered)")
    return bytes(a ^ b for a, b in zip(ct, _keystream(_kdf(k_int, b"enc"), nonce, len(ct))))


def key_from_secret(*parts: bytes, label: bytes = b"torussql/custody/key/v1") -> int:
    """Derive a 256-bit sealing key (as an int) from secret/public parts."""
    h = hmac.new(label, b"", hashlib.sha256)
    for p in parts:
        h.update(struct.pack(">I", len(p)) + p)
    return int.from_bytes(h.digest(), "big")


def passphrase_key(passphrase: str, salt: bytes) -> int:
    return int.from_bytes(hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 15, r=8, p=1,
                                         maxmem=128 * 1024 * 1024, dklen=KEYLEN), "big")

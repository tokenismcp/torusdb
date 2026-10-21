# SPDX-License-Identifier: Apache-2.0
"""Binary message framing for the TorusDB wire.

A frame is a 4-byte big-endian unsigned length prefix followed by that many
bytes of payload. This replaces newline-delimited framing: it is binary-safe
(payloads may contain any byte, including newlines), gives explicit message
boundaries, and needs no escaping. The payload encoding (canonical JSON today,
length-prefixed protobuf later) is independent of this framing.
"""
from __future__ import annotations

import struct

_HDR = struct.Struct(">I")
MAX_FRAME = 64 * 1024 * 1024            # 64 MiB sanity cap


def write_frame(wf, payload: bytes, max_frame: int = MAX_FRAME) -> None:
    if len(payload) > max_frame:
        raise ValueError(f"frame too large: {len(payload)} bytes")
    # one write: header and payload leave in the same segment (no Nagle /
    # delayed-ACK stall, and a peer never observes a header-only chunk)
    wf.write(_HDR.pack(len(payload)) + payload)
    wf.flush()


def _read_exact(rf, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = rf.read(n - len(buf))
        if not chunk:
            return None                # clean EOF (only valid before any byte)
        buf.extend(chunk)
    return bytes(buf)


def read_frame(rf, max_frame: int = MAX_FRAME) -> bytes | None:
    """Read one frame; returns None at clean end-of-stream. A declared length
    above ``max_frame`` is rejected *before* any payload is read or buffered."""
    hdr = _read_exact(rf, 4)
    if hdr is None:
        return None
    (n,) = _HDR.unpack(hdr)
    if n > max_frame:
        raise ValueError(f"declared frame too large: {n} bytes")
    payload = _read_exact(rf, n)
    if payload is None:
        raise EOFError("truncated frame")
    return payload

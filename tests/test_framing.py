# SPDX-License-Identifier: Apache-2.0
"""Length-prefixed binary framing — round-trips, binary-safety, EOF, truncation."""
import io

import pytest

from framing import read_frame, write_frame


def _pipe(payloads):
    buf = io.BytesIO()
    for p in payloads:
        write_frame(buf, p)
    buf.seek(0)
    return buf


def test_roundtrip_multiple_frames():
    msgs = [b"", b"hello", b'{"m":"sum"}', bytes(range(256)), b"\n\n\x00\n"]
    r = _pipe(msgs)
    out = [read_frame(r) for _ in msgs]
    assert out == msgs
    assert read_frame(r) is None        # clean EOF


def test_newline_bytes_are_not_boundaries():
    # a payload full of newlines must come back intact (the whole point vs the
    # old newline-delimited framing)
    p = b"line1\nline2\nline3\n"
    assert read_frame(_pipe([p])) == p


def test_truncated_frame_raises():
    good = _pipe([b"abcdef"]).getvalue()
    r = io.BytesIO(good[:-2])            # drop two payload bytes
    with pytest.raises(EOFError):
        read_frame(r)


def test_oversized_declared_length_rejected():
    import struct
    r = io.BytesIO(struct.pack(">I", 10 ** 9))   # absurd length
    with pytest.raises(ValueError):
        read_frame(r)

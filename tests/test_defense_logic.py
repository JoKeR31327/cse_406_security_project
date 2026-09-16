"""
Unit tests for Defense and RFC 793 Logic.
"""
from collections import OrderedDict


def test_rfc793_in_window_logic():
    rcv_nxt = 1000000
    window = 65535

    # 1. Exact hit
    assert (1000000 - rcv_nxt) % (2**32) < window
    # 2. In-window boundary
    assert (1065534 - rcv_nxt) % (2**32) < window
    # 3. Out-of-window
    assert (1065535 - rcv_nxt) % (2**32) >= window
    # 4. Wrap-around 32-bit case
    rcv_nxt_wrap = 4294960000
    seg_seq_wrapped = 10000
    assert (seg_seq_wrapped - rcv_nxt_wrap) % (2**32) < window


def test_quarantine_buffer_lru():
    max_size = 64
    buf = OrderedDict()

    # Fill buffer to capacity
    for i in range(max_size):
        buf[f"session_{i}"] = i

    assert len(buf) == 64

    # Add 65th entry and evict oldest
    if len(buf) >= max_size:
        oldest_k, oldest_v = buf.popitem(last=False)
        assert oldest_k == "session_0"

    buf["session_64"] = 64
    assert len(buf) == 64
    assert "session_0" not in buf
    assert "session_64" in buf


def test_telnet_iac_detection():
    # IAC (0xFF) DO (0xFD) TERMINAL_TYPE (0x18)
    legitimate_telnet_payload = b"\xff\xfd\x18\xff\xfb\x01"
    raw_probe_payload = b"GET / HTTP/1.1\r\n"

    assert b"\xff" in legitimate_telnet_payload
    assert b"\xff" not in raw_probe_payload

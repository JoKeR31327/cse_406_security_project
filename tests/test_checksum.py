"""
Unit tests for RFC 1071 Checksum Implementation.
"""
import pytest
from attacker.checksum import rfc1071_checksum, compute_ip_checksum, compute_tcp_checksum


def test_rfc1071_basic():
    # Test with standard known byte stream
    test_data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
    chk = rfc1071_checksum(test_data)
    assert 0 <= chk <= 0xFFFF
    # Placing checksum back into stream should result in 0 or 0xFFFF
    verified_data = test_data[:10] + chk.to_bytes(2, "big") + test_data[12:]
    res = rfc1071_checksum(verified_data)
    assert res == 0 or res == 0xFFFF


def test_compute_ip_checksum():
    ip_hdr = b"\x45\x00\x00\x28\x13\x37\x40\x00\x40\x06\x00\x00\x0a\x00\x01\x0a\x0a\x00\x01\x14"
    chk = compute_ip_checksum(ip_hdr)
    assert isinstance(chk, int)
    assert 0 <= chk <= 0xFFFF


def test_compute_tcp_checksum():
    src_ip = "10.0.1.10"
    dst_ip = "10.0.1.20"
    tcp_hdr = b"\xc0\x00\x00\x17\x00\x00\x10\x00\x00\x00\x00\x00\x50\x14\x00\x00\x00\x00\x00\x00"
    chk = compute_tcp_checksum(src_ip, dst_ip, tcp_hdr)
    assert isinstance(chk, int)
    assert 0 <= chk <= 0xFFFF

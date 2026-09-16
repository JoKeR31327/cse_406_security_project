"""
Unit tests for Raw Packet Crafter byte serialization.
"""
import struct
import socket
from attacker.raw_socket_crafter import RawSocketCrafter


def test_craft_ipv4_header_structure():
    crafter = RawSocketCrafter()
    src_ip = "10.0.1.10"
    dst_ip = "10.0.1.20"
    hdr = crafter.craft_ipv4_header(src_ip, dst_ip, payload_len=20)

    assert len(hdr) == 20
    version_ihl, dscp_ecn, total_len, ident, flags_frag, ttl, proto, chk, src_b, dst_b = struct.unpack(
        "!BBHHHBBH4s4s", hdr
    )
    assert version_ihl == 0x45
    assert dscp_ecn == 0x00
    assert total_len == 40
    assert ident == 0x1337
    assert flags_frag == 0x4000  # DF set
    assert ttl == 64
    assert proto == 6  # TCP
    assert src_b == socket.inet_aton(src_ip)
    assert dst_b == socket.inet_aton(dst_ip)


def test_craft_tcp_header_structure():
    crafter = RawSocketCrafter()
    src_ip = "10.0.1.10"
    dst_ip = "10.0.1.20"
    src_port = 49152
    dst_port = 23
    seq_num = 12345678
    ack_num = 87654321

    tcp_hdr = crafter.craft_tcp_header(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        flags=0x14,  # RST + ACK
        window_size=0,
    )

    assert len(tcp_hdr) == 20
    s_port, d_port, s_num, a_num, offset_res, flags, win, chk, urg = struct.unpack(
        "!HHIIBBHHH", tcp_hdr
    )
    assert s_port == src_port
    assert d_port == 23
    assert s_num == seq_num
    assert a_num == ack_num
    assert offset_res == 0x50  # 5 * 4 = 20 bytes
    assert flags == 0x14  # RST + ACK
    assert win == 0

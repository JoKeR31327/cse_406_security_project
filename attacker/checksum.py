"""
RFC 1071 Checksum calculation for IPv4 and TCP.
Implements the standard 16-bit one's complement sum algorithm.
"""
import socket
import struct


def rfc1071_checksum(data: bytes) -> int:
    """Computes the standard 16-bit one's complement checksum over a byte buffer."""
    # If buffer length is odd, pad with a trailing zero byte to align on 16-bit words
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Fold 32-bit carries into the lower 16 bits until no overflow remains
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    # Take one's complement
    return (~total) & 0xFFFF


def compute_ip_checksum(ip_header_bytes: bytes) -> int:
    """
    Computes IPv4 header checksum.
    The checksum field (offset 10-12) must be zeroed out during computation.
    """
    header_zeroed = ip_header_bytes[:10] + b"\x00\x00" + ip_header_bytes[12:]
    return rfc1071_checksum(header_zeroed)


def compute_tcp_checksum(src_ip: str, dst_ip: str, tcp_segment_bytes: bytes) -> int:
    """
    Computes TCP checksum using the 12-byte IPv4 pseudo-header + TCP segment.
    The TCP checksum field (offset 16-18) is zeroed out before computing.
    """
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    protocol = 6  # IPPROTO_TCP
    tcp_len = len(tcp_segment_bytes)

    # Build pseudo-header: src_ip, dst_ip, zero, proto, tcp_length
    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_ip_bytes,
        dst_ip_bytes,
        0,
        protocol,
        tcp_len,
    )

    # Zero out checksum field (bytes 16 and 17) in the TCP header
    tcp_zeroed = tcp_segment_bytes[:16] + b"\x00\x00" + tcp_segment_bytes[18:]
    data_to_checksum = pseudo_header + tcp_zeroed

    return rfc1071_checksum(data_to_checksum)

"""
RFC 1071 Checksum Implementation for IPv4 and TCP Pseudo-Header.
Calculates 16-bit one's complement sum using big-endian serialization.
"""
import socket
import struct


def rfc1071_checksum(data: bytes) -> int:
    """
    Computes the standard RFC 1071 16-bit one's complement checksum.
    
    Args:
        data: Byte buffer to checksum.
        
    Returns:
        16-bit unsigned integer checksum.
    """
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Fold 32-bit carries into 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    # One's complement
    return (~total) & 0xFFFF


def compute_ip_checksum(ip_header_bytes: bytes) -> int:
    """
    Computes IPv4 Header Checksum.
    The checksum field (bytes 10-11) must be zeroed before computation.
    """
    # Ensure bytes 10 and 11 are zeroed for checksum calculation
    header_zeroed = ip_header_bytes[:10] + b"\x00\x00" + ip_header_bytes[12:]
    return rfc1071_checksum(header_zeroed)


def compute_tcp_checksum(src_ip: str, dst_ip: str, tcp_segment_bytes: bytes) -> int:
    """
    Computes TCP Checksum over the 12-byte Pseudo-Header + TCP Segment.
    The checksum field in the TCP segment (bytes 16-17) must be zeroed before computation.
    
    Pseudo-Header format (12 bytes):
    - Source IP Address (4 bytes)
    - Destination IP Address (4 bytes)
    - Zero (1 byte)
    - Protocol (1 byte, TCP = 6)
    - TCP Length (2 bytes)
    """
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    protocol = 6  # IPPROTO_TCP
    tcp_len = len(tcp_segment_bytes)

    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_ip_bytes,
        dst_ip_bytes,
        0,
        protocol,
        tcp_len,
    )

    # Ensure bytes 16 and 17 in TCP header are zeroed
    tcp_zeroed = tcp_segment_bytes[:16] + b"\x00\x00" + tcp_segment_bytes[18:]
    data_to_checksum = pseudo_header + tcp_zeroed

    return rfc1071_checksum(data_to_checksum)

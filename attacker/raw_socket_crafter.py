"""
Raw IP and TCP packet serialization and raw socket injection.
Constructs standard 20-byte IPv4 and 20-byte TCP headers directly into big-endian
wire format without relying on high-level packet crafting libraries.
"""
import socket
import struct
from attacker.checksum import compute_ip_checksum, compute_tcp_checksum


class RawSocketCrafter:
    """Handles manual byte packing for IPv4/TCP headers and raw socket transmission."""

    def __init__(self, interface: str = None):
        self.interface = interface

    @staticmethod
    def craft_ipv4_header(
        src_ip: str,
        dst_ip: str,
        payload_len: int = 20,
        identification: int = 0x1337,
        ttl: int = 64,
        df: bool = True,
    ) -> bytes:
        """
        Builds a standard 20-byte IPv4 header.
        Uses two-pass packing to calculate the header checksum accurately.
        """
        version_ihl = (4 << 4) | 5   # IPv4, 5 x 32-bit words (20 bytes)
        dscp_ecn = 0x00              # Default routine service
        total_length = 20 + payload_len
        flags_offset = 0x4000 if df else 0x0000  # Set Don't Fragment (DF) flag
        protocol = 6                 # IPPROTO_TCP
        checksum = 0
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)

        # Initial pack with zeroed checksum
        header_temp = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_offset,
            ttl,
            protocol,
            checksum,
            src_ip_bytes,
            dst_ip_bytes,
        )

        checksum = compute_ip_checksum(header_temp)

        # Repack with the calculated RFC 1071 checksum
        header_final = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_offset,
            ttl,
            protocol,
            checksum,
            src_ip_bytes,
            dst_ip_bytes,
        )
        return header_final

    @staticmethod
    def craft_tcp_header(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int = 0,
        flags: int = 0x14,  # Default: RST + ACK
        window_size: int = 0,
        urgent_ptr: int = 0,
        payload: bytes = b"",
    ) -> bytes:
        """
        Builds a 20-byte TCP header with optional payload.
        Computes the TCP checksum across the pseudo-header and segment.
        """
        data_offset_reserved = (5 << 4) | 0  # 5 x 32-bit words (20 bytes)
        checksum = 0

        # Initial pack with zeroed checksum
        tcp_temp = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq_num & 0xFFFFFFFF,
            ack_num & 0xFFFFFFFF,
            data_offset_reserved,
            flags,
            window_size,
            checksum,
            urgent_ptr,
        ) + payload

        checksum = compute_tcp_checksum(src_ip, dst_ip, tcp_temp)

        # Repack with the computed pseudo-header checksum
        tcp_final = struct.pack(
            "!HHIIBBHHH",
            src_port,
            dst_port,
            seq_num & 0xFFFFFFFF,
            ack_num & 0xFFFFFFFF,
            data_offset_reserved,
            flags,
            window_size,
            checksum,
            urgent_ptr,
        ) + payload
        return tcp_final

    def craft_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int = 0,
        flags: int = 0x14,
        window_size: int = 0,
        payload: bytes = b"",
    ) -> bytes:
        """Assembles the complete wire-ready packet: IPv4 header + TCP segment."""
        tcp_segment = self.craft_tcp_header(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            window_size=window_size,
            payload=payload,
        )
        ip_header = self.craft_ipv4_header(
            src_ip=src_ip,
            dst_ip=dst_ip,
            payload_len=len(tcp_segment),
        )
        return ip_header + tcp_segment

    @staticmethod
    def send_raw_packet(packet_bytes: bytes, dst_ip: str, dst_port: int = 23):
        """Transmits raw bytes over an AF_INET raw socket with IP_HDRINCL enabled."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(packet_bytes, (dst_ip, dst_port))
        finally:
            sock.close()

"""
Raw IP and TCP Packet Serializer and Injector.
Serializes standard 20-byte IPv4 and 20-byte TCP headers into network byte order
(big-endian) strictly without high-level packet generation libraries.
"""
import socket
import struct
from attacker.checksum import compute_ip_checksum, compute_tcp_checksum


class RawSocketCrafter:
    """
    Low-level raw packet crafter adhering to Table 1 and Table 2 of the design report.
    """

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
        Builds a 20-byte IPv4 Header (Table 1).
        
        Fields:
        - Version: 4, IHL: 5 (4b + 4b -> 0x45)
        - DSCP/ECN: 0x00 (8b)
        - Total Length: 20 + payload_len (16b)
        - Identification: 0x1337 (16b)
        - Flags: 0x02 [DF] & Frag Offset: 0 (16b -> 0x4000)
        - TTL: 64 (8b)
        - Protocol: 6 [TCP] (8b)
        - Checksum: Calculated RFC 1071 (16b)
        - Source IP: src_ip (32b)
        - Destination IP: dst_ip (32b)
        """
        version_ihl = (4 << 4) | 5
        dscp_ecn = 0x00
        total_length = 20 + payload_len
        flags_offset = 0x4000 if df else 0x0000
        protocol = 6  # IPPROTO_TCP
        checksum = 0
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)

        # First pass with checksum = 0
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

        # Second pass with computed RFC 1071 checksum
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
        flags: int = 0x14,  # RST + ACK (Table 2)
        window_size: int = 0,
        urgent_ptr: int = 0,
        payload: bytes = b"",
    ) -> bytes:
        """
        Builds a 20-byte TCP Header (Table 2).
        
        Fields:
        - Source Port: src_port (16b)
        - Destination Port: dst_port (16b)
        - Sequence Number: seq_num (32b)
        - Acknowledgment Number: ack_num (32b)
        - Data Offset: 5 (20 bytes), Reserved: 0 (8b -> 0x50)
        - Flags: flags (8b, e.g. 0x14 for RST+ACK)
        - Window Size: window_size (16b)
        - Checksum: Calculated RFC 1071 Pseudo-Header Sum (16b)
        - Urgent Pointer: urgent_ptr (16b)
        """
        data_offset_reserved = (5 << 4) | 0
        checksum = 0

        # First pass with checksum = 0
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

        # Second pass with computed checksum
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
        """
        Combines IPv4 and TCP headers into a complete wire-ready raw packet.
        """
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
        """
        Transmits raw packet using AF_INET and SOCK_RAW with IP_HDRINCL.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(packet_bytes, (dst_ip, dst_port))
        finally:
            sock.close()

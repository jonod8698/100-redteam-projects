#!/usr/bin/env python3
"""
Firewall Detector
Detect firewall presence and rules through various techniques
"""

import socket
import argparse
import random
from concurrent.futures import ThreadPoolExecutor

class FirewallDetector:
    def __init__(self, target, timeout=2):
        self.target = target
        self.timeout = timeout

    def tcp_connect_scan(self, port):
        """Standard TCP connect scan"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False

    def detect_filtering(self, port):
        """Detect if port is filtered by firewall"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                return "OPEN"
            elif result == 111:  # Connection refused
                return "CLOSED"
            else:
                return "FILTERED"
        except socket.timeout:
            return "FILTERED"
        except:
            return "ERROR"

    def scan_multiple_ports(self, ports):
        """Scan multiple ports to detect filtering patterns"""
        print(f"[*] Scanning {self.target} for firewall detection")
        print(f"[*] Testing {len(ports)} ports")
        print("-" * 60)

        results = {
            'open': [],
            'closed': [],
            'filtered': []
        }

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.detect_filtering, port): port for port in ports}

            for future in futures:
                port = futures[future]
                state = future.result()

                if state == "OPEN":
                    results['open'].append(port)
                    print(f"[+] Port {port}: OPEN")
                elif state == "CLOSED":
                    results['closed'].append(port)
                elif state == "FILTERED":
                    results['filtered'].append(port)
                    print(f"[!] Port {port}: FILTERED (possible firewall)")

        return results

    def analyze_firewall(self, results):
        """Analyze results to detect firewall presence"""
        print("\n" + "=" * 60)
        print("FIREWALL DETECTION ANALYSIS")
        print("=" * 60)

        total_ports = len(results['open']) + len(results['closed']) + len(results['filtered'])

        print(f"\n[*] Scan Summary:")
        print(f"    Open ports: {len(results['open'])}")
        print(f"    Closed ports: {len(results['closed'])}")
        print(f"    Filtered ports: {len(results['filtered'])}")

        filtered_ratio = len(results['filtered']) / total_ports if total_ports > 0 else 0

        if filtered_ratio > 0.5:
            print(f"\n[!] FIREWALL DETECTED - High filtering ratio ({filtered_ratio:.1%})")
            print("[!] The target appears to be protected by a firewall")
        elif filtered_ratio > 0.2:
            print(f"\n[?] POSSIBLE FIREWALL - Moderate filtering ratio ({filtered_ratio:.1%})")
            print("[?] Some firewall rules may be in place")
        else:
            print(f"\n[+] NO FIREWALL DETECTED - Low filtering ratio ({filtered_ratio:.1%})")
            print("[+] The target does not appear to have significant firewall protection")

def main():
    parser = argparse.ArgumentParser(
        description='Firewall Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Scan common ports:
    %(prog)s -t 192.168.1.1

  Scan specific port range:
    %(prog)s -t example.com -p 1-1000

  Scan custom ports:
    %(prog)s -t 10.10.10.1 -p 80,443,8080,22,21
        '''
    )

    parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    parser.add_argument('-p', '--ports', help='Port range or comma-separated ports')
    parser.add_argument('--timeout', type=float, default=2, help='Timeout in seconds (default: 2)')

    args = parser.parse_args()

    # Determine ports to scan
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in args.ports.split(',')]
    else:
        # Default common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]

    # Run detection
    detector = FirewallDetector(args.target, timeout=args.timeout)
    results = detector.scan_multiple_ports(ports)
    detector.analyze_firewall(results)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Port Scanner with Service Footprinting
Scans ports and identifies the service running on them
"""

import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Common port-to-service mappings
PORT_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6667: "IRC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    6379: "Redis"
}

# Service detection patterns
SERVICE_PATTERNS = {
    'HTTP': [
        b'HTTP/',
        b'<!DOCTYPE',
        b'<html',
        b'Server:'
    ],
    'FTP': [
        b'220',
        b'FTP',
        b'FileZilla',
        b'ProFTPD',
        b'vsftpd'
    ],
    'SSH': [
        b'SSH-',
        b'OpenSSH'
    ],
    'SMTP': [
        b'220',
        b'SMTP',
        b'ESMTP',
        b'Postfix',
        b'Exim'
    ],
    'POP3': [
        b'+OK',
        b'POP3'
    ],
    'IMAP': [
        b'* OK',
        b'IMAP'
    ],
    'MySQL': [
        b'mysql',
        b'MariaDB'
    ],
    'PostgreSQL': [
        b'PostgreSQL'
    ],
    'DNS': [
        b'BIND',
        b'dnsmasq'
    ],
    'IRC': [
        b'IRC',
        b':ircd'
    ],
    'Telnet': [
        b'Telnet',
        b'Login:'
    ],
    'Redis': [
        b'Redis'
    ],
    'MongoDB': [
        b'MongoDB'
    ],
    'VNC': [
        b'RFB'
    ]
}

class PortFootprintScanner:
    def __init__(self, target, timeout=2):
        self.target = target
        self.timeout = timeout

    def grab_banner(self, port):
        """Attempt to grab the service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            # Try to receive banner
            try:
                banner = sock.recv(1024)
            except:
                # Some services need a probe first
                probes = [
                    b'HEAD / HTTP/1.0\r\n\r\n',
                    b'GET / HTTP/1.0\r\n\r\n',
                    b'HELP\r\n',
                    b'\r\n'
                ]
                banner = b''
                for probe in probes:
                    try:
                        sock.send(probe)
                        banner = sock.recv(1024)
                        if banner:
                            break
                    except:
                        continue

            sock.close()
            return banner.decode('utf-8', errors='ignore') if banner else None

        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            return None

    def identify_service(self, port, banner):
        """Identify service based on port and banner"""
        service_name = PORT_SERVICES.get(port, "Unknown")

        if banner:
            # Try to match against known patterns
            banner_bytes = banner.encode('utf-8', errors='ignore')

            for service, patterns in SERVICE_PATTERNS.items():
                for pattern in patterns:
                    if pattern in banner_bytes:
                        return service, banner[:100]

        return service_name, banner[:100] if banner else None

    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()

            if result == 0:
                # Port is open, try to identify service
                banner = self.grab_banner(port)
                service, banner_info = self.identify_service(port, banner)
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner_info
                }

        except socket.gaierror:
            return None
        except socket.error:
            return None
        except Exception:
            return None

        return None

    def scan(self, ports, threads=100):
        """Scan multiple ports"""
        print(f"[*] Scanning {self.target} for open ports with service detection...")
        print(f"[*] Timeout: {self.timeout}s | Threads: {threads}")
        print("-" * 80)

        open_ports = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}

            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self.print_result(result)

        return open_ports

    def print_result(self, result):
        """Print scan result"""
        port = result['port']
        service = result['service']
        banner = result['banner']

        print(f"Port {port:5d}/tcp    {service:15s}    OPEN", end='')

        if banner:
            # Clean up banner for display
            banner_clean = banner.replace('\r', ' ').replace('\n', ' ').strip()
            if banner_clean:
                print(f"    [{banner_clean}]")
            else:
                print()
        else:
            print()

def parse_port_range(port_range):
    """Parse port range string (e.g., '1-1000' or '80,443,8080')"""
    ports = []

    for part in port_range.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return ports

def main():
    parser = argparse.ArgumentParser(
        description='Port Scanner with Service Footprinting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 192.168.1.1 -p 1-1000
  %(prog)s scanme.nmap.org -p 80,443,8080
  %(prog)s example.com -p 1-65535 -t 200
  %(prog)s 10.0.0.1 --common
        '''
    )

    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1000 or 80,443,8080)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=2, help='Connection timeout in seconds (default: 2)')
    parser.add_argument('--common', action='store_true', help='Scan common ports only')

    args = parser.parse_args()

    # Determine ports to scan
    if args.common:
        ports = list(PORT_SERVICES.keys())
    elif args.ports:
        try:
            ports = parse_port_range(args.ports)
        except ValueError:
            print("Error: Invalid port range format")
            sys.exit(1)
    else:
        # Default to common ports
        ports = list(PORT_SERVICES.keys())

    # Validate target
    try:
        socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"Error: Cannot resolve hostname '{args.target}'")
        sys.exit(1)

    # Create scanner and run
    scanner = PortFootprintScanner(args.target, timeout=args.timeout)

    try:
        open_ports = scanner.scan(sorted(set(ports)), threads=args.threads)
        print("-" * 80)
        print(f"\n[+] Scan complete. Found {len(open_ports)} open port(s).\n")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Packet Capture Tool
Simple packet sniffer for network analysis
"""

import socket
import struct
import textwrap
import argparse

class PacketSniffer:
    def __init__(self, interface=None, count=None, filter_protocol=None):
        self.interface = interface
        self.count = count
        self.filter_protocol = filter_protocol
        self.packet_count = 0

    def ethernet_frame(self, data):
        """Unpack ethernet frame"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        """Format MAC address"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        """Unpack IPv4 packet"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        """Format IPv4 address"""
        return '.'.join(map(str, addr))

    def tcp_segment(self, data):
        """Unpack TCP segment"""
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def udp_segment(self, data):
        """Unpack UDP segment"""
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def capture(self):
        """Start packet capture"""
        try:
            # Create raw socket
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

            print("[*] Starting packet capture...")
            print(f"[*] Capture count: {'Unlimited' if not self.count else self.count}")
            if self.filter_protocol:
                print(f"[*] Filter: {self.filter_protocol}")
            print("-" * 80)

            while True:
                if self.count and self.packet_count >= self.count:
                    break

                raw_data, addr = conn.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)

                # IPv4
                if eth_proto == 8:
                    version, header_length, ttl, proto, src, target, data = self.ipv4_packet(data)

                    # TCP
                    if proto == 6 and (not self.filter_protocol or self.filter_protocol.upper() == 'TCP'):
                        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = self.tcp_segment(data)
                        self.packet_count += 1
                        print(f"\n[Packet #{self.packet_count}] TCP Packet:")
                        print(f"  Source: {src}:{src_port} -> Destination: {target}:{dest_port}")
                        print(f"  Flags: URG={flag_urg} ACK={flag_ack} PSH={flag_psh} RST={flag_rst} SYN={flag_syn} FIN={flag_fin}")

                    # UDP
                    elif proto == 17 and (not self.filter_protocol or self.filter_protocol.upper() == 'UDP'):
                        src_port, dest_port, size, data = self.udp_segment(data)
                        self.packet_count += 1
                        print(f"\n[Packet #{self.packet_count}] UDP Packet:")
                        print(f"  Source: {src}:{src_port} -> Destination: {target}:{dest_port}")
                        print(f"  Size: {size}")

        except KeyboardInterrupt:
            print(f"\n\n[*] Capture stopped. Total packets: {self.packet_count}")
        except PermissionError:
            print("[-] Error: Root/Administrator privileges required for packet capture")
        except Exception as e:
            print(f"[-] Error: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Packet Capture Tool (Requires root/admin privileges)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Capture all packets:
    sudo %(prog)s

  Capture 100 packets:
    sudo %(prog)s -c 100

  Capture only TCP packets:
    sudo %(prog)s -f TCP

  Capture only UDP packets:
    sudo %(prog)s -f UDP -c 50
        '''
    )

    parser.add_argument('-i', '--interface', help='Network interface (optional)')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-f', '--filter', help='Protocol filter (TCP or UDP)')

    args = parser.parse_args()

    sniffer = PacketSniffer(
        interface=args.interface,
        count=args.count,
        filter_protocol=args.filter
    )

    sniffer.capture()

if __name__ == "__main__":
    main()

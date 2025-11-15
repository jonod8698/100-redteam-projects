#!/usr/bin/env python3
"""
Badchar Detector
Detect bad characters in binary/exploit payloads
"""

import argparse
import sys

class BadcharDetector:
    def generate_all_chars(self):
        """Generate all possible byte values"""
        return bytes(range(0, 256))

    def detect_badchars(self, payload, excluded_chars=None):
        """Detect bad characters in payload"""
        if excluded_chars is None:
            excluded_chars = [b'\x00']  # NULL byte is commonly bad

        all_chars = self.generate_all_chars()
        badchars = []

        print("[*] Analyzing payload for bad characters...")
        print(f"[*] Payload length: {len(payload)}")
        print("-" * 60)

        for char in all_chars:
            char_byte = bytes([char])
            if char_byte in excluded_chars:
                badchars.append(char)
                print(f"[!] Bad character found: {hex(char)} (\\x{char:02x})")

        return badchars

    def generate_badchar_string(self, exclude=[]):
        """Generate string of all characters except specified ones"""
        all_chars = bytearray(range(1, 256))  # Exclude NULL by default

        for char in exclude:
            if isinstance(char, str):
                char = int(char, 16)
            if char in all_chars:
                all_chars.remove(char)

        return bytes(all_chars)

    def format_bytes(self, data, columns=16):
        """Format bytes for display"""
        result = []
        for i in range(0, len(data), columns):
            chunk = data[i:i+columns]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            result.append(hex_str)
        return '\n'.join(result)

def main():
    parser = argparse.ArgumentParser(
        description='Badchar Detector for Exploit Development',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Generate all chars except NULL:
    %(prog)s -g

  Generate chars excluding specific bytes:
    %(prog)s -g -e 00 0a 0d

  Test payload for badchars:
    %(prog)s -f payload.bin -e 00 0a
        '''
    )

    parser.add_argument('-g', '--generate', action='store_true',
                        help='Generate badchar string')
    parser.add_argument('-e', '--exclude', nargs='+',
                        help='Bytes to exclude (hex format, e.g., 00 0a 0d)')
    parser.add_argument('-f', '--file', help='Payload file to analyze')
    parser.add_argument('-o', '--output', help='Output file for generated badchar string')

    args = parser.parse_args()

    detector = BadcharDetector()

    if args.generate:
        # Generate badchar string
        exclude = []
        if args.exclude:
            exclude = [int(x, 16) for x in args.exclude]

        badchar_string = detector.generate_badchar_string(exclude=exclude)

        print("[+] Generated badchar string:")
        print("-" * 60)
        print(detector.format_bytes(badchar_string))
        print("-" * 60)
        print(f"\n[*] Total bytes: {len(badchar_string)}")

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(badchar_string)
            print(f"[+] Saved to: {args.output}")

        # Also print Python format
        print("\n[*] Python format:")
        hex_list = ''.join(f'\\x{b:02x}' for b in badchar_string)
        print(f'badchars = b"{hex_list}"')

    elif args.file:
        # Analyze payload file
        try:
            with open(args.file, 'rb') as f:
                payload = f.read()

            exclude = [0x00]  # Default exclude NULL
            if args.exclude:
                exclude.extend([int(x, 16) for x in args.exclude])

            exclude_bytes = [bytes([x]) for x in exclude]
            badchars = detector.detect_badchars(payload, exclude_bytes)

            print(f"\n[*] Total bad characters: {len(badchars)}")

        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
            sys.exit(1)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

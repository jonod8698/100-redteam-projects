#!/usr/bin/env python3
"""
OS Enumeration Script
Gather system information after gaining shell access
"""

import platform
import socket
import subprocess
import os
import argparse

class OSEnumerator:
    def __init__(self):
        self.info = {}

    def get_basic_info(self):
        """Get basic system information"""
        self.info['hostname'] = socket.gethostname()
        self.info['os'] = platform.system()
        self.info['os_version'] = platform.version()
        self.info['os_release'] = platform.release()
        self.info['architecture'] = platform.machine()
        self.info['processor'] = platform.processor()

    def get_network_info(self):
        """Get network configuration"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
            self.info['network'] = result.stdout
        except:
            self.info['network'] = 'Unable to retrieve'

    def get_users(self):
        """Get user information"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['net', 'user'], capture_output=True, text=True)
            else:
                result = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
            self.info['users'] = result.stdout
        except:
            self.info['users'] = 'Unable to retrieve'

    def get_processes(self):
        """Get running processes"""
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            self.info['processes'] = result.stdout[:2000]  # Limit output
        except:
            self.info['processes'] = 'Unable to retrieve'

    def get_environment(self):
        """Get environment variables"""
        self.info['env_vars'] = dict(os.environ)

    def enumerate(self, verbose=False):
        """Run full enumeration"""
        print("[*] Starting OS Enumeration")
        print("=" * 60)

        self.get_basic_info()
        print(f"\n[+] Hostname: {self.info['hostname']}")
        print(f"[+] OS: {self.info['os']} {self.info['os_release']}")
        print(f"[+] Architecture: {self.info['architecture']}")
        print(f"[+] Processor: {self.info['processor']}")

        if verbose:
            print("\n[*] Network Configuration:")
            print("-" * 60)
            self.get_network_info()
            print(self.info['network'][:500])

            print("\n[*] Users:")
            print("-" * 60)
            self.get_users()
            print(self.info['users'][:500])

            print("\n[*] Running Processes:")
            print("-" * 60)
            self.get_processes()
            print(self.info['processes'][:500])

            print("\n[*] Environment Variables:")
            print("-" * 60)
            self.get_environment()
            for key, value in list(self.info['env_vars'].items())[:10]:
                print(f"    {key}: {value}")

        return self.info

    def save_report(self, filename):
        """Save enumeration report to file"""
        with open(filename, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("OS ENUMERATION REPORT\n")
            f.write("=" * 60 + "\n\n")

            for key, value in self.info.items():
                f.write(f"\n{key.upper()}:\n")
                f.write("-" * 60 + "\n")
                if isinstance(value, dict):
                    for k, v in value.items():
                        f.write(f"{k}: {v}\n")
                else:
                    f.write(str(value) + "\n")

        print(f"\n[+] Report saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description='OS Enumeration Script')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Save report to file')

    args = parser.parse_args()

    enumerator = OSEnumerator()
    enumerator.enumerate(verbose=args.verbose)

    if args.output:
        enumerator.save_report(args.output)

if __name__ == "__main__":
    main()

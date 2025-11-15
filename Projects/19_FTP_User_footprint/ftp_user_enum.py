#!/usr/bin/env python3
"""
FTP User Footprint Tool
Enumerate valid FTP users on a server
"""

import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class FTPUserEnum:
    def __init__(self, host, port=21, timeout=5, verbose=False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.valid_users = []

    def check_user(self, username):
        """Check if username exists on FTP server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if self.verbose:
                print(f"[*] Banner: {banner.strip()}")

            # Send USER command
            sock.send(f"USER {username}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            sock.close()

            # Analyze response codes
            # 230 = User logged in (no password required)
            # 331 = User name okay, need password
            # 530 = Not logged in (user doesn't exist or wrong password)
            # 421 = Service not available

            if response.startswith('230'):
                # User exists and no password required
                return 'valid_no_pass'
            elif response.startswith('331'):
                # User exists, password required
                return 'valid_need_pass'
            elif response.startswith('530'):
                # Check response message for user enumeration
                if 'user' in response.lower() or 'unknown' in response.lower():
                    return 'invalid'
                else:
                    # Some servers return 530 for valid users too
                    return 'possible'
            else:
                return 'unknown'

        except socket.timeout:
            if self.verbose:
                print(f"[-] Timeout for user: {username}")
            return 'timeout'
        except socket.error as e:
            if self.verbose:
                print(f"[-] Connection error for {username}: {e}")
            return 'error'
        except Exception as e:
            if self.verbose:
                print(f"[-] Error checking {username}: {e}")
            return 'error'

    def enumerate_users(self, usernames, threads=5):
        """Enumerate multiple usernames"""
        print(f"[*] Starting FTP user enumeration")
        print(f"[*] Target: {self.host}:{self.port}")
        print(f"[*] Usernames to test: {len(usernames)}")
        print(f"[*] Threads: {threads}")
        print("-" * 60)

        results = {
            'valid_no_pass': [],
            'valid_need_pass': [],
            'possible': [],
            'invalid': [],
            'unknown': [],
            'error': []
        }

        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_user = {executor.submit(self.check_user, user): user for user in usernames}

            for future in as_completed(future_to_user):
                username = future_to_user[future]
                result = future.result()

                results[result].append(username)

                if result == 'valid_no_pass':
                    print(f"[+] VALID (No password): {username}")
                elif result == 'valid_need_pass':
                    print(f"[+] VALID (Needs password): {username}")
                elif result == 'possible':
                    print(f"[?] POSSIBLE: {username}")
                elif self.verbose:
                    print(f"[-] Invalid: {username}")

        return results

    def print_summary(self, results):
        """Print enumeration summary"""
        print("\n" + "=" * 60)
        print("ENUMERATION SUMMARY")
        print("=" * 60)

        if results['valid_no_pass']:
            print(f"\n[+] Valid users (no password required): {len(results['valid_no_pass'])}")
            for user in results['valid_no_pass']:
                print(f"    - {user}")

        if results['valid_need_pass']:
            print(f"\n[+] Valid users (password required): {len(results['valid_need_pass'])}")
            for user in results['valid_need_pass']:
                print(f"    - {user}")

        if results['possible']:
            print(f"\n[?] Possible valid users: {len(results['possible'])}")
            for user in results['possible']:
                print(f"    - {user}")

        total_valid = len(results['valid_no_pass']) + len(results['valid_need_pass'])
        print(f"\n[*] Total valid users found: {total_valid}")

def load_userlist(filename):
    """Load username list from file"""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='FTP User Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Single user check:
    %(prog)s -t ftp.example.com -u admin

  Enumerate from wordlist:
    %(prog)s -t 192.168.1.10 -U users.txt

  With custom port and threads:
    %(prog)s -t ftp.example.com -U users.txt -p 2121 -T 10

  Verbose mode:
    %(prog)s -t ftp.example.com -U users.txt -v
        '''
    )

    parser.add_argument('-t', '--target', required=True, help='Target FTP server')
    parser.add_argument('-p', '--port', type=int, default=21, help='FTP port (default: 21)')
    parser.add_argument('-u', '--user', help='Single username to check')
    parser.add_argument('-U', '--userlist', help='File containing usernames')
    parser.add_argument('-T', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Validate arguments
    if not args.user and not args.userlist:
        parser.error("Either -u/--user or -U/--userlist is required")

    # Load usernames
    if args.userlist:
        usernames = load_userlist(args.userlist)
    else:
        usernames = [args.user]

    # Create enumerator
    enumerator = FTPUserEnum(
        host=args.target,
        port=args.port,
        timeout=args.timeout,
        verbose=args.verbose
    )

    try:
        # Run enumeration
        results = enumerator.enumerate_users(usernames, threads=args.threads)

        # Print summary
        enumerator.print_summary(results)

    except KeyboardInterrupt:
        print("\n\n[!] Enumeration interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()

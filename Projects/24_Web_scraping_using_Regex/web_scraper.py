#!/usr/bin/env python3
"""
Web Scraper using Regex
Scrape web pages and extract data using regular expressions
"""

import requests
import re
import argparse
import sys

class WebScraper:
    def __init__(self, url, verbose=False):
        self.url = url
        self.verbose = verbose

    def fetch_page(self):
        """Fetch webpage content"""
        try:
            print(f"[*] Fetching: {self.url}")
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"[-] Error fetching page: {e}")
            return None

    def extract_emails(self, content):
        """Extract email addresses"""
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(pattern, content)
        return list(set(emails))

    def extract_urls(self, content):
        """Extract URLs"""
        pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)'
        urls = re.findall(pattern, content)
        return list(set(urls))

    def extract_phone_numbers(self, content):
        """Extract phone numbers"""
        patterns = [
            r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',
            r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        ]
        phones = []
        for pattern in patterns:
            phones.extend(re.findall(pattern, content))
        return list(set(phones))

    def extract_custom_pattern(self, content, pattern):
        """Extract using custom regex pattern"""
        try:
            matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
            return matches
        except re.error as e:
            print(f"[-] Invalid regex pattern: {e}")
            return []

    def scrape(self, extract_type='all', custom_pattern=None):
        """Main scraping function"""
        content = self.fetch_page()
        if not content:
            return

        results = {}

        if extract_type in ['all', 'emails']:
            emails = self.extract_emails(content)
            results['emails'] = emails
            if emails:
                print(f"\n[+] Found {len(emails)} email(s):")
                for email in emails:
                    print(f"    {email}")

        if extract_type in ['all', 'urls']:
            urls = self.extract_urls(content)
            results['urls'] = urls
            if urls:
                print(f"\n[+] Found {len(urls)} URL(s):")
                for url in urls[:20]:  # Limit display
                    print(f"    {url}")
                if len(urls) > 20:
                    print(f"    ... and {len(urls) - 20} more")

        if extract_type in ['all', 'phones']:
            phones = self.extract_phone_numbers(content)
            results['phones'] = phones
            if phones:
                print(f"\n[+] Found {len(phones)} phone number(s):")
                for phone in phones:
                    print(f"    {phone}")

        if custom_pattern:
            custom_matches = self.extract_custom_pattern(content, custom_pattern)
            results['custom'] = custom_matches
            if custom_matches:
                print(f"\n[+] Found {len(custom_matches)} custom match(es):")
                for match in custom_matches[:50]:
                    print(f"    {match}")

        return results

def main():
    parser = argparse.ArgumentParser(
        description='Web Scraper using Regular Expressions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Scrape all data types:
    %(prog)s -u https://example.com

  Extract only emails:
    %(prog)s -u https://example.com -t emails

  Extract with custom regex:
    %(prog)s -u https://example.com -r "\\bAPI[_-]?KEY\\b"

  Extract multiple types:
    %(prog)s -u https://example.com -t emails,urls
        '''
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL to scrape')
    parser.add_argument('-t', '--type', default='all',
                        help='Data type to extract: all, emails, urls, phones (default: all)')
    parser.add_argument('-r', '--regex', help='Custom regex pattern to extract')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    scraper = WebScraper(args.url, verbose=args.verbose)
    scraper.scrape(extract_type=args.type, custom_pattern=args.regex)

if __name__ == "__main__":
    main()

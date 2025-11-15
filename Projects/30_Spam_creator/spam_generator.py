#!/usr/bin/env python3
"""
Spam Creator/Generator
Generate spam text for testing spam filters
"""

import random
import argparse
import string

class SpamGenerator:
    # Common spam keywords and phrases
    SPAM_WORDS = [
        "FREE", "URGENT", "ACT NOW", "LIMITED TIME", "EXCLUSIVE", "WINNER",
        "CONGRATULATIONS", "CLICK HERE", "BUY NOW", "DISCOUNT", "SALE",
        "AMAZING", "INCREDIBLE", "GUARANTEE", "LOWEST PRICE", "SPECIAL OFFER",
        "NO RISK", "100% FREE", "MONEY BACK", "PRIZE", "BONUS",
        "CASINO", "VIAGRA", "PILLS", "WEIGHT LOSS", "EARN MONEY",
        "WORK FROM HOME", "MILLION DOLLARS", "PRINCE", "INHERITANCE",
        "BANK ACCOUNT", "VERIFY YOUR ACCOUNT", "SUSPENDED ACCOUNT"
    ]

    EMAIL_TEMPLATES = [
        "Dear {name},\n\n{spam_text}\n\nClick here to claim: {link}\n\nBest regards,\n{sender}",
        "URGENT: {name}!\n\n{spam_text}\n\nVisit: {link}\n\n{sender}",
        "Congratulations {name}!\n\n{spam_text}\n\nACT NOW: {link}\n\n{sender}",
        "{name},\n\nYou have been selected! {spam_text}\n\nClaim here: {link}\n\n{sender}"
    ]

    def __init__(self):
        self.names = ["Friend", "Customer", "Winner", "User", "Member"]
        self.senders = ["Admin", "Support Team", "Management", "Customer Service", "System"]
        self.links = ["http://bit.ly/xxxxx", "http://spam.example.com", "http://click-here-now.com"]

    def generate_spam_text(self, length=50):
        """Generate random spam text"""
        spam_text = []
        while len(' '.join(spam_text).split()) < length:
            spam_text.append(random.choice(self.SPAM_WORDS))
        return ' '.join(spam_text)

    def generate_email_spam(self, count=1):
        """Generate spam email messages"""
        emails = []
        for _ in range(count):
            template = random.choice(self.EMAIL_TEMPLATES)
            email = template.format(
                name=random.choice(self.names),
                spam_text=self.generate_spam_text(random.randint(20, 50)),
                link=random.choice(self.links),
                sender=random.choice(self.senders)
            )
            emails.append(email)
        return emails

    def generate_comment_spam(self, count=1):
        """Generate spam comments"""
        comments = []
        for _ in range(count):
            comment = f"{self.generate_spam_text(random.randint(10, 30))} {random.choice(self.links)}"
            comments.append(comment)
        return comments

    def generate_random_string(self, length):
        """Generate random string"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

def main():
    parser = argparse.ArgumentParser(
        description='Spam Generator for Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Generate email spam:
    %(prog)s -t email -c 5

  Generate comment spam:
    %(prog)s -t comment -c 10

  Save to file:
    %(prog)s -t email -c 100 -o spam.txt
        '''
    )

    parser.add_argument('-t', '--type', default='email', choices=['email', 'comment'],
                        help='Type of spam to generate (default: email)')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='Number of spam messages to generate (default: 1)')
    parser.add_argument('-o', '--output', help='Output file (optional)')

    args = parser.parse_args()

    generator = SpamGenerator()

    print(f"[*] Generating {args.count} {args.type} spam message(s)...")
    print("-" * 60)

    if args.type == 'email':
        spam_messages = generator.generate_email_spam(args.count)
    else:
        spam_messages = generator.generate_comment_spam(args.count)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            for msg in spam_messages:
                f.write(msg + "\n\n" + "="*60 + "\n\n")
        print(f"[+] Spam messages saved to: {args.output}")
    else:
        for i, msg in enumerate(spam_messages, 1):
            print(f"\n--- Spam Message #{i} ---")
            print(msg)
            print()

    print(f"\n[+] Generated {len(spam_messages)} spam message(s)")

if __name__ == "__main__":
    main()

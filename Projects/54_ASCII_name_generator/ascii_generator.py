#!/usr/bin/env python3
"""
ASCII Art Name Generator
Generate ASCII art from text
"""

import argparse

class ASCIIGenerator:
    FONTS = {
        'banner': {
            'A': ['  ##  ', ' #  # ', '#    #', '######', '#    #', '#    #'],
            'B': ['##### ', '#    #', '##### ', '#    #', '#    #', '##### '],
            'C': [' #### ', '#    #', '#     ', '#     ', '#    #', ' #### '],
            'D': ['##### ', '#    #', '#    #', '#    #', '#    #', '##### '],
            'E': ['######', '#     ', '##### ', '#     ', '#     ', '######'],
            ' ': ['      ', '      ', '      ', '      ', '      ', '      ']
        },
        'block': {
            'A': ['█████ ', '█   █ ', '█████ ', '█   █ ', '█   █ ', '█   █ '],
            'B': ['████  ', '█   █ ', '████  ', '█   █ ', '█   █ ', '████  '],
            'C': [' ████ ', '█     ', '█     ', '█     ', '█     ', ' ████ '],
            ' ': ['      ', '      ', '      ', '      ', '      ', '      ']
        }
    }

    def generate(self, text, font='banner'):
        """Generate ASCII art"""
        text = text.upper()
        lines = [''] * 6

        for char in text:
            if char in self.FONTS.get(font, self.FONTS['banner']):
                char_lines = self.FONTS[font][char]
                for i in range(6):
                    lines[i] += char_lines[i] + ' '
            else:
                for i in range(6):
                    lines[i] += '      '

        return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description='ASCII Art Name Generator')
    parser.add_argument('text', help='Text to convert to ASCII art')
    parser.add_argument('-f', '--font', default='banner', choices=['banner', 'block'],
                        help='ASCII font style (default: banner)')

    args = parser.parse_args()

    generator = ASCIIGenerator()
    ascii_art = generator.generate(args.text, args.font)
    print(ascii_art)

if __name__ == "__main__":
    main()

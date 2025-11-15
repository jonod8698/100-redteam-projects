#!/usr/bin/env python3
"""
UDP Chat Server
A multi-client chat server using UDP protocol
"""

import socket
import threading
from datetime import datetime

class UDPChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.clients = {}  # Dictionary to store client addresses and nicknames
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))

    def broadcast(self, message, sender_addr=None):
        """Broadcast message to all connected clients except sender"""
        for client_addr in self.clients.keys():
            if client_addr != sender_addr:
                try:
                    self.socket.sendto(message.encode('utf-8'), client_addr)
                except Exception as e:
                    print(f"Error sending to {client_addr}: {e}")

    def handle_client_message(self, message, client_addr):
        """Handle incoming client messages"""
        # Check if this is a new client joining
        if message.startswith('/join '):
            nickname = message.split(' ', 1)[1]
            self.clients[client_addr] = nickname
            join_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {nickname} has joined the chat!"
            print(join_msg)
            self.broadcast(join_msg)
            # Send welcome message to the new client
            welcome = f"Welcome to the UDP Chat Server, {nickname}!"
            self.socket.sendto(welcome.encode('utf-8'), client_addr)

        elif message == '/quit':
            if client_addr in self.clients:
                nickname = self.clients[client_addr]
                leave_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {nickname} has left the chat."
                print(leave_msg)
                self.broadcast(leave_msg)
                del self.clients[client_addr]

        elif message.startswith('/list'):
            # Send list of connected users
            if self.clients:
                user_list = "Connected users: " + ", ".join(self.clients.values())
            else:
                user_list = "No users connected."
            self.socket.sendto(user_list.encode('utf-8'), client_addr)

        else:
            # Regular chat message
            if client_addr in self.clients:
                nickname = self.clients[client_addr]
                chat_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {nickname}: {message}"
                print(chat_msg)
                self.broadcast(chat_msg, sender_addr=client_addr)
            else:
                # Client hasn't joined yet
                error_msg = "Please join the chat first using: /join <nickname>"
                self.socket.sendto(error_msg.encode('utf-8'), client_addr)

    def start(self):
        """Start the UDP chat server"""
        print(f"[*] UDP Chat Server started on {self.host}:{self.port}")
        print(f"[*] Waiting for clients...")

        try:
            while True:
                data, client_addr = self.socket.recvfrom(1024)
                message = data.decode('utf-8').strip()

                # Handle client message in a separate thread
                thread = threading.Thread(
                    target=self.handle_client_message,
                    args=(message, client_addr)
                )
                thread.daemon = True
                thread.start()

        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
            self.socket.close()

if __name__ == "__main__":
    import sys

    # Default values
    host = '0.0.0.0'
    port = 5555

    # Parse command line arguments
    if len(sys.argv) > 1:
        host = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])

    server = UDPChatServer(host, port)
    server.start()

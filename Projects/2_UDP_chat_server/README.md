# UDP Chat Server

A simple multi-client chat server using the UDP protocol.

## Description

This project implements a chat server and client using the UDP (User Datagram Protocol). Unlike TCP, UDP is connectionless and doesn't guarantee delivery, making it faster but less reliable. This implementation handles multiple clients and allows them to exchange messages in a chat room style.

## Features

- Multi-client support
- User nicknames
- Broadcast messages to all connected users
- List connected users
- Simple command system
- Threaded message handling

## Files

- `udp_chat_server.py` - The UDP chat server
- `udp_chat_client.py` - The UDP chat client

## Usage

### Starting the Server

```bash
python3 udp_chat_server.py [host] [port]
```

Default: `0.0.0.0:5555`

Example:
```bash
python3 udp_chat_server.py 0.0.0.0 5555
```

### Connecting a Client

```bash
python3 udp_chat_client.py [server_host] [server_port]
```

Default: `127.0.0.1:5555`

Example:
```bash
python3 udp_chat_client.py 127.0.0.1 5555
```

## Commands

- `/join <nickname>` - Join the chat with a nickname (automatically sent on connection)
- `/list` - List all connected users
- `/quit` - Leave the chat

## Example Session

Terminal 1 (Server):
```
$ python3 udp_chat_server.py
[*] UDP Chat Server started on 0.0.0.0:5555
[*] Waiting for clients...
[10:30:15] Alice has joined the chat!
[10:30:45] Bob has joined the chat!
[10:31:00] Alice: Hello everyone!
[10:31:05] Bob: Hi Alice!
```

Terminal 2 (Client 1):
```
$ python3 udp_chat_client.py
Enter your nickname: Alice
Connecting to UDP Chat Server at 127.0.0.1:5555...

Commands:
  /list  - List connected users
  /quit  - Leave the chat

> Hello everyone!
[10:31:05] Bob: Hi Alice!
```

Terminal 3 (Client 2):
```
$ python3 udp_chat_client.py
Enter your nickname: Bob
Connecting to UDP Chat Server at 127.0.0.1:5555...

Commands:
  /list  - List connected users
  /quit  - Leave the chat

>
[10:31:00] Alice: Hello everyone!
> Hi Alice!
```

## How It Works

1. **Server**: Listens for UDP packets on a specified port
2. **Client Connection**: Clients send a `/join` command with their nickname
3. **Message Broadcasting**: Server receives messages and broadcasts them to all connected clients
4. **Client Tracking**: Server maintains a dictionary of client addresses and nicknames
5. **Commands**: Special commands starting with `/` trigger specific actions

## UDP vs TCP

This implementation uses UDP, which differs from TCP in several ways:
- **Connectionless**: No handshake required
- **No delivery guarantee**: Messages may be lost
- **No ordering**: Messages may arrive out of order
- **Faster**: Lower overhead than TCP
- **Lightweight**: Good for real-time applications

## Limitations

- No message delivery guarantee
- No message ordering
- Basic error handling
- No encryption
- No authentication

## Security Notes

This is a basic implementation for educational purposes. In a production environment, you should consider:
- Implementing message encryption
- Adding authentication
- Implementing rate limiting
- Adding input validation
- Handling UDP packet loss and ordering

## Requirements

- Python 3.x
- No external dependencies (uses standard library)

## Author

Created as part of the 100 Red Team Projects collection.

## License

Educational purposes only. Use responsibly and only on systems you own or have explicit permission to test.

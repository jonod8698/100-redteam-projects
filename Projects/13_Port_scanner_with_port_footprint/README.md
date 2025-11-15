# Port Scanner with Service Footprinting

A multi-threaded port scanner that identifies services running on open ports through banner grabbing and service detection.

## Description

This advanced port scanner goes beyond basic port scanning by attempting to identify the actual service running on each open port. It uses a combination of:
- Known port-to-service mappings
- Banner grabbing
- Service pattern matching
- Multi-threaded scanning for speed

## Features

- Multi-threaded port scanning
- Service identification (HTTP, FTP, SSH, MySQL, etc.)
- Banner grabbing
- Configurable timeout and thread count
- Support for port ranges and individual ports
- Common ports preset
- OS fingerprinting through service banners

## Usage

### Basic Scan

```bash
python3 port_footprint_scanner.py <target>
```

### Scan Specific Port Range

```bash
python3 port_footprint_scanner.py <target> -p 1-1000
```

### Scan Specific Ports

```bash
python3 port_footprint_scanner.py <target> -p 80,443,8080,3306
```

### Scan Common Ports

```bash
python3 port_footprint_scanner.py <target> --common
```

### Advanced Options

```bash
python3 port_footprint_scanner.py <target> -p 1-65535 -t 200 --timeout 1
```

## Options

- `target` - Target IP address or hostname (required)
- `-p, --ports` - Port range (e.g., 1-1000 or 80,443,8080)
- `-t, --threads` - Number of threads (default: 100)
- `--timeout` - Connection timeout in seconds (default: 2)
- `--common` - Scan common ports only

## Example Output

```
$ python3 port_footprint_scanner.py scanme.nmap.org -p 1-1000

[*] Scanning scanme.nmap.org for open ports with service detection...
[*] Timeout: 2s | Threads: 100
--------------------------------------------------------------------------------
Port    22/tcp    SSH               OPEN    [SSH-2.0-OpenSSH_7.4]
Port    80/tcp    HTTP              OPEN    [HTTP/1.1 200 OK Server: Apache/2.4.7]
Port   443/tcp    HTTPS             OPEN    [HTTP/1.1 400 Bad Request]
--------------------------------------------------------------------------------

[+] Scan complete. Found 3 open port(s).
```

## Detected Services

The scanner can identify the following services:

### Network Services
- FTP (21)
- SSH (22)
- Telnet (23)
- SMTP (25, 587)
- DNS (53)
- DHCP (67, 68)
- TFTP (69)
- HTTP (80, 8080)
- HTTPS (443, 8443)
- POP3 (110)
- IMAP (143)
- SNMP (161, 162)
- IRC (194, 6667)
- LDAP (389)
- SMB (445)
- Syslog (514)

### Database Services
- MySQL (3306)
- PostgreSQL (5432)
- MS-SQL (1433)
- Oracle (1521)
- MongoDB (27017)
- Redis (6379)

### Remote Access
- RDP (3389)
- VNC (5900)

### Other Services
- NetBIOS (137, 138, 139)
- MS-RPC (135)
- And more...

## How It Works

1. **Port Scanning**: Attempts TCP connection to each port
2. **Banner Grabbing**: If port is open, tries to receive service banner
3. **Active Probing**: Sends various probes (HTTP requests, etc.) if no banner received
4. **Pattern Matching**: Matches banner against known service patterns
5. **Service Identification**: Returns identified service or defaults to common port mapping

## Service Detection Patterns

The scanner uses regex patterns to identify services:
- **HTTP**: Looks for HTTP/, DOCTYPE, Server headers
- **FTP**: Looks for 220 response, FTP server names
- **SSH**: Looks for SSH- protocol identifier
- **SMTP**: Looks for 220 response, SMTP/ESMTP identifiers
- **MySQL**: Looks for mysql/MariaDB identifiers
- And many more...

## Performance Tips

- Adjust thread count based on your system (`-t` option)
- Reduce timeout for faster scans on reliable networks (`--timeout`)
- Scan common ports first to get quick results (`--common`)
- Use smaller port ranges for faster results

## Limitations

- Service detection is based on banners and may not always be accurate
- Some services may not respond to probes
- Firewall rules may block banner grabbing
- IDS/IPS systems may detect scanning activity

## Security Notes

**WARNING**: Port scanning without permission is illegal in many jurisdictions.

Only use this tool on:
- Systems you own
- Networks you have explicit permission to test
- Authorized penetration testing engagements
- Educational lab environments

## Requirements

- Python 3.x
- No external dependencies (uses standard library)

## Legal Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized port scanning may be illegal. Always obtain proper authorization before scanning any network or system you do not own.

## Author

Created as part of the 100 Red Team Projects collection.

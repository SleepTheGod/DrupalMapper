# DrupalMapper

> Advanced Drupal Attack Surface Mapper  
> Made By Taylor Christian Newsome

---

## Overview

**DrupalMapper** is a high-performance reconnaissance and enumeration tool built to map the full exposed attack surface of Drupal applications.

It aggressively discovers:
- Sensitive endpoints
- Misconfigured routes
- Exposed administrative interfaces
- Weak access controls
- Hidden or undocumented paths

Designed for **red team operators, bug bounty hunters, and security researchers**, DrupalMapper focuses on speed, coverage, and actionable results.

---

## Core Capabilities

- ⚡ Multithreaded scanning engine
- 🧠 Dynamic endpoint expansion (users, nodes, entities, fields, REST)
- 🔍 Deep Drupal route enumeration
- 🚪 Access control classification:
  - 200 OK → exposed
  - 401/403 → protected (still valuable)
  - 301/302 → redirects
- 🛡️ Security header inspection
- 📂 Directory listing detection
- 🧩 Massive curated endpoint dataset

---

## Why This Tool Exists

Drupal environments often expose far more than intended due to:
- Misconfigured permissions
- Forgotten endpoints
- Legacy modules
- REST/API exposure
- Improper access controls

**DrupalMapper systematically surfaces those weaknesses at scale.**

---

## Installation

```bash
git clone https://github.com/SleepTheGod/DrupalMapper.git
cd DrupalMapper
pip3 install -r requirements.txt
```

---

## Usage

### Basic Scan
```bash
python3 main.py https://target.com
```

### Advanced Scan
```bash
python3 main.py https://target.com -t 100 --timeout 10
```

---

## CLI Options

| Option | Description |
|--------|-------------|
| target | Target URL |
| -t, --threads | Concurrent threads (default: 30) |
| --timeout | Request timeout in seconds (default: 5) |
| -h, --help | Show help menu |

---

## Example Output

```
[SCAN] Target: https://example.com

[HEADERS]
[+] X-Frame-Options
[-] Content-Security-Policy
[+] Strict-Transport-Security

[DIRECTORY LISTING]
[+] Disabled

[INFO] Total paths: 1400+

[+] 200 OK        → https://example.com/admin
[!] 403 PROTECTED → https://example.com/user/1/edit
[~] REDIRECT      → https://example.com/login
```

---

## Operational Use Cases

- Red Team Recon
- Bug Bounty Enumeration
- Security Research
- Misconfiguration Auditing
- Attack Surface Mapping

---

## Design Philosophy

- Speed over noise
- Coverage over assumptions
- Enumeration first, exploitation later
- Expose everything worth investigating

---

## Disclaimer

This tool is provided for **authorized security testing and research only**.

You are responsible for ensuring you have explicit permission before scanning any system.

Unauthorized use may violate laws and regulations.

---

## Author

Taylor Christian Newsome

---

## Final Note

If you're only scanning /admin and /user/login, you're missing the real attack surface.

DrupalMapper doesn’t.

# Console Bugs

> A comprehensive PowerShell security scanner for Windows environments. Automates vulnerability detection, system hardening, and security auditing — all from a single script.

---

## Overview

Console Bugs is a powerful Windows security assessment tool written in PowerShell. It performs deep system scans to identify misconfigurations, vulnerabilities, and security gaps across your Windows environment.

---

## Features

- 🔍 **System Vulnerability Scanning** — Detects known Windows security weaknesses
- 🛡️ **Hardening Checks** — Identifies missing security configurations and best practices
- 📊 **Audit Reporting** — Generates detailed security audit reports
- ⚡ **One-Command Execution** — Single PowerShell script, no dependencies
- 🔐 **Privilege Escalation Detection** — Checks for potential privilege escalation paths
- 🖥️ **Windows-Specific** — Optimized for Windows Server and Desktop environments

---

## Quick Start

### Prerequisites
- Windows PowerShell 5.1+ or PowerShell 7+
- Administrator privileges recommended

### Run

```powershell
# Run the scanner
.\security-scanner.ps1

# Or with execution policy bypass
powershell -ExecutionPolicy Bypass -File .\security-scanner.ps1
```

---

## What It Checks

- 🔓 Open ports and services
- 👤 User account vulnerabilities
- 🛡️ Windows Defender / antivirus status
- 🔐 Registry security settings
- 📁 File permission issues
- 🌐 Network configuration weaknesses
- 🔄 Pending security updates
- 📝 Event log analysis

---

## Output

The script outputs:
- Color-coded console results (pass/warn/fail)
- Detailed findings for each security check
- Remediation recommendations
- Summary score

---

## Use Cases

- **Security Auditors** — Quick Windows environment assessment
- **Sysadmins** — Automated hardening validation
- **Pen-testers** — Initial reconnaissance and vulnerability identification
- **DevOps** — CI/CD security gate for Windows build agents

---

## Example

```powershell
PS C:\> .\security-scanner.ps1

[+] Scanning Windows Security Configuration...
[✓] Windows Defender: Running
[✗] Firewall: Inbound rules too permissive
[!] SMBv1: Enabled (vulnerable)
[✓] UAC: Enabled
...

Scan Complete — Score: 72/100 (Needs Improvement)
```

---

## License

MIT

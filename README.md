# Console Bugs — Web Security Auditor v2.0

> **A comprehensive 14-phase whitehat vulnerability scanner for web applications. PowerShell-based, no dependencies, one-command execution.**

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 🧠 Deep Analysis

Console Bugs is NOT just a simple scanner — it's a **14-phase security audit pipeline** built entirely in PowerShell. Each phase builds on the previous one, creating a comprehensive security posture assessment:

| Phase | Module | What It Checks |
|-------|--------|----------------|
| 1 | **DNS Recon** | DNS records, IP resolution, ping reachability, HTTP→HTTPS redirect |
| 2 | **SSL/TLS** | Certificate expiry, issuer validation, SSL connection health |
| 3 | **Security Headers** | HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie flags (HttpOnly/Secure/SameSite) |
| 4 | **Attack Surface** | Server header disclosure, X-Powered-By, technology fingerprinting |
| 5 | **Port Scan** | Common ports (22, 80, 443, 3306, 3389, 8080, 8443) via async TCP |
| 6 | **Injection Testing** | SQLi, XSS, command injection payload reflection checks |
| 7 | **CORS Audit** | CORS headers, origin reflection, wildcard origins |
| 8 | **Info Leakage** | Directory listing, backup files, .git exposure, debug endpoints |
| 9 | **Tech Fingerprinting** | Server headers, cookie patterns, response signatures |
| 10 | **Email Discovery** | Common email pattern detection in page content |
| 11 | **HTTP Methods** | OPTIONS, PUT, DELETE, TRACE, CONNECT, PATCH method audit |
| 12 | **DNS Records** | MX, SPF, DMARC, DKIM, NS, TXT record enumeration |
| 13 | **Clickjacking** | X-Frame-Options validation, framebreaker detection |
| 14 | **Open Redirect** | Open redirect vulnerability detection |

---

## ⚡ One Command

```powershell
.\security-scanner.ps1 -Url "https://example.com"
```

No modules to install. No dependencies. Just run.

---

## 📊 Scoring System

Each check is scored as:
- **PASS** ✅ — Secure configuration
- **WARN** ⚠️ — Security improvement available
- **FAIL** ❌ — Vulnerability detected
- **INFO** ℹ️ — Informational only

At the end, a summary score (X/100) and remediation guide is generated.

---

## 🔧 Full Parameters

```powershell
.\security-scanner.ps1 -Url "https://example.com" [-PortScan] [-MethodsScan]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Url` | String (Required) | — | Target URL to scan |
| `-PortScan` | Switch | `$true` | Enable/disable port scanning phase |
| `-MethodsScan` | Switch | `$true` | Enable/disable HTTP methods audit |

---

## 📋 Example Output

```
    +------------------------------------------+
    |   WEB SECURITY AUDITOR v2.0              |
    |   Ultra Whitehat Vulnerability Scanner    |
    +------------------------------------------+

 Target : https://example.com
 Started: 2026-07-04 12:00:00

═══════════════════════════════════════════════════
 PHASE 1 - DNS & Network Reconnaissance
═══════════════════════════════════════════════════
 [PASS] DNS Resolution                        1 records: 93.184.216.34
 [INFO] Reachability (Ping)                   ICMP blocked (common)
 [PASS] HTTP->HTTPS Redirect                  Redirects (301)
...
```

---

## 💡 Use Cases

- **🔍 Bug Bounty Recon** — Initial target assessment
- **🛡️ Security Audits** — Compliance and hardening checks
- **⚡ CI/CD Pipeline** — Security gate for deployments
- **📝 Penetration Testing** — Automated information gathering

---

## ⚠️ Legal

For authorized security testing only. Unauthorized use may be illegal.

---

## 📄 License

MIT

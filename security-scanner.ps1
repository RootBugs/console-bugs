<#
.SYNOPSIS
    Web Security Auditor v2.0 - Whitehat Vulnerability Scanner
.DESCRIPTION
    14-phase security scanner: DNS recon, SSL, headers, attack surface,
    port scan, injection, CORS, info leakage, tech fingerprinting,
    email discovery, HTTP methods, DNS records, clickjacking, open redirect.
.PARAMETER Url
    Target URL (e.g. https://example.com)
.PARAMETER PortScan
    Run port scan (default: $true)
.PARAMETER MethodsScan
    Run HTTP methods audit (default: $true)
.EXAMPLE
    .\security-scanner.ps1 -Url "https://example.com"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Url,
    [switch]$PortScan = $true,
    [switch]$MethodsScan = $true
)

$script:Results = @()
$script:StartTime = Get-Date

function Write-Banner {
    Clear-Host
    Write-Host @"

    +------------------------------------------+
    |   WEB SECURITY AUDITOR v2.0              |
    |   Ultra Whitehat Vulnerability Scanner    |
    +------------------------------------------+

"@ -ForegroundColor Cyan
    Write-Host " Target : " -ForegroundColor White -NoNewline
    Write-Host "$Url" -ForegroundColor Yellow
    Write-Host " Started: " -ForegroundColor White -NoNewline
    Write-Host "$($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
    Write-Host ("-" * 55) -ForegroundColor DarkGray
}

function Write-Status {
    param([string]$Check, [string]$Status, [string]$Detail)
    $icon = switch($Status){"PASS"{"[PASS]"}"WARN"{"[WARN]"}"FAIL"{"[FAIL]"}"INFO"{"[INFO]"}default{"[----]"}}
    $color = switch($Status){"PASS"{"Green"}"WARN"{"Yellow"}"FAIL"{"Red"}"INFO"{"Cyan"}default{"Gray"}}
    Write-Host (" $icon ") -NoNewline -ForegroundColor $color
    Write-Host ("{0,-40} " -f $Check) -NoNewline -ForegroundColor White
    if ($Detail) { Write-Host $Detail -ForegroundColor $color } else { Write-Host "" }
}

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail, [string]$Recommendation)
    $script:Results += @{Check=$Check; Status=$Status; Detail=$Detail; Recommendation=$Recommendation}
}

function Test-PortOpen {
    param([string]$Hostname, [int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(3))) {
            $tcp.EndConnect($async) | Out-Null; $tcp.Close(); return $true
        }
        $tcp.Close(); return $false
    } catch { return $false }
}

function Test-HttpMethod {
    param([string]$Url, [string]$Method)
    try {
        $req = [System.Net.WebRequest]::Create($Url)
        $req.Method = $Method; $req.Timeout = 8000
        $req.UserAgent = "WebSecurityAuditor/2.0"
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        if ($code -in @(200,201,204,301,302,307,308,405,403,401)) {
            return $code
        }
        return $null
    } catch {
        if ($_.Exception.InnerException -and $_.Exception.InnerException.Response) {
            $r = $_.Exception.InnerException.Response
            return [int]$r.StatusCode
        }
        return $null
    }
}

# --- Phase 0: Validate URL ---
Write-Banner
if ($Url -notmatch '^https?://') { $Url = "https://$Url" }
try { $uri = [System.Uri]$Url; $Domain = $uri.Host } catch {
    Write-Host "`n [FAIL] Invalid URL" -ForegroundColor Red; exit 1
}
Write-Host " Resolved Host: " -ForegroundColor White -NoNewline
Write-Host "$Domain" -ForegroundColor Yellow
Write-Host ""; $base = if ($Url.EndsWith("/")) { $Url.TrimEnd("/") } else { $Url }

# ==========================================================================
# PHASE 1 - DNS & Network Reconnaissance
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 1 - DNS & Network Reconnaissance" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $ips = [System.Net.Dns]::GetHostAddresses($Domain) | % { $_.IPAddressToString }
    $ipList = $ips -join ","
    Write-Status -Check "DNS Resolution" -Status $(if($ips.Count -gt 1){"INFO"}else{"PASS"}) -Detail "$($ips.Count) records: $ipList"
    Add-Result -Check "DNS Resolution" -Status $(if($ips.Count -gt 1){"INFO"}else{"PASS"}) -Detail "$($ips.Count) records: $ipList"
} catch {
    Write-Status -Check "DNS Resolution" -Status "FAIL" -Detail "Could not resolve"
    Add-Result -Check "DNS Resolution" -Status "FAIL" -Detail "Could not resolve" -Recommendation "Check if domain exists"
}
try {
    $ping = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send($Domain, 5000)
    if ($reply.Status -eq "Success") {
        Write-Status -Check "Reachability" -Status "PASS" -Detail "$($reply.RoundtripTime)ms"
        Add-Result -Check "Reachability (Ping)" -Status "PASS" -Detail "$($reply.RoundtripTime)ms"
    } else {
        Write-Status -Check "Reachability" -Status "WARN" -Detail "Host unreachable"
        Add-Result -Check "Reachability (Ping)" -Status "WARN" -Detail "Unreachable"
    }
} catch {
    Write-Status -Check "Reachability" -Status "INFO" -Detail "ICMP blocked (common)"
    Add-Result -Check "Reachability (Ping)" -Status "INFO" -Detail "ICMP blocked"
}
try {
    $hu = $Url -replace '^https://', 'http://'
    $hr = [System.Net.WebRequest]::Create($hu); $hr.AllowAutoRedirect = $false; $hr.Timeout = 10000
    $hs = $hr.GetResponse(); $sc = [int]$hs.StatusCode; $hs.Close()
    if ($sc -in @(301,302,307,308)) {
        Write-Status -Check "HTTP->HTTPS" -Status "PASS" -Detail "Redirects ($sc)"
        Add-Result -Check "HTTP->HTTPS Redirect" -Status "PASS" -Detail "Redirects (HTTP $sc)"
    } else {
        Write-Status -Check "HTTP->HTTPS" -Status "FAIL" -Detail "No redirect ($sc)"
        Add-Result -Check "HTTP->HTTPS Redirect" -Status "FAIL" -Detail "No redirect" -Recommendation "Set up 301 HTTPS redirect"
    }
} catch {
    Write-Status -Check "HTTP->HTTPS" -Status "INFO" -Detail "HTTP unavailable (good)"
    Add-Result -Check "HTTP->HTTPS Redirect" -Status "INFO" -Detail "HTTP unavailable"
}
Write-Host ""

# ==========================================================================
# PHASE 2 - SSL/TLS Certificate
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 2 - SSL / TLS Certificate" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $tc = New-Object System.Net.Sockets.TcpClient; $tc.Connect($Domain,443)
    $ss = New-Object System.Net.Security.SslStream($tc.GetStream(),$false,{$true})
    $ss.AuthenticateAsClient($Domain)
    $c2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ss.RemoteCertificate
    $days = ($c2.NotAfter - (Get-Date)).Days
    if ($days -lt 0) {
        Write-Status -Check "Certificate Expiry" -Status "FAIL" -Detail "EXPIRED $($c2.NotAfter.ToString('yyyy-MM-dd'))"
        Add-Result -Check "Certificate Expiry" -Status "FAIL" -Detail "EXPIRED" -Recommendation "Renew immediately"
    } elseif ($days -lt 30) {
        Write-Status -Check "Certificate Expiry" -Status "WARN" -Detail "$days days left"
        Add-Result -Check "Certificate Expiry" -Status "WARN" -Detail "$days days" -Recommendation "Renew within 30 days"
    } else {
        Write-Status -Check "Certificate Expiry" -Status "PASS" -Detail "$days days remaining"
        Add-Result -Check "Certificate Expiry" -Status "PASS" -Detail "$days days"
    }
    Write-Status -Check "Issuer" -Status "INFO" -Detail $c2.Issuer
    Add-Result -Check "Certificate Issuer" -Status "INFO" -Detail $c2.Issuer
    $ss.Close(); $tc.Close()
} catch {
    Write-Status -Check "SSL/TLS" -Status "FAIL" -Detail "Cannot connect"
    Add-Result -Check "SSL/TLS" -Status "FAIL" -Detail "Cannot connect" -Recommendation "Ensure HTTPS configured"
}
Write-Host ""

# ==========================================================================
# PHASE 3 - Security Headers
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 3 - Security Headers" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $req = [System.Net.WebRequest]::Create($Url); $req.Timeout = 15000
    $req.UserAgent = "Mozilla/5.0 WebSecurityAuditor/2.0"
    $req.AllowAutoRedirect = $true; $resp = $req.GetResponse(); $h = $resp.Headers
    $checks = @(
        @{N="Strict-Transport-Security";D="HSTS";S="HIGH"},
        @{N="X-Frame-Options";D="Clickjacking Protection";S="HIGH"},
        @{N="X-Content-Type-Options";D="MIME Sniffing Protection";S="MEDIUM"},
        @{N="Content-Security-Policy";D="CSP";S="HIGH"},
        @{N="X-XSS-Protection";D="Legacy XSS Filter";S="LOW"},
        @{N="Referrer-Policy";D="Referrer Protection";S="MEDIUM"},
        @{N="Permissions-Policy";D="Feature Permissions";S="MEDIUM"}
    )
    foreach ($c in $checks) {
        $val = $h[$c.N]
        if ($val) {
            Write-Status -Check $c.D -Status "PASS" -Detail "$($c.N): $val"
            Add-Result -Check $c.N -Status "PASS" -Detail $val
        } else {
            $w = if ($c.S -eq "HIGH"){"FAIL"}else{"WARN"}
            Write-Status -Check $c.D -Status $w -Detail "MISSING: $($c.N)"
            Add-Result -Check $c.N -Status $w -Detail "Header not set" -Recommendation "Add $($c.N) header"
        }
    }
    $srv = $h["Server"]
    if ($srv) {
        Write-Status -Check "Server Disclosure" -Status "WARN" -Detail "$srv"
        Add-Result -Check "Server Header" -Status "WARN" -Detail "$srv" -Recommendation "Remove/obfuscate Server header"
    } else {
        Write-Status -Check "Server Disclosure" -Status "PASS" -Detail "Hidden"
        Add-Result -Check "Server Header" -Status "PASS" -Detail "Not disclosed"
    }
    $pwr = $h["X-Powered-By"]
    if ($pwr) {
        Write-Status -Check "X-Powered-By" -Status "WARN" -Detail "$pwr"
        Add-Result -Check "X-Powered-By" -Status "WARN" -Detail "$pwr" -Recommendation "Remove this header"
    }
    $ck = $h["Set-Cookie"]
    if ($ck) {
        $issues = @()
        if ($ck -notmatch "HttpOnly"){$issues+="No HttpOnly"}
        if ($ck -notmatch "Secure"){$issues+="No Secure"}
        if ($ck -notmatch "SameSite"){$issues+="No SameSite"}
        if ($issues.Count -gt 0) {
            Write-Status -Check "Cookie Security" -Status "WARN" -Detail "$($issues -join ', ')"
            Add-Result -Check "Cookie Security" -Status "WARN" -Detail "$($issues -join ', ')" -Recommendation "Add HttpOnly, Secure, SameSite flags"
        } else {
            Write-Status -Check "Cookie Security" -Status "PASS" -Detail "All flags present"
            Add-Result -Check "Cookie Security" -Status "PASS" -Detail "Flags OK"
        }
    }
    $resp.Close()
} catch {
    Write-Status -Check "HTTP Request" -Status "FAIL" -Detail "Could not fetch: $_"
    Add-Result -Check "HTTP Request" -Status "FAIL" -Detail "Fetch failed" -Recommendation "Verify URL reachable"
}
Write-Host ""

# ==========================================================================
# PHASE 4 - Attack Surface Scan (Sensitive Paths)
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 4 - Attack Surface (35+ Paths)" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

$paths = @(
    "/.git/config","/.git/HEAD","/.env","/.env.local","/.env.production",
    "/.htaccess","/.htpasswd","/admin","/administrator","/backup",
    "/wp-admin","/wp-config.php","/config","/config.php",
    "/phpinfo.php","/info.php","/robots.txt","/sitemap.xml",
    "/api","/api/v1","/graphql","/swagger","/swagger-ui/",
    "/.well-known/security.txt","/.well-known/",
    "/crossdomain.xml","/package.json","/server-status",
    "/debug","/test","/database","/dump","/cgi-bin/",
    "/shell","/cmd","/exec","/eval","/console",
    "/aws","/s3","/storage","/files","/uploads",
    "/web.config","/.DS_Store","/parameters"
)
$found = @()
foreach ($p in $paths) {
    try {
        $pr = [System.Net.WebRequest]::Create("$base$p"); $pr.Timeout = 8000; $pr.AllowAutoRedirect = $false
        $ps = $pr.GetResponse(); $sc = [int]$ps.StatusCode; $ps.Close()
        $sev = "INFO"
        if ($sc -eq 200 -or $sc -eq 204) { $sev = "FAIL" }
        elseif ($sc -in @(301,302,307,308,401,403,500,501)) { $sev = "WARN" }
        if ($sev -ne "INFO") { $found += [PSCustomObject]@{P=$p;C=$sc;S=$sev} }
    } catch {}
}
if ($found.Count -gt 0) {
    Write-Host "  Found $($found.Count) exposed paths:" -ForegroundColor Yellow
    foreach ($r in $found) {
        $co = if ($r.S -eq "FAIL"){"Red"}else{"Yellow"}
        Write-Host ("    [x] {0,-50} -> HTTP {1}" -f $r.P, $r.C) -ForegroundColor $co
        Add-Result -Check "Path: $($r.P)" -Status $r.S -Detail "HTTP $($r.C)" -Recommendation $(if($r.S -eq "FAIL"){"Restrict immediately"}else{"Review access control"})
    }
} else {
    Write-Status -Check "Sensitive Paths" -Status "PASS" -Detail "No exposures found"
    Add-Result -Check "Sensitive Paths" -Status "PASS" -Detail "35+ paths checked, none exposed"
}
Write-Host ""

# ==========================================================================
# PHASE 5 - Port Scan
# ==========================================================================
if ($PortScan) {
    Write-Host ("="*55) -ForegroundColor DarkGray
    Write-Host " PHASE 5 - Port Scan (21 Ports)" -ForegroundColor Magenta
    Write-Host ("="*55) -ForegroundColor DarkGray
    $ports = @(21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443,27017)
    $open = @(); $i = 0
    foreach ($pt in $ports) {
        $i++; Write-Progress -Activity "Port Scan $Domain" -Status "$i of $($ports.Count)" -PercentComplete (($i/$ports.Count)*100)
        if (Test-PortOpen -Hostname $Domain -Port $pt) {
            $svc = switch($pt){21{"FTP"}22{"SSH"}23{"Telnet"}25{"SMTP"}53{"DNS"}80{"HTTP"}110{"POP3"}143{"IMAP"}443{"HTTPS"}445{"SMB"}993{"IMAPS"}995{"POP3S"}1433{"MSSQL"}1521{"Oracle"}3306{"MySQL"}3389{"RDP"}5432{"PG"}5900{"VNC"}8080{"HTTP-Alt"}8443{"HTTPS-Alt"}27017{"MongoDB"}default{"?"}}
            $open += [PSCustomObject]@{Port=$pt;Service=$svc}
        }
    }
    Write-Progress -Activity "Port Scan $Domain" -Completed
    if ($open.Count -gt 0) {
        Write-Host "  Open ports:" -ForegroundColor Yellow
        foreach ($o in $open) {
            $sev = if ($o.Port -in @(21,23,445,3389,5900,3306,5432,27017)){"WARN"}else{"INFO"}
            Write-Host ("    Port {0,-5} -> {1}" -f $o.Port, $o.Service) -ForegroundColor $(if($sev -eq "WARN"){"Red"}else{"Yellow"})
            Add-Result -Check "Port $($o.Port)/$($o.Service)" -Status $sev -Detail "Open" -Recommendation $(if($sev -eq "WARN"){"Close if not needed"})
        }
    } else {
        Write-Status -Check "Port Scan" -Status "PASS" -Detail "No unexpected open ports"
        Add-Result -Check "Port Scan" -Status "PASS" -Detail "Clean"
    }
    Write-Host ""
}

# ==========================================================================
# PHASE 6 - Injection Reflection Check
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 6 - Injection Reflection" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

$payloads = @(
    @{N="XSS Basic";P="<script>alert(1)</script>"},
    @{N="XSS Img";P="<img src=x onerror=alert(1)>"},
    @{N="XSS Svg";P="<svg onload=alert(1)>"},
    @{N="SQLi Basic";P="' OR '1'='1"},
    @{N="SQLi Union";P="' UNION SELECT 1--"},
    @{N="XSS Polyglot";P="'';!--""<XSS>=&{()}"},
    @{N="Template Inject";P="{{7*7}}"}
)
$foundRef = $false
foreach ($pl in $payloads) {
    try {
        $tu = "$base`?q=$([System.Net.WebUtility]::UrlEncode($pl.P))"
        $tr = [System.Net.WebRequest]::Create($tu); $tr.Timeout = 10000; $tr.UserAgent = "WebSecAuditor/2.0"
        $ts = $tr.GetResponse()
        $rd = New-Object System.IO.StreamReader($ts.GetResponseStream())
        $body = $rd.ReadToEnd(); $rd.Close(); $ts.Close()
        $matchLen = [Math]::Min(20, $pl.P.Length)
        $match = $body -match [regex]::Escape($pl.P.Substring(0, $matchLen))
        if ($match) {
            $foundRef = $true
            Write-Status -Check $pl.N -Status "FAIL" -Detail "Payload reflected!"
            Add-Result -Check "$($pl.N) Reflection" -Status "FAIL" -Detail "Reflected" -Recommendation "Implement output encoding / prepared statements"
        } else {
            Write-Status -Check $pl.N -Status "PASS" -Detail "No reflection"
            Add-Result -Check "$($pl.N) Reflection" -Status "PASS" -Detail "No reflection"
        }
    } catch {
        Write-Status -Check $pl.N -Status "INFO" -Detail "Could not test"
        Add-Result -Check "$($pl.N) Reflection" -Status "INFO" -Detail "Test failed"
    }
}
if (-not $foundRef) { Write-Host "  [OK] No injection reflections found" -ForegroundColor Green }
Write-Host ""

# ==========================================================================
# PHASE 7 - CORS Check
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 7 - CORS Configuration" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $cr = [System.Net.WebRequest]::Create($Url); $cr.Timeout = 10000
    $cr.UserAgent = "WebSecAuditor/2.0"; $cr.Headers.Add("Origin","https://evil.com")
    $cp = $cr.GetResponse(); $ch = $cp.Headers["Access-Control-Allow-Origin"]; $cp.Close()
    if ($ch) {
        if ($ch -eq "*") {
            Write-Status -Check "CORS" -Status "FAIL" -Detail "Wildcard '*' allowed"
            Add-Result -Check "CORS" -Status "FAIL" -Detail "Wildcard '*' allowed" -Recommendation "Restrict to specific origins"
        } elseif ($ch -eq "https://evil.com") {
            Write-Status -Check "CORS" -Status "FAIL" -Detail "Reflects any origin"
            Add-Result -Check "CORS" -Status "FAIL" -Detail "Reflects Origin header" -Recommendation "Whitelist specific origins"
        } else {
            Write-Status -Check "CORS" -Status "INFO" -Detail "Restricted: $ch"
            Add-Result -Check "CORS" -Status "INFO" -Detail "Restricted to: $ch"
        }
    } else {
        Write-Status -Check "CORS" -Status "PASS" -Detail "No permissive header"
        Add-Result -Check "CORS" -Status "PASS" -Detail "Not permissive"
    }
} catch {
    Write-Status -Check "CORS" -Status "INFO" -Detail "Could not determine"
    Add-Result -Check "CORS" -Status "INFO" -Detail "Could not determine"
}
Write-Host ""

# ==========================================================================
# PHASE 8 - Information Leakage
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 8 - Information Leakage" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $rr = [System.Net.WebRequest]::Create("$base/robots.txt"); $rr.Timeout = 8000
    $rs = $rr.GetResponse(); $rdr = New-Object System.IO.StreamReader($rs.GetResponseStream())
    $rc = $rdr.ReadToEnd(); $rdr.Close(); $rs.Close()
    $dis = [regex]::Matches($rc,'Disallow:\s*(/\S*)') | %{$_.Groups[1].Value}
    if ($dis.Count -gt 0) {
        Write-Status -Check "robots.txt" -Status "WARN" -Detail "$($dis.Count) disallowed"
        Add-Result -Check "robots.txt" -Status "WARN" -Detail "$($dis.Count) paths" -Recommendation "Check disallowed paths"
        foreach ($d in $dis) { Write-Host ("      $d") -ForegroundColor Gray }
    } else {
        Write-Status -Check "robots.txt" -Status "INFO" -Detail "No disallows"
        Add-Result -Check "robots.txt" -Status "INFO" -Detail "Found but no disallows"
    }
} catch {
    Write-Status -Check "robots.txt" -Status "INFO" -Detail "Not found"
    Add-Result -Check "robots.txt" -Status "INFO" -Detail "Not found"
}
try {
    $wr = [System.Net.WebRequest]::Create("$base/.well-known/security.txt"); $wr.Timeout = 8000
    $ws = $wr.GetResponse()
    if ($ws.StatusCode -eq 200) {
        Write-Status -Check "security.txt" -Status "PASS" -Detail "Found!"
        Add-Result -Check "security.txt" -Status "PASS" -Detail "Found - good security practice!"
    }
    $ws.Close()
} catch {
    Write-Status -Check "security.txt" -Status "INFO" -Detail "Not found (recommended)"
    Add-Result -Check "security.txt" -Status "INFO" -Detail "Not found" -Recommendation "Add /.well-known/security.txt"
}
Write-Host ""

# ==========================================================================
# PHASE 9 - Technology Fingerprinting (NEW)
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 9 - Technology Fingerprinting [NEW]" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $tr = [System.Net.WebRequest]::Create($Url); $tr.Timeout = 15000
    $tr.UserAgent = "Mozilla/5.0 WebSecAuditor/2.0"
    $ts = $tr.GetResponse(); $th = $ts.Headers
    $tdr = New-Object System.IO.StreamReader($ts.GetResponseStream())
    $tBody = $tdr.ReadToEnd(); $tdr.Close(); $ts.Close()

    $foundTech = @()
    # Check server header
    if ($th["Server"]) {
        $foundTech += "Server: $($th["Server"])"
        Add-Result -Check "Tech: Server" -Status "INFO" -Detail "$($th["Server"])"
    }
    # Check Set-Cookie patterns for frameworks
    $cks = $th["Set-Cookie"]
    if ($cks) {
        if ($cks -match "PHPSESSID") { $foundTech += "PHP"; Add-Result -Check "Tech: PHP" -Status "INFO" -Detail "PHPSESSID cookie" }
        if ($cks -match "JSESSIONID") { $foundTech += "Java/J2EE"; Add-Result -Check "Tech: Java" -Status "INFO" -Detail "JSESSIONID cookie" }
        if ($cks -match "ASP\.NET_SessionId") { $foundTech += "ASP.NET"; Add-Result -Check "Tech: ASP.NET" -Status "INFO" -Detail "ASP.NET_SessionId cookie" }
        if ($cks -match "laravel_session") { $foundTech += "Laravel"; Add-Result -Check "Tech: Laravel" -Status "INFO" -Detail "laravel_session cookie" }
        if ($cks -match "symfony") { $foundTech += "Symfony"; Add-Result -Check "Tech: Symfony" -Status "INFO" -Detail "Symfony cookie" }
        if ($cks -match "rails") { $foundTech += "Rails"; Add-Result -Check "Tech: Rails" -Status "INFO" -Detail "Rails cookie" }
    }
    # Check X-Powered-By
    if ($th["X-Powered-By"]) {
        $foundTech += "X-Powered-By: $($th["X-Powered-By"])"
        Add-Result -Check "Tech: X-Powered-By" -Status "INFO" -Detail "$($th["X-Powered-By"])"
    }
    # Check X-Generator
    if ($th["X-Generator"]) {
        $foundTech += "Generator: $($th["X-Generator"])"
        Add-Result -Check "Tech: Generator" -Status "INFO" -Detail "$($th["X-Generator"])"
    }
    # HTML body analysis
    if ($tBody -match 'wp-content|wp-includes|wp-json') { $foundTech += "WordPress"; Add-Result -Check "Tech: WordPress" -Status "INFO" -Detail "Detected via wp-* patterns" }
    if ($tBody -match 'Joomla|com_content|com_modules') { $foundTech += "Joomla"; Add-Result -Check "Tech: Joomla" -Status "INFO" -Detail "Detected via Joomla patterns" }
    if ($tBody -match 'Drupal|drupal.js|sites/default') { $foundTech += "Drupal"; Add-Result -Check "Tech: Drupal" -Status "INFO" -Detail "Detected via Drupal patterns" }
    if ($tBody -match 'cdn\.cloudflare|cloudflare\.com|__cfduid') { $foundTech += "Cloudflare"; Add-Result -Check "Tech: Cloudflare" -Status "INFO" -Detail "CDN detected" }
    if ($tBody -match 'google-analytics|gtag|googletagmanager') { $foundTech += "Google Analytics"; Add-Result -Check "Tech: Google Analytics" -Status "INFO" -Detail "Analytics detected" }
    if ($tBody -match 'facebook\.com/tr|fbq\(') { $foundTech += "Facebook Pixel"; Add-Result -Check "Tech: Facebook Pixel" -Status "INFO" -Detail "Tracking detected" }
    if ($tBody -match 'react\.js|react\.min\.js|__REACT_DEVTOOLS') { $foundTech += "React"; Add-Result -Check "Tech: React" -Status "INFO" -Detail "Frontend framework" }
    if ($tBody -match 'vue\.js|vue\.min\.js|__VUE_DEVTOOLS') { $foundTech += "Vue.js"; Add-Result -Check "Tech: Vue.js" -Status "INFO" -Detail "Frontend framework" }
    if ($tBody -match 'angular\.js|ng-app|ng-version') { $foundTech += "Angular"; Add-Result -Check "Tech: Angular" -Status "INFO" -Detail "Frontend framework" }
    if ($tBody -match 'jquery') { $foundTech += "jQuery"; Add-Result -Check "Tech: jQuery" -Status "INFO" -Detail "Library detected" }
    if ($tBody -match 'bootstrap') { $foundTech += "Bootstrap"; Add-Result -Check "Tech: Bootstrap" -Status "INFO" -Detail "CSS framework" }
    if ($tBody -match 'Shopify|shopify\.com') { $foundTech += "Shopify"; Add-Result -Check "Tech: Shopify" -Status "INFO" -Detail "E-commerce platform" }
    if ($tBody -match 'Magento|mage\.') { $foundTech += "Magento"; Add-Result -Check "Tech: Magento" -Status "INFO" -Detail "E-commerce platform" }
    if ($tBody -match 'nginx') { $foundTech += "Nginx"; Add-Result -Check "Tech: Nginx" -Status "INFO" -Detail "Web server" }
    if ($tBody -match 'apache|Apache') { $foundTech += "Apache"; Add-Result -Check "Tech: Apache" -Status "INFO" -Detail "Web server" }
    if ($tBody -match 'IIS|Internet Information Services') { $foundTech += "IIS"; Add-Result -Check "Tech: IIS" -Status "INFO" -Detail "Web server" }

    if ($foundTech.Count -gt 0) {
        Write-Host "  Detected technologies:" -ForegroundColor Cyan
        foreach ($ft in $foundTech) { Write-Host ("    > $ft") -ForegroundColor Gray }
    } else {
        Write-Status -Check "Tech Fingerprinting" -Status "INFO" -Detail "No specific technologies detected"
        Add-Result -Check "Tech Fingerprinting" -Status "INFO" -Detail "None detected"
    }
} catch {
    Write-Status -Check "Tech Fingerprinting" -Status "INFO" -Detail "Could not analyze"
    Add-Result -Check "Tech Fingerprinting" -Status "INFO" -Detail "Could not analyze"
}
Write-Host ""

# ==========================================================================
# PHASE 10 - Email & Contact Discovery (NEW)
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 10 - Email & Contact Discovery [NEW]" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $er = [System.Net.WebRequest]::Create($Url); $er.Timeout = 15000
    $er.UserAgent = "Mozilla/5.0 WebSecAuditor/2.0"
    $es = $er.GetResponse(); $edr = New-Object System.IO.StreamReader($es.GetResponseStream())
    $eBody = $edr.ReadToEnd(); $edr.Close(); $es.Close()

    $emails = [regex]::Matches($eBody, '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}') | %{$_.Value} | Sort-Object -Unique
    $filtered = $emails | Where-Object {$_ -notlike '*@example*' -and $_ -notlike '*@domain*' -and $_ -notlike '*@test*'}
    if ($filtered.Count -gt 0) {
        Write-Host "  Found $($filtered.Count) email(s):" -ForegroundColor Yellow
        foreach ($em in $filtered) { Write-Host ("    $em") -ForegroundColor Gray }
        Add-Result -Check "Email Discovery" -Status "WARN" -Detail "$($filtered.Count) email(s) found" -Recommendation "Review if emails should be public"
    } else {
        Write-Status -Check "Email Discovery" -Status "PASS" -Detail "No public emails found"
        Add-Result -Check "Email Discovery" -Status "PASS" -Detail "No emails found"
    }
    # Social links
    $socialPatterns = @(
        @{N="Twitter/X";P="twitter\.com/|x\.com/"},
        @{N="LinkedIn";P="linkedin\.com/"},
        @{N="GitHub";P="github\.com/"},
        @{N="Facebook";P="facebook\.com/"},
        @{N="Instagram";P="instagram\.com/"},
        @{N="YouTube";P="youtube\.com/"}
    )
    $foundSocial = @()
    foreach ($sp in $socialPatterns) {
        if ($eBody -match $sp.P) { $foundSocial += $sp.N }
    }
    if ($foundSocial.Count -gt 0) {
        Write-Host "  Social links: $($foundSocial -join ', ')" -ForegroundColor Gray
    }
} catch {
    Write-Status -Check "Email Discovery" -Status "INFO" -Detail "Could not scan"
    Add-Result -Check "Email Discovery" -Status "INFO" -Detail "Could not scan"
}
Write-Host ""

# ==========================================================================
# PHASE 11 - HTTP Methods Audit (NEW)
# ==========================================================================
if ($MethodsScan) {
    Write-Host ("="*55) -ForegroundColor DarkGray
    Write-Host " PHASE 11 - HTTP Methods Audit [NEW]" -ForegroundColor Magenta
    Write-Host ("="*55) -ForegroundColor DarkGray

    $methods = @("GET","HEAD","POST","PUT","DELETE","OPTIONS","TRACE","CONNECT","PATCH","PURGE")
    $supported = @()
    foreach ($m in $methods) {
        $code = Test-HttpMethod -Url $Url -Method $m
        if ($code -ne $null -and $code -ne 405 -and $code -ne 403 -and $code -ne 501 -and $code -ne 502) {
            $supported += "$m (HTTP $code)"
        }
    }
    if ($supported.Count -gt 0) {
        Write-Host "  Supported methods: $($supported -join ', ')" -ForegroundColor $(if($supported.Count -gt 3){"Yellow"}else{"Gray"})
        foreach ($sm in $supported) {
            $isDangerous = ($sm -match "PUT|DELETE|TRACE|CONNECT|PURGE|PATCH")
            if ($isDangerous) {
                Write-Status -Check "HTTP $sm" -Status "FAIL" -Detail "Dangerous method enabled!"
                Add-Result -Check "HTTP $sm" -Status "FAIL" -Detail "Dangerous HTTP method" -Recommendation "Disable this method on production server"
            } else {
                Add-Result -Check "HTTP $sm" -Status "INFO" -Detail "Standard method"
            }
        }
    } else {
        Write-Status -Check "HTTP Methods" -Status "PASS" -Detail "Only standard methods allowed"
        Add-Result -Check "HTTP Methods" -Status "PASS" -Detail "No dangerous methods detected"
    }
    Write-Host ""
}

# ==========================================================================
# PHASE 12 - DNS Records Check (NEW)
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 12 - DNS Records Check [NEW]" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $dnsHost = [System.Net.Dns]::GetHostEntry($Domain)
    $hasMX = $false; $hasTXT = $false
    # Try resolving MX records via nslookup
    $mxResult = cmd /c "nslookup -type=MX $Domain 2>nul | findstr `"mail exchanger`"" 2>$null
    if ($mxResult) {
        $hasMX = $true
        $mxLines = $mxResult -split "`r`n" | Where-Object { $_ -ne "" }
        Write-Host "  MX records:" -ForegroundColor Cyan
        foreach ($ml in $mxLines) { Write-Host ("    $ml") -ForegroundColor Gray }
        Add-Result -Check "DNS: MX Records" -Status "INFO" -Detail "Mail servers found"
    } else {
        Write-Status -Check "DNS: MX Records" -Status "INFO" -Detail "No MX records (no mail?)"
        Add-Result -Check "DNS: MX Records" -Status "INFO" -Detail "No MX records found"
    }
    # SPF record check
    $spfResult = cmd /c "nslookup -type=TXT $Domain 2>nul | findstr `"v=spf1`"" 2>$null
    if ($spfResult) {
        Write-Status -Check "DNS: SPF Record" -Status "PASS" -Detail "SPF found"
        Add-Result -Check "DNS: SPF Record" -Status "PASS" -Detail "SPF found"
        foreach ($sr in $spfResult) { Write-Host ("    $sr") -ForegroundColor Gray }
    } else {
        Write-Status -Check "DNS: SPF Record" -Status "WARN" -Detail "No SPF record"
        Add-Result -Check "DNS: SPF Record" -Status "WARN" -Detail "No SPF" -Recommendation "Add SPF DNS record to prevent email spoofing"
    }
    # DMARC record check
    $dmarcResult = cmd /c "nslookup -type=TXT _dmarc.$Domain 2>nul | findstr `"v=DMARC1`"" 2>$null
    if ($dmarcResult) {
        Write-Status -Check "DNS: DMARC Record" -Status "PASS" -Detail "DMARC found"
        Add-Result -Check "DNS: DMARC Record" -Status "PASS" -Detail "DMARC found"
        foreach ($dr in $dmarcResult) { Write-Host ("    $dr") -ForegroundColor Gray }
    } else {
        Write-Status -Check "DNS: DMARC Record" -Status "WARN" -Detail "No DMARC record"
        Add-Result -Check "DNS: DMARC Record" -Status "WARN" -Detail "No DMARC" -Recommendation "Add DMARC DNS record for email security"
    }
} catch {
    Write-Status -Check "DNS Records" -Status "INFO" -Detail "Could not query"
    Add-Result -Check "DNS Records" -Status "INFO" -Detail "Could not query DNS"
}
Write-Host ""

# ==========================================================================
# PHASE 13 - Clickjacking Test (NEW)
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 13 - Clickjacking Protection [NEW]" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

try {
    $jr = [System.Net.WebRequest]::Create($Url); $jr.Timeout = 10000
    $jr.UserAgent = "WebSecAuditor/2.0"
    $js = $jr.GetResponse(); $jh = $js.Headers; $js.Close()

    $xfo = $jh["X-Frame-Options"]
    $csp = $jh["Content-Security-Policy"]
    $frameAncestors = $null
    if ($csp -match 'frame-ancestors\s+([^;]+)') { $frameAncestors = $matches[1] }

    if ($xfo) {
        Write-Status -Check "X-Frame-Options" -Status "PASS" -Detail "$xfo"
        Add-Result -Check "Clickjacking: XFO" -Status "PASS" -Detail $xfo
    } else {
        Write-Status -Check "X-Frame-Options" -Status "FAIL" -Detail "MISSING"
        Add-Result -Check "Clickjacking: XFO" -Status "FAIL" -Detail "Missing" -Recommendation "Add X-Frame-Options: DENY or SAMEORIGIN"
    }
    if ($frameAncestors) {
        Write-Status -Check "CSP frame-ancestors" -Status "PASS" -Detail "$frameAncestors"
        Add-Result -Check "Clickjacking: CSP frame-ancestors" -Status "PASS" -Detail $frameAncestors
    } else {
        Write-Status -Check "CSP frame-ancestors" -Status "WARN" -Detail "Not set in CSP"
        Add-Result -Check "Clickjacking: CSP frame-ancestors" -Status $(if(-not $csp){"WARN"}else{"INFO"}) -Detail "Not set" -Recommendation "Add frame-ancestors to CSP"
    }
} catch {
    Write-Status -Check "Clickjacking Test" -Status "INFO" -Detail "Could not check"
    Add-Result -Check "Clickjacking Test" -Status "INFO" -Detail "Could not check"
}
Write-Host ""

# ==========================================================================
# PHASE 14 - Open Redirect Test (NEW)
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " PHASE 14 - Open Redirect Test [NEW]" -ForegroundColor Magenta
Write-Host ("="*55) -ForegroundColor DarkGray

$redirectPayloads = @(
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "//evil.com%2F%2F",
    "/%5cevil.com",
    "//evil.com@good.com"
)
$foundRedirect = $false
foreach ($rp in $redirectPayloads) {
    try {
        $ru = "$base`?redirect=$([System.Net.WebUtility]::UrlEncode($rp))"
        $ru2 = "$base`?url=$([System.Net.WebUtility]::UrlEncode($rp))"
        $ru3 = "$base`?next=$([System.Net.WebUtility]::UrlEncode($rp))"

        foreach ($testUrl in @($ru, $ru2, $ru3)) {
            $rrq = [System.Net.WebRequest]::Create($testUrl); $rrq.Timeout = 8000
            $rrq.AllowAutoRedirect = $false; $rrq.UserAgent = "WebSecAuditor/2.0"
            $rrs = $rrq.GetResponse()
            [int]$rrc = $rrs.StatusCode
            $loc = $rrs.Headers["Location"]
            $rrs.Close()

            if ($rrc -in @(301,302,307,308) -and $loc -match '(evil\.com|//evil)') {
                $foundRedirect = $true
                Write-Status -Check "Open Redirect" -Status "FAIL" -Detail "Redirects to $loc"
                Add-Result -Check "Open Redirect" -Status "FAIL" -Detail "Redirects to $loc" -Recommendation "Do not redirect based on user input; validate redirect targets"
                break
            }
        }
        if ($foundRedirect) { break }
    } catch {}
}
if (-not $foundRedirect) {
    Write-Status -Check "Open Redirect" -Status "PASS" -Detail "No open redirect detected"
    Add-Result -Check "Open Redirect" -Status "PASS" -Detail "No open redirect"
}
Write-Host ""

# ==========================================================================
# SUMMARY
# ==========================================================================
Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " SECURITY AUDIT SUMMARY" -ForegroundColor Cyan
Write-Host ("="*55) -ForegroundColor DarkGray

$total = $script:Results.Count
$failed = ($script:Results | ?{$_.Status -eq "FAIL"}).Count
$warns = ($script:Results | ?{$_.Status -eq "WARN"}).Count
$passed = ($script:Results | ?{$_.Status -eq "PASS"}).Count
$infos = ($script:Results | ?{$_.Status -eq "INFO"}).Count
$elapsed = [math]::Round(((Get-Date)-$script:StartTime).TotalSeconds,1)

Write-Host ""
Write-Host ("  {0,-30} {1}" -f "Total Checks:",$total) -ForegroundColor White
Write-Host ("  {0,-30} " -f "Vulnerabilities (FAIL):") -NoNewline -ForegroundColor White
Write-Host "$failed" -ForegroundColor $(if($failed -gt 0){"Red"}else{"Green"})
Write-Host ("  {0,-30} " -f "Warnings:") -NoNewline -ForegroundColor White
Write-Host "$warns" -ForegroundColor Yellow
Write-Host ("  {0,-30} " -f "Passed:") -NoNewline -ForegroundColor White
Write-Host "$passed" -ForegroundColor Green
Write-Host ("  {0,-30} " -f "Informational:") -NoNewline -ForegroundColor White
Write-Host "$infos" -ForegroundColor Cyan
Write-Host ("  {0,-30} " -f "Scan Duration:") -NoNewline -ForegroundColor White
Write-Host "${elapsed}s" -ForegroundColor Gray
Write-Host ""

if ($failed -gt 0) {
    Write-Host " [FAIL] $failed critical issues found - review above." -ForegroundColor Red
} elseif ($warns -gt 0) {
    Write-Host " [WARN] $warns warnings found - address for better security." -ForegroundColor Yellow
} else {
    Write-Host " [PASS] Good security posture!" -ForegroundColor Green
}

# ==========================================================================
# HTML REPORT
# ==========================================================================
Write-Host ""; Write-Host " Generating HTML report..." -ForegroundColor Cyan
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$sf = $Domain -replace '[^a-zA-Z0-9]', '_'
$rp = Join-Path $PSScriptRoot "report_${sf}_${ts}.html"

$html = @"
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width">
<title>Security Audit Report - $Domain</title>
<style>
body{font-family:'Segoe UI',Tahoma,sans-serif;background:#0d1117;color:#c9d1d9;padding:40px}
.container{max-width:1000px;margin:auto}
h1{color:#58a6ff;font-size:28px}
h2{color:#f0883e;font-size:18px;margin:25px 0 10px;border-bottom:1px solid #30363d;padding-bottom:5px}
.meta{color:#8b949e;font-size:14px;margin-bottom:20px}
.summary{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px 24px;min-width:120px;text-align:center}
.card .num{font-size:32px;font-weight:bold}
.card .label{font-size:13px;color:#8b949e;margin-top:4px}
.critical{color:#f85149}.warning{color:#d29922}.pass{color:#3fb950}.info{color:#58a6ff}
table{width:100%;border-collapse:collapse;margin:10px 0 20px}
th{background:#21262d;color:#8b949e;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;border:1px solid #30363d}
td{padding:10px 12px;border:1px solid #30363d;font-size:14px}
tr:hover{background:#1c2128}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600}
.badge-fail{background:#3d1f1e;color:#f85149;border:1px solid #f85149}
.badge-warn{background:#3d2e00;color:#d29922;border:1px solid #d29922}
.badge-pass{background:#0d3a1e;color:#3fb950;border:1px solid #3fb950}
.badge-info{background:#0d2b45;color:#58a6ff;border:1px solid #58a6ff}
.rec{color:#d29922;font-size:13px;font-style:italic;margin-top:2px}
.footer{margin-top:30px;text-align:center;color:#484f58;font-size:12px}
</style></head><body><div class="container">
<h1>Security Audit Report - v2.0</h1>
<div class="meta">Target: <strong>$Domain</strong> | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Duration: ${elapsed}s | 14 Phases</div>
<div class="summary">
<div class="card"><div class="num critical">$failed</div><div class="label">Vulnerabilities</div></div>
<div class="card"><div class="num warning">$warns</div><div class="label">Warnings</div></div>
<div class="card"><div class="num pass">$passed</div><div class="label">Passed</div></div>
<div class="card"><div class="num info">$infos</div><div class="label">Info</div></div>
<div class="card"><div class="num">$total</div><div class="label">Total Checks</div></div>
</div>
<h2>Detailed Results</h2>
<table><tr><th style="width:100px">Status</th><th style="width:300px">Check</th><th>Detail</th></tr>
"@

foreach ($r in $script:Results) {
    $bc = switch($r.Status){"FAIL"{"badge-fail"}"WARN"{"badge-warn"}"PASS"{"badge-pass"}default{"badge-info"}}
    $ed = ($r.Detail -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
    $er = if($r.Recommendation){"<div class='rec'>[Tip] $($r.Recommendation -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')</div>"}else{""}
    $html += "<tr><td><span class='badge $bc'>$($r.Status)</span></td><td>$($r.Check)</td><td>$ed $er</td></tr>`n"
}

$html += @"
</table>
<div class="footer">Web Security Auditor v2.0 | 14 Phases | Whitehat Tool | For authorized testing only</div>
</div></body></html>
"@

$html | Out-File -FilePath $rp -Encoding utf8
Write-Host " [OK] Report: $rp" -ForegroundColor Green
try { Start-Process $rp } catch { Write-Host " [INFO] Open HTML file in browser." -ForegroundColor Gray }
Write-Host ""; Write-Host ("="*55) -ForegroundColor DarkGray
Write-Host " Scan complete." -ForegroundColor Cyan; Write-Host ("="*55) -ForegroundColor DarkGray
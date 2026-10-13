# Wayfare SOC Lab — SQLi + IDOR Attack Chain with Wazuh Detection

A self-built home lab simulating a full attack-to-detection lifecycle against a deliberately vulnerable travel booking web application, with detection engineering performed in Wazuh SIEM.

Built to practice offensive techniques (web exploitation, chained vulnerabilities) and defensive engineering (log ingestion, custom detection rules, SIEM troubleshooting) in one connected environment, rather than treating them as separate skillsets.

## Lab Architecture

Three VMs on an isolated VMware Workstation host-only network:

| VM | Role |
|---|---|
| **Kali** | Attacker — recon, exploitation, automated tooling |
| **Wazuh Manager** | SIEM — log aggregation, rule engine, dashboard |
| **VictimVM** (Ubuntu 22.04) | Target — hosts the vulnerable web app, runs the Wazuh agent + Sysmon-for-Linux |

```
[ Kali (attacker) ] ---> [ VictimVM: Apache + PHP + MySQL + Wazuh agent + Sysmon ] ---> [ Wazuh Manager: rules + dashboard ]
```

## Target Application: "Wayfare"

A travel booking site purpose-built for this lab — PHP/MySQL backend, login/register, trip browsing, and booking management — styled to resemble a real product rather than an obviously bare-bones test app.

**Stack:** Apache 2.4.52, PHP (mysqli), MySQL 8.0, Ubuntu 22.04

**Schema:**
- `users (id, username, password, email, role)`
- `bookings (id, user_id, destination, travel_date, price, status)`

**Pages:** `index.html`, `login.php`, `register.php`, `dashboard.php`, `booking.php`, `new_booking.php`, `logout.php`

## Vulnerabilities (By Design)

### 1. SQL Injection — Authentication Bypass
`login.php` builds its query via raw string concatenation with no prepared statements:
```php
$query = "SELECT * FROM users WHERE username='$u' AND password='$p'";
```
**Exploit:** `admin' -- -` as username bypasses authentication entirely.

### 2. SQL Injection — Credential Dump (UNION-based)
Same injection point, escalated to exfiltrate every credential in the database through the login page itself:
```
' UNION SELECT 1,(SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a) FROM users),3,4,'user' -- -
```
The dumped `username:password` pairs render directly in the post-login dashboard, since the UNION's second column maps to the session's stored username field.

### 3. IDOR (Insecure Direct Object Reference)
`booking.php?id=X` returns booking records by ID with **no ownership check** against the logged-in session:
```php
$id = $_GET['id'];
$query = "SELECT * FROM bookings WHERE id = $id";
```
A low-privilege, authenticated user can walk sequential IDs to read every other user's booking data — discovered via a legitimate link on their own dashboard, then exploited through simple parameter tampering.

### Chained Attack Path
1. SQL injection → authenticate as any user, or dump all credentials directly
2. Authenticated session → enumerate booking IDs via IDOR → access other users' private data

This mirrors a realistic post-compromise pattern: initial access via injection, lateral data access via broken object-level authorization — no second exploit needed, just a logic flaw.

## Exploitation

**Manual:**
- Auth bypass via `' -- -` comment injection
- UNION-based credential dump via the login form
- IDOR confirmed by walking `booking.php?id=1` through `id=N` as a non-admin user

**Automated:**
```bash
sqlmap -u "http://<target>/login.php" \
  --data="username=test&password=test" \
  --dbms=mysql --batch \
  --dump -T users -D bookingdb
```
sqlmap identified and exploited the same injection point using an **error-based technique** (`CASE WHEN` / `CONVERT(CONCAT(...))`) distinct from the manual UNION-based payload — a useful reminder that automated tools don't always reproduce the same attack path a manual tester finds, and detection needs to account for both.

## Detection Engineering (Wazuh)

### Log Sources Ingested
- **Apache access log** — decoded natively by Wazuh (`web-accesslog`), gives clean `data.url`, `data.srcip`, `data.protocol` fields
- **MySQL general query log** — full raw queries including injection payloads (see troubleshooting below)
- **Sysmon for Linux** — process creation and network connection events, for host-level visibility

### Custom Rules

| Rule ID | Trigger | Level | Purpose |
|---|---|---|---|
| `100500` | Regex match on SQLi patterns in MySQL query log (`UNION (ALL )?SELECT`, `OR '1'='1`, comment injection, `information_schema`, error-based fingerprints) | 10 | Catch SQLi payloads regardless of manual/automated origin |
| `100503` | 10+ matches of rule 100500 from the same source IP within 30s | 12 | Flag high-volume/automated injection attempts |
| `100504` | `sqlmap` string in Apache User-Agent header | 10 | Tool fingerprinting — catches sqlmap's presence before any payload succeeds |

```xml
<group name="lab_attack_chain,">

  <rule id="100500" level="10">
    <location>/var/log/mysql/general.log</location>
    <regex type="pcre2">(?i)UNION(\s+ALL)?\s+SELECT|OR\s+'1'='1|--\s|admin'#|'\s+OR\s+'|information_schema|CASE\s+WHEN|CONVERT\(CONCAT</regex>
    <description>SQL Injection payload detected in MySQL query log</description>
    <group>lab_attack_chain,sqli,</group>
  </rule>

  <rule id="100503" level="12" frequency="10" timeframe="30">
    <if_matched_sid>100500</if_matched_sid>
    <same_source_ip />
    <description>Automated SQL injection tool detected (high-volume SQLi attempts from single source)</description>
    <group>lab_attack_chain,sqli,automated_tool,</group>
  </rule>

  <rule id="100504" level="10">
    <if_sid>31100</if_sid>
    <regex type="pcre2">sqlmap</regex>
    <description>sqlmap tool detected via User-Agent</description>
    <group>lab_attack_chain,sqli,automated_tool,</group>
  </rule>

</group>
```

### Results

Both manual and automated SQLi were independently detected — manual auth bypass and UNION dump matched rule `100500`, and sqlmap's run triggered both `100500` (payload regex, once adjusted) and `100504` (User-Agent fingerprint), confirming two independent detection layers on the same attack.

![SQLi detection firing in Wazuh Security Events](screenshots/sqlmap-detection.png)
*Replace with your own screenshot — see "Adding Your Own Evidence" below.*

## Troubleshooting Log (Real Debugging, Not Just a Happy Path)

A SOC lab is as much about fixing a broken pipeline as it is about the attacks themselves. Notable issues hit and resolved during this build:

- **MySQL general log not persisting** — `SET GLOBAL general_log = 'ON'` doesn't survive a restart; fixed by setting `general_log` and `general_log_file` permanently in `/etc/mysql/mysql.conf.d/mysqld.cnf`.
- **Wazuh agent couldn't read the MySQL log** — required adding the `wazuh` user to the `adm` group and correcting file ownership/permissions on `general.log`.
- **MySQL log silently not ingesting despite correct permissions and no errors** — root cause was the `mysql_log` log format in Wazuh's `ossec.conf`, which expects slow-query-log-style multi-line entries and never flushed anything against MySQL 8's flat general log format. Fixed by switching that `<localfile>` block's `log_format` to `syslog`, which ships raw lines with no format-specific parsing required.
- **SQLi regex missed sqlmap's actual payload** — initial rule matched literal `UNION SELECT`; sqlmap used `UNION ALL SELECT` and a separate error-based technique entirely, neither of which matched. Rewrote the regex to be case-insensitive and technique-agnostic, and added a User-Agent-based rule as a second, payload-independent detection layer.
- **nmap SYN scans invisible to Sysmon** — Sysmon-for-Linux's NetworkConnect events hook at the socket `connect()` level; nmap's default SYN scan (run as root) crafts raw packets and often bypasses this entirely. TCP connect scans (`-sT`) do trigger it reliably. *(Open item — see below.)*

## Current Status / Open Work

- [x] SQL injection (auth bypass + credential dump) — exploited and detected
- [x] IDOR — exploited, **not yet alerting** (no rule written yet)
- [x] Automated tooling detection (sqlmap) — two independent detection layers confirmed
- [ ] IDOR detection rule (frequency-based on sequential booking ID access per session)
- [ ] nmap / port scan detection — Sysmon network events confirmed flowing but still unparsed raw XML; needs a decoder or regex-based rule, and a secondary detection method for SYN scans specifically
- [ ] Wazuh Vulnerability Detection module — native CVE-matching against installed package versions, to automate the "check for CVE" step of the original assessment lifecycle
- [ ] Sysmon XML decoder — currently ingesting as raw unparsed text; a proper decoder would allow field-level rule matching instead of regex-on-blob

## Why This Lab

Built to connect offensive and defensive security practice directly, rather than practicing them in isolation: the same vulnerability chain that's exploited on the attack side is what the detection rules on the SIEM side are built to catch — closing the loop between "can I break this" and "can I see myself breaking it."

---

*Lab built and documented by [your name/handle]. VM architecture, application code, and detection rules are original to this project.*

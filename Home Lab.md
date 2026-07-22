# Wazuh SIEM Home Lab — Build Log & First Detection

**A record of building a detection lab from scratch, breaking it, fixing it, and finally watching a real attack get caught.**

---

## 1. Goal

Build a home SOC lab to learn detection & response work hands-on:
- Stand up a SIEM (Wazuh)
- Monitor a second machine as an "agent"
- Simulate a real attack
- Watch it get detected, end to end

**Environment:**
- Host laptop: 16GB RAM, 4-core CPU, VMware Workstation
- `wazuh-manager` VM — Ubuntu Server 22.04.5 LTS, 4GB RAM, 2 cores, 40GB disk
- `victim` VM — Ubuntu Server 22.04.5 LTS, 2GB RAM, 1-2 cores, 20GB disk
- `kali` VM — attacker machine
- All three VMs: **Bridged networking** (so they behave like real peers on the home network)

---

## 2. What Each Piece Does

| Component | Role |
|---|---|
| **Wazuh indexer** | Stores and indexes all security data |
| **Wazuh manager** | Analyzes incoming logs, runs detection rules, generates alerts |
| **Wazuh dashboard** | Web UI for viewing agents, events, and alerts |
| **Wazuh agent** | Lightweight program on a monitored machine; ships logs back to the manager |
| **Kali (attacker)** | Not monitored — used to generate real attack traffic against the victim |

Key concept: **the manager also monitors itself** by default (registered as agent `000`) — this is normal, not a misconfiguration.

---

## 3. Build Log — What Broke, and Why

This lab did *not* go smoothly on the first attempt, and that was actually the most educational part.

### Attempt 1: Ubuntu 26.04 ("Resolute Raccoon")
- Not on Wazuh 4.9.2's supported OS list
- Hit repeated failures: missing `wazuh-keystore` binary, broken `prerm` uninstall scripts, dpkg lock conflicts with `unattended-upgrades`, LVM only allocating 19GB of a 40GB disk, and a dashboard install failing from disk space exhaustion
- **Lesson:** always check a tool's officially supported OS list before installing — using a bleeding-edge OS version can silently break install/uninstall scripts that assume older system behavior

### Fix: Rebuilt on Ubuntu 22.04.5 LTS
- Officially supported by Wazuh → clean install with **zero errors**, all four components (indexer, manager, filebeat, dashboard) installed successfully in one run

### Other real issues hit and fixed along the way:
- **VM not bridged initially** → fixed via VM Settings → Network Adapter → Bridged
- **dpkg lock held by `unattended-upgrades`** → disabled the service to prevent background updates interrupting installs
- **LVM using only half the virtual disk** → `sudo lvextend -l +100%FREE` + `resize2fs` to reclaim the rest
- **Clock drift (VM clock ~7 hours ahead, NTP blocked by network)** → manually set correct time with `sudo date -s`; NTP couldn't sync (port 123 blocked), so time needs occasional manual correction
- **Dashboard showing "No results match your search criteria" despite data existing** → confirmed via direct OpenSearch queries (`curl .../_search?q=...`) that the data was indexed correctly; root cause was a combination of the clock drift (breaking relative time filters like "Last 24 hours") and a DQL field-type quirk with numeric fields like `rule.id`

**Big lesson from this whole process:** when something looks broken, check each layer independently rather than guessing — raw logs → agent logs → manager alerts.log → OpenSearch index directly via curl → dashboard UI. Each layer can be tested in isolation to narrow down exactly where a pipeline breaks.

---

## 4. Proving the Pipeline Works

Before attempting a real attack, verified the full chain manually:

```
victim generates a log (failed SSH login)
   → agent reads it (via journald)
   → ships to manager over port 1514
   → manager's rule engine matches it against rules
   → alert written to alerts.json
   → Filebeat ships it to the indexer
   → indexed into wazuh-alerts-4.x-<date>
   → visible in the dashboard
```

Confirmed each step independently using:
- `tail -f /var/log/auth.log` (raw OS log)
- `grep -i "agentd" /var/ossec/logs/ossec.log` (agent connection status)
- `sudo /var/ossec/bin/agent_control -l` (manager's view of connected agents)
- `sudo tail -50 /var/ossec/logs/alerts/alerts.log` (manager's generated alerts)
- `curl -k -u admin:<pw> https://127.0.0.1:9200/_cat/indices?v` (indexer's actual index contents)
- Wazuh dashboard, Discover / Threat Hunting views

---

## 5. The Attack — SSH Brute Force with Hydra

**Setup:**
- Attacker: Kali VM
- Target: `victim` VM, SSH service (port 22)
- Tool: Hydra

**Command run from Kali:**
```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<victim-ip>
```

**What happened, in order:**

| Rule ID | Description | Level | Meaning |
|---|---|---|---|
| 5760 | sshd: authentication failed | 5 | A single failed login — normal, low-severity on its own |
| 2502 | syslog: User missed the password | 10 | PAM-level failure classification, already elevated |
| **40111** | **Multiple authentication failures** | **10** | **Correlation rule** — recognized the pattern of many failures from one source in a short window and escalated |

**Key insight:** individual failed logins are *noise* — everyone mistypes a password sometimes. What actually triggered a meaningful alert was the **pattern**: high frequency, single source, short time window. This is the core principle of detection engineering — rules are layered, from raw event logging up to correlation logic that recognizes attacker behavior rather than isolated events.

---

## 6. Concepts Learned

- **Host-based vs. network-based detection**
  Wazuh (as configured) only sees what gets logged by the OS/applications. A port scan (`nmap`) generated *zero* alerts because `sshd` doesn't log connection attempts that never try a password — nothing was written to any log for Wazuh to read. Network-based tools (Wireshark, Suricata, Zeek) would have seen it, since they inspect raw traffic instead of relying on application logs.

- **Firewalls vs. logging — two separate pipelines**
  A firewall controls whether traffic reaches a service at all (network layer). Logging happens *after* traffic is already allowed through, at the application/OS layer. A firewall blocking an attack often means *no log entry at all* — which is why real SOCs correlate both firewall logs and host logs for full visibility.

- **Rule severity levels (rule.level)** as a fast noise-vs-signal filter:
  - 0-3: routine/informational
  - 4-6: worth a glance
  - 7-9: increasingly significant
  - 10+: high severity, often correlation-based

- **Clock accuracy matters** — a drifted system clock can silently break relative time-based queries ("Last 24 hours") even when the underlying data is completely fine. Always sanity-check `date`/`timedatectl` before assuming a dashboard problem is a data problem.

---

## 7. Next Steps / Ideas to Explore

- [ ] Look at rule `40111`'s actual definition/threshold logic
- [ ] Try firewall logging (`ufw logging on`) and re-run an `nmap` scan to see it become visible
- [ ] Write a custom detection rule from scratch
- [ ] Explore File Integrity Monitoring (FIM) — modify a monitored file and watch the alert
- [ ] Set up real-time alerting (email/Slack) instead of manually checking the dashboard
- [ ] Try Suricata or Zeek alongside Wazuh for network-based detection
- [ ] Set a static IP / DHCP reservation for the manager VM so its address stops changing

---

*Built as a hands-on learning project — every error above was a real one hit and solved during setup, kept here as a reference for what "actually happened" versus a clean tutorial.*

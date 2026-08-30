# Wazuh — SSH Brute-Force Detection & Active Response
**Date:** August 30, 2026

## Goal
Get Wazuh to automatically firewall-block an attacking IP after repeated failed SSH logins (tested via Hydra from Kali against the victim VM), with a realistic threshold — not on the very first failed attempt.

---

## Attempt 1 — Active response bound to rule `5760`

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5760</rules_id>
  <timeout>600</timeout>
</active-response>
```

- **Result:** Worked — Hydra's IP got dropped via iptables. Confirmed end-to-end pipeline (agent → manager → active response → firewall-drop) is functional.
- **Problem:** Checked rule `5760`'s definition in `0095-sshd_rules.xml`:
  ```xml
  <rule id="5760" level="5">
    <if_sid>5700,5716</if_sid>
    <match>Failed password|Failed keyboard|authentication error</match>
    <description>sshd: authentication failed.</description>
  </rule>
  ```
  No `frequency` or `timeframe` attribute at all. It fires on the **very first** failed password, from anyone. That means one genuine human typo would trigger a full 10-minute IP block — too aggressive for realistic use.

---

## Attempt 2 — Switch to rule `5720` (the "correct" multi-attempt rule)

```xml
<rule id="5720" level="10" frequency="8">
  <if_matched_sid>5716</if_matched_sid>
  <same_source_ip />
  <description>sshd: Multiple authentication failures.</description>
</rule>
```

This looked like the right rule — `frequency="8"` — but it depends on rule `5716` matching first:
```xml
<rule id="5716" level="5">
  <if_sid>5700</if_sid>
  <match>^Failed|^error: PAM: Authentication</match>
  <description>sshd: authentication failed.</description>
</rule>
```

- **Result:** Rebound active response to `rules_id: 5720`, re-ran Hydra. **Never fired** — not even after 300+ logged failed attempts (confirmed via `grep '"id":"5720"' alerts.json` returning nothing).
- **Root cause, found using `wazuh-logtest`:**
  ```bash
  echo "Aug 30 08:39:01 victim sshd[8147]: Failed password for iron_man from 192.168.100.92 port 39314 ssh2" | /var/ossec/bin/wazuh-logtest
  ```
  Output showed the log line landing directly on rule `5760` — rule `5716` was never even evaluated.

  Why: `5760`'s `if_sid` is `5700,5716` — meaning "matches if parent is 5700 **OR** 5716," not AND. Wazuh's rule engine evaluates and **stops at the first satisfying match**. Since `5760`'s pattern (`Failed password|Failed keyboard|authentication error`) is **unanchored** (matches anywhere in the line) while `5716`'s pattern (`^Failed|^error: PAM...`) is **anchored to the start of the line**, `5760` "wins" the match first for this exact log format. `5716` never independently fires, so `5720` (which depends on `if_matched_sid: 5716`) never gets a chance to count anything.

  Confirmed via alert histogram:
  ```
  sudo grep -o '"id":"57[0-9][0-9]"' /var/ossec/logs/alerts/alerts.json | sort | uniq -c
        1 "id":"5715"
       52 "id":"5758"
      375 "id":"5760"
        2 "id":"5762"
        3 "id":"5763"
  ```
  Zero hits on 5716 or 5720, despite 375 failed logins being logged under 5760.

**Lesson:** Hundreds of failed logins were logged correctly the whole time (5760 fired every time). The reason nothing happened is that **no rule existed yet that was actually counting 5760 toward a threshold** — 5720 was silently unreachable because its prerequisite (5716) was being shadowed. It wasn't a frequency/timeframe bug or a same-source-ip bug — it was a broken dependency chain.

---

## Attempt 3 — Custom local rule (the fix that worked)

Since built-in rule `5716` was unreachable for this log format, built a custom rule directly on top of `5760` (the rule that was actually firing), in `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,syslog,sshd,">
  <rule id="100100" level="10" frequency="8" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>Custom: Multiple SSH authentication failures from same source (8 in 120s).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>
</group>
```

Then repointed active response:
```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>600</timeout>
</active-response>
```

- **Result:** Active response now only fires after **8 failed attempts from the same source IP within a 120-second rolling window** — tolerant of one honest typo, still catches real brute-force speed.
- Verified via `/var/ossec/logs/active-responses.log` on the victim: clean `add` (block) → eventual `delete` (auto-unblock at the 600s timeout mark).

---

## Dashboard observation — why the count looked confusing at first glance

When eyeballing the Threat Hunting event list, many different rule IDs appeared for what was really the same underlying failed logins — because multiple decoders (PAM, generic syslog, sshd-specific) each independently log and alert on the same raw event:

| Rule ID | Description |
|---|---|
| 5760 | sshd: authentication failed |
| 5758 | Maximum authentication attempts |
| 5503 | PAM: User login failed |
| 5551 | PAM: Multiple failed logins in a session |
| 2501/2502 | syslog: generic auth failure / missed password |
| 40111 | Multiple authentication failures |

Only rows tagged **5760** count toward custom rule `100100` — the rest are separate decoders logging the same event and are irrelevant to this specific threshold.

Also, Hydra was run with `-t 4` (4 parallel threads), so `5760` entries arrive in near-simultaneous bursts of ~4 rather than one at a time — making the running count look inconsistent/bursty when scrolling the dashboard live, even though each attempt was still logged and counted individually and correctly under the hood. Running Hydra with `-t 1` would give a cleaner one-at-a-time sequence to visually confirm the exact 8-attempt threshold.

---

## Key Takeaways
1. **Check a rule's `frequency`/`timeframe` before binding active response to it** — some rules (like 5760) fire on the very first match with no threshold at all.
2. **`if_sid` with multiple comma-separated values is an OR, not an AND** — and Wazuh stops at the first matching rule, so a broader/unanchored rule can silently shadow a more specific one that would otherwise fire.
3. **`wazuh-logtest`** is the right tool to trace exactly which rule a raw log line actually lands on — essential for debugging "why isn't my rule firing" issues.
4. **Custom local rules** (`/var/ossec/etc/rules/local_rules.xml`, IDs `100000`–`109999`) are the reliable way to build your own threshold logic on top of whichever rule is actually firing, without depending on built-in chains that may not apply cleanly to your log format.
5. **One raw log line can trigger multiple different rule IDs** across different decoders (PAM, syslog, sshd) — don't assume every visible row in the dashboard counts toward a specific correlation rule's threshold.

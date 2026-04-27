# APT29 / Cozy Bear -- Purple Team Emulation Campaign

**Threat Actor:** APT29 / Cozy Bear / Midnight Blizzard / NOBELIUM (MITRE G0016)  
**Attribution:** Russia Foreign Intelligence Service (SVR)  
**Lab Target:** corp.local -- Dell T320 / Proxmox VE 9.1  
**Framework:** MITRE ATT&CK G0016 | CISA AA21-116A  
**Status:** Phase 1 Complete | Phase 2 In Progress

---

## Overview

APT29 is one of the most sophisticated nation-state threat actors operating today, responsible for the
SolarWinds supply chain compromise, the 2024 Microsoft corporate breach, and ongoing campaigns
targeting NATO-aligned governments. Their defining characteristics are patience, stealth, and
living-off-the-land techniques that blend into normal administrative activity.

This campaign emulates their real-world TTPs against a purpose-built Active Directory lab environment,
mapping each technique to MITRE ATT&CK, executing it against live infrastructure, and measuring
detection coverage in Wazuh.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Hardware | Dell PowerEdge T320, 96GB RAM |
| Hypervisor | Proxmox VE 9.1 |
| Domain | corp.local |
| DC | Windows Server 2022 + AD CS |
| Endpoints | Windows 11 (x2) |
| Mail Server | Windows Server 2022, hMailServer + GoPhish |
| ADFS | Windows Server 2022, adfs.corp.local |
| SIEM | Wazuh 4.14.4 |
| Firewall | pfSense CE 2.8.1 |
| Attack Platform | Kali Linux via SOCKS5 proxy |

---

## Campaign Phases

### Phase 1 -- Initial Access to Golden Ticket
📁 [phase-1-initial-access-to-golden-ticket](./phase-1-initial-access-to-golden-ticket/)

Full APT29 kill chain from spearphishing to full domain compromise in a single session.

| Metric | Result |
|--------|--------|
| Techniques Executed | 13 / 15 |
| Detection Rate | 23% (3 of 13) |
| Time to Compromise | ~3 hours |
| Final Objective | Golden Ticket, krbtgt extracted, 10-year forged TGT |
| Outcome | FULL DOMAIN COMPROMISE |

**Kill chain executed:**
1. GoPhish phishing lure delivered via hMailServer to oflynn@corp.local
2. RDP foothold on WIN11-01 via captured credentials
3. Encoded PowerShell execution and dual persistence (scheduled task + registry run key)
4. SMB share enumeration discovering aturner Domain Admin password in plaintext
5. Kerberoasting four service accounts (svc_sql, svc_backup, svc_web, svc_monitor)
6. RDP pivot to DC01, Defender disabled, Mimikatz LSASS dump
7. DCSync extraction of krbtgt NTLM hash, Golden Ticket forgery valid for 10 years

**Key techniques:** T1566.001 · T1078.002 · T1558.003 · T1003.006 · T1558.001

### Phase 1 Retest: Sysmon Detection Capability

After the original engagement identified missing endpoint telemetry as the dominant detection gap, Sysmon was deployed via GPO with Olaf Hartong's modular configuration and integrated into Wazuh. The same techniques were retested to measure the improvement.

**Date:** 26 April 2026

**Outcome:** Attack chain disruption improved from 23% to 71% on the retested technique set

**Highlight:** LSASS credential dumping was blocked at the endpoint by Microsoft Defender (HackTool:Win32/DumpLsass.H signature)

**Gaps identified for Phase 2:** Defender event channel ingestion, PowerShell Script Block Logging, Wazuh rule severity tuning, DC audit policy

---

### Phase 2 -- AD CS ESC Exploitation + Golden SAML
📁 `phase-2-adcs-esc-golden-saml/` *(coming soon)*

Post-remediation re-engagement targeting AD CS certificate abuse (ESC6/ESC8) and ADFS
Golden SAML forgery. Goal: achieve domain compromise via a different attack path and measure
detection improvement after Phase 1 remediations are applied.

---
## Detection Coverage Across Phases
| Phase | Techniques | Detected | Coverage | Notes |
|-------|------------|----------|----------|-------|
| Phase 1 | 13 | 3 | 23% | Original engagement |
| Phase 1 Retest | 7 | 5 | 71% | Sysmon scope (excludes DC-side techniques) |
| Phase 2 | TBD | TBD | TBD | AD CS ESC + Golden SAML |
| **Target** | | | **>80%** | |
---

## Disclaimer

This work is conducted in a fully isolated lab for personal learning, defensive research, and skill development. All attack execution is performed against systems owned and operated by the author. The TTPs documented map to public threat intelligence (MITRE ATT&CK G0016, CISA advisories) and are presented for defender education.
## References

- [MITRE ATT&CK -- APT29 (G0016)](https://attack.mitre.org/groups/G0016/)
- [CISA Advisory AA21-116A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a)
- [CISA Advisory AA22-011A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-011a)
- [CISA Advisory AA23-347A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a)

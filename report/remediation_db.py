"""Remediation database - one entry per check_id with timeline,
context, steps and references. Loaded by report.remediation:get_rem.

Add new entries here; the rest of the codebase only reads via get_rem().
v1.5.0 - extracted from report_generator.py to keep source files small.
"""
from __future__ import annotations

_REMEDIATION_DB: dict[str, dict] = {
    # -----------------------------------------------------------------------
    "AD-DOMAIN-006": {
        "timeline": "immediate",
        "context": (
            "RC4-HMAC and DES are legacy Kerberos encryption types vulnerable to offline "
            "cracking attacks (AS-REP / TGS-REP roasting). The DC's msDS-SupportedEncryptionTypes "
            "value 28 (0x1C) includes RC4 (0x04). Removing RC4 prevents hash capture and offline attacks."
        ),
        "steps": [
            "Audit current encryption types on all DCs and service accounts:",
            "  Get-ADComputer -Filter {PrimaryGroupID -eq 516} -Properties msDS-SupportedEncryptionTypes | Select Name,msDS-SupportedEncryptionTypes",
            "Set AES-only on DCs (value 24 = AES128 + AES256):",
            "  Get-ADDomainController -Filter * | ForEach-Object { Set-ADComputer $_.Name -Replace @{'msDS-SupportedEncryptionTypes'=24} }",
            "Apply via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options",
            "  'Network security: Configure encryption types allowed for Kerberos' = AES128, AES256 only",
            "Before disabling RC4, verify all service accounts support AES:",
            "  Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties msDS-SupportedEncryptionTypes | Where-Object {($_.msDS-SupportedEncryptionTypes -band 4) -ne 0}",
            "After applying, test Kerberos authentication before enforcing domain-wide.",
        ],
        "references": [
            "CIS Microsoft AD Benchmark L2 - 2.3.11.x",
            "NIST SP 800-63B §5.1.8",
            "MS Security Advisory ADV190023",
            "MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-DOMAIN-002": {
        "timeline": "week",
        "context": (
            "The ms-DS-MachineAccountQuota attribute allows any authenticated user to join up to 10 "
            "computers to the domain. This is a well-known persistence and lateral movement vector: "
            "attackers can create rogue machine accounts (MachineAccountQuota abuse) to generate "
            "silver tickets or maintain access."
        ),
        "steps": [
            "Set domain-wide quota to 0 to block unauthorized domain joins:",
            "  Set-ADDomain -Identity <your-domain.tld> -Replace @{'ms-DS-MachineAccountQuota'=0}",
            "Delegate domain join rights to a specific IT group only:",
            "  Create OU 'Staging Computers', delegate 'Create/Delete Computer Objects' to IT Helpdesk group",
            "  Set-ADObject -Identity 'OU=Staging,DC=<your-domain>,DC=tld' -Add @{nTSecurityDescriptor=...} (use AD delegation wizard)",
            "Document which accounts are authorized to join workstations.",
            "Verify change: Get-ADDomain | Select -ExpandProperty AllowedDNSSuffixes; (Get-ADDomain).ms-DS-MachineAccountQuota",
        ],
        "references": [
            "CIS Microsoft AD Benchmark L1 - 1.1.x",
            "MITRE ATT&CK T1136.002 (Create Account: Domain Account)",
            "Kevin Robertson - MachineAccountQuota research",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-IDENTITY-001": {
        "timeline": "week",
        "context": (
            "The number of accounts with Domain Admin, Enterprise Admin, or Schema Admin membership "
            "should be minimized. Each additional privileged account expands the blast radius of a "
            "credential compromise. Privileged accounts should only be used for administrative tasks "
            "via dedicated Privileged Access Workstations (PAW)."
        ),
        "steps": [
            "Review all Domain Admin members — remove accounts not requiring DA for daily tasks:",
            "  Get-ADGroupMember 'Domain Admins' -Recursive | Select Name,SamAccountName,Enabled",
            "Implement tiered administration model:",
            "  Tier 0: DC/forest management only (dedicated accounts + PAW)",
            "  Tier 1: Server administration",
            "  Tier 2: Workstation administration",
            "Create separate admin accounts per tier (e.g., user.t0, user.t1) — never shared with daily-use accounts.",
            "Use Authentication Policy Silos to restrict Tier 0 accounts to specific hosts.",
            "Enable Protected Users group for all privileged accounts (see AD-IDENTITY-002).",
            "Review Enterprise Admins and Schema Admins — should only have members during forest-level operations.",
        ],
        "references": [
            "CIS AD Benchmark L1 - 1.2.x",
            "Microsoft PAW guidance: aka.ms/paw",
            "MITRE ATT&CK T1078.002 (Valid Accounts: Domain Accounts)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-IDENTITY-002": {
        "timeline": "month",
        "context": (
            "The Protected Users security group provides additional Kerberos hardening: disables NTLM, "
            "DES, and RC4 for members; forces Kerberos AES; limits TGT lifetime to 4 hours; "
            "prevents credential caching. Requires Windows Server 2012 R2+ DFL."
        ),
        "steps": [
            "Enroll all Tier 0 and Tier 1 admin accounts in Protected Users group:",
            "  Add-ADGroupMember -Identity 'Protected Users' -Members <admin-account-1>,<admin-account-2>,...",
            "Verify DFL supports Protected Users (requires Windows Server 2012 R2+ domain functional level).",
            "Test in staging first — Protected Users cannot use NTLM; verify all admin tools support Kerberos.",
            "Monitor for authentication failures after enrollment using Event IDs 4625 / 4771.",
            "Document exceptions (service accounts that must use NTLM cannot be in this group).",
        ],
        "references": [
            "MS Docs: Protected Users Security Group",
            "CIS AD L2 - hardening privileged accounts",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-IDENTITY-003": {
        "timeline": "week",
        "context": (
            "Inactive accounts that have not been used for 180+ days represent attack surface. "
            "If compromised, they may go unnoticed for extended periods since no legitimate user "
            "would report login issues. Stale accounts are a common initial access vector."
        ),
        "steps": [
            "Identify all inactive accounts:",
            "  Search-ADAccount -AccountInactive -TimeSpan 180.00:00:00 -UsersOnly | Select Name,SamAccountName,LastLogonDate",
            "Disable (do not delete immediately) all inactive accounts:",
            "  Disable-ADAccount -Identity <account>",
            "Move disabled accounts to a quarantine OU with restricted GPO:",
            "  Move-ADObject -Identity <DN> -TargetPath 'OU=Disabled,DC=<your-domain>,DC=tld'",
            "After 90 days in quarantine with no business justification, delete the account.",
            "Implement an automated quarterly review process (script + HR integration).",
        ],
        "references": [
            "CIS AD L1 - 1.1.4",
            "NIST SP 800-53 AC-2 (Account Management)",
            "MITRE ATT&CK T1078 (Valid Accounts)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-IDENTITY-004": {
        "timeline": "week",
        "context": (
            "The built-in Administrator account (RID 500) is a well-known, always-enabled target. "
            "Its SID is predictable, it cannot be locked out by default, and is a primary target "
            "for pass-the-hash and credential stuffing attacks."
        ),
        "steps": [
            "Rename built-in Administrator to a non-obvious name:",
            "  Rename-LocalUser -Name 'Administrator' -NewName '<company-prefix>_legacy_admin'  # on each DC",
            "  Via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > 'Accounts: Rename administrator account'",
            "Create a decoy 'Administrator' account with no privileges and extensive auditing.",
            "Deny interactive and network logon for the built-in account via GPO User Rights Assignment.",
            "Set a long random password (32+ chars) managed via LAPS or a PAM solution.",
            "Enable alerting on any use of the original RID-500 account (Event ID 4624, account = <renamed>).",
        ],
        "references": [
            "CIS AD L1 - 2.2.x (Deny access to this computer from the network)",
            "NIST SP 800-53 AC-6 (Least Privilege)",
            "MS Security Baseline",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-IDENTITY-005": {
        "timeline": "month",
        "context": (
            "Disabled accounts still present in AD maintain SIDs that can be referenced in ACLs "
            "and group memberships. They represent unnecessary attack surface and complicate "
            "audits. Accounts disabled for 90+ days should be reviewed for removal."
        ),
        "steps": [
            "List disabled accounts and their last activity:",
            "  Get-ADUser -Filter {Enabled -eq $false} | Select Name,SamAccountName,DistinguishedName,WhenChanged",
            "Remove group memberships from disabled accounts:",
            "  (Get-ADUser <sam> -Properties MemberOf).MemberOf | ForEach-Object { Remove-ADGroupMember -Identity $_ -Members <sam> -Confirm:$false }",
            "Move to quarantine OU if not already there.",
            "Delete accounts inactive for 90+ days after confirmation with business/HR.",
            "Implement automated cleanup script on a quarterly schedule.",
        ],
        "references": [
            "NIST SP 800-53 AC-2(3) (Disable Accounts)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-LDAP-001": {
        "timeline": "immediate",
        "context": (
            "RestrictAnonymous=0 allows unauthenticated clients to enumerate domain users, "
            "groups, shares, and password policies via LDAP null sessions. This is a critical "
            "reconnaissance enabler — attackers can enumerate the entire AD structure without "
            "credentials. CVE-linked attacks leverage null sessions for initial foothold."
        ),
        "steps": [
            "Set via GPO (recommended — enforced and auditable):",
            "  Computer Config > Windows Settings > Security Settings > Local Policies > Security Options:",
            "  'Network access: Do not allow anonymous enumeration of SAM accounts' = Enabled",
            "  'Network access: Do not allow anonymous enumeration of SAM accounts and shares' = Enabled",
            "  'Network access: Restrict anonymous access to Named Pipes and Shares' = Enabled",
            "Set registry directly on DCs (backup first):",
            "  Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymous -Value 2",
            "  Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymousSAM -Value 1",
            "Test: net use \\\\<DC>\\IPC$ /user:'' '' — should fail after fix.",
            "Monitor Event ID 4625 (failed logon) for anonymous access attempts.",
        ],
        "references": [
            "CIS Windows Server Benchmark L1 - 2.3.10.x",
            "MS KB246261",
            "MITRE ATT&CK T1135 (Network Share Discovery)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-LDAP-002": {
        "timeline": "immediate",
        "context": (
            "LDAPServerIntegrity=1 (Negotiate) means signing is optional — a man-in-the-middle "
            "attacker can downgrade the connection to unsigned LDAP and relay or modify AD queries. "
            "LDAP channel binding disabled allows relay attacks even over TLS. "
            "MS KB4520412 (March 2020) strongly recommends enforcement."
        ),
        "steps": [
            "Enable LDAP signing requirement on DCs via GPO:",
            "  Computer Config > Windows Settings > Security Settings > Local Policies > Security Options:",
            "  'Domain controller: LDAP server signing requirements' = Require signing",
            "Enable LDAP channel binding on DCs:",
            "  Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name 'LdapEnforceChannelBinding' -Value 2",
            "  (0=Never, 1=When supported, 2=Always — set to 2)",
            "Enforce LDAP signing on clients via GPO:",
            "  Computer Config > Windows Settings > Security Settings > Local Policies > Security Options:",
            "  'Network security: LDAP client signing requirements' = Require signing",
            "Enable LDAP signing audit before enforcing (to identify non-compliant clients):",
            "  Set LDAP diagnostic logging to capture Event ID 2889 (unsigned LDAP binds)",
            "  Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics' -Name '16 LDAP Interface Events' -Value 2",
            "Review Event ID 2889 logs for clients not supporting signing before enforcing.",
        ],
        "references": [
            "MS KB4520412 — 2020 LDAP channel binding and signing advisory",
            "MS KB935834",
            "CIS AD L1 - 2.3.6.x",
            "MITRE ATT&CK T1557 (Adversary-in-the-Middle)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-LAPS-001": {
        "timeline": "week",
        "context": (
            "Local Administrator Password Solution (LAPS) manages unique, rotating local admin "
            "passwords per computer, preventing lateral movement via pass-the-hash with shared "
            "local admin credentials. Without LAPS, a single compromised local admin password "
            "gives access to all machines sharing that password."
        ),
        "steps": [
            "Deploy Windows LAPS (built-in since Windows Server 2019 / Windows 11 22H2):",
            "  Update-LapsADSchema  # extend AD schema (run once, Schema Admin required)",
            "  Set-LapsADComputerSelfPermission -Identity 'OU=<workstations-OU>,DC=<your-domain>,DC=tld'",
            "Configure Windows LAPS via GPO:",
            "  Computer Config > Administrative Templates > System > LAPS:",
            "  'Configure password backup directory' = Active Directory",
            "  'Password settings': Length=20, Complexity=LargeLettersSmallLettersNumbersSpecials, Age=30 days",
            "  'Post-authentication actions': Reset password after managed account use",
            "Grant read permissions to LAPS passwords to specific admin groups only:",
            "  Set-LapsADReadPasswordPermission -Identity 'OU=<workstations-OU>,...' -AllowedPrincipals '<DOMAIN>\\IT_LAPS_Readers'",
            "Verify LAPS deployment: Get-LapsADPassword -Identity <computer-name> -AsPlainText",
            "Apply to all computers in scope; review the 'Computers Without LAPS' table in the audit output for the prioritised list.",
        ],
        "references": [
            "MS Docs: Windows LAPS overview",
            "CIS AD L1 - local admin password management",
            "MITRE ATT&CK T1550.002 (Pass the Hash)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-PWPOL-001": {
        "timeline": "week",
        "context": (
            "The current password policy may have weaknesses (short minimum length, insufficient "
            "lockout, or missing complexity). Weak password policies directly enable credential "
            "attacks including brute force, password spray, and dictionary attacks."
        ),
        "steps": [
            "Review current policy: Get-ADDefaultDomainPasswordPolicy",
            "Configure minimum settings via GPO (Computer Config > Windows Settings > Security Settings > Account Policies > Password Policy):",
            "  Minimum password length: 14 characters (NIST recommends 12+, CIS L1 requires 14)",
            "  Password complexity: Enabled",
            "  Password history: 24 passwords remembered",
            "  Maximum password age: 90 days",
            "  Minimum password age: 1 day",
            "Configure Account Lockout Policy:",
            "  Threshold: 5 invalid attempts",
            "  Duration: 15 minutes",
            "  Observation window: 15 minutes",
            "For privileged accounts, create a Fine-Grained Password Policy (PSO) with stricter requirements:",
            "  New-ADFineGrainedPasswordPolicy -Name 'PSO-PrivilegedAccounts' -Precedence 1 -MinPasswordLength 20 -LockoutThreshold 3 -ComplexityEnabled $true -PasswordHistoryCount 24",
            "  Add-ADFineGrainedPasswordPolicySubject -Identity 'PSO-PrivilegedAccounts' -Subjects 'Domain Admins','Enterprise Admins'",
        ],
        "references": [
            "CIS AD L1 - 1.1.1 through 1.1.7",
            "NIST SP 800-63B §5.1.1",
            "MS Security Baseline - Password Policy",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-PWPOL-003": {
        "timeline": "week",
        "context": (
            "Accounts with password-never-expire set bypass the domain password policy rotation. "
            "If these credentials are compromised, they remain valid indefinitely. Service accounts "
            "are often legitimate exceptions, but must be converted to Managed Service Accounts "
            "(MSA/gMSA) where possible to eliminate manual password management entirely."
        ),
        "steps": [
            "Identify all accounts with PasswordNeverExpires=True:",
            "  Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | Select Name,SamAccountName,Description",
            "For regular user accounts: enforce password expiration by removing the flag:",
            "  Set-ADUser <sam> -PasswordNeverExpires $false",
            "For service accounts: evaluate migration to Group Managed Service Accounts (gMSA):",
            "  # gMSAs rotate passwords automatically (240-char, machine-managed)",
            "  New-ADServiceAccount -Name 'svc-bindldap' -DNSHostName '<dc-fqdn>' -PrincipalsAllowedToRetrieveManagedPassword 'bind_servers_group'",
            "For bind accounts that cannot use gMSA: document exception, set a rotation schedule (90 days), store in a PAM vault.",
            "Remove PasswordNeverExpires from all accounts not formally documented as exceptions.",
        ],
        "references": [
            "CIS AD L1 - 1.1.5",
            "MS Docs: Group Managed Service Accounts",
            "NIST SP 800-63B §10.2.1",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-GPO-002": {
        "timeline": "month",
        "context": (
            "Without GPO restrictions on privileged account logon, Domain Admin credentials can "
            "be used interactively on workstations and member servers. If a workstation is "
            "compromised (a common initial access point), the attacker can capture DA credentials "
            "from LSASS memory, achieving immediate domain compromise. "
            "This is the core defense against credential harvesting lateral movement."
        ),
        "steps": [
            "Create a dedicated GPO: 'Security - Restrict Privileged Logon'",
            "Apply to all OUs except Domain Controllers.",
            "Configure User Rights Assignment (Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment):",
            "  'Deny access to this computer from the network': add Domain Admins, Enterprise Admins",
            "  'Deny log on locally': add Domain Admins, Enterprise Admins",
            "  'Deny log on through Remote Desktop Services': add Domain Admins, Enterprise Admins",
            "  'Deny log on as a batch job': add Domain Admins, Enterprise Admins",
            "  'Deny log on as a service': add Domain Admins, Enterprise Admins",
            "Create separate Tier 1 accounts for server administration and Tier 2 for workstations.",
            "Test thoroughly before applying broadly — ensure break-glass account is available.",
            "Deploy Authentication Policy Silos for Tier 0 accounts to restrict DC-only logon.",
        ],
        "references": [
            "CIS AD L1 - 2.2.x (Deny access / log on rights)",
            "Microsoft PAW guidance: aka.ms/paw",
            "Microsoft Securing Privileged Access: aka.ms/spa",
            "MITRE ATT&CK T1078.002 + T1003 (OS Credential Dumping)",
        ],
    },
    # -----------------------------------------------------------------------
    "AD-IR-SEC-002": {
        "timeline": "none",
        "context": (
            "No user account creation events (Event ID 4720) were detected in the lookback period. "
            "This is a positive indicator that no unauthorized account creation has occurred recently."
        ),
        "steps": [
            "Maintain monitoring for Event ID 4720 (user account created) via SIEM or scheduled task.",
            "Alert on any account creation outside business hours or by non-IT accounts.",
        ],
        "references": ["MITRE ATT&CK T1136 (Create Account)"],
    },
    # -----------------------------------------------------------------------
    "AD-IR-SEC-003": {
        "timeline": "immediate",
        "context": (
            "Security group membership changes (Event IDs 4728/4732/4756) were detected in the "
            "30-day lookback window. In an incident response context, any privilege escalation or "
            "group modification must be verified against a change management record. "
            "Unauthorized group additions are a key indicator of Active Directory compromise."
        ),
        "steps": [
            "Immediately review all detected group membership changes in the audit output (security_events.csv).",
            "For each change, verify against change management tickets or authorized personnel approval.",
            "Investigate the actor accounts — check if they were used from expected IP/hosts:",
            "  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728,4732,4756; StartTime=(Get-Date).AddDays(-30)} | Select-Object TimeCreated,Message",
            "If any change is unauthorized: disable the actor account immediately, reset credentials, review all changes made by that account.",
            "Add monitoring alerts for changes to: Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, Remote Desktop Users.",
            "Configure SIEM alerts for Event IDs 4728, 4732, 4756, 4756, 4768, 4769 on high-privilege groups.",
        ],
        "references": [
            "MITRE ATT&CK T1098 (Account Manipulation)",
            "MS Docs: Security Event ID 4728",
            "NIST SP 800-92 (Log Management Guide)",
        ],
    },
    "AD-KERBEROS-001": {
        "timeline": "immediate",
        "context": (
            "Unconstrained Kerberos delegation allows any service or computer account configured with this flag to "
            "impersonate any user that authenticates to it — including Domain Admins. If an attacker compromises a host "
            "with unconstrained delegation, they can harvest Ticket Granting Tickets (TGTs) from memory and use them to "
            "move laterally or escalate to Domain Admin. Domain Controllers legitimately carry this flag; all other "
            "accounts should be migrated to constrained delegation or RBCD."
        ),
        "steps": [
            "Identify all accounts: Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name,DistinguishedName",
            "Also check computers: Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name,DistinguishedName",
            "Remove unconstrained delegation from user accounts: Set-ADUser <account> -TrustedForDelegation $false",
            "Remove unconstrained delegation from computer accounts: Set-ADComputer <computer> -TrustedForDelegation $false",
            "For services that require delegation, configure Constrained Delegation (KCD): Set-ADUser <account> -TrustedToAuthForDelegation $true ; Set-ADUser <account> -Add @{'msDS-AllowedToDelegateTo'='service/host'}",
            "For modern environments, prefer Resource-Based Constrained Delegation (RBCD) managed from the resource side.",
            "Alert on Event ID 4738 (user account changed) and 4742 (computer account changed) where TrustedForDelegation bit changes.",
        ],
        "references": [
            "MITRE ATT&CK T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)",
            "MITRE ATT&CK T1550.003 (Use Alternate Authentication Material: Pass the Ticket)",
            "Microsoft Docs: Configuring Constrained Delegation",
            "Harmj0y: The Most Dangerous User Right You Probably Have Never Heard Of",
        ],
    },
    "AD-ACL-002": {
        "timeline": "immediate",
        "context": (
            "DCSync is an attack technique that abuses Active Directory's replication protocol. Accounts holding the "
            "DS-Replication-Get-Changes-All extended right can request password hashes for any account in the domain — "
            "including krbtgt — without ever touching a Domain Controller directly. Legitimate holders are Domain Controllers, "
            "SYSTEM, and Domain/Enterprise Admins. Any other account with this right poses a critical credential theft risk "
            "and should be considered compromised until investigated."
        ),
        "steps": [
            "Audit current holders: (Get-Acl 'AD:\\<domain DN>').Access | Where-Object {$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -and $_.ActiveDirectoryRights -match 'ExtendedRight'}",
            "For each non-DC/non-admin account found, immediately investigate: when was the ACE added? (check Security Event 5136 — AD object modification)",
            "Remove the ACE using AD Users and Computers > Advanced Security Settings, or via PowerShell: $acl = Get-Acl 'AD:\\<DN>' ; $acl.RemoveAccessRule(<rule>) ; Set-Acl 'AD:\\<DN>' $acl",
            "Rotate the password of the affected account immediately, even if removal is confirmed — assume credential theft already occurred.",
            "Reset krbtgt password twice (double-reset procedure) if the account held DCSync rights for any significant period.",
            "Review all AD object ACLs periodically: Import-Module DSInternals ; Get-ADReplAccount -All | ...",
            "Configure audit policy: Advanced Audit Policy > DS Access > Audit Directory Service Changes (Success). Monitor Event 5136 for changes to domain object ACLs.",
        ],
        "references": [
            "MITRE ATT&CK T1003.006 (OS Credential Dumping: DCSync)",
            "Benjamin Delpy: mimikatz lsadump::dcsync",
            "Microsoft KB: Replication rights in Active Directory",
            "BloodHound: DCSync edge documentation",
        ],
    },
    "AD-HOSTHARDENING-001": {
        "timeline": "week",
        "context": (
            "WDigest authentication was designed for HTTP Digest authentication and, when enabled, causes Windows to cache "
            "plaintext credentials in LSASS memory. Tools like Mimikatz can extract these directly. LSA Protection (RunAsPPL) "
            "configures LSASS as a Protected Process Light, preventing non-protected processes — including most malware and "
            "credential-dumping tools — from reading LSASS memory. Together, disabling WDigest and enabling RunAsPPL are "
            "among the most impactful, low-effort host hardening controls available."
        ),
        "steps": [
            "Disable WDigest via GPO: Computer Config > Preferences > Windows Settings > Registry > HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest, Value: UseLogonCredential = 0 (DWORD)",
            "Verify via PowerShell: Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential",
            "Enable LSA Protection via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options > LSASS as a Protected Process = Enabled with UEFI Lock",
            "Alternatively via registry: Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL -Value 2 (2 = enabled with UEFI lock, 1 = enabled without lock)",
            "Verify PPL status: Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL",
            "After enabling RunAsPPL, ensure all LSA plugins/drivers are signed — unsigned ones will fail to load.",
            "For maximum protection, enable Credential Guard (Virtualization Based Security): Computer Config > Admin Templates > System > Device Guard > Turn On Virtualization Based Security",
            "Test with a lab machine before broad deployment — some AV/EDR solutions may conflict with PPL.",
        ],
        "references": [
            "MITRE ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory)",
            "Microsoft KB2871997: WDigest credential caching update",
            "Microsoft Docs: Configuring Additional LSA Protection",
            "CIS Benchmark for Windows Server 2019/2022: Section 2.3.11.x",
        ],
    },
    # -----------------------------------------------------------------------
    # v1.5.0 - coverage gap fixes
    # -----------------------------------------------------------------------
    "AD-ACL-001": {
        "timeline": "week",
        "context": (
            "Non-default permissions on Organizational Units broaden the AD "
            "attack surface. ACEs that allow GenericAll, WriteDacl, WriteOwner "
            "or unexpected GenericWrite to non-tier-0 principals enable lateral "
            "movement and persistence."
        ),
        "steps": [
            "Enumerate non-standard ACEs:",
            "  Get-ChildItem 'AD:\\{{domain_dn}}' -Recurse | ForEach-Object { Get-Acl $_.PSPath } | Select Path,Owner",
            "Compare against a known-good baseline (export ACL set, diff after each audit).",
            "Remove ACEs not justified by current operations; reset OU ACL to defaults if necessary:",
            "  dsacls 'OU=<ou>,{{domain_dn}}' /resetDefaultDACL",
            "Document approved delegations centrally and review quarterly.",
        ],
        "references": [
            "MITRE ATT&CK T1222.001",
            "BloodHound - Object ACL abuse paths",
        ],
    },
    "AD-ADCS-002": {
        "timeline": "immediate",
        "context": (
            "ADCS templates flagged ESC4 grant low-privilege users sufficient "
            "permissions on the template object to alter EnrolleeSuppliesSubject / "
            "extended-key-usage and issue authentication certificates as any "
            "principal. Direct path to Domain Admin."
        ),
        "steps": [
            "List templates with the ESC4 condition (insufficient ACL):",
            "  certutil -dstemplate | findstr /i 'pKIExtendedKeyUsage'",
            "On each affected template, restrict 'Write' / 'WriteDacl' permissions to Domain Admins.",
            "Disable EnrolleeSuppliesSubject for end-user templates.",
            "Retire low-assurance v1 templates (User, User Signature Only, Basic EFS, Authenticated Session).",
            "After remediation: Get-CertificationAuthority | Get-CertificationAuthorityAcl",
        ],
        "references": [
            "SpecterOps - Certified Pre-Owned (ESC1-ESC8)",
            "MITRE ATT&CK T1649",
        ],
    },
    "AD-DOMAIN-005": {
        "timeline": "immediate",
        "context": (
            "End-of-life or unsupported Windows operating systems no longer "
            "receive security patches. They become a trivial pivot host for "
            "lateral movement and ransomware propagation."
        ),
        "steps": [
            "Inventory all OS versions: Get-ADComputer -Filter * -Properties operatingSystem | Group operatingSystem",
            "For Legacy (XP/2003/2008/Win7/Win8): isolate VLAN, disable SMBv1, schedule decommission.",
            "For Server 2016: plan upgrade to 2022/2025; enable extended security updates.",
            "Block legacy OS access to DCs via GPO and firewall rules until decommissioned.",
            "Add SCCM/Intune to track lifecycle for every endpoint.",
        ],
        "references": [
            "Microsoft Lifecycle: aka.ms/lifecycle",
            "MITRE ATT&CK T1210",
        ],
    },
    "AD-DOMAIN-005c": {
        "timeline": "immediate",
        "context": "Variant of AD-DOMAIN-005 emitted when EOL hosts are confirmed online.",
        "steps": ["See AD-DOMAIN-005."],
        "references": ["See AD-DOMAIN-005."],
    },
    "AD-IDENTITY-006": {
        "timeline": "immediate",
        "context": (
            "krbtgt password age exceeds the recommended rotation cadence "
            "(180 days). If a Golden Ticket was forged at any point, a single "
            "rotation is insufficient - Microsoft recommends double-reset."
        ),
        "steps": [
            "Check current age: (Get-ADUser krbtgt -Properties pwdLastSet).pwdLastSet",
            "Run Reset-KrbTgt-Password.ps1 twice with 24h gap.",
            "Monitor Event ID 4769 for failed Kerberos service-ticket requests after each reset.",
            "Schedule recurring krbtgt rotation (every 180 days).",
        ],
        "references": [
            "MITRE ATT&CK T1558.001 (Golden Ticket)",
            "Microsoft Reset-KrbTgt-Password.ps1",
        ],
    },
    "AD-IDENTITY-007": {
        "timeline": "week",
        "context": (
            "Privileged accounts were observed logging on interactively to "
            "non-PAW hosts - primary lateral-movement enabler when those hosts "
            "are compromised."
        ),
        "steps": [
            "Identify recent interactive logons: review Event ID 4624 LogonType=2/10.",
            "Move privileged accounts to dedicated Authentication Policy Silo restricting logon to PAWs / DCs.",
            "Apply 'Deny log on locally' GPO on workstations and member servers for Domain/Enterprise/Schema Admins.",
            "Document required exceptions and review quarterly.",
        ],
        "references": [
            "Microsoft Securing Privileged Access (SPA): aka.ms/spa",
            "MITRE ATT&CK T1078.002 + T1003",
        ],
    },
    "AD-IDENTITY-008": {
        "timeline": "week",
        "context": (
            "Account lockout threshold is set too high or to zero (disabled), "
            "removing brute-force protection."
        ),
        "steps": [
            "Configure lockout threshold <= 10 attempts:",
            "  Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00",
            "Apply stricter policy to privileged accounts via PSO.",
            "Monitor 4625/4740 events for spray patterns.",
        ],
        "references": [
            "CIS AD L1 - Account Lockout",
            "MITRE ATT&CK T1110",
        ],
    },
    "AD-PWPOL-002": {
        "timeline": "week",
        "context": (
            "Password history is too short, allowing users to cycle through "
            "a small set of passwords."
        ),
        "steps": [
            "Set password history to 24:",
            "  Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24",
            "For privileged accounts apply via PSO with stricter precedence.",
        ],
        "references": ["CIS AD L1 - 1.1.x"],
    },
    "AD-PWPOL-005": {
        "timeline": "week",
        "context": (
            "Many accounts have passwords older than the policy threshold. "
            "These represent durable credential surface - if any were captured "
            "prior to the audit, they remain valid until forced rotation."
        ),
        "steps": [
            "Generate report:",
            "  Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet | Where { $_.PasswordLastSet -lt (Get-Date).AddDays(-90) }",
            "Force change at next logon: Set-ADUser <sam> -ChangePasswordAtLogon $true",
            "Prioritise privileged accounts and service accounts (migrate to gMSA).",
            "Communicate to users 5-7 days in advance.",
        ],
        "references": ["NIST SP 800-63B 5.1.1.2"],
    },
    "AD-SPN-001": {
        "timeline": "immediate",
        "context": (
            "Accounts with SPN registered are eligible for offline Kerberoasting. "
            "Privileged accounts with SPNs are the top-tier vector."
        ),
        "steps": [
            "List kerberoastable accounts: Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName",
            "Migrate service accounts to Group Managed Service Accounts (gMSA).",
            "For unavoidable SPNs, ensure password >= 25 random characters and rotated quarterly.",
            "Move privileged users with SPNs out of admin groups.",
            "Alert on Event ID 4769 with TicketEncryption RC4-HMAC for sensitive accounts.",
        ],
        "references": [
            "MITRE ATT&CK T1558.003 (Kerberoasting)",
            "SpecterOps - Roasting AS-REPs",
        ],
    },
    # -----------------------------------------------------------------------
    # v1.5.0 - IR-specific synthetic findings
    # -----------------------------------------------------------------------
    "AD-IR-001": {
        "timeline": "immediate",
        "context": (
            "El Security log no produjo eventos de gestion de cuentas en la "
            "ventana auditada ({{window_start}} - {{window_end}}). En contexto "
            "post-incidente esto sugiere borrado del log (T1070.001), "
            "desactivacion de auditoria (T1562.002) o tamano de log insuficiente. "
            "Antes de descartar el hallazgo deben revisarse las tres causas."
        ),
        "steps": [
            "Verificar tamano y retencion del Security log:",
            "  wevtutil gl Security",
            "Buscar evento 1102 (Security log was cleared):",
            "  Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 100 | Format-Table TimeCreated,Message -Auto",
            "Buscar evento 4719 (System audit policy was changed):",
            "  Get-WinEvent -FilterHashtable @{LogName='Security';Id=4719} -MaxEvents 100",
            "Comprobar politica de auditoria en {{hostname}}:",
            "  AuditPol /get /category:* | findstr /i 'Account Group'",
            "Determinar el evento mas antiguo presente:",
            "  Get-WinEvent -LogName Security -Oldest | Select -First 1 TimeCreated",
            "Cruzar con telemetria EDR / Sysmon - habitualmente la fuente alternativa cuando el log Windows esta limpiado.",
            "Si se confirma borrado: tratar el sistema como comprometido, preservar disco para forense, escalar a IR formal.",
        ],
        "references": [
            "MITRE ATT&CK T1070.001 (Indicator Removal: Clear Windows Event Logs)",
            "MITRE ATT&CK T1562.002 (Disable Windows Event Logging)",
            "NIST SP 800-86 (Forensic data preservation)",
        ],
    },
    "AD-IR-002": {
        "timeline": "immediate",
        "context": (
            "krbtgt no fue rotado tras el incidente del {{incident_date}}. Si el "
            "atacante exfiltro el hash krbtgt o los hashes NTDS, puede emitir "
            "Golden Tickets validos indefinidamente."
        ),
        "steps": [
            "Descargar Reset-KrbTgt-Password.ps1.",
            "Reset 1: .\\Reset-KrbTgt-Password.ps1 -Mode Reset -Confirm:$false",
            "Esperar 12-24 horas.",
            "Reset 2: .\\Reset-KrbTgt-Password.ps1 -Mode Reset -Confirm:$false",
            "Verificar replicacion: repadmin /showrepl",
            "Monitorizar 4769 con TicketEncryption RC4 tras cada reset.",
            "Programar rotacion recurrente cada 180 dias.",
        ],
        "references": [
            "MITRE ATT&CK T1558.001 (Golden Ticket)",
            "Microsoft - Reset-KrbTgt-Password.ps1",
        ],
    },
    "AD-IR-003": {
        "timeline": "immediate",
        "context": (
            "Se detectaron muchas cuentas con contrasenas vencidas en el momento "
            "del incidente. Cualquiera podria haber sido capturada y permanece "
            "valida tras la contencion si no se fuerza rotacion."
        ),
        "steps": [
            "Listar afectadas: Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet,MemberOf | Where { $_.PasswordLastSet -lt (Get-Date).AddDays(-90) }",
            "Forzar cambio: Set-ADUser <sam> -ChangePasswordAtLogon $true",
            "Para cuentas privilegiadas: rotacion inmediata + revision de uso reciente via 4624.",
            "Notificar a usuarios y planificar escalamiento por lotes.",
        ],
        "references": ["NIST SP 800-63B 5.1.1.2"],
    },
}

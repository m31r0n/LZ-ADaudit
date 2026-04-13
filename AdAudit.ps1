<#
    .NOTES
        Original script by phillips321.co.uk
        Maintained by Lazarus Security Framework
    .SYNOPSIS
        LZ-ADaudit  Active Directory Security Assessment tool.
    .DESCRIPTION
        Enumerates and audits Active Directory for common misconfigurations, weak
        settings, and attack-surface exposures. Produces structured JSON/CSV output
        suitable for audit pipelines, dashboards, and baseline comparison.
        Requires: PowerShell 5.0+, ActiveDirectory module (RSAT).
        Optional: DSInternals (password quality), GroupPolicy, LAPS modules.
        Release:
            [x] Version 1.0.0 - 12/04/2026
                * First public release of LZ-ADaudit as a standalone tool
                * Structured output contract (execution/summary/findings + CSV/NDJSON)
                * Baseline diff support and inventory/evidence exports
                * Incident-response profile with Security event correlation
    .EXAMPLE
        PS> AdAudit.ps1 -all
    .EXAMPLE
        PS> AdAudit.ps1 -profile standard -quiet -outputPath C:\AuditOut
    .EXAMPLE
        PS> AdAudit.ps1 -preflight
    .EXAMPLE
        PS> AdAudit.ps1 -inventory -evidence -outputPath C:\AuditOut
    .EXAMPLE
        PS> AdAudit.ps1 -incidentresponse -quiet -outputPath C:\AuditOut
#>
[CmdletBinding()]
Param (
    [switch]$installdeps = $false,
    [switch]$hostdetails = $false,
    [switch]$domainaudit = $false,
    [switch]$trusts = $false,
    [switch]$accounts = $false,
    [switch]$passwordpolicy = $false,
    [switch]$ntds = $false,
    [switch]$oldboxes = $false,
    [switch]$gpo = $false,
    [switch]$ouperms = $false,
    [switch]$laps = $false,
    [switch]$authpolsilos = $false,
    [switch]$insecurednszone = $false,
    [switch]$recentchanges = $false,
    [switch]$adcs = $false,
    [switch]$spn = $false,
    [switch]$asrep = $false,
    [switch]$acl = $false,
    [switch]$ldapsecurity = $false,
    [switch]$securityevents = $false,
    [Alias('incident-response','incident-respones')]
    [switch]$incidentresponse = $false,
    [switch]$all = $false,
    [string[]]$exclude = @(),
    [string]$select,
    [string]$profile = "",
    [int]$moduleTimeoutSeconds = 0,
    [string]$outputPath = "",
    [switch]$quiet = $false,
    [ValidateSet('normal','verbose','debug')]
    [string]$logLevel = "normal",
    [switch]$noNessus = $false,
    [string]$baseline = "",
    [switch]$inventory = $false,
    [switch]$evidence = $false,
    [switch]$preflight = $false,
    [switch]$libraryOnly = $false
)

$selectedChecks = @()
if ($select) { $selectedChecks = $select.Split(',') }

if ($incidentresponse.IsPresent) {
    # convenience mode switch requested by operators (equivalent to -profile incident-response)
    $profile = 'incident-response'
}
if ($profile -ieq 'incident-respones') {
    # typo-tolerant alias seen in field usage
    $profile = 'incident-response'
}

$script:switchesUsed    = @($MyInvocation.BoundParameters.Keys)
$script:resolvedProfile = $profile
$script:modulesRequested = @()

$versionnum = "v1.0.0"
$AdministratorTranslation = @("Administrator", "Administrateur", "Administrador")#If missing put the default Administrator name for your own language here

Function Get-Variables() {
    #Retrieve group names and OS version
    try {
        $script:OSVersion = (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName -ErrorAction Stop).ProductName
    } catch {
        Write-Both "    [!] Warning: Could not retrieve OS version from registry: $($_.Exception.Message)"
        $script:OSVersion = "Unknown"
    }

    try {
        $script:Administrators = (Get-ADGroup -Identity S-1-5-32-544 -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Administrators group: $($_.Exception.Message)"
        return
    }

    try {
        $script:Users = (Get-ADGroup -Identity S-1-5-32-545 -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Users group: $($_.Exception.Message)"
        return
    }

    try {
        $domainSID = (Get-ADDomain -Current LoggedOnUser -ErrorAction Stop).domainsid.value
        $script:DomainAdminsSID = $domainSID + "-512"
        $script:DomainUsersSID = $domainSID + "-513"
        $script:DomainControllersSID = $domainSID + "-516"
        $script:SchemaAdminsSID = $domainSID + "-518"
        $script:EnterpriseAdminsSID = $domainSID + "-519"
    } catch {
        Write-Both "    [!] Error: Failed to retrieve domain information: $($_.Exception.Message)"
        return
    }

    try {
        $script:EveryOneSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
        $script:EntrepriseDomainControllersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-9"
        $script:AuthenticatedUsersSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-11"
        $script:SystemSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-18"
        $script:LocalServiceSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-5-19"
    } catch {
        Write-Both "    [!] Error: Failed to create SID objects: $($_.Exception.Message)"
        return
    }

    try {
        $script:DomainAdmins = (Get-ADGroup -Identity $DomainAdminsSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Domain Admins group: $($_.Exception.Message)"
        return
    }

    try {
        $script:DomainUsers = (Get-ADGroup -Identity $DomainUsersSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Domain Users group: $($_.Exception.Message)"
        return
    }

    try {
        $script:DomainControllers = (Get-ADGroup -Identity $DomainControllersSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [!] Error: Failed to retrieve Domain Controllers group: $($_.Exception.Message)"
        return
    }

    # Schema Admins and Enterprise Admins only exist in forest root domain
    try {
        $script:SchemaAdmins = (Get-ADGroup -Identity $SchemaAdminsSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [i] Schema Admins not available in this domain (expected in child domains)"
        $script:SchemaAdmins = $null
    }

    try {
        $script:EnterpriseAdmins = (Get-ADGroup -Identity $EnterpriseAdminsSID -ErrorAction Stop).SamAccountName
    } catch {
        Write-Both "    [i] Enterprise Admins not available in this domain (expected in child domains)"
        $script:EnterpriseAdmins = $null
    }

    try {
        $script:EveryOne = $EveryOneSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:EntrepriseDomainControllers = $EntrepriseDomainControllersSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:AuthenticatedUsers = $AuthenticatedUsersSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:System = $SystemSID.Translate([System.Security.Principal.NTAccount]).Value
        $script:LocalService = $LocalServiceSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        Write-Both "    [!] Error: Failed to translate SIDs to account names: $($_.Exception.Message)"
        return
    }
    Write-Both "    [+] Administrators               : $Administrators"
    Write-Both "    [+] Users                        : $Users"
    Write-Both "    [+] Domain Admins                : $DomainAdmins"
    Write-Both "    [+] Domain Users                 : $DomainUsers"
    Write-Both "    [+] Domain Controllers           : $DomainControllers"
    Write-Both "    [+] Schema Admins                : $SchemaAdmins"
    Write-Both "    [+] Enterprise Admins            : $EnterpriseAdmins"
    Write-Both "    [+] Everyone                     : $EveryOne"
    Write-Both "    [+] Entreprise Domain Controllers: $EntrepriseDomainControllers"
    Write-Both "    [+] Authenticated Users          : $AuthenticatedUsers"
    Write-Both "    [+] System                       : $System"
    Write-Both "    [+] Local Service                : $LocalService"
}
Function Write-Both() {
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [object[]]$Message
        ,
        [ValidateSet('normal','verbose','debug')]
        [string]$Level = 'normal'
    )
    # Writes to console and persistent logs.
    $text = if ($Message -and $Message.Count -gt 0) { ($Message -join ' ') } else { "$args" }
    if (-not $script:quietMode) {
        $canPrint = $false
        switch ($Level) {
            'debug'   { if ($script:logLevel -eq 'debug') { $canPrint = $true } }
            'verbose' { if ($script:logLevel -in @('verbose','debug')) { $canPrint = $true } }
            default   { $canPrint = $true }
        }
        if ($canPrint) { Write-Host $text }
    }
    Add-Content -Path "$outputdir\consolelog.txt" -Value $text -ErrorAction SilentlyContinue
    if ($script:logsDir) {
        Add-Content -Path "$script:logsDir\console.log" -Value $text -ErrorAction SilentlyContinue
        Add-Content -Path "$script:logsDir\debug.log" -Value "$(Get-Date -Format o) | [$Level] $text" -ErrorAction SilentlyContinue
    }
}
Function Write-Trace() {
    param(
        [string]$Message,
        [ValidateSet('verbose','debug')]
        [string]$Level = 'verbose'
    )
    Write-Both -Level $Level $Message
}
Function Write-Nessus-Header() {
    #Creates nessus XML file header
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<?xml version=`"1.0`" ?><AdAudit>"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<Report name=`"$env:ComputerName`" xmlns:cm=`"http://www.nessus.org/cm`">"
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportHost name=`"$env:ComputerName`"><HostProperties></HostProperties>"
}
Function Write-Nessus-Finding( [string]$pluginname, [string]$pluginid, [string]$pluginexample) {
    # Intercept: create structured finding from Nessus output
    if ($null -ne $script:findings) {
        Add-NessusFinding -PluginName $pluginname -PluginId $pluginid -Evidence $pluginexample
    }

    # Write Nessus XML unless suppressed
    if (-not $noNessus) {
        # Properly escape XML special characters in all parameters
        $escapedPluginName    = Escape-XmlSpecialCharacters $pluginname
        $escapedPluginId      = Escape-XmlSpecialCharacters $pluginid
        $escapedPluginExample = Escape-XmlSpecialCharacters $pluginexample

        Add-Content -Path "$outputdir\adaudit.nessus" -Value "<ReportItem port=`"0`" svc_name=`"`" protocol=`"`" severity=`"0`" pluginID=`"ADAudit_$escapedPluginId`" pluginName=`"$escapedPluginName`" pluginFamily=`"Windows`">"
        Add-Content -Path "$outputdir\adaudit.nessus" -Value "<description>There's an issue with $escapedPluginName</description>"
        Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_type>remote</plugin_type><risk_factor>Low</risk_factor>"
        Add-Content -Path "$outputdir\adaudit.nessus" -Value "<solution>CCS Recommends fixing the issues with $escapedPluginName on the host</solution>"
        Add-Content -Path "$outputdir\adaudit.nessus" -Value "<synopsis>There's an issue with the $escapedPluginName settings on the host</synopsis>"
        Add-Content -Path "$outputdir\adaudit.nessus" -Value "<plugin_output>$escapedPluginExample</plugin_output></ReportItem>"
    }
}
Function Write-Nessus-Footer() {
    Add-Content -Path "$outputdir\adaudit.nessus" -Value "</ReportHost></Report></AdAudit>"
}
Function Escape-XmlSpecialCharacters {
    #Properly escapes XML special characters
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    $Value = $Value -replace '&', '&amp;'   # Must be FIRST to avoid double-escaping!
    $Value = $Value -replace '<', '&lt;'
    $Value = $Value -replace '>', '&gt;'
    $Value = $Value -replace '"', '&quot;'
    $Value = $Value -replace "'", '&apos;'

    return $Value
}
Function Get-DNSZoneInsecure {
    #Check DNS zones allowing insecure updates
    if ($OSVersion -notlike "Windows Server 2008*") {
        $count = 0
        $progresscount = 0
        $insecurezones = Get-DnsServerZone | Where-Object { $_.DynamicUpdate -like '*nonsecure*' }
        $totalcount = ($insecurezones | Measure-Object | Select-Object Count).count
        if ($totalcount -gt 0) {
            foreach ($insecurezone in $insecurezones ) {
                Add-Content -Path "$outputdir\insecure_dns_zones.txt" -Value "The DNS Zone $($insecurezone.ZoneName) allows insecure updates ($($insecurezone.DynamicUpdate))"
            }
            Write-Both "    [!] There were $totalcount DNS zones configured to allow insecure updates (KB842)"
            Write-Nessus-Finding "InsecureDNSZone" "KB842" ([System.IO.File]::ReadAllText("$outputdir\insecure_dns_zones.txt"))
        }
    }
    else {
        Write-Both "    [-] Not Windows 2012 or above, skipping Get-DNSZoneInsecure check."
    }
}
Function Get-OUPerms {
    #Check for non-standard perms for authenticated users, domain users, users and everyone groups
    $count = 0
    $progresscount = 0
    $objects = (Get-ADObject -Filter *)
    $totalcount = ($objects | Measure-Object | Select-Object Count).count
    foreach ($object in $objects) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*" -or $OSVersion -like "Windows Server 2025*") {
            $output = (Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$object").Access | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        }
        else {
            $output = (Get-Acl AD:$object).Access                                                                    | Where-Object { ($_.IdentityReference -eq "$AuthenticatedUsers") -or ($_.IdentityReference -eq "$EveryOne") -or ($_.IdentityReference -like "*\$DomainUsers") -or ($_.IdentityReference -eq "BUILTIN\$Users") } | Where-Object { ($_.ActiveDirectoryRights -ne 'GenericRead') -and ($_.ActiveDirectoryRights -ne 'GenericExecute') -and ($_.ActiveDirectoryRights -ne 'ExtendedRight') -and ($_.ActiveDirectoryRights -ne 'ReadControl') -and ($_.ActiveDirectoryRights -ne 'ReadProperty') -and ($_.ActiveDirectoryRights -ne 'ListObject') -and ($_.ActiveDirectoryRights -ne 'ListChildren') -and ($_.ActiveDirectoryRights -ne 'ListChildren, ReadProperty, ListObject') -and ($_.ActiveDirectoryRights -ne 'ReadProperty, GenericExecute') -and ($_.AccessControlType -ne 'Deny') }
        }
        if ($output -ne $null) {
            $count++
            Add-Content -Path "$outputdir\ou_permissions.txt" -Value "OU: $object"
            Add-Content -Path "$outputdir\ou_permissions.txt" -Value "[!] Rights: $($output.IdentityReference) $($output.ActiveDirectoryRights) $($output.AccessControlType)"
        }
    }
    Write-Progress -Activity "Searching for non standard permissions for authenticated users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] Issue identified, see $outputdir\ou_permissions.txt"
        Write-Nessus-Finding "OUPermissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\ou_permissions.txt"))
    }
}
function Get-LAPSStatus {

    # --- prerequisites & helpers -------------------------------------------------
    $ErrorActionPreference = 'Stop'

    try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
        Write-Warning "ActiveDirectory module is required for LAPS checks."
        return
    }

    # Default $outputdir if not set by caller
    if (-not (Get-Variable -Name outputdir -ErrorAction SilentlyContinue)) {
        $script:outputdir = Join-Path $env:TEMP "laps-audit"
    }
    if (-not (Test-Path $outputdir)) { New-Item -ItemType Directory -Path $outputdir | Out-Null }

    # Helper: identify DCs using userAccountControl SERVER_TRUST_ACCOUNT (0x2000)
    function Test-IsDomainController {
        param(
            [Parameter(Mandatory)]
            [Microsoft.ActiveDirectory.Management.ADComputer]$Computer
        )
        $uac = 0
        if ($Computer.userAccountControl) { $uac = [int]$Computer.userAccountControl }
        if ( ($uac -band 0x2000) -ne 0 ) { return $true } else { return $false }
    }

    # Convenience
    $rootDse   = Get-ADRootDSE
    $dnConfig  = $rootDse.configurationNamingContext
    $schemaBase = "CN=Schema,$dnConfig"
    $forestDN  = (Get-ADDomain).DistinguishedName

    # Principals to ignore in rights exports
    $systemPrincipals = @('NT AUTHORITY\SYSTEM','SYSTEM','S-1-5-18')

    # --- schema detection ---------------------------------------------------------
    $legacyLapsSchemaPresent = $false
    $winLapsSchemaPresent    = $false

    try {
        # Legacy LAPS attributes exist?
        $legacyAttr = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwd)' -SearchBase $schemaBase -ErrorAction Stop
        $legacyExp  = Get-ADObject -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' -SearchBase $schemaBase -ErrorAction Stop
        if ($legacyAttr -and $legacyExp) { $legacyLapsSchemaPresent = $true }
    } catch { }

    try {
        # Windows LAPS attributes exist?
        $winAttrPwd = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-Password)' -SearchBase $schemaBase -ErrorAction Stop
        $winAttrExp = Get-ADObject -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' -SearchBase $schemaBase -ErrorAction Stop
        if ($winAttrPwd -and $winAttrExp) { $winLapsSchemaPresent = $true }
    } catch { }

    if ($legacyLapsSchemaPresent) { Write-Both "    [+] Legacy LAPS schema is present in the domain." }
    else {
        Write-Both "    [!] Legacy LAPS schema not found (AdmPwd)."
        Write-Nessus-Finding "LAPSMissing" "KB258" "Legacy LAPS schema not found in domain $forestDN"
    }

    if ($winLapsSchemaPresent) { Write-Both "    [+] Windows LAPS schema is present in the domain." }
    else {
        Write-Both "    [!] Windows LAPS schema not found."
        Write-Nessus-Finding "WindowsLAPSMissing" "KB258" "Windows LAPS schema not found in domain $forestDN"
    }

    if ($legacyLapsSchemaPresent -and -not $winLapsSchemaPresent) {
        Write-Both "    [>] Legacy LAPS is present but Windows LAPS is not. Recommendation: plan migration to Windows LAPS for encryption, DSRM support, and built-in management."
        Write-Nessus-Finding "LAPSUpgradeRecommended" "KB258" "Legacy LAPS present; Windows LAPS not detected. Recommend upgrading."
    }

    # --- determine if DSRM checks should be enforced on DCs ----------------------
    # DSRM password management requires DFL 2016+; otherwise skip DC DSRM 'missing' findings.
    $domainModeName = (Get-ADDomain).DomainMode.ToString()
    $dsrmSupported = $false
    if ($domainModeName -match '2016|2019|2022|2025') { $dsrmSupported = $true }  # coarse but effective

    if ($winLapsSchemaPresent -and -not $dsrmSupported) {
        Write-Both "    [i] Domain Functional Level is earlier than 2016; Windows LAPS DSRM management isn't supported. DCs will not be flagged for missing DSRM backup."
        Write-Nessus-Finding "WindowsLAPSDSRMNotSupported" "KB258" "DFL < 2016. DC DSRM backup via Windows LAPS isn't supported; skipping DC DSRM 'missing' findings."
    }

    # --- Legacy LAPS deep checks (if module available) ---------------------------
    if ($legacyLapsSchemaPresent) {
        if (Get-Module -ListAvailable -Name AdmPwd.PS) {
            Import-Module AdmPwd.PS -ErrorAction SilentlyContinue | Out-Null

            # Pull inventory with UAC to detect DCs
            $legacyAll = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','userAccountControl'

            # Computers missing a legacy LAPS password (exclude DCs)
            $missingLegacyFile = Join-Path $outputdir 'legacy_laps_missing-computers.txt'
            Remove-Item $missingLegacyFile -ErrorAction SilentlyContinue
            $legacyMissing = $legacyAll |
                             Where-Object { -not (Test-IsDomainController -Computer $_) } |
                             Where-Object { -not $_.'ms-Mcs-AdmPwd' } |
                             Select-Object -ExpandProperty Name
            if ($legacyMissing) {
                $legacyMissing | Set-Content -Path $missingLegacyFile
                Write-Both  "    [!] Some computers/servers don't have a LEGACY LAPS password set, see $missingLegacyFile"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($missingLegacyFile))
            }

            # Expired legacy LAPS passwords (exclude DCs)
            $legacyExpiredFile = Join-Path $outputdir 'legacy_laps_expired-passwords.txt'
            Remove-Item $legacyExpiredFile -ErrorAction SilentlyContinue
            $now = Get-Date
            $legacyExpired = foreach ($c in $legacyAll) {
                if (Test-IsDomainController -Computer $c) { continue }
                $expRaw = $c.'ms-Mcs-AdmPwdExpirationTime'
                if ($expRaw) {
                    try {
                        $exp = [DateTime]::FromFileTime([Int64]$expRaw)
                        if ($exp -lt $now) { "{0} password expired since {1:u}" -f $c.Name, $exp }
                    } catch { }
                }
            }
            if ($legacyExpired) {
                $legacyExpired | Set-Content -Path $legacyExpiredFile
                Write-Both  "    [!] Some computers/servers have LEGACY LAPS password expired, see $legacyExpiredFile"
                Write-Nessus-Finding "LAPSMissingorExpired" "KB258" ([System.IO.File]::ReadAllText($legacyExpiredFile))
            }

            # Extended rights (legacy) - explicit -Identity
            $legacyRightsFile = Join-Path $outputdir 'legacy_laps_read-extendedrights.txt'
            Remove-Item $legacyRightsFile -ErrorAction SilentlyContinue
            $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName |
                   Where-Object { $_.DistinguishedName -and $_.Name } |
                   Sort-Object DistinguishedName

            foreach ($ou in $ous) {
                try {
                    $res = Find-AdmPwdExtendedRights -Identity $ou.DistinguishedName -ErrorAction Stop
                    foreach ($holder in $res.ExtendedRightHolders) {
                        if ($systemPrincipals -notcontains $holder) {
                            "$holder can read LEGACY LAPS password attribute in $($ou.DistinguishedName)" |
                                Add-Content -Path $legacyRightsFile
                        }
                    }
                } catch { continue }
            }
            if (Test-Path $legacyRightsFile) {
                Write-Both  "    [!] LEGACY LAPS extended rights exported, see $legacyRightsFile"
                Write-Nessus-Finding "LAPSExtendedRights" "KB258" ([System.IO.File]::ReadAllText($legacyRightsFile))
            }

        } else {
            Write-Both "    [!] AdmPwd.PS module is not installed on this host; limited legacy LAPS checks only."
        }
    }

    # --- Windows LAPS deep checks (schema-based, module optional) ----------------
    if ($winLapsSchemaPresent) {
        $winMissingFile    = Join-Path $outputdir 'winlaps_missing-computers.txt'
        $winExpiredFile    = Join-Path $outputdir 'winlaps_expired-passwords.txt'
        $dcMissingDSRMFile = Join-Path $outputdir 'winlaps_dcs_missing-dsrm.txt'
        $dcExpiredDSRMFile = Join-Path $outputdir 'winlaps_dcs_expired-dsrm.txt'
        $winRightsFile     = Join-Path $outputdir 'winlaps_read-extendedrights.txt'
        Remove-Item $winMissingFile,$winExpiredFile,$winRightsFile,$dcMissingDSRMFile,$dcExpiredDSRMFile -ErrorAction SilentlyContinue

        # Pull all computers with Windows LAPS-related attributes (and UAC for DC detection)
        $props = @('msLAPS-Password','msLAPS-EncryptedPassword','msLAPS-PasswordExpirationTime','msLAPS-EncryptedDSRMPassword','userAccountControl')
        $allWin = Get-ADComputer -Filter * -Properties $props

        # Partition DCs vs non-DCs
        $dcComputers    = @()
        $nonDCComputers = @()
        foreach ($c in $allWin) {
            if (Test-IsDomainController -Computer $c) { $dcComputers += $c } else { $nonDCComputers += $c }
        }

        # ---- Non-DC missing Windows LAPS backup
        $nonDCMissing = $nonDCComputers | Where-Object {
            -not $_.'msLAPS-Password' -and -not $_.'msLAPS-EncryptedPassword'
        } | Select-Object -ExpandProperty Name

        # ---- DC missing DSRM backup (only when supported)
        $dcMissingDSRM = @()
        if ($dsrmSupported) {
            $dcMissingDSRM = $dcComputers | Where-Object {
                -not $_.'msLAPS-EncryptedDSRMPassword'
            } | Select-Object -ExpandProperty Name
        }

        # Combine for the aggregate "missing" file (non-DCs + DCs where supported)
        $aggregateMissing = @()
        if ($nonDCMissing) { $aggregateMissing += $nonDCMissing }
        if ($dcMissingDSRM) { $aggregateMissing += $dcMissingDSRM }

        if ($aggregateMissing) {
            $aggregateMissing | Set-Content -Path $winMissingFile
            Write-Both  "    [!] Some computers/servers don't have a WINDOWS LAPS password backed up (or DSRM on DCs where supported), see $winMissingFile"
            Write-Nessus-Finding "WindowsLAPSMissingOrNotBackedUp" "KB258" ([System.IO.File]::ReadAllText($winMissingFile))
        }

        # Write DC-specific missing file if applicable
        if ($dcMissingDSRM) {
            $dcMissingDSRM | Set-Content -Path $dcMissingDSRMFile
            Write-Both  "    [!] Domain Controllers missing DSRM backup via Windows LAPS: see $dcMissingDSRMFile"
            Write-Nessus-Finding "WindowsLAPSDSRMissing" "KB258" ([System.IO.File]::ReadAllText($dcMissingDSRMFile))
        }

        # ---- Expired (both DC and non-DC share the same expiration attribute)
        $now = Get-Date

        $nonDCExpiredLines = foreach ($c in $nonDCComputers) {
            $expRaw = $c.'msLAPS-PasswordExpirationTime'
            if ($expRaw) {
                try {
                    $exp = [DateTime]::FromFileTime([Int64]$expRaw)
                    if ($exp -lt $now) { "{0} password expired since {1:u}" -f $c.Name, $exp }
                } catch { }
            }
        }

        $dcExpiredDSRMLines = @()
        if ($dsrmSupported) {
            $dcExpiredDSRMLines = foreach ($c in $dcComputers) {
                $expRaw = $c.'msLAPS-PasswordExpirationTime'
                if ($expRaw) {
                    try {
                        $exp = [DateTime]::FromFileTime([Int64]$expRaw)
                        if ($exp -lt $now) { "{0} DSRM password expired since {1:u}" -f $c.Name, $exp }
                    } catch { }
                }
            }
        }

        # Aggregate expired
        $aggregateExpired = @()
        if ($nonDCExpiredLines) { $aggregateExpired += $nonDCExpiredLines }
        if ($dcExpiredDSRMLines) { $aggregateExpired += $dcExpiredDSRMLines }

        if ($aggregateExpired) {
            $aggregateExpired | Set-Content -Path $winExpiredFile
            Write-Both  "    [!] Some computers/servers have WINDOWS LAPS password expired (or DSRM on DCs), see $winExpiredFile"
            Write-Nessus-Finding "WindowsLAPSMissingOrExpired" "KB258" ([System.IO.File]::ReadAllText($winExpiredFile))
        }

        # DC-specific expired DSRM file
        if ($dcExpiredDSRMLines) {
            $dcExpiredDSRMLines | Set-Content -Path $dcExpiredDSRMFile
            Write-Both  "    [!] Domain Controllers with EXPIRED DSRM secret: see $dcExpiredDSRMFile"
            Write-Nessus-Finding "WindowsLAPSDSRMExpired" "KB258" ([System.IO.File]::ReadAllText($dcExpiredDSRMFile))
        }

        # --- NEW: Positive confirmation for DSRM status on DCs -------------------
        if ($dsrmSupported) {
            # If there were no DCs missing DSRM and none expired, report OK
            $allDCsHaveDSRM = ($dcComputers.Count -gt 0) -and (-not $dcMissingDSRM -or $dcMissingDSRM.Count -eq 0)
            $noDCExpired    = (-not $dcExpiredDSRMLines -or $dcExpiredDSRMLines.Count -eq 0)

            if ($allDCsHaveDSRM -and $noDCExpired) {
                Write-Both "    [+] Windows LAPS DSRM configuration on Domain Controllers looks OK (all DCs have DSRM secret backed up, none expired)."
            }
        } else {
            Write-Both "    [i] DSRM checks skipped (Domain Functional Level < 2016). See Microsoft guidance: DSRM management requires DFL 2016 or later."
        }

        # Extended rights (Windows LAPS) - explicit -Identity
        if (Get-Module -ListAvailable -Name LAPS) {
            Import-Module LAPS -ErrorAction SilentlyContinue | Out-Null

            $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName |
                   Where-Object { $_.DistinguishedName -and $_.Name } |
                   Sort-Object DistinguishedName

            foreach ($ou in $ous) {
                try {
                    $result = Find-LapsADExtendedRights -Identity $ou.DistinguishedName -ErrorAction Stop
                    if ($result -and $result.ExtendedRightHolders) {
                        foreach ($holder in $result.ExtendedRightHolders) {
                            if ($systemPrincipals -notcontains $holder) {
                                "$holder can read WINDOWS LAPS password info in $($ou.DistinguishedName)" |
                                    Add-Content -Path $winRightsFile
                            }
                        }
                    }
                } catch { continue }
            }

            if (Test-Path $winRightsFile) {
                Write-Both  "    [!] WINDOWS LAPS extended rights exported, see $winRightsFile"
                Write-Nessus-Finding "WindowsLAPSExtendedRights" "KB258" ([System.IO.File]::ReadAllText($winRightsFile))
            } else {
                Write-Both "    [+] No non-system extended rights discovered for Windows LAPS password read on any OU."
            }
        } else {
            Write-Both "    [!] LAPS module not found; skipping Windows LAPS extended rights export. (Import the builtin 'LAPS' module on this host to enable.)"
        }
    }

    Write-Both "    [+] LAPS checks complete."
}
Function Get-PrivilegedGroupAccounts {
    #Lists users in Admininstrators, DA and EA groups
    [array]$privilegedusers = @()

    try {
        $privilegedusers += Get-ADGroupMember $Administrators -Recursive -ErrorAction Stop
    } catch {
        Write-Both "    [!] Warning: Could not retrieve Administrators group members: $($_.Exception.Message)"
    }

    try {
        $privilegedusers += Get-ADGroupMember $DomainAdmins -Recursive -ErrorAction Stop
    } catch {
        Write-Both "    [!] Warning: Could not retrieve Domain Admins members: $($_.Exception.Message)"
    }

    # Enterprise Admins only exists in forest root domain
    if ($EnterpriseAdmins) {
        try {
            $privilegedusers += Get-ADGroupMember $EnterpriseAdmins -Recursive -ErrorAction Stop
        } catch {
            Write-Both "    [i] Enterprise Admins not available (child domain)"
        }
    }

    $privusersunique = $privilegedusers | Sort-Object -Unique
    $count = 0
    $totalcount = ($privilegedusers | Measure-Object | Select-Object Count).count
    foreach ($account in $privusersunique) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_userPrivileged.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users who are in privileged groups..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts in privileged groups, see accounts_userPrivileged.txt (KB426)"
        Write-Nessus-Finding "AdminSDHolders" "KB426" ([System.IO.File]::ReadAllText("$outputdir\accounts_userPrivileged.txt"))
    }
}
Function Get-ProtectedUsers {
    #Lists users in "Protected Users" group (2012R2 and above)
    $DomainLevel = (Get-ADDomain).domainMode
    $supportedDFL = @("Windows2012Domain","Windows2012R2Domain","Windows2016Domain","Windows2019Domain","Windows2022Domain","Windows2025Domain")
    if ([string]$DomainLevel -in $supportedDFL) {
        #Checking for 2012 or above domain functional level
        $ProtectedUsersSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-525"
        $ProtectedUsers = (Get-ADGroup -Identity $ProtectedUsersSID).SamAccountName
        $count = 0
        $protectedaccounts = (Get-ADGroup $ProtectedUsers -Properties members).Members
        $totalcount = ($protectedaccounts | Measure-Object | Select-Object Count).count
        foreach ($members in $protectedaccounts) {
            if ($totalcount -eq 0) { break }
            Write-Progress -Activity "Searching for protected users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
            $account = Get-ADObject $members -Properties SamAccountName
            Add-Content -Path "$outputdir\accounts_protectedusers.txt" -Value "$($account.SamAccountName) ($($account.Name))"
            $count++
        }
        Write-Progress -Activity "Searching for protected users..." -Status "Ready" -Completed
        if ($count -gt 0) {
            Write-Both "    [!] There are $count accounts in the 'Protected Users' group, see accounts_protectedusers.txt"
            Write-Nessus-Finding "ProtectedUsers" "KB549" ([System.IO.File]::ReadAllText("$outputdir\accounts_protectedusers.txt"))
        }
    }
    else { Write-Both "    [-] Not Windows 2012 Domain Functional level or above, skipping Get-ProtectedUsers check." }
}
Function Get-AuthenticationPoliciesAndSilos {
    #Lists any authentication policies and silos (2012R2 and above)
    if ([single](Get-WinVersion) -ge [single]6.3) {
        #NT6.2 or greater detected so running this script
        $count = 0
        foreach ($policy in Get-ADAuthenticationPolicy -Filter *) {
            Write-Both "    [!] Found $policy Authentication Policy"
            $count++
        }
        if ($count -lt 1) {
            Write-Both "    [!] There were no AD Authentication Policies found in the domain"
        }
        $count = 0
        foreach ($policysilo in Get-ADAuthenticationPolicySilo -Filter *) {
            Write-Both "    [!] Found $policysilo Authentication Policy Silo"
            $count++
        }
        if ($count -lt 1) {
            Write-Both "    [!] There were no AD Authentication Policy Silos found in the domain"
        }
    }
}
Function Get-MachineAccountQuota {
    #Get number of machines a user can add to a domain
    $MachineAccountQuota = (Get-ADDomain | select -ExpandProperty DistinguishedName | Get-ADObject -Property 'ms-DS-MachineAccountQuota' | select -ExpandProperty ms-DS-MachineAccountQuota)
    if ($MachineAccountQuota -gt 0) {
        Write-Both "    [!] Domain users can add $MachineAccountQuota devices to the domain! (KB251)"
        Write-Nessus-Finding "DomainAccountQuota" "KB251" "Domain users can add $MachineAccountQuota devices to the domain"
    }
}
Function Get-PasswordPolicy {
    Write-Both "    [+] Checking default password policy"
    if (!(Get-ADDefaultDomainPasswordPolicy).ComplexityEnabled) {
        Write-Both "    [!] Password Complexity not enabled (KB262)"
        Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold -lt 5) {
        Write-Both "    [!] Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold) (KB263)"
        Write-Nessus-Finding "LockoutThreshold" "KB263" "Lockout threshold is less than 5, currently set to $((Get-ADDefaultDomainPasswordPolicy).LockoutThreshold)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength -lt 14) {
        Write-Both "    [!] Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength) (KB262)"
        Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length is less than 14, currently set to $((Get-ADDefaultDomainPasswordPolicy).MinPasswordLength)"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).ReversibleEncryptionEnabled) {
        Write-Both "    [!] Reversible encryption is enabled"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge -eq "00:00:00") {
        Write-Both "    [!] Passwords do not expire (KB254)"
        Write-Nessus-Finding "PasswordsDoNotExpire" "KB254" "Passwords do not expire"
    }
    if ((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount -lt 12) {
        Write-Both "    [!] Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount) (KB262)"
        Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history is less than 12, currently set to $((Get-ADDefaultDomainPasswordPolicy).PasswordHistoryCount)"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).NoLmHash -eq 0) {
        Write-Both "    [!] LM Hashes are stored! (KB510)"
        Write-Nessus-Finding "LMHashesAreStored" "KB510" "LM Hashes are stored"
    }
    Write-Both "    [-] Finished checking default password policy"
    Write-Both "    [+] Checking fine-grained password policies if they exist"
    foreach ($finegrainedpolicy in Get-ADFineGrainedPasswordPolicy -Filter *) {
        $finegrainedpolicyappliesto = $finegrainedpolicy.AppliesTo
        Write-Both "    [!] Policy: $finegrainedpolicy"
        Write-Both "    [!] AppliesTo: $($finegrainedpolicyappliesto)"
        if (!($finegrainedpolicy).PasswordComplexity) {
            Write-Both "    [!] Password Complexity not enabled (KB262)"
            Write-Nessus-Finding "PasswordComplexity" "KB262" "Password Complexity not enabled for $finegrainedpolicy"
        }
        if (($finegrainedpolicy).LockoutThreshold -lt 5) {
            Write-Both "    [!] Lockout threshold is less than 5, currently set to $($finegrainedpolicy).LockoutThreshold) (KB263)"
            Write-Nessus-Finding "LockoutThreshold" "KB263" " Lockout threshold for $finegrainedpolicy is less than 5, currently set to $(($finegrainedpolicy).LockoutThreshold)"
        }
        if (($finegrainedpolicy).MinPasswordLength -lt 14) {
            Write-Both "    [!] Minimum password length is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength) (KB262)"
            Write-Nessus-Finding "PasswordLength" "KB262" "Minimum password length for $finegrainedpolicy is less than 14, currently set to $(($finegrainedpolicy).MinPasswordLength)"
        }
        if (($finegrainedpolicy).ReversibleEncryptionEnabled) {
            Write-Both "    [!] Reversible encryption is enabled"
        }
        if (($finegrainedpolicy).MaxPasswordAge -eq "00:00:00") {
            Write-Both "    [!] Passwords do not expire (KB254)"
        }
        if (($finegrainedpolicy).PasswordHistoryCount -lt 12) {
            Write-Both "    [!] Passwords history is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount) (KB262)"
            Write-Nessus-Finding "PasswordHistory" "KB262" "Passwords history for $finegrainedpolicy is less than 12, currently set to $(($finegrainedpolicy).PasswordHistoryCount)"
        }
    }
    Write-Both "    [-] Finished checking fine-grained password policy"
}
Function Get-NULLSessions {
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymous -eq 0) {
        Write-Both "    [!] RestrictAnonymous is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).RestrictAnonymousSam -eq 0) {
        Write-Both "    [!] RestrictAnonymousSam is set to 0! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" " RestrictAnonymous is set to 0"
    }
    if ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa).everyoneincludesanonymous -eq 1) {
        Write-Both "    [!] EveryoneIncludesAnonymous is set to 1! (KB81)"
        Write-Nessus-Finding "NullSessions" "KB81" "EveryoneIncludesAnonymous is set to 1"
    }
}
Function Get-DomainTrusts {
    #Lists domain trusts if they are bad
    foreach ($trust in (Get-ADObject -Filter { objectClass -eq "trustedDomain" } -Properties TrustPartner, TrustDirection, trustType, trustAttributes)) {
        if ($trust.TrustDirection -eq 2) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
        if ($trust.TrustDirection -eq 3) {
            if ($trust.TrustAttributes -eq 1 -or $trust.TrustAttributes -eq 4) {
                #1 means trust is non-transitive, 4 is external so we check for anything but that
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain."
            }
            else {
                Write-Both "    [!] The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive! (KB250)"
                Write-Nessus-Finding "DomainTrusts" "KB250" "The domain $($trust.Name) is trusted by $env:UserDomain and it is Transitive!"
            }
        }
    }
}
Function Get-WinVersion {
    $WinVersion = [single]([string][environment]::OSVersion.Version.Major + "." + [string][environment]::OSVersion.Version.Minor)
    return [single]$WinVersion
}
Function Get-SMB1Support {
    #Check if server supports SMBv1
    if ([single](Get-WinVersion) -le [single]6.1) {
        #NT6.1 or less detected so checking reg key
        if (!(Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters).SMB1 -eq 0) {
            Write-Both "    [!] SMBv1 is not disabled (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
    elseif ([single](Get-WinVersion) -ge [single]6.2) {
        #NT6.2 or greater detected so using powershell function
        if ((Get-SmbServerConfiguration).EnableSMB1Protocol) {
            Write-Both "    [!] SMBv1 is enabled! (KB290)"
            Write-Nessus-Finding "SMBv1Support" "KB290" "SMBv1 is enabled"
        }
    }
}
Function Get-UserPasswordNotChangedRecently {
    #Reports users that haven't changed passwords in more than 90 days
    $count = 0
    $DaysAgo = (Get-Date).AddDays(-90)
    $accountsoldpasswords = Get-ADUser -Filter { PwdLastSet -lt $DaysAgo -and Enabled -eq "true" } -Properties PasswordLastSet
    $totalcount = ($accountsoldpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $accountsoldpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Currently identified $count" -PercentComplete ($count / $totalcount * 100)
        if ($account.PasswordLastSet) {
            $datelastchanged = $account.PasswordLastSet
        }
        else {
            $datelastchanged = "Never"
        }
        Add-Content -Path "$outputdir\accounts_with_old_passwords.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not changed their password since $datelastchanged"
        $count++
    }
    Write-Progress -Activity "Searching for passwords older than 90days..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count accounts with passwords older than 90days, see accounts_with_old_passwords.txt (KB550)"
        Write-Nessus-Finding "AccountsWithOldPasswords" "KB550" ([System.IO.File]::ReadAllText("$outputdir\accounts_with_old_passwords.txt"))
    }
    $krbtgtPasswordDate = (Get-ADUser -Filter { SamAccountName -eq "krbtgt" } -Properties PasswordLastSet).PasswordLastSet
    if ($krbtgtPasswordDate -lt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] krbtgt password not changed since $krbtgtPasswordDate! (KB253)"
        Write-Nessus-Finding "krbtgtPasswordNotChanged" "KB253" "krbtgt password not changed since $krbtgtPasswordDate"
    }
}
Function Get-GPOtoFile {
    #Outputs complete GPO report
    try {
        if (Test-Path "$outputdir\GPOReport.html") { Remove-Item "$outputdir\GPOReport.html" -Recurse -ErrorAction Stop }
        Get-GPOReport -All -ReportType HTML -Path "$outputdir\GPOReport.html" -ErrorAction Stop
        Write-Both "    [+] GPO Report saved to GPOReport.html"
    } catch {
        Write-Both "    [!] Warning: Error generating GPO HTML report: $($_.Exception.Message)"
    }

    try {
        if (Test-Path "$outputdir\GPOReport.xml") { Remove-Item "$outputdir\GPOReport.xml" -Recurse -ErrorAction Stop }
        Get-GPOReport -All -ReportType XML -Path "$outputdir\GPOReport.xml" -ErrorAction Stop
        Write-Both "    [+] GPO Report saved to GPOReport.xml, now run Grouper offline using the following command (KB499)"
        Write-Both "    [+]     PS>Import-Module Grouper.psm1 ; Invoke-AuditGPOReport -Path C:\GPOReport.xml -Level 3"
    } catch {
        Write-Both "    [!] Warning: Error generating GPO XML report: $($_.Exception.Message)"
    }
}
Function Get-GPOsPerOU {
    #Lists all OUs and which GPOs apply to them
    $count = 0
    $ousgpos = @(Get-ADOrganizationalUnit -Filter *)
    $totalcount = ($ousgpos | Measure-Object | Select-Object Count).count
    foreach ($ouobject in $ousgpos) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Currently identifed $count OUs" -PercentComplete ($count / $totalcount * 100)
        $combinedgpos = ($(((Get-GPInheritance -Target $ouobject).InheritedGpoLinks) | select DisplayName) | ForEach-Object { $_.DisplayName }) -join ','
        Add-Content -Path "$outputdir\ous_inheritedGPOs.txt" -Value "$($ouobject.Name) Inherits these GPOs: $combinedgpos"
        $count++
    }
    Write-Progress -Activity "Identifying which GPOs apply to which OUs..." -Status "Ready" -Completed
    Write-Both "    [+] Inherited GPOs saved to ous_inheritedGPOs.txt"
}
Function Get-NTDSdit {
    #Dumps NTDS.dit, SYSTEM and SAM for password cracking
    if (Test-Path "$outputdir\ntds.dit") { Remove-Item "$outputdir\ntds.dit" -Recurse }
    $outputdirntds = '\"' + $outputdir + '\ntds.dit\"'
    $command = "ntdsutil `"ac in ntds`" `"ifm`" `"cr fu $outputdirntds `" q q"
    $hide = cmd.exe /c "$command" 2>&1
    Write-Both "    [+] NTDS.dit, SYSTEM & SAM saved to output folder"
    Write-Both "    [+] Use secretsdump.py -system registry/SYSTEM -ntds Active\ Directory/ntds.dit LOCAL -outputfile customer"
}
Function Get-SYSVOLXMLS {
    #Finds XML files in SYSVOL (thanks --> https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
    $XMLFiles = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
    $count = 0
    if ($XMLFiles) {
        $progresscount = 0
        $totalcount = ($XMLFiles | Measure-Object | Select-Object Count).count
        foreach ($File in $XMLFiles) {
            if ($totalcount -eq 0) { break }
            $progresscount++
            Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Currently searched through $count" -PercentComplete ($progresscount / $totalcount * 100)
            $Filename = Split-Path $File -Leaf
            $Distinguishedname = (Split-Path (Split-Path (Split-Path( Split-Path (Split-Path $File -Parent) -Parent ) -Parent ) -Parent) -Leaf).Substring(1).TrimEnd('}')
            [xml]$Xml = Get-Content ($File)
            if ($Xml.innerxml -like "*cpassword*" -and $Xml.innerxml -notlike '*cpassword=""*') {
                if (!(Test-Path "$outputdir\sysvol")) { New-Item -ItemType Directory -Path "$outputdir\sysvol" | Out-Null }
                Write-Both "    [!] cpassword found in file, copying to output folder (KB329)"
                Write-Both "        $File"
                Copy-Item -Path $File -Destination $outputdir\sysvol\$Distinguishedname.$Filename
                $count++
            }
        }
        Write-Progress -Activity "Searching SYSVOL *.xmls for cpassword..." -Status "Ready" -Completed
    }
    if ($count -eq 0) {
        Write-Both "    ...cpassword not found in the $($XMLFiles.count) XML files found."
    }
    else {
        $GPOxml = (Get-Content "$outputdir\sysvol\*.xml" -ErrorAction SilentlyContinue)
        $GPOxml = $GPOxml -Replace "<", "&lt;"
        $GPOxml = $GPOxml -Replace ">", "&gt;"
        Write-Nessus-Finding "GPOPasswordStorage" "KB329" "$GPOxml"
    }
}
Function Get-InactiveAccounts {
    #Lists accounts not used in past 180 days plus some checks for admin accounts
    $count = 0
    $progresscount = 0
    $inactiveaccounts = Search-ADaccount -AccountInactive -Timespan (New-TimeSpan -Days 180) -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($inactiveaccounts | Measure-Object | Select-Object Count).count
    foreach ($account in $inactiveaccounts) {
        if ($totalcount -eq 0) { break }
        $progresscount++
        Write-Progress -Activity "Searching for inactive users..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
        if ($account.Enabled) {
            if ($account.LastLogonDate) {
                $userlastused = $account.LastLogonDate
            }
            else {
                $userlastused = "Never"
            }
            Add-Content -Path "$outputdir\accounts_inactive.txt" -Value "User $($account.SamAccountName) ($($account.Name)) has not logged on since $userlastused"
            $count++
        }
    }
    Write-Progress -Activity "Searching for inactive users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count inactive user accounts(180days), see accounts_inactive.txt (KB500)"
        Write-Nessus-Finding "InactiveAccounts" "KB500" ([System.IO.File]::ReadAllText("$outputdir\accounts_inactive.txt"))
    }
}
Function Get-AdminAccountChecks {
    #Checks if Administrator account has been renamed, replaced and is no longer used.
    $AdministratorSID = ((Get-ADDomain -Current LoggedOnUser).domainsid.value) + "-500"
    $AdministratorSAMAccountName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).SamAccountName
    $AdministratorName = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties SamAccountName).Name
    if ($AdministratorTranslation -contains $AdministratorSAMAccountName) {
        Write-Both "    [!] Local Administrator account (UID500) has not been renamed (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Administrator account (UID500) has not been renamed"
    }
    else {
        $count = 0
        foreach ($AdminName in $AdministratorTranslation) {
            if ((Get-ADUser -Filter { SamAccountName -eq $AdminName })) { $count++ }
        }
        if ($count -eq 0) {
            Write-Both "    [!] Local Administrator account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place! (KB309)"
            Write-Nessus-Finding "AdminAccountRenamed" "KB309" "Local Admin account renamed to $AdministratorSAMAccountName ($($AdministratorName)), but a dummy account not made in it's place"
        }
    }
    $AdministratorLastLogonDate = (Get-ADUser -Filter { SID -eq $AdministratorSID } -Properties LastLogonDate).LastLogonDate
    if ($AdministratorLastLogonDate -gt (Get-Date).AddDays(-180)) {
        Write-Both "    [!] UID500 (LocalAdministrator) account is still used, last used $AdministratorLastLogonDate! (KB309)"
        Write-Nessus-Finding "AdminAccountRenamed" "KB309" "UID500 (LocalAdmini) account is still used, last used $AdministratorLastLogonDate"
    }
}
Function Get-DisabledAccounts {
    #Lists disabled accounts
    $disabledaccounts = Search-ADaccount -AccountDisabled -UsersOnly
    $count = 0
    $totalcount = ($disabledaccounts | Measure-Object | Select-Object Count).count
    foreach ($account in $disabledaccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for disabled users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_disabled.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is disabled"
        $count++
    }
    Write-Progress -Activity "Searching for disabled users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count disabled user accounts, see accounts_disabled.txt (KB501)"
        Write-Nessus-Finding "DisabledAccounts" "KB501" ([System.IO.File]::ReadAllText("$outputdir\accounts_disabled.txt"))
    }
}
Function Get-LockedAccounts {
    #Lists locked accounts
    $lockedAccounts = Get-ADUser -Filter * -Properties LockedOut | Where-Object { $_.LockedOut -eq $true }
    $count = 0
    $totalcount = ($lockedAccounts | Measure-Object | Select-Object Count).Count
    foreach ($account in $lockedAccounts) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for locked users..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_locked.txt" -Value "Account $($account.SamAccountName) ($($account.Name)) is locked"
        $count++
    }
    Write-Progress -Activity "Searching for locked users..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] $count locked user accounts, see accounts_locked.txt"
    }
}
Function Get-AccountPassDontExpire {
    #Lists accounts who's passwords dont expire
    $count = 0
    $nonexpiringpasswords = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object { $_.Enabled -eq $true }
    $totalcount = ($nonexpiringpasswords | Measure-Object | Select-Object Count).count
    foreach ($account in $nonexpiringpasswords) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\accounts_passdontexpire.txt" -Value "$($account.SamAccountName) ($($account.Name))"
        $count++
    }
    Write-Progress -Activity "Searching for users with passwords that dont expire..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] There are $count accounts that don't expire, see accounts_passdontexpire.txt (KB254)"
        Write-Nessus-Finding "AccountsThatDontExpire" "KB254" ([System.IO.File]::ReadAllText("$outputdir\accounts_passdontexpire.txt"))
    }
}
Function Get-OldBoxes {
    #Lists 2000/2003/XP/Vista/7/2008 machines
    $count = 0
    $oldboxes = Get-ADComputer -Filter { OperatingSystem -Like "*2003*" -and Enabled -eq "true" -or OperatingSystem -Like "*XP*" -and Enabled -eq "true" -or OperatingSystem -Like "*2000*" -and Enabled -eq "true" -or OperatingSystem -like '*Windows 7*' -and Enabled -eq "true" -or OperatingSystem -like '*vista*' -and Enabled -eq "true" -or OperatingSystem -like '*2008*' -and Enabled -eq "true" -or OperatingSystem -like '*2012*' -and Enabled -eq "true"} -Property OperatingSystem
    $totalcount = ($oldboxes | Measure-Object | Select-Object Count).count
    foreach ($machine in $oldboxes) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for 2000/2003/XP/Vista/7/2008 devices joined to the domain..." -Status "Currently identifed $count" -PercentComplete ($count / $totalcount * 100)
        Add-Content -Path "$outputdir\machines_old.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address)"
        $count++
    }
    Write-Progress -Activity "Searching for 2000/2003/XP/Vista/7/2008 devices joined to the domain..." -Status "Ready" -Completed
    if ($count -gt 0) {
        Write-Both "    [!] We found $count machines running 2000/2003/XP/Vista/7/2008! see machines_old.txt (KB3/37/38/KB259)"
        Write-Nessus-Finding "OldBoxes" "KB259" ([System.IO.File]::ReadAllText("$outputdir\machines_old.txt"))
    }
}
Function Get-DCsNotOwnedByDA {
    #Searches for DC objects not owned by the Domain Admins group
    $count = 0
    $progresscount = 0
    $domaincontrollers = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } -Property *
    $totalcount = ($domaincontrollers | Measure-Object | Select-Object Count).count
    if ($totalcount -gt 0) {
        foreach ($machine in $domaincontrollers) {
            $progresscount++
            Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Currently identifed $count" -PercentComplete ($progresscount / $totalcount * 100)
            if ($machine.ntsecuritydescriptor.Owner -ne "$env:UserDomain\$DomainAdmins") {
                Add-Content -Path "$outputdir\dcs_not_owned_by_da.txt" -Value "$($machine.Name), $($machine.OperatingSystem), $($machine.OperatingSystemServicePack), $($machine.OperatingSystemVersio), $($machine.IPv4Address), owned by $($machine.ntsecuritydescriptor.Owner)"
                $count++
            }
        }
        Write-Progress -Activity "Searching for DCs not owned by Domain Admins group..." -Status "Ready" -Completed
    }
    if ($count -gt 0) {
        Write-Both "    [!] We found $count DCs not owned by Domains Admins group! see dcs_not_owned_by_da.txt"
        Write-Nessus-Finding "DCsNotByDA" "KB547" ([System.IO.File]::ReadAllText("$outputdir\dcs_not_owned_by_da.txt"))
    }
}
Function Get-HostDetails {
    #Gets basic information about the host
    Write-Both "    [+] Device Name:  $env:ComputerName"
    Write-Both "    [+] Domain Name:  $env:UserDomain"
    Write-Both "    [+] User Name  :  $env:UserName"
    Write-Both "    [+] NT Version :  $(Get-WinVersion)"
    $IPAddresses = [net.dns]::GetHostAddresses("") | select -ExpandProperty IP*
    foreach ($ip in $IPAddresses) {
        if ($ip -ne "::1") {
            Write-Both "    [+] IP Address :  $ip"
        }
    }
}
Function Get-FunctionalLevel {
    #Gets the functional level for domain and forest
    $DomainLevel = (Get-ADDomain).domainMode
    if ($DomainLevel -eq "Windows2000Domain" -and [single](Get-WinVersion) -gt 5.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2003InterimDomain" -and [single](Get-WinVersion) -gt 5.1) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2003Domain" -and [single](Get-WinVersion) -gt 5.2) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2008Domain" -and [single](Get-WinVersion) -gt 6.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2008R2Domain" -and [single](Get-WinVersion) -gt 6.1) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2012Domain" -and [single](Get-WinVersion) -gt 6.2) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2012R2Domain" -and [single](Get-WinVersion) -gt 6.3) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    if ($DomainLevel -eq "Windows2016Domain" -and [single](Get-WinVersion) -gt 10.0) { Write-Both "    [!] DomainLevel is reduced for backwards compatibility to $DomainLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "DomainLevel is reduced for backwards compatibility to $DomainLevel" }
    $ForestLevel = (Get-ADForest).ForestMode
    if ($ForestLevel -eq "Windows2000Forest" -and [single](Get-WinVersion) -gt 5.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2003InterimForest" -and [single](Get-WinVersion) -gt 5.1) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2003Forest" -and [single](Get-WinVersion) -gt 5.2) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2008Forest" -and [single](Get-WinVersion) -gt 6.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2008R2Forest" -and [single](Get-WinVersion) -gt 6.1) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2012Forest" -and [single](Get-WinVersion) -gt 6.2) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2012R2Forest" -and [single](Get-WinVersion) -gt 6.3) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
    if ($ForestLevel -eq "Windows2016Forest" -and [single](Get-WinVersion) -gt 10.0) { Write-Both "    [!] ForestLevel is reduced for backwards compatibility to $ForestLevel!" ; Write-Nessus-Finding "FunctionalLevel" "KB546" "ForestLevel is reduced for backwards compatibility to $ForestLevel" }
}
Function Get-GPOEnum {
    #Loops GPOs for some important domain-wide settings
    $AllowedJoin = @()
    $HardenNTLM = @()
    $DenyNTLM = @()
    $AuditNTLM = @()
    $NTLMAuthExceptions = @()
    $EncryptionTypesNotConfigured = $true
    $AdminLocalLogonAllowed = $true
    $AdminRPDLogonAllowed = $true
    $AdminNetworkLogonAllowed = $true
    $AllGPOs = Get-GPO -All | sort DisplayName
    foreach ($GPO in $AllGPOs) {
        $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
        #Look for GPO that allows join PC to domain
        $permissionindex = $GPOreport.IndexOf('<q1:Name>SeMachineAccountPrivilege</q1:Name>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeMachineAccountPrivilege' }).Member) ) {
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name GPO  -Value $GPO.DisplayName
                $obj | Add-Member -MemberType NoteProperty -Name SID  -Value $member.Sid.'#text'
                $obj | Add-Member -MemberType NoteProperty -Name Name -Value $member.Name.'#text'
                $AllowedJoin += $obj
            }
        }
        #Look for GPO that hardens NTLM
        $permissionindex = $GPOreport.IndexOf('NoLMHash</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'NoLMHash' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "NoLMHash $($value.Display.DisplayBoolean)"
            $HardenNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('LmCompatibilityLevel</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'LmCompatibilityLevel' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "LmCompatibilityLevel $($value.Display.DisplayString)"
            $HardenNTLM += $obj
        }
        #Look for GPO that denies NTLM
        $permissionindex = $GPOreport.IndexOf('RestrictNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'RestrictNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "RestrictNTLMInDomain $($value.Display.DisplayString)"
            $DenyNTLM += $obj
        }
        #Look for GPO that audits NTLM
        $permissionindex = $GPOreport.IndexOf('AuditNTLMInDomain</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditNTLMInDomain' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditNTLMInDomain $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        $permissionindex = $GPOreport.IndexOf('AuditReceivingNTLMTraffic</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            $value = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditReceivingNTLMTraffic' }
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name GPO   -Value $GPO.DisplayName
            $obj | Add-Member -MemberType NoteProperty -Name Value -Value "AuditReceivingNTLMTraffic $($value.Display.DisplayString)"
            $AuditNTLM += $obj
        }
        #Look for GPO that allows NTLM exclusions
        $permissionindex = $GPOreport.IndexOf('DCAllowedNTLMServers</q1:KeyName>')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'DCAllowedNTLMServers' }).SettingStrings.Value) ) {
                $NTLMAuthExceptions += $member
            }
        }
        #Validate Kerberos Encryption algorithm
        $permissionindex = $GPOreport.IndexOf('MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
        if ($permissionindex -gt 0) {
            $EncryptionTypesNotConfigured = $false
            $xmlreport = [xml]$GPOreport
            $EncryptionTypes = $xmlreport.GPO.Computer.ExtensionData.Extension.SecurityOptions.Display.DisplayFields.Field
            if (($EncryptionTypes     | Where-Object { $_.Name -eq 'DES_CBC_CRC' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_CRC for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'DES_CBC_MD5' }             | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled DES_CBC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'RC4_HMAC_MD5' }            | select -ExpandProperty value) -eq 'true') { Write-Both "    [!] GPO [$($GPO.DisplayName)] enabled RC4_HMAC_MD5 for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES128_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES128_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'AES256_HMAC_SHA1' }        | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] AES256_HMAC_SHA1 not enabled for Kerberos!" }
            elseif (($EncryptionTypes | Where-Object { $_.Name -eq 'Future encryption types' } | select -ExpandProperty value) -eq 'false') { Write-Both "    [!] Future encryption types not enabled for Kerberos!" }
        }
        #Validates Admins local logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminLocalLogonAllowed = $false
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins RDP logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyRemoteInteractiveLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyRemoteInteractiveLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminRPDLogonAllowed = $false
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyRemoteInteractiveLogonRight $($member.Name.'#text')"
                }
            }
        }
        #Validates Admins network logon restrictions
        $permissionindex = $GPOreport.IndexOf('SeDenyNetworkLogonRight')
        if ($permissionindex -gt 0) {
            $xmlreport = [xml]$GPOreport
            foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeDenyNetworkLogonRight' }).Member)) {
                if ($member.Name.'#text' -match "$SchemaAdmins" -or $member.Name.'#text' -match "$DomainAdmins" -or $member.Name.'#text' -match "$EnterpriseAdmins") {
                    $AdminNetworkLogonAllowed = $false
                    Add-Content -Path "$outputdir\admin_logon_restrictions.txt" -Value "$($GPO.DisplayName) SeDenyNetworkLogonRight $($member.Name.'#text')"
                }
            }
        }
    }
    #Output for join PC to domain
    foreach ($record in $AllowedJoin) {
        Write-Both "    [+] GPO [$($record.GPO)] allows [$($record.Name)] to join computers to domain"
    }
    #Output for Admins local logon restrictions
    if ($AdminLocalLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise local logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise local logon across domain!"
    }
    #Output for Admins RDP logon restrictions
    if ($AdminRPDLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise RDP logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise RDP logon across domain!"
    }
    #Output for Admins network logon restrictions
    if ($AdminNetworkLogonAllowed) {
        Write-Both "    [!] No GPO restricts Domain, Schema and Enterprise network logon across domain!!!"
        Write-Nessus-Finding "AdminLogon" "KB479" "No GPO restricts Domain, Schema and Enterprise network logon across domain!"
    }
    #Output for Validate Kerberos Encryption algorithm
    if ($EncryptionTypesNotConfigured) {
        Write-Both "    [!] RC4_HMAC_MD5 enabled for Kerberos across domain!!!"
    }
    #Output for deny NTLM
    if ($DenyNTLM.count -eq 0) {
        if ($HardenNTLM.count -eq 0) {
            Write-Both "    [!] No GPO denies NTLM authentication!"
            Write-Both "    [!] No GPO explicitely restricts LM or NTLMv1!"
        }
        else {
            Write-Both "    [+] NTLM authentication hardening implemented, but NTLM not denied"
            foreach ($record in $HardenNTLM) {
                Write-Both "        [-] $($record.value)"
                Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
            }
        }
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM restricted by GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
    #Output for NTLM exceptions
    if ($NTLMAuthExceptions.count -ne 0) {
        foreach ($record in $NTLMAuthExceptions) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM auth exceptions $($record)"
        }
    }
    #Output for NTLM audit
    if ($AuditNTLM.count -eq 0) {
        Write-Both "    [!] No GPO enables NTLM audit authentication!"
    }
    else {
        foreach ($record in $DenyNTLM) {
            Add-Content -Path "$outputdir\ntlm_restrictions.txt" -Value "NTLM audit GPO [$($record.gpo)] with value [$($record.value)]"
        }
    }
}
Function Get-PrivilegedGroupMembership {
    #List Domain Admins, Enterprise Admins and Schema Admins members
    # Note: Schema Admins and Enterprise Admins only exist in forest root domain
    if ($SchemaAdmins) {
        try {
            $SchemaMembers = Get-ADGroup $SchemaAdmins -ErrorAction Stop | Get-ADGroupMember -ErrorAction Stop
            if (($SchemaMembers | measure).count -ne 0) {
                Write-Both "    [!] Schema Admins not empty!!!"
                foreach ($member in $SchemaMembers) {
                    Add-Content -Path "$outputdir\schema_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
                }
            }
        } catch {
            Write-Both "    [i] Schema Admins not available in this domain (expected in child domains)"
        }
    } else {
        Write-Both "    [i] Schema Admins not available (child domain)"
    }

    if ($EnterpriseAdmins) {
        try {
            $EnterpriseMembers = Get-ADGroup $EnterpriseAdmins -ErrorAction Stop | Get-ADGroupMember -ErrorAction Stop
            if (($EnterpriseMembers | measure).count -ne 0) {
                Write-Both "    [!] Enterprise Admins not empty!!!"
                foreach ($member in $EnterpriseMembers) {
                    Add-Content -Path "$outputdir\enterprise_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
                }
            }
        } catch {
            Write-Both "    [i] Enterprise Admins not available in this domain (expected in child domains)"
        }
    } else {
        Write-Both "    [i] Enterprise Admins not available (child domain)"
    }

    try {
        $DomainAdminsMembers = Get-ADGroup $DomainAdmins -ErrorAction Stop | Get-ADGroupMember -ErrorAction Stop
        foreach ($member in $DomainAdminsMembers) {
            Add-Content -Path "$outputdir\domain_admins.txt" -Value "$($member.objectClass) $($member.SamAccountName) $($member.Name)"
        }
    } catch {
        Write-Both "    [!] Error retrieving Domain Admins members: $($_.Exception.Message)"
    }
}
Function Get-DCEval {
    #Basic validation of all DCs in forest
    #Collect all DCs in forest
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    #Validate OS version of DCs
    $osList = @()
    $ADs | ForEach-Object { $osList += $_.OperatingSystem }
    if (($osList | sort -Unique | measure).Count -eq 1) {
        Write-Both "    [+] All DCs are the same OS version of $($osList | sort -Unique)"
    }
    else {
        Write-Both "    [!] Operating system differs across DCs!!!"
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2003' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2003"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2003' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2008 !(R2)' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2008"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2008 !(R2)' } | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2008 R2' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2008 R2" ; $ADs | Where-Object { $_.OperatingSystem -Match '2008 R2' }    | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2012 !(R2)' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2012"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2012 !(R2)' } | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2012 R2' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2012 R2" ; $ADs | Where-Object { $_.OperatingSystem -Match '2012 R2' }    | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2016' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2016"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2016' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2019' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2019"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2019' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
        if (($ADs | Where-Object { $_.OperatingSystem -Match '2022' }) -ne $null) { Write-Both "        [+] Domain controllers with WS 2022"    ; $ADs | Where-Object { $_.OperatingSystem -Match '2022' }       | ForEach-Object { Write-Both "            [-] $($_.Name) has $($_.OperatingSystem)" } }
    }
    #Validate DCs hotfix level
    if ( (( $ADs | Select-Object OperatingSystemHotfix -Unique ) | measure).count -eq 1 -or ( $ADs | Select-Object OperatingSystemHotfix -Unique ) -eq $null ) {
        Write-Both "    [+] All DCs have the same hotfix of [$($ADs | Select-Object OperatingSystemHotFix -Unique | ForEach-Object {$_.OperatingSystemHotfix})]"
    }
    else {
        Write-Both "    [!] Hotfix level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) hotfix [$($_.OperatingSystemHotfix)]"
        }
    }
    #Validate DCs Service Pack level
    if ((($ADs | Select-Object OperatingSystemServicePack -Unique) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemServicePack -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same Service Pack of [$($ADs | Select-Object OperatingSystemServicePack -Unique | ForEach-Object {$_.OperatingSystemServicePack})]"
    }
    else {
        Write-Both "    [!] Service Pack level differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) Service Pack [$($_.OperatingSystemServicePack)]"
        }
    }
    #Validate DCs OS Version
    if ((($ADs | Select-Object OperatingSystemVersion -Unique ) | measure).count -eq 1 -or ($ADs | Select-Object OperatingSystemVersion -Unique) -eq $null) {
        Write-Both "    [+] All DCs have the same OS Version of [$($ADs | Select-Object OperatingSystemVersion -Unique | ForEach-Object {$_.OperatingSystemVersion})]"
    }
    else {
        Write-Both "    [!] OS Version differs across DCs!!!"
        $ADs | ForEach-Object {
            Write-Both "        [-] DC $($_.Name) OS Version [$($_.OperatingSystemVersion)]"
        }
    }
    #List sites without GC
    $SitesWithNoGC = $false
    foreach ($Site in $Forest.Sites) {
        if (($ADs | Where-Object { $_.Site -eq $Site.Name } | Where-Object { $_.IsGlobalCatalog -eq $true }) -eq $null) {
            $SitesWithNoGC = $true
            Add-Content -Path "$outputdir\sites_no_gc.txt" -Value "$($Site.Name)"
        }
    }
    if ($SitesWithNoGC -eq $true) {
        Write-Both "    [!] You have sites with no Global Catalog!"
    }
    #Does one DC holds all FSMO
    if (($ADs | Where-Object { $_.OperationMasterRoles -ne $null } | measure).count -eq 1) {
        Write-Both "    [!] DC $($ADs | Where-Object {$_.OperationMasterRoles -ne $null} | select -ExpandProperty Hostname) holds all FSMO roles!"
    }
    #DCs with weak Kerberos algorithm (*CH* Changed below to look for msDS-SupportedEncryptionTypes to work with 2008R2)
    $ADcomputers = $ADs | ForEach-Object { Get-ADComputer $_.Name -Properties msDS-SupportedEncryptionTypes }
    $WeakKerberos = $false
    foreach ($DC in $ADcomputers) {
        #Value 8 stands for AES-128, value 16 stands for AES-256 and value 24 stands for AES-128 & AES-256
        #Values 0 to 7, 9 to 15, 17 to 23 and 25 to 31 include RC4 and/or DES
        #See https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797
        if ($DC."msDS-SupportedEncryptionTypes" -ne 8 -and $DC."msDS-SupportedEncryptionTypes" -ne 16 -and $DC."msDS-SupportedEncryptionTypes" -ne 24) {
            $WeakKerberos = $true
            Add-Content -Path "$outputdir\dcs_weak_kerberos_ciphersuite.txt" -Value "$($DC.DNSHostName) $($dc."msDS-SupportedEncryptionTypes")"
        }
    }
    if ($WeakKerberos) {
        Write-Both "    [!] You have DCs with RC4 or DES allowed for Kerberos!!!"
        Write-Nessus-Finding "WeakKerberosEncryption" "KB995" ([System.IO.File]::ReadAllText("$outputdir\dcs_weak_kerberos_ciphersuite.txt"))
    }
    #Check where newly joined computers go
    $newComputers = (Get-ADDomain).ComputersContainer
    $newUsers = (Get-ADDomain).UsersContainer
    Write-Both "    [+] New joined computers are stored in $newComputers"
    Write-Both "    [+] New users are stored in $newUsers"
}
Function Get-DefaultDomainControllersPolicy {
    #Enumerates Default Domain Controllers Policy for default unsecure and excessive options
    $ExcessiveDCInteractiveLogon = $false
    $ExcessiveDCBackupPermissions = $false
    $ExcessiveDCRestorePermissions = $false
    $ExcessiveDCDriverPermissions = $false
    $ExcessiveDCLocalShutdownPermissions = $false
    $ExcessiveDCRemoteShutdownPermissions = $false
    $ExcessiveDCTimePermissions = $false
    $ExcessiveDCBatchLogonPermissions = $false
    $ExcessiveDCRDPLogonPermissions = $false
    try {
        $GPO = Get-GPO 'Default Domain Controllers Policy' -ErrorAction Stop
    } catch {
        try {
            # Well-known GUID for Default Domain Controllers Policy (locale-independent)
            $GPO = Get-GPO -Guid '6AC1786C-016F-11D2-945F-00C04fB984F9' -ErrorAction Stop
        } catch {
            Write-Both "    [!] Default Domain Controllers Policy GPO not found by name or GUID. Skipping DC policy audit."
            return
        }
    }
    $GPOreport = Get-GPOReport -Guid $GPO.Id -ReportType Xml
    #Interactive local logon
    $permissionindex = $GPOreport.IndexOf('SeInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCInteractiveLogon = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Batch logon
    $permissionindex = $GPOreport.IndexOf('SeBatchLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBatchLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBatchLogonPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBatchLogonRight $($member.Name.'#text')"
            }
        }
    }
    #RDP logon
    $permissionindex = $GPOreport.IndexOf('SeRemoteInteractiveLogonRight')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteInteractiveLogonRight' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$EntrepriseDomainControllers") {
                $ExcessiveDCRDPLogonPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteInteractiveLogonRight $($member.Name.'#text')"
            }
        }
    }
    #Backup
    $permissionindex = $GPOreport.IndexOf('SeBackupPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeBackupPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCBackupPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeBackupPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Restore
    $permissionindex = $GPOreport.IndexOf('SeRestorePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRestorePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRestorePermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRestorePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Load driver
    $permissionindex = $GPOreport.IndexOf('SeLoadDriverPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeLoadDriverPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCDriverPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeLoadDriverPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Local shutdown
    $permissionindex = $GPOreport.IndexOf('SeShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCLocalShutdownPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Remote shutdown
    $permissionindex = $GPOreport.IndexOf('SeRemoteShutdownPrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeRemoteShutdownPrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators") {
                $ExcessiveDCRemoteShutdownPermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeRemoteShutdownPrivilege $($member.Name.'#text')"
            }
        }
    }
    #Change time
    $permissionindex = $GPOreport.IndexOf('SeSystemTimePrivilege')
    if ($permissionindex -gt 0 -and $GPO.DisplayName -eq 'Default Domain Controllers Policy') {
        $xmlreport = [xml]$GPOreport
        foreach ($member in (($xmlreport.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.Name -eq 'SeSystemTimePrivilege' }).Member)) {
            if ($member.Name.'#text' -ne "BUILTIN\$Administrators" -and $member.Name.'#text' -ne "$LocalService") {
                $ExcessiveDCTimePermissions = $true
                Add-Content -Path "$outputdir\default_domain_controller_policy_audit.txt" -Value "SeSystemTimePrivilege $($member.Name.'#text')"
            }
        }
    }
    #Output for Default Domain Controllers Policy
    if ($ExcessiveDCInteractiveLogon -or $ExcessiveDCBackupPermissions -or $ExcessiveDCRestorePermissions -or $ExcessiveDCDriverPermissions -or $ExcessiveDCLocalShutdownPermissions -or $ExcessiveDCRemoteShutdownPermissions -or $ExcessiveDCTimePermissions -or $ExcessiveDCBatchLogonPermissions -or $ExcessiveDCRDPLogonPermissions) {
        Write-Both "    [!] Excessive permissions in Default Domain Controllers Policy detected!"
    }
}
Function Get-RecentChanges() {
    #Retrieve users and groups that have been created during last 30 days
    $DateCutOff = ((Get-Date).AddDays(-30)).Date
    $newUsers = Get-ADUser  -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $newGroups = Get-ADGroup -Filter { whenCreated -ge $DateCutOff } -Properties whenCreated | select whenCreated, SamAccountName
    $countUsers = 0
    $countGroups = 0
    $progresscountUsers = 0
    $progresscountGroups = 0
    $totalcountUsers = ($newUsers  | Measure-Object | Select-Object Count).count
    $totalcountGroups = ($newGroups | Measure-Object | Select-Object Count).count
    if ($totalcountUsers -gt 0) {
        foreach ($newUser in $newUsers ) { Add-Content -Path "$outputdir\new_users.txt" -Value "Account $($newUser.SamAccountName) was created $($newUser.whenCreated)" }
        Write-Both "    [!] $totalcountUsers new users were created last 30 days, see $outputdir\new_users.txt"
    }
    if ($totalcountGroups -gt 0) {
        foreach ($newGroup in $newGroups ) { Add-Content -Path "$outputdir\new_groups.txt" -Value "Group $($newGroup.SamAccountName) was created $($newGroup.whenCreated)" }
        Write-Both "    [!] $totalcountGroups new groups were created last 30 days, see $outputdir\new_groups.txt"
    }
}
Function Get-IncidentResponseSecurityEvents() {
    # Correlates high-value Security log events for post-incident AD triage.
    $lookbackDays = 30
    $startTime = (Get-Date).AddDays(-$lookbackDays)
    $eventIds = @(4720, 4728, 4732, 4756)
    $records = [System.Collections.Generic.List[object]]::new()

    function Write-SecurityEvidencePlaceholder {
        param(
            [string]$Status,
            [string]$Reason
        )
        try {
            $evDir = Join-Path $outputdir 'evidence'
            if (!(Test-Path -LiteralPath $evDir)) { New-Item -ItemType Directory -Path $evDir | Out-Null }
            'timestamp_utc,event_id,action,actor,target,group_name,dc_name,record_id,details' | Out-File "$outputdir\security_events.csv" -Encoding UTF8
            'timestamp_utc,event_id,action,actor,target,group_name,dc_name,record_id,details' | Out-File "$evDir\security_events.csv" -Encoding UTF8
            [ordered]@{
                status          = $Status
                reason          = $Reason
                lookback_days   = $lookbackDays
                start_time_utc  = $startTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                event_ids       = @($eventIds)
                generated_at_utc= (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            } | ConvertTo-Json -Depth 6 | Out-File "$evDir\security_events.json" -Encoding UTF8
        } catch {}
    }

    try {
        $events = @(
            Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$eventIds; StartTime=$startTime } -ErrorAction Stop |
            Sort-Object TimeCreated
        )
    } catch {
        $err = $_.Exception.Message
        Write-Both "    [!] Could not read Security log events (4720/4728/4732/4756): $err"
        Write-SecurityEvidencePlaceholder -Status 'not_evaluated' -Reason $err
        New-Finding `
            -CheckId           'AD-IR-SEC-001' `
            -CheckName         'Incident Response Security Event Correlation' `
            -Category          'incident_response' `
            -Subcategory       'security_events' `
            -Title             'Security Event Correlation Not Evaluated' `
            -Description       'Could not query Security event log for account creation and privileged group membership changes.' `
            -Severity          'medium' `
            -Confidence        'high' `
            -Impact            'medium' `
            -RemediationEffort 'low' `
            -Status            'not_evaluated' `
            -Scope             'domain' `
            -AffectedCount     0 `
            -NotEvaluatedReason $err `
            -Evidence          "Get-WinEvent failed: $err" `
            -Recommendation    'Run as local administrator with Security log read permissions and re-run incident-response mode.' `
            -References        @('Event ID 4720', 'Event ID 4728', 'Event ID 4732', 'Event ID 4756') `
            -Tags              @('incident-response','security-events','not-evaluated') |
        Add-Finding
        return
    }

    $userCreatedRows = [System.Collections.Generic.List[object]]::new()
    $privMembershipRows = [System.Collections.Generic.List[object]]::new()

    foreach ($evt in $events) {
        $eventData = @{}
        try {
            $xml = [xml]$evt.ToXml()
            foreach ($d in @($xml.Event.EventData.Data)) {
                if ($null -eq $d) { continue }
                $name = [string]$d.Name
                if ([string]::IsNullOrWhiteSpace($name)) { continue }
                $eventData[$name] = [string]$d.'#text'
            }
        } catch {}

        $subjectUser   = if ($eventData.ContainsKey('SubjectUserName'))   { [string]$eventData['SubjectUserName'] }   else { '' }
        $subjectDomain = if ($eventData.ContainsKey('SubjectDomainName')) { [string]$eventData['SubjectDomainName'] } else { '' }
        $actor = if (-not [string]::IsNullOrWhiteSpace($subjectUser) -and -not [string]::IsNullOrWhiteSpace($subjectDomain)) {
            "$subjectDomain\$subjectUser"
        } elseif (-not [string]::IsNullOrWhiteSpace($subjectUser)) {
            $subjectUser
        } else {
            'unknown'
        }

        $targetUser = if ($eventData.ContainsKey('TargetUserName')) { [string]$eventData['TargetUserName'] } else { '' }
        $memberName = if ($eventData.ContainsKey('MemberName'))     { [string]$eventData['MemberName'] }     else { '' }
        $memberSid  = if ($eventData.ContainsKey('MemberSid'))      { [string]$eventData['MemberSid'] }      else { '' }
        if ([string]::IsNullOrWhiteSpace($memberName)) { $memberName = $memberSid }

        $action = 'tracked_event'
        $target = $targetUser
        $groupName = ''
        $details = 'Tracked Security event'

        switch ([int]$evt.Id) {
            4720 {
                $action = 'user_created'
                $target = $targetUser
                $details = 'A user account was created.'
            }
            4728 {
                $action = 'member_added_global_group'
                $target = $memberName
                $groupName = $targetUser
                $details = 'A member was added to a security-enabled global group.'
            }
            4732 {
                $action = 'member_added_local_group'
                $target = $memberName
                $groupName = $targetUser
                $details = 'A member was added to a security-enabled local group.'
            }
            4756 {
                $action = 'member_added_universal_group'
                $target = $memberName
                $groupName = $targetUser
                $details = 'A member was added to a security-enabled universal group.'
            }
        }

        $record = [PSCustomObject]@{
            timestamp_utc = if ($evt.TimeCreated) { $evt.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            event_id      = [int]$evt.Id
            action        = $action
            actor         = $actor
            target        = $target
            group_name    = $groupName
            dc_name       = $evt.MachineName
            record_id     = $evt.RecordId
            details       = $details
        }

        $records.Add($record)
        if ([int]$evt.Id -eq 4720) { $userCreatedRows.Add($record) }
        if ([int]$evt.Id -in @(4728,4732,4756)) { $privMembershipRows.Add($record) }
    }

    try {
        if ($records.Count -gt 0) {
            @($records) | Export-Csv -Path "$outputdir\security_events.csv" -NoTypeInformation -Encoding UTF8
        } else {
            'timestamp_utc,event_id,action,actor,target,group_name,dc_name,record_id,details' | Out-File "$outputdir\security_events.csv" -Encoding UTF8
        }
        Write-Both "    [+] Security events exported: $outputdir\security_events.csv"
    } catch {
        Write-Both "    [!] security_events.csv export failed: $($_.Exception.Message)"
    }

    try {
        $evDir = Join-Path $outputdir 'evidence'
        if (!(Test-Path -LiteralPath $evDir)) { New-Item -ItemType Directory -Path $evDir | Out-Null }
        [ordered]@{
            generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            lookback_days    = $lookbackDays
            start_time_utc   = $startTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            event_ids        = @($eventIds)
            totals           = [ordered]@{
                total_events                  = $records.Count
                user_creations                = $userCreatedRows.Count
                privileged_group_membership_additions = $privMembershipRows.Count
            }
            events = @($records)
        } | ConvertTo-Json -Depth 8 | Out-File "$evDir\security_events.json" -Encoding UTF8
        if ($records.Count -gt 0) {
            @($records) | Export-Csv -Path "$evDir\security_events.csv" -NoTypeInformation -Encoding UTF8
        } else {
            'timestamp_utc,event_id,action,actor,target,group_name,dc_name,record_id,details' | Out-File "$evDir\security_events.csv" -Encoding UTF8
        }
        Write-Both "    [+] evidence/security_events.json"
        Write-Both "    [+] evidence/security_events.csv"
    } catch {
        Write-Both "    [!] evidence/security_events export failed: $($_.Exception.Message)"
    }

    $userAffected = @(
        $userCreatedRows |
        ForEach-Object { if ($_.target) { $_.target } } |
        Select-Object -Unique -First 50
    )
    $privAffected = @(
        $privMembershipRows |
        ForEach-Object {
            $member = if ($_.target) { $_.target } else { 'unknown-member' }
            $group  = if ($_.group_name) { $_.group_name } else { 'unknown-group' }
            "$member -> $group"
        } |
        Select-Object -Unique -First 50
    )

    if ($userCreatedRows.Count -gt 0) {
        New-Finding `
            -CheckId           'AD-IR-SEC-002' `
            -CheckName         'Recent User Account Creations' `
            -Category          'incident_response' `
            -Subcategory       'security_events' `
            -Title             'Recent User Account Creations Detected (Event ID 4720)' `
            -Description       "Detected user account creation events in the last $lookbackDays days." `
            -Severity          'medium' `
            -Confidence        'high' `
            -Impact            'medium' `
            -RemediationEffort 'medium' `
            -Status            'warning' `
            -Scope             'domain' `
            -AffectedCount     $userCreatedRows.Count `
            -AffectedObjects   $userAffected `
            -Evidence          "Review evidence/security_events.csv for actor and target mapping." `
            -Recommendation    'Validate each created account against approved change records. Disable suspicious accounts and rotate impacted credentials.' `
            -References        @('Event ID 4720') `
            -Tags              @('incident-response','security-events','account-creation') |
        Add-Finding
    } else {
        New-Finding `
            -CheckId           'AD-IR-SEC-002' `
            -CheckName         'Recent User Account Creations' `
            -Category          'incident_response' `
            -Subcategory       'security_events' `
            -Title             'No Recent User Account Creations Detected (Event ID 4720)' `
            -Description       "No user creation events were detected in the last $lookbackDays days." `
            -Severity          'informational' `
            -Confidence        'high' `
            -Impact            'low' `
            -RemediationEffort 'low' `
            -Status            'passed' `
            -Scope             'domain' `
            -AffectedCount     0 `
            -Evidence          "Evaluated Security log for Event ID 4720 since $($startTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))." `
            -Recommendation    'Continue periodic monitoring of account creation events.' `
            -References        @('Event ID 4720') `
            -Tags              @('incident-response','security-events','account-creation') |
        Add-Finding
    }

    if ($privMembershipRows.Count -gt 0) {
        New-Finding `
            -CheckId           'AD-IR-SEC-003' `
            -CheckName         'Privileged Group Membership Additions' `
            -Category          'incident_response' `
            -Subcategory       'security_events' `
            -Title             'Recent Security Group Membership Additions Detected (Event IDs 4728/4732/4756)' `
            -Description       "Detected security-enabled group membership additions in the last $lookbackDays days." `
            -Severity          'high' `
            -Confidence        'high' `
            -Impact            'high' `
            -RemediationEffort 'medium' `
            -Status            'failed' `
            -Scope             'domain' `
            -AffectedCount     $privMembershipRows.Count `
            -AffectedObjects   $privAffected `
            -Evidence          "Review evidence/security_events.csv for actor/member/group triplets and timestamps." `
            -Recommendation    'Investigate each membership addition as potential persistence. Remove unauthorized memberships and reset credentials for exposed principals.' `
            -References        @('Event ID 4728', 'Event ID 4732', 'Event ID 4756') `
            -Tags              @('incident-response','security-events','group-membership','persistence') |
        Add-Finding
    } else {
        New-Finding `
            -CheckId           'AD-IR-SEC-003' `
            -CheckName         'Privileged Group Membership Additions' `
            -Category          'incident_response' `
            -Subcategory       'security_events' `
            -Title             'No Recent Security Group Membership Additions Detected (Event IDs 4728/4732/4756)' `
            -Description       "No tracked security-enabled group membership additions were detected in the last $lookbackDays days." `
            -Severity          'informational' `
            -Confidence        'high' `
            -Impact            'low' `
            -RemediationEffort 'low' `
            -Status            'passed' `
            -Scope             'domain' `
            -AffectedCount     0 `
            -Evidence          "Evaluated Security log for Event IDs 4728/4732/4756 since $($startTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))." `
            -Recommendation    'Keep continuous monitoring for group membership changes in high-value groups.' `
            -References        @('Event ID 4728', 'Event ID 4732', 'Event ID 4756') `
            -Tags              @('incident-response','security-events','group-membership') |
        Add-Finding
    }
}
Function Get-ReplicationType {
    #Retrieve replication mechanism (FRS or DFSR)
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $DFSRFlags = (Get-ADObject -Identity "CN=DFSR-GlobalSettings,$((Get-ADDomain).systemscontainer)" -Properties msDFSR-Flags).'msDFSR-Flags'
        switch ($DFSRFlags) {
            0 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: started!" }
            16 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: prepared!" }
            32 { Write-Both "    [!] Migration from FRS to DFSR is not finished. Current state: redirected!" }
            48 { Write-Both "    [+] DFSR mechanism is used to replicate across domain controllers." }
        }
    }
    else {
        Write-Both "    [!] FRS mechanism is still used to replicate across domain controllers, you should migrate to DFSR!"
    }
}
Function Get-RecycleBinState {
    #Check if recycle bin is enabled
    if ((Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"').EnabledScopes) {
        Write-Both "    [+] Recycle Bin is enabled in the domain"
    }
    else {
        Write-Both "    [!] Recycle Bin is disabled in the domain, you should consider enabling it!"
    }
}
Function Get-CriticalServicesStatus {
    #Check AD services status
    Write-Both "    [+] Checking services on all DCs"
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $objectName = "DFSR-GlobalSettings"
    $searcher = [ADSISearcher] "(objectClass=msDFSR-GlobalSettings)"
    $objectExists = $searcher.FindOne() -ne $null
    if ($objectExists) {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntds", "dfsr")
    }
    else {
        $services = @("dns", "netlogon", "kdc", "w32time", "ntds", "ntfrs")
    }
    foreach ($DC in $dcList) {
        foreach ($service in $services) {
            $checkService = Get-Service $service -ComputerName $DC -ErrorAction SilentlyContinue
            $serviceName = $checkService.Name
            $serviceStatus = $checkService.Status
            if (!($serviceStatus)) {
                Write-Both "        [!] Service $($service) cannot be checked on $DC!"
            }
            elseif ($serviceStatus -ne "Running") {
                Write-Both "        [!] Service $($service) is not running on $DC!"
            }
        }
    }
}
Function Get-LastWUDate {
    #Check Windows update status and last install date
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    $lastMonth = (Get-Date).AddDays(-30)
    Write-Both "    [+] Checking Windows Update"
    foreach ($DC in $dcList) {

        $startMode = (Get-WmiObject -ComputerName $DC -Class Win32_Service -Property StartMode -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue).StartMode
        if (!($startMode)) {
            Write-Both "        [!] Windows Update service cannot be checked on $DC!"
        }
        elseif ($startMode -eq "Disabled") {
            Write-Both "        [!] Windows Update service is disabled on $DC!"
        }
    }
    $progresscount = 0
    $totalcount = ($dcList | Measure-Object | Select-Object Count).count
    foreach ($DC in $dcList) {
        if ($totalcount -eq 0) { break }
        Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Currently searching on $DC" -PercentComplete ($progresscount / $totalcount * 100)
        try {
            $lastHotfix = (Get-HotFix -ComputerName $DC | Where-Object { $_.InstalledOn -ne $null } | Sort-Object -Descending InstalledOn  | Select-Object -First 1).InstalledOn
            if ($lastHotfix -lt $lastMonth) {
                Write-Both "        [!] Windows is not up to date on $DC, last install: $($lastHotfix)"
            }
            else {
                Write-Both "        [+] Windows is up to date on $DC, last install: $($lastHotfix)"
            }
        }
        catch {
            Write-Both "        [!] Cannot check last update date on $DC"
        }
        $progresscount++
    }
    Write-Progress -Activity "Searching for last Windows Update installation on all DCs..." -Status "Ready" -Completed
}
Function Get-TimeSource {
    #Get NTP sync source
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking NTP configuration"
    foreach ($DC in $dcList) {
        $ntpSource = w32tm /query /source /computer:$DC
        if ($ntpSource -like '*0x800706BA*') {
            Write-Both "        [!] Cannot get time source for $DC"
        }
        else {
            Write-Both "        [+] $DC is syncing time from $ntpSource"
        }
    }
}
Function Get-RODC {
    #Check for RODC
    Write-Both "    [+] Checking for Read Only DCs"
    $ADs = Get-ADDomainController -Filter { Site -like "*" }
    $ADs | ForEach-Object {
        if ($_.IsReadOnly) {
            Write-Both "        [+] DC $($_.Name) is a RODC server!"
        }
    }
}
Function Install-Dependencies {
    #Install DSInternals
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch {
            Write-Both "    [!] Warning: Could not set TLS 1.2 protocol: $($_.Exception.Message)"
        }

        $count = 0
        $totalcount = 3
        Write-Progress -Activity "Installing dependencies..." -Status "Currently installing NuGet Package Provider" -PercentComplete ($count / $totalcount * 100)
        try {
            if (!(Get-PackageProvider -ListAvailable -Name Nuget -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop | Out-Null
            }
        } catch {
            Write-Both "    [!] Warning: Failed to install NuGet: $($_.Exception.Message)"
        }

        $count++
        Write-Progress -Activity "Installing dependencies..." -Status "Currently adding PSGallery to trusted Repositories" -PercentComplete ($count / $totalcount * 100)
        try {
            if ((Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy -eq "Untrusted") {
                Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction Stop
            }
        } catch {
            Write-Both "    [!] Warning: Failed to set PSGallery as trusted: $($_.Exception.Message)"
        }

        $count++
        Write-Progress -Activity "Installing dependencies..." -Status "Currently installing module DSInternals" -PercentComplete ($count / $totalcount * 100)
        try {
            if (!(Get-Module -ListAvailable -Name DSInternals -ErrorAction SilentlyContinue)) {
                Install-Module -Name DSInternals -Force -ErrorAction Stop
            }
            Import-Module DSInternals -ErrorAction Stop
            Write-Both "    [+] DSInternals module installed successfully"
        } catch {
            Write-Both "    [!] Warning: Failed to install DSInternals module: $($_.Exception.Message)"
        }

        Write-Progress -Activity "Installing dependencies..." -Status "Ready" -Completed
    }
    else {
        Write-Both "    [!] PowerShell 5 or greater is needed, see https://www.microsoft.com/en-us/download/details.aspx?id=54616"
    }
}
Function Remove-StringLatinCharacters {
    #Removes latin characters
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}
Function Get-PasswordQuality {
    #Use DSInternals to evaluate password quality
    if (Get-Module -ListAvailable -Name DSInternals) {
        try {
            $totalSite = (Get-ADObject -Filter { objectClass -like "site" } -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -ErrorAction Stop | measure).Count
            $count = 0
            Get-ADObject -Filter { objectClass -like "site" } -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -ErrorAction Stop | ForEach-Object {
                if ($_.Name -eq $(Remove-StringLatinCharacters $_.Name)) { $count++ }
            }
            if ($count -ne $totalSite) {
                Write-Both "    [!] One or more site have illegal characters in their name, can't get password quality!"
            }
            else {
                Get-ADReplAccount -All -Server $env:ComputerName -NamingContext $(Get-ADDomain | select -ExpandProperty DistinguishedName) -ErrorAction Stop | Test-PasswordQuality -IncludeDisabledAccounts | Out-File "$outputdir\password_quality.txt"
                Write-Both "    [!] Password quality test done, see $outputdir\password_quality.txt"
            }
        } catch {
            Write-Both "    [!] Error running password quality test: $($_.Exception.Message)"
        }
    }
}
Function Check-Shares {
    #Check SYSVOL and NETLOGON share exists
    $dcList = @()
    (Get-ADDomainController -Filter *) | ForEach-Object { $dcList += $_.Name }
    Write-Both "    [+] Checking SYSVOL and NETLOGON shares on all DCs"
    foreach ($DC in $dcList) {
        $shareList = (Get-WmiObject -Class Win32_Share -ComputerName $DC -ErrorAction SilentlyContinue)
        if (!($shareList)) {
            Write-Both "        [!] Cannot test shares on $DC!"
        }
        else {
            $sysvolShare = ($shareList | ? { $_ -match 'SYSVOL' }   | measure).Count
            $netlogonShare = ($shareList | ? { $_ -match 'NETLOGON' } | measure).Count
            if ($sysvolShare -eq 0) { Write-Both "        [!] SYSVOL share is missing on $DC!" }
            if ($netlogonShare -eq 0) { Write-Both "        [!] NETLOGON share is missing on $DC!" }
        }
    }
}

Function Get-ADCSVulns {
    #Check for ADCS Vulnerabiltiies, ESC1,2,3,4 and 8. ESC8 will output to a different issues mapped to Nessus.
    try {
        $certutil_output = certutil -v -template -ErrorAction Stop
    } catch {
        Write-Both "    [!] Error: Unable to enumerate certificate templates: $($_.Exception.Message)"
        Write-Both "    [!] Make sure you have the appropriate permissions and certutil is available"
        return
    }

    try {
        $certutil_lines = $certutil_output.Trim().Split("`n")
    $templates = @()
    foreach ($line in $certutil_lines) {
        if ($line.StartsWith("Template[")) {
            $template_unparsed = $current_template.TrimEnd(",").Split(",")
            $SuppliesSubjectCheck = $false
            $ClientAuthCheck = $false
            $AllowEnrollCheck = $false
            $AnyPurposeCheck = $false
            $AllowWriteCheck = $false
            $AllowFullControl = $false
            $CertificateRequestAgentCheck = $false

            $TemplatePropCommonName = $null
            foreach ($detail in $template_unparsed) {
                if ($detail -like "*TemplatePropCommonName =*") {
                    $TemplatePropCommonName = $detail.Split("=")[1].Trim()
                }
                if ($detail -like "*CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1*") {
                    $SuppliesSubjectCheck = $true
                }
                if ($detail -like "*Client Authentication*") {
                    $ClientAuthCheck = $true
                }
                if ($detail -match "^\s*Allow Enroll\s+.*\\Authenticated Users\s*$|^\s*Allow Enroll\s+.*\\Domain Users\s*$") {
                    $AllowEnrollCheck = $true
                }
                if ($detail -like "2.5.29.37.0 Any Purpose") {
                    $AnyPurposeCheck = $true
                }
                if ($detail -match "^\s*Allow Write\s+.*\\Authenticated Users\s*$|^\s*Allow Write\s+.*\\Domain Users\s*$") {
                    $AllowWriteCheck = $true
                }
                # Check for Allow Full Control
                if ($detail -match "^\s*Allow Full Control\s+.*\\Authenticated Users\s*$|^\s*Allow Full Control\s+.*\\Domain Users\s*$") {
                    $AllowFullControl = $true
                }
                if ($detail -like "Certificate Request Agent (1.3.6.1.4.1.311.20.2.1)") {
                    $CertificateRequestAgentCheck = $true
                }
                # Create object with details. Objectg name is TemplatePropCommonName
                $template = New-Object -TypeName PSObject -Property @{
                    "SuppliesSubjectCheck"         = $SuppliesSubjectCheck
                    "ClientAuthCheck"              = $ClientAuthCheck
                    "AllowEnrollCheck"             = $AllowEnrollCheck
                    "AnyPurposeCheck"              = $AnyPurposeCheck
                    "AllowWriteCheck"              = $AllowWriteCheck
                    "AllowFullControl"             = $AllowFullControl
                    "TemplatePropCommonName"       = $TemplatePropCommonName
                    "CertificateRequestAgentCheck" = $CertificateRequestAgentCheck
                }
            }
            $templates += $template
            $current_template = $line + ","
        }
        else {
            $current_template += $line + ","
        }
    }

    # Check for ESC1
    # ESC1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1 and  Client Authentication and ( enroll or full control )

    $ESC1 = @()
    $ESC1e = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowEnrollCheck }
    $ESC1f = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowFullControl }
    $ESC1w = $templates | Where-Object { $_.SuppliesSubjectCheck -and $_.ClientAuthCheck -and $_.AllowWriteCheck }
    $ESC1 += $ESC1e
    $ESC1 += $ESC1f
    $ESC1 += $ESC1w
    # Remove duplicates
    $ESC1 = $ESC1 | Select-Object -Property TemplatePropCommonName -unique
    $ESC2 = $templates | Where-Object { $_.AnyPurposeCheck -and $_.AllowEnrollCheck }
    $ESC3 = $templates | Where-Object { $_.CertificateRequestAgentCheck -and $_.AllowEnrollCheck }
    $ESC4 = $templates | Where-Object { $_.AllowWriteCheck -or $_.AllowFullControl }

    $template_path = $outputdir + "\vulnerable_templates.txt"
    $web_enrollmeent_path = $outputdir + "\web_enrollment.txt"

    foreach ($template in $ESC1) {
        $ESC1line = "ESC1 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC1line
        Write-Both '    [!]'$ESC1line
    }
    foreach ($template in $ESC2) {
        $ESC2line = "ESC2 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC2line
        Write-Both '    [!]'$ESC2line
    }
    foreach ($template in $ESC3) {
        $ESC3line = "ESC3 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC3line
        Write-Both '    [!]'$ESC3line
    }
    foreach ($template in $ESC4) {
        $ESC4line = "ESC4 Vulnerable Templates:" + $template.TemplatePropCommonName
        add-content -path $template_path -value $ESC4line
        Write-Both '    [!]'$ESC4line
    }
    } catch {
        Write-Both "    [!] Error parsing certificate templates: $($_.Exception.Message)"
    }

    # ESC8 Check, If error 401 and response is unauthorized, then vulnerable
    try {
        $certInfo = & certutil
        $serverName = ($certInfo | Select-String 'Server:' | Select-Object -First 1).ToString().Split(':')[1].Trim().Replace('"', '')
        $response = Invoke-WebRequest -Uri ("http://$serverName/certsrv/") -ErrorAction Stop
        $response
    }
    catch {
        # If error and response is unauthorised, then vulnerable
        if ($_.Exception.Response.StatusCode -eq 401) {
            Add-Content -Path $web_enrollmeent_path -Value "ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
            Write-Both "    [!] ESC8 Vulnerable: Endpoint located at http://$serverName/certsrv/"
        }
        else {
            Write-Both "    [+] ESC8 not vulnerable"
        }
    }
    if (Test-Path "$outputdir\web_enrollment.txt") {
        Write-Nessus-Finding "Active Directory Certificate Service Web Enrollment Enabled in HTTP" "KB1095" ([System.IO.File]::ReadAllText("$outputdir\web_enrollment.txt"))
    }
    if (Test-Path "$outputdir\vulnerable_templates.txt") {
        Write-Nessus-Finding "Active Directory Certificate Service Vulnerable Templates" "KB1096" ([System.IO.File]::ReadAllText("$outputdir\vulnerable_templates.txt"))
    }
}

Function Get-SPNs {
    $default_groups = @("Domain Admins", "Domain Admins", "Enterprise Admins", "Schema Admins", "Domain Controllers", "Backup Operators", "Account Operators", "Server Operators", "Print Operators", "Remote Desktop Users", "Network Configuration Operators", "Exchange Organization Admins", "Exchange View-Only Admins", "Exchange Recipient Admins", "Exchange Servers", "Exchange Trusted Subsystem", "Exchange Public Folder Admins", "Exchange UM Management")
    $base_groups = @()
    foreach ($group in $default_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
            $base_groups += $ADGrp.Name
        }
        catch {
            $base_groups = $base_groups | Where-Object { $_ -ne $group }
        }
    }

    $all_groups = $base_groups
    foreach ($group in $default_groups) {
        try {
            $ADGrp = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
            $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))"
            foreach ($result in $QueryResult) {
                $all_groups += $result.Name
            }
        }
        catch {}
    }

#    while ($base_groups.count -gt 0) {
#        $new_groups = @()
#        foreach ($group in $base_groups) {
#            # I dont want to see errors if a group is not found
#            try {
#                $ADGrp = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
#                $QueryResult = Get-ADGroup -LDAPFilter "(&(objectCategory=group)(memberof=$($ADGrp.DistinguishedName)))"
#                foreach ($result in $QueryResult) {
#                    $all_groups += $result.Name
#                    $new_groups += $result.Name
#                }
#            }
#            catch {
#                # Remove group from all_groups
#                $all_groups = $all_groups | Where-Object { $_ -ne $group }
#            }
#        }
#        $base_groups = $new_groups
#    }
#    
    $SPNs = Get-ADObject -Filter { serviceprincipalname -like "*" } -Properties MemberOf |
    Where-Object { $_.ObjectClass -eq "user" } |
    ForEach-Object {
        $groups = $_.MemberOf | Get-ADObject | Where-Object { $_.ObjectClass -eq "group" }
        $_ | Select-Object Name, @{ Name = "Groups"; Expression = { $groups.Name -join ',' } }
    }

    # for spn in spns check if a group in spn.groups is in all_groups
    $high_value_users = @()
    foreach ($spn in $SPNs) {
        $spn_groups = $spn.Groups.Split(',')
        $name = $spn.Name
        foreach ($spn_group in $spn_groups) {
            if ($all_groups -contains $spn_group) {
                # Create object with user and group
                # Add object to high_value_users if the user.name is not already in the list
                $user = New-Object -TypeName PSObject -Property @{
                    Name  = $name
                    Group = $spn_group
                }
                if ($high_value_users.Name -notcontains $name) {
                    $high_value_users += $user
                }
            }
        }
    }

    foreach ($user in $high_value_users) {
        $kerbuser = '    [!] High value kerberoastable user: ' + $user.Name + ' in groups: ' + $user.Group
        Write-both $kerbuser
        add-content -path $outputdir\SPNs.txt -value $user.Name
    }

    # Only write Nessus finding if SPNs were actually found
    if (Test-Path "$outputdir\SPNs.txt") {
        Write-Nessus-Finding  "Kerberoast Attack - Services Configured With a Weak Password" "KB611" ([System.IO.File]::ReadAllText("$outputdir\SPNs.txt"))
    } else {
        Write-Both "    [+] No high-value kerberoastable accounts found"
    }
}

function Get-ADUsersWithoutPreAuth {
    $ASREP = Get-ADUser -Filter * -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.DoesNotRequirePreAuth -eq "True" -and $_.Enabled -eq "True" } | Select-Object Name
    foreach ($user in $ASREP) {
        $asrepuser = '    [!] AS-REP Roastable user: ' + $user.Name
        Write-both $asrepuser
        add-content -path $outputdir\ASREP.txt -value $user.Name
    }
    if (-not (Test-Path "$outputdir\ASREP.txt") -or !(Get-Content "$outputdir\ASREP.txt")) {
        Write-Both "    [+] No ASREP Accounts"
    }
    else {
        Write-Nessus-Finding "AS-REP Roasting Attack" "KB720" ([System.IO.File]::ReadAllText("$outputdir\ASREP.txt"))
    }
}

function Get-LDAPSecurity {
    # Check if LDAP signing is enabled
    $computerName = $env:COMPUTERNAME
    
    # Check if LDAP signing is enabled
    try {
        $ldapSigning = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -Name "LDAPServerIntegrity" -ErrorAction Stop).LDAPServerIntegrity

        if ($ldapSigning -eq 2) {
            Write-both "    [+] LDAP signing is enabled on $computerName"
        }
        else {
            Write-Both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry value is currently set to $ldapSigning."
            Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
        }
    }
    catch {
        Write-both "    [!] Issue identified LDAP signing is not enabled on $computerName, the registry key does not exist."
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAP signing is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAP signing is not enabled on $computerName, the registry key does not exist"
    }

    # Check if LDAPS is configured
    $serverAuthOid = '1.3.6.1.5.5.7.3.1'
    $ldapsCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date) -and
        (
            $_.Extensions |
            Where-Object {
                $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
                ($_.EnhancedKeyUsages | Where-Object { $_.Value -eq $serverAuthOid })
            }
        )
    }

    if ($ldapsCert) {
        Write-Both "    [+] LDAPS is configured on $computerName"
    } else {
        Write-Both "    [!] Issue identified LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS is not configured on $computerName, LDAPs certificates are not configured"
    }


    # Check if LDAPS Channel binding is enabled
    try {
        $ldapsBinding = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction Stop).LdapEnforceChannelBinding

        if ($ldapsBinding -eq 2) {
            Write-both "    [+] LDAPS channel binding is enabled on $computerName"
        }
        else {
            Write-both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, currently set to $ldapsBinding"
        }
    }
    catch {
        Write-both "    [!] Issue identified LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Add-Content -Path $outputdir\LDAPSecurity.txt -Value "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
        Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "LDAPS channel binding is not enabled on $computerName, the registry key does not exist"
    }


    # Check for LDAP null sessions (anonymous bind with effective read)
    $Server = Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName -First 1
    $Port   = 389  # Use 636 + SSL if you want to test LDAPS

    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols

        # Create LDAP connection (explicit host/port)
        $id   = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)

        # Force a true anonymous bind (no fallback to current logon)
        $conn.AuthType   = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $conn.Credential = [System.Net.NetworkCredential]::new($null, $null)
        $conn.Timeout    = [TimeSpan]::FromSeconds(5)
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
        # For LDAPS testing, uncomment and set $Port=636:
        # $conn.SessionOptions.SecureSocketLayer = $true
        # (Lab-only) ignore cert trust:
        # $conn.SessionOptions.VerifyServerCertificate = { param($c,$cert) $true }

        # Anonymous bind
        $conn.Bind()

     # Discover default naming context from RootDSE (safe for discovery only)
        $rootReq = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", "Base", "defaultNamingContext")
        $rootRes = $conn.SendRequest($rootReq)

        $defaultNC = $null
        if ($rootRes -and $rootRes.Entries.Count -gt 0) {
            $entry = $rootRes.Entries[0]
            if ($entry.Attributes -and $entry.Attributes.Contains("defaultNamingContext")) {
                $vals = $entry.Attributes["defaultNamingContext"].GetValues([string])
                if ($vals -and $vals.Count -gt 0) { $defaultNC = $vals[0] }
            }
        }

        if (-not $defaultNC) {
         Write-Both "    [+] LDAP null session not useful on $Server`:$Port (no naming context visible)"
         Add-Content -Path (Join-Path $outputdir 'LDAPSecurity.txt') -Value "Anonymous bind present but NC not visible on $Server`:$Port"
         return
        }

        # Attempt a real directory read under default NC (no paging; limit to 1 entry)
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest(
            $defaultNC,
            "(objectClass=*)",
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            @("distinguishedName")
        )
        $req.SizeLimit = 1
        $req.TimeLimit = [TimeSpan]::FromSeconds(3)

        $res = $conn.SendRequest($req)

        if ($res.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success -and
            $res.Entries.Count -gt 0) {

            Write-Both "    [!] LDAP anonymous (null) bind allows directory READ on $Server`:$Port"
            Add-Content -Path (Join-Path $outputdir 'LDAPSecurity.txt') -Value "Anonymous bind allows directory read on $Server`:$Port"
            Write-Nessus-Finding "Weak LDAP Settings" "KB1101" "Anonymous LDAP bind allows directory read on $Server`:$Port"

        } else {
            Write-Both ("    [+] LDAP null session not allowed/useful on {0}:{1} - Result: {2} ({3}) Msg: {4}" -f `
             $Server, $Port, [int]$res.ResultCode, $res.ResultCode, $res.ErrorMessage)
        }
    }
    catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        # Typically indicates anonymous bind succeeded, but search was blocked (your DSID-0C090D44 case)
        $resp = $_.Exception.Response
        if ($resp) {
         Write-Both ("    [+] LDAP null session not allowed/useful on {0}:{1} - Result: {2} ({3}) Msg: {4}" -f `
                $Server, $Port, [int]$resp.ResultCode, $resp.ResultCode, $resp.ErrorMessage)
            Add-Content -Path (Join-Path $outputdir 'LDAPSecurity.txt') -Value "Anonymous bind present but read blocked on $Server`:$Port"
        } else {
            Write-Both "    [+] LDAP null session not allowed/useful on $Server`:$Port (directory operation blocked)"
        }
    }
    catch [System.DirectoryServices.Protocols.LdapException] {
        switch ($_.Exception.ErrorCode) {
            49 {  # InvalidCredentials -> anonymous fully disabled
                Write-Both "    [+] LDAP anonymous bind NOT allowed on $Server`:$Port (InvalidCredentials)"
            }
            8 {   # StrongerAuthRequired -> signing/TLS required; try LDAPS if you want to check further
                Write-Both "    [+] LDAP anonymous bind refused on $Server`:$Port (StrongerAuthRequired - signing/LDAPS required)"
            }
            default {
                Write-Both ("    [i] LDAP error on {0}:{1} - {2} (code {3})" -f $Server, $Port, $_.Exception.Message, $_.Exception.ErrorCode)
            }
        }
    }
    finally {
        if ($conn) { $conn.Dispose() }
    }

}

function Find-DangerousACLPermissions {
    #Specify the ACLs and Groups to check against
    $dangerousAces = @('GenericAll', 'GenericWrite', 'ForceChangePassword', 'WriteDacl', 'WriteOwner', 'Delete')
    $groupsToCheck = @('NT AUTHORITY\Authenticated Users', 'DOMAIN\Domain Users', 'Everyone')

    # Find dangerous permissions on Computers
    $computers = Get-ADObject -Filter { objectClass -eq 'computer' -and objectCategory -eq 'computer' } -Properties *
    $computerResults = foreach ($computer in $computers) {
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*" -or $OSVersion -like "Windows Server 2025*") {
	$acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($computer.DistinguishedName)"} else {
	$acl = Get-Acl AD:\$computer}

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Computer'
                    ObjectName            = $computer
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on computers" -Status "Computers searched: $($computers.IndexOf($computer) + 1)/$($computers.Count)" -PercentComplete (($computers.IndexOf($computer) + 1) / $computers.Count * 100)
    }

    # Find dangerous permissions on groups
    $groups = Get-ADObject -Filter { objectClass -eq 'group' -and objectCategory -eq 'group' } -Properties *
    $groupResults = foreach ($group in $groups) {
        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*" -or $OSVersion -like "Windows Server 2025*") {
	$acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($group.DistinguishedName)"} else {
	$acl = Get-Acl AD:\$group}

        $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }

        if ($dangerousRules) {
            foreach ($rule in $dangerousRules) {
                [PSCustomObject]@{
                    ObjectType            = 'Group'
                    ObjectName            = $group
                    IdentityReference     = $rule.IdentityReference
                    AccessControlType     = $rule.AccessControlType
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights
                }
            }
        }
        Write-Progress -Activity "Searching for dangerous ACL permissions on groups" -Status "Groups searched: $($groups.IndexOf($group) + 1)/$($groups.Count)" -PercentComplete (($groups.IndexOf($group) + 1) / $groups.Count * 100)
    }
    # Find dangerous permissions on users
    $users = Get-ADObject -Filter { objectClass -eq 'user' -and objectCategory -eq 'person' } -Properties *

    $userResults = foreach ($user in $users) {
        $acl = $null

        if ($OSVersion -like "Windows Server 2019*" -or $OSVersion -like "Windows Server 2022*" -or $OSVersion -like "Windows Server 2025*") {
	$acl = Get-Acl -Path "Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/$($user.DistinguishedName)"} else {
	$acl = Get-Acl AD:\$user}

        if ($acl) {
            $dangerousRules = $acl.Access | Where-Object { $_.ActiveDirectoryRights -in $dangerousAces -and $_.IdentityReference -in $groupsToCheck }
            if ($dangerousRules) {
                foreach ($rule in $dangerousRules) {
                    [PSCustomObject]@{
                        ObjectType            = 'User'
                        ObjectName            = $user
                        IdentityReference     = $rule.IdentityReference
                        AccessControlType     = $rule.AccessControlType
                        ActiveDirectoryRights = $rule.ActiveDirectoryRights
                    }
                }
            }
            Write-Progress -Activity "Searching for dangerous ACL permissions on users" -Status "Users searched: $($users.IndexOf($user) + 1)/$($users.Count)" -PercentComplete (($users.IndexOf($user) + 1) / $users.Count * 100)
        }
    }

    # Output results
    if ($computerResults) {
        $computerResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "Computer" } }, @{ Label = "Computer Name"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $computerResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType | Out-File $outputdir\dangerousACL_Computer.txt -Encoding UTF8
        Write-Both "    [!] Issue identified, vulnerable ACL on Computer, see $outputdir\dangerousACL_Computer.txt"
        Write-Nessus-Finding "Weak Computer Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACL_Computer.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any computer."
    }

    if ($groupResults) {
        $groupResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "Group" } }, @{ Label = "Group Name"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $groupResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File $outputdir\dangerousACL_Groups.txt
        Write-Both "    [!] Issue identified, vulnerable ACL on Group, see $outputdir\dangerousACL_Groups.txt"
        Write-Nessus-Finding "Weak Group Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACL_Groups.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any group."
    }
    if ($userResults) {
        $userResults | ConvertTo-Html -Property @{ Label = "Type"; Expression = { "User" } }, @{ Label = "User"; Expression = { $_.ObjectName } }, @{ Label = "Allowed Group"; Expression = { $_.IdentityReference } }, AccessControlType, ActiveDirectoryRights | Out-File -Encoding UTF8 $outputdir\dangerousACLs.html -Append
        $userResults | Format-Table -AutoSize -Property ObjectType, ObjectName, IdentityReference, AccessControlType, ActiveDirectoryRights | Out-File $outputdir\dangerousACLUsers.txt
        Write-Both "    [!] Issue identified, vulnerable ACL on User, see $outputdir\dangerousACLUsers.txt"
        Write-Nessus-Finding "Weak User Permissions" "KB551" ([System.IO.File]::ReadAllText("$outputdir\dangerousACLUsers.txt"))
    }
    else {
        Write-Host "    [+] No dangerous ACL permissions were found on any user."
    }
}

# 
#  PHASE 1  STRUCTURED OUTPUT INFRASTRUCTURE
#  Collection: check registry, profiles, timeouts
#  Finding engine: New-Finding, Add-Finding, Add-NessusFinding
#  Module runner:  Invoke-AuditModule
#  Export layer:   execution.json, summary.json, findings.ndjson, findings.csv
# 

# --- Schema version ---
$script:SchemaVersion = "1.0"
$script:ToolName      = "LZ-ADaudit"
$script:ToolVersion   = $versionnum

# --- Check registry: KB code  normalized check metadata ---
$script:CheckRegistry = @{
    'KB258'  = @{ check_id='AD-LAPS-001';       category='laps';      severity='high';          confidence='high'; impact='high';     remediation_effort='medium'; title='LAPS Configuration Issue';                               recommendation='Deploy and configure LAPS for all computer accounts. Prefer Windows LAPS (built-in) over legacy AdmPwd.' }
    'KB262'  = @{ check_id='AD-PWPOL-001';      category='policy';    severity='medium';         confidence='high'; impact='medium';   remediation_effort='low';    title='Password Policy Weakness';                               recommendation='Set minimum length >= 14, enable complexity, disable reversible encryption, set history >= 12.' }
    'KB263'  = @{ check_id='AD-PWPOL-002';      category='policy';    severity='medium';         confidence='high'; impact='medium';   remediation_effort='low';    title='Account Lockout Threshold Too Permissive';                recommendation='Set lockout threshold to 5 or fewer failed attempts.' }
    'KB254'  = @{ check_id='AD-PWPOL-003';      category='policy';    severity='medium';         confidence='high'; impact='medium';   remediation_effort='low';    title='Passwords Never Expire';                                  recommendation='Enable password expiration or apply FGPP with defined expiry per tier.' }
    'KB510'  = @{ check_id='AD-PWPOL-004';      category='policy';    severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='LM Hashes Stored on Domain Controller';                   recommendation='Set NoLMHash=1 in registry and via GPO to prevent LM hash storage.' }
    'KB81'   = @{ check_id='AD-LDAP-001';       category='ldap';      severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='Null Sessions Allowed';                                   recommendation='Set RestrictAnonymous=1, RestrictAnonymousSam=1, EveryoneIncludesAnonymous=0.' }
    'KB290'  = @{ check_id='AD-DOMAIN-001';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='SMBv1 Enabled';                                          recommendation='Disable SMBv1 via GPO: Set-SmbServerConfiguration -EnableSMB1Protocol $false.' }
    'KB251'  = @{ check_id='AD-DOMAIN-002';     category='domain';    severity='medium';         confidence='high'; impact='medium';   remediation_effort='low';    title='Machine Account Quota Non-Zero';                          recommendation='Set ms-DS-MachineAccountQuota=0; use delegated OU permissions for domain joins.' }
    'KB546'  = @{ check_id='AD-DOMAIN-003';     category='domain';    severity='medium';         confidence='high'; impact='medium';   remediation_effort='medium'; title='Domain/Forest Functional Level Below Current OS Version';  recommendation='Raise functional level to match highest OS version deployed in domain/forest.' }
    'KB426'  = @{ check_id='AD-IDENTITY-001';   category='identity';  severity='medium';         confidence='high'; impact='high';     remediation_effort='medium'; title='Excessive Privileged Group Membership';                   recommendation='Review and minimise privileged group membership. Enforce least privilege.' }
    'KB549'  = @{ check_id='AD-IDENTITY-002';   category='identity';  severity='informational';  confidence='high'; impact='low';      remediation_effort='low';    title='Protected Users Group Membership';                        recommendation='Ensure all privileged accounts are members of the Protected Users group.' }
    'KB250'  = @{ check_id='AD-TRUST-001';      category='trust';     severity='medium';         confidence='high'; impact='high';     remediation_effort='medium'; title='Domain Trust Risk';                                       recommendation='Review all trusts. Remove unnecessary ones. Prefer non-transitive, one-way trusts.' }
    'KB547'  = @{ check_id='AD-DOMAIN-004';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='Domain Controllers Not Owned by Domain Admins';           recommendation='Correct ownership of all DC computer objects to Domain Admins group.' }
    'KB842'  = @{ check_id='AD-DNS-001';        category='dns';       severity='medium';         confidence='high'; impact='medium';   remediation_effort='low';    title='DNS Zone Allows Insecure Dynamic Updates';                recommendation='Configure all DNS zones to require Secure Only dynamic updates.' }
    'KB551'  = @{ check_id='AD-ACL-001';        category='acl';       severity='high';           confidence='high'; impact='high';     remediation_effort='medium'; title='Dangerous ACL Permissions on AD Objects';                 recommendation='Remove Write/FullControl permissions for Domain Users, Authenticated Users, or Everyone on AD objects.' }
    'KB1095' = @{ check_id='AD-ADCS-001';       category='adcs';      severity='critical';       confidence='high'; impact='critical'; remediation_effort='low';    title='ADCS Web Enrollment over HTTP (ESC8)';                    recommendation='Disable HTTP web enrollment or enforce HTTPS + Extended Protection for Authentication (EPA).' }
    'KB1096' = @{ check_id='AD-ADCS-002';       category='adcs';      severity='critical';       confidence='high'; impact='critical'; remediation_effort='medium'; title='ADCS Vulnerable Certificate Templates (ESC1/2/3/4)';      recommendation='Restrict template permissions. Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT where not required.' }
    'KB259'  = @{ check_id='AD-DOMAIN-005';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='high';   title='End-of-Life Operating Systems Joined to Domain';          recommendation='Decommission or upgrade EOL systems. Isolate on a restricted VLAN where immediate upgrade is impossible.' }
    'KB3'    = @{ check_id='AD-DOMAIN-005';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='high';   title='End-of-Life Operating Systems Joined to Domain';          recommendation='Decommission or upgrade EOL systems.' }
    'KB37'   = @{ check_id='AD-DOMAIN-005';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='high';   title='End-of-Life Operating Systems Joined to Domain';          recommendation='Decommission or upgrade EOL systems.' }
    'KB38'   = @{ check_id='AD-DOMAIN-005';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='high';   title='End-of-Life Operating Systems Joined to Domain';          recommendation='Decommission or upgrade EOL systems.' }
    'KB995'  = @{ check_id='AD-DOMAIN-006';     category='domain';    severity='high';           confidence='high'; impact='high';     remediation_effort='medium'; title='Weak Kerberos Encryption Algorithms (RC4/DES) on DCs';    recommendation='Set msDS-SupportedEncryptionTypes to 24 (AES-128+AES-256) or higher on all DCs and service accounts.' }
    'KB329'  = @{ check_id='AD-GPO-001';        category='gpo';       severity='critical';       confidence='high'; impact='critical'; remediation_effort='low';    title='Cleartext Credentials in SYSVOL (cpassword)';             recommendation='Remove all cpassword entries from SYSVOL immediately and rotate all affected credentials.' }
    'KB479'  = @{ check_id='AD-GPO-002';        category='gpo';       severity='medium';         confidence='medium';impact='medium';  remediation_effort='medium'; title='No GPO Restricts Privileged Account Logon';              recommendation='Define GPO restricting interactive/RDP/network logon for DA/EA/SA on non-DC systems.' }
    'KB611'  = @{ check_id='AD-SPN-001';        category='spn';       severity='high';           confidence='high'; impact='high';     remediation_effort='medium'; title='High-Value Kerberoastable Service Accounts';              recommendation='Use long random passwords for service accounts with SPNs. Migrate to gMSA where possible.' }
    'KB720'  = @{ check_id='AD-ASREP-001';      category='identity';  severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='Accounts with Kerberos Pre-Auth Disabled (AS-REP Roastable)'; recommendation='Enable pre-authentication requirement on all user accounts. Audit DONT_REQ_PREAUTH flag.' }
    'KB1101' = @{ check_id='AD-LDAP-002';       category='ldap';      severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='Weak LDAP Security Configuration';                        recommendation='Enable LDAP signing (LDAPServerIntegrity=2), deploy LDAPS certificate, enable channel binding.' }
    'KB500'  = @{ check_id='AD-IDENTITY-003';   category='identity';  severity='medium';         confidence='high'; impact='medium';   remediation_effort='medium'; title='Inactive User Accounts (180+ days)';                       recommendation='Disable or remove accounts inactive for more than 180 days. Implement automated lifecycle process.' }
    'KB309'  = @{ check_id='AD-IDENTITY-004';   category='identity';  severity='medium';         confidence='high'; impact='medium';   remediation_effort='low';    title='Default Administrator Account Not Hardened';              recommendation='Rename the Administrator account (UID 500) and create a decoy account in its place.' }
    'KB501'  = @{ check_id='AD-IDENTITY-005';   category='identity';  severity='low';            confidence='high'; impact='low';      remediation_effort='low';    title='Disabled User Accounts Still in Domain';                  recommendation='Review and remove disabled accounts that are no longer needed. Clean up stale objects.' }
    'KB550'  = @{ check_id='AD-PWPOL-005';      category='policy';    severity='medium';         confidence='high'; impact='medium';   remediation_effort='medium'; title='User Accounts with Passwords Older Than 90 Days';         recommendation='Enforce password expiry policy. Identify accounts exceeding maximum password age.' }
    'KB253'  = @{ check_id='AD-IDENTITY-006';   category='identity';  severity='high';           confidence='high'; impact='high';     remediation_effort='low';    title='krbtgt Password Not Recently Changed';                    recommendation='Reset krbtgt password. Follow Microsoft guidance for krbtgt password rollover procedure.' }
}

# --- Default per-module timeouts (seconds) ---
$script:DefaultModuleTimeouts = @{
    hostdetails     = 30
    domainaudit     = 180
    trusts          = 60
    accounts        = 180
    passwordpolicy  = 90
    ntds            = 300
    oldboxes        = 90
    gpo             = 300
    ouperms         = 600
    laps            = 90
    authpolsilos    = 30
    insecurednszone = 30
    recentchanges   = 30
    spn             = 90
    asrep           = 30
    acl             = 600
    adcs            = 60
    ldapsecurity    = 60
    securityevents  = 120
}

# --- Profile definitions (profile name  ordered list of module names) ---
$script:Profiles = @{
    'light'          = @('hostdetails', 'accounts', 'passwordpolicy', 'ldapsecurity')
    'standard'       = @('hostdetails', 'domainaudit', 'trusts', 'accounts', 'passwordpolicy', 'oldboxes', 'gpo', 'laps', 'insecurednszone', 'recentchanges', 'spn', 'asrep', 'ldapsecurity')
    'deep'           = @('hostdetails', 'domainaudit', 'trusts', 'accounts', 'passwordpolicy', 'oldboxes', 'gpo', 'ouperms', 'laps', 'authpolsilos', 'insecurednszone', 'recentchanges', 'spn', 'asrep', 'acl', 'adcs', 'ldapsecurity', 'ntds')
    'evidence'       = @('hostdetails', 'domainaudit', 'trusts', 'accounts', 'passwordpolicy', 'oldboxes', 'gpo', 'ouperms', 'laps', 'authpolsilos', 'insecurednszone', 'recentchanges', 'spn', 'asrep', 'acl', 'adcs', 'ldapsecurity')
    'incident-response' = @('hostdetails', 'domainaudit', 'trusts', 'accounts', 'passwordpolicy', 'oldboxes', 'gpo', 'ouperms', 'laps', 'authpolsilos', 'insecurednszone', 'recentchanges', 'spn', 'asrep', 'acl', 'adcs', 'ldapsecurity', 'securityevents')
    'inventory-only' = @('hostdetails', 'domainaudit', 'accounts', 'oldboxes')
}

# --- Script-scope state (initialised in main execution block) ---
$script:quietMode      = $false
$script:findings       = $null   # set to List[object] in main block
$script:findingCounter = 0
$script:moduleResults  = @{}
$script:logsDir        = $null
$script:capabilities   = @{}
$script:logLevel       = 'normal'
$script:selfScriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$script:warnings       = [System.Collections.Generic.List[string]]::new()
$script:diffSummary    = $null

#  Finding infrastructure 

function Get-PriorityScore {
    param(
        [string]$Severity,
        [string]$Confidence,
        [string]$Impact,
        [int]$AffectedCount = 0,
        [string]$Scope = 'domain'
    )
    $sevMap   = @{ critical=50; high=30; medium=15; low=5; informational=1 }
    $confMap  = @{ high=3; medium=2; low=1 }
    $impMap   = @{ critical=4; high=3; medium=2; low=1 }
    $scopeBonus = if ($Scope -in @('domain','forest')) { 5 } else { 0 }
    $countBonus = if ($AffectedCount -gt 100) { 5 } elseif ($AffectedCount -gt 10) { 3 } elseif ($AffectedCount -gt 0) { 1 } else { 0 }
    $score = ($sevMap[$Severity] -as [int]) + ($confMap[$Confidence] -as [int]) + ($impMap[$Impact] -as [int]) + $scopeBonus + $countBonus
    return [int]$score
}

function Get-FindingFingerprint {
    param(
        [string]$CheckId,
        [string]$Category,
        [string]$Scope,
        [string]$Title,
        [int]$AffectedCount = 0,
        [object[]]$AffectedObjects = @()
    )
    $objectText = ''
    if ($AffectedObjects -and $AffectedObjects.Count -gt 0) {
        $objectText = @(
            $AffectedObjects |
            ForEach-Object { "$_".Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
        ) -join ';'
    }
    $raw = @(
        ($CheckId  | ForEach-Object { "$_".Trim().ToLowerInvariant() }),
        ($Category | ForEach-Object { "$_".Trim().ToLowerInvariant() }),
        ($Scope    | ForEach-Object { "$_".Trim().ToLowerInvariant() }),
        ($Title    | ForEach-Object { "$_".Trim().ToLowerInvariant() }),
        "$AffectedCount",
        $objectText
    ) -join '|'
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function New-Finding {
    param(
        [string]$CheckId,
        [string]$CheckName,
        [string]$Category,
        [string]$Subcategory           = '',
        [string]$Title,
        [string]$Description           = '',
        [ValidateSet('informational','low','medium','high','critical')]
        [string]$Severity              = 'medium',
        [ValidateSet('low','medium','high')]
        [string]$Confidence            = 'high',
        [ValidateSet('low','medium','high','critical')]
        [string]$Impact                = 'medium',
        [ValidateSet('low','medium','high')]
        [string]$Exploitability        = 'medium',
        [ValidateSet('low','medium','high')]
        [string]$RemediationEffort     = 'medium',
        [ValidateSet('passed','failed','warning','not_applicable','not_evaluated','partial','error')]
        [string]$Status                = 'failed',
        [string]$Scope                 = 'domain',
        [int]$AffectedCount            = 0,
        [object[]]$AffectedObjects     = @(),
        [string]$Evidence              = '',
        [string]$DataSource            = 'ActiveDirectory',
        [string]$Collector             = '',
        [string]$AppliesTo             = '',
        [string]$NotApplicableReason   = '',
        [string]$NotEvaluatedReason    = '',
        [string]$PartialReason         = '',
        [string]$Recommendation        = '',
        [string[]]$References          = @(),
        [string[]]$Tags                = @()
    )
    $script:findingCounter++
    $priorityScore = Get-PriorityScore -Severity $Severity -Confidence $Confidence -Impact $Impact `
                                       -AffectedCount $AffectedCount -Scope $Scope
    $effectiveTitle = if ([string]::IsNullOrWhiteSpace($Title)) { $CheckName } else { $Title }
    $fingerprint = Get-FindingFingerprint -CheckId $CheckId -Category $Category -Scope $Scope -Title $effectiveTitle `
                                          -AffectedCount $AffectedCount -AffectedObjects $AffectedObjects
    $findingId = "FIND-{0}" -f $fingerprint.Substring(0, 12).ToUpperInvariant()
    return [PSCustomObject]@{
        finding_id            = $findingId
        finding_fingerprint   = $fingerprint
        check_id              = $CheckId
        check_name            = $CheckName
        category              = $Category
        subcategory           = $Subcategory
        title                 = $effectiveTitle
        description           = $Description
        severity              = $Severity
        confidence            = $Confidence
        impact                = $Impact
        exploitability        = $Exploitability
        remediation_effort    = $RemediationEffort
        status                = $Status
        scope                 = $Scope
        affected_count        = $AffectedCount
        affected_objects      = $AffectedObjects
        evidence              = $Evidence
        data_source           = $DataSource
        collector             = $Collector
        applies_to            = $AppliesTo
        not_applicable_reason = $NotApplicableReason
        not_evaluated_reason  = $NotEvaluatedReason
        partial_reason        = $PartialReason
        recommendation        = $Recommendation
        references            = $References
        tags                  = $Tags
        priority_score        = $priorityScore
        created_at_utc        = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

function Add-Finding {
    param([Parameter(Mandatory, ValueFromPipeline)][object]$Finding)
    process {
        if ($null -ne $script:findings) { $script:findings.Add($Finding) }
    }
}

function Add-NessusFinding {
    param(
        [string]$PluginName,
        [string]$PluginId,
        [string]$Evidence
    )
    $meta = $script:CheckRegistry[$PluginId]
    if (-not $meta) {
        $meta = @{
            check_id           = "AD-UNKNOWN-$PluginId"
            category           = 'unknown'
            severity           = 'medium'
            confidence         = 'medium'
            impact             = 'medium'
            remediation_effort = 'medium'
            title              = $PluginName
            recommendation     = 'Review finding details and consult vendor guidance.'
        }
    }
    New-Finding `
        -CheckId           $meta.check_id `
        -CheckName         $PluginName `
        -Category          $meta.category `
        -Title             $meta.title `
        -Description       $PluginName `
        -Severity          $meta.severity `
        -Confidence        $meta.confidence `
        -Impact            $meta.impact `
        -RemediationEffort $meta.remediation_effort `
        -Status            'failed' `
        -Evidence          ($Evidence -replace "`r`n",' ' -replace "`n",' ') `
        -Recommendation    $meta.recommendation `
        -Tags              @('nessus-intercepted') |
    Add-Finding
}

#  Module runner 

function Invoke-AuditModule {
    param(
        [string]$Name,
        [string]$DisplayName,
        [scriptblock]$Code,
        [int]$TimeoutSeconds = 120
    )
    if (-not (Test-ModulePrereqs -Name $Name)) { return }
    $start = Get-Date
    $script:moduleResults[$Name] = [PSCustomObject]@{
        module           = $Name
        display_name     = $DisplayName
        status           = 'running'
        started_at_utc   = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ended_at_utc     = $null
        duration_seconds = 0
        timeout_seconds  = $TimeoutSeconds
        findings_added   = 0
        error            = $null
    }
    $countBefore = if ($script:findings) { $script:findings.Count } else { 0 }
    $useBackgroundTimeout = $TimeoutSeconds -gt 0 -and (Get-Command Start-Job -ErrorAction SilentlyContinue) -and `
                            -not [string]::IsNullOrWhiteSpace($script:selfScriptPath) -and `
                            (Test-Path -LiteralPath $script:selfScriptPath)

    if ($useBackgroundTimeout) {
        Write-Trace -Level 'debug' -Message "Module '$Name' executing in timeout-managed job (${TimeoutSeconds}s budget)."
        $codeText = $Code.ToString()
        $job = $null
        try {
            $job = Start-Job -ScriptBlock {
                param(
                    [string]$ScriptPath,
                    [string]$CodeText,
                    [string]$ModuleName,
                    [string]$OutputDir,
                    [bool]$QuietMode,
                    [string]$LogLevel,
                    [bool]$NoNessusSwitch
                )

                $runnerResult = [ordered]@{
                    status   = 'executed'
                    error    = $null
                    findings = @()
                }

                try {
                    $rawScript = Get-Content -Path $ScriptPath -Raw -Encoding UTF8 -ErrorAction Stop
                    $parts = [regex]::Split($rawScript, '(?m)^#\s+MAIN EXECUTION\s*$', 2)
                    if ($parts.Count -lt 2) { throw "Could not isolate function section from script source." }
                    . ([scriptblock]::Create($parts[0]))
                    $outputdir         = $OutputDir
                    $script:quietMode  = $QuietMode
                    $script:logLevel   = $LogLevel
                    $noNessus          = $NoNessusSwitch
                    $script:logsDir    = Join-Path $OutputDir 'logs'
                    if (-not (Test-Path -LiteralPath $script:logsDir)) { New-Item -ItemType Directory -Path $script:logsDir | Out-Null }

                    $script:findings       = [System.Collections.Generic.List[object]]::new()
                    $script:findingCounter = 0

                    try { if (Get-Module -ListAvailable -Name ActiveDirectory) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue } } catch {}
                    try { if (Get-Module -ListAvailable -Name GroupPolicy)     { Import-Module GroupPolicy     -ErrorAction SilentlyContinue } } catch {}
                    try { if (Get-Module -ListAvailable -Name ServerManager)   { Import-Module ServerManager   -ErrorAction SilentlyContinue } } catch {}
                    try { if (Get-Module -ListAvailable -Name DSInternals)     { Import-Module DSInternals     -ErrorAction SilentlyContinue } } catch {}

                    try { Get-Variables | Out-Null } catch {}
                    & ([scriptblock]::Create($CodeText))
                    $runnerResult.findings = @($script:findings)
                } catch {
                    $runnerResult.status = 'failed'
                    $runnerResult.error  = $_.Exception.Message
                    try { $runnerResult.findings = @($script:findings) } catch { $runnerResult.findings = @() }
                }

                [PSCustomObject]@{
                    status   = $runnerResult.status
                    error    = $runnerResult.error
                    findings = $runnerResult.findings
                }
            } -ArgumentList $script:selfScriptPath, $codeText, $Name, $outputdir, [bool]$script:quietMode, $script:logLevel, [bool]$noNessus

            $waitResult = Wait-Job -Job $job -Timeout $TimeoutSeconds
            if ($null -eq $waitResult) {
                Stop-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
                $end = Get-Date
                $script:moduleResults[$Name].status           = 'partial'
                $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
                $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore
                $script:moduleResults[$Name].error            = "Timed out after ${TimeoutSeconds}s"
                $script:warnings.Add("Module '$Name' timed out after ${TimeoutSeconds}s")
                Write-Both "    [!] Module '$Name' timed out after ${TimeoutSeconds}s (marked partial)"
            } else {
                $received = @(Receive-Job -Job $job -ErrorAction SilentlyContinue)
                $payload = $null
                foreach ($item in $received) {
                    if ($null -eq $item) { continue }
                    if ($null -ne $item.PSObject.Properties['status']) {
                        $payload = [PSCustomObject]@{
                            status   = $item.status
                            error    = $item.error
                            findings = $item.findings
                        }
                        continue
                    }
                    if ($item -is [System.Collections.IDictionary] -and $item.Contains('status')) {
                        $payload = [PSCustomObject]@{
                            status   = $item['status']
                            error    = $item['error']
                            findings = $item['findings']
                        }
                    }
                }

                if ($payload -and $payload.findings) {
                    foreach ($f in @($payload.findings)) {
                        if ($null -ne $f) { $script:findings.Add($f) }
                    }
                }

                $end = Get-Date
                $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
                $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore

                if ($payload -and $payload.status -eq 'executed') {
                    $script:moduleResults[$Name].status = 'executed'
                } elseif ($payload) {
                    $script:moduleResults[$Name].status = 'failed'
                    $script:moduleResults[$Name].error  = if ($payload) { $payload.error } else { "Module '$Name' returned no payload" }
                    Write-Both "    [!] Module '$Name' failed: $($script:moduleResults[$Name].error)"
                } else {
                    Write-Both "    [!] Module '$Name' timeout worker returned no payload. Falling back to inline execution."
                    try {
                        & $Code
                        $end = Get-Date
                        $script:moduleResults[$Name].status           = 'executed'
                        $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
                        $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore
                        $script:moduleResults[$Name].error            = "Timeout worker unavailable; executed inline without hard timeout."
                        $script:warnings.Add("Module '$Name' executed inline because timeout worker returned no payload.")
                    } catch {
                        $end = Get-Date
                        $script:moduleResults[$Name].status           = 'failed'
                        $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                        $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
                        $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore
                        $script:moduleResults[$Name].error            = $_.Exception.Message
                        Write-Both "    [!] Module '$Name' failed after inline fallback: $($_.Exception.Message)"
                    }
                }
            }
        } catch {
            $end = Get-Date
            $script:moduleResults[$Name].status           = 'failed'
            $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
            $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore
            $script:moduleResults[$Name].error            = $_.Exception.Message
            Write-Both "    [!] Module '$Name' failed: $($_.Exception.Message)"
        } finally {
            if ($job) {
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
    } else {
        if ($TimeoutSeconds -gt 0) {
            Write-Trace -Level 'verbose' -Message "Timeout budget requested for module '$Name', but Start-Job/script path unavailable. Running inline."
        }
        try {
            & $Code
            $end = Get-Date
            $script:moduleResults[$Name].status           = 'executed'
            $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
            $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore
        } catch {
            $end = Get-Date
            $script:moduleResults[$Name].status           = 'failed'
            $script:moduleResults[$Name].ended_at_utc     = $end.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $script:moduleResults[$Name].duration_seconds = [math]::Round(($end - $start).TotalSeconds, 1)
            $script:moduleResults[$Name].findings_added   = $(if ($script:findings) { $script:findings.Count } else { 0 }) - $countBefore
            $script:moduleResults[$Name].error            = $_.Exception.Message
            Write-Both "    [!] Module '$Name' failed: $($_.Exception.Message)"
        }
    }
    $dur = $script:moduleResults[$Name].duration_seconds
    $fnd = $script:moduleResults[$Name].findings_added
    Write-Both "    [*] Module '$DisplayName' completed in ${dur}s ($fnd new findings)"
}

function Get-ModuleTimeout {
    param([string]$Name)
    if ($moduleTimeoutSeconds -gt 0) { return $moduleTimeoutSeconds }
    if ($script:DefaultModuleTimeouts.ContainsKey($Name)) { return $script:DefaultModuleTimeouts[$Name] }
    return 120
}

#  Export layer 

function Get-ScriptHash {
    param([string]$Path)
    try { return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return 'unavailable' }
}

function Export-ExecutionManifest {
    param([string]$OutputDir, [int]$ExitCode)
    $endTime = Get-Date
    $domain  = $null ; $forest = $null
    try { $domain = Get-ADDomain  -ErrorAction SilentlyContinue } catch {}
    try { $forest = Get-ADForest  -ErrorAction SilentlyContinue } catch {}
    $moduleWarnings = @($script:moduleResults.Values | Where-Object { $_.status -in @('skipped','partial') } | ForEach-Object { "$($_.module): $($_.error)" })
    $allWarnings    = @($script:warnings) + $moduleWarnings
    $allErrors      = @($script:moduleResults.Values | Where-Object { $_.status -eq 'failed' -and $_.error } | ForEach-Object { "$($_.module): $($_.error)" })
    $fqdn = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
    $manifest = [ordered]@{
        tool_name          = $script:ToolName
        tool_version       = $script:ToolVersion
        schema_version     = $script:SchemaVersion
        script_hash        = Get-ScriptHash -Path $script:selfScriptPath
        hostname           = $env:COMPUTERNAME
        fqdn               = $fqdn
        domain_name        = if ($domain) { $domain.DNSRoot }  else { $env:USERDNSDOMAIN }
        forest_name        = if ($forest) { $forest.Name }     else { 'unknown' }
        dc_name            = $env:COMPUTERNAME
        execution_user     = "$env:USERDOMAIN\$env:USERNAME"
        execution_context  = if ([Environment]::UserInteractive) { 'interactive' } else { 'non-interactive' }
        is_interactive     = [Environment]::UserInteractive
        log_level          = $script:logLevel
        quiet_mode         = $script:quietMode
        profile_selected   = $script:resolvedProfile
        switches_used      = $script:switchesUsed
        output_path        = $OutputDir
        started_at_utc     = $script:sessionStartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        ended_at_utc       = $endTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        duration_seconds   = [math]::Round(($endTime - $script:sessionStartTime).TotalSeconds, 1)
        modules_requested  = $script:modulesRequested
        modules_executed   = @($script:moduleResults.Values | Where-Object { $_.status -eq 'executed' } | ForEach-Object { $_.module })
        modules_skipped    = @($script:moduleResults.Values | Where-Object { $_.status -eq 'skipped'  } | ForEach-Object { $_.module })
        modules_partial    = @($script:moduleResults.Values | Where-Object { $_.status -eq 'partial'  } | ForEach-Object { $_.module })
        modules_failed     = @($script:moduleResults.Values | Where-Object { $_.status -eq 'failed'   } | ForEach-Object { $_.module })
        modules_detail     = $script:moduleResults
        capabilities_detected = $script:capabilities
        capabilities          = $script:capabilities
        baseline_input        = $baseline
        baseline_diff         = $script:diffSummary
        warnings              = @($allWarnings | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        errors                = @($allErrors | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        preflight_result   = $script:preflightResult
        exit_code          = $ExitCode
    }
    $manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath "$OutputDir\execution.json" -Encoding UTF8
}

function Export-SummaryJson {
    param([string]$OutputDir)
    $byStatus = @{} ; $bySeverity = @{} ; $byCategory = @{} ; $byConfidence = @{}
    $modules = @($script:moduleResults.Values)
    foreach ($f in $script:findings) {
        foreach ($h in @(
            @{d=$byStatus;     k=$f.status},
            @{d=$bySeverity;   k=$f.severity},
            @{d=$byCategory;   k=$f.category},
            @{d=$byConfidence; k=$f.confidence}
        )) { if (-not $h.d.ContainsKey($h.k)) { $h.d[$h.k]=0 } ; $h.d[$h.k]++ }
    }
    $coverageRows = @(
        $modules |
        Where-Object {
            ($_.PSObject.Properties.Name -contains 'coverage') -and
            $null -ne $_.coverage
        } |
        ForEach-Object { $_.coverage }
    )
    $expectedTotal = [int](($coverageRows | ForEach-Object { [int]$_.objects_expected }  | Measure-Object -Sum).Sum)
    $evaluatedTotal = [int](($coverageRows | ForEach-Object { [int]$_.objects_evaluated } | Measure-Object -Sum).Sum)
    $overallCoveragePct = if ($expectedTotal -gt 0) { [math]::Round(($evaluatedTotal / $expectedTotal) * 100, 1) } else { $null }
    $coverageSummary = [ordered]@{
        modules_total          = $modules.Count
        modules_with_coverage  = $coverageRows.Count
        modules_without_coverage = @(
            $modules |
            Where-Object { -not (($_.PSObject.Properties.Name -contains 'coverage') -and $null -ne $_.coverage) } |
            ForEach-Object { $_.module }
        )
        objects_expected_total = $expectedTotal
        objects_evaluated_total= $evaluatedTotal
        overall_coverage_pct   = $overallCoveragePct
    }

    $riskNotes = [System.Collections.Generic.List[object]]::new()
    $failedModuleCount = @($modules | Where-Object { $_.status -eq 'failed' }).Count
    $partialModuleCount = @($modules | Where-Object { $_.status -eq 'partial' }).Count
    $criticalHighCount = @($script:findings | Where-Object { $_.status -eq 'failed' -and $_.severity -in @('critical','high') }).Count
    if ($script:preflightResult -and (-not $script:preflightResult.overall_pass)) {
        $riskNotes.Add([ordered]@{ code='PREFLIGHT_LIMITATIONS'; severity='medium'; note='Preflight reported failed checks. Coverage may be incomplete.' })
    }
    if ($failedModuleCount -gt 0) {
        $riskNotes.Add([ordered]@{ code='MODULE_FAILURES'; severity='high'; note="$failedModuleCount module(s) failed during execution." })
    }
    if ($partialModuleCount -gt 0) {
        $riskNotes.Add([ordered]@{ code='MODULE_PARTIAL'; severity='medium'; note="$partialModuleCount module(s) completed partially (typically timeout-bound)." })
    }
    if ($criticalHighCount -gt 0) {
        $riskNotes.Add([ordered]@{ code='CRITICAL_OR_HIGH_FINDINGS'; severity='high'; note="$criticalHighCount critical/high finding(s) require immediate containment and hardening review." })
    }
    if ($script:diffSummary -and $script:diffSummary.findings_added -gt 0) {
        $riskNotes.Add([ordered]@{ code='NEW_FINDINGS_VS_BASELINE'; severity='high'; note="$($script:diffSummary.findings_added) new finding(s) detected compared to baseline." })
    }
    if ($script:diffSummary -and $script:diffSummary.inventory_diff) {
        $inventoryAdds = @($script:diffSummary.inventory_diff | ForEach-Object { [int]$_.added } | Measure-Object -Sum).Sum
        if ($inventoryAdds -gt 0) {
            $riskNotes.Add([ordered]@{ code='INVENTORY_ADDITIONS_VS_BASELINE'; severity='medium'; note="$inventoryAdds inventory addition(s) detected across key datasets." })
        }
    }

    $topPriorities = @(
        $script:findings |
        Where-Object { $_.status -eq 'failed' -and $_.severity -in @('critical','high') } |
        Sort-Object priority_score -Descending | Select-Object -First 10 |
        ForEach-Object { [ordered]@{ check_id=$_.check_id; title=$_.title; severity=$_.severity; priority_score=$_.priority_score } }
    )
    $summary = [ordered]@{
        schema_version         = $script:SchemaVersion
        generated_at_utc       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        total_checks           = ($script:findings | Where-Object { $_.status -ne 'not_evaluated' } | Measure-Object).Count
        total_findings         = ($script:findings | Where-Object { $_.status -eq 'failed' }        | Measure-Object).Count
        findings_by_severity   = $bySeverity
        findings_by_category   = $byCategory
        findings_by_status     = $byStatus
        findings_by_confidence = $byConfidence
        top_priorities         = $topPriorities
        modules_summary        = @($modules | ForEach-Object {
            [ordered]@{ module=$_.module; status=$_.status; duration_seconds=$_.duration_seconds; findings_added=$_.findings_added }
        })
        coverage_summary       = $coverageSummary
        execution_risk_notes   = @($riskNotes)
        coverage_notes         = 'Phase 1: structured findings derived from Nessus interceptor. All Write-Nessus-Finding calls produce a normalized finding. Legacy text files remain for backward compatibility.'
    }
    $summary | ConvertTo-Json -Depth 10 | Out-File -FilePath "$OutputDir\summary.json" -Encoding UTF8
}

function Export-FindingsNDJSON {
    param([string]$OutputDir)
    $path = "$OutputDir\findings.ndjson"
    Remove-Item $path -ErrorAction SilentlyContinue
    foreach ($f in $script:findings) {
        ($f | ConvertTo-Json -Compress -Depth 5) | Add-Content -Path $path -Encoding UTF8
    }
}

function Export-FindingsCSV {
    param([string]$OutputDir)
    $rows = @(
        $script:findings | ForEach-Object {
            [PSCustomObject]@{
                finding_id         = $_.finding_id
                finding_fingerprint= $_.finding_fingerprint
                check_id           = $_.check_id
                check_name         = $_.check_name
                category           = $_.category
                subcategory        = $_.subcategory
                title              = $_.title
                severity           = $_.severity
                confidence         = $_.confidence
                impact             = $_.impact
                exploitability     = $_.exploitability
                remediation_effort = $_.remediation_effort
                status             = $_.status
                scope              = $_.scope
                affected_count     = $_.affected_count
                affected_objects   = ($_.affected_objects -join '; ')
                evidence           = ($_.evidence -replace '[`r`n]+',' ')
                recommendation     = $_.recommendation
                priority_score     = $_.priority_score
                created_at_utc     = $_.created_at_utc
            }
        }
    )
    if ($rows.Count -gt 0) {
        $rows | Export-Csv -Path "$OutputDir\findings.csv" -NoTypeInformation -Encoding UTF8
    } else {
        # Write header-only CSV so downstream tools can expect the schema
        'finding_id,finding_fingerprint,check_id,check_name,category,subcategory,title,severity,confidence,impact,exploitability,remediation_effort,status,scope,affected_count,affected_objects,evidence,recommendation,priority_score,created_at_utc' |
            Set-Content -Path "$OutputDir\findings.csv" -Encoding UTF8
    }
}

function Get-NormalizedFindingRows {
    param([object[]]$Findings)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($Findings)) {
        $checkId = [string]$f.check_id
        if ([string]::IsNullOrWhiteSpace($checkId)) { $checkId = [string]$f.check_name }

        $title = [string]$f.title
        if ([string]::IsNullOrWhiteSpace($title)) { $title = [string]$f.check_name }
        if ([string]::IsNullOrWhiteSpace($title)) { $title = $checkId }

        $scope = [string]$f.scope
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = 'domain' }

        $status = [string]$f.status
        if ([string]::IsNullOrWhiteSpace($status)) { $status = 'not_evaluated' }

        $severity = [string]$f.severity
        if ([string]::IsNullOrWhiteSpace($severity)) { $severity = 'informational' }

        $category = [string]$f.category
        if ([string]::IsNullOrWhiteSpace($category)) { $category = 'unknown' }

        $affectedCount = 0
        try { $affectedCount = [int]$f.affected_count } catch { $affectedCount = 0 }

        $affectedObjects = ''
        if ($null -ne $f.affected_objects) {
            if ($f.affected_objects -is [System.Array]) {
                $affectedObjects = @(
                    $f.affected_objects |
                    ForEach-Object { "$_".Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Sort-Object -Unique
                ) -join '; '
            } else {
                $affectedObjects = [string]$f.affected_objects
            }
        }

        $fingerprint = [string]$f.finding_fingerprint
        if ([string]::IsNullOrWhiteSpace($fingerprint)) {
            $fingerprint = Get-FindingFingerprint -CheckId $checkId -Category $category -Scope $scope -Title $title `
                                                  -AffectedCount $affectedCount -AffectedObjects @($affectedObjects)
        }

        $correlationKey = $fingerprint

        $rows.Add([PSCustomObject]@{
            correlation_key = $correlationKey
            finding_id      = [string]$f.finding_id
            finding_fingerprint = $fingerprint
            check_id        = $checkId
            title           = $title
            category        = $category
            scope           = $scope
            status          = $status
            severity        = $severity
            affected_count  = $affectedCount
            affected_objects= $affectedObjects
        })
    }
    return @($rows)
}

function Resolve-BaselineFindingsInput {
    param([string]$BaselinePath)
    if ([string]::IsNullOrWhiteSpace($BaselinePath)) {
        throw "Baseline path is empty."
    }

    $fullPath = [System.IO.Path]::GetFullPath($BaselinePath)
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Baseline path not found: $fullPath"
    }

    $item = Get-Item -LiteralPath $fullPath -ErrorAction Stop
    if ($item.PSIsContainer) {
        $csvPath    = Join-Path $fullPath 'findings.csv'
        $ndjsonPath = Join-Path $fullPath 'findings.ndjson'
        if (Test-Path -LiteralPath $csvPath) {
            return [PSCustomObject]@{ path = $csvPath; format = 'csv' }
        }
        if (Test-Path -LiteralPath $ndjsonPath) {
            return [PSCustomObject]@{ path = $ndjsonPath; format = 'ndjson' }
        }
        throw "Baseline directory does not contain findings.csv or findings.ndjson: $fullPath"
    }

    $ext = [System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()
    if ($ext -eq '.csv')    { return [PSCustomObject]@{ path = $fullPath; format = 'csv' } }
    if ($ext -eq '.ndjson') { return [PSCustomObject]@{ path = $fullPath; format = 'ndjson' } }
    throw "Unsupported baseline file type '$ext'. Use findings.csv or findings.ndjson."
}

function Import-BaselineFindings {
    param([string]$Path, [string]$Format)
    if ($Format -eq 'csv') {
        return @(Import-Csv -Path $Path -ErrorAction Stop)
    }
    if ($Format -eq 'ndjson') {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($line in Get-Content -Path $Path -ErrorAction Stop) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $items.Add(($line | ConvertFrom-Json -ErrorAction Stop)) } catch {}
        }
        return @($items)
    }
    throw "Unsupported baseline input format: $Format"
}

function Export-InventoryDiff {
    param(
        [string]$Name,
        [string]$CurrentPath,
        [string]$BaselinePath,
        [string[]]$KeyColumns,
        [string]$DiffDir
    )

    $result = [ordered]@{
        inventory = $Name
        compared  = $false
        reason    = $null
        added     = 0
        removed   = 0
    }

    if (-not (Test-Path -LiteralPath $CurrentPath)) {
        $result.reason = "Current inventory missing: $CurrentPath"
        return [PSCustomObject]$result
    }
    if (-not (Test-Path -LiteralPath $BaselinePath)) {
        $result.reason = "Baseline inventory missing: $BaselinePath"
        return [PSCustomObject]$result
    }

    $currentRows  = @(Import-Csv -Path $CurrentPath -ErrorAction SilentlyContinue)
    $baselineRows = @(Import-Csv -Path $BaselinePath -ErrorAction SilentlyContinue)
    if ($null -eq $currentRows)  { $currentRows = @() }
    if ($null -eq $baselineRows) { $baselineRows = @() }

    $buildKey = {
        param($row)
        if ($KeyColumns -and $KeyColumns.Count -gt 0) {
            return (
                @(
                    foreach ($c in $KeyColumns) {
                        $value = if ($row.PSObject.Properties.Name -contains $c) { [string]$row.$c } else { '' }
                        $value.Trim().ToLowerInvariant()
                    }
                ) -join '|'
            )
        }
        return (($row.PSObject.Properties | ForEach-Object { ([string]$_.Value).Trim().ToLowerInvariant() }) -join '|')
    }

    $currentByKey  = @{}
    $baselineByKey = @{}
    foreach ($row in $currentRows)  { $k = & $buildKey $row ; if (-not [string]::IsNullOrWhiteSpace($k) -and -not $currentByKey.ContainsKey($k))  { $currentByKey[$k] = $row } }
    foreach ($row in $baselineRows) { $k = & $buildKey $row ; if (-not [string]::IsNullOrWhiteSpace($k) -and -not $baselineByKey.ContainsKey($k)) { $baselineByKey[$k] = $row } }

    $added   = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $currentByKey.Keys)  { if (-not $baselineByKey.ContainsKey($k)) { $added.Add($currentByKey[$k]) } }
    foreach ($k in $baselineByKey.Keys) { if (-not $currentByKey.ContainsKey($k))  { $removed.Add($baselineByKey[$k]) } }

    $addedPath   = Join-Path $DiffDir ("inventory-{0}-added.csv" -f $Name)
    $removedPath = Join-Path $DiffDir ("inventory-{0}-removed.csv" -f $Name)
    if ($added.Count -gt 0) {
        @($added) | Export-Csv -Path $addedPath -NoTypeInformation -Encoding UTF8
    } else {
        ($KeyColumns -join ',') | Set-Content -Path $addedPath -Encoding UTF8
    }
    if ($removed.Count -gt 0) {
        @($removed) | Export-Csv -Path $removedPath -NoTypeInformation -Encoding UTF8
    } else {
        ($KeyColumns -join ',') | Set-Content -Path $removedPath -Encoding UTF8
    }

    $result.compared = $true
    $result.added    = $added.Count
    $result.removed  = $removed.Count
    return [PSCustomObject]$result
}

function Export-BaselineDiff {
    param([string]$OutputDir, [string]$BaselinePath)

    $baselineInput    = Resolve-BaselineFindingsInput -BaselinePath $BaselinePath
    $baselineFindings = Import-BaselineFindings -Path $baselineInput.path -Format $baselineInput.format

    $currentRows  = @(Get-NormalizedFindingRows -Findings $script:findings)
    $baselineRows = @(Get-NormalizedFindingRows -Findings $baselineFindings)

    $currentByKey  = @{}
    $baselineByKey = @{}
    foreach ($r in $currentRows)  { if (-not $currentByKey.ContainsKey($r.correlation_key))  { $currentByKey[$r.correlation_key]  = $r } }
    foreach ($r in $baselineRows) { if (-not $baselineByKey.ContainsKey($r.correlation_key)) { $baselineByKey[$r.correlation_key] = $r } }

    $added   = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $changed = [System.Collections.Generic.List[object]]::new()

    foreach ($k in $currentByKey.Keys) {
        if (-not $baselineByKey.ContainsKey($k)) {
            $added.Add($currentByKey[$k])
        }
    }

    foreach ($k in $baselineByKey.Keys) {
        if (-not $currentByKey.ContainsKey($k)) {
            $removed.Add($baselineByKey[$k])
            continue
        }

        $base = $baselineByKey[$k]
        $curr = $currentByKey[$k]
        $statusChanged   = ($base.status   -ne $curr.status)
        $severityChanged = ($base.severity -ne $curr.severity)
        if ($statusChanged -or $severityChanged) {
            $changeType = if ($statusChanged -and $severityChanged) { 'status_and_severity_changed' }
                          elseif ($statusChanged)                   { 'status_changed' }
                          else                                      { 'severity_changed' }

            $changed.Add([PSCustomObject]@{
                correlation_key   = $k
                finding_fingerprint = $curr.finding_fingerprint
                check_id          = $curr.check_id
                title             = $curr.title
                category          = $curr.category
                scope             = $curr.scope
                baseline_status   = $base.status
                current_status    = $curr.status
                baseline_severity = $base.severity
                current_severity  = $curr.severity
                change_type       = $changeType
            })
        }
    }

    $diffDir = Join-Path $OutputDir 'diff'
    if (-not (Test-Path $diffDir)) { New-Item -ItemType Directory -Path $diffDir | Out-Null }

    $addedPath   = Join-Path $diffDir 'findings-added.csv'
    $removedPath = Join-Path $diffDir 'findings-removed.csv'
    $changedPath = Join-Path $diffDir 'findings-changed.csv'

    $findingDiffColumns = 'correlation_key,finding_fingerprint,finding_id,check_id,title,category,scope,status,severity,affected_count,affected_objects'
    if ($added.Count -gt 0) {
        @($added) | Export-Csv -Path $addedPath -NoTypeInformation -Encoding UTF8
    } else {
        $findingDiffColumns | Set-Content -Path $addedPath -Encoding UTF8
    }

    if ($removed.Count -gt 0) {
        @($removed) | Export-Csv -Path $removedPath -NoTypeInformation -Encoding UTF8
    } else {
        $findingDiffColumns | Set-Content -Path $removedPath -Encoding UTF8
    }

    if ($changed.Count -gt 0) {
        @($changed) | Export-Csv -Path $changedPath -NoTypeInformation -Encoding UTF8
    } else {
        'correlation_key,finding_fingerprint,check_id,title,category,scope,baseline_status,current_status,baseline_severity,current_severity,change_type' |
            Set-Content -Path $changedPath -Encoding UTF8
    }

    $baselineRoot = (Get-Item -LiteralPath (Split-Path -Parent $baselineInput.path)).FullName
    $currentInvDir  = Join-Path $OutputDir 'inventory'
    $baselineInvDir = Join-Path $baselineRoot 'inventory'
    $inventoryDiffs = @()
    if ((Test-Path -LiteralPath $currentInvDir) -and (Test-Path -LiteralPath $baselineInvDir)) {
        $inventoryConfig = @(
            @{ name='privileged_accounts'; keys=@('Group','SamAccountName') },
            @{ name='service_accounts';    keys=@('SamAccountName') },
            @{ name='trusts';              keys=@('Name','Source','Target','Direction','TrustType') },
            @{ name='gpos';                keys=@('Id','DisplayName') },
            @{ name='adcs_templates';      keys=@('Name','DisplayName') }
        )
        foreach ($cfg in $inventoryConfig) {
            $inventoryDiffs += Export-InventoryDiff -Name $cfg.name `
                                                   -CurrentPath (Join-Path $currentInvDir ("{0}.csv" -f $cfg.name)) `
                                                   -BaselinePath (Join-Path $baselineInvDir ("{0}.csv" -f $cfg.name)) `
                                                   -KeyColumns $cfg.keys `
                                                   -DiffDir $diffDir
        }
    }

    $summary = [ordered]@{
        compared_at_utc          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        baseline_input           = $BaselinePath
        baseline_resolved_path   = $baselineInput.path
        baseline_format          = $baselineInput.format
        baseline_findings_total  = $baselineRows.Count
        current_findings_total   = $currentRows.Count
        findings_added           = $added.Count
        findings_removed         = $removed.Count
        findings_changed         = $changed.Count
        inventory_diff           = $inventoryDiffs
    }
    $summary | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $diffDir 'diff-summary.json') -Encoding UTF8
    $script:diffSummary = $summary

    Write-Both "[+] Baseline diff exported to $diffDir"
    Write-Both "    diff/diff-summary.json"
    Write-Both "    diff/findings-added.csv"
    Write-Both "    diff/findings-removed.csv"
    Write-Both "    diff/findings-changed.csv"
    if (@($inventoryDiffs | Where-Object { $_.compared }).Count -gt 0) {
        Write-Both "    diff/inventory-*-added.csv"
        Write-Both "    diff/inventory-*-removed.csv"
    }
}

function Export-AllFindings {
    param([string]$OutputDir, [int]$ExitCode)
    Write-Both "[*] Exporting structured results..."
    try { Export-FindingsNDJSON    -OutputDir $OutputDir } catch { Write-Both "    [!] findings.ndjson export failed: $($_.Exception.Message)" }
    try { Export-FindingsCSV       -OutputDir $OutputDir } catch { Write-Both "    [!] findings.csv export failed: $($_.Exception.Message)" }
    if ($script:inventoryMode) {
        Write-Both "[*] Exporting inventories and evidence..."
        try { Export-Inventories -OutputDir $OutputDir } catch { Write-Both "    [!] Inventory export failed: $($_.Exception.Message)" }
        try { Export-Evidence    -OutputDir $OutputDir } catch { Write-Both "    [!] Evidence export failed: $($_.Exception.Message)" }
    }
    if (-not [string]::IsNullOrWhiteSpace($baseline)) {
        try {
            Export-BaselineDiff -OutputDir $OutputDir -BaselinePath $baseline
        } catch {
            $msg = "Baseline diff export failed: $($_.Exception.Message)"
            $script:warnings.Add($msg)
            Write-Both "    [!] $msg"
        }
    }
    try { Export-SummaryJson       -OutputDir $OutputDir } catch { Write-Both "    [!] summary.json export failed: $($_.Exception.Message)" }
    try { Export-ExecutionManifest -OutputDir $OutputDir -ExitCode $ExitCode } catch { Write-Both "    [!] execution.json export failed: $($_.Exception.Message)" }
    Write-Both "[+] Structured output written to $OutputDir"
    Write-Both "    execution.json      - execution manifest (hash, context, module status)"
    Write-Both "    preflight.json      - preflight check results"
    Write-Both "    summary.json        - findings summary by severity/category"
    Write-Both "    findings.ndjson     - all findings, one JSON object per line"
    Write-Both "    findings.csv        - all findings as flat CSV"
    if (-not [string]::IsNullOrWhiteSpace($baseline)) {
        Write-Both "    diff/*.json|csv     - baseline comparison output"
    }
    if ($script:inventoryMode) {
        Write-Both "    inventory/*.csv     - AD object inventories (users, groups, computers, etc.)"
        Write-Both "    evidence/*.json     - evidence snapshots (policies, trusts, GPO, ACL, ADCS, LAPS, domain, LDAP, security events)"
    }
    if ($script:logsDir) {
        Write-Both "    logs/console.log    - full console log"
        Write-Both "    logs/debug.log      - timestamped detailed log"
    }
}

function Get-AuditExitCode {
    $failed   = @($script:moduleResults.Values | Where-Object { $_.status -in @('failed','partial') })
    $findings = @($script:findings | Where-Object { $_.status -eq 'failed' -and $_.severity -in @('critical','high','medium','low') })
    if ($failed.Count -gt 0)   { return 2 }  # partial execution (module errors)
    if ($findings.Count -gt 0) { return 1 }  # clean execution with findings
    return 0                                  # clean execution, no actionable findings
}

# 
#  PHASE 2  Preflight, prerequisites, coverage, inventories, evidence
# 

$script:ModulePrereqs = @{
    hostdetails      = @()
    domainaudit      = @('AD', 'GroupPolicy')
    trusts           = @('AD')
    accounts         = @('AD')
    passwordpolicy   = @('AD')
    ntds             = @('DSInternals')
    oldboxes         = @('AD')
    gpo              = @('GroupPolicy')
    ouperms          = @('AD')
    laps             = @('AD')
    authpolsilos     = @('AD')
    insecurednszone  = @()
    recentchanges    = @('AD')
    spn              = @('AD')
    asrep            = @('AD')
    acl              = @('AD')
    adcs             = @()
    ldapsecurity     = @('AD')
    securityevents   = @()
}

$script:preflightResult = $null

function Invoke-Preflight {
    param([string]$OutputDir)
    $pf = [ordered]@{
        tool           = $script:ToolName
        schema_version = $script:SchemaVersion
        timestamp_utc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        hostname       = $env:COMPUTERNAME
        checks         = [System.Collections.Generic.List[object]]::new()
        overall_pass   = $true
    }
    function pf_check {
        param([string]$name, [string]$status, [string]$detail = '')
        $pf.checks.Add([PSCustomObject][ordered]@{ check=$name; status=$status; detail=$detail })
        if ($status -eq 'fail') { $pf.overall_pass = $false }
        $icon = if ($status -eq 'pass') { '[+]' } elseif ($status -eq 'warn') { '[!]' } else { '[X]' }
        Write-Both "    $icon Preflight: $name  $detail"
    }

    $psver = $PSVersionTable.PSVersion.Major
    if ($psver -ge 5) { pf_check 'ps_version' 'pass' "PowerShell $psver" }
    else              { pf_check 'ps_version' 'fail' "PowerShell $psver (5+ required)" }

    $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($elevated) { pf_check 'elevated' 'pass' 'Running as Administrator' }
    else           { pf_check 'elevated' 'warn' 'Not elevated  some checks may be incomplete' }

    if (Get-Module -ListAvailable -Name ActiveDirectory) { pf_check 'module_ad'  'pass' 'ActiveDirectory module available' }
    else                                                  { pf_check 'module_ad'  'fail' 'ActiveDirectory module missing (install RSAT)' }

    if (Get-Module -ListAvailable -Name GroupPolicy) { pf_check 'module_gp'  'pass' 'GroupPolicy module available' }
    else                                              { pf_check 'module_gp'  'warn' 'GroupPolicy module missing (GPO checks will be skipped)' }

    if (Get-Module -ListAvailable -Name DSInternals) { pf_check 'module_dsi' 'pass' 'DSInternals module available' }
    else                                              { pf_check 'module_dsi' 'warn' 'DSInternals missing  password quality unavailable (use -installdeps)' }

    try {
        $dom = Get-ADDomain -ErrorAction Stop
        pf_check 'ad_connectivity' 'pass' "Connected to $($dom.DNSRoot)"
    } catch {
        pf_check 'ad_connectivity' 'fail' "Cannot connect to AD: $($_.Exception.Message)"
    }

    try {
        $testFile = Join-Path $OutputDir '.preflight_write_test'
        [System.IO.File]::WriteAllText($testFile, 'test')
        Remove-Item $testFile -ErrorAction SilentlyContinue
        pf_check 'output_writable' 'pass' "Output path writable: $OutputDir"
    } catch {
        pf_check 'output_writable' 'fail' "Cannot write to output path: $OutputDir"
    }

    try {
        $drive     = [System.IO.Path]::GetPathRoot($OutputDir)
        $driveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.RootDirectory.FullName -eq $drive }
        $freeMB    = if ($driveInfo) { [math]::Round($driveInfo.AvailableFreeSpace / 1MB, 0) } else { 0 }
        if ($freeMB -ge 200) { pf_check 'disk_space' 'pass' "${freeMB} MB free on $drive" }
        else                 { pf_check 'disk_space' 'warn' "Only ${freeMB} MB free on $drive (200 MB recommended)" }
    } catch {
        pf_check 'disk_space' 'warn' "Could not check disk space: $($_.Exception.Message)"
    }

    try {
        $dom2   = Get-ADDomain -ErrorAction SilentlyContinue
        $sysvol = if ($dom2) { "\\$($dom2.PDCEmulator)\SYSVOL" } else { $null }
        if ($sysvol -and (Test-Path $sysvol -ErrorAction SilentlyContinue)) { pf_check 'sysvol_access' 'pass' "SYSVOL reachable at $sysvol" }
        else { pf_check 'sysvol_access' 'warn' 'SYSVOL unreachable  GPO file scans may fail' }
    } catch {
        pf_check 'sysvol_access' 'warn' "SYSVOL check failed: $($_.Exception.Message)"
    }

    $cu = Get-Command certutil -ErrorAction SilentlyContinue
    if ($cu) { pf_check 'certutil' 'pass' "certutil found at $($cu.Source)" }
    else     { pf_check 'certutil' 'warn' 'certutil not found  ADCS checks may be limited' }

    if ($profile -eq 'incident-response') {
        try {
            $secLog = Get-WinEvent -ListLog Security -ErrorAction Stop
            if ($secLog) {
                pf_check 'security_log_access' 'pass' "Security log query available for incident-response correlation (records=$($secLog.RecordCount))"
            } else {
                pf_check 'security_log_access' 'warn' 'Security log metadata returned empty response'
            }
        } catch {
            pf_check 'security_log_access' 'warn' "Security log may be restricted: $($_.Exception.Message)"
        }
    }

    $script:preflightResult = $pf
    try {
        $pf | ConvertTo-Json -Depth 10 | Out-File -FilePath "$OutputDir\preflight.json" -Encoding UTF8
        Write-Both "[+] Preflight complete  preflight.json written ($($pf.checks.Count) checks, pass=$($pf.overall_pass))"
    } catch {
        Write-Both "    [!] Could not write preflight.json: $($_.Exception.Message)"
    }
    return [PSCustomObject]$pf
}

function Test-ModulePrereqs {
    param([string]$Name)
    $reqs = $script:ModulePrereqs[$Name]
    if (-not $reqs -or $reqs.Count -eq 0) { return $true }
    foreach ($cap in $reqs) {
        if (-not $script:capabilities[$cap]) {
            Write-Both "    [!] Module '$Name' skipped  missing capability: $cap"
            $script:moduleResults[$Name] = [PSCustomObject]@{
                module           = $Name
                display_name     = $Name
                status           = 'skipped'
                started_at_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                ended_at_utc     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                duration_seconds = 0
                timeout_seconds  = 0
                findings_added   = 0
                error            = "Missing capability: $cap"
            }
            return $false
        }
    }
    return $true
}

function Set-ModuleCoverage {
    param([string]$Name, [int]$Expected, [int]$Evaluated, [string]$Note = '')
    if ($script:moduleResults.ContainsKey($Name)) {
        $pct = if ($Expected -gt 0) { [math]::Round(($Evaluated / $Expected) * 100, 1) } else { 100 }
        $script:moduleResults[$Name] | Add-Member -NotePropertyName 'coverage' -NotePropertyValue ([PSCustomObject]@{
            objects_expected  = $Expected
            objects_evaluated = $Evaluated
            coverage_pct      = $pct
            note              = $Note
        }) -Force
    }
}

function Export-Inventories {
    param([string]$OutputDir)
    $invDir = Join-Path $OutputDir 'inventory'
    try {
        if (!(Test-Path $invDir)) { New-Item -ItemType Directory -Path $invDir | Out-Null }
    } catch {
        Write-Both "    [!] Could not create inventory/ directory: $($_.Exception.Message)" ; return
    }

    try {
        $props = @('SamAccountName','DisplayName','Enabled','PasswordNeverExpires','PasswordLastSet',
                   'LastLogonDate','DoesNotRequirePreAuth','AdminCount','ServicePrincipalNames','WhenCreated','DistinguishedName')
        Get-ADUser -Filter * -Properties $props -ErrorAction Stop |
            Select-Object SamAccountName, DisplayName, Enabled, PasswordNeverExpires, PasswordLastSet,
                          LastLogonDate, DoesNotRequirePreAuth, AdminCount,
                          @{n='SPNs';e={$_.ServicePrincipalNames -join ';'}}, WhenCreated, DistinguishedName |
            Export-Csv -Path "$invDir\users.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/users.csv"
    } catch { Write-Both "    [!] users.csv failed: $($_.Exception.Message)" }

    try {
        Get-ADGroup -Filter * -Properties Description, ManagedBy, WhenCreated, GroupCategory, GroupScope -ErrorAction Stop |
            Select-Object SamAccountName, Name, GroupCategory, GroupScope, Description, ManagedBy, WhenCreated, DistinguishedName |
            Export-Csv -Path "$invDir\groups.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/groups.csv"
    } catch { Write-Both "    [!] groups.csv failed: $($_.Exception.Message)" }

    try {
        Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate, WhenCreated, DNSHostName -ErrorAction Stop |
            Select-Object Name, DNSHostName, Enabled, OperatingSystem, OperatingSystemVersion, LastLogonDate, WhenCreated, DistinguishedName |
            Export-Csv -Path "$invDir\computers.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/computers.csv"
    } catch { Write-Both "    [!] computers.csv failed: $($_.Exception.Message)" }

    try {
        Get-ADDomainController -Filter * -ErrorAction Stop |
            Select-Object Name, HostName, Site, IPv4Address, IsGlobalCatalog, IsReadOnly, OperatingSystem, OperatingSystemVersion |
            Export-Csv -Path "$invDir\dcs.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/dcs.csv"
    } catch { Write-Both "    [!] dcs.csv failed: $($_.Exception.Message)" }

    try {
        Get-ADTrust -Filter * -Properties Direction, TrustType, TrustAttributes, Source, Target, WhenCreated -ErrorAction Stop |
            Select-Object Name, Direction, TrustType, TrustAttributes, Source, Target, WhenCreated |
            Export-Csv -Path "$invDir\trusts.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/trusts.csv"
    } catch { Write-Both "    [!] trusts.csv failed: $($_.Exception.Message)" }

    try {
        if (Get-Module GroupPolicy -ErrorAction SilentlyContinue) {
            Get-GPO -All -ErrorAction Stop |
                Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime, Id,
                              @{n='WmiFilter';e={$_.WmiFilter.Name}} |
                Export-Csv -Path "$invDir\gpos.csv" -NoTypeInformation -Encoding UTF8
            Write-Both "    [+] inventory/gpos.csv"
        } else { Write-Both "    [!] gpos.csv skipped  GroupPolicy module unavailable" }
    } catch { Write-Both "    [!] gpos.csv failed: $($_.Exception.Message)" }

    try {
        $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                        'Backup Operators','Account Operators','Server Operators')
        $privRows = foreach ($gn in $privGroups) {
            try {
                $grp = Get-ADGroup -Filter { Name -eq $gn } -ErrorAction SilentlyContinue
                if ($grp) {
                    Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue |
                        Where-Object { $_.objectClass -eq 'user' } |
                        ForEach-Object { [PSCustomObject]@{ Group=$gn; SamAccountName=$_.SamAccountName; Name=$_.name; DistinguishedName=$_.distinguishedName } }
                }
            } catch {}
        }
        if ($privRows) {
            $privRows | Export-Csv -Path "$invDir\privileged_accounts.csv" -NoTypeInformation -Encoding UTF8
            Write-Both "    [+] inventory/privileged_accounts.csv"
        }
    } catch { Write-Both "    [!] privileged_accounts.csv failed: $($_.Exception.Message)" }

    try {
        Get-ADUser -Filter { ServicePrincipalNames -like '*' } -Properties ServicePrincipalNames, PasswordLastSet, Enabled, AdminCount -ErrorAction Stop |
            Select-Object SamAccountName, Enabled, AdminCount, PasswordLastSet,
                          @{n='SPNs';e={$_.ServicePrincipalNames -join ';'}} |
            Export-Csv -Path "$invDir\service_accounts.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/service_accounts.csv"
    } catch { Write-Both "    [!] service_accounts.csv failed: $($_.Exception.Message)" }

    try {
        $rootDse = Get-ADRootDSE -ErrorAction Stop
        $templatesBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
        Get-ADObject -SearchBase $templatesBase -LDAPFilter '(objectClass=pKICertificateTemplate)' `
            -Properties displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage,whenChanged,whenCreated -ErrorAction Stop |
            Select-Object Name, displayName,
                          @{n='EnrollmentFlags';e={ $_.'msPKI-Enrollment-Flag' }},
                          @{n='NameFlags';e={ $_.'msPKI-Certificate-Name-Flag' }},
                          @{n='RA_Signature';e={ $_.'msPKI-RA-Signature' }},
                          @{n='EKUs';e={ ($_.pKIExtendedKeyUsage -join ';') }},
                          whenCreated, whenChanged, DistinguishedName |
            Export-Csv -Path "$invDir\adcs_templates.csv" -NoTypeInformation -Encoding UTF8
        Write-Both "    [+] inventory/adcs_templates.csv"
    } catch { Write-Both "    [!] adcs_templates.csv failed: $($_.Exception.Message)" }

    Write-Both "[+] Inventory exports complete  $invDir"
}

function Export-Evidence {
    param([string]$OutputDir)
    $evDir = Join-Path $OutputDir 'evidence'
    try {
        if (!(Test-Path $evDir)) { New-Item -ItemType Directory -Path $evDir | Out-Null }
    } catch {
        Write-Both "    [!] Could not create evidence/ directory: $($_.Exception.Message)" ; return
    }

    try {
        $defPol = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
        $fgpps  = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction SilentlyContinue)
        @{ default_policy=$defPol; fine_grained_policies=$fgpps } |
            ConvertTo-Json -Depth 10 | Out-File "$evDir\password_policy.json" -Encoding UTF8
        Write-Both "    [+] evidence/password_policy.json"
    } catch { Write-Both "    [!] password_policy.json failed: $($_.Exception.Message)" }

    try {
        @(Get-ADTrust -Filter * -Properties * -ErrorAction SilentlyContinue) |
            ConvertTo-Json -Depth 5 | Out-File "$evDir\trusts.json" -Encoding UTF8
        Write-Both "    [+] evidence/trusts.json"
    } catch { Write-Both "    [!] trusts.json failed: $($_.Exception.Message)" }

    try {
        if (Get-Module GroupPolicy -ErrorAction SilentlyContinue) {
            @(Get-GPO -All -ErrorAction Stop |
                Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime, Id,
                              @{n='WmiFilter';e={$_.WmiFilter.Name}}) |
                ConvertTo-Json -Depth 6 | Out-File "$evDir\gpo.json" -Encoding UTF8
            Write-Both "    [+] evidence/gpo.json"
        } else {
            @{ status = 'not_evaluated'; reason = 'GroupPolicy module unavailable' } |
                ConvertTo-Json | Out-File "$evDir\gpo.json" -Encoding UTF8
            Write-Both "    [!] evidence/gpo.json generated with not_evaluated status (GroupPolicy unavailable)"
        }
    } catch { Write-Both "    [!] gpo.json failed: $($_.Exception.Message)" }

    try {
        $dom    = Get-ADDomain -ErrorAction SilentlyContinue
        $dfl    = if ($dom) { "$($dom.DomainMode)" } else { 'unknown' }
        $legacy = $null ; $winlaps = $null
        try { $legacy = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { name -eq 'ms-Mcs-AdmPwd' } -ErrorAction SilentlyContinue } catch {}
        try { $winlaps = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { name -eq 'msLAPS-Password' } -ErrorAction SilentlyContinue } catch {}
        @{ domain_functional_level=$dfl; legacy_laps_schema=[bool]$legacy; windows_laps_schema=[bool]$winlaps } |
            ConvertTo-Json | Out-File "$evDir\laps.json" -Encoding UTF8
        Write-Both "    [+] evidence/laps.json"
    } catch { Write-Both "    [!] laps.json failed: $($_.Exception.Message)" }

    try {
        $dom  = Get-ADDomain  -ErrorAction SilentlyContinue
        $frst = Get-ADForest  -ErrorAction SilentlyContinue
        $recycleEnabled = $false
        try { $recycleEnabled = [bool](Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' } -ErrorAction SilentlyContinue | Where-Object { $_.EnabledScopes }) } catch {}
        [ordered]@{
            domain_name           = if ($dom)  { $dom.DNSRoot }            else { $null }
            domain_mode           = if ($dom)  { "$($dom.DomainMode)" }    else { $null }
            forest_mode           = if ($frst) { "$($frst.ForestMode)" }   else { $null }
            pdc_emulator          = if ($dom)  { $dom.PDCEmulator }        else { $null }
            rid_master            = if ($dom)  { $dom.RIDMaster }          else { $null }
            infrastructure_master = if ($dom)  { $dom.InfrastructureMaster } else { $null }
            schema_master         = if ($frst) { $frst.SchemaMaster }      else { $null }
            domain_naming_master  = if ($frst) { $frst.DomainNamingMaster } else { $null }
            recycle_bin_enabled   = $recycleEnabled
        } | ConvertTo-Json | Out-File "$evDir\domain.json" -Encoding UTF8
        Write-Both "    [+] evidence/domain.json"
    } catch { Write-Both "    [!] domain.json failed: $($_.Exception.Message)" }

    try {
        $ldapReg = [ordered]@{}
        try { $ldapReg['LDAPServerIntegrity']       = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity'       -ErrorAction Stop).LDAPServerIntegrity       } catch {}
        try { $ldapReg['LdapEnforceChannelBinding']  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding'  -ErrorAction Stop).LdapEnforceChannelBinding  } catch {}
        try { $ldapReg['RestrictAnonymous']          = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'              -Name 'RestrictAnonymous'          -ErrorAction Stop).RestrictAnonymous          } catch {}
        try { $ldapReg['RestrictAnonymousSam']       = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'              -Name 'RestrictAnonymousSam'       -ErrorAction Stop).RestrictAnonymousSam       } catch {}
        $ldapReg | ConvertTo-Json | Out-File "$evDir\ldap.json" -Encoding UTF8
        Write-Both "    [+] evidence/ldap.json"
    } catch { Write-Both "    [!] ldap.json failed: $($_.Exception.Message)" }

    try {
        $aclEvidence = [ordered]@{
            generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            sources          = @()
        }
        $aclFiles = @(
            "$outputdir\dangerousACL_Computer.txt",
            "$outputdir\dangerousACL_Groups.txt",
            "$outputdir\dangerousACLUsers.txt",
            "$outputdir\dangerousACLs.html"
        )
        foreach ($f in $aclFiles) {
            if (Test-Path -LiteralPath $f) {
                $lineCount = 0
                try { $lineCount = (Get-Content -Path $f -ErrorAction SilentlyContinue | Measure-Object -Line).Lines } catch {}
                $aclEvidence.sources += [ordered]@{
                    path       = $f
                    exists     = $true
                    line_count = $lineCount
                }
            }
        }
        if ($aclEvidence.sources.Count -eq 0) {
            $aclEvidence.sources += [ordered]@{
                path       = $null
                exists     = $false
                line_count = 0
            }
        }
        $aclEvidence | ConvertTo-Json -Depth 8 | Out-File "$evDir\acl.json" -Encoding UTF8
        Write-Both "    [+] evidence/acl.json"
    } catch { Write-Both "    [!] acl.json failed: $($_.Exception.Message)" }

    try {
        $adcsEvidence = [ordered]@{
            generated_at_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            enrollment_services = @()
            templates = @()
            files = @()
        }
        try {
            $rootDse = Get-ADRootDSE -ErrorAction Stop
            $enrollmentBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
            $templatesBase  = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)"
            $adcsEvidence.enrollment_services = @(
                Get-ADObject -SearchBase $enrollmentBase -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName,certificateTemplates,displayName -ErrorAction SilentlyContinue |
                Select-Object Name,displayName,dNSHostName,@{n='certificateTemplates';e={ ($_.certificateTemplates -join ';') }}
            )
            $adcsEvidence.templates = @(
                Get-ADObject -SearchBase $templatesBase -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties displayName,pKIExtendedKeyUsage -ErrorAction SilentlyContinue |
                Select-Object Name,displayName,@{n='EKUs';e={ ($_.pKIExtendedKeyUsage -join ';') }}
            )
        } catch {}
        foreach ($f in @("$outputdir\vulnerable_templates.txt", "$outputdir\web_enrollment.txt")) {
            $adcsEvidence.files += [ordered]@{
                path   = $f
                exists = [bool](Test-Path -LiteralPath $f)
            }
        }
        $adcsEvidence | ConvertTo-Json -Depth 8 | Out-File "$evDir\adcs.json" -Encoding UTF8
        Write-Both "    [+] evidence/adcs.json"
    } catch { Write-Both "    [!] adcs.json failed: $($_.Exception.Message)" }

    Write-Both "[+] Evidence exports complete  $evDir"
}

# Internal mode used by timeout-managed child jobs.
if ($libraryOnly.IsPresent) { return }

# 
#  MAIN EXECUTION
# 

$outputdir = if ($outputPath) { [System.IO.Path]::GetFullPath($outputPath) } else { Join-Path (Get-Item -Path ".\").FullName $env:computername }
$script:sessionStartTime = Get-Date
$script:quietMode        = $quiet.IsPresent
$script:logLevel         = $logLevel.ToLowerInvariant()
$scriptname = $MyInvocation.MyCommand.Name
if ($PSCommandPath) { $script:selfScriptPath = $PSCommandPath }
if (-not [string]::IsNullOrWhiteSpace($script:selfScriptPath)) {
    $script:selfScriptPath = [System.IO.Path]::GetFullPath($script:selfScriptPath)
}
try {
    if (!(Test-Path "$outputdir")) { New-Item -ItemType Directory -Path $outputdir | Out-Null }
} catch {
    Write-Host "[!] Error: Cannot create output directory: $($_.Exception.Message)"
    exit 4
}

# Create logs/ subdirectory
$script:logsDir = Join-Path $outputdir "logs"
try {
    if (!(Test-Path $script:logsDir)) { New-Item -ItemType Directory -Path $script:logsDir | Out-Null }
} catch {
    $script:logsDir = $null  # degrade gracefully
}

# Initialise findings accumulator (requires output dir to exist first)
$script:findings       = [System.Collections.Generic.List[object]]::new()
$script:findingCounter = 0
$script:moduleResults  = @{}
$script:inventoryMode  = $false
$script:warnings       = [System.Collections.Generic.List[string]]::new()
$script:diffSummary    = $null

# Preflight checks
Write-Both "[*] Running preflight checks..."
Invoke-Preflight -OutputDir $outputdir | Out-Null
if ($preflight.IsPresent) {
    $preflightExit = if ($script:preflightResult -and $script:preflightResult.overall_pass) { 0 } else { 3 }
    Write-Both "[*] Preflight mode selected. Skipping audit modules."
    Write-Both "[*] Exit code        : $preflightExit"
    exit $preflightExit
}

# Banner
Write-Both "+====================================================================+"
Write-Both "|       LZ-ADaudit - Active Directory Security Assessment            |"
Write-Both "|       Lazarus Security Framework  |  $versionnum                           |"
Write-Both "+====================================================================+"
Write-Both ""

$running = $false
Write-Both "[*] Script start time $($script:sessionStartTime)"
Write-Both "[+] Outputting to $outputdir"

# Module imports
try {
    if (Get-Module -ListAvailable -Name ActiveDirectory) { Import-Module ActiveDirectory -ErrorAction Stop }
    else { Write-Both "[!] ActiveDirectory module not installed, exiting..." ; exit 3 }
} catch {
    Write-Both "[!] Error loading ActiveDirectory module: $($_.Exception.Message)" ; exit 3
}

try {
    if (Get-Module -ListAvailable -Name ServerManager) { Import-Module ServerManager -ErrorAction Stop }
    else { Write-Both "[!] ServerManager module not installed, exiting..." ; exit 3 }
} catch {
    Write-Both "[!] Error loading ServerManager module: $($_.Exception.Message)" ; exit 3
}

try {
    if (Get-Module -ListAvailable -Name GroupPolicy) { Import-Module GroupPolicy -ErrorAction Stop }
    else { Write-Both "[!] GroupPolicy module not installed, exiting..." ; exit 3 }
} catch {
    Write-Both "[!] Error loading GroupPolicy module: $($_.Exception.Message)" ; exit 3
}

if (Get-Module -ListAvailable -Name DSInternals) {
    Import-Module DSInternals -ErrorAction SilentlyContinue
    $script:capabilities['DSInternals'] = $true
} else {
    Write-Both "[!] DSInternals module not installed, use -installdeps to force install"
    $script:capabilities['DSInternals'] = $false
}
$script:capabilities['ActiveDirectory'] = $true
$script:capabilities['AD']              = $true
$script:capabilities['GroupPolicy']     = $true
$script:capabilities['ServerManager']   = $true
$script:capabilities['AdmPwdPS']        = [bool](Get-Module -ListAvailable -Name AdmPwd.PS)
$script:capabilities['LAPS']            = [bool](Get-Module -ListAvailable -Name LAPS)
$script:capabilities['Interactive']     = [Environment]::UserInteractive

# Nessus setup
try {
    if (Test-Path "$outputdir\adaudit.nessus") { Remove-Item -recurse "$outputdir\adaudit.nessus" | Out-Null }
} catch {
    Write-Both "[!] Warning: Could not clean old nessus file: $($_.Exception.Message)"
}
if (-not $noNessus) { Write-Nessus-Header }

# AD variables
Write-Both "[*] Lang specific variables"
Get-Variables

if (!$?) {
    Write-Both "[!] Error: Failed to initialize script variables. Exiting..."
    exit 4
}

#  Resolve which modules to run 

$modulesToRun = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

if ($profile -and $script:Profiles.ContainsKey($profile)) {
    Write-Both "[*] Using profile: $profile"
    foreach ($m in $script:Profiles[$profile]) { [void]$modulesToRun.Add($m) }
}

# Explicit switches (additive to profile)
if ($hostdetails)     { [void]$modulesToRun.Add('hostdetails')     }
if ($domainaudit)     { [void]$modulesToRun.Add('domainaudit')     }
if ($trusts)          { [void]$modulesToRun.Add('trusts')          }
if ($accounts)        { [void]$modulesToRun.Add('accounts')        }
if ($passwordpolicy)  { [void]$modulesToRun.Add('passwordpolicy')  }
if ($ntds)            { [void]$modulesToRun.Add('ntds')            }
if ($oldboxes)        { [void]$modulesToRun.Add('oldboxes')        }
if ($gpo)             { [void]$modulesToRun.Add('gpo')             }
if ($ouperms)         { [void]$modulesToRun.Add('ouperms')         }
if ($laps)            { [void]$modulesToRun.Add('laps')            }
if ($authpolsilos)    { [void]$modulesToRun.Add('authpolsilos')    }
if ($insecurednszone) { [void]$modulesToRun.Add('insecurednszone') }
if ($recentchanges)   { [void]$modulesToRun.Add('recentchanges')   }
if ($spn)             { [void]$modulesToRun.Add('spn')             }
if ($asrep)           { [void]$modulesToRun.Add('asrep')           }
if ($acl)             { [void]$modulesToRun.Add('acl')             }
if ($adcs)            { [void]$modulesToRun.Add('adcs')            }
if ($ldapsecurity)    { [void]$modulesToRun.Add('ldapsecurity')    }
if ($securityevents)  { [void]$modulesToRun.Add('securityevents')  }

foreach ($s in $selectedChecks) { [void]$modulesToRun.Add($s.Trim()) }

if ($all) {
    foreach ($m in @('hostdetails','domainaudit','trusts','accounts','passwordpolicy','ntds','oldboxes',
                      'gpo','ouperms','laps','authpolsilos','insecurednszone','recentchanges',
                      'spn','asrep','acl','adcs','ldapsecurity','securityevents')) { [void]$modulesToRun.Add($m) }
}

foreach ($ex in $exclude) { [void]$modulesToRun.Remove($ex.Trim()) }
$script:modulesRequested = @($modulesToRun)

# Activate inventory/evidence mode
if ($inventory.IsPresent -or $evidence.IsPresent -or $profile -in @('evidence','inventory-only','incident-response')) {
    $script:inventoryMode = $true
}

#  Module execution 

if ($installdeps) {
    $running = $true
    Write-Both "[*] Installing optional features"
    Install-Dependencies
}

if ($modulesToRun.Contains('hostdetails')) {
    $running = $true ; Write-Both "[*] Device Information"
    Invoke-AuditModule -Name 'hostdetails' -DisplayName 'Device Information' -Code { Get-HostDetails } `
                       -TimeoutSeconds (Get-ModuleTimeout 'hostdetails')
}
if ($modulesToRun.Contains('domainaudit')) {
    $running = $true ; Write-Both "[*] Domain Audit"
    Invoke-AuditModule -Name 'domainaudit' -DisplayName 'Domain Audit' -TimeoutSeconds (Get-ModuleTimeout 'domainaudit') -Code {
        Get-LastWUDate ; Get-DCEval ; Get-TimeSource ; Get-PrivilegedGroupMembership
        Get-MachineAccountQuota ; Get-DefaultDomainControllersPolicy ; Get-SMB1Support
        Get-FunctionalLevel ; Get-DCsNotOwnedByDA ; Get-ReplicationType
        Check-Shares ; Get-RecycleBinState ; Get-CriticalServicesStatus ; Get-RODC
    }
}
if ($modulesToRun.Contains('trusts')) {
    $running = $true ; Write-Both "[*] Domain Trust Audit"
    Invoke-AuditModule -Name 'trusts' -DisplayName 'Domain Trust Audit' -Code { Get-DomainTrusts } `
                       -TimeoutSeconds (Get-ModuleTimeout 'trusts')
}
if ($modulesToRun.Contains('accounts')) {
    $running = $true ; Write-Both "[*] Accounts Audit"
    Invoke-AuditModule -Name 'accounts' -DisplayName 'Accounts Audit' -TimeoutSeconds (Get-ModuleTimeout 'accounts') -Code {
        Get-InactiveAccounts ; Get-DisabledAccounts ; Get-LockedAccounts
        Get-AdminAccountChecks ; Get-NULLSessions ; Get-PrivilegedGroupAccounts ; Get-ProtectedUsers
    }
}
if ($modulesToRun.Contains('passwordpolicy')) {
    $running = $true ; Write-Both "[*] Password Information Audit"
    Invoke-AuditModule -Name 'passwordpolicy' -DisplayName 'Password Policy' -TimeoutSeconds (Get-ModuleTimeout 'passwordpolicy') -Code {
        Get-AccountPassDontExpire ; Get-UserPasswordNotChangedRecently ; Get-PasswordPolicy ; Get-PasswordQuality
    }
}
if ($modulesToRun.Contains('ntds')) {
    $running = $true ; Write-Both "[*] Trying to save NTDS.dit, please wait..."
    Invoke-AuditModule -Name 'ntds' -DisplayName 'NTDS.dit Dump' -Code { Get-NTDSdit } `
                       -TimeoutSeconds (Get-ModuleTimeout 'ntds')
}
if ($modulesToRun.Contains('oldboxes')) {
    $running = $true ; Write-Both "[*] Computer Objects Audit"
    Invoke-AuditModule -Name 'oldboxes' -DisplayName 'EOL Operating Systems' -Code { Get-OldBoxes } `
                       -TimeoutSeconds (Get-ModuleTimeout 'oldboxes')
}
if ($modulesToRun.Contains('gpo')) {
    $running = $true ; Write-Both "[*] GPO audit (and checking SYSVOL for passwords)"
    Invoke-AuditModule -Name 'gpo' -DisplayName 'GPO Audit' -TimeoutSeconds (Get-ModuleTimeout 'gpo') -Code {
        Get-GPOtoFile ; Get-GPOsPerOU ; Get-SYSVOLXMLS ; Get-GPOEnum
    }
}
if ($modulesToRun.Contains('ouperms')) {
    $running = $true ; Write-Both "[*] Check Generic Group AD Permissions"
    Invoke-AuditModule -Name 'ouperms' -DisplayName 'OU Permissions' -Code { Get-OUPerms } `
                       -TimeoutSeconds (Get-ModuleTimeout 'ouperms')
}
if ($modulesToRun.Contains('laps')) {
    $running = $true ; Write-Both "[*] Check For Existence of LAPS in domain"
    Invoke-AuditModule -Name 'laps' -DisplayName 'LAPS Status' -Code { Get-LAPSStatus } `
                       -TimeoutSeconds (Get-ModuleTimeout 'laps')
}
if ($modulesToRun.Contains('authpolsilos')) {
    $running = $true ; Write-Both "[*] Check For Existence of Authentication Policies and Silos"
    Invoke-AuditModule -Name 'authpolsilos' -DisplayName 'Auth Policies and Silos' -Code { Get-AuthenticationPoliciesAndSilos } `
                       -TimeoutSeconds (Get-ModuleTimeout 'authpolsilos')
}
if ($modulesToRun.Contains('insecurednszone')) {
    $running = $true ; Write-Both "[*] Check For Insecure DNS Zones"
    Invoke-AuditModule -Name 'insecurednszone' -DisplayName 'Insecure DNS Zones' -Code { Get-DNSZoneInsecure } `
                       -TimeoutSeconds (Get-ModuleTimeout 'insecurednszone')
}
if ($modulesToRun.Contains('recentchanges')) {
    $running = $true ; Write-Both "[*] Check For Newly Created Users and Groups"
    Invoke-AuditModule -Name 'recentchanges' -DisplayName 'Recent Changes' -Code { Get-RecentChanges } `
                       -TimeoutSeconds (Get-ModuleTimeout 'recentchanges')
}
if ($modulesToRun.Contains('spn')) {
    $running = $true ; Write-Both "[*] Check High Value Kerberoastable User Accounts"
    Invoke-AuditModule -Name 'spn' -DisplayName 'SPN / Kerberoast' -Code { Get-SPNs } `
                       -TimeoutSeconds (Get-ModuleTimeout 'spn')
}
if ($modulesToRun.Contains('asrep')) {
    $running = $true ; Write-Both "[*] Check For Accounts Without Kerberos Pre-Auth"
    Invoke-AuditModule -Name 'asrep' -DisplayName 'AS-REP Roasting' -Code { Get-ADUsersWithoutPreAuth } `
                       -TimeoutSeconds (Get-ModuleTimeout 'asrep')
}
if ($modulesToRun.Contains('acl')) {
    $running = $true ; Write-Both "[*] Check For Dangerous ACL Permissions"
    Invoke-AuditModule -Name 'acl' -DisplayName 'Dangerous ACL Permissions' -Code { Find-DangerousACLPermissions } `
                       -TimeoutSeconds (Get-ModuleTimeout 'acl')
}
if ($modulesToRun.Contains('adcs')) {
    $running = $true ; Write-Both "[*] Check For ADCS Vulnerabilities"
    Invoke-AuditModule -Name 'adcs' -DisplayName 'ADCS Vulnerabilities' -Code { Get-ADCSVulns } `
                       -TimeoutSeconds (Get-ModuleTimeout 'adcs')
}
if ($modulesToRun.Contains('ldapsecurity')) {
    $running = $true ; Write-Both "[*] Check For LDAP Security Issues"
    Invoke-AuditModule -Name 'ldapsecurity' -DisplayName 'LDAP Security' -Code { Get-LDAPSecurity } `
                       -TimeoutSeconds (Get-ModuleTimeout 'ldapsecurity')
}
if ($modulesToRun.Contains('securityevents')) {
    $running = $true ; Write-Both "[*] Incident Response Security Event Correlation"
    Invoke-AuditModule -Name 'securityevents' -DisplayName 'Security Events Correlation' -Code { Get-IncidentResponseSecurityEvents } `
                       -TimeoutSeconds (Get-ModuleTimeout 'securityevents')
}

if ($preflight.IsPresent -or $inventory.IsPresent -or $evidence.IsPresent) { $running = $true }

if (-not $running) {
    Write-Both "[!] No arguments selected"
    Write-Both "[!] Options (combinable):"
    Write-Both "    -profile <light|standard|deep|evidence|incident-response|inventory-only>  predefined module set"
    Write-Both "    -incidentresponse|-incident-response|-incident-respones  incident response mode shortcut (profile + evidence/inventory focus)"
    Write-Both "    -installdeps      install optional features (DSInternals)"
    Write-Both "    -hostdetails      hostname and basic host info"
    Write-Both "    -domainaudit      functional level, DC config, SMB, Kerberos, FSMO"
    Write-Both "    -trusts           domain trust audit"
    Write-Both "    -accounts         inactive/disabled/locked/privileged accounts"
    Write-Both "    -passwordpolicy   default and fine-grained password policies"
    Write-Both "    -ntds             dump NTDS.dit via ntdsutil"
    Write-Both "    -oldboxes         EOL operating systems in domain"
    Write-Both "    -gpo              GPO export and SYSVOL credential scan"
    Write-Both "    -ouperms          non-standard OU permissions for authenticated users"
    Write-Both "    -laps             LAPS deployment status (legacy + Windows LAPS)"
    Write-Both "    -authpolsilos     authentication policies and silos"
    Write-Both "    -insecurednszone  DNS zones allowing insecure updates"
    Write-Both "    -recentchanges    newly created users and groups (last 30 days)"
    Write-Both "    -spn              high-value kerberoastable accounts"
    Write-Both "    -asrep            AS-REP roastable accounts"
    Write-Both "    -acl              dangerous ACL permissions on computers/users/groups"
    Write-Both "    -adcs             ADCS vulnerabilities (ESC1-4, ESC8)"
    Write-Both "    -ldapsecurity     LDAP signing, LDAPS, channel binding, null sessions"
    Write-Both "    -securityevents   correlate Security events (4720/4728/4732/4756) for IR traceability"
    Write-Both "    -all              run all checks"
    Write-Both "    -exclude <list>   exclude checks from -all (comma-separated)"
    Write-Both "    -select <list>    run only specific checks (comma-separated)"
    Write-Both "    -quiet            suppress console output (file log still written)"
    Write-Both "    -logLevel <normal|verbose|debug>  console verbosity level (logs still complete)"
    Write-Both "    -noNessus         skip Nessus XML output"
    Write-Both "    -outputPath <p>   custom output directory path"
    Write-Both "    -moduleTimeoutSeconds <n>  per-module timeout override"
    Write-Both "    -inventory        export inventory CSVs (users, groups, computers, DCs, GPOs, etc.)"
    Write-Both "    -evidence         export evidence JSON snapshots (policies, trusts, LAPS, LDAP, domain, security events)"
    Write-Both "    -preflight        run preflight checks and exit"
    Write-Both "    -baseline <path>  compare findings against a previous run baseline"
    exit 5
}

#  Finalise 

if (-not $noNessus) { Write-Nessus-Footer }

$endtime  = Get-Date
$exitCode = Get-AuditExitCode

Export-AllFindings -OutputDir $outputdir -ExitCode $exitCode

$totalFindings = ($script:findings | Where-Object { $_.status -eq 'failed' }).Count
$critHigh      = ($script:findings | Where-Object { $_.status -eq 'failed' -and $_.severity -in @('critical','high') }).Count
$failedMods    = ($script:moduleResults.Values | Where-Object { $_.status -eq 'failed' }).Count
$partialMods   = ($script:moduleResults.Values | Where-Object { $_.status -eq 'partial' }).Count
$duration      = [math]::Round(($endtime - $script:sessionStartTime).TotalSeconds, 1)

Write-Both ""
Write-Both "[*] "
Write-Both "[*]  LZ-ADaudit $versionnum  Execution Summary"
Write-Both "[*] "
Write-Both "[*]  Duration         : ${duration}s"
Write-Both "[*]  Modules run      : $($script:moduleResults.Values.Count)"
Write-Both "[*]  Modules failed   : $failedMods"
Write-Both "[*]  Modules partial  : $partialMods"
Write-Both "[*]  Total findings   : $totalFindings"
Write-Both "[*]  Critical / High  : $critHigh"
Write-Both "[*]  Output directory : $outputdir"
Write-Both "[*]  Exit code        : $exitCode"
Write-Both "[*] "
Write-Both "[*] Script end time $endtime"

exit $exitCode



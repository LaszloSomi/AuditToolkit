#Requires -Version 7.2
<#
.SYNOPSIS
    Exports Microsoft Purview data security settings relevant to AI and Microsoft 365 Copilot.

.DESCRIPTION
    Authenticates to Security & Compliance PowerShell and exports:
    - DLP compliance policies and their rules
    - Insider Risk Management global settings and policies
    - Audit log retention policies
    - DSPM for AI policy inventory (derived from the above)
    Output is written as a single JSON file for offline analysis or sharing with Microsoft.

.PARAMETER Environment
    Target cloud environment. Valid values: Commercial, GCC, GCCH, DoD.
    Defaults to Commercial.

.PARAMETER UserPrincipalName
    UPN of the account used to authenticate to the tenant.

.PARAMETER AuthFlow
    Authentication flow. Valid values: Interactive, DeviceCode.
    Defaults to Interactive.

.PARAMETER OutputPath
    Directory to write the export file. Defaults to current directory.

.EXAMPLE
    .\Get-PurviewAudit.ps1 -UserPrincipalName admin@contoso.com

.EXAMPLE
    .\Get-PurviewAudit.ps1 -Environment GCCH -UserPrincipalName admin@contoso.us -AuthFlow DeviceCode

.NOTES
    Requires ExchangeOnlineManagement 3.x:
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force

    Required Purview roles (read-only):
      View-Only DLP Compliance Management
      View-Only Insider Risk Management
      View-Only Audit Logs
    Minimum: Compliance Reader built-in role.

.OUTPUTS
    Purview-Export-{TenantId}-{Environment}-{Timestamp}.json
#>
#Requires -Version 7.2
[CmdletBinding()]
param (
    [ValidateSet('Commercial', 'GCC', 'GCCH', 'DoD')]
    [string]$Environment = 'Commercial',

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [ValidateSet('Interactive', 'DeviceCode')]
    [string]$AuthFlow = 'Interactive',

    [string]$OutputPath = $PWD.Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Environment configuration
$IppsEndpointMap = @{
    Commercial = 'https://ps.compliance.protection.outlook.com/powershell-liveid'
    GCC        = 'https://ps.compliance.protection.outlook.com/powershell-liveid'
    GCCH       = 'https://ps.compliance.protection.office365.us/powershell-liveid'
    DoD        = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid'
}

function Resolve-IppsEndpoint {
    param([string]$EnvironmentName)
    $endpoint = $IppsEndpointMap[$EnvironmentName]
    if ([string]::IsNullOrEmpty($endpoint)) {
        throw "Unknown environment '$EnvironmentName'. Valid values: $($IppsEndpointMap.Keys -join ', ')."
    }
    return $endpoint
}
#endregion

#region Prerequisites
function Assert-IppsModule {
    if (-not (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement')) {
        throw "Required module 'ExchangeOnlineManagement' is not installed.`nRun: Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force"
    }
    Write-Verbose 'ExchangeOnlineManagement module present.'
}
#endregion

#region Authentication
function Connect-ToIPPS {
    param(
        [string]$EnvironmentName,
        [string]$Upn,
        [string]$Flow
    )

    $endpoint = Resolve-IppsEndpoint $EnvironmentName

    $connectParams = @{
        UserPrincipalName = $Upn
        ConnectionUri     = $endpoint
    }

    if ($Flow -eq 'DeviceCode') {
        $connectParams.Remove('UserPrincipalName')
        $connectParams['Device'] = $true
    }

    Write-Host "Connecting to Security & Compliance PowerShell ($EnvironmentName)..." -ForegroundColor Cyan
    Connect-IPPSSession @connectParams

    # Retrieve connection metadata for the export envelope.
    $conn = Get-ConnectionInformation | Select-Object -First 1
    if ($null -eq $conn) {
        throw 'Could not retrieve connection information after Connect-IPPSSession.'
    }

    Write-Host "Connected as: $($conn.UserPrincipalName)  |  Tenant: $($conn.TenantID)" -ForegroundColor Green
    return $conn
}
#endregion

#region Data collection
function Get-AuditRetentionPolicies {
    Write-Host 'Collecting audit log retention policies...' -ForegroundColor Cyan

    $policies = @(Get-UnifiedAuditLogRetentionPolicy)

    Write-Host "Retrieved $($policies.Count) retention policy(s)." -ForegroundColor Green
    return $policies
}

function Get-DlpPolicies {
    Write-Host 'Collecting DLP compliance policies...' -ForegroundColor Cyan

    $policies = @(Get-DlpCompliancePolicy -IncludeExtendedProperties $true)
    Write-Host "Retrieved $($policies.Count) DLP policy(s). Collecting rules..." -ForegroundColor Cyan

    $result = foreach ($policy in $policies) {
        $rules = @(Get-DlpComplianceRule -Policy $policy.Name -ResultSize Unlimited -ErrorAction SilentlyContinue)
        [PSCustomObject]@{
            policy = $policy
            rules  = $rules
        }
    }

    Write-Host "DLP collection complete." -ForegroundColor Green
    return @($result)
}
#endregion

#region DSPM inventory
# (placeholder — implemented in Task 6)
#endregion

#region Output
# (placeholder — implemented in Task 7)
#endregion

#region Main
if ($MyInvocation.InvocationName -ne '.') {
    throw 'Script is not yet complete. See implementation plan.'
}
#endregion

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

function Get-IrmData {
    Write-Host 'Collecting Insider Risk Management settings and policies...' -ForegroundColor Cyan

    $settings = $null
    try {
        $settings = Get-InsiderRiskSettings
    } catch {
        Write-Warning "Could not retrieve IRM settings (role may be missing): $_"
    }

    $policies = @()
    try {
        $policies = @(Get-InsiderRiskPolicy)
        Write-Host "Retrieved $($policies.Count) IRM policy(s)." -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve IRM policies: $_"
    }

    $commCompliancePolicies = @()
    try {
        $commCompliancePolicies = @(Get-SupervisoryReviewPolicyV2 -ErrorAction SilentlyContinue)
        Write-Host "Retrieved $($commCompliancePolicies.Count) Communication Compliance policy(s)." -ForegroundColor Green
    } catch {
        Write-Warning "Could not retrieve Communication Compliance policies: $_"
    }

    return [PSCustomObject]@{
        settings                = $settings
        policies                = $policies
        communicationCompliance = $commCompliancePolicies
    }
}
#endregion

#region DSPM inventory

# Known DSPM for AI policy definitions.
# Each entry: canonicalName (the DSPM-created name), policyType, and a legacy prefix if applicable.
$script:DspmPolicyDefinitions = @(
    @{ canonicalName = 'DSPM for AI: Detect sensitive info added to AI sites';                                             policyType = 'DLP' }
    @{ canonicalName = 'DSPM for AI - Block sensitive info from AI sites';                                                  policyType = 'DLP' }
    @{ canonicalName = 'DSPM for AI - Block elevated risk users from submitting prompts to AI apps in Microsoft Edge';      policyType = 'DLP' }
    @{ canonicalName = 'DSPM for AI - Block sensitive info from AI apps in Edge';                                           policyType = 'DLP' }
    @{ canonicalName = 'DSPM for AI - Protect sensitive data from Copilot processing';                                      policyType = 'DLP' }
    @{ canonicalName = 'DSPM for AI - Detect when users visit AI sites';                                                    policyType = 'IRM' }
    @{ canonicalName = 'DSPM for AI - Detect risky AI usage';                                                               policyType = 'IRM' }
    @{ canonicalName = 'DSPM for AI - Unethical behavior in AI apps';                                                       policyType = 'CommunicationCompliance' }
)

# Strips the leading "DSPM for AI" (or "Microsoft AI Hub") prefix to get the discriminating suffix.
# Used to match the legacy prefix variant against canonical names.
function Get-DspmSuffix {
    param([string]$PolicyName)
    # Remove canonical prefix
    $name = $PolicyName -replace '^DSPM for AI\s*[-:]\s*', ''
    # Remove legacy preview prefix
    $name = $name -replace '^Microsoft AI Hub\s*[-:]\s*', ''
    return $name.Trim()
}

function Get-DspmPolicyInventory {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] $DlpPolicies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] $IrmPolicies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] $CommCompliancePolicies
    )

    $inventory = foreach ($def in $script:DspmPolicyDefinitions) {
        $suffix  = Get-DspmSuffix $def.canonicalName
        $matched = $null

        switch ($def.policyType) {
            'DLP' {
                $matched = $DlpPolicies | Where-Object {
                    (Get-DspmSuffix $_.Name) -eq $suffix
                } | Select-Object -First 1
            }
            'IRM' {
                $matched = $IrmPolicies | Where-Object {
                    (Get-DspmSuffix $_.Name) -eq $suffix
                } | Select-Object -First 1
            }
            'CommunicationCompliance' {
                $matched = $CommCompliancePolicies | Where-Object {
                    (Get-DspmSuffix $_.Name) -eq $suffix
                } | Select-Object -First 1
            }
        }

        [PSCustomObject]@{
            policyName  = $def.canonicalName
            policyType  = $def.policyType
            detected    = ($null -ne $matched)
            mode        = if ($null -ne $matched -and $def.policyType -eq 'DLP') { $matched.Mode }    else { $null }
            enabled     = if ($null -ne $matched -and $def.policyType -eq 'DLP') { $matched.Enabled } else { $null }
        }
    }

    return @($inventory)
}
#endregion

#region Output
function Write-PurviewExport {
    param(
        [Parameter(Mandatory)] $Connection,
        [Parameter(Mandatory)] [string]$Environment,
        [Parameter(Mandatory)] [AllowEmptyCollection()] $RetentionPolicies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] $DlpData,
        [Parameter(Mandatory)] $IrmData,
        [Parameter(Mandatory)] [AllowEmptyCollection()] $DspmInventory,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $fileName  = "Purview-Export-$($Connection.TenantID)-$Environment-$timestamp.json"
    $filePath  = Join-Path $OutputPath $fileName

    $envelope = [ordered]@{
        exportedBy             = $Connection.UserPrincipalName
        exportedAt             = (Get-Date -Format 'o')
        environment            = $Environment
        tenantId               = $Connection.TenantID
        auditRetentionPolicies = @($RetentionPolicies)
        dlpPolicies            = @($DlpData)
        insiderRisk            = $IrmData
        dspmPolicyInventory    = @($DspmInventory)
        collectionLimitations  = @(
            @{
                setting    = 'DSPM for AI collection policy status'
                reason     = 'No PowerShell cmdlet exposes collection policy configuration.'
                portalPath = 'Microsoft Purview portal > DSPM for AI > Policies'
            }
            @{
                setting    = 'Data risk assessment results'
                reason     = 'Risk assessment output is portal-only; no API or cmdlet.'
                portalPath = 'Microsoft Purview portal > DSPM for AI > Data risks'
            }
            @{
                setting    = 'Pay-as-you-go billing model enablement'
                reason     = 'No PowerShell cmdlet exposes DSPM billing configuration.'
                portalPath = 'Microsoft Purview portal > DSPM for AI > Settings'
            }
            @{
                setting    = 'Device onboarding status'
                reason     = 'Managed via Microsoft Defender for Endpoint, not Purview cmdlets.'
                portalPath = 'Microsoft Defender portal'
            }
            @{
                setting    = 'Browser extension deployment status'
                reason     = 'Managed via Intune or Group Policy.'
                portalPath = 'Microsoft Intune admin center'
            }
            @{
                setting    = 'Fabric data risk assessment prerequisites'
                reason     = 'Requires separate Fabric Admin REST API connection.'
                portalPath = 'GET https://api.fabric.microsoft.com/v1/admin/tenantsettings'
            }
        )
    }

    $envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $filePath -Encoding UTF8
    Write-Host "JSON export written: $filePath" -ForegroundColor Green

    return [PSCustomObject]@{
        JsonPath = $filePath
    }
}
#endregion

#region Main
if ($MyInvocation.InvocationName -ne '.') {
    throw 'Script is not yet complete. See implementation plan.'
}
#endregion

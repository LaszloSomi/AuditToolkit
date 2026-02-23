<#
.SYNOPSIS
    Exports all Conditional Access policies from a Microsoft 365 tenant.

.DESCRIPTION
    Authenticates to Microsoft Graph using delegated permissions and exports
    all Conditional Access policies to JSON or CSV. Supports Commercial, GCC,
    GCC High (GCCH), and DoD environments.

.PARAMETER Environment
    Target cloud environment. Valid values: Commercial, GCC, GCCH, DoD.
    Defaults to Commercial.

.PARAMETER UserPrincipalName
    UPN of the account used to authenticate to the tenant.

.PARAMETER AuthFlow
    Authentication flow. Valid values: Interactive, DeviceCode.
    Defaults to Interactive.

.PARAMETER OutputFormat
    Output file format. Valid values: JSON, CSV. Defaults to JSON.

.PARAMETER OutputPath
    Directory to write the export file. Defaults to current directory.

.EXAMPLE
    .\Get-CAAudit.ps1 -UserPrincipalName admin@contoso.com

.EXAMPLE
    .\Get-CAAudit.ps1 -Environment GCCH -UserPrincipalName admin@contoso.us -AuthFlow DeviceCode -OutputFormat CSV

.NOTES
    Requires the Microsoft.Graph PowerShell SDK.
    Install: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns -Scope CurrentUser
    Required Graph permission (delegated): Policy.Read.All
    Recommended Graph permission (delegated): Directory.Read.All (to resolve object IDs to display names)
    The authenticating account must hold one of: Conditional Access Administrator, Security Reader,
    Security Administrator, Global Reader, or Global Administrator.

.OUTPUTS
    A JSON or CSV file written to OutputPath named:
    CA-Export-{TenantId}-{Environment}-{Timestamp}.json|csv
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

    [ValidateSet('JSON', 'CSV')]
    [string]$OutputFormat = 'JSON',

    [string]$OutputPath = $PWD.Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Environment configuration
$EnvironmentMap = @{
    Commercial = @{
        GraphEnvironment = 'Global'
        GraphEndpoint    = 'https://graph.microsoft.com'
        AuthAuthority    = 'https://login.microsoftonline.com'
        TokenAudience    = 'https://graph.microsoft.com'
    }
    GCC        = @{
        GraphEnvironment = 'Global'
        GraphEndpoint    = 'https://graph.microsoft.com'
        AuthAuthority    = 'https://login.microsoftonline.com'
        TokenAudience    = 'https://graph.microsoft.com'
    }
    GCCH       = @{
        GraphEnvironment = 'USGov'
        GraphEndpoint    = 'https://graph.microsoft.us'
        AuthAuthority    = 'https://login.microsoftonline.us'
        TokenAudience    = 'https://graph.microsoft.us'
    }
    DoD        = @{
        GraphEnvironment = 'USGovDoD'
        GraphEndpoint    = 'https://dod-graph.microsoft.us'
        AuthAuthority    = 'https://login.microsoftonline.us'
        TokenAudience    = 'https://dod-graph.microsoft.us'
    }
}

function Resolve-Environment {
    param([string]$EnvironmentName)
    $config = $EnvironmentMap[$EnvironmentName]
    if ($null -eq $config) { throw "Unknown environment '$EnvironmentName'. Valid values: $($EnvironmentMap.Keys -join ', ')." }
    Write-Verbose "Environment '$EnvironmentName': Graph=$($config.GraphEndpoint), Auth=$($config.AuthAuthority)"
    return $config
}
#endregion

#region Prerequisites
function Assert-GraphModule {
    $required = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.SignIns')
    foreach ($mod in $required) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            throw "Required module '$mod' is not installed. Run: Install-Module $mod -Scope CurrentUser"
        }
    }
    Write-Verbose "All required modules present."
}
#endregion

#region Authentication
function Connect-ToGraph {
    param(
        [string]$EnvironmentName,
        [string]$Upn,
        [string]$Flow
    )

    $config = Resolve-Environment $EnvironmentName

    $connectParams = @{
        Environment = $config.GraphEnvironment
        Scopes      = @('Policy.Read.All', 'Directory.Read.All')
        NoWelcome   = $true
    }

    if ($Flow -eq 'DeviceCode') {
        $connectParams['UseDeviceAuthentication'] = $true
    }

    Write-Host "Connecting to Microsoft Graph ($EnvironmentName)..." -ForegroundColor Cyan
    Connect-MgGraph @connectParams

    $context = Get-MgContext
    if ($context.Account -ne $Upn) {
        Write-Warning "Signed in as '$($context.Account)' but expected '$Upn'. Proceeding."
    }

    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
    return $context
}
#endregion

#region Data collection
function Get-AllCAPolicies {
    Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan

    $policies = @(Get-MgIdentityConditionalAccessPolicy -All)

    Write-Host "Retrieved $($policies.Count) policies." -ForegroundColor Green
    return $policies
}

function Resolve-DirectoryObjects {
    param([string[]]$Ids)

    $wellKnown = @('All', 'None', 'GuestsOrExternalUsers', '00000000-0000-0000-0000-000000000000')
    $realIds   = $Ids | Where-Object { $_ -notin $wellKnown -and $_ -match '^[0-9a-f-]{36}$' }

    if (-not $realIds) { return @{} }

    $map = @{}
    $batches = [System.Linq.Enumerable]::Chunk([string[]]$realIds, 20)
    foreach ($batch in $batches) {
        $filter = ($batch | ForEach-Object { "id eq '$_'" }) -join ' or '
        try {
            $objects = Get-MgDirectoryObject -Filter $filter -Property id, displayName `
                -ErrorAction SilentlyContinue
            foreach ($obj in $objects) {
                $map[$obj.Id] = $obj.AdditionalProperties['displayName'] ?? $obj.Id
            }
        }
        catch {
            Write-Verbose "Could not resolve batch of IDs: $_"
        }
    }
    return $map
}

function Resolve-PolicyIds {
    param($Policies)

    Write-Host "Resolving directory object display names..." -ForegroundColor Cyan

    $allIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $Policies) {
        $u = $policy.Conditions.Users
        if ($null -ne $u) {
            @($u.IncludeUsers + $u.ExcludeUsers + $u.IncludeGroups + $u.ExcludeGroups +
              $u.IncludeRoles + $u.ExcludeRoles) |
                Where-Object { $_ } |
                ForEach-Object { [void]$allIds.Add($_) }
        }
        $a = $policy.Conditions.Applications
        if ($null -ne $a) {
            @($a.IncludeApplications + $a.ExcludeApplications) |
                Where-Object { $_ } |
                ForEach-Object { [void]$allIds.Add($_) }
        }
    }

    return Resolve-DirectoryObjects -Ids ([string[]]$allIds)
}
#endregion

#region Serialization
function Resolve-Id {
    param([string]$Id, [hashtable]$Map)
    if ([string]::IsNullOrEmpty($Id)) { return $Id }
    if ($Map.ContainsKey($Id)) { return "$Id ($($Map[$Id]))" }
    return $Id
}

function ConvertTo-ExportObject {
    param($Policy, [hashtable]$IdMap)

    $p = $Policy
    $c = $p.Conditions
    $g = $p.GrantControls
    $s = $p.SessionControls

    return [ordered]@{
        # Core metadata
        id               = $p.Id
        displayName      = $p.DisplayName
        state            = $p.State
        createdDateTime  = $p.CreatedDateTime
        modifiedDateTime = $p.ModifiedDateTime
        templateId       = $p.TemplateId

        # Assignments — users
        includeUsers     = @($c.Users.IncludeUsers  | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeUsers     = @($c.Users.ExcludeUsers  | ForEach-Object { Resolve-Id $_ $IdMap })
        includeGroups    = @($c.Users.IncludeGroups | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeGroups    = @($c.Users.ExcludeGroups | ForEach-Object { Resolve-Id $_ $IdMap })
        includeRoles     = @($c.Users.IncludeRoles  | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeRoles     = @($c.Users.ExcludeRoles  | ForEach-Object { Resolve-Id $_ $IdMap })
        includeGuestsOrExternalUsers = $c.Users.IncludeGuestsOrExternalUsers
        excludeGuestsOrExternalUsers = $c.Users.ExcludeGuestsOrExternalUsers
        clientApplications           = $c.ClientApplications

        # Conditions
        includeApplications = @($c.Applications.IncludeApplications | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeApplications = @($c.Applications.ExcludeApplications | ForEach-Object { Resolve-Id $_ $IdMap })
        includeUserActions  = $c.Applications.IncludeUserActions
        authenticationContextClassReferences = $c.Applications.IncludeAuthenticationContextClassReferences
        clientAppTypes      = $c.ClientAppTypes
        platforms           = $c.Platforms
        deviceFilter        = if ($null -ne $c.Devices) { $c.Devices.DeviceFilter } else { $null }
        locations           = $c.Locations
        signInRiskLevels    = $c.SignInRiskLevels
        userRiskLevels      = $c.UserRiskLevels
        servicePrincipalRiskLevels = $c.ServicePrincipalRiskLevels
        insiderRiskLevels   = $c.InsiderRiskLevels
        authenticationFlows = $c.AuthenticationFlows

        # Grant controls
        grantOperator               = if ($null -ne $g) { $g.Operator }               else { $null }
        grantBuiltInControls        = if ($null -ne $g) { $g.BuiltInControls }        else { $null }
        authenticationStrength      = if ($null -ne $g) { $g.AuthenticationStrength } else { $null }
        termsOfUse                  = if ($null -ne $g) { $g.TermsOfUse }             else { $null }
        customAuthenticationFactors = if ($null -ne $g) { $g.CustomAuthenticationFactors } else { $null }

        # Session controls
        signInFrequency                 = if ($null -ne $s) { $s.SignInFrequency }                 else { $null }
        persistentBrowser               = if ($null -ne $s) { $s.PersistentBrowser }               else { $null }
        applicationEnforcedRestrictions = if ($null -ne $s) { $s.ApplicationEnforcedRestrictions } else { $null }
        cloudAppSecurity                = if ($null -ne $s) { $s.CloudAppSecurity }                else { $null }
        disableResilienceDefaults       = if ($null -ne $s) { $s.DisableResilienceDefaults }       else { $null }
        continuousAccessEvaluation      = if ($null -ne $s) { $s.AdditionalProperties['continuousAccessEvaluation'] } else { $null }
        secureSignInSession             = if ($null -ne $s) { $s.AdditionalProperties['secureSignInSession'] } else { $null }
    }
}
#endregion

#region Output
function Get-OutputFileName {
    param([string]$TenantId, [string]$Env, [string]$Format)
    $timestamp = Get-Date -Format 'yyyyMMddTHHmmssZ'
    $ext = $Format.ToLower()
    return "CA-Export-$TenantId-$Env-$timestamp.$ext"
}

function Write-JsonExport {
    param($ExportPolicies, $Context, [string]$Env, [string]$FilePath)

    $envelope = [ordered]@{
        exportedBy  = $Context.Account
        exportedAt  = (Get-Date -Format 'o')
        environment = $Env
        tenantId    = $Context.TenantId
        policyCount = $ExportPolicies.Count
        policies    = $ExportPolicies
    }

    $envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $FilePath -Encoding UTF8
    Write-Host "JSON export written: $FilePath" -ForegroundColor Green
}

function Write-CsvExport {
    param($ExportPolicies, [string]$FilePath)

    $rows = $ExportPolicies | ForEach-Object {
        $row = [ordered]@{}
        foreach ($key in $_.Keys) {
            $val = $_[$key]
            if ($null -eq $val) {
                $row[$key] = ''
            } elseif ($val -is [string] -or $val -is [bool] -or $val -is [datetime]) {
                $row[$key] = $val
            } else {
                $row[$key] = $val | ConvertTo-Json -Compress -Depth 10
            }
        }
        [PSCustomObject]$row
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV export written: $FilePath" -ForegroundColor Green
}
#endregion

#region Main
Assert-GraphModule
$context = Connect-ToGraph -EnvironmentName $Environment -Upn $UserPrincipalName -Flow $AuthFlow

try {
    $policies       = Get-AllCAPolicies
    $idMap          = Resolve-PolicyIds -Policies $policies
    $exportPolicies = @($policies | ForEach-Object { ConvertTo-ExportObject -Policy $_ -IdMap $idMap })

    $fileName = Get-OutputFileName -TenantId $context.TenantId -Env $Environment -Format $OutputFormat
    $filePath = Join-Path -Path $OutputPath -ChildPath $fileName

    if ($OutputFormat -eq 'JSON') {
        Write-JsonExport -ExportPolicies $exportPolicies -Context $context -Env $Environment -FilePath $filePath
    } else {
        Write-CsvExport -ExportPolicies $exportPolicies -FilePath $filePath
    }

    Write-Host "`nAudit complete. $($policies.Count) policies exported to: $filePath" -ForegroundColor Cyan
}
finally {
    Disconnect-MgGraph | Out-Null
    Write-Verbose "Disconnected from Microsoft Graph."
}
#endregion

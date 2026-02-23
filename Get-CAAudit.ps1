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
    param([string]$Env)
    $config = $EnvironmentMap[$Env]
    if (-not $config) { throw "Unknown environment: $Env" }
    Write-Verbose "Environment '$Env': Graph=$($config.GraphEndpoint), Auth=$($config.AuthAuthority)"
    return $config
}
#endregion

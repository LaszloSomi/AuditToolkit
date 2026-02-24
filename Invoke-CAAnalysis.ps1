#Requires -Version 7.2
<#
.SYNOPSIS
    Analyses a CA policy export for misconfigurations that could block Microsoft 365 Copilot.

.DESCRIPTION
    Reads a JSON export produced by Get-CAAudit.ps1, runs seven rule checks, and writes
    a Markdown report and JSON findings file. Fully offline — no network calls, no Graph auth.

.PARAMETER InputPath
    Path to the CA export JSON file produced by Get-CAAudit.ps1.

.PARAMETER CopilotAppIds
    List of Microsoft 365 Copilot application GUIDs to check for explicit scoping.
    Defaults to the built-in list of known Commercial Copilot app IDs.

.PARAMETER OutputPath
    Directory to write the two output files. Defaults to the current directory.

.EXAMPLE
    .\Invoke-CAAnalysis.ps1 -InputPath .\CA-Export-contoso-Commercial-20260224T000000Z.json

.NOTES
    #Requires -Version 7.2
    No Microsoft.Graph modules required. Fully offline.

.OUTPUTS
    CA-Analysis-{tenantId}-{environment}-{timestamp}.md
    CA-Analysis-{tenantId}-{environment}-{timestamp}.json
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    # Known Microsoft 365 Copilot application IDs (Commercial).
    # GCC High and DoD use different app registrations — override with -CopilotAppIds as needed.
    # Sources: https://learn.microsoft.com/en-us/copilot/microsoft-365/microsoft-365-copilot-requirements
    [string[]]$CopilotAppIds = @(
        'd3590ed6-52b3-4102-aeff-aad2292ab01c',  # Microsoft Office (Word, Excel, PowerPoint, Teams + in-app Copilot)
        '0be67e7d-4b14-4f1c-8e7a-ab3e5e3dff0c'  # Microsoft Copilot (copilot.microsoft.com)
    ),

    [string]$OutputPath = $PWD.Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Import-CAExport {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Input file not found: '$Path'"
    }

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    try {
        $export = $raw | ConvertFrom-Json
    } catch {
        throw "Failed to parse CA export JSON: $_"
    }

    foreach ($field in @('exportedBy', 'exportedAt', 'environment', 'tenantId', 'policyCount', 'policies')) {
        if ($null -eq $export.$field) {
            throw "CA export JSON is missing required field: '$field'"
        }
    }

    return $export
}

# Returns grantBuiltInControls as a normalised array regardless of whether
# the JSON field is a string (single control) or an array (multiple controls).
function Get-BuiltInControls {
    param($Controls)
    if ($null -eq $Controls) { return @() }
    if ($Controls -is [string]) { return @($Controls) }
    return @($Controls)
}

# Returns true if any element of $Applications matches $AppId (exact GUID or
# "GUID (Display Name)" format produced by Get-CAAudit.ps1).
function Test-AppIdMatch {
    param(
        [string]$AppId,
        $Applications   # string or array
    )
    if ($null -eq $Applications) { return $false }
    $apps = if ($Applications -is [string]) { @($Applications) } else { @($Applications) }
    foreach ($app in $apps) {
        if ($app -eq $AppId -or $app -like "$AppId (*") { return $true }
    }
    return $false
}

#endregion Helpers

#region Rules

function Test-DirectBlock {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    $findings = @()
    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }

        $controls = Get-BuiltInControls $policy.grantBuiltInControls
        if ('block' -notin $controls) { continue }

        # Policies scoped to user actions (includeApplications = null) are not app-access blocks.
        if ($null -eq $policy.includeApplications) { continue }

        $apps = if ($policy.includeApplications -is [string]) { @($policy.includeApplications) } else { @($policy.includeApplications) }
        $appMatchAll     = 'All' -in $apps
        $appMatchCopilot = $CopilotAppIds | Where-Object { Test-AppIdMatch -AppId $_ -Applications $policy.includeApplications } | Select-Object -First 1

        if (-not ($appMatchAll -or $appMatchCopilot)) { continue }
        if ($policy.includeUsers -ne 'All') { continue }

        $scope = if ($appMatchAll) { 'all applications including Microsoft 365 Copilot' } else { 'Microsoft 365 Copilot' }
        $findings += [PSCustomObject]@{
            ruleId         = 'R1'
            severity       = 'Critical'
            policyId       = $policy.id
            policyName     = $policy.displayName
            policyState    = $policy.state
            summary        = "Policy '$($policy.displayName)' blocks all users from accessing $scope."
            detail         = "This policy grants the 'block' control for all users with application scope covering Microsoft 365 Copilot. Any user subject to this policy will be denied access to Copilot entirely."
            recommendation = "Exclude Copilot application IDs from this policy's scope, add an exclusion group for Copilot-licensed users, or replace the block control with a conditional grant (e.g., MFA + compliant device)."
        }
    }
    return $findings
}

function Test-CompliantDeviceGate {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    $findings = @()
    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }

        $controls = Get-BuiltInControls $policy.grantBuiltInControls
        if ('compliantDevice' -notin $controls) { continue }

        # If the operator is OR and mfa is an alternative, the user can satisfy
        # the policy with MFA alone — compliant device is not strictly required.
        if ($policy.grantOperator -eq 'OR' -and 'mfa' -in $controls) { continue }

        if ($policy.includeApplications -ne 'All') { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'R2'
            severity       = 'Critical'
            policyId       = $policy.id
            policyName     = $policy.displayName
            policyState    = $policy.state
            summary        = "Policy '$($policy.displayName)' requires a compliant device for all applications, which Copilot web experiences cannot satisfy."
            detail         = "Microsoft 365 Copilot web experiences (copilot.microsoft.com) run in a browser and do not report device compliance status. Users accessing Copilot from these entry points will be blocked by this policy."
            recommendation = "Add MFA as an OR alternative to compliant device (set grantOperator = OR with controls: compliantDevice + mfa), or exclude Copilot app IDs from this policy's scope."
        }
    }
    return $findings
}

#endregion Rules

#region Report
# (Write-AnalysisReport added in Task 10)
#endregion Report

#region Main
# Guard ensures the main execution block does not run when this script is dot-sourced
# for Pester testing (InvocationName = '.' when dot-sourced).
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-Path -Path $OutputPath -PathType Container)) {
        throw "OutputPath '$OutputPath' does not exist or is not a directory."
    }

    $export = Import-CAExport -Path $InputPath
    Write-Host "Analysing $($export.policyCount) policies in tenant $($export.tenantId)..." -ForegroundColor Cyan

    # Rule execution and report writing are added as functions are implemented.
}
#endregion Main

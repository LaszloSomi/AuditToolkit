#Requires -Version 7.2
<#
.SYNOPSIS
    Analyses a Purview export for DSPM for AI policy readiness.

.DESCRIPTION
    Reads a JSON export produced by Get-PurviewAudit.ps1, runs four rule checks,
    and writes a Markdown report and JSON findings file. Fully offline — no network
    calls, no authentication required.

.PARAMETER InputPath
    Path to the Purview export JSON file produced by Get-PurviewAudit.ps1.

.PARAMETER OutputPath
    Directory to write the two output files. Defaults to the current directory.

.EXAMPLE
    .\Invoke-PurviewAnalysis.ps1 -InputPath .\Purview-Export-contoso-Commercial-20260228T000000Z.json

.OUTPUTS
    Purview-Analysis-{tenantId}-{environment}-{timestamp}.md
    Purview-Analysis-{tenantId}-{environment}-{timestamp}.json
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [string]$OutputPath = $PWD.Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Import-PurviewExport {
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
        throw "Failed to parse Purview export JSON: $_"
    }

    foreach ($field in @('exportedBy', 'exportedAt', 'environment', 'tenantId',
                          'dspmPolicyInventory', 'auditRetentionPolicies', 'collectionLimitations')) {
        if ($null -eq $export.$field) {
            throw "Purview export JSON is missing required field: '$field'"
        }
    }

    return $export
}

#endregion Helpers

#region Rules

function Test-DspmPolicyNotDeployed {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] $DspmInventory
    )

    $findings = @()
    foreach ($entry in $DspmInventory) {
        if ($entry.detected) { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'P1'
            severity       = 'Warning'
            policyName     = $entry.policyName
            policyType     = $entry.policyType
            summary        = "DSPM for AI policy '$($entry.policyName)' ($($entry.policyType)) is not deployed in this tenant."
            detail         = "This policy is part of the DSPM for AI default policy set and has not been created in this tenant. Without it, the corresponding AI governance control is absent."
            recommendation = "In the Microsoft Purview portal, navigate to DSPM for AI > Policies and activate this policy."
        }
    }
    return $findings
}

function Test-DspmPolicyTestMode {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] $DspmInventory
    )

    $findings = @()
    foreach ($entry in $DspmInventory) {
        if ($entry.policyType -ne 'DLP') { continue }
        if (-not $entry.detected) { continue }
        if ($entry.mode -notin @('TestWithNotifications', 'TestWithoutNotifications')) { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'P2'
            severity       = 'Warning'
            policyName     = $entry.policyName
            policyType     = $entry.policyType
            summary        = "DSPM for AI DLP policy '$($entry.policyName)' is deployed but in test mode ($($entry.mode)) — it is not enforcing."
            detail         = "Test mode policies log matches and optionally send notifications but do not enforce the policy action. Data submitted to AI apps is not blocked or restricted while this policy is in test mode."
            recommendation = "Switch the policy mode to 'Enable' in the Microsoft Purview portal to enforce protection."
        }
    }
    return $findings
}

# (placeholder — Rules P3, A1 added in Tasks 4-5)
#endregion Rules

#region Report
# (placeholder — implemented in Task 6)
#endregion Report

#region Main
if ($MyInvocation.InvocationName -ne '.') {
    throw 'Script is not yet complete. See implementation plan.'
}
#endregion Main

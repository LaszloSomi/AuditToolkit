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
# (placeholder — implemented in Tasks 2-5)
#endregion Rules

#region Report
# (placeholder — implemented in Task 6)
#endregion Report

#region Main
if ($MyInvocation.InvocationName -ne '.') {
    throw 'Script is not yet complete. See implementation plan.'
}
#endregion Main

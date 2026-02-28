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

function Test-DspmPolicyDisabled {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] $DspmInventory
    )

    $findings = @()
    foreach ($entry in $DspmInventory) {
        if ($entry.policyType -ne 'DLP') { continue }
        if (-not $entry.detected) { continue }
        if ($entry.enabled -ne $false) { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'P3'
            severity       = 'Warning'
            policyName     = $entry.policyName
            policyType     = $entry.policyType
            summary        = "DSPM for AI DLP policy '$($entry.policyName)' is deployed but disabled — it is not enforcing."
            detail         = "The policy exists in this tenant but has been explicitly disabled. It is not evaluating any traffic and provides no data protection."
            recommendation = "Re-enable the policy in the Microsoft Purview portal under DSPM for AI > Policies."
        }
    }
    return $findings
}

function Test-CopilotInteractionRetention {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] $RetentionPolicies
    )

    $covered = $RetentionPolicies | Where-Object {
        # Normalise: RecordTypes may be a string (single type) or array.
        'CopilotInteraction' -in @($_.RecordTypes)
    }

    if ($null -ne $covered -and @($covered).Count -gt 0) {
        return @()
    }

    return @([PSCustomObject]@{
        ruleId         = 'A1'
        severity       = 'Info'
        policyName     = '(no policy)'
        policyType     = $null
        summary        = 'No audit log retention policy covers the CopilotInteraction record type.'
        detail         = 'DSPM for AI surfaces AI risk signals from the audit log. Without a custom retention policy covering CopilotInteraction, these records are kept for only 90 days (the Microsoft default). Extended retention is recommended for governance and investigation workflows.'
        recommendation = 'Create a custom audit retention policy in Microsoft Purview that includes the CopilotInteraction record type with a retention period appropriate for your organisation.'
    })
}

function Test-DlpCopilotCoverage {
    # T-11: RTM FR-D1
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] $DlpPolicies
    )

    $copilotWorkloads = @('CopilotInteractions', 'M365Copilot')

    $covered = $null
    if ($null -ne $DlpPolicies) {
        $covered = @($DlpPolicies) | Where-Object {
            $p = $_.policy
            $p.Mode -eq 'Enable' -and
            $p.Enabled -eq $true -and
            ($copilotWorkloads | Where-Object { $p.Workload -like "*$_*" })
        } | Select-Object -First 1
    }

    if ($null -ne $covered) {
        return @()
    }

    return @([PSCustomObject]@{
        ruleId         = 'D1'
        severity       = 'Warning'
        policyName     = '(no policy)'
        policyType     = 'DLP'
        summary        = 'No enforced DLP policy covers a Copilot workload (CopilotInteractions or M365Copilot).'
        detail         = 'Without a DLP policy scoped to the Copilot workload in enforce mode, data submitted to Copilot is not evaluated against DLP rules. Sensitive information can be shared with Copilot without restriction.'
        recommendation = 'Create or enable a DLP policy in Microsoft Purview that targets the CopilotInteractions or M365Copilot workload and set its mode to Enable.'
    })
}

function Test-IrmAiPolicyActive {
    # T-12: RTM FR-I1
    param(
        [Parameter(Mandatory)] [AllowNull()] $InsiderRisk
    )

    $aiTemplates = @('RiskyAIUsage', 'DataLeak', 'DataLeakByPriorityUser', 'DataTheftByDepartingEmployee')

    $active = $null
    if ($null -ne $InsiderRisk -and $null -ne $InsiderRisk.policies) {
        $active = @($InsiderRisk.policies) | Where-Object {
            $_.PolicyStatus -eq 'Active' -and $_.PolicyTemplate -in $aiTemplates
        } | Select-Object -First 1
    }

    if ($null -ne $active) {
        return @()
    }

    return @([PSCustomObject]@{
        ruleId         = 'I1'
        severity       = 'Info'
        policyName     = '(no active policy)'
        policyType     = 'IRM'
        summary        = 'No active Insider Risk Management policy uses an AI-relevant template.'
        detail         = 'IRM policies with templates such as RiskyAIUsage, DataLeak, DataLeakByPriorityUser, or DataTheftByDepartingEmployee generate risk signals that DSPM for AI surfaces as AI-related insider risk. Without an active policy of this type, AI-related insider risk events are not scored or surfaced.'
        recommendation = 'In Microsoft Purview, navigate to Insider Risk Management > Policies and create or activate a policy using the Risky AI usage, Data leak, or Data theft by departing employee template.'
    })
}
#endregion Rules

#region Report

function Write-PurviewAnalysisReport {
    param(
        [Parameter(Mandatory)] $Export,
        [Parameter(Mandatory)] $Findings,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $baseName  = "Purview-Analysis-$($Export.tenantId)-$($Export.environment)-$timestamp"
    $mdPath    = Join-Path $OutputPath "$baseName.md"
    $jsonPath  = Join-Path $OutputPath "$baseName.json"

    $warningCount = @($Findings | Where-Object severity -eq 'Warning').Count
    $infoCount    = @($Findings | Where-Object severity -eq 'Info').Count

    # ── Markdown ──────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# Purview Analysis — DSPM for AI Readiness')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("**Tenant:** $($Export.tenantId)  |  **Environment:** $($Export.environment)")
    [void]$sb.AppendLine("**Exported by:** $($Export.exportedBy)  |  **Analysed:** $(Get-Date -Format 'o')")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Severity | Count |')
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| 🟡 Warning | $warningCount |")
    [void]$sb.AppendLine("| 🔵 Info | $infoCount |")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Findings')
    [void]$sb.AppendLine('')

    if (@($Findings).Count -eq 0) {
        [void]$sb.AppendLine('_No issues found._')
    } else {
        $orderedFindings = @(
            @($Findings | Where-Object severity -eq 'Warning')
            @($Findings | Where-Object severity -eq 'Info')
        )
        foreach ($f in $orderedFindings) {
            $icon = switch ($f.severity) { 'Warning' { '🟡' } default { '🔵' } }
            [void]$sb.AppendLine("### $icon $($f.ruleId) — $($f.summary)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Policy:** $($f.policyName)  |  **Type:** $($f.policyType ?? 'N/A')  |  **Severity:** $($f.severity)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine($f.detail)
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Recommendation:** $($f.recommendation)")
            [void]$sb.AppendLine('')
        }
    }

    [void]$sb.AppendLine('## DSPM for AI Policy Inventory')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Policy | Type | Detected | Mode |')
    [void]$sb.AppendLine('|---|---|---|---|')
    foreach ($entry in $Export.dspmPolicyInventory) {
        $detected = if ($entry.detected) { 'Yes' } else { 'No' }
        $mode     = if ($null -ne $entry.mode) { $entry.mode } else { '-' }
        [void]$sb.AppendLine("| $($entry.policyName) | $($entry.policyType) | $detected | $mode |")
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('## Collection Limitations')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('The following settings could not be collected via PowerShell and must be verified manually in the portal:')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Setting | Reason | Portal Path |')
    [void]$sb.AppendLine('|---|---|---|')
    foreach ($lim in $Export.collectionLimitations) {
        [void]$sb.AppendLine("| $($lim.setting) | $($lim.reason) | $($lim.portalPath) |")
    }

    Set-Content -Path $mdPath -Value $sb.ToString() -Encoding UTF8
    Write-Host "Markdown report written: $mdPath" -ForegroundColor Green

    # ── JSON ──────────────────────────────────────────────────────────────────
    $envelope = [ordered]@{
        analysedBy   = 'Invoke-PurviewAnalysis.ps1'
        analysedAt   = (Get-Date -Format 'o')
        tenantId     = $Export.tenantId
        environment  = $Export.environment
        findingCount = @($Findings).Count
        findings     = $Findings
    }
    $envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "JSON findings written: $jsonPath" -ForegroundColor Green

    return [PSCustomObject]@{
        MarkdownPath = $mdPath
        JsonPath     = $jsonPath
    }
}

#endregion Report

#region Main
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-Path -Path $OutputPath -PathType Container)) {
        throw "OutputPath '$OutputPath' does not exist or is not a directory."
    }

    $export = Import-PurviewExport -Path $InputPath
    Write-Host "Analysing Purview export for tenant $($export.tenantId) ($($export.environment))..." -ForegroundColor Cyan

    $findings = @()
    $findings += @(Test-DspmPolicyNotDeployed       -DspmInventory     $export.dspmPolicyInventory)
    $findings += @(Test-DspmPolicyTestMode          -DspmInventory     $export.dspmPolicyInventory)
    $findings += @(Test-DspmPolicyDisabled          -DspmInventory     $export.dspmPolicyInventory)
    $findings += @(Test-CopilotInteractionRetention -RetentionPolicies $export.auditRetentionPolicies)
    $findings += @(Test-DlpCopilotCoverage          -DlpPolicies       $export.dlpPolicies)
    $findings += @(Test-IrmAiPolicyActive           -InsiderRisk       $export.insiderRisk)

    $severitySummary = ($findings | Group-Object severity | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
    Write-Host "Found $($findings.Count) issue(s)$(if ($findings.Count -gt 0) { ": $severitySummary" })." `
        -ForegroundColor $(if ($findings.Count -eq 0) { 'Green' } else { 'Yellow' })

    $result = Write-PurviewAnalysisReport -Export $export -Findings $findings -OutputPath $OutputPath

    Write-Host ''
    Write-Host 'Analysis complete.' -ForegroundColor Cyan
    Write-Host "  Markdown: $($result.MarkdownPath)"
    Write-Host "  JSON:     $($result.JsonPath)"
}
#endregion Main

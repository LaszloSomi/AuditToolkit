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

function Test-SignInFrequency {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    $findings = @()
    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }

        $sif = $policy.signInFrequency
        if ($null -eq $sif) { continue }
        if ($sif.IsEnabled -ne $true) { continue }
        if ($sif.FrequencyInterval -ne 'everyTime') { continue }

        if ($policy.includeApplications -ne 'All') { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'R3'
            severity       = 'Warning'
            policyId       = $policy.id
            policyName     = $policy.displayName
            policyState    = $policy.state
            summary        = "Policy '$($policy.displayName)' forces full re-authentication every session for all applications, breaking Copilot continuity."
            detail         = "Sign-in frequency set to 'Every time' requires full re-authentication at every new session. Microsoft 365 Copilot relies on persistent token lifetimes for a seamless conversational experience; this setting interrupts Copilot sessions and degrades usability."
            recommendation = "Either exclude Copilot app IDs from this policy's scope, or change the sign-in frequency to a bounded interval (e.g., 1 hour or 8 hours) rather than 'Every time'."
        }
    }
    return $findings
}

function Test-ReportOnlyRisk {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    $findings = @()
    $reportOnlyPolicies = @($Policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

    foreach ($policy in $reportOnlyPolicies) {
        # Create a synthetic enabled copy via JSON round-trip to avoid mutating the original.
        $simulatedJson = $policy | ConvertTo-Json -Depth 20
        $simulated = $simulatedJson | ConvertFrom-Json
        $simulated.state = 'enabled'

        $wouldTrigger = @()
        if (@(Test-DirectBlock          -Policies @($simulated) -CopilotAppIds $CopilotAppIds).Count -gt 0) { $wouldTrigger += 'R1 (Direct Block)' }
        if (@(Test-CompliantDeviceGate  -Policies @($simulated) -CopilotAppIds $CopilotAppIds).Count -gt 0) { $wouldTrigger += 'R2 (Compliant Device Gate)' }
        if (@(Test-SignInFrequency      -Policies @($simulated) -CopilotAppIds $CopilotAppIds).Count -gt 0) { $wouldTrigger += 'R3 (Sign-in Frequency)' }

        if ($wouldTrigger.Count -eq 0) { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'R4'
            severity       = 'Warning'
            policyId       = $policy.id
            policyName     = $policy.displayName
            policyState    = $policy.state
            summary        = "Report-only policy '$($policy.displayName)' would trigger $($wouldTrigger -join ', ') if switched to enforced."
            detail         = "This policy is currently in report-only mode and is not enforcing its controls. Enabling it would create the Copilot-blocking issues listed above."
            recommendation = "Before enabling this policy, review and apply the recommendations for the triggered rules. Consider excluding Copilot app IDs or adjusting controls before enforcement."
        }
    }
    return $findings
}

function Test-TokenProtection {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    $findings = @()
    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }

        $sss = $policy.secureSignInSession
        if ($null -eq $sss) { continue }

        $isEnabled = if ($null -ne $sss.IsEnabled) { [bool]$sss.IsEnabled }
                     elseif ($null -ne $sss.isEnabled) { [bool]$sss.isEnabled }
                     else { $true }

        if (-not $isEnabled) { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'R5'
            severity       = 'Warning'
            policyId       = $policy.id
            policyName     = $policy.displayName
            policyState    = $policy.state
            summary        = "Policy '$($policy.displayName)' enables token protection (secure sign-in session binding), which Microsoft 365 Copilot does not currently support."
            detail         = "Token protection binds access tokens to a specific device using a cryptographic proof key. Microsoft 365 Copilot does not implement token binding and may fail to access protected resources when this control is enforced."
            recommendation = "Exclude Microsoft 365 Copilot application IDs from this policy's scope, or verify with Microsoft support that Copilot supports token binding in your environment before enforcing."
        }
    }
    return $findings
}

function Test-MfaCoverageGap {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }
        if ($policy.includeUsers -ne 'All') { continue }
        if ($policy.includeApplications -ne 'All') { continue }

        $controls = Get-BuiltInControls $policy.grantBuiltInControls
        $hasMfa = 'mfa' -in $controls
        $hasAuthStrength = ($null -ne $policy.authenticationStrength -and
                            -not [string]::IsNullOrEmpty($policy.authenticationStrength.Id))

        if ($hasMfa -or $hasAuthStrength) { return @() }
    }

    return @([PSCustomObject]@{
        ruleId         = 'R6'
        severity       = 'Info'
        policyId       = $null
        policyName     = '(no policy)'
        policyState    = $null
        summary        = 'No Conditional Access policy enforces MFA for all users and all applications.'
        detail         = 'Microsoft 365 Copilot requires multi-factor authentication. Without a baseline MFA policy covering all users and all applications, users can access Copilot without completing MFA.'
        recommendation = "Create or verify a CA policy with: state = enabled, includeUsers = All, includeApplications = All, grantBuiltInControls includes 'mfa' (or authenticationStrength set to a phishing-resistant method)."
    })
}

function Test-CopilotAppScoping {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$CopilotAppIds
    )

    $findings = @()
    foreach ($policy in $Policies) {
        $matched = @()
        foreach ($id in $CopilotAppIds) {
            if ((Test-AppIdMatch -AppId $id -Applications $policy.includeApplications) -or
                (Test-AppIdMatch -AppId $id -Applications $policy.excludeApplications)) {
                $matched += $id
            }
        }

        if ($matched.Count -eq 0) { continue }

        $findings += [PSCustomObject]@{
            ruleId         = 'R7'
            severity       = 'Info'
            policyId       = $policy.id
            policyName     = $policy.displayName
            policyState    = $policy.state
            summary        = "Policy '$($policy.displayName)' explicitly scopes Microsoft 365 Copilot app(s): $($matched -join ', ')."
            detail         = "One or more known Microsoft 365 Copilot application IDs appear in this policy's include or exclude application list, meaning the policy specifically targets or exempts Copilot."
            recommendation = "Review to confirm the scoping is intentional. If the policy was designed for other applications and Copilot was included inadvertently, consider removing it from the scope."
        }
    }
    return $findings
}

#endregion Rules

#region Report

function Write-AnalysisReport {
    param(
        [Parameter(Mandatory)] $Export,
        [Parameter(Mandatory)] $Findings,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $baseName  = "CA-Analysis-$($Export.tenantId)-$($Export.environment)-$timestamp"
    $mdPath    = Join-Path $OutputPath "$baseName.md"
    $jsonPath  = Join-Path $OutputPath "$baseName.json"

    $criticalCount = @($Findings | Where-Object severity -eq 'Critical').Count
    $warningCount  = @($Findings | Where-Object severity -eq 'Warning').Count
    $infoCount     = @($Findings | Where-Object severity -eq 'Info').Count

    $policiesWithFindings = @($Findings | Where-Object policyId | Select-Object -ExpandProperty policyId -Unique)
    $cleanPolicies = @($Export.policies | Where-Object { $_.id -notin $policiesWithFindings })

    # ── Markdown ──────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('# CA Policy Analysis — Copilot Readiness')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("**Tenant:** $($Export.tenantId)  |  **Environment:** $($Export.environment)")
    [void]$sb.AppendLine("**Exported by:** $($Export.exportedBy)  |  **Analysed:** $(Get-Date -Format 'o')")
    [void]$sb.AppendLine("**Policies analysed:** $($Export.policyCount)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Summary')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Severity | Count |')
    [void]$sb.AppendLine('|---|---|')
    [void]$sb.AppendLine("| 🔴 Critical | $criticalCount |")
    [void]$sb.AppendLine("| 🟡 Warning | $warningCount |")
    [void]$sb.AppendLine("| 🔵 Info | $infoCount |")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Findings')
    [void]$sb.AppendLine('')

    if ($Findings.Count -eq 0) {
        [void]$sb.AppendLine('_No issues found._')
    } else {
        $orderedFindings = @(
            @($Findings | Where-Object severity -eq 'Critical')
            @($Findings | Where-Object severity -eq 'Warning')
            @($Findings | Where-Object severity -eq 'Info')
        )
        foreach ($f in $orderedFindings) {
            $icon = switch ($f.severity) { 'Critical' { '🔴' } 'Warning' { '🟡' } default { '🔵' } }
            [void]$sb.AppendLine("### $icon $($f.ruleId) — $($f.summary)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Policy:** $($f.policyName)  |  **State:** $($f.policyState ?? 'N/A')  |  **Severity:** $($f.severity)")
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine($f.detail)
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine("**Recommendation:** $($f.recommendation)")
            [void]$sb.AppendLine('')
        }
    }

    [void]$sb.AppendLine('## Policies With No Issues')
    [void]$sb.AppendLine('')
    if ($cleanPolicies.Count -eq 0) {
        [void]$sb.AppendLine('_All policies had at least one finding._')
    } else {
        foreach ($p in $cleanPolicies) {
            [void]$sb.AppendLine("- $($p.displayName)")
        }
    }

    Set-Content -Path $mdPath -Value $sb.ToString() -Encoding UTF8
    Write-Host "Markdown report written: $mdPath" -ForegroundColor Green

    # ── JSON ──────────────────────────────────────────────────────────────────
    $envelope = [ordered]@{
        analysedBy   = 'Invoke-CAAnalysis.ps1'
        analysedAt   = (Get-Date -Format 'o')
        tenantId     = $Export.tenantId
        environment  = $Export.environment
        policyCount  = $Export.policyCount
        findingCount = $Findings.Count
        findings     = $Findings
    }
    $envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "JSON findings written:   $jsonPath" -ForegroundColor Green

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

    $export = Import-CAExport -Path $InputPath
    Write-Host "Analysing $($export.policyCount) policies in tenant $($export.tenantId) ($($export.environment))..." -ForegroundColor Cyan

    $findings = @()
    $findings += @(Test-DirectBlock         -Policies $export.policies -CopilotAppIds $CopilotAppIds)
    $findings += @(Test-CompliantDeviceGate -Policies $export.policies -CopilotAppIds $CopilotAppIds)
    $findings += @(Test-SignInFrequency     -Policies $export.policies -CopilotAppIds $CopilotAppIds)
    $findings += @(Test-ReportOnlyRisk      -Policies $export.policies -CopilotAppIds $CopilotAppIds)
    $findings += @(Test-TokenProtection     -Policies $export.policies -CopilotAppIds $CopilotAppIds)
    $findings += @(Test-MfaCoverageGap      -Policies $export.policies -CopilotAppIds $CopilotAppIds)
    $findings += @(Test-CopilotAppScoping   -Policies $export.policies -CopilotAppIds $CopilotAppIds)

    $severitySummary = ($findings | Group-Object severity | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
    Write-Host "Found $($findings.Count) issue(s)$(if ($findings.Count -gt 0) { ": $severitySummary" })." `
        -ForegroundColor $(if ($findings.Count -eq 0) { 'Green' } else { 'Yellow' })

    $result = Write-AnalysisReport -Export $export -Findings $findings -OutputPath $OutputPath

    Write-Host ''
    Write-Host 'Analysis complete.' -ForegroundColor Cyan
    Write-Host "  Markdown: $($result.MarkdownPath)"
    Write-Host "  JSON:     $($result.JsonPath)"
}
#endregion Main

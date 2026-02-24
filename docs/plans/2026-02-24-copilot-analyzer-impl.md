# Copilot CA Policy Analyzer — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `Invoke-CAAnalysis.ps1` (7-rule offline PowerShell analyzer) and `copilot-agent/` (M365 Copilot declarative agent) per `docs/plans/2026-02-24-copilot-analyzer-design.md`.

**Architecture:** Two independent tools sharing the same rule set. The PowerShell script reads a CA export JSON, runs seven named rule functions, and writes a Markdown + JSON report — no network calls, no Graph auth. The declarative agent exposes the same logic as a Copilot Studio agent: user pastes the export JSON into chat, agent returns findings in the standard format.

**Tech Stack:** PowerShell 7.2+, Pester 5.x (TDD), JSON (CA export + output), Markdown (report), Copilot Studio declarative agent schema v2.1

**Test data:** `CA-Export-f3b7001b-92fa-4ac8-b755-d37ead1ff538-Commercial-20260224T000613Z.json` (4 policies; expected: 1 Warning finding — R4 firing for the report-only everyTime re-auth policy)

---

## Task 1: Script Scaffold — Parameters, Dot-Source Guard, Import-CAExport, Helpers

**Files:**
- Create: `Invoke-CAAnalysis.ps1`

**Step 1: Create the script scaffold**

```powershell
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
# (Rule functions added in Tasks 3–9)
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
```

**Step 2: Verify the script is syntactically valid**

```powershell
pwsh -NoProfile -Command "& { . ./Invoke-CAAnalysis.ps1 -InputPath dummy 2>&1 | Out-Null; Write-Host 'Scaffold OK' }"
```

Expected: `Scaffold OK` (main block skipped because dot-source guard fires — the `-Command` context is not a dot-source, but `InputPath 'dummy'` will fail in Import-CAExport which is only called from the main block; if running directly the script will error on Import-CAExport since 'dummy' doesn't exist, but the point is it parses/loads correctly — adjust test to dot-source):

Actually, run this to verify parsing:

```powershell
pwsh -NoProfile -Command "& { [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path ./Invoke-CAAnalysis.ps1), [ref]`$null, [ref]`$errors); if (`$errors.Count -eq 0) { 'Syntax OK' } else { `$errors } }"
```

Expected: `Syntax OK`

**Step 3: Commit**

```bash
git add Invoke-CAAnalysis.ps1
git commit -m "feat: add Invoke-CAAnalysis.ps1 scaffold with Import-CAExport and helpers"
```

---

## Task 2: Pester Infrastructure

**Files:**
- Create: `tests/` (directory)
- Create: `tests/.gitkeep` (placeholder; removed once test files are added)

**Step 1: Verify Pester 5.x is available**

```powershell
pwsh -NoProfile -Command "Get-Module -ListAvailable Pester | Select-Object Name, Version | Sort-Object Version -Descending | Select-Object -First 1"
```

Expected: Pester 5.x. If only 3.x or 4.x is found:

```powershell
pwsh -NoProfile -Command "Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck"
```

**Step 2: Create tests directory and smoke test**

```bash
mkdir tests
```

Create `tests/Smoke.Tests.ps1`:

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    # Dot-source the script to load function definitions.
    # InvocationName inside the script will be '.' so the main block is skipped.
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Invoke-CAAnalysis.ps1 scaffold' {
    It 'Loads Import-CAExport as a function' {
        Get-Command Import-CAExport -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Get-BuiltInControls as a function' {
        Get-Command Get-BuiltInControls -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Loads Test-AppIdMatch as a function' {
        Get-Command Test-AppIdMatch -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-BuiltInControls' {
    It 'Returns empty array for null input' {
        Get-BuiltInControls $null | Should -BeNullOrEmpty
    }

    It 'Wraps a single string in an array' {
        $result = Get-BuiltInControls 'mfa'
        $result | Should -Be @('mfa')
    }

    It 'Returns an array unchanged' {
        $result = Get-BuiltInControls @('mfa', 'compliantDevice')
        $result.Count | Should -Be 2
        $result | Should -Contain 'mfa'
        $result | Should -Contain 'compliantDevice'
    }
}

Describe 'Test-AppIdMatch' {
    It 'Matches exact GUID' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications 'aaaaaaaa-0000-0000-0000-000000000001' | Should -Be $true
    }

    It 'Matches GUID with display name suffix' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications 'aaaaaaaa-0000-0000-0000-000000000001 (My App)' | Should -Be $true
    }

    It 'Does not match a different GUID' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications 'bbbbbbbb-0000-0000-0000-000000000002' | Should -Be $false
    }

    It 'Returns false for null applications' {
        Test-AppIdMatch -AppId 'aaaaaaaa-0000-0000-0000-000000000001' -Applications $null | Should -Be $false
    }
}
```

**Step 3: Run smoke tests — verify they pass**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Smoke.Tests.ps1 -Output Detailed"
```

Expected: All tests pass (green). If `BeforeAll` fails with parameter binding error on `InputPath`, check that Pester 5.x is being used (`Import-Module Pester -MinimumVersion 5.0` if needed).

**Step 4: Commit**

```bash
git add tests/Smoke.Tests.ps1
git commit -m "test: add Pester infrastructure and scaffold smoke tests"
```

---

## Task 3: R1 — Test-DirectBlock

**Files:**
- Modify: `Invoke-CAAnalysis.ps1` (add `Test-DirectBlock` function in `#region Rules`)
- Create: `tests/Test-DirectBlock.Tests.ps1`

**Step 1: Write the failing test**

Create `tests/Test-DirectBlock.Tests.ps1`:

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-DirectBlock (R1)' {
    Context 'Enabled block policy — all users, all apps' {
        It 'Returns one Critical finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-01'
                displayName          = 'Block All Users'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId    | Should -Be 'R1'
            $result[0].severity  | Should -Be 'Critical'
            $result[0].policyId  | Should -Be 'r1-test-01'
        }
    }

    Context 'Enabled block policy — all users, specific Copilot app ID' {
        It 'Returns one Critical finding when app ID matches CopilotAppIds' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-02'
                displayName          = 'Block Copilot App'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @($copilotId)
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
            $result[0].ruleId | Should -Be 'R1'
        }
    }

    Context 'Disabled block policy' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-03'
                displayName          = 'Disabled Block'
                state                = 'disabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only block policy' {
        It 'Returns no findings (R4 handles report-only)' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-04'
                displayName          = 'Report-Only Block'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled block policy scoped to user action (includeApplications is null)' {
        It 'Returns no findings — policy applies to user actions, not app access' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-05'
                displayName          = 'Block Security Info Registration'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = $null
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled MFA policy — all users, all apps' {
        It 'Returns no findings — grant is mfa not block' {
            $policy = [PSCustomObject]@{
                id                   = 'r1-test-06'
                displayName          = 'MFA for All'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-DirectBlock -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
```

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-DirectBlock.Tests.ps1 -Output Detailed"
```

Expected: FAIL — `Test-DirectBlock` command not found.

**Step 3: Implement Test-DirectBlock in Invoke-CAAnalysis.ps1**

Add this function inside `#region Rules`:

```powershell
function Test-DirectBlock {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
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
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-DirectBlock.Tests.ps1 -Output Detailed"
```

Expected: All tests pass.

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-DirectBlock.Tests.ps1
git commit -m "feat: implement Test-DirectBlock (R1) with Pester tests"
```

---

## Task 4: R2 — Test-CompliantDeviceGate

**Files:**
- Modify: `Invoke-CAAnalysis.ps1`
- Create: `tests/Test-CompliantDeviceGate.Tests.ps1`

**Step 1: Write the failing test**

Create `tests/Test-CompliantDeviceGate.Tests.ps1`:

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-CompliantDeviceGate (R2)' {
    Context 'Enabled policy — compliantDevice as sole control, all apps' {
        It 'Returns one Critical finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-01'
                displayName          = 'Require Compliant Device'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'compliantDevice'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R2'
            $result[0].severity | Should -Be 'Critical'
        }
    }

    Context 'Enabled policy — compliantDevice AND mfa (AND operator)' {
        It 'Returns one Critical finding — mfa is required in addition to compliant device' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-02'
                displayName          = 'Compliant Device AND MFA'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = @('compliantDevice', 'mfa')
                grantOperator        = 'AND'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
        }
    }

    Context 'Enabled policy — compliantDevice OR mfa (OR operator)' {
        It 'Returns no findings — user can satisfy policy with MFA alone' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-03'
                displayName          = 'Compliant Device OR MFA'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = @('compliantDevice', 'mfa')
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only compliant device policy' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-04'
                displayName          = 'Report-Only Compliant Device'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'compliantDevice'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled compliant device policy scoped to specific app (not All)' {
        It 'Returns no findings — not all apps' {
            $policy = [PSCustomObject]@{
                id                   = 'r2-test-05'
                displayName          = 'Compliant Device for Exchange'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @('00000002-0000-0ff1-ce00-000000000000')
                grantBuiltInControls = 'compliantDevice'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CompliantDeviceGate -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
```

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-CompliantDeviceGate.Tests.ps1 -Output Detailed"
```

Expected: FAIL — `Test-CompliantDeviceGate` not found.

**Step 3: Implement Test-CompliantDeviceGate in Invoke-CAAnalysis.ps1**

Add after `Test-DirectBlock`:

```powershell
function Test-CompliantDeviceGate {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
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
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-CompliantDeviceGate.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-CompliantDeviceGate.Tests.ps1
git commit -m "feat: implement Test-CompliantDeviceGate (R2) with Pester tests"
```

---

## Task 5: R3 — Test-SignInFrequency

**Files:**
- Modify: `Invoke-CAAnalysis.ps1`
- Create: `tests/Test-SignInFrequency.Tests.ps1`

**Step 1: Write the failing test**

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-SignInFrequency (R3)' {
    Context 'Enabled everyTime policy — all apps' {
        It 'Returns one Warning finding' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-01'
                displayName         = 'Reauth Every Session'
                state               = 'enabled'
                includeUsers        = 'All'
                includeApplications = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                    AuthenticationType = 'primaryAndSecondaryAuthentication'
                    Type              = $null
                    Value             = $null
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            $result = @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R3'
            $result[0].severity | Should -Be 'Warning'
        }
    }

    Context 'Report-only everyTime policy' {
        It 'Returns no findings (R4 handles this)' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-02'
                displayName         = 'Report-Only Reauth'
                state               = 'enabledForReportingButNotEnforced'
                includeUsers        = 'All'
                includeApplications = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled policy with no signInFrequency set' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-03'
                displayName         = 'No SIF Policy'
                state               = 'enabled'
                includeUsers        = 'All'
                includeApplications = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $null
                    FrequencyInterval = $null
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled everyTime policy scoped to specific app (not All)' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                  = 'r3-test-04'
                displayName         = 'Reauth for Exchange Only'
                state               = 'enabled'
                includeUsers        = 'All'
                includeApplications = @('00000002-0000-0ff1-ce00-000000000000')
                grantBuiltInControls = 'mfa'
                grantOperator       = 'OR'
                signInFrequency     = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                }
                secureSignInSession = $null
                authenticationStrength = $null
            }
            @(Test-SignInFrequency -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
```

Save to `tests/Test-SignInFrequency.Tests.ps1`.

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-SignInFrequency.Tests.ps1 -Output Detailed"
```

**Step 3: Implement Test-SignInFrequency**

```powershell
function Test-SignInFrequency {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
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
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-SignInFrequency.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-SignInFrequency.Tests.ps1
git commit -m "feat: implement Test-SignInFrequency (R3) with Pester tests"
```

---

## Task 6: R4 — Test-ReportOnlyRisk

**Files:**
- Modify: `Invoke-CAAnalysis.ps1`
- Create: `tests/Test-ReportOnlyRisk.Tests.ps1`

**Background:** R4 checks whether a report-only policy *would* trigger R1, R2, or R3 if it were switched to `enabled`. The implementation uses a JSON round-trip to create an `enabled` copy of the policy, then calls the other three rule functions against it. This means R4 must be placed **after** R1, R2, and R3 in the script.

**Step 1: Write the failing test**

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-ReportOnlyRisk (R4)' {
    Context 'Report-only policy that would trigger R1 if enabled' {
        It 'Returns one Warning finding noting R1' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-01'
                displayName          = 'Report-Only Block All'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{ IsEnabled = $null; FrequencyInterval = $null }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R4'
            $result[0].severity | Should -Be 'Warning'
            $result[0].summary  | Should -Match 'R1'
        }
    }

    Context 'Report-only policy that would trigger R3 if enabled' {
        It 'Returns one Warning finding noting R3' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-02'
                displayName          = 'Report-Only Reauth Every Time'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{
                    IsEnabled         = $true
                    FrequencyInterval = 'everyTime'
                }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId  | Should -Be 'R4'
            $result[0].summary | Should -Match 'R3'
        }
    }

    Context 'Enabled policy (not report-only)' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-03'
                displayName          = 'Enabled Block'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'block'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{ IsEnabled = $null; FrequencyInterval = $null }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only policy that would NOT trigger R1, R2, or R3' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r4-test-04'
                displayName          = 'Report-Only MFA Harmless'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = [PSCustomObject]@{ IsEnabled = $null; FrequencyInterval = $null }
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-ReportOnlyRisk -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
```

Save to `tests/Test-ReportOnlyRisk.Tests.ps1`.

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-ReportOnlyRisk.Tests.ps1 -Output Detailed"
```

**Step 3: Implement Test-ReportOnlyRisk**

```powershell
function Test-ReportOnlyRisk {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
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
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-ReportOnlyRisk.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-ReportOnlyRisk.Tests.ps1
git commit -m "feat: implement Test-ReportOnlyRisk (R4) with Pester tests"
```

---

## Task 7: R5 — Test-TokenProtection

**Files:**
- Modify: `Invoke-CAAnalysis.ps1`
- Create: `tests/Test-TokenProtection.Tests.ps1`

**Background:** `secureSignInSession` is extracted from `SessionControls.AdditionalProperties` by `Get-CAAudit.ps1`. When set, it's a JSON object (e.g., `{ "isEnabled": true }`). The field uses camelCase from Graph but Pester will create PSCustomObjects with PascalCase after `ConvertFrom-Json`. The script normalises both casings.

**Step 1: Write the failing test**

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-TokenProtection (R5)' {
    Context 'Enabled policy with secureSignInSession IsEnabled = true' {
        It 'Returns one Warning finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-01'
                displayName          = 'Token Protection Policy'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = [PSCustomObject]@{ IsEnabled = $true }
                authenticationStrength = $null
            }
            $result = @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R5'
            $result[0].severity | Should -Be 'Warning'
        }
    }

    Context 'Enabled policy with secureSignInSession = null' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-02'
                displayName          = 'No Token Protection'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Enabled policy with secureSignInSession IsEnabled = false' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-03'
                displayName          = 'Token Protection Disabled'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = [PSCustomObject]@{ IsEnabled = $false }
                authenticationStrength = $null
            }
            @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only policy with token protection enabled' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r5-test-04'
                displayName          = 'Report-Only Token Protection'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = [PSCustomObject]@{ IsEnabled = $true }
                authenticationStrength = $null
            }
            @(Test-TokenProtection -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }
}
```

Save to `tests/Test-TokenProtection.Tests.ps1`.

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-TokenProtection.Tests.ps1 -Output Detailed"
```

**Step 3: Implement Test-TokenProtection**

```powershell
function Test-TokenProtection {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
    )

    $findings = @()
    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }

        $sss = $policy.secureSignInSession
        if ($null -eq $sss) { continue }

        # IsEnabled may be named with either casing depending on deserialization path.
        $isEnabled = if ($null -ne $sss.IsEnabled) { [bool]$sss.IsEnabled }
                     elseif ($null -ne $sss.isEnabled) { [bool]$sss.isEnabled }
                     else { $true }   # object present, no explicit IsEnabled = treat as enabled

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
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-TokenProtection.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-TokenProtection.Tests.ps1
git commit -m "feat: implement Test-TokenProtection (R5) with Pester tests"
```

---

## Task 8: R6 — Test-MfaCoverageGap

**Files:**
- Modify: `Invoke-CAAnalysis.ps1`
- Create: `tests/Test-MfaCoverageGap.Tests.ps1`

**Background:** R6 is a policy-set-level check. It fires once if the *entire set* has no single enabled policy covering all users + all apps + MFA (or authenticationStrength). A single qualifying policy is enough to satisfy the rule.

**Step 1: Write the failing test**

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-MfaCoverageGap (R6)' {
    Context 'No policy covers all users + all apps + MFA' {
        It 'Returns one Info finding' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-01'
                displayName          = 'MFA for Admins Only'
                state                = 'enabled'
                includeUsers         = @('admin-group-guid')
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = $null }
            }
            $result = @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R6'
            $result[0].severity | Should -Be 'Info'
        }
    }

    Context 'One enabled policy covers all users + all apps + MFA' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-02'
                displayName          = 'MFA for All'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = $null }
            }
            @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'One enabled policy covers all users + all apps + authenticationStrength' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-03'
                displayName          = 'Phishing-Resistant MFA for All'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = $null
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = 'aaaaaaaa-auth-strength-guid-0000000001' }
            }
            @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @()).Count | Should -Be 0
        }
    }

    Context 'Report-only MFA policy covering all users + all apps' {
        It 'Returns one Info finding — report-only does not count as enforced coverage' {
            $policy = [PSCustomObject]@{
                id                   = 'r6-test-04'
                displayName          = 'Report-Only MFA for All'
                state                = 'enabledForReportingButNotEnforced'
                includeUsers         = 'All'
                includeApplications  = 'All'
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = [PSCustomObject]@{ Id = $null }
            }
            $result = @(Test-MfaCoverageGap -Policies @($policy) -CopilotAppIds @())
            $result.Count | Should -Be 1
            $result[0].ruleId | Should -Be 'R6'
        }
    }
}
```

Save to `tests/Test-MfaCoverageGap.Tests.ps1`.

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-MfaCoverageGap.Tests.ps1 -Output Detailed"
```

**Step 3: Implement Test-MfaCoverageGap**

```powershell
function Test-MfaCoverageGap {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
    )

    foreach ($policy in $Policies) {
        if ($policy.state -ne 'enabled') { continue }
        if ($policy.includeUsers -ne 'All') { continue }
        if ($policy.includeApplications -ne 'All') { continue }

        $controls = Get-BuiltInControls $policy.grantBuiltInControls
        $hasMfa = 'mfa' -in $controls

        $hasAuthStrength = ($null -ne $policy.authenticationStrength -and
                            -not [string]::IsNullOrEmpty($policy.authenticationStrength.Id))

        if ($hasMfa -or $hasAuthStrength) {
            return @()   # Covered — return no findings immediately.
        }
    }

    return @([PSCustomObject]@{
        ruleId         = 'R6'
        severity       = 'Info'
        policyId       = $null
        policyName     = '(no policy)'
        policyState    = $null
        summary        = 'No Conditional Access policy enforces MFA for all users and all applications.'
        detail         = 'Microsoft 365 Copilot requires multi-factor authentication. Without a baseline MFA policy covering all users and all applications, users can access Copilot without completing MFA, violating Microsoft best practices and many compliance frameworks.'
        recommendation = "Create or verify a CA policy with: state = enabled, includeUsers = All, includeApplications = All, grantBuiltInControls includes 'mfa' (or authenticationStrength set to a phishing-resistant method)."
    })
}
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-MfaCoverageGap.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-MfaCoverageGap.Tests.ps1
git commit -m "feat: implement Test-MfaCoverageGap (R6) with Pester tests"
```

---

## Task 9: R7 — Test-CopilotAppScoping

**Files:**
- Modify: `Invoke-CAAnalysis.ps1`
- Create: `tests/Test-CopilotAppScoping.Tests.ps1`

**Step 1: Write the failing test**

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'
}

Describe 'Test-CopilotAppScoping (R7)' {
    Context 'Policy includes a known Copilot app ID in includeApplications' {
        It 'Returns one Info finding' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-01'
                displayName          = 'MFA with Copilot Scoped'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @($copilotId, '00000002-0000-0ff1-ce00-000000000000')
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
            $result[0].ruleId   | Should -Be 'R7'
            $result[0].severity | Should -Be 'Info'
        }
    }

    Context 'Policy excludes a known Copilot app ID in excludeApplications' {
        It 'Returns one Info finding' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-02'
                displayName          = 'MFA Excluding Copilot'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = @($copilotId)
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
            $result[0].ruleId | Should -Be 'R7'
        }
    }

    Context 'Policy with Copilot ID in display-name format (GUID + name)' {
        It 'Returns one Info finding' {
            $copilotId = 'deadbeef-0000-0000-0000-c0pilot00001'
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-03'
                displayName          = 'Resolved Name Policy'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = @("$copilotId (Microsoft Copilot)")
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            $result = @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @($copilotId))
            $result.Count | Should -Be 1
        }
    }

    Context 'Policy with no Copilot app IDs' {
        It 'Returns no findings' {
            $policy = [PSCustomObject]@{
                id                   = 'r7-test-04'
                displayName          = 'MFA All Apps'
                state                = 'enabled'
                includeUsers         = 'All'
                includeApplications  = 'All'
                excludeApplications  = $null
                grantBuiltInControls = 'mfa'
                grantOperator        = 'OR'
                signInFrequency      = $null
                secureSignInSession  = $null
                authenticationStrength = $null
            }
            @(Test-CopilotAppScoping -Policies @($policy) -CopilotAppIds @('deadbeef-0000-0000-0000-c0pilot00001')).Count | Should -Be 0
        }
    }
}
```

Save to `tests/Test-CopilotAppScoping.Tests.ps1`.

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-CopilotAppScoping.Tests.ps1 -Output Detailed"
```

**Step 3: Implement Test-CopilotAppScoping**

```powershell
function Test-CopilotAppScoping {
    param(
        [Parameter(Mandatory)] $Policies,
        [Parameter(Mandatory)] [string[]]$CopilotAppIds
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
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Test-CopilotAppScoping.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Test-CopilotAppScoping.Tests.ps1
git commit -m "feat: implement Test-CopilotAppScoping (R7) with Pester tests"
```

---

## Task 10: Write-AnalysisReport

**Files:**
- Modify: `Invoke-CAAnalysis.ps1` (add `Write-AnalysisReport` in `#region Report`)
- Create: `tests/Write-AnalysisReport.Tests.ps1`

**Step 1: Write the failing test**

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'

    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterReportTest-$(New-Guid)"
    New-Item -Path $script:TempDir -ItemType Directory | Out-Null

    $script:MockExport = [PSCustomObject]@{
        tenantId    = 'test-tenant-id'
        environment = 'Commercial'
        exportedBy  = 'admin@test.onmicrosoft.com'
        policyCount = 2
        policies    = @(
            [PSCustomObject]@{ id = 'p1'; displayName = 'Clean Policy' },
            [PSCustomObject]@{ id = 'p2'; displayName = 'Policy With Finding' }
        )
    }

    $script:MockFindings = @(
        [PSCustomObject]@{
            ruleId         = 'R1'
            severity       = 'Critical'
            policyId       = 'p2'
            policyName     = 'Policy With Finding'
            policyState    = 'enabled'
            summary        = 'Test critical finding'
            detail         = 'Detail text'
            recommendation = 'Fix it'
        }
    )
}

AfterAll {
    Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Write-AnalysisReport' {
    It 'Creates both a .md and a .json file' {
        Write-AnalysisReport -Export $script:MockExport -Findings $script:MockFindings -OutputPath $script:TempDir
        $files = Get-ChildItem -Path $script:TempDir
        ($files | Where-Object Extension -eq '.md').Count  | Should -Be 1
        ($files | Where-Object Extension -eq '.json').Count | Should -Be 1
    }

    It 'Output filenames contain tenant ID, environment, and a timestamp' {
        $files = Get-ChildItem -Path $script:TempDir
        $md = $files | Where-Object Extension -eq '.md'
        $md.Name | Should -Match 'test-tenant-id'
        $md.Name | Should -Match 'Commercial'
        $md.Name | Should -Match '\d{8}T\d{6}Z'
    }

    It 'Markdown report contains the Critical finding summary' {
        $md = Get-ChildItem -Path $script:TempDir -Filter '*.md' | Select-Object -First 1
        $content = Get-Content $md.FullName -Raw
        $content | Should -Match 'R1'
        $content | Should -Match 'Test critical finding'
    }

    It 'Markdown report lists the clean policy in Policies With No Issues' {
        $md = Get-ChildItem -Path $script:TempDir -Filter '*.md' | Select-Object -First 1
        $content = Get-Content $md.FullName -Raw
        $content | Should -Match 'Clean Policy'
    }

    It 'JSON output has the correct envelope structure' {
        $json = Get-ChildItem -Path $script:TempDir -Filter '*.json' | Select-Object -First 1
        $data = Get-Content $json.FullName -Raw | ConvertFrom-Json
        $data.analysedBy   | Should -Be 'Invoke-CAAnalysis.ps1'
        $data.tenantId     | Should -Be 'test-tenant-id'
        $data.findingCount | Should -Be 1
        $data.findings[0].ruleId | Should -Be 'R1'
    }

    It 'Returns an object with MarkdownPath and JsonPath properties' {
        # Clean up previous run files first
        Get-ChildItem -Path $script:TempDir | Remove-Item -Force
        $result = Write-AnalysisReport -Export $script:MockExport -Findings @() -OutputPath $script:TempDir
        $result.MarkdownPath | Should -Not -BeNullOrEmpty
        $result.JsonPath     | Should -Not -BeNullOrEmpty
        Test-Path $result.MarkdownPath | Should -Be $true
        Test-Path $result.JsonPath     | Should -Be $true
    }
}
```

Save to `tests/Write-AnalysisReport.Tests.ps1`.

**Step 2: Run test — verify it fails**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Write-AnalysisReport.Tests.ps1 -Output Detailed"
```

**Step 3: Implement Write-AnalysisReport in Invoke-CAAnalysis.ps1**

Replace the `#region Report` comment with:

```powershell
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
    [void]$sb.AppendLine("# CA Policy Analysis — Copilot Readiness")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("**Tenant:** $($Export.tenantId)  |  **Environment:** $($Export.environment)")
    [void]$sb.AppendLine("**Exported by:** $($Export.exportedBy)  |  **Analysed:** $(Get-Date -Format 'o')")
    [void]$sb.AppendLine("**Policies analysed:** $($Export.policyCount)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Severity | Count |")
    [void]$sb.AppendLine("|---|---|")
    [void]$sb.AppendLine("| 🔴 Critical | $criticalCount |")
    [void]$sb.AppendLine("| 🟡 Warning | $warningCount |")
    [void]$sb.AppendLine("| 🔵 Info | $infoCount |")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Findings")
    [void]$sb.AppendLine("")

    if ($Findings.Count -eq 0) {
        [void]$sb.AppendLine("_No issues found._")
    } else {
        $orderedFindings = @(
            @($Findings | Where-Object severity -eq 'Critical')
            @($Findings | Where-Object severity -eq 'Warning')
            @($Findings | Where-Object severity -eq 'Info')
        )
        foreach ($f in $orderedFindings) {
            $icon = switch ($f.severity) { 'Critical' { '🔴' } 'Warning' { '🟡' } default { '🔵' } }
            [void]$sb.AppendLine("### $icon $($f.ruleId) — $($f.summary)")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("**Policy:** $($f.policyName)  |  **State:** $($f.policyState ?? 'N/A')  |  **Severity:** $($f.severity)")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine($f.detail)
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("**Recommendation:** $($f.recommendation)")
            [void]$sb.AppendLine("")
        }
    }

    [void]$sb.AppendLine("## Policies With No Issues")
    [void]$sb.AppendLine("")
    if ($cleanPolicies.Count -eq 0) {
        [void]$sb.AppendLine("_All policies had at least one finding._")
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
    Write-Host "JSON findings written: $jsonPath" -ForegroundColor Green

    return [PSCustomObject]@{
        MarkdownPath = $mdPath
        JsonPath     = $jsonPath
    }
}

#endregion Report
```

**Step 4: Run test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Write-AnalysisReport.Tests.ps1 -Output Detailed"
```

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Write-AnalysisReport.Tests.ps1
git commit -m "feat: implement Write-AnalysisReport with Pester tests"
```

---

## Task 11: Main Orchestration Block + Integration Test

**Files:**
- Modify: `Invoke-CAAnalysis.ps1` (wire up main block)
- Create: `tests/Integration.Tests.ps1`

**Background:** Replace the placeholder `#region Main` with the full orchestration block. Then run an integration test against the real CA export file to verify expected findings.

**Expected result from test file `CA-Export-f3b7001b-92fa-4ac8-b755-d37ead1ff538-Commercial-20260224T000613Z.json`:**
- R4: 1 Warning — policy "Reauthentication on signin risk" (report-only, would trigger R3)
- No R1, R2, R3, R5, R7 findings
- R6: 0 findings (Policy 1 is enabled, all users, all apps, mfa ✓)
- Total: 1 finding

**Step 1: Update the main block in Invoke-CAAnalysis.ps1**

Replace the existing `#region Main` block with:

```powershell
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

    Write-Host ""
    Write-Host "Analysis complete." -ForegroundColor Cyan
    Write-Host "  Markdown: $($result.MarkdownPath)"
    Write-Host "  JSON:     $($result.JsonPath)"
}
#endregion Main
```

**Step 2: Write the integration test**

Create `tests/Integration.Tests.ps1`:

```powershell
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    . "$PSScriptRoot/../Invoke-CAAnalysis.ps1" -InputPath 'dummy'

    # Resolve path to real CA export test fixture relative to repo root.
    $script:ExportPath = Join-Path $PSScriptRoot '..' 'CA-Export-f3b7001b-92fa-4ac8-b755-d37ead1ff538-Commercial-20260224T000613Z.json'
    $script:Export = Import-CAExport -Path $script:ExportPath

    $script:DefaultCopilotAppIds = @(
        'd3590ed6-52b3-4102-aeff-aad2292ab01c',
        '0be67e7d-4b14-4f1c-8e7a-ab3e5e3dff0c'
    )

    $script:AllFindings = @()
    $script:AllFindings += @(Test-DirectBlock         -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-CompliantDeviceGate -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-SignInFrequency     -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-ReportOnlyRisk      -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-TokenProtection     -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-MfaCoverageGap      -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
    $script:AllFindings += @(Test-CopilotAppScoping   -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds)
}

Describe 'Integration — CA-Export-f3b7001b (4 policies, Commercial)' {
    It 'Loads 4 policies from the export' {
        $script:Export.policies.Count | Should -Be 4
    }

    It 'Produces exactly 1 finding total' {
        $script:AllFindings.Count | Should -Be 1
    }

    It 'The one finding is R4 (report-only risk)' {
        $script:AllFindings[0].ruleId    | Should -Be 'R4'
        $script:AllFindings[0].severity  | Should -Be 'Warning'
    }

    It 'R4 finding references the reauthentication policy' {
        $script:AllFindings[0].policyName | Should -Match 'Reauthentication'
    }

    It 'R4 summary mentions R3' {
        $script:AllFindings[0].summary | Should -Match 'R3'
    }

    It 'R1 produces no findings (no enabled block on apps)' {
        @(Test-DirectBlock -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds).Count | Should -Be 0
    }

    It 'R6 produces no findings (Policy 1 covers all users + all apps + mfa)' {
        @(Test-MfaCoverageGap -Policies $script:Export.policies -CopilotAppIds $script:DefaultCopilotAppIds).Count | Should -Be 0
    }

    Context 'Write-AnalysisReport end-to-end' {
        BeforeAll {
            $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterIntegration-$(New-Guid)"
            New-Item -Path $script:TempDir -ItemType Directory | Out-Null
            $script:ReportResult = Write-AnalysisReport -Export $script:Export -Findings $script:AllFindings -OutputPath $script:TempDir
        }
        AfterAll {
            Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'Writes a Markdown file' {
            Test-Path $script:ReportResult.MarkdownPath | Should -Be $true
        }

        It 'Writes a JSON file' {
            Test-Path $script:ReportResult.JsonPath | Should -Be $true
        }

        It 'JSON findingCount = 1' {
            $data = Get-Content $script:ReportResult.JsonPath -Raw | ConvertFrom-Json
            $data.findingCount | Should -Be 1
        }
    }
}
```

**Step 3: Run integration test — verify it passes**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Integration.Tests.ps1 -Output Detailed"
```

Expected: All tests pass.

**Step 4: Run the full Pester suite to confirm no regressions**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/ -Output Normal"
```

Expected: All tests pass across all test files.

**Step 5: Commit**

```bash
git add Invoke-CAAnalysis.ps1 tests/Integration.Tests.ps1
git commit -m "feat: wire up main orchestration block, add integration tests"
```

---

## Task 12: copilot-agent/manifest.json

**Files:**
- Create: `copilot-agent/manifest.json`

**Step 1: Create the directory and file**

```bash
mkdir copilot-agent
```

Create `copilot-agent/manifest.json` with the following content. The schema v2.1 format is documented at [Copilot Studio declarative agent schema](https://learn.microsoft.com/en-us/microsoft-365-copilot/extensibility/declarative-agent-manifest).

```json
{
  "schema_version": "v2.1",
  "name_for_human": "CA Policy Analyzer",
  "description_for_human": "Analyzes Conditional Access policy exports for misconfigurations that could block Microsoft 365 Copilot.",
  "namespace": "CAPolicyAnalyzer",
  "capabilities": {
    "conversation_starters": [
      { "text": "Analyse my CA policy export for Copilot readiness" },
      { "text": "Which policies could block Microsoft 365 Copilot?" },
      { "text": "Are there report-only policies I should review before enabling?" }
    ]
  }
}
```

**Step 2: Validate JSON is syntactically correct**

```powershell
pwsh -NoProfile -Command "Get-Content copilot-agent/manifest.json -Raw | ConvertFrom-Json | Out-Null; Write-Host 'manifest.json OK'"
```

Expected: `manifest.json OK`

**Step 3: Commit**

```bash
git add copilot-agent/manifest.json
git commit -m "feat: add copilot-agent manifest.json"
```

---

## Task 13: copilot-agent/instruction.txt

**Files:**
- Create: `copilot-agent/instruction.txt`

**Step 1: Create instruction.txt**

This is the system prompt for the declarative agent. It is plain text. Create `copilot-agent/instruction.txt`:

```
# CA Policy Analyzer — Agent Instructions

## Role

You are the CA Policy Analyzer, a Microsoft 365 Copilot agent that helps IT administrators identify Conditional Access (CA) policy misconfigurations that could block or degrade Microsoft 365 Copilot experiences.

You analyze CA policy export files produced by Get-CAAudit.ps1. You are scoped strictly to Copilot-related CA policy analysis. You do not perform other administrative tasks, make configuration changes, or call external APIs.

## Data Intake

When a user starts a conversation, ask them to paste the full JSON content of their CA export file. The file is produced by Get-CAAudit.ps1 and follows this envelope format:

{
  "exportedBy": "...",
  "exportedAt": "...",
  "environment": "...",
  "tenantId": "...",
  "policyCount": N,
  "policies": [ ... ]
}

Validate that the pasted content:
1. Is syntactically valid JSON
2. Contains all required fields: exportedBy, exportedAt, environment, tenantId, policyCount, policies
3. Has a policies array

If the JSON is invalid or a field is missing, tell the user exactly what is wrong and ask them to check the file and try again.

Once you have valid JSON, confirm receipt with a brief message: "Received your CA policy export. Tenant: {tenantId}, Environment: {environment}, {policyCount} policies. Analysing..."

Then immediately apply all 7 rules below and respond with your findings.

## Rule Set

Apply all 7 rules to every policy in the export. A finding is produced when all conditions for a rule are met. When no conditions are met, the policy passes that rule silently.

### R1 — Direct Block | Severity: Critical

Fires when ALL of the following are true for a policy:
- policy.state = "enabled"
- policy.grantBuiltInControls contains "block" (this field may be a string or an array — check both)
- policy.includeApplications is NOT null (if null, the policy applies to user actions only, not app access — skip R1)
- policy.includeApplications = "All" OR any element of policy.includeApplications matches a known Copilot app ID (see Copilot App IDs section)
- policy.includeUsers = "All"

Meaning: This policy will block all in-scope users from accessing Microsoft 365 Copilot.

### R2 — Compliant Device Gate | Severity: Critical

Fires when ALL of the following are true:
- policy.state = "enabled"
- policy.grantBuiltInControls contains "compliantDevice"
- NOT (policy.grantOperator = "OR" AND policy.grantBuiltInControls also contains "mfa") — if both compliantDevice and mfa are present with OR, users can satisfy the policy with MFA alone, so R2 does NOT fire
- policy.includeApplications = "All"

Meaning: Copilot web experiences run in a browser and cannot report device compliance. They will be blocked.

### R3 — Sign-in Frequency: Every Time | Severity: Warning

Fires when ALL of the following are true:
- policy.state = "enabled"
- policy.signInFrequency.IsEnabled = true
- policy.signInFrequency.FrequencyInterval = "everyTime"
- policy.includeApplications = "All"

Meaning: Forcing full re-authentication every session breaks Microsoft 365 Copilot's conversational continuity.

### R4 — Report-Only Risk | Severity: Warning

For each policy where policy.state = "enabledForReportingButNotEnforced":
Simulate the policy as if it were enabled (state = "enabled") and check whether it would trigger R1, R2, or R3.

If any of R1, R2, R3 would fire, produce one R4 finding for this policy, noting which rules (R1, R2, R3) would be triggered.

Meaning: This policy is not yet enforced. Enabling it would impact Copilot.

### R5 — Token Protection | Severity: Warning

Fires when ALL of the following are true:
- policy.state = "enabled"
- policy.secureSignInSession is not null
- policy.secureSignInSession.IsEnabled = true (if IsEnabled is absent but secureSignInSession is non-null, treat as enabled)

Meaning: Microsoft 365 Copilot does not support token binding and may be blocked.

### R6 — MFA Coverage Gap | Severity: Info

This is a policy-set-level check (not per-policy).

Fires if NO single enabled policy satisfies ALL of:
- policy.state = "enabled"
- policy.includeUsers = "All"
- policy.includeApplications = "All"
- policy.grantBuiltInControls contains "mfa" OR policy.authenticationStrength.Id is not null

If any one enabled policy satisfies all four conditions, R6 does NOT fire.

Meaning: No baseline MFA policy covers all users and all apps. Microsoft 365 Copilot requires MFA.

### R7 — Copilot App Scoping | Severity: Info

Fires for each policy where any known Copilot app ID (see Copilot App IDs section) appears in policy.includeApplications OR policy.excludeApplications.

Match on the GUID prefix: the export may contain entries like "d3590ed6-52b3-4102-aeff-aad2292ab01c (Microsoft Office)" — match the GUID portion only.

Meaning: Copilot is explicitly targeted or exempted by this policy. Review to confirm intent.

## Copilot App IDs

Match these GUIDs in includeApplications and excludeApplications. Display names may be appended in the export — match the GUID prefix only.

| App ID | Application |
|---|---|
| d3590ed6-52b3-4102-aeff-aad2292ab01c | Microsoft Office (Word, Excel, PowerPoint, Teams, in-app Copilot) |
| 0be67e7d-4b14-4f1c-8e7a-ab3e5e3dff0c | Microsoft Copilot (copilot.microsoft.com) |

Note: GCC High and DoD environments use different app registrations. If the user's export shows environment = "GCCH" or "DoD", inform them that the default Copilot app ID list applies to Commercial tenants and they should verify the correct app IDs for their environment.

## Output Format

Always respond in this exact structure, regardless of finding count:

1. Severity Summary Table

| Severity | Count |
|---|---|
| 🔴 Critical | N |
| 🟡 Warning | N |
| 🔵 Info | N |

2. Findings (ordered Critical → Warning → Info)

For each finding, one section:

**[icon] [Rule ID] — [Policy Name]**
Rule: [Rule name] | Severity: [severity] | State: [policy state]

[One-sentence summary of what triggered this finding]

**Why this matters for Copilot:** [Explanation of Copilot impact]

**Recommendation:** [Concrete action the admin should take]

If no findings, write: "No issues found. All policies passed all 7 rules."

3. Policies With No Issues

List all policies that produced zero findings across all 7 rules:
- Policy Name (state)

If all policies had at least one finding, write: "All policies had at least one finding."

## Scope

- You analyse only the policy data provided. You cannot call Microsoft Graph or access live tenant data.
- You do not recommend enabling or disabling policies — only identify Copilot-blocking risks.
- You do not auto-remediate. You provide recommendations for human action.
- You analyse JSON exports only. You do not accept CSV format.
- If asked about a policy not in the provided export, explain that you can only analyse what was provided.
```

**Step 2: Verify the file is readable and well-formed**

```powershell
pwsh -NoProfile -Command "(Get-Content copilot-agent/instruction.txt).Count; Write-Host 'instruction.txt readable'"
```

Expected: Line count printed, then `instruction.txt readable`.

**Step 3: Commit**

```bash
git add copilot-agent/instruction.txt
git commit -m "feat: add copilot-agent instruction.txt with 7-rule system prompt"
```

---

## Final: Full Test Suite + Summary Commit

**Step 1: Run the complete Pester test suite**

```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/ -Output Normal"
```

Expected: All tests pass. If any fail, debug and fix before proceeding.

**Step 2: Run the script end-to-end against the real export**

```powershell
pwsh -NoProfile -File Invoke-CAAnalysis.ps1 -InputPath ".\CA-Export-f3b7001b-92fa-4ac8-b755-d37ead1ff538-Commercial-20260224T000613Z.json" -OutputPath "."
```

Expected output:
```
Analysing 4 policies in tenant f3b7001b-92fa-4ac8-b755-d37ead1ff538 (Commercial)...
Found 1 issue(s): 1 Warning.
Markdown report written: .\CA-Analysis-f3b7001b-...-Commercial-...Z.md
JSON findings written: .\CA-Analysis-f3b7001b-...-Commercial-...Z.json

Analysis complete.
  Markdown: .\CA-Analysis-...
  JSON:     .\CA-Analysis-...
```

**Step 3: Verify the Markdown report content**

```powershell
pwsh -NoProfile -Command "Get-Content (Get-ChildItem CA-Analysis-*.md | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName"
```

Confirm:
- Summary table shows 0 Critical, 1 Warning, 0 Info
- R4 finding appears for "Reauthentication on signin risk..."
- "Policies With No Issues" lists the other 3 policies

**Step 4: Clean up generated output files (optional — do not commit them)**

```bash
git status
# If CA-Analysis-*.md or CA-Analysis-*.json appear as untracked, add them to .gitignore:
echo "CA-Analysis-*.md" >> .gitignore
echo "CA-Analysis-*.json" >> .gitignore
git add .gitignore
git commit -m "chore: ignore CA-Analysis output files"
```

---

## Repository Layout After Implementation

```
AuditToolkit/
├── Get-CAAudit.ps1                     # collection script (existing)
├── Invoke-CAAnalysis.ps1               # NEW: offline analysis script
├── RUNBOOK.md                          # existing customer docs
├── CA-Audit-Script-Spec.md             # existing spec
├── copilot-agent/                      # NEW
│   ├── manifest.json
│   └── instruction.txt
├── tests/                              # NEW
│   ├── Smoke.Tests.ps1
│   ├── Test-DirectBlock.Tests.ps1
│   ├── Test-CompliantDeviceGate.Tests.ps1
│   ├── Test-SignInFrequency.Tests.ps1
│   ├── Test-ReportOnlyRisk.Tests.ps1
│   ├── Test-TokenProtection.Tests.ps1
│   ├── Test-MfaCoverageGap.Tests.ps1
│   ├── Test-CopilotAppScoping.Tests.ps1
│   ├── Write-AnalysisReport.Tests.ps1
│   └── Integration.Tests.ps1
└── docs/plans/
    ├── 2026-02-23-ca-audit-script.md
    ├── 2026-02-24-copilot-analyzer-design.md
    └── 2026-02-24-copilot-analyzer-impl.md  ← this file
```

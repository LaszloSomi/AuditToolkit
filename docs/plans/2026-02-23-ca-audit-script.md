# CA Audit Script Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a PowerShell script that exports all Conditional Access policies from a Microsoft 365 tenant (Commercial, GCC, GCCH, DoD) to JSON or CSV, with full data fidelity for downstream Copilot misconfiguration analysis.

**Architecture:** A single self-contained PowerShell script (`Get-CAAudit.ps1`) that authenticates to Microsoft Graph using delegated auth (interactive or device code), pages through all CA policies, enriches object IDs with display names, and writes a metadata-enveloped JSON or flattened CSV export. No modules beyond `Microsoft.Graph.Identity.SignIns` and `Microsoft.Graph.DirectoryObjects` are required.

**Tech Stack:** PowerShell 7+, Microsoft.Graph PowerShell SDK (`Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Authentication`)

---

## Reference

- Spec: `CA-Audit-Script-Spec.md` in repo root
- Graph endpoint: `GET /identity/conditionalAccess/policies`
- SDK cmdlet: `Get-MgIdentityConditionalAccessPolicy`
- Auth cmdlet: `Connect-MgGraph`

---

### Task 1: Script skeleton and parameter block

**Files:**
- Create: `Get-CAAudit.ps1`

**Step 1: Create the file with parameter block and help header**

```powershell
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
#>
[CmdletBinding()]
param (
    [ValidateSet('Commercial', 'GCC', 'GCCH', 'DoD')]
    [string]$Environment = 'Commercial',

    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [ValidateSet('Interactive', 'DeviceCode')]
    [string]$AuthFlow = 'Interactive',

    [ValidateSet('JSON', 'CSV')]
    [string]$OutputFormat = 'JSON',

    [string]$OutputPath = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
```

**Step 2: Verify the file parses without error**

```powershell
pwsh -NoProfile -Command "& { . ./Get-CAAudit.ps1 -UserPrincipalName test@test.com -WhatIf }" 2>&1
```

Expected: Parameter binding error or no output — NOT a parse/syntax error.

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add script skeleton and parameter block"
```

---

### Task 2: Environment-to-endpoint resolution

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add the endpoint map and a Resolve-Environment function**

Add after the param block:

```powershell
#region Environment configuration
$EnvironmentMap = @{
    Commercial = @{
        GraphEnvironment  = 'Global'          # Connect-MgGraph -Environment value
        GraphEndpoint     = 'https://graph.microsoft.com'
        AuthAuthority     = 'https://login.microsoftonline.com'
        TokenAudience     = 'https://graph.microsoft.com'
    }
    GCC        = @{
        GraphEnvironment  = 'Global'
        GraphEndpoint     = 'https://graph.microsoft.com'
        AuthAuthority     = 'https://login.microsoftonline.com'
        TokenAudience     = 'https://graph.microsoft.com'
    }
    GCCH       = @{
        GraphEnvironment  = 'USGov'
        GraphEndpoint     = 'https://graph.microsoft.us'
        AuthAuthority     = 'https://login.microsoftonline.us'
        TokenAudience     = 'https://graph.microsoft.us'
    }
    DoD        = @{
        GraphEnvironment  = 'USGovDoD'
        GraphEndpoint     = 'https://dod-graph.microsoft.us'
        AuthAuthority     = 'https://login.microsoftonline.us'
        TokenAudience     = 'https://dod-graph.microsoft.us'
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
```

**Step 2: Test resolution manually**

```powershell
pwsh -NoProfile -Command @"
. ./Get-CAAudit.ps1 -UserPrincipalName x@x.com 2>$null
(Resolve-Environment 'GCCH').GraphEndpoint
"@
```

Expected output: `https://graph.microsoft.us`

**Step 3: Verify GCC resolves to worldwide endpoints**

```powershell
pwsh -NoProfile -Command @"
. ./Get-CAAudit.ps1 -UserPrincipalName x@x.com 2>$null
(Resolve-Environment 'GCC').GraphEndpoint
"@
```

Expected output: `https://graph.microsoft.com`

**Step 4: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add environment-to-endpoint resolution map"
```

---

### Task 3: Module prerequisite check

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add module check function**

Add after the environment map region:

```powershell
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
```

**Step 2: Call it early in the main script body**

Add at the end of the file (beginning of main execution):

```powershell
#region Main
Assert-GraphModule
#endregion
```

**Step 3: Verify it throws a useful error when module is absent**

This can be validated at review time — the check pattern is standard and well-understood.

**Step 4: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add module prerequisite check"
```

---

### Task 4: Authentication

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add Connect-ToGraph function**

Add after the prerequisites region:

```powershell
#region Authentication
function Connect-ToGraph {
    param(
        [string]$Env,
        [string]$Upn,
        [string]$Flow
    )

    $config = Resolve-Environment $Env

    $connectParams = @{
        Environment = $config.GraphEnvironment
        Scopes      = @('Policy.Read.All', 'Directory.Read.All')
        NoWelcome   = $true
    }

    if ($Flow -eq 'DeviceCode') {
        $connectParams['UseDeviceAuthentication'] = $true
    }

    Write-Host "Connecting to Microsoft Graph ($Env)..." -ForegroundColor Cyan
    Connect-MgGraph @connectParams

    # Confirm the signed-in account matches the expected UPN
    $context = Get-MgContext
    if ($context.Account -ne $Upn) {
        Write-Warning "Signed in as '$($context.Account)' but expected '$Upn'. Proceeding."
    }

    Write-Host "Connected as: $($context.Account)" -ForegroundColor Green
    return $context
}
#endregion
```

**Step 2: Call it in the main region**

Replace the main region with:

```powershell
#region Main
Assert-GraphModule
$context = Connect-ToGraph -Env $Environment -Upn $UserPrincipalName -Flow $AuthFlow
#endregion
```

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add delegated Graph authentication with environment support"
```

---

### Task 5: Policy retrieval with pagination

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add Get-AllCAPolicies function**

Add after the authentication region:

```powershell
#region Data collection
function Get-AllCAPolicies {
    Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan

    # -All handles @odata.nextLink pagination automatically in the SDK
    $policies = Get-MgIdentityConditionalAccessPolicy -All -ExpandProperty * `
        -Property id, displayName, state, createdDateTime, modifiedDateTime, templateId, `
                  conditions, grantControls, sessionControls

    Write-Host "Retrieved $($policies.Count) policies." -ForegroundColor Green
    return $policies
}
#endregion
```

> **Note:** The `-All` switch on `Get-MgIdentityConditionalAccessPolicy` automatically follows `@odata.nextLink` tokens. No manual pagination loop is needed when using the SDK.

**Step 2: Call it in the main region**

```powershell
#region Main
Assert-GraphModule
$context = Connect-ToGraph -Env $Environment -Upn $UserPrincipalName -Flow $AuthFlow
$policies = Get-AllCAPolicies
#endregion
```

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add paginated CA policy retrieval"
```

---

### Task 6: Object ID to display name resolution

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add Resolve-DirectoryObjects function**

Add inside the data collection region, after `Get-AllCAPolicies`:

```powershell
function Resolve-DirectoryObjects {
    param([string[]]$Ids)

    # Filter out well-known placeholder values that are not real object IDs
    $wellKnown = @('All', 'None', 'GuestsOrExternalUsers')
    $realIds = $Ids | Where-Object { $_ -notin $wellKnown -and $_ -match '^[0-9a-f-]{36}$' }

    if (-not $realIds) { return @{} }

    $map = @{}
    # Graph supports batches of up to 20 IDs per $filter request
    $batches = [System.Linq.Enumerable]::Chunk($realIds, 20)
    foreach ($batch in $batches) {
        $filter = ($batch | ForEach-Object { "id eq '$_'" }) -join ' or '
        try {
            $objects = Get-MgDirectoryObject -Filter $filter -Property id, displayName `
                -ErrorAction SilentlyContinue
            foreach ($obj in $objects) {
                $map[$obj.Id] = $obj.AdditionalProperties['displayName'] ?? $obj.Id
            }
        } catch {
            Write-Verbose "Could not resolve batch of IDs: $_"
        }
    }
    return $map
}

function Resolve-PolicyIds {
    param($Policies)

    Write-Host "Resolving directory object display names..." -ForegroundColor Cyan

    # Collect all unique object IDs referenced across all policies
    $allIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $Policies) {
        $u = $policy.Conditions.Users
        if ($u) {
            @($u.IncludeUsers + $u.ExcludeUsers + $u.IncludeGroups + $u.ExcludeGroups +
              $u.IncludeRoles + $u.ExcludeRoles) | Where-Object { $_ } | ForEach-Object { [void]$allIds.Add($_) }
        }
        $a = $policy.Conditions.Applications
        if ($a) {
            @($a.IncludeApplications + $a.ExcludeApplications) | Where-Object { $_ } | ForEach-Object { [void]$allIds.Add($_) }
        }
    }

    return Resolve-DirectoryObjects -Ids ([string[]]$allIds)
}
```

**Step 2: Call resolution in main region**

```powershell
#region Main
Assert-GraphModule
$context = Connect-ToGraph -Env $Environment -Upn $UserPrincipalName -Flow $AuthFlow
$policies  = Get-AllCAPolicies
$idMap     = Resolve-PolicyIds -Policies $policies
#endregion
```

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add batched directory object ID-to-displayName resolution"
```

---

### Task 7: Policy serialization to export object

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add ConvertTo-ExportObject function**

Add after the data collection region:

```powershell
#region Serialization
function Resolve-Id {
    param([string]$Id, [hashtable]$Map)
    if (-not $Id) { return $Id }
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
        id                  = $p.Id
        displayName         = $p.DisplayName
        state               = $p.State
        createdDateTime     = $p.CreatedDateTime
        modifiedDateTime    = $p.ModifiedDateTime
        templateId          = $p.TemplateId

        # Assignments — users
        includeUsers        = ($c.Users.IncludeUsers        | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeUsers        = ($c.Users.ExcludeUsers        | ForEach-Object { Resolve-Id $_ $IdMap })
        includeGroups       = ($c.Users.IncludeGroups       | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeGroups       = ($c.Users.ExcludeGroups       | ForEach-Object { Resolve-Id $_ $IdMap })
        includeRoles        = ($c.Users.IncludeRoles        | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeRoles        = ($c.Users.ExcludeRoles        | ForEach-Object { Resolve-Id $_ $IdMap })
        includeGuestsOrExternalUsers = $c.Users.IncludeGuestsOrExternalUsers
        excludeGuestsOrExternalUsers = $c.Users.ExcludeGuestsOrExternalUsers
        clientApplications  = $c.ClientApplications

        # Conditions
        includeApplications = ($c.Applications.IncludeApplications | ForEach-Object { Resolve-Id $_ $IdMap })
        excludeApplications = ($c.Applications.ExcludeApplications | ForEach-Object { Resolve-Id $_ $IdMap })
        includeUserActions  = $c.Applications.IncludeUserActions
        authenticationContextClassReferences = $c.Applications.IncludeAuthenticationContextClassReferences
        clientAppTypes      = $c.ClientAppTypes
        platforms           = $c.Platforms
        deviceFilter        = $c.Devices.DeviceFilter
        locations           = $c.Locations
        signInRiskLevels    = $c.SignInRiskLevels
        userRiskLevels      = $c.UserRiskLevels
        servicePrincipalRiskLevels = $c.ServicePrincipalRiskLevels
        insiderRiskLevels   = $c.InsiderRiskLevels
        authenticationFlows = $c.AuthenticationFlows

        # Grant controls
        grantOperator           = $g.Operator
        grantBuiltInControls    = $g.BuiltInControls
        authenticationStrength  = $g.AuthenticationStrength
        termsOfUse              = $g.TermsOfUse
        customAuthenticationFactors = $g.CustomAuthenticationFactors

        # Session controls
        signInFrequency                  = $s.SignInFrequency
        persistentBrowser                = $s.PersistentBrowser
        applicationEnforcedRestrictions  = $s.ApplicationEnforcedRestrictions
        cloudAppSecurity                 = $s.CloudAppSecurity
        disableResilienceDefaults        = $s.DisableResilienceDefaults
        continuousAccessEvaluation       = $s.AdditionalProperties['continuousAccessEvaluation']
        secureSignInSession              = $s.AdditionalProperties['secureSignInSession']
    }
}
#endregion
```

**Step 2: Build export objects in main region**

```powershell
#region Main
Assert-GraphModule
$context        = Connect-ToGraph -Env $Environment -Upn $UserPrincipalName -Flow $AuthFlow
$policies       = Get-AllCAPolicies
$idMap          = Resolve-PolicyIds -Policies $policies
$exportPolicies = $policies | ForEach-Object { ConvertTo-ExportObject -Policy $_ -IdMap $idMap }
#endregion
```

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add policy-to-export-object serialization with ID enrichment"
```

---

### Task 8: Output file writing (JSON and CSV)

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add output filename builder and write functions**

Add after the serialization region:

```powershell
#region Output
function Get-OutputFileName {
    param([string]$TenantId, [string]$Env, [string]$Format)
    $timestamp = (Get-Date -Format 'yyyyMMddTHHmmssZ')
    $ext = $Format.ToLower()
    return "CA-Export-$TenantId-$Env-$timestamp.$ext"
}

function Write-JsonExport {
    param($ExportPolicies, $Context, [string]$Env, [string]$FilePath)

    $envelope = [ordered]@{
        exportedBy   = $Context.Account
        exportedAt   = (Get-Date -Format 'o')
        environment  = $Env
        tenantId     = $Context.TenantId
        policyCount  = $ExportPolicies.Count
        policies     = $ExportPolicies
    }

    $envelope | ConvertTo-Json -Depth 20 | Set-Content -Path $FilePath -Encoding UTF8
    Write-Host "JSON export written: $FilePath" -ForegroundColor Green
}

function Write-CsvExport {
    param($ExportPolicies, [string]$FilePath)

    # Nested objects/arrays are serialized as compact JSON strings for CSV compatibility
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
```

**Step 2: Call output functions in main region**

```powershell
#region Main
Assert-GraphModule
$context        = Connect-ToGraph -Env $Environment -Upn $UserPrincipalName -Flow $AuthFlow
$policies       = Get-AllCAPolicies
$idMap          = Resolve-PolicyIds -Policies $policies
$exportPolicies = $policies | ForEach-Object { ConvertTo-ExportObject -Policy $_ -IdMap $idMap }

$fileName   = Get-OutputFileName -TenantId $context.TenantId -Env $Environment -Format $OutputFormat
$filePath   = Join-Path $OutputPath $fileName

if ($OutputFormat -eq 'JSON') {
    Write-JsonExport -ExportPolicies $exportPolicies -Context $context -Env $Environment -FilePath $filePath
} else {
    Write-CsvExport -ExportPolicies $exportPolicies -FilePath $filePath
}

Write-Host "`nAudit complete. $($policies.Count) policies exported to: $filePath" -ForegroundColor Cyan
#endregion
```

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: add JSON and CSV output with metadata envelope and spec-compliant naming"
```

---

### Task 9: Disconnect and cleanup

**Files:**
- Modify: `Get-CAAudit.ps1`

**Step 1: Add disconnect at end of main region**

```powershell
Disconnect-MgGraph | Out-Null
Write-Verbose "Disconnected from Microsoft Graph."
```

**Step 2: Wrap main region in try/finally to ensure disconnect on error**

Replace the `#region Main` block with:

```powershell
#region Main
Assert-GraphModule
$context = Connect-ToGraph -Env $Environment -Upn $UserPrincipalName -Flow $AuthFlow

try {
    $policies       = Get-AllCAPolicies
    $idMap          = Resolve-PolicyIds -Policies $policies
    $exportPolicies = $policies | ForEach-Object { ConvertTo-ExportObject -Policy $_ -IdMap $idMap }

    $fileName = Get-OutputFileName -TenantId $context.TenantId -Env $Environment -Format $OutputFormat
    $filePath = Join-Path $OutputPath $fileName

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
```

**Step 3: Commit**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: wrap execution in try/finally to guarantee Graph disconnect on error"
```

---

### Task 10: Smoke test (manual validation checklist)

No automated tests exist for this script because all behavior requires live Graph API calls. Validate manually:

**Checklist:**

- [ ] Run with `-Environment Commercial -AuthFlow Interactive` → browser opens, auth succeeds
- [ ] Run with `-AuthFlow DeviceCode` → device code printed, auth succeeds after browser sign-in
- [ ] Run with `-Environment GCCH` (if GCCH tenant available) → `graph.microsoft.us` is targeted
- [ ] Verify output JSON file matches naming convention: `CA-Export-{tenantId}-Commercial-{timestamp}.json`
- [ ] Verify JSON envelope contains `exportedBy`, `exportedAt`, `tenantId`, `policyCount`, `policies`
- [ ] Verify policies array is not empty (if tenant has CA policies)
- [ ] Verify group/user IDs in assignments include display names in `id (display name)` format
- [ ] Run with `-OutputFormat CSV` → CSV file created, nested objects serialized as JSON strings
- [ ] Confirm `Disconnect-MgGraph` is called even when script throws an error (kill connection manually to test)
- [ ] Run `-Verbose` flag → endpoint selection and ID resolution messages visible

**Step 1: Commit final**

```bash
git add Get-CAAudit.ps1
git commit -m "feat: complete CA audit script per spec"
```

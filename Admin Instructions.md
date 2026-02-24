# How to Analyse a Conditional Access Policy Export

This guide walks you through running `Invoke-CAAnalysis.ps1` — a script that reads a CA policy export file and checks it for misconfigurations that could block or degrade Microsoft 365 Copilot.

> **What the script does in plain English:** It reads the JSON file the customer sent you, checks every policy against seven rules, and produces a Markdown report and a JSON findings file on your machine. It makes no network calls and does not touch the customer's tenant.

---

## Before You Start

### 1. You need PowerShell 7.2 or later

**Check your version:**
```powershell
$PSVersionTable.PSVersion
```

If `Major` is 7 and `Minor` is 2 or higher, you are good. If not, download and install PowerShell 7 from:
https://aka.ms/powershell-release?tag=stable

No additional PowerShell modules are required. Unlike `Get-CAAudit.ps1`, the analysis script is fully offline and does not connect to Microsoft Graph.

### 2. You need the export file from the customer

Ask the customer to run `Get-CAAudit.ps1` using the instructions in **Customer Instructions.md** and send you the resulting file. The file will be named:

```
CA-Export-{TenantId}-{Environment}-{Timestamp}.json
```

**Do not modify the file.** If the JSON is altered the script will reject it.

---

## Running the Analysis

### Step 1 — Open PowerShell 7

Open **PowerShell 7** (not Windows PowerShell). Search for "pwsh" or "PowerShell 7" in the Start menu.

### Step 2 — Navigate to the folder containing both scripts and the export file

```powershell
cd "C:\Path\To\AuditToolkit"
```

### Step 3 — Run the analysis

```powershell
.\Invoke-CAAnalysis.ps1 -InputPath ".\CA-Export-{filename}.json"
```

Replace `{filename}` with the actual file name the customer sent you.

**Example:**
```powershell
.\Invoke-CAAnalysis.ps1 -InputPath ".\CA-Export-f3b7001b-Commercial-20260224T000613Z.json"
```

The script prints progress as it works:

```
Analysing 47 policies in tenant 00000000-0000-0000-0000-000000000000 (Commercial)...
Found 3 issue(s): 1 Critical, 2 Warning.
Markdown report written: .\CA-Analysis-00000000-Commercial-20260224T143000Z.md
JSON findings written:   .\CA-Analysis-00000000-Commercial-20260224T143000Z.json

Analysis complete.
  Markdown: .\CA-Analysis-00000000-Commercial-20260224T143000Z.md
  JSON:     .\CA-Analysis-00000000-Commercial-20260224T143000Z.json
```

---

## The Output Files

The script always produces two files in the same folder as the export (or wherever you specify with `-OutputPath`).

**File name format:**
```
CA-Analysis-{TenantId}-{Environment}-{Timestamp}.md
CA-Analysis-{TenantId}-{Environment}-{Timestamp}.json
```

### Markdown report (`.md`)

Open this in any Markdown viewer (Visual Studio Code, GitHub, Obsidian) for a formatted, human-readable report. It contains:

- A severity summary table
- One section per finding with the policy name, what triggered it, the Copilot impact, and a recommendation
- A list of policies that passed all checks

### JSON findings file (`.json`)

Machine-readable output for import into ticketing systems, dashboards, or further automation. Structure:

```json
{
  "analysedBy":   "Invoke-CAAnalysis.ps1",
  "analysedAt":   "2026-02-24T14:30:00.0000000Z",
  "tenantId":     "00000000-0000-0000-0000-000000000000",
  "environment":  "Commercial",
  "policyCount":  47,
  "findingCount": 3,
  "findings": [
    {
      "ruleId":         "R1",
      "severity":       "Critical",
      "policyId":       "9d2c8123-...",
      "policyName":     "Block legacy authentication",
      "policyState":    "enabled",
      "summary":        "...",
      "detail":         "...",
      "recommendation": "..."
    }
  ]
}
```

---

## Understanding the Findings

The script checks every policy against seven rules. Here is what each rule means and why it matters for Copilot.

| Rule | Severity | What it detects |
|---|---|---|
| R1 | 🔴 Critical | A policy that outright blocks access to Copilot for all users |
| R2 | 🔴 Critical | A compliant device requirement that Copilot web experiences cannot satisfy |
| R3 | 🟡 Warning | Sign-in frequency set to "every time", which breaks Copilot session continuity |
| R4 | 🟡 Warning | A report-only policy that would cause R1, R2, or R3 if switched to enforced |
| R5 | 🟡 Warning | Token protection (secure sign-in session binding), which Copilot does not support |
| R6 | 🔵 Info | No MFA baseline policy covering all users and all applications |
| R7 | 🔵 Info | A Copilot application ID explicitly named in a policy's include or exclude list |

### Severity guide

| Severity | Meaning |
|---|---|
| 🔴 Critical | Copilot access will fail for the affected users. Address before enabling Copilot. |
| 🟡 Warning | Copilot may fail or behave unexpectedly. Review and assess before enabling Copilot. |
| 🔵 Info | Informational only. No immediate action required, but worth reviewing. |

### Common finding — R4 (Report-Only Risk)

R4 is the most frequently seen finding. It means a policy is currently in **report-only mode** (not enforcing) but would block or degrade Copilot if someone switches it to enforced. The recommendation is always to review the flagged rules and apply their fixes *before* enabling the policy.

---

## All Parameters at a Glance

| Parameter | Required | Default | What it does |
|---|---|---|---|
| `-InputPath` | **Yes** | — | Path to the CA export JSON from `Get-CAAudit.ps1` |
| `-CopilotAppIds` | No | Built-in list | Copilot app GUIDs to check for explicit policy scoping. Override for GCC High / DoD tenants. |
| `-OutputPath` | No | Current folder | Where to write the two output files (must be an existing folder) |

**Example with all parameters:**
```powershell
.\Invoke-CAAnalysis.ps1 `
    -InputPath  ".\CA-Export-contoso-Commercial-20260224T143000Z.json" `
    -OutputPath "C:\Reports"
```

---

## Saving the output to a specific folder

```powershell
.\Invoke-CAAnalysis.ps1 -InputPath ".\CA-Export-contoso-Commercial-20260224T143000Z.json" -OutputPath "C:\Reports"
```

The folder must already exist. The script will not create it.

---

## GCC High and DoD tenants

The built-in Copilot app ID list covers **Commercial** tenants. GCC High and DoD use different app registrations for some Microsoft 365 services. If you are analysing an export where `environment` is `GCCH` or `DoD`, pass the correct app IDs with `-CopilotAppIds`:

```powershell
.\Invoke-CAAnalysis.ps1 `
    -InputPath      ".\CA-Export-contoso-GCCH-20260224T143000Z.json" `
    -CopilotAppIds  @('app-guid-1', 'app-guid-2')
```

Consult current Microsoft documentation to obtain the correct app GUIDs for the target environment before running the analysis.

---

## Troubleshooting

### "Running scripts is disabled on this system"

PowerShell's execution policy is blocking the script. Run this once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then try again.

---

### "Input file not found"

The path you passed to `-InputPath` does not exist or contains a typo. Check the path with:

```powershell
Test-Path ".\CA-Export-{filename}.json"
```

This should return `True`. If it returns `False`, verify the filename and your current directory.

---

### "Failed to parse CA export JSON"

The file is not valid JSON. This usually means the file was modified or truncated after export. Ask the customer to re-run `Get-CAAudit.ps1` and send a fresh export.

---

### "CA export JSON is missing required field"

The file does not have the expected envelope structure. This is not a valid export from `Get-CAAudit.ps1`. Confirm you have the correct file.

---

### "OutputPath '...' does not exist or is not a directory"

The folder specified with `-OutputPath` does not exist. Create it first:

```powershell
New-Item -Path "C:\Reports" -ItemType Directory
```

---

### The report shows no findings

This can mean the tenant is well-configured for Copilot, or it can mean the export only contains a small number of policies. Confirm the `policyCount` in the report header matches what you expect for the tenant. If the number seems low, ask the customer to re-run the collection script.

---

## Frequently Asked Questions

**Does this script connect to Microsoft or the customer's tenant?**
No. It is entirely offline. It reads only the file you provide and writes output files locally. No network calls are made.

**Can I run this on a file from a GCC High or DoD tenant?**
Yes, but pass the correct Copilot app IDs for that environment using `-CopilotAppIds`. The built-in default list covers Commercial only.

**Can I run this more than once on the same file?**
Yes. Each run produces a new timestamped output file. Previous reports are not overwritten.

**The policy names show GUIDs instead of display names. Is the analysis still valid?**
Yes. The analysis is based on policy logic (grant controls, included users, included applications), not on display names. GUIDs appear when the customer's tenant blocked `Directory.Read.All` consent during collection. The findings are not affected.

**How do I share the results with the customer?**
Send the Markdown file (`.md`) for a readable report, or the JSON file (`.json`) if the customer needs to import findings into a tool. Both files contain no credentials — only policy configuration data that the customer already has access to.

**What PowerShell version do I need?**
PowerShell 7.2 or later. The Windows built-in PowerShell 5.1 is not supported.

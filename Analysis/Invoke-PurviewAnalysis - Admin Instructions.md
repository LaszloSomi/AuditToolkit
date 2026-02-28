# How to Analyse a Purview Data Security Export

This guide walks you through running `Invoke-PurviewAnalysis.ps1` — a script that reads a Purview export file and checks it for gaps in DSPM for AI policy deployment, DLP enforcement, audit log retention, and Insider Risk Management configuration.

> **What the script does in plain English:** It reads the JSON file the customer sent you, checks the DSPM for AI policy inventory, audit settings, DLP workload coverage, and IRM configuration against six rules, and produces a Markdown report and a JSON findings file on your machine. It makes no network calls and does not touch the customer's tenant.

## Requirements at a glance

| Requirement | Detail |
|---|---|
| **Authentication** | None — fully offline |
| **Roles required** | None |
| **PowerShell modules** | None |
| **PowerShell version** | 7.2 or later |
| **Network access** | None |

---

## Before You Start

### 1. You need PowerShell 7.2 or later

**Check your version:**
```powershell
$PSVersionTable.PSVersion
```

If `Major` is 7 and `Minor` is 2 or higher, you are good. If not, download and install PowerShell 7 from:
https://aka.ms/powershell-release?tag=stable

No additional PowerShell modules are required. The analysis script is fully offline and does not connect to any Microsoft service.

### 2. You need the export file from the customer

Ask the customer to run `Get-PurviewAudit.ps1` using the instructions in **Get-PurviewAudit - Customer Instructions.md** and send you the resulting file. The file will be named:

```
Purview-Export-{TenantId}-{Environment}-{Timestamp}.json
```

**Do not modify the file.** If the JSON is altered the script will reject it.

---

## Running the Analysis

### Step 1 — Open PowerShell 7

Open **PowerShell 7** (not Windows PowerShell). Search for "pwsh" or "PowerShell 7" in the Start menu.

### Step 2 — Navigate to the folder containing the script and the export file

```powershell
cd "C:\Path\To\AuditToolkit\Analysis"
```

### Step 3 — Run the analysis

```powershell
.\Invoke-PurviewAnalysis.ps1 -InputPath ".\Purview-Export-{filename}.json"
```

Replace `{filename}` with the actual file name the customer sent you.

**Example:**
```powershell
.\Invoke-PurviewAnalysis.ps1 -InputPath ".\Purview-Export-f3b7001b-Commercial-20260228T143000Z.json"
```

The script prints progress as it works:

```
Analysing Purview export for tenant 00000000-0000-0000-0000-000000000000 (Commercial)...
Found 4 issue(s): 3 Warning, 1 Info.
Markdown report written: .\Purview-Analysis-00000000-Commercial-20260228T143000Z.md
JSON findings written:   .\Purview-Analysis-00000000-Commercial-20260228T143000Z.json

Analysis complete.
  Markdown: .\Purview-Analysis-00000000-Commercial-20260228T143000Z.md
  JSON:     .\Purview-Analysis-00000000-Commercial-20260228T143000Z.json
```

---

## The Output Files

The script produces two files in the current directory (or wherever you specify with `-OutputPath`).

**File name format:**
```
Purview-Analysis-{TenantId}-{Environment}-{Timestamp}.md
Purview-Analysis-{TenantId}-{Environment}-{Timestamp}.json
```

### Markdown report (`.md`)

Open this in any Markdown viewer (Visual Studio Code, GitHub, Obsidian) for a formatted, human-readable report. It contains:

- A severity summary table
- One section per finding with the policy name, what triggered it, the impact, and a recommendation
- A full DSPM for AI policy inventory table showing which policies are deployed and their enforcement mode
- A collection limitations table listing settings that require manual portal verification

### JSON findings file (`.json`)

Machine-readable output for import into ticketing systems, dashboards, or further automation. Structure:

```json
{
  "analysedBy":   "Invoke-PurviewAnalysis.ps1",
  "analysedAt":   "2026-02-28T14:30:00.0000000Z",
  "tenantId":     "00000000-0000-0000-0000-000000000000",
  "environment":  "Commercial",
  "findingCount": 4,
  "findings": [
    {
      "ruleId":         "P1",
      "severity":       "Warning",
      "policyName":     "DSPM for AI - Protect sensitive data from Copilot processing",
      "policyType":     "DLP",
      "summary":        "...",
      "detail":         "...",
      "recommendation": "..."
    }
  ]
}
```

---

## Understanding the Findings

The script checks the export against six rules across four categories.

### DSPM for AI Policy Rules

These rules check whether the DSPM for AI out-of-the-box policies have been deployed and are actually enforcing.

| Rule | Severity | What it detects |
|---|---|---|
| P1 | 🟡 Warning | A DSPM for AI policy that has not been deployed in this tenant at all |
| P2 | 🟡 Warning | A DSPM for AI DLP policy that is deployed but in test mode — it logs but does not enforce |
| P3 | 🟡 Warning | A DSPM for AI DLP policy that is deployed but explicitly disabled |

### Audit Retention Rules

| Rule | Severity | What it detects |
|---|---|---|
| A1 | 🔵 Info | No custom audit retention policy covering the `CopilotInteraction` record type |

### DLP Workload Rules

| Rule | Severity | What it detects |
|---|---|---|
| D1 | 🟡 Warning | No enforced DLP policy scoped to the `CopilotInteractions` or `M365Copilot` workload |

D1 fires when the tenant has no DLP policy that simultaneously targets a Copilot workload, is in `Enable` mode, and is enabled. Policies in test mode or disabled do not satisfy this check. Without such a policy, data submitted to Copilot is not evaluated against any DLP rules.

### Insider Risk Management Rules

| Rule | Severity | What it detects |
|---|---|---|
| I1 | 🔵 Info | No active IRM policy using an AI-relevant template |

I1 fires when no IRM policy with status `Active` uses one of the following templates: `RiskyAIUsage`, `DataLeak`, `DataLeakByPriorityUser`, or `DataTheftByDepartingEmployee`. These templates generate risk signals that DSPM for AI surfaces as AI-related insider risk. Without an active policy of this type, AI-related risk events are not scored or surfaced.

### Severity guide

| Severity | Meaning |
|---|---|
| 🟡 Warning | A protection gap that leaves AI interactions unprotected or unmonitored. Review and remediate. |
| 🔵 Info | Informational. No immediate action required, but worth reviewing for long-term governance. |

### DSPM for AI Policy Inventory

The report includes a complete inventory table of the eight standard DSPM for AI policies, showing which are present in the tenant and whether DLP policies are in enforced or test mode. Use this table to give the customer a full picture regardless of whether individual items produced findings.

**The eight standard DSPM for AI policies are:**

| Policy | Type |
|---|---|
| DSPM for AI: Detect sensitive info added to AI sites | DLP |
| DSPM for AI - Block sensitive info from AI sites | DLP |
| DSPM for AI - Block elevated risk users from submitting prompts to AI apps in Microsoft Edge | DLP |
| DSPM for AI - Block sensitive info from AI apps in Edge | DLP |
| DSPM for AI - Protect sensitive data from Copilot processing | DLP |
| DSPM for AI - Detect when users visit AI sites | IRM |
| DSPM for AI - Detect risky AI usage | IRM |
| DSPM for AI - Unethical behavior in AI apps | Communication Compliance |

> **Legacy prefix note:** Policies created during preview may appear with the prefix `Microsoft AI Hub -` instead of `DSPM for AI -`. The script recognises both and treats them as equivalent.

### Collection Limitations

Every report includes a **Collection Limitations** section listing settings that could not be exported by script and must be verified manually in the Purview portal. Walk the customer through each item in this section as part of the review. The items are:

| Setting | Where to check |
|---|---|
| DSPM for AI collection policy status | Purview portal > DSPM for AI > Policies |
| Data risk assessment results | Purview portal > DSPM for AI > Data risks |
| Pay-as-you-go billing model enablement | Purview portal > DSPM for AI > Settings |
| Device onboarding status | Microsoft Defender portal |
| Browser extension deployment status | Microsoft Intune admin center |
| Fabric data risk assessment prerequisites | Fabric Admin REST API |

---

## All Parameters at a Glance

| Parameter | Required | Default | What it does |
|---|---|---|---|
| `-InputPath` | **Yes** | — | Path to the Purview export JSON from `Get-PurviewAudit.ps1` |
| `-OutputPath` | No | Current folder | Where to write the two output files (must be an existing folder) |

**Example with all parameters:**
```powershell
.\Invoke-PurviewAnalysis.ps1 `
    -InputPath  ".\Purview-Export-contoso-Commercial-20260228T143000Z.json" `
    -OutputPath "C:\Reports"
```

---

## Saving the Output to a Specific Folder

```powershell
.\Invoke-PurviewAnalysis.ps1 -InputPath ".\Purview-Export-contoso-Commercial-20260228T143000Z.json" -OutputPath "C:\Reports"
```

The folder must already exist. The script will not create it.

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

The path passed to `-InputPath` does not exist or contains a typo. Check with:

```powershell
Test-Path ".\Purview-Export-{filename}.json"
```

This should return `True`. If it returns `False`, verify the filename and your current directory.

---

### "Failed to parse Purview export JSON"

The file is not valid JSON. This usually means the file was modified or truncated after export. Ask the customer to re-run `Get-PurviewAudit.ps1` and send a fresh export.

---

### "Purview export JSON is missing required field"

The file does not have the expected envelope structure. Confirm you have the correct file — it must be produced by `Get-PurviewAudit.ps1`, not `Get-CAAudit.ps1` or any other export tool.

---

### "OutputPath '...' does not exist or is not a directory"

The folder specified with `-OutputPath` does not exist. Create it first:

```powershell
New-Item -Path "C:\Reports" -ItemType Directory
```

---

### The report shows no findings

This can mean the tenant is well-configured across all six checks: all DSPM for AI policies deployed and enforced, a `CopilotInteraction` retention policy in place, an enforced DLP policy covering the Copilot workload, and an active IRM policy using an AI-relevant template. Confirm by reviewing the DSPM policy inventory table in the report.

---

## Frequently Asked Questions

**Does this script connect to Microsoft or the customer's tenant?**
No. It is entirely offline. It reads only the file you provide and writes output files locally. No network calls are made.

**Can I run this more than once on the same file?**
Yes. Each run produces a new timestamped output file. Previous reports are not overwritten.

**The DSPM inventory shows some policies as "Not detected" — is that always bad?**
Not necessarily. A customer may have intentionally chosen not to deploy certain DSPM for AI policies (for example, if they use custom DLP policies instead). Use the findings as conversation starters, not as definitive verdicts.

**How does this relate to the Conditional Access analysis?**
They are complementary. `Invoke-CAAnalysis.ps1` checks whether Copilot can be *accessed* at all. `Invoke-PurviewAnalysis.ps1` checks whether data is *protected* once Copilot is being used. Run both for a complete picture.

**How do I share the results with the customer?**
Send the Markdown file (`.md`) for a readable report, or the JSON file (`.json`) if the customer needs to import findings into a tool. Both files contain only policy configuration metadata — no credentials or user data.

**What PowerShell version do I need?**
PowerShell 7.2 or later. The Windows built-in PowerShell 5.1 is not supported.

# How to Run the Purview Data Security Audit Script

This guide walks you through running `Get-PurviewAudit.ps1` — a script that exports your Microsoft Purview data security settings relevant to AI and Microsoft 365 Copilot so they can be reviewed for coverage gaps.

> **What the script does in plain English:** It signs into your tenant's Compliance Center using your admin account, reads your Data Loss Prevention policies, Insider Risk Management settings, and audit log retention policies, then saves the results to a file on your machine. Nothing is changed in your tenant. It is read-only.

## Requirements at a glance

| Requirement | Detail |
|---|---|
| **Authentication** | Security & Compliance PowerShell (`Connect-IPPSSession`) — interactive browser or device code |
| **Minimum role** | Compliance Reader (built-in Purview role group) |
| **Individual roles** | `View-Only DLP Compliance Management` · `View-Only Insider Risk Management` · `View-Only Audit Logs` |
| **PowerShell module** | `ExchangeOnlineManagement` 3.x or later |
| **PowerShell version** | 7.2 or later |
| **Network access** | Outbound HTTPS to the Security & Compliance PowerShell endpoint for your environment |

---

## Before You Start

Work through this checklist once. You only need to do it the first time.

### 1. You need PowerShell 7.2 or later

The script will not run on Windows PowerShell 5.1 (the version built into Windows). You need the newer cross-platform PowerShell 7.

**Check your version:**
```powershell
$PSVersionTable.PSVersion
```

If `Major` is 7 and `Minor` is 2 or higher, you are good. If not, download and install PowerShell 7 from:
https://aka.ms/powershell-release?tag=stable

### 2. You need one PowerShell module

This module is how PowerShell talks to the Microsoft Compliance Center. Install it once:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
```

> If you are prompted to install from an untrusted repository, type `Y` and press Enter.

**Verify it is installed:**
```powershell
Get-Module -ListAvailable ExchangeOnlineManagement
```

This should return a result with version 3.x or later. If it returns nothing, re-run the `Install-Module` command.

### 3. Your account needs the right role

The account you sign in with must hold at minimum the built-in **Compliance Reader** role in Microsoft Purview, or all three of the following roles:

| Role | What it covers |
|---|---|
| `View-Only DLP Compliance Management` | Reads Data Loss Prevention policies and rules |
| `View-Only Insider Risk Management` | Reads Insider Risk Management settings and policies |
| `View-Only Audit Logs` | Reads audit log retention policies |

**How to check:** Go to Microsoft Purview portal → Settings → Roles and scopes → Role groups, and confirm the account is a member of the **Compliance Reader** group (or the three individual groups above).

> You do not need to be a Global Administrator. Compliance Reader is sufficient.

---

## Know Your Environment

Before running the script, confirm which Microsoft 365 environment your tenant is in:

| If your tenant is… | Use this value |
|---|---|
| Standard Microsoft 365 | `Commercial` |
| Microsoft 365 GCC (US Government Community Cloud) | `GCC` |
| Microsoft 365 GCC High | `GCCH` |
| Microsoft 365 / Azure DoD | `DoD` |

**Not sure?** If you sign into the Purview portal at `compliance.microsoft.com`, you are almost certainly `Commercial`. If you use `compliance.microsoft.us`, you are `GCCH` or `DoD` — contact your licensing team to confirm.

---

## Running the Script

### Step 1 — Open PowerShell 7

Open **PowerShell 7** (not Windows PowerShell). Search for "pwsh" or "PowerShell 7" in the Start menu.

### Step 2 — Navigate to where you saved the script

```powershell
cd "C:\Path\To\Where\You\Saved\The\Script"
```

### Step 3 — Run it

Pick the command that matches your environment and preferred sign-in method.

---

#### Commercial (most customers)

**Interactive sign-in (browser pop-up):**
```powershell
.\Get-PurviewAudit.ps1 -UserPrincipalName you@yourdomain.com
```

**Device code sign-in (no browser on this machine):**
```powershell
.\Get-PurviewAudit.ps1 -UserPrincipalName you@yourdomain.com -AuthFlow DeviceCode
```

---

#### GCC

```powershell
.\Get-PurviewAudit.ps1 -Environment GCC -UserPrincipalName you@yourdomain.com
```

> GCC uses the same compliance endpoints as Commercial. The `-Environment GCC` flag is required so the script routes correctly.

---

#### GCC High

```powershell
.\Get-PurviewAudit.ps1 -Environment GCCH -UserPrincipalName you@yourdomain.us -AuthFlow DeviceCode
```

> GCC High uses sovereign compliance endpoints (`compliance.microsoft.us`). Device Code is the safer authentication choice in these environments.

---

#### DoD

```powershell
.\Get-PurviewAudit.ps1 -Environment DoD -UserPrincipalName you@yourdomain.mil -AuthFlow DeviceCode
```

> DoD environments require Device Code authentication in most configurations.

---

### Step 4 — Sign in when prompted

**Interactive mode:** A browser window opens. Sign in with the account you specified. Complete MFA if required.

**Device Code mode:** The terminal prints a message like:

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXXX to authenticate.
```

Open that URL on any browser (it does not need to be the same machine), enter the code, and sign in.

### Step 5 — Wait for it to finish

The script prints progress as it works:

```
Connecting to Security & Compliance PowerShell (Commercial)...
Connected as: you@yourdomain.com  |  Tenant: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Collecting audit log retention policies...
Retrieved 3 retention policy(s).
Collecting DLP compliance policies...
Retrieved 12 DLP policy(s). Collecting rules...
DLP collection complete.
Collecting Insider Risk Management settings and policies...
Retrieved 2 IRM policy(s).
Retrieved 1 Communication Compliance policy(s).
JSON export written: C:\Scripts\Purview-Export-xxxxxxxx-Commercial-20260227T143000Z.json

Export complete.
  JSON: C:\Scripts\Purview-Export-xxxxxxxx-Commercial-20260227T143000Z.json
```

Depending on how many policies your tenant has, this typically takes 1 to 3 minutes.

---

## The Output File

The script saves a single JSON file in the current directory (or wherever you specify with `-OutputPath`).

**File name format:**
```
Purview-Export-{TenantId}-{Environment}-{Timestamp}.json
```

**Example:**
```
Purview-Export-00000000-0000-0000-0000-000000000000-Commercial-20260227T143000Z.json
```

The file contains a metadata header followed by your DLP policies, IRM settings, audit retention policies, and a DSPM for AI policy inventory:

```json
{
  "exportedBy": "you@yourdomain.com",
  "exportedAt": "2026-02-27T14:30:00.0000000+00:00",
  "environment": "Commercial",
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "auditRetentionPolicies": [ ... ],
  "dlpPolicies": [ ... ],
  "insiderRisk": { ... },
  "dspmPolicyInventory": [ ... ],
  "collectionLimitations": [ ... ]
}
```

**Send this file** to your Microsoft contact or the team performing the analysis. Do not modify it — the file is machine-readable and any changes may affect downstream analysis.

> **Note:** The file also includes a `collectionLimitations` section. This lists settings that could not be collected automatically (such as DSPM for AI collection policy status, which is only visible in the Purview portal). This is normal and expected — your analyst will walk you through those items separately.

---

## All Parameters at a Glance

| Parameter | Required | Default | What it does |
|---|---|---|---|
| `-UserPrincipalName` | **Yes** | — | Your sign-in account (e.g. `admin@contoso.com`) |
| `-Environment` | No | `Commercial` | Cloud environment: `Commercial`, `GCC`, `GCCH`, or `DoD` |
| `-AuthFlow` | No | `Interactive` | How to sign in: `Interactive` (browser) or `DeviceCode` |
| `-OutputPath` | No | Current folder | Where to save the file (must be an existing folder) |

**Example with all parameters specified:**
```powershell
.\Get-PurviewAudit.ps1 `
    -UserPrincipalName admin@contoso.com `
    -Environment Commercial `
    -AuthFlow Interactive `
    -OutputPath "C:\PurviewExports"
```

---

## Saving the File to a Specific Folder

```powershell
.\Get-PurviewAudit.ps1 -UserPrincipalName you@yourdomain.com -OutputPath "C:\PurviewExports"
```

The folder must already exist. The script will not create it for you.

---

## Troubleshooting

### "Running scripts is disabled on this system"

PowerShell's execution policy is blocking the script. Run this once:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then try again.

---

### "Required module 'ExchangeOnlineManagement' is not installed"

The module is missing. Run:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
```

---

### "OutputPath '...' does not exist or is not a directory"

The folder you specified with `-OutputPath` does not exist. Create it first:

```powershell
New-Item -Path "C:\PurviewExports" -ItemType Directory
```

---

### "Could not retrieve IRM settings (role may be missing)"

This warning appears when the account does not have the `View-Only Insider Risk Management` role. The script continues and exports what it can. To resolve: assign the account to the **Compliance Reader** role group in the Purview portal and re-run.

---

### "Could not retrieve Communication Compliance policies"

Communication Compliance requires a specific license (Microsoft 365 E5 Compliance or equivalent). If your tenant does not have this license, this warning is expected and the rest of the export is complete.

---

### The script appears to hang after "Connecting..."

The sign-in prompt may have opened in a browser window behind your current windows. Check your taskbar for a new browser window asking for credentials.

If you are in a headless environment (no browser available), re-run with `-AuthFlow DeviceCode`.

---

### Signed in as the wrong account

If you signed into a different account than expected, the export continues with the account you actually signed in with. Re-run the script and ensure you select the correct account at the sign-in prompt.

---

## Frequently Asked Questions

**Does this script make any changes to my tenant?**
No. It is entirely read-only. It connects to the Compliance Center with read-only permissions and makes no modifications.

**Can I run this without being a Global Administrator?**
Yes. The Compliance Reader role is sufficient.

**How long does it take?**
Typically 1 to 3 minutes, depending on how many DLP policies your tenant has.

**Can I run this more than once?**
Yes. Each run produces a new timestamped file. Previous files are not overwritten.

**Is the output file sensitive?**
Yes. The export contains your DLP policy configuration and Insider Risk Management settings, which are security-relevant. Treat it the same way you would treat any security configuration export — share only with authorized parties over secure channels.

**What is the `collectionLimitations` section in the output?**
Some settings are only accessible through the Purview portal UI and cannot be read by a script. The `collectionLimitations` section documents exactly which settings those are and where to find them in the portal. Your analyst will review these with you.

**What PowerShell version do I need?**
PowerShell 7.2 or later. The Windows built-in PowerShell 5.1 is not supported.

**I already ran Get-CAAudit.ps1 — do I need to run this too?**
Yes. `Get-CAAudit.ps1` collects Conditional Access policy data. `Get-PurviewAudit.ps1` collects a different set of data — DLP, Insider Risk Management, and audit settings. Both files together give a complete picture of your tenant's AI data security posture.

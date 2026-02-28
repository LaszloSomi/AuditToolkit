# How to Run the Conditional Access Audit Script

This guide walks you through running `Get-CAAudit.ps1` — a script that exports all Conditional Access (CA) policies from your Microsoft 365 tenant so they can be reviewed for misconfigurations.

> **What the script does in plain English:** It signs into your tenant using your admin account, reads every Conditional Access policy, and saves the results to a file on your machine. Nothing is changed in your tenant. It is read-only.

## Requirements at a glance

| Requirement | Detail |
|---|---|
| **Authentication** | Microsoft Graph — interactive browser sign-in or device code |
| **Minimum role** | Security Reader (Global Administrator not required) |
| **Accepted roles** | Conditional Access Administrator, Security Reader, Security Administrator, Global Reader, Global Administrator |
| **Graph permissions** | `Policy.Read.All` (required) · `Directory.Read.All` (recommended — resolves GUIDs to display names) |
| **PowerShell modules** | `Microsoft.Graph.Authentication` · `Microsoft.Graph.Identity.SignIns` |
| **PowerShell version** | 7.2 or later |
| **Network access** | Outbound HTTPS to `graph.microsoft.com` (or sovereign equivalent) |

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

### 2. You need two PowerShell modules

These modules are how PowerShell talks to Microsoft Graph. Install them once:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

> If you are prompted to install from an untrusted repository, type `Y` and press Enter.

**Verify they are installed:**
```powershell
Get-Module -ListAvailable Microsoft.Graph.Authentication
Get-Module -ListAvailable Microsoft.Graph.Identity.SignIns
```

Both should return a result. If either returns nothing, re-run the `Install-Module` command for that module.

### 3. Your account needs the right role

The account you sign in with must have one of the following Entra ID roles:

| Role | Notes |
|---|---|
| Conditional Access Administrator | Most targeted — recommended |
| Security Reader | Read-only access to security settings |
| Security Administrator | Broader security admin access |
| Global Reader | Read-only access to everything |
| Global Administrator | Full access |

You do not need to be a Global Administrator. A Security Reader is sufficient.

### 4. Your account needs to consent to two Graph permissions

The script requests these two permissions when you sign in:

| Permission | Why it is needed |
|---|---|
| `Policy.Read.All` | Required — reads the CA policies |
| `Directory.Read.All` | Recommended — resolves IDs to display names (e.g. turns a group GUID into "Executives") |

On first run, Microsoft will ask you to consent to these permissions in a browser window. This is normal. If your tenant requires admin consent, a Global Administrator will need to grant consent once before you can run the script.

> **If Directory.Read.All is blocked by your tenant:** The script will still work. Group and user IDs in the export will appear as raw GUIDs instead of display names, but the policy data will be complete.

---

## Know Your Environment

Before running the script, confirm which Microsoft 365 environment your tenant is in. Use the table below:

| If your tenant is… | Use this value |
|---|---|
| Standard Microsoft 365 | `Commercial` |
| Microsoft 365 GCC (US Government Community Cloud) | `GCC` |
| Microsoft 365 GCC High | `GCCH` |
| Microsoft 365 / Azure DoD | `DoD` |

**Not sure?** If you sign in at `portal.microsoft.com`, you are almost certainly `Commercial`. If you sign in at `portal.azure.us`, you are `GCCH` or `DoD` — contact your licensing team to confirm which.

---

## Running the Script

### Step 1 — Open PowerShell 7

Open **PowerShell 7** (not Windows PowerShell). You can find it by searching "pwsh" or "PowerShell 7" in the Start menu.

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
.\Get-CAAudit.ps1 -UserPrincipalName you@yourdomain.com
```

**Device code sign-in (no browser on this machine):**
```powershell
.\Get-CAAudit.ps1 -UserPrincipalName you@yourdomain.com -AuthFlow DeviceCode
```

---

#### GCC

```powershell
.\Get-CAAudit.ps1 -Environment GCC -UserPrincipalName you@yourdomain.com
```

> GCC uses the same sign-in endpoints as Commercial. The `-Environment GCC` flag is required so the script knows which tenant type to expect.

---

#### GCC High

```powershell
.\Get-CAAudit.ps1 -Environment GCCH -UserPrincipalName you@yourdomain.us -AuthFlow DeviceCode
```

> GCC High uses `login.microsoftonline.us` and `graph.microsoft.us`. Interactive browser sign-in may not display correctly in some environments — Device Code is the safer choice here.

---

#### DoD

```powershell
.\Get-CAAudit.ps1 -Environment DoD -UserPrincipalName you@yourdomain.mil -AuthFlow DeviceCode
```

> DoD environments require Device Code authentication in most configurations.

---

### Step 4 — Sign in when prompted

**Interactive mode:** A browser window opens. Sign in with the account you specified. If MFA is required, complete it as normal.

**Device Code mode:** The terminal prints a message like:

```
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXXX to authenticate.
```

Open that URL on any browser (it does not have to be on the same machine), enter the code, and sign in with your account.

### Step 5 — Consent to permissions (first run only)

On first run, Microsoft will ask you to accept the permissions the script needs (`Policy.Read.All` and `Directory.Read.All`). Click **Accept**.

You will only be asked this once per account. On subsequent runs, the consent is remembered.

### Step 6 — Wait for it to finish

The script will print progress as it works:

```
Connecting to Microsoft Graph (Commercial)...
Connected as: you@yourdomain.com
Retrieving Conditional Access policies...
Retrieved 47 policies.
Resolving directory object display names...
JSON export written: C:\Scripts\CA-Export-xxxxxxxx-Commercial-20260223T143000Z.json

Audit complete. 47 policies exported to: C:\Scripts\CA-Export-xxxxxxxx-Commercial-20260223T143000Z.json
```

Depending on how many policies and users/groups your tenant has, this typically takes 30 seconds to a few minutes.

---

## The Output File

The script saves a file in the current directory (or wherever you specify with `-OutputPath`).

**File name format:**
```
CA-Export-{TenantId}-{Environment}-{Timestamp}.json
```

**Example:**
```
CA-Export-00000000-0000-0000-0000-000000000000-Commercial-20260223T143000Z.json
```

The file contains a metadata header followed by all policies:

```json
{
  "exportedBy": "you@yourdomain.com",
  "exportedAt": "2026-02-23T14:30:00.0000000+00:00",
  "environment": "Commercial",
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "policyCount": 47,
  "policies": [ ... ]
}
```

**Send this file** to your Microsoft contact or the team performing the analysis. Do not modify it — the file is machine-readable and any changes may affect downstream analysis.

---

## All Parameters at a Glance

| Parameter | Required | Default | What it does |
|---|---|---|---|
| `-UserPrincipalName` | **Yes** | — | Your sign-in account (e.g. `admin@contoso.com`) |
| `-Environment` | No | `Commercial` | Cloud environment: `Commercial`, `GCC`, `GCCH`, or `DoD` |
| `-AuthFlow` | No | `Interactive` | How to sign in: `Interactive` (browser) or `DeviceCode` |
| `-OutputFormat` | No | `JSON` | File format: `JSON` or `CSV` |
| `-OutputPath` | No | Current folder | Where to save the file (must be an existing folder) |

**Example with all parameters specified:**
```powershell
.\Get-CAAudit.ps1 `
    -UserPrincipalName admin@contoso.com `
    -Environment Commercial `
    -AuthFlow Interactive `
    -OutputFormat JSON `
    -OutputPath "C:\CAExports"
```

---

## Exporting as CSV instead of JSON

If you prefer a spreadsheet-friendly format:

```powershell
.\Get-CAAudit.ps1 -UserPrincipalName you@yourdomain.com -OutputFormat CSV
```

> Note: CA policies contain nested data (lists of groups, conditions, controls). In the CSV, these are stored as compact JSON strings within each cell. The JSON export is preferred for analysis — use CSV only if you specifically need it.

---

## Saving the file to a specific folder

```powershell
.\Get-CAAudit.ps1 -UserPrincipalName you@yourdomain.com -OutputPath "C:\CAExports"
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

### "Required module 'Microsoft.Graph.Authentication' is not installed"

The module is missing. Run:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

---

### "OutputPath '...' does not exist or is not a directory"

The folder you specified with `-OutputPath` does not exist. Create it first:

```powershell
New-Item -Path "C:\CAExports" -ItemType Directory
```

---

### "Insufficient privileges to complete the operation"

Your account does not have a required Entra ID role. Confirm your account holds one of the roles listed in the [Prerequisites](#3-your-account-needs-the-right-role) section.

---

### "Admin consent required"

Your tenant requires an administrator to pre-approve the Graph permissions. Have a Global Administrator visit the following URL and grant consent on behalf of the organization:

```
https://login.microsoftonline.com/{your-tenant-id}/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e
```

Replace `{your-tenant-id}` with your tenant's GUID or primary domain.

> For GCC High and DoD, replace `login.microsoftonline.com` with `login.microsoftonline.us`.

---

### The export file is missing display names (shows GUIDs instead of group names)

This means `Directory.Read.All` was not consented or was blocked by your tenant policy. The export is still valid — IDs are present and the analysis can proceed. If display names are important to you, ask your Global Administrator to grant `Directory.Read.All` consent for your account.

---

### Signed in as the wrong account / "Signed in as X but expected Y" warning

The script detected you signed into a different account than you specified with `-UserPrincipalName`. The export continues using whatever account you actually signed in with. If this is unintentional, re-run the script and make sure you select the correct account in the sign-in prompt.

---

## Frequently Asked Questions

**Does this script make any changes to my tenant?**
No. It is entirely read-only. It calls Microsoft Graph with read-only permissions and makes no modifications.

**Can I run this without being a Global Administrator?**
Yes. A Security Reader role is sufficient.

**How long does it take?**
Typically 30 seconds to 2 minutes, depending on how many policies and directory objects are in your tenant.

**Can I run this more than once?**
Yes. Each run produces a new timestamped file. Previous files are not overwritten.

**Is the output file sensitive?**
Yes. The export contains your Conditional Access policy configuration, which is security-relevant information. Treat it the same way you would treat any security configuration export — share only with authorized parties over secure channels.

**Can I open the JSON file in Excel?**
Not directly. If you need it in Excel, re-run with `-OutputFormat CSV`. Alternatively, paste the JSON into a tool like Visual Studio Code with a JSON formatter to read it easily.

**What PowerShell version do I need?**
PowerShell 7.2 or later. The Windows built-in PowerShell 5.1 is not supported.

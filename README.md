# AuditToolkit

This toolkit audits your Microsoft 365 tenant for configurations that affect the security and availability of Microsoft 365 Copilot. It covers two areas:

1. **Conditional Access** — checks that your CA policies won't block Copilot access
2. **Purview Data Security** — checks that DLP, Insider Risk Management, and audit settings protect your data in AI experiences

Each area follows the same two-step workflow: a customer runs a collection script that exports settings to a file, then an analyst reviews that file to identify gaps.

Nothing in your tenant is ever changed. All scripts are read-only.

---

## I am a customer — what do I need to do?

You need to run one or both collection scripts and send the output files to your Microsoft contact.

### Conditional Access export

Exports all Conditional Access policies so they can be checked for configurations that block or degrade Copilot.

👉 **Read [Get-CAAudit - Customer Instructions.md](LogCollection/Get-CAAudit%20-%20Customer%20Instructions.md) for step-by-step guidance.**

**In short:**
- You need PowerShell 7 and two Microsoft Graph modules (the guide walks you through this)
- You run one command and sign in with your admin account
- The script saves a `CA-Export-*.json` file to your machine
- Send that file to your Microsoft contact

### Purview Data Security export

Exports your DLP policies, Insider Risk Management settings, and audit retention policies so they can be checked for gaps in AI data protection.

👉 **Read [Get-PurviewAudit - Customer Instructions.md](LogCollection/Get-PurviewAudit%20-%20Customer%20Instructions.md) for step-by-step guidance.**

**In short:**
- You need PowerShell 7 and one module (`ExchangeOnlineManagement`) — the guide walks you through this
- You run one command and sign in with your compliance admin account
- The script saves a `Purview-Export-*.json` file to your machine
- Send that file to your Microsoft contact

---

## I am an analyst — what do I need to do?

Once you have the export file(s) from the customer, use the analysis script or the Copilot agent to review them.

👉 **Read [Admin Instructions.md](Analysis/Admin%20Instructions.md) for step-by-step guidance on the Conditional Access analysis script.**

**In short:**
- You need PowerShell 7 — no modules required, no internet connection needed
- You run one command pointing at the customer's CA export file
- The script produces a Markdown report and a JSON findings file
- No changes are made to anything

---

## What does the Conditional Access analysis check for?

The analysis script checks every CA policy against seven rules:

| Rule | What it looks for |
|---|---|
| 🔴 R1 — Direct Block | A policy that flat-out blocks users from accessing Copilot |
| 🔴 R2 — Compliant Device Gate | A policy that requires a compliant device, which Copilot web experiences cannot satisfy |
| 🟡 R3 — Sign-in Frequency | A policy that forces full re-authentication every session, breaking Copilot conversations |
| 🟡 R4 — Report-Only Risk | A report-only policy that would cause R1, R2, or R3 problems if someone enables it |
| 🟡 R5 — Token Protection | A policy using token binding, which Copilot does not support |
| 🔵 R6 — MFA Coverage Gap | No MFA policy covering all users — Copilot requires MFA |
| 🔵 R7 — Copilot App Scoping | A policy that explicitly names Copilot — flagged for review |

🔴 Critical = Copilot will be blocked. Fix before enabling Copilot.
🟡 Warning = Copilot may have problems. Review before enabling Copilot.
🔵 Info = Worth knowing about, but no immediate action required.

---

## I want to use the Copilot chat agent instead of the analysis script

There is also a Microsoft 365 Copilot declarative agent that does the Conditional Access analysis inside Copilot chat. Instead of running a PowerShell script, you paste the export JSON directly into a Copilot conversation and the agent checks it for you.

**Deploy it once, use it from Copilot chat forever.**

### What you need

- A Microsoft 365 Copilot licence
- Access to [Copilot Studio](https://copilotstudio.microsoft.com)
- The `copilot-agent/` folder from this repo

### How to deploy

1. **Download the agent files** — get `copilot-agent/manifest.json` and `copilot-agent/instruction.txt` from this repo onto your machine.

2. **Create a zip file** — put both files into a zip. The zip must contain the files directly (not inside a subfolder):
   ```
   CA-Policy-Analyzer.zip
   ├── manifest.json
   └── instruction.txt
   ```

3. **Import into Copilot Studio**
   - Go to [copilotstudio.microsoft.com](https://copilotstudio.microsoft.com)
   - Click **Agents** in the left menu
   - Click **Import**
   - Upload your zip file

4. **Publish** — once imported, click **Publish** to make it available in Microsoft 365 Copilot.

5. **Use it** — open Microsoft 365 Copilot, find the **CA Policy Analyzer** agent, and start a conversation. Paste the contents of the customer's `CA-Export-*.json` file into the chat and the agent will analyse it.

> The agent uses the same seven rules as `Invoke-CAAnalysis.ps1`. The two tools are independent — you do not need one to use the other.

---

## Files in this repo

| File | What it is |
|---|---|
| `LogCollection/Get-CAAudit.ps1` | Exports Conditional Access policies from the tenant |
| `LogCollection/Get-CAAudit - Customer Instructions.md` | Step-by-step guide for customers running the CA export |
| `LogCollection/Get-PurviewAudit.ps1` | Exports Purview DLP, IRM, and audit settings from the tenant |
| `LogCollection/Get-PurviewAudit - Customer Instructions.md` | Step-by-step guide for customers running the Purview export |
| `Analysis/Invoke-CAAnalysis.ps1` | Analyses a CA export for Copilot-blocking misconfigurations |
| `Analysis/Admin Instructions.md` | Step-by-step guide for analysts running the CA analysis |
| `Analysis/tests/` | Automated Pester tests for the CA analysis script |
| `copilot-agent/manifest.json` | Copilot Studio agent manifest |
| `copilot-agent/instruction.txt` | Agent system prompt with all 7 CA rules |

---

## Quick start

**Customer — export Conditional Access policies:**
```powershell
.\LogCollection\Get-CAAudit.ps1 -UserPrincipalName admin@yourdomain.com
```

**Customer — export Purview data security settings:**
```powershell
.\LogCollection\Get-PurviewAudit.ps1 -UserPrincipalName admin@yourdomain.com
```

**Analyst — analyse the CA export:**
```powershell
.\Analysis\Invoke-CAAnalysis.ps1 -InputPath ".\CA-Export-{filename}.json"
```

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

Once you have the export file(s) from the customer, run the relevant analysis script. Both are fully offline — no modules, no internet connection, no tenant access required.

### Conditional Access analysis

👉 **Read [Invoke-CAAnalysis - Admin Instructions.md](Analysis/Invoke-CAAnalysis%20-%20Admin%20Instructions.md) for step-by-step guidance.**

- Takes the customer's `CA-Export-*.json` file
- Checks every CA policy against seven rules
- Produces a Markdown report and a JSON findings file

### Purview Data Security analysis

👉 **Read [Invoke-PurviewAnalysis - Admin Instructions.md](Analysis/Invoke-PurviewAnalysis%20-%20Admin%20Instructions.md) for step-by-step guidance.**

- Takes the customer's `Purview-Export-*.json` file
- Checks DSPM for AI policy deployment, DLP enforcement, audit retention, and IRM configuration against six rules
- Produces a Markdown report and a JSON findings file

---

## What do the analysis scripts check for?

### Conditional Access analysis

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

### Purview Data Security analysis

| Rule | What it looks for |
|---|---|
| 🟡 P1 — Policy Not Deployed | A DSPM for AI policy that has not been created in the tenant |
| 🟡 P2 — Policy in Test Mode | A DSPM for AI DLP policy that exists but is not enforcing (test mode only) |
| 🟡 P3 — Policy Disabled | A DSPM for AI DLP policy that exists but has been explicitly disabled |
| 🔵 A1 — No Copilot Audit Retention | No custom audit retention policy covering the `CopilotInteraction` record type |
| 🟡 D1 — No DLP Copilot Coverage | No enforced DLP policy scoped to the `CopilotInteractions` or `M365Copilot` workload |
| 🔵 I1 — No Active AI IRM Policy | No active Insider Risk Management policy using an AI-relevant template |

---

## I want to use Copilot chat agents instead of the analysis scripts

Both analysis scripts have a matching Microsoft 365 Copilot declarative agent. Instead of running PowerShell, you paste the export JSON directly into a Copilot conversation and the agent checks it for you.

**Deploy once, use from Copilot chat forever.**

### What you need

- A Microsoft 365 Copilot licence
- Access to [Copilot Studio](https://copilotstudio.microsoft.com)

### How to deploy either agent

1. **Download the agent files** from the relevant subfolder inside `Copilot Agents/` in this repo.

2. **Create a zip file** containing both files directly (not inside a subfolder):
   ```
   AgentName.zip
   ├── manifest.json
   └── instruction.txt
   ```

3. **Import into Copilot Studio**
   - Go to [copilotstudio.microsoft.com](https://copilotstudio.microsoft.com)
   - Click **Agents** in the left menu → **Import**
   - Upload your zip file

4. **Publish** — click **Publish** to make it available in Microsoft 365 Copilot.

5. **Use it** — open Microsoft 365 Copilot, find the agent, and paste the relevant export JSON into the chat.

### Available agents

| Agent | Folder | Analyses | Export file |
|---|---|---|---|
| CA Policy Analyzer | `Copilot Agents/CA Policy Analyzer/` | Conditional Access policies (7 rules) | `CA-Export-*.json` |
| Purview AI Readiness Analyzer | `Copilot Agents/Purview AI Readiness Analyzer/` | DSPM for AI policies, DLP enforcement, audit retention, IRM (6 rules) | `Purview-Export-*.json` |

---

## Files in this repo

| File | What it is |
|---|---|
| `LogCollection/Get-CAAudit.ps1` | Exports Conditional Access policies from the tenant |
| `LogCollection/Get-CAAudit - Customer Instructions.md` | Step-by-step guide for customers running the CA export |
| `LogCollection/Get-PurviewAudit.ps1` | Exports Purview DLP, IRM, and audit settings from the tenant |
| `LogCollection/Get-PurviewAudit - Customer Instructions.md` | Step-by-step guide for customers running the Purview export |
| `Analysis/Invoke-CAAnalysis.ps1` | Analyses a CA export for Copilot-blocking misconfigurations |
| `Analysis/Invoke-CAAnalysis - Admin Instructions.md` | Step-by-step guide for analysts running the CA analysis |
| `Analysis/Invoke-PurviewAnalysis.ps1` | Analyses a Purview export for DSPM for AI policy gaps |
| `Analysis/Invoke-PurviewAnalysis - Admin Instructions.md` | Step-by-step guide for analysts running the Purview analysis |
| `Analysis/tests/` | Automated Pester tests for both analysis scripts |
| `Copilot Agents/CA Policy Analyzer/manifest.json` | CA Policy Analyzer — Copilot Studio agent manifest |
| `Copilot Agents/CA Policy Analyzer/instruction.txt` | CA Policy Analyzer — agent system prompt (7 CA rules) |
| `Copilot Agents/Purview AI Readiness Analyzer/manifest.json` | Purview AI Readiness Analyzer — Copilot Studio agent manifest |
| `Copilot Agents/Purview AI Readiness Analyzer/instruction.txt` | Purview AI Readiness Analyzer — agent system prompt (6 Purview rules) |

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

**Analyst — analyse the Purview export:**
```powershell
.\Analysis\Invoke-PurviewAnalysis.ps1 -InputPath ".\Purview-Export-{filename}.json"
```

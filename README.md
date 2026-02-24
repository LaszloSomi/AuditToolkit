# AuditToolkit

This toolkit checks your Microsoft 365 Conditional Access policies to make sure they won't block Microsoft 365 Copilot.

It has two parts that work together:

1. **The customer runs a script** that reads their Conditional Access policies and saves them to a file.
2. **The analyst runs a second script** on that file to check for problems and produce a report.

Nothing in your tenant is ever changed. Both scripts are read-only.

---

## I am a customer — what do I need to do?

You need to run one script that exports your Conditional Access policies to a file and send that file to your Microsoft contact.

👉 **Read [Customer Instructions.md](LogCollection/Customer%20Instructions.md) for step-by-step guidance.**

**In short:**
- You need PowerShell 7 and two Microsoft Graph modules installed (the guide walks you through this)
- You run one command and sign in with your admin account
- The script saves a `.json` file to your machine
- You send that file to your Microsoft contact — that is all you need to do

---

## I am an analyst — what do I need to do?

Once you have the export file from the customer, you run the analysis script on it. It checks the policies against seven rules and produces a Markdown report and a JSON findings file.

👉 **Read [Admin Instructions.md](Analysis/Admin%20Instructions.md) for step-by-step guidance.**

**In short:**
- You need PowerShell 7 — no Microsoft Graph modules required, no internet connection needed
- You run one command pointing at the customer's export file
- The script produces two files: a readable report (`.md`) and a machine-readable findings file (`.json`)
- No changes are made to anything — it reads the file and writes a report, that is it

---

## What does the analysis check for?

The analysis script checks every policy against seven rules:

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

## I want to use the Copilot chat agent instead of the script

There is also a Microsoft 365 Copilot declarative agent that does the same analysis inside Copilot chat. Instead of running a PowerShell script, you paste the export JSON directly into a Copilot conversation and the agent checks it for you.

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

5. **Use it** — open Microsoft 365 Copilot, find the **CA Policy Analyzer** agent in the agent store or use a direct link, and start a conversation. When asked, paste the contents of the customer's export `.json` file into the chat. The agent will analyse it and return its findings.

> The agent uses the same seven rules as `Invoke-CAAnalysis.ps1`. The two tools are independent — you do not need one to use the other.

---

## Files in this repo

| File | What it is |
|---|---|
| `LogCollection/Get-CAAudit.ps1` | The script customers run to export their policies |
| `LogCollection/Customer Instructions.md` | Step-by-step guide for customers running the export |
| `Analysis/Invoke-CAAnalysis.ps1` | The script analysts run to check the export for problems |
| `Analysis/Admin Instructions.md` | Step-by-step guide for analysts running the analysis |
| `copilot-agent/manifest.json` | Copilot Studio agent manifest |
| `copilot-agent/instruction.txt` | Agent system prompt with all 7 rules |
| `tests/` | Automated tests for the analysis script |

---

## Quick start — two commands

**Customer (export):**
```powershell
.\LogCollection\Get-CAAudit.ps1 -UserPrincipalName admin@yourdomain.com
```

**Analyst (analyse):**
```powershell
.\Analysis\Invoke-CAAnalysis.ps1 -InputPath ".\CA-Export-{filename}.json"
```

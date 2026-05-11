# XPIA Demo Pre-Setup Script — README

## What This Does

`Invoke-XPIADemoSetup.ps1` automates the night-before setup for the XPIA demo playbook. Instead of manually clicking through the Compliance Center, Exchange Admin, and Azure portal, run this once and it handles:

| Phase | What It Does | Playbook Section |
|-------|-------------|-----------------|
| 1 | Checks prerequisites (modules, connections) | §2.1 |
| 2 | Deploys custom XPIA Sensitive Information Type to Purview | §2.3, Appendix C |
| 3 | Creates Exchange mail flow rule for XPIA detection | §2.4, Appendix D.1 |
| 4 | Creates DLP policy with high/medium confidence rules | §2.5 |
| 5 | Outputs test XPIA email templates for manual sending via OWA | §3.1, Appendix B |
| 6 | Outputs KQL queries for manual save in Advanced Hunting | §2.8, Appendix A |
| 7 | Tests Content Safety API with all 3 attack variants + benign baseline | §2.9, Appendix D.2 |
| 8 | Runs full environment validation checklist | §2.10, Appendix D.3 |

## Prerequisites

- **PowerShell 5.1+** (or PowerShell 7)
- **ExchangeOnlineManagement** module: `Install-Module ExchangeOnlineManagement -Scope CurrentUser`
- **Admin credentials** with access to Exchange Online and Security & Compliance Center
- **Azure AI Content Safety** resource provisioned (for Phase 7)

## Quick Start

### Full setup (run everything):

```powershell
.\Invoke-XPIADemoSetup.ps1 `
    -AdminUpn admin@contoso.com `
    -ContentSafetyEndpoint "https://xpia-cs.cognitiveservices.azure.com" `
    -ContentSafetyKey "<your-key>" `
    -SentinelWorkspaceId "<workspace-guid>" `
    -TestSenderEmail attacker@outlook.com `
    -TestRecipientEmail victim1@contoso.com `
    -SecondaryRecipientEmail victim2@contoso.com `
    -SecurityTeamDl secteam@contoso.com
```

### Dry run (see what would happen without changes):

```powershell
.\Invoke-XPIADemoSetup.ps1 -AdminUpn admin@contoso.com -WhatIf
```

### Validation only (morning-of readiness check):

```powershell
.\Invoke-XPIADemoSetup.ps1 `
    -AdminUpn admin@contoso.com `
    -ContentSafetyEndpoint "https://xpia-cs.cognitiveservices.azure.com" `
    -ContentSafetyKey "<your-key>" `
    -ValidateOnly
```

### Skip specific phases:

```powershell
# Already have the SIT and mail flow rule, just need DLP + test emails
.\Invoke-XPIADemoSetup.ps1 `
    -AdminUpn admin@contoso.com `
    -SkipSIT -SkipMailFlow `
    -TestSenderEmail attacker@outlook.com `
    -TestRecipientEmail victim1@contoso.com
```

## Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-AdminUpn` | Yes | — | Admin UPN for Exchange/Compliance connections |
| `-ContentSafetyEndpoint` | No | `""` | Azure AI Content Safety endpoint URL |
| `-ContentSafetyKey` | No | `""` | API key for Content Safety resource |
| `-SentinelWorkspaceId` | No | `""` | Log Analytics workspace ID (for validation) |
| `-TestSenderEmail` | No | `attacker@testdomain.com` | External sender for test emails |
| `-TestRecipientEmail` | No | `victim1@company.com` | Primary victim mailbox |
| `-SecondaryRecipientEmail` | No | `victim2@company.com` | Secondary victim for campaign detection |
| `-SecurityTeamDl` | No | `securityteam@company.com` | DL for incident reports |
| `-TestEmailCount` | No | `1` | Emails per payload variant (1-10) |
| `-SkipSIT` | No | `$false` | Skip Phase 2 |
| `-SkipMailFlow` | No | `$false` | Skip Phase 3 |
| `-SkipDLP` | No | `$false` | Skip Phase 4 |
| `-SkipTestEmails` | No | `$false` | Skip Phase 5 |
| `-SkipValidation` | No | `$false` | Skip Phase 8 |
| `-ValidateOnly` | No | `$false` | Run only Phase 8 (validation) |
| `-WhatIf` | No | `$false` | Preview mode — no changes made |

## Timing Notes

- **SIT propagation:** 30–60 min after Phase 2 before DLP can reference it
- **DLP policy activation:** 1–4 hours before it starts matching content
- **Communication Compliance:** Up to 24 hours (configure manually via UI)
- **Test email alerts:** ~15 min after Phase 5 for Defender XDR alerts to appear
- **DSPM for AI:** 24–48 hours after first enablement

**Recommended timeline:**
1. Run full setup script **the evening before** the demo
2. Run `-ValidateOnly` the **morning of** the demo
3. Send final test email **15 minutes before** the customer arrives

## What You Still Need to Do Manually

The script handles everything automatable. These items require the Compliance Center UI:

1. **Communication Compliance policy** (§2.6) — no PowerShell cmdlet for Copilot channel config
2. **Insider Risk Management policy** (§2.8) — requires UI configuration
3. **DSPM for AI enablement** — toggle in compliance.microsoft.com → DSPM for AI → Settings
4. **DLP Copilot experience location** — after Phase 4, edit the DLP policy in the Compliance Center and enable "Microsoft Copilot experiences" (and "Devices" if applicable) under Locations. The cmdlet does not yet support this location.
5. **Test emails** — Phase 5 outputs email templates to the console. Copy-paste them into OWA from the external sender account to the victim mailbox(es).
6. **KQL queries** — Phase 6 outputs them; paste and save in Advanced Hunting manually
7. **Browser tabs** — Phase 8 reminds you which tabs to pre-stage

## Content Safety API Schema

The script uses the correct Prompt Shields schema:

```json
{
    "userPrompt": "Summarize this document for me",
    "documents": ["document content here..."]
}
```

This is **not** the generic `{"text":"..."}` schema. The `userPrompt` + `documents` structure enables separate analysis of the user's intent vs. grounding data — which is exactly how XPIA works.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `Connect-ExchangeOnline` fails | Install module: `Install-Module ExchangeOnlineManagement` |
| `Connect-IPPSSession` fails | Ensure admin has Security & Compliance admin role |
| SIT not found after Phase 2 | Wait 30-60 min for propagation, then re-run with `-ValidateOnly` |
| DLP policy fails to create | SIT must propagate first. Run Phase 2, wait, then re-run with `-SkipSIT` |
| Test emails fail to send | Phase 5 now outputs templates instead of sending. Copy-paste into OWA manually |
| Content Safety API 401 | Re-copy Key 1 from Azure portal → Content Safety → Keys and Endpoint |
| Content Safety API 404 | Check endpoint URL includes resource name; use API version `2024-09-01` |

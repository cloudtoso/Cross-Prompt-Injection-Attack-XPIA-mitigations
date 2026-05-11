# Cross/Indirect Prompt Injection Attack (XPIA) Mitigations

Author: Christian Williams

## Overview
This repository contains documentation, technical analysis, and presentation materials for detecting, validating, responding to, and preventing Cross/Indirect Prompt Injection Attacks (XPIA) in Microsoft Agent 365 and M365 Copilot environments.

## Contents

### Documentation
- **xpia-response-strategy.md** — Strategic framework for XPIA response: 7 customer concerns decomposed, 10 Microsoft capabilities mapped, 6 product gaps identified, and a 5-station demonstration plan
- **xpia-technical-analysis.md** — Deep technical analysis covering detection architecture, KQL queries, email pattern scenarios, insider risk analysis, recommended architecture, and a 6-step demo script
- **xpia-customer-document-outline.md** — Executive document outline with 7 sections, 5 customer scenarios, and regulatory mapping (OCC/FCA/SOX/NIST)

### Presentation
- **XPIA-Agent365-Security-Response.pptx** — 19-slide customer-facing presentation deck covering XPIA detection capabilities, gaps, workarounds, and recommended architecture

### Demo Playbook
- **xpia-demo-playbook.md** — Comprehensive 5-station demo playbook with step-by-step instructions for demonstrating XPIA detection, validation, and response capabilities. Covers: Station 1 (Prompt Shields), Station 2 (DLP Custom SIT), Station 3 (Exchange Mail Flow Rules), Station 4 (Copilot for Security KQL), Station 5 (Executive Briefing + Governance Maturity Model)
- **xpia-demo-playbook.docx** — Word version of the demo playbook for easy sharing and editing
- **xpia-demo-playbook.pdf** — PDF version of the demo playbook for distribution and printing

### Demo Automation
- **Invoke-XPIADemoSetup.ps1** — 8-phase PowerShell pre-demo automation script that automates tenant configuration for the demo: module installation, tenant connectivity, Content Safety API validation, custom SIT creation, Exchange mail flow rules, test email templates, DLP policy creation, and validation summary
- **xpia-demo-setup-README.md** — Companion guide for the setup script with prerequisites, usage instructions, and phase descriptions

## Key Topics
- XPIA detection with Azure AI Prompt Shields
- Microsoft Defender XDR integration and alerting
- Microsoft Purview DLP custom Sensitive Information Types (SIT) for XPIA patterns
- Exchange mail flow rules for pre-delivery XPIA detection
- Correlation queries joining DLP + XDR alerts for campaign attribution
- Insider risk scenarios and document-based XPIA vectors
- EchoLeak (CVE-2025-32711) implications
- Product gap analysis and Microsoft roadmap recommendations
- Demo pre-staging automation via PowerShell

## Architecture
The recommended detection architecture uses a layered approach:
1. **Pre-Delivery** — Exchange mail flow rules with XPIA pattern matching
2. **Content Analysis** — DLP policies with custom SITs for XPIA regex patterns
3. **Runtime Protection** — Azure AI Prompt Shields evaluating content at Agent 365 query time
4. **Post-Incident Correlation** — KQL queries joining Purview DLP matches with Defender XDR alerts

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
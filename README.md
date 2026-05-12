# Cross/Indirect Prompt Injection Attack (XPIA) Mitigations

**Author:** Christian Williams  
**License:** MIT  
**Status:** Active — evolving with the threat landscape

---

## What Is XPIA?

A **Cross/Indirect Prompt Injection Attack (XPIA)** exploits AI agents by embedding malicious instructions in external data sources — emails, documents, web content, or messages from other agents — that the AI processes as trusted input. Unlike traditional prompt injection where a user directly manipulates a chatbot, XPIA attacks are *indirect*: the attacker never interacts with the AI system directly. Instead, they plant payloads in content the AI will eventually consume.

**Why this matters in enterprise environments:**

- Traditional security tools (XDR, SIEM, email gateways) don't see XPIA because from the network layer, it looks like normal email and document traffic
- AI agents in regulated industries touch sensitive processes — payroll, lending decisions, AML screening, customer onboarding — where a successful injection can trigger compliance violations or unauthorized transactions
- Unlike phishing, XPIA attacks contain no malicious URLs or attachments, so they bypass conventional threat detection entirely
- Multi-agent architectures amplify the risk: an injection that compromises one agent can propagate through agent-to-agent communication ("instruction laundering")

For organizations deploying Microsoft Agent 365 or M365 Copilot, XPIA represents a governance challenge that requires detection, response, and audit capabilities *at the agent layer* — not just at the network perimeter.

---

## Why This Repository Exists

Organizations adopting Agent 365 and M365 Copilot need answers to hard questions:

- **How does XPIA detection actually work?** Not marketing claims — the real architecture.
- **Can we verify it's effective?** What can we test, and what are the honest limitations?
- **What happens when 50 users receive XPIA emails from the same domain?** Can we detect the campaign?
- **How do we attribute blocked attacks to threat actors?** Detection without attribution isn't enough for FSI compliance.
- **What about insider threats using XPIA?** A trusted employee embedding injection payloads in documents they upload.

This repository provides the **complete toolkit** for answering those questions:

- A strategic response framework that maps customer concerns to Microsoft capabilities and honest gap disclosure
- Deep technical analysis with KQL queries, regex patterns, and detection architecture
- An executive document outline tailored for C-level governance conversations
- A 19-slide customer-facing presentation deck
- A comprehensive 5-station demo playbook with step-by-step instructions
- PowerShell automation to pre-stage an entire demo environment

Everything here follows a **transparency-first** approach: we lead with what works, acknowledge what doesn't, and provide actionable workarounds for current gaps.

---

## Who Is This For?

| Audience | Start Here | Why |
|----------|-----------|-----|
| **Security Architects** | [`xpia-response-strategy.md`](xpia-response-strategy.md) | Maps 7 customer concerns to 10 Microsoft capabilities with gap analysis |
| **SOC Analysts** | [`xpia-technical-analysis.md`](xpia-technical-analysis.md) | KQL queries, detection patterns, correlation logic, and email scenario analysis |
| **Compliance / Risk Officers** | [`xpia-customer-document-outline.md`](xpia-customer-document-outline.md) | Regulatory mapping (OCC, FCA, SOX 404, NIST AI RMF), governance maturity model |
| **Microsoft Partners** | [`xpia-demo-playbook.md`](xpia-demo-playbook.md) | Full 5-station demo with setup, execution, and narrative guidance |
| **Presales Engineers** | [`Invoke-XPIADemoSetup.ps1`](Invoke-XPIADemoSetup.ps1) + [`xpia-demo-setup-README.md`](xpia-demo-setup-README.md) | Automated tenant configuration for live demos |
| **Executives / CISOs** | [`XPIA-Agent365-Security-Response.pptx`](XPIA-Agent365-Security-Response.pptx) | 19-slide deck: detection capabilities, gaps, architecture, roadmap |

---

## Architecture: Defense-in-Depth

The recommended detection architecture uses four complementary layers. No single layer is sufficient — each catches what the others miss.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     XPIA DEFENSE-IN-DEPTH                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Layer 1: PRE-DELIVERY                                        │  │
│  │  Exchange mail flow rules with XPIA regex pattern matching    │  │
│  │  ► Intercepts known injection patterns before mailbox delivery│  │
│  │  ► Quarantines or flags suspicious content for SOC review     │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Layer 2: CONTENT ANALYSIS                                    │  │
│  │  Purview DLP with custom Sensitive Information Types (SIT)    │  │
│  │  ► Regex-based detection of XPIA payload families             │  │
│  │  ► High-confidence and medium-confidence rule tiers           │  │
│  │  ► Policy-driven actions: block, notify, audit                │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Layer 3: RUNTIME PROTECTION                                  │  │
│  │  Azure AI Prompt Shields at Agent 365 query time              │  │
│  │  ► Evaluates user prompt vs. grounding documents separately   │  │
│  │  ► Detects instruction-override, privilege escalation,        │  │
│  │    semantic divergence from expected input                    │  │
│  │  ► Blocks or flags before LLM processes the injection         │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Layer 4: POST-INCIDENT CORRELATION                           │  │
│  │  KQL queries joining Purview DLP + Defender XDR alerts        │  │
│  │  ► Campaign detection across multiple recipients/timeframes   │  │
│  │  ► Payload family clustering for attribution analysis         │  │
│  │  ► Retrospective investigation of blocked and missed attacks  │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Key design principle:** Layers 1–2 are deterministic (pattern-matching); Layer 3 is probabilistic (AI classification); Layer 4 is investigative (human-driven correlation). The combination provides both automated blocking and forensic depth.

---

## Key Capabilities Demonstrated

The demo playbook proves these capabilities in a live tenant environment:

| Station | Capability | What It Proves |
|---------|-----------|---------------|
| **1 — Prompt Shields** | Azure AI Content Safety runtime detection | XPIA payloads are detected and blocked at the agent gateway before the LLM processes them |
| **2 — DLP Custom SIT** | Purview DLP with XPIA-specific regex patterns | Known injection pattern families are caught at the content layer with configurable confidence tiers |
| **3 — Mail Flow Rules** | Exchange transport rule pre-delivery interception | XPIA payloads in email bodies are quarantined before reaching the recipient's mailbox |
| **4 — KQL Correlation** | Copilot for Security + Advanced Hunting queries | DLP alerts and Defender XDR signals are correlated to identify coordinated attack campaigns |
| **5 — Executive Briefing** | Governance maturity assessment + gap disclosure | Transparent discussion of current capabilities, known gaps, and the roadmap — positioned for C-level trust |

---

## Getting Started

**If you're a security architect** evaluating XPIA risk:
1. Read [`xpia-response-strategy.md`](xpia-response-strategy.md) — the strategic framework mapping 7 customer concerns to Microsoft capabilities
2. Review the gap analysis (GAP-01 through GAP-07) and the workarounds available today
3. Use the defense-in-depth architecture above to plan your detection layers

**If you're preparing a demo** for a customer engagement:
1. Read [`xpia-demo-playbook.md`](xpia-demo-playbook.md) — the full 5-station demo with step-by-step instructions
2. Run [`Invoke-XPIADemoSetup.ps1`](Invoke-XPIADemoSetup.ps1) the evening before (see [Prerequisites](#prerequisites) below)
3. Run the script again with `-ValidateOnly` the morning of the demo
4. Review [`xpia-demo-setup-README.md`](xpia-demo-setup-README.md) for parameter details and troubleshooting

**If you need the executive summary** for a C-level conversation:
1. Start with [`xpia-customer-document-outline.md`](xpia-customer-document-outline.md) — 7-section executive outline with speaker notes
2. Use [`XPIA-Agent365-Security-Response.pptx`](XPIA-Agent365-Security-Response.pptx) as the presentation deck
3. Review the governance maturity model (Levels 1–4) to frame the customer's current state and target state

---

## Prerequisites

To run the demo playbook and automation script, you need:

### Licensing
- Microsoft 365 **E5** or **E5 Security** (required for Purview DLP, Defender XDR, Communication Compliance)
- **Azure AI Content Safety** resource provisioned in your Azure subscription (for Prompt Shields API)
- Microsoft 365 E7 licensing provides additional Agent 365 governance capabilities

### Admin Roles
- **Exchange Online Administrator** — for mail flow rule creation
- **Compliance Administrator** — for DLP policy and custom SIT creation
- **Security Administrator** — for Defender XDR Advanced Hunting access
- **Azure AI Content Safety** contributor role — for Prompt Shields API testing

### Environment
- PowerShell 5.1+ (or PowerShell 7)
- `ExchangeOnlineManagement` module installed
- Test mailboxes (at least 2) for sending/receiving XPIA test payloads
- An external sender account (e.g., Outlook.com) for simulating external threat actors

### Timing
- Run the setup script **the evening before** the demo — SIT propagation takes 30–60 minutes, DLP policy activation takes 1–4 hours
- Run `-ValidateOnly` the **morning of** the demo
- Send final test email **15 minutes before** the customer session

---

## Repository Contents

### Documentation
| File | Size | Description |
|------|------|-------------|
| [`xpia-response-strategy.md`](xpia-response-strategy.md) | 32 KB | Strategic framework: 7 customer concerns decomposed, 10 Microsoft capabilities mapped, 6 product gaps identified, 5-station demo plan |
| [`xpia-technical-analysis.md`](xpia-technical-analysis.md) | 48 KB | Deep technical analysis: detection architecture, KQL queries, email pattern scenarios, insider risk analysis, 6-step demo script |
| [`xpia-customer-document-outline.md`](xpia-customer-document-outline.md) | 19 KB | Executive document outline: 7 sections, 5 customer scenarios, regulatory mapping (OCC/FCA/SOX/NIST), speaker notes |

### Presentation
| File | Description |
|------|-------------|
| [`XPIA-Agent365-Security-Response.pptx`](XPIA-Agent365-Security-Response.pptx) | 19-slide customer-facing deck: XPIA detection capabilities, gap disclosure, defense-in-depth architecture, governance roadmap |

### Demo Playbook
| File | Description |
|------|-------------|
| [`xpia-demo-playbook.md`](xpia-demo-playbook.md) | Comprehensive 5-station demo playbook — Station 1 (Prompt Shields), Station 2 (DLP Custom SIT), Station 3 (Exchange Mail Flow), Station 4 (KQL Correlation), Station 5 (Executive Briefing + Governance Maturity) |
| [`xpia-demo-playbook.docx`](xpia-demo-playbook.docx) | Word version for sharing and editing |
| [`xpia-demo-playbook.pdf`](xpia-demo-playbook.pdf) | PDF version for distribution |

### Demo Automation
| File | Description |
|------|-------------|
| [`Invoke-XPIADemoSetup.ps1`](Invoke-XPIADemoSetup.ps1) | 8-phase PowerShell script: module checks, custom SIT deployment, mail flow rules, DLP policy creation, test email templates, KQL output, Content Safety API validation, environment readiness check |
| [`xpia-demo-setup-README.md`](xpia-demo-setup-README.md) | Companion guide: prerequisites, parameters, timing notes, troubleshooting |

---

## Known Gaps & Transparency

This repository follows a **transparency-first** approach. XPIA is an evolving threat space, and no vendor has complete coverage today. Here is what we acknowledge:

### Current Gaps

| Gap | Description | Available Workaround |
|-----|-------------|---------------------|
| **Campaign correlation** | No native engine to detect "50 users received XPIA emails from the same domain" | Custom KQL queries against EmailEvents + Purview DLP alerts |
| **Threat actor attribution** | Blocked XPIA attacks don't automatically trace back to the sender/actor | KQL-based payload clustering by family, timing, and delivery vector |
| **Pre-consumption content scanning** | Emails/documents aren't scanned for XPIA patterns before the AI agent processes them | Exchange mail flow rules + DLP custom SITs provide partial pre-delivery coverage |
| **Insider risk + XPIA correlation** | Purview IRM doesn't natively flag XPIA payloads in insider-uploaded documents | Communication Compliance keyword policies + manual investigation |
| **DSPM for AI integration** | Unified DSPM experience for AI data governance is still rolling out | Monitor compliance.microsoft.com for enablement; 24–48 hour activation |
| **Quantitative detection reporting** | No native XPIA detection rate dashboard or confidence scoring | Test with seeded payloads; measure detection across known pattern variants |

### Why This Matters

The disclosure of **EchoLeak (CVE-2025-32711)** — a cross-plugin data exfiltration vulnerability in AI agent ecosystems — underscores why continuous improvement in this space is essential. EchoLeak validated the exact concern class that this repository addresses: that AI agents processing external content can be manipulated to leak sensitive data across trust boundaries.

The workarounds documented here (custom KQL, DLP SITs, mail flow rules) are achievable within existing Microsoft 365 licensing and represent the current best-practice defense while native capabilities mature.

---

## Related Resources

### Microsoft Documentation
- [Azure AI Content Safety — Prompt Shields](https://learn.microsoft.com/azure/ai-services/content-safety/concepts/jailbreak-detection) — runtime XPIA detection architecture
- [Microsoft Purview DLP — Custom Sensitive Information Types](https://learn.microsoft.com/purview/create-a-custom-sensitive-information-type) — creating regex-based SITs for XPIA patterns
- [Exchange Online Mail Flow Rules](https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules) — transport rules for pre-delivery content inspection
- [Microsoft Defender XDR — Advanced Hunting](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview) — KQL queries for cross-product correlation
- [Microsoft Copilot for Security](https://learn.microsoft.com/security-copilot/microsoft-security-copilot) — AI-assisted security investigation
- [Microsoft Purview Insider Risk Management](https://learn.microsoft.com/purview/insider-risk-management) — insider threat detection and investigation

### Research & Context
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — LLM01: Prompt Injection
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/risk-management-framework) — governance framework for AI systems
- [CVE-2025-32711 (EchoLeak)](https://msrc.microsoft.com/update-guide/) — cross-plugin data exfiltration via prompt injection

---

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
- Governance maturity model for XPIA readiness (Levels 1–4)
- Regulatory mapping: OCC, FCA, SOX 404, NIST AI RMF

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

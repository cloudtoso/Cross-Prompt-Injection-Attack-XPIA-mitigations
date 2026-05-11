# XPIA Response Strategy Framework
## Cross/Indirect Prompt Injection Attack — FSI Customer Engagement

**Prepared by:** Keaton (Lead/Strategist) — Agent 365 POV Team
**Date:** 2026-05-11
**Classification:** Microsoft Confidential — Customer Engagement
**Customer Vertical:** Financial Services (FSI)

---

## Executive Summary

This document provides a structured response framework for an FSI customer's critical concerns about Cross/Indirect Prompt Injection Attacks (XPIA) in the context of Agent 365 and the broader Microsoft security ecosystem. The customer has identified legitimate gaps in visibility, attribution, and investigation capabilities that require honest acknowledgment paired with a concrete roadmap of what's available today, what's coming, and where product feedback is needed.

**Strategic Posture:** Lead with transparency. This customer is sophisticated enough to detect when we're hand-waving. Acknowledge the real gaps, demonstrate what works today, and position Microsoft as the vendor actively investing in closing these gaps — which we are.

---

## 1. Customer Concern Decomposition

### Concern Matrix

| ID | Concern | Customer Quote (Paraphrased) | Severity | Addressability |
|----|---------|------------------------------|----------|----------------|
| C-1 | **XPIA Detection Transparency** | "How XPIA detection is functioning" | High | Addressable today with documentation walkthrough |
| C-2 | **Verification of Effectiveness** | "How we can verify its effectiveness" | Critical | Partially addressable — requires demo + telemetry access |
| C-3 | **Source Material Pattern Alerting** | "Controls or alerting mechanisms to detect source material patterns that may introduce prompt risks into emails or documents" | Critical | Gap — requires multi-product integration |
| C-4 | **Cross-Firm Email Pattern Detection** | "50 users receive emails with XPIA technique... same root domain... need to identify that behavior" | Critical | Gap — not natively supported as described |
| C-5 | **Insider Risk XPIA Detection** | "Insider risk... sharing documents with XPIA... code of conduct investigation" | High | Partially addressable via Purview IRM (emerging) |
| C-6 | **Purview DSPM Integration** | "Should be integrated into Purview DSPM" | High | On roadmap — unified DSPM experience rolling out |
| C-7 | **Threat Actor Attribution** | "Unable to identify the threat actor even if they were unsuccessful" | Critical | Gap — biggest delta between detection and investigation |

### Concern Detail Breakdown

#### C-1: XPIA Detection Mechanism Transparency
**What the customer wants:** Documentation and discussion on how Agent 365 detects and blocks XPIA in real-time.

**What we can provide:**
- Microsoft Prompt Shields architecture walkthrough (prevention + detection layers)
- Defense-in-depth model documentation:
  - **Spotlighting** — delimiting, data marking, and encoding techniques that isolate untrusted content
  - **Hardened system prompts** — resist override by injected instructions
  - **Probabilistic AI classifiers** — real-time scanning of incoming content for injection patterns
  - **Deterministic blocking** — blocks known exfiltration techniques (malicious markdown/image tags, unauthorized external links)
- Human-in-the-loop confirmation for sensitive actions
- Short-lived, just-in-time privilege model for agent actions

#### C-2: Verification of Detection Effectiveness
**What the customer wants:** Ability to test and confirm that XPIA defenses are actually working — not just trust that they are.

**What we can provide today:**
- Audit logging of all Copilot/Agent prompts and responses
- Telemetry and anomaly detection for unusual query patterns
- Red team / purple team exercise frameworks (Microsoft publishes guidance)
- Content Safety API testing for custom validation

**What requires further development:**
- Quantitative detection rate reporting (industry research indicates ~23% detection rate for sophisticated attacks — customer needs transparency on this)
- Structured "XPIA health check" or confidence dashboard
- Automated regression testing of prompt shields against evolving attack patterns

#### C-3: Source Material Pattern Alerting
**What the customer wants:** Automated alerting when emails or documents across the firm contain patterns consistent with prompt injection techniques.

**Current state:** This is a **genuine integration gap**. Today:
- Prompt Shields evaluate content at the point of AI consumption (when Agent 365 processes it)
- There is no pre-consumption scanning of email/document bodies specifically for XPIA patterns
- Exchange Online Protection (EOP) and Defender for Office 365 focus on phishing URLs, malware, and impersonation — not embedded prompt injection text

**What's possible with configuration:**
- Custom mail flow rules (Exchange Transport Rules) with regex pattern matching for known XPIA signatures
- Microsoft Sentinel custom analytics rules to detect XPIA-patterned content in email telemetry
- Communication Compliance policies for keyword/pattern matching in email content

#### C-4: Cross-Firm Email Pattern Detection (The 50-User Scenario)
**What the customer wants:** If 50 users receive emails from the same sender/domain containing XPIA techniques (no malicious URLs, so not flagged as phishing), detect and correlate that campaign.

**This is the customer's strongest concern and our biggest gap.**

**Current state:**
- Defender for Office 365 **does not** have an XPIA-specific detection category
- Emails without traditional phishing indicators (URLs, attachments) pass through
- There is no native correlation engine that says "50 users got content with similar embedded prompt injection from domain X"

**What can be built today:**
- **Microsoft Sentinel + Advanced Hunting (KQL):**
  - Ingest email metadata and body content via the EmailEvents and EmailUrlInfo tables
  - Build custom detection rules that:
    - Flag emails from the same sender/domain to N+ recipients within a time window
    - Pattern-match body content against known XPIA techniques (regex-based)
    - Correlate with Copilot/Agent audit logs to see if any recipients' agents processed the content
  - Create automated investigation playbooks triggered by these detections
- **Defender for Office 365 Advanced Hunting:**
  - Custom detection queries across EmailEvents, EmailAttachmentInfo
  - Not real-time but enables retrospective investigation

**What requires product investment:**
- Native XPIA content classification in Defender for Office 365
- Automated campaign detection for non-URL-based email threats
- Integration between Prompt Shield detection events and email source attribution

#### C-5: Insider Risk XPIA Detection
**What the customer wants:** Detect when an insider shares documents containing XPIA techniques internally, warranting a code-of-conduct investigation.

**Current state:**
- Purview Insider Risk Management (IRM) monitors data movement patterns but does not natively classify document content as "containing XPIA"
- IRM's new network-based detection (rolling out July 2025+) will monitor sensitive files shared to cloud apps and GenAI platforms
- AI prompt and output governance capabilities can classify and monitor sensitive content in AI interactions

**What can be configured today:**
- IRM policies for anomalous document sharing patterns (volume, recipients, timing)
- Sensitivity labels + DLP policies that flag documents with specific content patterns
- Communication Compliance for internal message/document content review with keyword triggers
- Custom classifiers trained on XPIA pattern examples

**What's coming (2025-2026 roadmap):**
- XPIA recognized as a new insider threat risk class in Microsoft advisories
- Enhanced network indicators in IRM for risky AI usage
- Automated workflows triggering security controls when XPIA patterns detected

#### C-6: Purview DSPM Integration
**What the customer wants:** XPIA detection and investigation integrated into Purview DSPM for AI — single pane of glass.

**Current state:**
- Purview DSPM for AI provides: granular AI activity analytics, DLP for AI prompts, agent observability/inventory, automated risk assessments, inline real-time controls
- The unified DSPM experience is rolling out through early 2026 with enhanced AI observability
- DSPM does **not** currently surface XPIA-specific alerts or source material scanning results

**What's available now in DSPM for AI:**
- Track prompts and outputs across Copilot and third-party AI agents
- DLP policies enforced directly inside user AI prompts
- Risk levels maintained per AI agent (Copilot Studio, Azure AI Foundry agents)
- Weekly automated risk assessments with bulk remediation
- Triage and Posture AI agents for automated alert handling

**What requires product development:**
- XPIA-specific risk signals surfaced in the DSPM dashboard
- Email/document pre-consumption XPIA scanning results flowing into DSPM
- Threat actor attribution data linked to DSPM AI activity records

#### C-7: Threat Actor Attribution
**What the customer wants:** Even when RAI and XDR successfully block an XPIA attempt, identify WHO attempted it — the sender, the domain, the pattern.

**This is the "so what" concern — and it's valid.**

**Current state:**
- Prompt Shields block the attack but telemetry about the blocked event is limited
- XDR sees the block as a "non-event" — no incident is created for a successfully defended prompt
- There is no automated path from "Prompt Shield blocked injection from email content" back to "that email came from sender X at domain Y"

**What can be built today:**
- **Custom correlation pipeline:**
  1. Agent 365 / Copilot audit logs → capture blocked prompt events with content metadata
  2. Sentinel ingestion → correlate timestamp + user + content hash with email delivery logs
  3. Advanced Hunting → identify source email, sender, domain
  4. Alert rule → trigger investigation workflow
- This requires custom KQL development and is not out-of-the-box

**What requires product investment:**
- Automated attribution chain: Prompt Shield block → content source → sender identity
- "Blocked XPIA Attempt" as a first-class incident type in Defender XDR
- Campaign view linking multiple blocked attempts to a common threat actor

---

## 2. Microsoft Security Stack Mapping

### Capability-to-Concern Matrix

| Microsoft Capability | C-1 | C-2 | C-3 | C-4 | C-5 | C-6 | C-7 |
|---------------------|-----|-----|-----|-----|-----|-----|-----|
| **Agent 365 Prompt Shields** | ✅ Primary | ✅ Demo | ⚠️ Partial | ❌ | ❌ | ⚠️ Feed | ⚠️ Source |
| **Azure AI Content Safety API** | ✅ | ✅ Testable | ⚠️ Custom | ❌ | ❌ | ❌ | ❌ |
| **Defender XDR** | ⚠️ Limited | ⚠️ Custom | ⚠️ Custom | ⚠️ Custom KQL | ❌ | ❌ | ⚠️ Custom |
| **Defender for Office 365** | ❌ | ❌ | ⚠️ Transport Rules | ✅ Advanced Hunting | ❌ | ❌ | ✅ Sender Data |
| **Microsoft Sentinel** | ❌ | ⚠️ Custom | ✅ Custom Rules | ✅ Custom Rules | ⚠️ Custom | ❌ | ✅ Custom |
| **Purview DSPM for AI** | ⚠️ Dashboard | ⚠️ Analytics | ❌ | ❌ | ⚠️ Emerging | ✅ Primary | ❌ |
| **Purview IRM** | ❌ | ❌ | ❌ | ❌ | ✅ Primary | ⚠️ Feed | ❌ |
| **Purview Communication Compliance** | ❌ | ❌ | ✅ Pattern Match | ⚠️ Partial | ✅ Investigation | ⚠️ Feed | ⚠️ Partial |
| **Purview DLP** | ❌ | ❌ | ⚠️ Content Rules | ❌ | ⚠️ Labels | ⚠️ Feed | ❌ |
| **Copilot for Security** | ✅ Explain | ✅ Investigate | ⚠️ Hunting | ✅ Hunting | ⚠️ Triage | ⚠️ Triage | ✅ Investigation |

**Legend:** ✅ = Directly addresses | ⚠️ = Partially addresses / requires configuration | ❌ = Does not address

### Detailed Stack Mapping

#### 2.1 Agent 365 Built-in XPIA Protections
- **Prompt Shields:** Real-time AI classifier scanning all incoming content for injection patterns (multi-language)
- **Spotlighting:** Three-mode content isolation (delimiting, data marking, encoding)
- **Deterministic Blocking:** Hardcoded blocks on known exfiltration patterns
- **System Prompt Hardening:** Resist override by injected instructions
- **Human-in-the-Loop:** User confirmation required for sensitive/risky actions
- **Just-in-Time Privileges:** Minimum permissions, provisioned and revoked per action
- **Rule of Two:** Agents should never simultaneously process untrusted input + access sensitive systems + perform external state changes

#### 2.2 Microsoft Defender XDR — Current XPIA Reporting
**Honest assessment:** Defender XDR does **not** provide named, purpose-built alerts for XPIA.
- Can detect consequences of successful injection (unusual automation, privilege escalation, data exfiltration)
- Cannot detect the injection attempt itself as a classified threat
- Custom detection rules via KQL can flag behavioral indicators
- Integration with Sentinel extends correlation capabilities

**Customer's observation is correct:** "The reporting we see in XDR is minimal" — because XPIA is not yet a first-class detection category in XDR.

#### 2.3 Azure AI Content Safety / RAI Prompt Shields
- Standalone API for pre-consumption content scanning
- Supports both direct and indirect prompt injection detection
- Returns risk scores and category flags
- Can be integrated into custom workflows for email/document preprocessing
- Enterprise-grade logging and compliance support
- **Key differentiator for this customer:** Can be used to build the "source material scanning" capability they're requesting

#### 2.4 Purview DSPM for AI — Current State
- **Available now:** AI activity analytics, DLP for AI prompts, agent inventory, automated risk assessments, inline controls, Triage + Posture AI agents
- **Rolling out (early-mid 2026):** Unified DSPM experience, deeper risk reporting, expanded third-party AI integrations, posture playbooks
- **Not yet available:** XPIA-specific risk signals, pre-consumption scanning results, threat actor attribution

#### 2.5 Purview Insider Risk Management
- **Available now:** Behavioral analytics, anomalous sharing detection, policy-based triggers, pseudonymized investigation
- **Rolling out (July 2025+):** Network-based detection of sensitive data sharing to GenAI platforms
- **Emerging:** XPIA classified as insider threat risk class, AI-related policy templates
- **Configuration needed:** Custom policies for XPIA document sharing patterns

#### 2.6 Purview Communication Compliance
- **Available now:** Keyword and regex pattern matching across email and message content
- Can be configured with XPIA-pattern dictionaries
- Supports investigation workflows and code-of-conduct case management
- **Best current fit** for the insider risk document-sharing scenario (C-5)

#### 2.7 Copilot for Security
- Natural language investigation across the security stack
- Advanced Hunting acceleration (write KQL from natural language)
- Incident summarization and correlation
- **Key value:** Enables the customer's SOC to investigate XPIA-related signals without deep KQL expertise

---

## 3. Gap Analysis

### 3.1 What CAN Be Done Today ✅

| # | Capability | How |
|---|-----------|-----|
| 1 | Explain XPIA detection mechanisms | Documentation walkthrough + architecture session |
| 2 | Demonstrate Prompt Shield blocking | Live demo with test injection payloads |
| 3 | Show Agent 365 audit logging | Admin center → Copilot audit logs |
| 4 | Test Content Safety API for XPIA | Azure AI Content Safety playground + API calls |
| 5 | Configure Communication Compliance for XPIA keywords | Purview → Communication Compliance → custom policy with XPIA regex patterns |
| 6 | Build Sentinel custom detection for email campaigns | KQL queries against EmailEvents correlating sender/domain/recipient count/content patterns |
| 7 | Configure IRM for anomalous document sharing | Purview → IRM → data theft/leaks policy template |
| 8 | Use Copilot for Security for XPIA investigation | Natural language hunting across Defender + Sentinel data |
| 9 | Deploy DLP policies for AI prompts | Purview → DLP → AI app policies |
| 10 | Access DSPM for AI dashboards | Purview → DSPM → AI activity overview |

### 3.2 What Requires Configuration/Enablement ⚠️

| # | Capability | Effort | Prerequisites |
|---|-----------|--------|---------------|
| 1 | Custom Sentinel analytics rules for XPIA email detection | Medium (2-3 days KQL development) | Sentinel workspace, email log ingestion |
| 2 | Communication Compliance XPIA dictionary | Low (1 day policy setup) | Purview E5 licensing, XPIA pattern library |
| 3 | Custom detection rules in Defender XDR | Medium (2-3 days) | Advanced Hunting enabled, custom detections |
| 4 | IRM network indicators for AI-related sharing | Low (configuration toggle) | IRM E5, network partner integration |
| 5 | Content Safety API integration for pre-scan workflow | High (custom development) | Azure AI Services subscription, Logic Apps / Power Automate |
| 6 | End-to-end attribution pipeline (Prompt Shield → Email source) | High (custom KQL + Logic Apps) | Sentinel, Copilot audit logs, email logs unified |

### 3.3 What Is on the Roadmap (Not Yet Available) 🔜

| # | Capability | Expected Timing | Source |
|---|-----------|-----------------|--------|
| 1 | Unified DSPM experience with enhanced AI observability | Early-mid 2026 GA | Microsoft 365 Roadmap |
| 2 | IRM network-based detection for GenAI data sharing | Rolling out July 2025+ | MC1102773 |
| 3 | XPIA as classified insider threat risk category | 2025-2026 | Microsoft Security advisories |
| 4 | Expanded third-party AI model coverage in DSPM | Mid 2026 | Microsoft 365 Roadmap |
| 5 | Posture playbooks for AI incident response | Early 2026 | Microsoft Purview roadmap |
| 6 | Enhanced Prompt Shield detection models (improved detection rates) | Continuous | Microsoft Research (LLMail-Inject, TaskTracker) |

### 3.4 Genuine Gaps Requiring Product Feedback 🔴

| # | Gap | Customer Impact | Recommended Action |
|---|-----|----------------|-------------------|
| 1 | **No XPIA content classification in Defender for Office 365** | Emails with embedded prompt injection pass undetected if they lack traditional phishing indicators | Product feedback: XPIA as a detection category in Safe Links/Safe Attachments threat pipeline |
| 2 | **No automated campaign detection for non-URL email threats** | Customer cannot correlate 50 users receiving same XPIA payload from same sender without custom KQL | Product feedback: Campaign view for content-pattern-based threats (not just URL/attachment) |
| 3 | **Prompt Shield blocks are not first-class XDR incidents** | Successfully blocked XPIA attempts don't generate incidents — no threat actor attribution | Product feedback: "Blocked XPIA Attempt" incident type with source attribution in Defender XDR |
| 4 | **No pre-consumption XPIA scanning of email/document bodies** | Content is only evaluated when AI processes it, not when it arrives in the environment | Product feedback: Integration of Content Safety XPIA scanning into mail flow and document ingestion |
| 5 | **DSPM does not surface XPIA-specific risk signals** | CISO cannot see "these are the XPIA attempts across your org this week" in one dashboard | Product feedback: XPIA risk category in DSPM for AI analytics |
| 6 | **Attribution chain is broken** | Even when Prompt Shields work perfectly, there's no automated path back to the threat actor | Product feedback: End-to-end attribution from AI defense event → content source → sender identity |

---

## 4. Demonstration Plan

### Demo Flow: "Detect, Validate, Respond, Prevent"

**Target Duration:** 90 minutes
**Audience:** CISO, Security Architecture, SOC Leadership

---

#### Station 1: DETECT — XPIA Protection in Action (20 min)

**Objective:** Show that Agent 365 actively detects and blocks XPIA attempts.

| Step | Action | What Customer Sees |
|------|--------|--------------------|
| 1.1 | Prepare test email with embedded XPIA payload (no URLs, no attachments — mirrors customer scenario) | Realistic attack simulation |
| 1.2 | User opens email in Outlook, then asks Copilot/Agent to summarize or act on it | Agent processes the email content |
| 1.3 | Prompt Shield intercepts the injection attempt | Agent refuses the injected instruction, returns safe response |
| 1.4 | Show Copilot audit log entry for the blocked event | Timestamp, user, content hash, block reason |
| 1.5 | Show Azure AI Content Safety API analysis of the same payload | Risk score, injection category classification |

**Key Message:** "The defense works. Now let's show you how to see it working."

#### Station 2: VALIDATE — Proving Effectiveness (20 min)

**Objective:** Demonstrate how the customer can independently verify XPIA defenses.

| Step | Action | What Customer Sees |
|------|--------|--------------------|
| 2.1 | Walk through Prompt Shield architecture (spotlighting, classifiers, deterministic blocks) | Technical transparency |
| 2.2 | Run multiple XPIA variants through Content Safety API | Detection rates across attack types |
| 2.3 | Show DSPM for AI dashboard — AI activity analytics | Prompt/response monitoring, risk levels per agent |
| 2.4 | Show DLP policy firing on a sensitive AI prompt | Real-time inline protection |
| 2.5 | Discuss red team framework and purple team exercise recommendations | Customer can run their own validation |

**Key Message:** "You don't have to trust us — you can test it yourself."

#### Station 3: RESPOND — Investigation and Attribution (25 min)

**Objective:** Show the investigation workflow for XPIA incidents, including the custom attribution pipeline.

| Step | Action | What Customer Sees |
|------|--------|--------------------|
| 3.1 | **Sentinel custom rule demo:** KQL query that detects emails from same domain to 50+ recipients with body content matching XPIA patterns | Campaign detection for their specific scenario |
| 3.2 | Alert triggers → automated investigation playbook | Sender identification, recipient list, content analysis |
| 3.3 | Copilot for Security investigation | Natural language: "Show me all emails from domain X in the last 7 days and correlate with any Copilot prompt shield blocks" |
| 3.4 | Defender Advanced Hunting | Cross-reference email source with Copilot audit events |
| 3.5 | Show the attribution chain: blocked prompt → email content → sender → domain | End-to-end threat actor identification |

**Key Message:** "With some custom work, we can close the attribution gap today. We're also pushing for this to be native."

**Pre-built KQL Example for Station 3.1:**
```kql
// Detect potential XPIA email campaigns: same sender domain, 
// multiple recipients, body content matching injection patterns
let xpia_patterns = dynamic([
    "ignore previous instructions",
    "ignore all prior instructions", 
    "disregard your instructions",
    "you are now",
    "new instructions:",
    "override system prompt",
    "forget everything above",
    "act as if",
    "respond only with",
    "do not follow your original"
]);
let time_window = 24h;
let recipient_threshold = 10;
EmailEvents
| where Timestamp > ago(time_window)
| where DeliveryAction == "Delivered"
| extend SenderDomain = tostring(split(SenderFromAddress, "@")[1])
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(time_window)
    | summarize RecipientCount = dcount(RecipientEmailAddress) by SenderDomain = tostring(split(SenderFromAddress, "@")[1])
    | where RecipientCount >= recipient_threshold
) on SenderDomain
| project Timestamp, SenderFromAddress, SenderDomain, RecipientEmailAddress, Subject, RecipientCount
| order by RecipientCount desc, Timestamp asc
```

#### Station 4: PREVENT — Policy Configuration for Ongoing Protection (15 min)

**Objective:** Configure real policies the customer can activate immediately.

| Step | Action | What Customer Sees |
|------|--------|--------------------|
| 4.1 | Communication Compliance policy with XPIA keyword dictionary | Content monitoring across email and documents |
| 4.2 | IRM policy for anomalous document sharing patterns | Insider risk detection for XPIA document distribution |
| 4.3 | DLP policy for AI prompts containing sensitive data | Prevents data leakage even if injection succeeds |
| 4.4 | Sentinel automation rule for XPIA campaign detection | Continuous monitoring with automated alerting |
| 4.5 | DSPM for AI configuration — agent inventory and risk levels | Ongoing posture management |

**Key Message:** "These policies go live today. You walk out of this session with active protection."

#### Station 5: ROADMAP — What's Coming (10 min)

**Objective:** Show the customer that Microsoft is actively investing in closing the gaps they've identified.

| Topic | Timeline | Impact |
|-------|----------|--------|
| Unified DSPM with XPIA signals | H1 2026 | Single-pane XPIA visibility |
| IRM network detection for GenAI | Rolling out now | Insider XPIA detection at network layer |
| Enhanced Prompt Shield models | Continuous | Improved detection rates |
| Product feedback items submitted | Ongoing | Their voice directly influencing product roadmap |

---

## 5. Recommended Next Steps

### Immediate Actions (This Week)

| # | Action | Owner | Timeline |
|---|--------|-------|----------|
| 1 | Schedule 90-minute demo session using the flow above | Account Team | Within 5 business days |
| 2 | Prepare XPIA test payloads for demo (non-URL, email-based, document-based) | Microsoft Security SA | Pre-demo |
| 3 | Pre-build the Sentinel KQL queries for email campaign detection | Microsoft Security SA | Pre-demo |
| 4 | Pre-configure Communication Compliance XPIA policy in demo tenant | Microsoft Security SA | Pre-demo |
| 5 | Share this document (sanitized version) with customer as "discussion framework" | Account Team | With demo invite |

### Customer Should Enable Now

| # | Action | Impact | License Required |
|---|--------|--------|-----------------|
| 1 | Enable Copilot/Agent audit logging (if not already) | Visibility into all AI interactions | M365 E5 |
| 2 | Activate Purview DSPM for AI | AI activity analytics and risk posture | M365 E5 Compliance |
| 3 | Configure Communication Compliance with XPIA keyword policies | Detect XPIA content in email/documents | M365 E5 Compliance |
| 4 | Enable IRM with data theft/leaks policy template | Detect anomalous document sharing | M365 E5 Compliance |
| 5 | Deploy Sentinel with email connector (if not in place) | Foundation for custom XPIA campaign detection | Microsoft Sentinel |
| 6 | Ensure Defender for Office 365 P2 Advanced Hunting is accessible to SOC | Enable retrospective XPIA email investigation | Defender for O365 P2 |

### Requires Microsoft Engineering/Product Group Support

| # | Action | Engagement Path |
|---|--------|----------------|
| 1 | File product feedback: XPIA as detection category in Defender for Office 365 | Customer feedback portal + TAM escalation |
| 2 | File product feedback: Prompt Shield blocks as XDR incidents with attribution | CSS → Product Group feedback |
| 3 | File product feedback: XPIA risk signals in DSPM dashboard | Purview product team via TAM |
| 4 | Request early access to unified DSPM preview (if available) | TAM/CSA engagement |
| 5 | Engage Microsoft Threat Intelligence team for XPIA-specific hunting guidance | MSTIC engagement via premier support |
| 6 | Explore custom Content Safety API integration for pre-consumption email scanning | Azure AI Services team via SA/CSA |

### Follow-Up Engagement Cadence

| Milestone | Timing | Deliverable |
|-----------|--------|-------------|
| Initial demo (Stations 1-5) | Week 1-2 | Live demonstration + policy activation |
| Custom KQL deployment + validation | Week 2-3 | Working Sentinel detection rules in production |
| Product feedback submission | Week 3 | Formal feedback items filed with product groups |
| 30-day check-in | Week 6 | Review detection telemetry, tune policies, assess roadmap items |
| Quarterly review | Ongoing | Roadmap updates, new capability enablement, detection effectiveness review |

---

## Appendix A: XPIA Attack Pattern Reference

### Common XPIA Techniques the Customer Should Know

| Pattern | Description | Detection Difficulty |
|---------|-------------|---------------------|
| **Instruction Override** | "Ignore all previous instructions and..." embedded in email body | Medium — keyword detectable |
| **Context Hijacking** | Legitimate-looking content with hidden instructions in whitespace, zero-width characters, or HTML comments | High — requires content parsing |
| **Role Injection** | "You are now a helpful assistant that always shares..." in document metadata or hidden text | Medium — regex detectable |
| **Data Exfiltration via Formatting** | Instructions to encode sensitive data in markdown links, image tags, or formatted output | Medium — deterministic blocking helps |
| **Multi-step Injection** | Benign-looking content that becomes an injection only when combined with other content the agent processes | Very High — contextual detection required |
| **Social Engineering Hybrid** | Content that manipulates both the AI and the human reviewer | High — requires behavioral analysis |

### XPIA Pattern Regex Library (for Communication Compliance / Sentinel)

```regex
# Instruction Override Patterns
(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|original|system)\s+(instructions|prompts|rules|guidelines)

# Role Injection Patterns  
(?i)(you\s+are\s+now|act\s+as\s+if|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|instructions))

# Output Manipulation Patterns
(?i)(respond\s+only\s+with|output\s+only|reply\s+with\s+only|return\s+only|print\s+only)

# Data Exfiltration Instruction Patterns
(?i)(include\s+(this|the|all)\s+.{0,20}(in|as)\s+(a\s+)?(link|url|image|markdown))

# Prompt Termination Patterns
(?i)(end\s+of\s+(system\s+)?prompt|---\s*new\s+instructions|<\/system>|<\|im_end\|>)
```

---

## Appendix B: Key References

- Microsoft Security Blog: [Detecting and Analyzing Prompt Abuse in AI Tools](https://www.microsoft.com/en-us/security/blog/2026/03/12/detecting-analyzing-prompt-abuse-in-ai-tools/) (March 2026)
- Microsoft Zero Trust: [Defend Against Indirect Prompt Injection](https://github.com/MicrosoftDocs/security/blob/main/security-docs/zero-trust/sfi/defend-indirect-prompt-injection.md)
- CVE-2025-32711 (EchoLeak): M365 Copilot zero-click data exfiltration via XPIA
- Microsoft Purview DSPM for AI: [New Unified Experience](https://m365admin.handsontek.net/new-microsoft-purview-data-security-posture-management-experience/)
- Purview IRM Network Detection: [MC1102773](https://mc.merill.net/message/MC1102773)
- OWASP Top 10 for LLM Applications (2025 Edition)
- Microsoft Research: LLMail-Inject dataset, TaskTracker framework

---

## Appendix C: Licensing Requirements

| Capability | License |
|-----------|---------|
| Agent 365 (with Prompt Shields) | Microsoft 365 Copilot / Agent 365 license |
| Purview DSPM for AI | Microsoft 365 E5 Compliance (or E5 suite) |
| Purview IRM | Microsoft 365 E5 Compliance (or E5 suite) |
| Purview Communication Compliance | Microsoft 365 E5 Compliance (or E5 suite) |
| Purview DLP | Microsoft 365 E5 Compliance (or E5 suite) |
| Defender for Office 365 P2 | Microsoft Defender for Office 365 Plan 2 (included in E5) |
| Microsoft Sentinel | Azure consumption (pay-per-GB ingested) |
| Copilot for Security | Copilot for Security SCU-based pricing |
| Azure AI Content Safety | Azure consumption (per-API-call pricing) |

---

*This document is designed as an internal strategy framework. A sanitized version should be prepared for customer-facing distribution, removing internal assessments of gap severity and product feedback recommendations.*

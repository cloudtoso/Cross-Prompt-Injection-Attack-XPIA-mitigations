# Cross/Indirect Prompt Injection Attack (XPIA) Mitigations

## Overview
This repository contains documentation, technical analysis, and presentation materials for detecting, validating, responding to, and preventing Cross/Indirect Prompt Injection Attacks (XPIA) in Microsoft Agent 365 and M365 Copilot environments.

## Contents

### Documentation
- **xpia-response-strategy.md** — Strategic framework for XPIA response: 7 customer concerns decomposed, 10 Microsoft capabilities mapped, 6 product gaps identified, and a 5-station demonstration plan
- **xpia-technical-analysis.md** — Deep technical analysis covering detection architecture, KQL queries, email pattern scenarios, insider risk analysis, recommended architecture, and a 6-step demo script
- **xpia-customer-document-outline.md** — Executive document outline with 7 sections, 5 customer scenarios, and regulatory mapping (OCC/FCA/SOX/NIST)

### Presentation
- **XPIA-Agent365-Security-Response.pptx** — 19-slide customer-facing presentation deck covering XPIA detection capabilities, gaps, workarounds, and recommended architecture

## Key Topics
- XPIA detection with Azure AI Prompt Shields
- Microsoft Defender XDR integration and alerting
- Microsoft Purview DLP custom Sensitive Information Types (SIT) for XPIA patterns
- Exchange mail flow rules for pre-delivery XPIA detection
- Correlation queries joining DLP + XDR alerts for campaign attribution
- Insider risk scenarios and document-based XPIA vectors
- EchoLeak (CVE-2025-32711) implications
- Product gap analysis and Microsoft roadmap recommendations

## Architecture
The recommended detection architecture uses a layered approach:
1. **Pre-Delivery** — Exchange mail flow rules with XPIA pattern matching
2. **Content Analysis** — DLP policies with custom SITs for XPIA regex patterns
3. **Runtime Protection** — Azure AI Prompt Shields evaluating content at Agent 365 query time
4. **Post-Incident Correlation** — KQL queries joining Purview DLP matches with Defender XDR alerts

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

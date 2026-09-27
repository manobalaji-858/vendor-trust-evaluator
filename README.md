# Vendor Trust Evaluator

**Third-party risk assessment based on SOC 2 and ISO 27001.**

Every vendor has assessments. Few check what they actually cover. This app
profiles a vendor, scores and tiers its inherent risk, scopes the AICPA Trust
Services Criteria it must meet, runs a tier-appropriate control questionnaire,
then tests all of it against the vendor's SOC 2 report and contracts (DPA, MSA,
SOW) — with every control mapped to **SOC 2 TSC**, **ISO/IEC 27001:2022** and
**NIST SP 800-53 Rev. 5**. Every value it relies on is cited to a page, and
anything uncertain goes to a human reviewer.

**Designed by:** Manobalaji Ganapathi — IT risk, audit & control automation
**Status:** v2.1 · in development · demo on synthetic data

> **Live demo:** _add your Streamlit Cloud link here_ — start with
> **▶ Guided tour** on the home page (60 seconds, no input needed).

---

## What it checks

- **Coverage gaps** — TSC categories the engagement needs but the SOC 2 never examined
- **Report quality** — Type I vs Type II, auditor opinion, exceptions, stale periods needing a bridge letter
- **Shared responsibility** — complementary user entity controls (CUECs) and carved-out sub-processors
- **Proportionate due diligence** — Tier 1 / 2 / 3 decides how deep the questionnaire goes
- **Report scope** — whether the SOC 2 covers the product, regions and data flows you actually use
- **Contracts** — 26 clauses across DPA, MSA and SOW, each quoted with its § section
- **Contradictions** — e.g. "right to audit: Yes" at intake but no audit clause in the MSA; 72-hour breach notice claimed but the DPA says 96 hours
- **Control mapping** — 18 unified controls scored from every source and mapped to ISO 27001 Annex A, SOC 2 and NIST 800-53
- **Traceability** — page citations, confidence levels, a review queue, SHA-256 evidence register and reviewer sign-off
- **Residual risk** — what's left after evidenced controls, with a recommendation

## How it works

| Step | What happens |
|---|---|
| **1 · Vendor scope** | Vendor profile, contract dates and value, data shared, record volume, processing regions, access, criticality, claimed certifications, sub-processors, **right to audit** |
| **2 · Inherent risk** | Uptime dependence, customer-facing, processing reliance, credentials, code in our environment, AI training on our data, cross-border transfers, fourth parties, regulations — and **tier escalation** |
| **3 · TSC scope** | Security always; Availability, Confidentiality, Processing Integrity and Privacy added from the answers, each with the reason shown |
| **4 · Control questionnaire** | Up to 56 controls in 11 domains, depth set by tier, each mapped to a TSC criterion; critical controls flagged |
| **5 · Evidence & contracts** | SOC 2 PDF triage and page-cited extraction (AI as a cross-check), a **review workspace** — reviewer summary, review queue, CUEC owners, sub-processor evidence, exception decisions — or questionnaire-only; DPA / MSA / SOW checklist with upload or sample |
| **6 · Dashboard** | Residual risk, TSC coverage, maturity breakdown, ISO 27001 ↔ SOC 2 ↔ NIST 800-53 control matrix, cross-document obligations, evidence register and sign-off, findings, and a one-click **evidence pack** (ZIP) plus Jira CSV |

### Guided tour & simulate

Three synthetic vendors, one per tier (`demo.py`):

| Vendor | Tier | Demonstrates |
|---|---|---|
| NimbusCRM Cloud | 2 | Type II that misses Privacy, CUECs, carve-out, DPA / MSA / SOW review, the control matrix |
| PayBridge Financial | 1 | Enhanced Due Diligence, qualified and stale SOC 2, critical controls missing → Critical |
| Santoso Hardware Supply | 3 | Lite questionnaire, no SOC 2, proportionate self-attested assessment → Low |

**▶ Guided tour** pre-fills every step with a narration panel explaining what
to look at. **⚡ Simulate results** jumps straight to the dashboard. Tour data is
fixed (no AI call), so results are repeatable.

## What's new in v2.1 — PDF intelligence

A SOC 2 is not a pass/fail certificate; the signals that matter are scattered
across 100+ pages. v2.1 turns the PDF into cited, reviewable evidence:

- **Document triage** — detects unreadable, password-protected, scanned (OCR
  needed) and suspiciously short files before anything is extracted, and
  fingerprints each file with SHA-256
- **Page-cited extraction** — report type, opinion, audit period, report date,
  TSC categories, carve-out / inclusive method, CUECs, subservice organisations,
  exceptions (with control and sample size) and scope (system, regions,
  exclusions), each with the **page and the sentence** it came from
- **AI as a cross-check, not the source** — the AI reads only the cited pages;
  agreement raises confidence, disagreement sends the field to a **review queue**
- **Scope match** — flags when your processing regions or product aren't
  covered, e.g. *EU data, SOC 2 scope US only*
- **Review workspace** — owners and status for each CUEC, downstream evidence
  for each carved-out sub-processor (with the dependency chain), and a decision
  for each exception: accept, compensating control, remediate or escalate
- **Cross-document obligations** — SOC 2 vs MSA vs DPA: SOC 2 required by
  contract, breach deadline, sub-processor governance, scope, deletion, audit
  rights, transfer mechanism
- **NIST SP 800-53 Rev. 5** added to the many-to-many control matrix
- **Evidence pack** — one ZIP with the report (Markdown + JSON), control
  matrix, Jira import CSV and evidence register with hashes; reviewer sign-off
  recorded with the decision
- **Try it** — download the synthetic 10-page SOC 2 from the Evidence step and
  upload it to see the full pipeline

## Scoring model

> The frameworks (AICPA TSC, ISO 27001:2022 Annex A, SOC 2 report concepts) are
> real; the weights and thresholds below are **my own illustrative model**,
> aligned with common TPRM practice (NIST SP 800-161, ISO/IEC 27036, SIG
> Lite/Core-style tiering). Organisations calibrate these to their own risk
> appetite.

**Inherent risk** = 0.45 × data sensitivity + 0.35 × access + 0.20 × criticality

| Tier | Criteria | Also raised here by | Questionnaire | Review |
|---|---|---|---|---|
| 1 · high | Inherent ≥ 65 | >100k sensitive records; privileged access + credentials | **Full + Enhanced Due Diligence** (exit plan, audit access, 24x7 SOC, insurance, financial stability…) | 3 months |
| 2 · moderate | 40 – 64 | code in our environment; AI training on our data; PHI / financial data cross-border; business-critical + customer-facing | **Standard** — every question in the in-scope domains | 6 months |
| 3 · low | < 40 | — | **Lite** — critical controls and key basics | 12 months |

Escalation rules only ever raise a tier.

**Control maturity** starts from the evidence and adds or subtracts factors:

- Baseline: SOC 2 Type II 85 · Type I / SOC 3 35 · no report = 60% of the questionnaire score
- Qualified opinion −20 · adverse / disclaimer −45 · exceptions −10 · period older than 12 months −15
- Each required TSC category not covered −12 (−6 if the matching questionnaire domain scores ≥ 75%)
- CUECs −5 while any are unconfirmed (0 once each is owned and implemented) · critical controls the vendor says are missing −5 each (max −15)
- Right to audit: +5 when there are gaps it can close; −5 without one for Tier 1 / 2 (Tier 3 exempt)

**Residual risk** = inherent × (1 − 0.70 × maturity ÷ 100) → Low ≤ 20 · Medium ≤ 40 · High ≤ 65 · Critical

Controls can remove at most 70% of inherent risk — some risk always stays with a third party.

## Contract review & control mapping

`contracts.py` checks DPA, MSA and SOW clauses — GDPR Art. 28(3) processor
terms, transfer mechanism, right to audit, security schedule, breach notice
(≤ 72h), liability, insurance, exit, SLAs, screening, data locations — using
**transparent keyword rules, not AI**. Contract text never leaves the app, and
every result quotes the sentence it matched. Clause presence is not a legal
opinion on adequacy.

The **control matrix** scores 18 unified controls, each mapped to ISO/IEC
27001:2022 Annex A and the TSC, from contract clauses, questionnaire answers,
intake answers and the SOC 2 report at once. Each source counts Met = 1,
Partial = 0.5, Gap = 0; a control is Met at ≥ 0.8 and Partial at ≥ 0.4.
Contract assurance is shown separately and does not change residual risk.

## Run it

```bash
pip install -r requirements.txt
```
```bash
streamlit run app.py
```

AI extraction of SOC 2 reports is optional. Add keys in **Streamlit Cloud →
Settings → Secrets**, or a gitignored `.streamlit/secrets.toml` locally:

```toml
GROQ_API_KEY = "gsk_..."   # optional, tried first
HF_TOKEN = "hf_..."        # Hugging Face Inference Providers
```

Without keys, or if every provider fails, a rule-based extractor takes over
and the app says why on screen.

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Wizard UI, scoring engines, findings, dashboard |
| `questionnaire.py` | 56-question control bank, tier depth, scoring |
| `contracts.py` | Clause library, sample agreements, ISO 27001 / TSC / NIST 800-53 mapping |
| `demo.py` | Synthetic demo vendors, reviewer decisions and guided-tour narration |
| `pdfintel.py` | PDF triage, page-cited extraction, AI cross-check, review queue, synthetic 10-page sample PDF |

## Versions

- **v1 · classic** — the original single-page SOC 2 validator:
  [soc2-report-validator](https://github.com/manobalaji-858/soc2-report-validator)
- **v2 · Vendor Trust Evaluator** — this repository
- **v2.1 · PDF intelligence** — page citations, review workflow, NIST mapping, evidence pack
- What's next: see [ROADMAP.md](ROADMAP.md)

## Notes

Demo on **synthetic data**. Use the samples or non-confidential documents only
— real SOC 2 reports and contracts are typically confidential and NDA-bound.
Not affiliated with the AICPA or ISO. Not audit or legal advice.

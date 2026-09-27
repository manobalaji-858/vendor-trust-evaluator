# Roadmap

The problem: third-party assurance data is locked inside long, inconsistent
SOC 2 and contract PDFs. Reviewers hunt for scope limits, exceptions, CUECs,
sub-processors and contractual obligations, then retype them into
spreadsheets with little traceability. This project turns those PDFs into
traceable, risk-based vendor decisions.

## Shipped

**v1 · classic** — single-page SOC 2 validator: TSC scoping, report extraction,
residual score. ([soc2-report-validator](https://github.com/manobalaji-858/soc2-report-validator))

**v2 · Vendor Trust Evaluator**
- Vendor profile, inherent-risk questionnaire, tiering with escalation rules
- Tier-based control questionnaire (Lite / Standard / Full + EDD)
- SOC 2 validation: coverage gaps, Type I vs II, stale periods, CUECs, carve-outs
- DPA / MSA / SOW clause review with quoted evidence
- ISO 27001 ↔ SOC 2 control matrix, guided tour, mobile layout

**v2.1 · PDF intelligence**
- PDF triage (unreadable / password-protected / scanned / short) and SHA-256
- Page-cited extraction with confidence; AI only as a cross-check
- Review queue, CUEC owners, sub-processor evidence, exception decisions
- Scope match (regions / product), cross-document obligation matrix
- NIST SP 800-53 Rev. 5 mapping; evidence pack (ZIP) and Jira CSV; sign-off

## Next

**v3 · continuous vendor monitoring** (needs storage and a scheduler)
- Vendor Registry as the home page: portfolio view and "needs attention" rules
- Saved assessments and report history; compare report periods
- SOC 2 expiry alerts (e.g. 60 / 30 / 7 days) and bridge-letter requests
- Sub-processor change detection between report versions
- Public trust-center and sub-processor-page snapshots (text + hash)
- Free outside-in signals: TLS grade, security headers, SPF / DMARC
- Scheduled checks with GitHub Actions

## Not planned

- Scraping gated trust centers (NDA / login walls)
- Paid security-rating APIs — free outside-in signals instead
- Uploading real, confidential vendor reports to the public demo

_Demo on synthetic data. Not audit or legal advice._

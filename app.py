"""
SOC 2 Trust Services Evaluator
------------------------------
A vendor risk-assessment tool built around the AICPA Trust Services Criteria.

Flow:
  0. Overview — what the tool does, then Start
  1. Vendor Scope for Access and Data — vendor profile, contract, data,
     regions, access, certifications, Right to Audit
  2. Inherent Risk Questionnaire (IRQ) — with tier-escalation rules
  3. Auto-scope the TSC categories/criteria that must be satisfied
  4. Control Questionnaire — domains in scope, mapped to TSC (questionnaire.py)
  5. Upload (or load a sample) SOC 2 / SOC 3 report -> AI extraction with a
     rule-based fallback, or proceed on the questionnaire alone
  6. Dashboard — coverage, maturity, residual score, findings, download

Version 1 (single-page wizard).

Designed by Manobalaji Ganapathi  |  GRC & security automation
Demo on synthetic data. Not affiliated with the AICPA. Not audit advice.
"""

import os
import re
import json
import math
import base64
import io
import zipfile
import datetime as dt

import streamlit as st

import contracts as ct
import demo
import pdfintel as pi
import questionnaire as qn

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
st.set_page_config(page_title="Vendor Trust Evaluator · SOC 2 & ISO 27001",
                   page_icon="🛡️", layout="wide")


def _secret(key, default=None):
    """Read from st.secrets (Streamlit Cloud) first, then os.environ."""
    try:
        if key in st.secrets:
            return st.secrets[key]
    except Exception:  # noqa: BLE001 - no secrets.toml present
        pass
    return os.environ.get(key, default)


# MODEL must show an "Inference Providers" panel on its HF model page. If it is
# gated or unavailable, the app automatically falls back to rule-based extraction.
HF_TOKEN = _secret("HF_TOKEN")
MODEL = _secret("MODEL", "meta-llama/Llama-3.1-8B-Instruct")
PROVIDER = _secret("PROVIDER", "auto")
# Optional: Groq's free tier (OpenAI-compatible). Tried before HF when set.
GROQ_API_KEY = _secret("GROQ_API_KEY")
GROQ_MODEL = _secret("GROQ_MODEL", "llama-3.1-8b-instant")
TODAY = dt.date.today()
DESIGNER = "Manobalaji"

# ----------------------------------------------------------------------
# Trust Services Criteria catalogue (AICPA TSC 2017, rev.)
# ----------------------------------------------------------------------
COMMON_CRITERIA = {
    "CC1": "Control Environment",
    "CC2": "Communication & Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical & Physical Access Controls",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}
CATEGORY_CRITERIA = {
    "Availability": {
        "A1.1": "Capacity & performance management",
        "A1.2": "Environmental protections, backup & recovery infrastructure",
        "A1.3": "Recovery plan testing",
    },
    "Confidentiality": {
        "C1.1": "Identify & maintain confidential information",
        "C1.2": "Dispose of confidential information",
    },
    "Processing Integrity": {
        "PI1.1": "Definitions of processing specifications",
        "PI1.2": "Completeness & accuracy of inputs",
        "PI1.3": "Completeness & accuracy of processing",
        "PI1.4": "Accuracy & timeliness of outputs",
        "PI1.5": "Storage integrity",
    },
    "Privacy": {
        "P1": "Notice & communication of privacy commitments",
        "P2": "Choice & consent",
        "P3": "Collection",
        "P4": "Use, retention & disposal",
        "P5": "Access",
        "P6": "Disclosure & notification",
        "P7": "Quality",
        "P8": "Monitoring & enforcement",
    },
}
ALL_CATEGORIES = ["Security", "Availability", "Confidentiality",
                  "Processing Integrity", "Privacy"]

# ----------------------------------------------------------------------
# Scoring maps
# ----------------------------------------------------------------------
DATA_SENS = {
    "None": 5, "Internal business data": 25, "Confidential / proprietary": 55,
    "Customer PII": 60, "Employee PII": 60, "Authentication / credentials": 75,
    "Financial / cardholder": 80, "Health / PHI": 90,
}
ACCESS_SCORE = {
    "No access to our systems or data": 10,
    "Reads our production data": 35,
    "Read-write to core systems": 65,
    "Admin / privileged access": 90,
}
CRIT_SCORE = {"Low": 10, "Moderate": 40, "Business-critical": 75}
SERVICE_CATEGORIES = ["SaaS application", "Cloud infrastructure",
                      "Payment processor", "Data analytics", "Marketing / CRM",
                      "Managed IT service", "HR / payroll",
                      "Communications / email", "Legal / professional services",
                      "Hardware & equipment", "Open-source dependency"]
REGIONS = ["India", "United States", "EU / EEA", "United Kingdom",
           "Singapore / APAC", "Middle East", "Other"]
CERTIFICATIONS = ["SOC 2 Type II", "SOC 2 Type I", "SOC 3", "ISO 27001",
                  "ISO 27701", "ISO 22301", "PCI DSS", "HIPAA attestation",
                  "CSA STAR"]
REGULATIONS = ["GDPR", "DPDP Act (India)", "CCPA / CPRA", "HIPAA", "PCI DSS",
               "SOX", "GLBA", "RBI / SEBI outsourcing"]
VOLUMES = ["< 10k records", "10k – 100k records", "100k – 1M records",
           "> 1M records"]
SPEND = ["< $10k", "$10k – $50k", "$50k – $250k", "> $250k"]
PRIVACY_REGS = {"GDPR", "DPDP Act (India)", "CCPA / CPRA", "HIPAA"}
SENSITIVE = {"Customer PII", "Employee PII", "Health / PHI",
             "Financial / cardholder", "Authentication / credentials"}

NO_REPORT = {
    "report_type": "None", "period_start": None, "period_end": None,
    "tsc_categories": [], "auditor_opinion": "N/A",
    "exceptions_noted": False, "exceptions_summary": None,
    "cuecs_present": False, "cuecs_summary": None,
    "subservice_method": "Unknown", "_method": "questionnaire only"}

# ----------------------------------------------------------------------
# Extraction: page-cited rules first, AI as a cross-check (pdfintel.py)
# ----------------------------------------------------------------------
EXTRACT_PROMPT = """You are a SOC 2 analyst. The text below contains the relevant pages of a SOC report, each marked [Page N]. Return ONLY a JSON object, no prose, with these keys:
report_type: one of "SOC 2 Type II","SOC 2 Type I","SOC 3","Unknown"
period_start: YYYY-MM-DD or null
period_end: YYYY-MM-DD or null
tsc_categories: array from ["Security","Availability","Confidentiality","Processing Integrity","Privacy"] (only categories actually examined)
auditor_opinion: one of "Unqualified","Qualified","Adverse","Disclaimer","Unknown"
exceptions_noted: true or false
exceptions_summary: short string or null
cuecs_present: true or false
cuecs_summary: short string or null
subservice_method: one of "Carve-out","Inclusive","Unknown"

REPORT PAGES:
"""


def ai_backends():
    """(label, client kwargs, model) for each configured AI provider, in order."""
    backends = []
    if GROQ_API_KEY:
        backends.append(("Groq", {"base_url": "https://api.groq.com/openai/v1",
                                  "api_key": GROQ_API_KEY}, GROQ_MODEL))
    if HF_TOKEN:
        backends.append(("HF", {"provider": PROVIDER, "api_key": HF_TOKEN}, MODEL))
    return backends


def ai_extract(text, client_kwargs, model):
    """Call a hosted chat model; raise on any failure so caller can fall back."""
    from huggingface_hub import InferenceClient
    client = InferenceClient(**client_kwargs)
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": EXTRACT_PROMPT + text[:12000]}],
        max_tokens=600, temperature=0.1,
    )
    raw = resp.choices[0].message.content.strip()
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    start, end = raw.find("{"), raw.rfind("}")
    data = json.loads(raw[start:end + 1])
    data.setdefault("tsc_categories", ["Security"])
    return data


def ai_error_reason(e):
    """Plain-English reason an AI call failed, for the on-screen fallback note."""
    status = getattr(getattr(e, "response", None), "status_code", None)
    msg = str(e).lower()
    if status == 401:
        return "invalid or revoked API key (401)"
    if status == 402:
        return "monthly credits exhausted (402)"
    if status == 403:
        return "key lacks inference permission (403)"
    if status == 429:
        return "rate limited (429)"
    if "model_not_supported" in msg or status == 404:
        return "model not served for this key"
    if isinstance(e, (json.JSONDecodeError, ValueError)):
        return "model returned unparseable output"
    return type(e).__name__ + (" (%s)" % status if status else "")


REVIEW_PREFIX = "rv_"
SAMPLE_PDF_NAME = "Synthetic SOC 2 Type 2 - NimbusCRM Cloud (10 pages).pdf"


def reset_review(target):
    """Forget reviewer decisions that belonged to a previous report."""
    for k in [k for k in target if k.startswith(REVIEW_PREFIX)]:
        del target[k]
    for k in [k for k in st.session_state
              if k.startswith("w_" + REVIEW_PREFIX)]:
        del st.session_state[k]


def register_evidence(target, doc_type, name, digest, pages=None,
                      status="OK"):
    """Evidence register entry: stable ID, file name, SHA-256, when."""
    reg = target.setdefault("evidence", {})
    order = ["SOC 2", "DPA", "MSA", "SOW"]
    reg[doc_type] = {"id": "EV-%02d" % (order.index(doc_type) + 1
                                        if doc_type in order else len(reg) + 1),
                     "type": doc_type, "name": name, "sha256": digest,
                     "pages": pages, "status": status,
                     "loaded": dt.datetime.now().strftime("%Y-%m-%d %H:%M")}


def process_report(target, data, name, use_ai=True):
    """Triage, extract with page citations, cross-check with AI and store.
    Returns the triage info; target["extracted"] is None if unreadable."""
    info, pages = pi.triage(data)
    reset_review(target)
    target["pdf"] = info
    target["evidence_name"] = name
    target["evidence_key"] = info["sha256"]
    register_evidence(target, "SOC 2", name, info["sha256"], info["pages"],
                      info["status"])
    if not pages or info["text_pages"] == 0:
        target["extracted"] = None
        return info
    ext = pi.extract(pages)
    info["issues"] += pi.completeness(ext)
    ai, reasons, label = None, [], None
    if use_ai:
        context = pi.ai_context(pages, ext)
        for lbl, kwargs, model in ai_backends():
            try:
                ai = ai_extract(context, kwargs, model)
                label = "%s · %s" % (lbl, model.split("/")[-1])
                break
            except Exception as e:  # noqa: BLE001 - demo resilience
                reasons.append("%s: %s" % (lbl, ai_error_reason(e)))
    ext = pi.merge(ext, ai)
    if label:
        ext["_method"] = "page-cited rules, cross-checked by AI (%s)" % label
    elif reasons:
        ext["_method"] = ("page-cited rules (AI cross-check unavailable — %s)"
                          % "; ".join(reasons))
    elif use_ai:
        ext["_method"] = "page-cited rules (no AI key set)"
    else:
        ext["_method"] = "page-cited rules (tour data, no AI call)"
    target["extracted"] = ext
    return info


def read_pdf(uploaded):
    from pypdf import PdfReader
    reader = PdfReader(uploaded)
    return "\n".join((p.extract_text() or "") for p in reader.pages)


def effective_ext(a):
    """The report as the reviewer has confirmed it: review-queue overrides
    applied, plus the CUEC / subservice / exception decisions."""
    ext = dict(a.get("extracted") or NO_REPORT)
    for f in ext.get("_queue", []):
        v = a.get(REVIEW_PREFIX + "q_" + f)
        if v not in (None, "", []):
            ext[f] = v
    ext["_cuec_state"] = [
        {"owner": a.get("%scuec_owner_%d" % (REVIEW_PREFIX, i), ""),
         "status": a.get("%scuec_status_%d" % (REVIEW_PREFIX, i),
                         "Not assessed")}
        for i in range(len(ext.get("_cuecs", [])))]
    ext["_sub_state"] = [a.get("%ssub_ev_%d" % (REVIEW_PREFIX, i),
                               "Not requested")
                         for i in range(len(ext.get("_subservice", [])))]
    ext["_exc_state"] = [
        {"decision": a.get("%sexc_dec_%d" % (REVIEW_PREFIX, i), "Undecided"),
         "note": a.get("%sexc_note_%d" % (REVIEW_PREFIX, i), "")}
        for i in range(len(ext.get("_exceptions", [])))]
    return ext


# ----------------------------------------------------------------------
# GRC engines
# ----------------------------------------------------------------------
def compute_inherent(a):
    sens = max([DATA_SENS.get(d, 5) for d in a["data"]] or [5])
    acc = ACCESS_SCORE[a["access"]]
    crit = CRIT_SCORE[a["crit"]]
    inh = round(0.45 * sens + 0.35 * acc + 0.20 * crit)
    tier = 1 if inh >= 65 else 2 if inh >= 40 else 3
    return inh, tier


def tier_escalation(a, tier):
    """Tier overrides from the Inherent Risk Questionnaire.

    The inherent score stays the weighted formula; these rules can only raise
    the tier (lower number = higher risk), as TPRM programmes commonly do for
    exposures a single score under-weights.
    """
    reasons = []
    data = set(a.get("data", []))
    big = a.get("volume") in ("100k – 1M records", "> 1M records")
    if big and data & SENSITIVE:
        reasons.append((1, "large volume of sensitive data (%s)" % a["volume"]))
    if a.get("access") == "Admin / privileged access" and a.get("irq_creds"):
        reasons.append((1, "privileged access plus credential handling"))
    if a.get("irq_code"):
        reasons.append((2, "vendor code runs in our environment"))
    if a.get("irq_ai"):
        reasons.append((2, "our data is used to train AI / ML models"))
    if a.get("irq_crossborder") and data & {"Health / PHI",
                                            "Financial / cardholder"}:
        reasons.append((2, "regulated data transferred across borders"))
    if a.get("irq_customer_facing") and a.get("crit") == "Business-critical":
        reasons.append((2, "business-critical and customer-facing"))
    final = min([tier] + [t for t, _ in reasons])
    return final, [r for t, r in reasons if t < tier]


def assess_tier(a):
    inh, base = compute_inherent(a)
    tier, reasons = tier_escalation(a, base)
    return inh, base, tier, reasons


def scope_tsc(a):
    """Return the TSC categories that must be satisfied for this engagement."""
    cats = ["Security"]  # Common Criteria always in scope
    regs = set(a.get("regulations", []))
    pii = any(d in a["data"] for d in
              ["Customer PII", "Employee PII", "Health / PHI"])
    if pii or regs & PRIVACY_REGS:
        cats.append("Privacy")
    if "Confidential / proprietary" in a["data"] or pii \
            or a["data"] not in ([], ["None"]):
        if "Confidentiality" not in cats:
            cats.append("Confidentiality")
    if a["crit"] == "Business-critical" or a.get("irq_uptime") \
            or a.get("irq_customer_facing"):
        cats.append("Availability")
    # SOX reliance means we depend on the vendor's processing accuracy
    if a.get("irq_processing") or "SOX" in regs:
        cats.append("Processing Integrity")
    # keep canonical order
    return [c for c in ALL_CATEGORIES if c in cats]


def scope_reasons(a, required):
    """Why each category is in scope, for the TSC Scope step."""
    regs = set(a.get("regulations", []))
    why = {"Security": "Common Criteria — always required"}
    if "Privacy" in required:
        src = [d for d in a["data"] if d in ("Customer PII", "Employee PII",
                                              "Health / PHI")]
        src += sorted(regs & PRIVACY_REGS)
        why["Privacy"] = "personal data / privacy law: " + ", ".join(src)
    if "Confidentiality" in required:
        why["Confidentiality"] = "confidential data shared: " + ", ".join(
            d for d in a["data"] if d != "None")
    if "Availability" in required:
        why["Availability"] = ", ".join(
            r for r, on in [("business-critical", a["crit"] ==
                             "Business-critical"),
                            ("we depend on uptime", a.get("irq_uptime")),
                            ("customer-facing", a.get("irq_customer_facing"))]
            if on)
    if "Processing Integrity" in required:
        why["Processing Integrity"] = ", ".join(
            r for r, on in [("we rely on its processing accuracy",
                             a.get("irq_processing")),
                            ("SOX reliance", "SOX" in regs)] if on)
    return why


def required_criteria(required):
    """Flatten the required categories into (category, id, name) criteria."""
    rows = [("Security", k, v) for k, v in COMMON_CRITERIA.items()]
    for cat in required:
        rows += [(cat, k, v) for k, v in CATEGORY_CRITERIA.get(cat, {}).items()]
    return rows


def assurance_gaps(missing, ext, stale):
    """Places where the SOC 2 alone doesn't give full assurance."""
    gaps = []
    if missing:
        gaps.append("untested categories (%s)" % ", ".join(missing))
    if ext["report_type"] == "None":
        gaps.append("independent assurance (no SOC 2 provided)")
    elif ext["report_type"] != "SOC 2 Type II":
        gaps.append("operating effectiveness (report is %s)" % ext["report_type"])
    if stale:
        gaps.append("the period since the report ended")
    if ext.get("subservice_method") == "Carve-out":
        gaps.append("carved-out sub-processors")
    return gaps


COVERING_DOMAIN = {d["covers"]: d["key"] for d in qn.DOMAINS if d["covers"]}
SELF_PCT = round(qn.SELF_ATTESTED_WEIGHT * 100)


def report_maturity(required, ext, rta="No", tier=3, q=None):
    """Translate report quality into a control-maturity proxy (0-100).

    `q` is the control questionnaire result ({"per", "overall", "critical"}).
    The SOC 2 is the primary evidence; the self-attested questionnaire only
    (a) stands in, at SELF_ATTESTED_WEIGHT, when no report exists, (b) softens a
    coverage gap when its matching domain scores >= 75%, and (c) penalises
    critical controls the vendor itself says are missing.

    Returns (score, missing categories, stale flag, adjustments) where
    adjustments is a list of (label, points) for the dashboard breakdown.
    """
    rtype = ext["report_type"]
    if rtype == "None":
        overall = q["overall"] if q else 0
        base = round(qn.SELF_ATTESTED_WEIGHT * overall)
        adj = []
        if q and q["critical"]:
            adj.append(("Critical controls missing (%d)" % len(q["critical"]),
                        -min(15, 5 * len(q["critical"]))))
        # no independent coverage at all; the 70% weight already prices it in
        missing = list(required)
        gaps = assurance_gaps(missing, ext, False)
        if rta == "Yes":
            adj.append(("Right to audit can close gaps", +5))
        elif tier < 3:  # self-attestation is acceptable for Tier 3
            adj.append(("No right to audit", -5))
        m = base + sum(d for _, d in adj)
        label = "Self-attested (%d%% × %d%%)" % (SELF_PCT, overall)
        return max(0, min(100, m)), missing, False, [(label, base)] + adj
    if rtype in ("SOC 2 Type I", "SOC 3", "Unknown"):
        base, base_label = 35, "%s baseline" % rtype  # design-only / summary
    else:
        base, base_label = 85, "Type II baseline"
    adj = []
    op = ext["auditor_opinion"]
    if op == "Qualified":
        adj.append(("Qualified opinion", -20))
    elif op in ("Adverse", "Disclaimer"):
        adj.append(("%s opinion" % op, -45))
    if ext["exceptions_noted"]:
        adj.append(("Exceptions noted", -10))
    # period currency (needs bridge letter if end > ~12 months ago)
    stale = False
    if ext.get("period_end"):
        try:
            end = dt.date.fromisoformat(ext["period_end"])
            if (TODAY - end).days > 365:
                stale = True
                adj.append(("Stale period (>12 months)", -15))
        except ValueError:
            pass
    # coverage of required categories
    covered = set(ext.get("tsc_categories", []))
    missing = [c for c in required if c not in covered]
    for c in missing:
        dom = COVERING_DOMAIN.get(c)
        pct = q["per"].get(dom) if q and dom else None
        if pct is not None and pct >= qn.COMPENSATING_THRESHOLD:
            adj.append(("%s not covered (self-attested %d%%)" % (c, pct), -6))
        else:
            adj.append(("%s not covered" % c, -12))
    # CUECs: controls *we* must operate. With the CUEC list extracted, only
    # unconfirmed ones count; without it, any CUEC is an open question.
    state = ext.get("_cuec_state")
    if ext.get("_cuecs") and state is not None:
        open_ = sum(1 for c in state
                    if c["status"] not in ("Implemented", "Not applicable"))
        if open_:
            adj.append(("CUECs not confirmed (%d of %d)" % (open_, len(state)),
                        -5))
    elif ext["cuecs_present"]:
        adj.append(("CUECs present", -5))
    if q and q["critical"]:
        adj.append(("Critical controls missing (%d)" % len(q["critical"]),
                    -min(15, 5 * len(q["critical"]))))
    # Right to audit (CC9.2 vendor risk management): a contractual audit right
    # lets you close assurance gaps directly; without one the report is the
    # only assurance, which matters most for Tier 1 vendors or when gaps exist.
    gaps = assurance_gaps(missing, ext, stale)
    if rta == "Yes" and gaps:
        adj.append(("Right to audit can close gaps", +5))
    elif rta == "No" and tier < 3 and (gaps or tier == 1):
        adj.append(("No right to audit", -5))
    m = base + sum(d for _, d in adj)
    return max(0, min(100, m)), missing, stale, [(base_label, base)] + adj


def compute_residual(inherent, maturity):
    res = max(0, min(100, round(inherent * (1 - 0.70 * (maturity / 100)))))
    band = ("Low" if res <= 20 else "Medium" if res <= 40
            else "High" if res <= 65 else "Critical")
    return res, band


def build_findings(a, ext, missing, stale, gaps, q=None, domains=()):
    """(severity, title, detail, TSC reference) for each finding, worst first."""
    f = []
    no_report = ext["report_type"] == "None"
    if no_report:
        if a["tier"] == 3:
            f.append(("Low", "Self-attested only",
                      "No SOC 2 was provided; for a Tier 3 vendor the "
                      "questionnaire (counted at %d%%) is proportionate "
                      "evidence." % SELF_PCT, "CC9.2"))
        else:
            f.append(("High" if a["tier"] == 1 else "Medium",
                      "No independent assurance",
                      "No SOC 2 was provided, so every control rests on the "
                      "vendor's own answers (counted at %d%%). Request a SOC 2 "
                      "Type II, ISO 27001 certificate, or exercise the right to "
                      "audit." % SELF_PCT, "CC9.2"))
    elif missing:
        f.append(("High", "Coverage gap",
                  "The report does not cover %s, which this engagement requires. "
                  "Request an updated report with these categories in scope, or "
                  "add compensating evidence." % ", ".join(missing),
                  ", ".join(missing)))
    if not no_report and ext["report_type"] != "SOC 2 Type II":
        f.append(("High", "Not a Type II report",
                  "Report is %s — operating effectiveness over time is not "
                  "evidenced." % ext["report_type"], "All"))
    if ext["auditor_opinion"] in ("Qualified", "Adverse", "Disclaimer"):
        f.append(("High", "%s opinion" % ext["auditor_opinion"],
                  "Investigate the basis for the modified opinion.", "All"))
    if ext["exceptions_noted"]:
        f.append(("Medium", "Exceptions noted",
                  "Review each exception and its remediation status." +
                  (" " + ext["exceptions_summary"]
                   if ext.get("exceptions_summary") else ""), "CC4 / CC5"))
    if stale:
        f.append(("Medium", "Stale report period",
                  "Period ended more than 12 months ago — request a bridge "
                  "letter covering the gap to today.", "CC4"))
    if ext["cuecs_present"] and not ext.get("_cuecs"):
        # without the extracted list, all we can say is that CUECs exist;
        # the per-CUEC findings come from evidence_findings()
        f.append(("Medium", "Complementary User Entity Controls",
                  "These are controls you must operate. Confirm you perform "
                  "them or the assurance does not hold." +
                  (" " + ext["cuecs_summary"] if ext.get("cuecs_summary") else ""),
                  "CC2.3"))
    if ext.get("subservice_method") == "Carve-out":
        named = ", ".join(o["name"] for o in ext.get("_subservice", []))
        subs = a.get("subprocessors", "").strip()
        f.append(("Medium", "Carved-out sub-processors",
                  "Subservice organisations' controls are excluded; assess the "
                  "sub-processor separately (nth-party risk)." +
                  (" Named in the report: %s." % named if named else "") +
                  (" Declared at intake: %s." % subs if subs else ""),
                  "CC9.2"))
    if a.get("rta") == "No" and a["tier"] < 3 and (gaps or a["tier"] == 1):
        f.append(("High" if a["tier"] == 1 else "Medium", "No right to audit",
                  "The SOC 2 is your only assurance, so %s cannot be verified "
                  "independently. Negotiate a right-to-audit clause at renewal."
                  % (", ".join(gaps) if gaps else "a Tier 1 vendor's controls"),
                  "CC9.2"))
    elif a.get("rta") == "Yes" and gaps:
        f.append(("Low", "Right to audit available",
                  "Use it to test %s directly." % ", ".join(gaps), "CC9.2"))

    # ---- control questionnaire (self-attested) ----
    if q:
        for dom, text, ref, ans in q["critical"]:
            f.append(("High", "Critical control missing — %s" % dom,
                      "Vendor answered %s: %s." % (ans.lower(), text), ref))
        crit_ids = {c[1] for c in q["critical"]}
        for d in domains:
            weak = [(t, ref, a.get("answers", {}).get(qid) or "Unanswered")
                    for qid, t, ref, crit in d["questions"]
                    if t not in crit_ids
                    and a.get("answers", {}).get(qid) in (None, "No",
                                                         "Partial")]
            if not weak:
                continue
            nos = [w for w in weak if w[2] != "Partial"]
            sev = "Medium" if nos else "Low"
            f.append((sev, "%s — %d control%s not fully in place"
                      % (d["name"], len(weak), "s" if len(weak) > 1 else ""),
                      "; ".join("%s (%s)" % (t, ans.lower())
                                for t, _, ans in weak), d["tsc"]))
        # contradictions between what the vendor says and what the audit shows
        summary = (ext.get("exceptions_summary") or "").lower()
        access_related = not summary or any(
            w in summary for w in ("access", "revok", "terminat", "cc6"))
        if not no_report and "Security" in ext.get("tsc_categories", []) \
                and a.get("answers", {}).get("iam5") in ("No", "Partial") \
                and ext["exceptions_noted"] and access_related:
            f.append(("Medium", "Self-assessment matches audit exception",
                      "Timely access revocation is weak in both the "
                      "questionnaire and the SOC 2 exceptions — treat as a "
                      "confirmed control weakness.", "CC6.2"))

    # ---- vendor profile ----
    regions = a.get("regions", [])
    if "Privacy" in a.get("required", []) and (a.get("irq_crossborder") or
                                               len(regions) > 1) \
            and a.get("answers", {}).get("prv5") != "Yes":
        f.append(("High", "Cross-border transfer without a transfer mechanism",
                  "Personal data is processed in %s but the vendor has not "
                  "confirmed SCCs / adequacy / a permitted-country basis."
                  % (", ".join(regions) or "multiple regions"), "P6"))
    claimed = set(a.get("certs", []))
    if not no_report and "SOC 2 Type II" in claimed \
            and ext["report_type"] != "SOC 2 Type II":
        f.append(("Medium", "Claimed certification not evidenced",
                  "Vendor claims SOC 2 Type II but the report provided is %s."
                  % ext["report_type"], "CC9.2"))
    if no_report and claimed & {"SOC 2 Type II", "ISO 27001"}:
        f.append(("Medium", "Certification claimed but not provided",
                  "Vendor claims %s — request the report / certificate before "
                  "relying on it." % ", ".join(sorted(claimed & {
                      "SOC 2 Type II", "ISO 27001"})), "CC9.2"))
    end = a.get("contract_end")
    if end:
        days = (end - TODAY).days
        if days < 0:
            f.append(("Medium", "Contract expired",
                      "Contract ended %d days ago but the service is still "
                      "being assessed — confirm the commercial and data-"
                      "protection terms in force." % -days, "CC9.2"))
        elif days <= 90:
            f.append(("Medium" if a.get("rta") == "No" else "Low",
                      "Renewal in %d days" % days,
                      "Use the renewal to fix contract terms: " +
                      ("add a right-to-audit clause, " if a.get("rta") == "No"
                       else "") + "security schedule, breach notice and "
                      "sub-processor approval.", "CC9.2"))
    if not a.get("owner"):
        f.append(("Low", "No relationship owner",
                  "Assign an accountable business owner for this vendor.",
                  "CC9.2"))
    order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(f, key=lambda x: order[x[0]])


# ----------------------------------------------------------------------
# Contracts and the unified control matrix (ISO 27001 <-> SOC 2)
# ----------------------------------------------------------------------
CLAUSE_VALUE = {"Met": 1.0, "Partial": 0.5, "Missing": 0.0}


def contract_results(a):
    """{clause_id: (status, snippet, note)} for every agreement provided."""
    res = {}
    for doc in a.get("docs", []):
        res.update(a.get("contracts", {}).get(doc, {}).get("results", {}))
    return res


def clause_refs(cid):
    """ISO / TSC references of the controls a clause evidences."""
    iso, tsc = [], []
    for _, _, i, t, sources in ct.CONTROLS:
        if ("clause", cid) in sources:
            iso += [x for x in i if x not in iso]
            tsc += [x for x in t if x not in tsc]
    return iso, tsc


def source_value(src, a, ext, asked, clauses):
    """(value 0-1 or None if not assessed, label, note) for one evidence
    source; label None means the source doesn't apply and is hidden."""
    kind = src[0]
    no_report = ext is None or ext["report_type"] == "None"
    if kind == "clause":
        c = ct.CLAUSE[src[1]]
        label = "%s · %s" % (c[1], c[2])
        if src[1] not in clauses:
            return None, label, "not provided"
        status, _, note = clauses[src[1]]
        return CLAUSE_VALUE[status], label, note or status.lower()
    if kind == "q":
        if src[1] not in asked:
            return None, None, None
        ans = a.get("answers", {}).get(src[1])
        text = asked[src[1]]
        label = "Questionnaire · " + (text if len(text) <= 48
                                      else text[:47] + "…")
        if ans == "N/A":
            return None, label, "n/a"
        return qn.SCORE.get(ans, 0.0), label, (ans or "unanswered").lower()
    if kind == "soc2":
        label = "SOC 2 · %s category" % src[1]
        if no_report:
            return None, label, "no report"
        ok = src[1] in ext.get("tsc_categories", [])
        return (1.0 if ok else 0.0), label, "examined" if ok else "not in scope"
    if kind == "soc2type":
        if no_report:
            return None, "SOC 2 · report type", "no report"
        t2 = ext["report_type"] == "SOC 2 Type II"
        return (1.0 if t2 else 0.5), "SOC 2 · report type", ext["report_type"]
    if kind == "subservice":
        m = ext.get("subservice_method") if ext else None
        if no_report or m not in ("Carve-out", "Inclusive"):
            return None, None, None
        return (1.0 if m == "Inclusive" else 0.5), "SOC 2 · sub-processors", \
            m.lower()
    if kind == "rta":
        return (1.0 if a.get("rta") == "Yes" else 0.0), \
            "Intake · right to audit", (a.get("rta") or "—").lower()
    if kind == "owner":
        return (1.0 if a.get("owner") else 0.0), "Intake · relationship owner", \
            "assigned" if a.get("owner") else "none"
    return None, None, None


def control_matrix(a, ext, domains):
    """Status of every unified control from all its evidence sources."""
    asked = {q[0]: q[1] for d in domains for q in d["questions"]}
    clauses = contract_results(a)
    rows = []
    for cid, name, iso, tsc, sources in ct.CONTROLS:
        evidence, vals = [], []
        for src in sources:
            v, label, note = source_value(src, a, ext, asked, clauses)
            if label is None:
                continue
            evidence.append((label, v, note))
            if v is not None:
                vals.append(v)
        score = sum(vals) / len(vals) if vals else None
        status = ("Not assessed" if score is None else "Met" if score >= 0.8
                  else "Partial" if score >= 0.4 else "Gap")
        rows.append({"id": cid, "name": name, "iso": iso, "tsc": tsc,
                     "nist": ct.NIST_MAP.get(cid, []),
                     "evidence": evidence, "score": score, "status": status,
                     "sources": len(vals)})
    return rows


STATUS_RANK = {"Met": 3, "Partial": 2, "Gap": 1, "Not assessed": 0}


def framework_rollup(rows, key):
    """Best status per framework reference: a reference is satisfied when
    at least one control mapped to it is (the crosswalk convention)."""
    best = {}
    for r in rows:
        for ref in r[key]:
            if STATUS_RANK[r["status"]] > STATUS_RANK.get(best.get(ref), -1):
                best[ref] = r["status"]
    return best


def contract_findings(a):
    clauses = contract_results(a)
    answers = a.get("answers", {})
    cross_border = a.get("irq_crossborder") or len(a.get("regions", [])) > 1
    f = []
    for doc in a.get("docs", []):
        res = {k: v for k, v in clauses.items() if ct.CLAUSE[k][1] == doc}
        if not res:
            f.append(("Low", "%s ticked but not loaded" % doc,
                      "Upload the %s or load the sample so its clauses can be "
                      "checked." % doc, "CC9.2"))
            continue
        missing = [k for k, v in res.items() if v[0] == "Missing"
                   and not (k == "dpa_transfer" and not cross_border)]
        critical = [k for k in missing if ct.CLAUSE[k][5] and not (
            k == "msa_rta" and a.get("tier") != 1 and a.get("rta") != "Yes")]
        for k in critical:
            iso, tsc = clause_refs(k)
            f.append(("High", "%s is missing: %s" % (doc, ct.CLAUSE[k][2]),
                      "No clause found in the %s for a critical term." % doc,
                      "ISO %s · %s" % (", ".join(iso), ", ".join(tsc))))
        rest = [k for k in missing if k not in critical]
        if rest:
            iso = sorted({i for k in rest for i in clause_refs(k)[0]})
            f.append(("Medium", "%s — %d clause%s missing" % (
                doc, len(rest), "s" if len(rest) > 1 else ""),
                "; ".join(ct.CLAUSE[k][2] for k in rest) + ".",
                "ISO " + ", ".join(iso)))
        for k, (status, snip, note) in res.items():
            if status == "Partial":
                iso, tsc = clause_refs(k)
                f.append(("Medium", "%s: %s is weak" % (doc, ct.CLAUSE[k][2]),
                          "%s. Contract says: “%s”" % (note[0].upper() + note[1:],
                                                        snip),
                          "ISO %s · %s" % (", ".join(iso), ", ".join(tsc))))
    # contradictions between what we were told and what the contract says
    if "MSA" in a.get("docs", []) and \
            clauses.get("msa_rta", ("",))[0] == "Missing" and a.get("rta") == "Yes":
        f.append(("High", "Right to audit not in the contract",
                  "Intake says we have a right to audit, but the MSA contains "
                  "no audit clause. Treat the right as unconfirmed.",
                  "ISO A.5.22, A.5.35 · CC9.2"))
    breach = clauses.get("dpa_breach", ("",))[0]
    if answers.get("inc2") == "Yes" and breach in ("Partial", "Missing"):
        f.append(("Medium", "72-hour breach notice claimed, not contracted",
                  "The vendor answered Yes to 72-hour breach notification, but "
                  "the DPA %s." % ("commits to a longer or open-ended deadline"
                                    if breach == "Partial"
                                    else "has no breach clause"),
                  "ISO A.5.24, A.6.8 · CC7.4"))
    if answers.get("prv5") == "Yes" and \
            clauses.get("dpa_transfer", ("",))[0] == "Missing":
        f.append(("Medium", "Transfer mechanism claimed, not contracted",
                  "The vendor says SCCs / adequacy are in place, but the DPA "
                  "doesn't include them.", "ISO A.5.14, A.5.34 · P6"))
    personal = set(a.get("data", [])) & {"Customer PII", "Employee PII",
                                          "Health / PHI"}
    if personal and "DPA" not in a.get("docs", []):
        f.append(("Medium", "No DPA on file",
                  "The vendor processes personal data (%s); GDPR Art. 28 and "
                  "the DPDP Act require a written processing agreement."
                  % ", ".join(sorted(personal)), "ISO A.5.34 · P6"))
    return f


def scope_check(a, ext):
    """Does the report's scope cover what we actually buy and where?"""
    scope = ext.get("_scope") or {}
    out = {"regions_missing": [], "product": None, "report_regions":
           scope.get("regions", []), "system": scope.get("system")}
    ours = [r for r in a.get("regions", []) if r != "Other"]
    if scope.get("regions") and ours:
        out["regions_missing"] = [r for r in ours
                                  if r not in scope["regions"]]
    product = (a.get("product") or "").strip()
    hay = ext.get("_haystack", "")
    if product and hay:
        low = product.lower()
        if any(low in x["text"].lower() for x in scope.get("exclusions", [])):
            out["product"] = "excluded"
        elif low not in hay:
            out["product"] = "not named"
        else:
            out["product"] = "named"
    return out


def evidence_findings(a, ext):
    """Findings from the reviewer's work on the report: review queue, CUECs,
    subservice organisations, exceptions, scope and document triage."""
    f = []
    queue = [q for q in ext.get("_queue", [])
             if not a.get(REVIEW_PREFIX + "qc_" + q)]
    if queue:
        f.append(("Medium", "%d extracted value%s awaiting reviewer "
                  "confirmation" % (len(queue), "s" if len(queue) > 1 else ""),
                  "Low-confidence or conflicting values: %s. Confirm them on "
                  "the Evidence step before relying on this assessment."
                  % ", ".join(pi.FIELD_LABEL.get(q, q) for q in queue),
                  "CC9.2"))
    cuecs = ext.get("_cuecs", [])
    state = ext.get("_cuec_state", [])
    no_owner = [c["text"] for c, s in zip(cuecs, state) if not s["owner"]
                and s["status"] != "Not applicable"]
    open_ = [c["text"] for c, s in zip(cuecs, state) if s["owner"]
             and s["status"] in ("Not assessed", "In progress")]
    if no_owner:
        f.append(("High" if a.get("tier") == 1 else "Medium",
                  "%d CUEC%s with no internal owner" % (
                      len(no_owner), "s" if len(no_owner) > 1 else ""),
                  "The report's assurance depends on controls we operate. "
                  "Unowned: " + " · ".join(t[:90] for t in no_owner), "CC2.3"))
    if open_:
        f.append(("Low", "%d CUEC%s owned but not yet confirmed" % (
            len(open_), "s" if len(open_) > 1 else ""),
            "Collect evidence that these are operating: " +
            " · ".join(t[:90] for t in open_), "CC2.3"))
    subs = ext.get("_subservice", [])
    sub_state = ext.get("_sub_state", [])
    if ext.get("subservice_method") == "Carve-out":
        none = [o["name"] for o, s in zip(subs, sub_state)
                if s == "Not requested"]
        waiting = [o["name"] for o, s in zip(subs, sub_state)
                   if s == "Requested"]
        if none:
            f.append(("Medium", "No downstream evidence for carved-out "
                      "sub-processors",
                      "Request a SOC 2 / ISO 27001 or the vendor's oversight "
                      "evidence for: %s." % ", ".join(none), "CC9.2"))
        if waiting:
            f.append(("Low", "Downstream evidence requested",
                      "Awaiting evidence for: %s." % ", ".join(waiting),
                      "CC9.2"))
    for e, s in zip(ext.get("_exceptions", []), ext.get("_exc_state", [])):
        where = "%s%s" % (e["control"], " (p.%s)" % e["page"]
                          if e.get("page") else "")
        if s["decision"] == "Escalate":
            f.append(("High", "Exception escalated — %s" % where, e["text"],
                      e["control"]))
        elif s["decision"] == "Request remediation":
            f.append(("Medium", "Remediation requested — %s" % where,
                      e["text"] + " Track remediation evidence to closure.",
                      e["control"]))
        elif s["decision"] == "Undecided":
            f.append(("Medium", "Exception not yet decided — %s" % where,
                      e["text"] + " Accept, accept with a compensating "
                      "control, request remediation or escalate.",
                      e["control"]))
    sc = scope_check(a, ext)
    if sc["regions_missing"]:
        f.append(("High", "Processing region outside the report scope",
                  "Our data is processed in %s, but the SOC 2 scope covers "
                  "%s only. The report gives no assurance for those regions."
                  % (", ".join(sc["regions_missing"]),
                     ", ".join(sc["report_regions"])), "CC9.2 · A.5.23"))
    if sc["product"] == "excluded":
        f.append(("High", "The product we use is excluded from the report",
                  "“%s” appears in the report's scope exclusions."
                  % a.get("product"), "CC9.2"))
    elif sc["product"] == "not named":
        f.append(("Medium", "The product we use isn't named in the report",
                  "“%s” doesn't appear in the report; the system examined is "
                  "“%s”. Confirm it covers the service we buy."
                  % (a.get("product"), sc["system"] or "unknown"), "CC9.2"))
    info = a.get("pdf")
    if info and info.get("status") not in ("OK", None):
        f.append(("Medium", "Document triage: %s" % info["status"],
                  " ".join(info.get("issues", [])), "CC9.2"))
    return f


def obligation_matrix(a, ext):
    """Cross-document review questions: SOC 2 vs MSA vs DPA (vs intake)."""
    cl = contract_results(a)
    docs = a.get("docs", [])
    no_report = ext["report_type"] == "None"

    def clause(cid):
        doc = ct.CLAUSE[cid][1]
        if doc not in docs or cid not in cl:
            return None, "%s not provided" % doc
        status, snip, note = cl[cid]
        return status, (note + " — " if note else "") + (snip or "no clause "
                                                          "found")
    rows = []
    s, d = clause("msa_soc2")
    rows.append(("Does the contract require a current SOC 2 Type II?",
                 "MSA", s, d))
    s, d = clause("dpa_breach")
    s2, d2 = clause("msa_breach")
    rows.append(("Is there a breach-notification deadline?", "DPA / MSA",
                 s or s2, d if s else d2))
    s, d = clause("dpa_subp")
    sub = ext.get("subservice_method")
    extra = " · SOC 2: %s" % sub.lower() if sub not in (None, "Unknown") \
        else ""
    rows.append(("Are sub-processors governed and notified?",
                 "DPA / SOC 2", s, d + extra))
    sc = scope_check(a, ext)
    if no_report:
        rows.append(("Does the SOC 2 scope support the service we buy?",
                     "SOC 2 / SOW", None, "no SOC 2 provided"))
    else:
        gaps = []
        if sc["regions_missing"]:
            gaps.append("regions %s not in scope" % ", ".join(
                sc["regions_missing"]))
        if sc["product"] in ("excluded", "not named"):
            gaps.append("product %s" % sc["product"])
        missing = [c for c in a.get("required", [])
                   if c not in ext.get("tsc_categories", [])]
        if missing:
            gaps.append("%s not examined" % ", ".join(missing))
        rows.append(("Does the SOC 2 scope support the service we buy?",
                     "SOC 2 / SOW / intake",
                     "Missing" if sc["regions_missing"] or sc["product"] ==
                     "excluded" else "Partial" if gaps else "Met",
                     "; ".join(gaps) or "system: %s · regions: %s" % (
                         sc["system"] or "—",
                         ", ".join(sc["report_regions"]) or "—")))
    s, d = clause("dpa_delete")
    rows.append(("Does the vendor have data-deletion obligations?", "DPA",
                 s, d))
    s, d = clause("msa_rta")
    if s == "Missing" and a.get("rta") == "Yes":
        d = "intake says Yes, but no audit clause in the MSA"
    rows.append(("Do we hold a right to audit?", "MSA / intake", s, d))
    cross = a.get("irq_crossborder") or len(a.get("regions", [])) > 1
    s, d = clause("dpa_transfer")
    rows.append(("Is there a cross-border transfer mechanism?", "DPA",
                 s if cross else "Not needed" if s is None else s,
                 d if cross else "no cross-border processing declared"))
    return rows


SIGNOFF = ["Pending", "Approve", "Approve with conditions", "Reject",
           "Escalate to risk committee"]


def evidence_rows(a):
    """Evidence register rows for the documents actually in this review."""
    reg = a.get("evidence", {})
    keep = []
    if a.get("extracted") and a["extracted"].get("report_type") != "None":
        keep.append("SOC 2")
    keep += [d for d in a.get("docs", []) if a.get("contracts", {}).get(d)]
    return [reg[k] for k in keep if k in reg]


def matrix_csv(matrix):
    rows = ["Control ID,Control,ISO 27001:2022,SOC 2 TSC,NIST 800-53 Rev.5,"
            "Status,Score,Evidence"]
    for r in matrix:
        ev = "; ".join("%s (%s)" % (l, n) for l, _, n in r["evidence"])
        rows.append('%s,"%s","%s","%s","%s",%s,%s,"%s"' % (
            r["id"], r["name"], " ".join(r["iso"]), " ".join(r["tsc"]),
            " ".join(r["nist"]), r["status"], "" if r["score"] is None else
            "%.2f" % r["score"], ev.replace('"', "'")))
    return "\n".join(rows)


def jira_csv(findings, vendor):
    """Findings as a CSV that Jira's importer (or ServiceNow) can map."""
    import csv
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["Summary", "Issue Type", "Priority", "Labels", "Description"])
    for sev, title, detail, ref in findings:
        wr.writerow(["[%s] %s" % (vendor, title), "Task",
                     {"High": "High", "Medium": "Medium", "Low": "Low"}[sev],
                     "vendor-risk cc9.2",
                     "%s\n\nReference: %s" % (detail, ref)])
    return buf.getvalue()


BAND_COLOR = {"Low": "#1FAF5A", "Medium": "#F2C12E",
              "High": "#FF7A2F", "Critical": "#F0405A"}
SEV_COLOR = {"High": "#F0405A", "Medium": "#F2C12E", "Low": "#1FAF5A"}
CAT_COLOR = {"Security": "#1FAF5A", "Availability": "#3D5AFE",
             "Confidentiality": "#6B6B6B", "Processing Integrity": "#4DD0E1",
             "Privacy": "#FF7A2F"}
TIER_LABEL = {1: "Tier 1 (high)", 2: "Tier 2 (moderate)", 3: "Tier 3 (low)"}
TIER_COLOR = {1: "#F0405A", 2: "#F2C12E", 3: "#1FAF5A"}
STEPS = ["Overview", "Vendor Scope", "Inherent Risk", "TSC Scope",
         "Control Questionnaire", "Evidence", "Dashboard"]
ANSWER_COLOR = {"Yes": "#1FAF5A", "Partial": "#F2C12E", "No": "#F0405A",
                "N/A": "#9CA3AF"}

# ----------------------------------------------------------------------
# Visual helpers (inline SVG / HTML — no chart dependencies)
# ----------------------------------------------------------------------
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{--ink:#0E0E0E;--muted:#6B7280;--line:#E5E7EB;--track:#ECEEF1;
  --green:#1FAF5A;--green-2:#5BE39A}
html,body,.stApp{font-family:'Inter',sans-serif}
header[data-testid="stHeader"]{display:none}
.block-container{max-width:1240px;padding-top:1.2rem;padding-bottom:3rem}
.nav{display:flex;align-items:center;justify-content:space-between;
  background:var(--ink);color:#fff;border-radius:12px;padding:14px 22px;
  margin-bottom:26px;gap:16px;flex-wrap:wrap}
.brand{font-weight:700;font-size:1.25rem;letter-spacing:-.02em;color:#fff}
.brand b{color:var(--green-2)}
.nav-r{display:flex;align-items:center;gap:14px}
.dev{background:#FFF4D6;color:#8A5A00;border:1px solid #F2C12E;border-radius:999px;
  padding:3px 10px;font-size:.7rem;font-weight:700;letter-spacing:.04em}
.by{display:flex;align-items:center;gap:8px;font-size:.8rem;color:#fff;
  font-weight:600}
.av{width:30px;height:30px;border-radius:50%;background:var(--green);color:#fff;
  display:flex;align-items:center;justify-content:center;font-weight:700}
.by small{display:block;color:#9CA3AF;font-size:.64rem;font-weight:400;
  line-height:1.1}
.hero{text-align:center;margin:6px 0 10px}
.hero .ico{display:inline-flex;vertical-align:middle;margin-right:12px}
.hero h1{display:inline;vertical-align:middle;font-size:1.8rem;font-weight:700;
  letter-spacing:-.03em;color:var(--ink);padding:0}
.crumb{font-size:.74rem;color:var(--muted);margin-top:8px}
.crumb b{color:var(--ink)}
.tabs{display:flex;gap:26px;border-bottom:1px solid var(--line);margin:16px 0 24px;
  overflow-x:auto}
.tabs span{font-size:.8rem;color:var(--muted);padding:8px 0;white-space:nowrap}
.tabs span.on{color:var(--ink);font-weight:600;border-bottom:2px solid var(--ink)}
.tabs span.done{color:var(--green)}
.h-page{font-size:1.8rem;font-weight:700;letter-spacing:-.02em;color:var(--ink);
  margin:0 0 4px}
.sub{color:var(--muted);font-size:.9rem;margin-bottom:10px}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;
  box-shadow:0 1px 2px rgba(16,24,40,.05);margin-bottom:8px;overflow:hidden}
.card-h{display:flex;justify-content:space-between;align-items:center;
  padding:14px 18px;border-bottom:1px solid var(--line);font-weight:600;
  font-size:1rem;color:var(--ink)}
.card-b{padding:18px}
.row{display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.bar{margin:0 0 12px}
.bar-l{display:flex;justify-content:space-between;font-size:.76rem;color:#374151;
  margin-bottom:4px;gap:8px}
.bar-t{height:12px;background:var(--track);border-radius:2px;overflow:hidden}
.bar-f{height:100%;border-radius:2px}
.muted{color:var(--muted)}
.lg{display:flex;justify-content:space-between;font-size:.78rem;padding:4px 0;
  color:#374151;gap:10px}
.lg span:last-child{text-align:right}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px}
.kpis{display:flex;gap:34px;margin-top:14px;padding-top:12px;flex-wrap:wrap;
  border-top:1px solid var(--line)}
.kpi small{display:block;font-size:.7rem;font-weight:600;color:var(--ink)}
.kpi span{font-size:1.35rem;color:#222}
.pill{display:inline-block;padding:3px 11px;border-radius:999px;font-size:.76rem;
  font-weight:600;margin:3px 6px 3px 0;border:1px solid}
.find{display:flex;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}
.find:last-child{border-bottom:none}
.sev{font-size:.64rem;font-weight:700;border-radius:4px;padding:3px 7px;color:#fff;
  height:fit-content;min-width:58px;text-align:center}
.find b{font-size:.88rem;color:var(--ink)}
.find p{margin:2px 0 0;font-size:.8rem;color:#4B5563}
.ref{font-family:ui-monospace,monospace;font-size:.7rem;color:var(--muted)}
.feat{border:1px solid var(--line);border-radius:10px;padding:16px}
.feat .n{width:28px;height:28px;border-radius:50%;background:#E8F8EF;
  color:var(--green);font-weight:700;display:flex;align-items:center;
  justify-content:center;font-size:.8rem;margin-bottom:10px}
.feat b{display:block;font-size:.9rem;color:var(--ink);margin-bottom:4px}
.feat p{font-size:.78rem;color:#4B5563;margin:0}
.banner{background:linear-gradient(120deg,#E9FBF1,#CFF5E0 60%,#B8F0D2);
  border-radius:14px;padding:28px 30px;margin:4px 0 18px}
.banner h2{font-size:1.5rem;letter-spacing:-.02em;margin:0 0 8px;color:var(--ink);
  padding:0}
.banner p{margin:0;color:#1F3B2C;font-size:.93rem;line-height:1.55;
  max-width:900px}
.tgs{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.tg{border:1px solid;border-radius:10px;padding:14px 16px}
.tg-h{display:flex;align-items:center;gap:2px;margin-bottom:6px;font-size:.95rem}
.tg-you{margin-left:auto;font-size:.66rem;font-weight:700;background:#111;
  color:#fff;border-radius:999px;padding:2px 8px}
.tg-k{font-size:.66rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
  color:var(--muted);margin-top:9px}
.tg p,.tg li{font-size:.78rem;color:#374151;margin:2px 0 0;line-height:1.45}
.tg ul{margin:2px 0 0;padding-left:16px}
table.mx{width:100%;border-collapse:collapse;font-size:.78rem;min-width:760px}
table.mx th{text-align:left;font-size:.66rem;font-weight:700;letter-spacing:.05em;
  text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line);
  padding:8px 10px;background:#FAFAFB}
table.mx td{vertical-align:top;padding:10px;border-bottom:1px solid var(--line);
  color:#374151;line-height:1.4}
table.mx td.q{font-size:.76rem;color:#4B5563;max-width:420px}
.rn{font-size:.7rem;color:var(--muted)}
.ev{display:inline-flex;align-items:center;gap:5px;border:1px solid;border-radius:6px;
  padding:2px 7px;margin:2px 4px 2px 0;font-size:.7rem;color:#374151;background:#fff}
.ev i{width:7px;height:7px;border-radius:50%;display:inline-block}
.ev em{color:var(--muted);font-style:normal}
.tour{background:#0E0E0E;color:#E5E7EB;border-radius:12px;padding:16px 20px;
  margin:0 0 10px}
.tour-h{display:flex;justify-content:space-between;align-items:center;
  font-size:.74rem;color:#5BE39A;font-weight:600;letter-spacing:.02em}
.tour-dots{display:flex;gap:5px}
.tour-t{font-size:1.05rem;font-weight:700;color:#fff;margin:6px 0 4px}
.tour p{margin:0;font-size:.86rem;line-height:1.55;color:#D1D5DB}
.tour b{color:#fff}
.strip{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 16px}
.strip .st{display:flex;align-items:center;gap:7px;font-size:.8rem;color:#374151;
  border:1px solid var(--line);border-radius:999px;padding:5px 12px 5px 5px}
.strip .st span{width:20px;height:20px;border-radius:50%;background:#E8F8EF;
  color:var(--green);font-weight:700;font-size:.7rem;display:flex;
  align-items:center;justify-content:center}
.foot{text-align:center;color:var(--muted);font-size:.74rem;margin-top:26px}
.chain{margin-top:12px;font-size:.82rem;color:#374151;background:#F6F7F9;
  border-radius:8px;padding:10px 12px}
.chain span{color:#B45309}
.tabs-m{display:none}
.card-b > img{display:block;margin:0 auto}
[data-testid="stMarkdownContainer"] table{display:block;overflow-x:auto}

/* ---------- tablet: 641–1100px ---------- */
@media (max-width:1100px){
  .block-container{padding-left:1.25rem;padding-right:1.25rem}
  .tabs{gap:16px}
  .tabs span{font-size:.76rem}
  [class*="st-key-grid4"] [data-testid="stHorizontalBlock"],
  .st-key-grid3 [data-testid="stHorizontalBlock"]{flex-wrap:wrap}
  [class*="st-key-grid4"] [data-testid="stColumn"],
  .st-key-grid3 [data-testid="stColumn"]{min-width:calc(50% - 1rem) !important}
  [class*="st-key-stack_"] [data-testid="stHorizontalBlock"]{flex-wrap:wrap}
  [class*="st-key-stack_"] > div > [data-testid="stHorizontalBlock"] >
    [data-testid="stColumn"]{min-width:100% !important}
}
@media (max-width:900px){
  [class*="st-key-split_"] > div > [data-testid="stHorizontalBlock"]{flex-wrap:wrap}
  [class*="st-key-split_"] > div > [data-testid="stHorizontalBlock"] >
    [data-testid="stColumn"]{min-width:100% !important}
}

/* ---------- phone: ≤ 640px ---------- */
@media (max-width:640px){
  .block-container{padding:.6rem .85rem 2rem}
  .nav{padding:10px 14px;border-radius:10px;margin-bottom:14px;gap:8px}
  .brand{font-size:1.02rem}
  .dev{font-size:.6rem;padding:2px 8px}
  .av{width:26px;height:26px;font-size:.8rem}
  .by{font-size:.72rem}
  .hero{margin:0 0 6px}
  .hero .ico img{width:34px !important}
  .hero h1{font-size:1.25rem;line-height:1.3}
  .crumb{font-size:.66rem;line-height:1.5}
  .tabs{display:none}
  .tabs-m{display:block;margin:10px 0 16px;font-size:.8rem;color:var(--muted)}
  .tabs-m b{color:var(--ink)}
  .pbar{height:5px;background:var(--track);border-radius:3px;margin-top:6px;
    overflow:hidden}
  .pbar i{display:block;height:100%;background:var(--green);border-radius:3px}
  .h-page{font-size:1.35rem}
  .sub{font-size:.84rem}
  .banner{padding:18px 18px;border-radius:12px}
  .banner h2{font-size:1.2rem;line-height:1.3}
  .banner p{font-size:.86rem}
  .card-h{padding:12px 14px;font-size:.95rem}
  .card-b{padding:14px}
  .kpis{gap:16px 22px}
  .kpi span{font-size:1.15rem}
  .row{gap:14px;justify-content:center}
  .tour{padding:14px 16px}
  .tour-t{font-size:.95rem}
  .tour p{font-size:.8rem}
  .find{gap:8px}
  .sev{min-width:48px}
  /* button rows stay side by side instead of stacking */
  [class*="st-key-btnrow"] [data-testid="stHorizontalBlock"]{flex-wrap:nowrap;
    gap:.5rem}
  [class*="st-key-btnrow"] [data-testid="stColumn"]{min-width:0 !important;
    flex:1 1 0 !important;width:auto !important}
  .st-key-btnrow_nav [data-testid="stColumn"]:nth-child(2),
  .st-key-btnrow_end [data-testid="stColumn"]:nth-child(2),
  .st-key-btnrow_tour [data-testid="stColumn"]:nth-child(4){display:none}
  [class*="st-key-btnrow"] button{padding-left:.4rem;padding-right:.4rem}
  [class*="st-key-btnrow"] button p{font-size:.8rem;white-space:nowrap;
    overflow:hidden;text-overflow:ellipsis}
  /* tables become stacked cards */
  table.mx{min-width:0}
  table.mx, table.mx tbody, table.mx tr, table.mx td{display:block;width:100%}
  table.mx tr:has(th){display:none}
  table.mx tr{border:1px solid var(--line);border-radius:10px;padding:4px 12px;
    margin-bottom:10px;background:#fff}
  table.mx td{border-bottom:1px solid #F1F2F4;padding:8px 0}
  table.mx tr td:last-child{border-bottom:none}
  table.mx td[data-l]::before{content:attr(data-l);display:block;font-size:.6rem;
    font-weight:700;letter-spacing:.05em;text-transform:uppercase;
    color:var(--muted);margin-bottom:3px}
  table.mx td.q{max-width:none}
  .tgs{grid-template-columns:1fr}
  [data-testid="stButtonGroup"] button{min-height:42px}
}
.stButton button[kind="primary"]{background:var(--green);border-color:var(--green);
  font-weight:600}
.stButton button[kind="primary"]:hover{background:#17924A;border-color:#17924A}
</style>
"""


def html(s):
    st.html(s)


def svg_img(svg, width=None):
    """Embed an SVG as a data-URI <img>: st.html sanitises inline <svg> away."""
    svg = svg.replace("<svg ", "<svg xmlns='http://www.w3.org/2000/svg' "
                      "font-family='Inter, Helvetica, Arial, sans-serif' ", 1)
    return ("<img src='data:image/svg+xml;base64,%s' style='%s' alt=''/>"
            % (base64.b64encode(svg.encode()).decode(),
               "width:%s;max-width:100%%" % width if width else "max-width:100%"))


def donut(segments, center, sub="", size=190, stroke=20, total=None,
          center_size=34):
    """SVG donut from [(value, color)]; total defaults to the sum of values."""
    total = total or sum(v for v, _ in segments) or 1
    r = (size - stroke) / 2
    c = size / 2
    circ = 2 * math.pi * r
    parts = ["<circle cx='%s' cy='%s' r='%s' fill='none' stroke='#ECEEF1' "
             "stroke-width='%s'/>" % (c, c, r, stroke)]
    offset = 0.0
    gap = 3 if len([v for v, _ in segments if v]) > 1 else 0
    for v, color in segments:
        if not v:
            continue
        seg = circ * v / total
        parts.append(
            "<circle cx='%s' cy='%s' r='%s' fill='none' stroke='%s' "
            "stroke-width='%s' stroke-dasharray='%.2f %.2f' "
            "stroke-dashoffset='%.2f' transform='rotate(-90 %s %s)'/>"
            % (c, c, r, color, stroke, max(seg - gap, 0.1), circ,
               -offset, c, c))
        offset += seg
    parts.append("<text x='%s' y='%s' text-anchor='middle' font-size='11' "
                 "font-weight='600' fill='#111'>%s</text>"
                 % (c, c - center_size * 0.62, sub))
    parts.append("<text x='%s' y='%s' text-anchor='middle' font-size='%s' "
                 "fill='#111'>%s</text>"
                 % (c, c + center_size * 0.38, center_size, center))
    return svg_img("<svg width='%d' height='%d' viewBox='0 0 %d %d'>%s</svg>"
                   % (size, size, size, size, "".join(parts)))


def bar(label, frac, color, note=""):
    return ("<div class='bar'><div class='bar-l'><span>%s</span>"
            "<span class='muted'>%s</span></div><div class='bar-t'>"
            "<div class='bar-f' style='width:%.0f%%;background:%s'></div>"
            "</div></div>" % (label, note, max(0, min(1, frac)) * 100, color))


def legend(label, value, color):
    return ("<div class='lg'><span><span class='dot' style='background:%s'>"
            "</span>%s</span><span>%s</span></div>" % (color, label, value))


def how(text):
    """Small 'how it's calculated' note at the foot of a dashboard card."""
    return ("<div style='margin-top:12px;padding:9px 11px;background:#F6F7F9;"
            "border-radius:8px;font-size:.72rem;line-height:1.5;color:#4B5563'>"
            "%s</div>" % text)


STATUS_COLOR = {"Met": "#1FAF5A", "Partial": "#F2C12E", "Gap": "#F0405A",
                "Not assessed": "#9CA3AF", "Missing": "#F0405A"}


def status_pill(status):
    c = STATUS_COLOR[status]
    return ("<span class='pill' style='color:%s;border-color:%s;white-space:"
            "nowrap'>%s</span>" % (c, c, status))


CONF_COLOR = {"High": "#1FAF5A", "Medium": "#F2C12E", "Low": "#F0405A"}
CUEC_STATUS = ["Not assessed", "In progress", "Implemented", "Not applicable"]
SUB_EVIDENCE = ["Not requested", "Requested", "Received: SOC 2",
                "Received: ISO 27001", "Received: other evidence",
                "Not needed"]
EXC_DECISIONS = ["Undecided", "Accept", "Accept with compensating control",
                 "Request remediation", "Escalate"]


def conf_pill(conf):
    if not conf:
        return "<span class='pill' style='color:#9CA3AF;border-color:#D1D5DB'>" \
               "—</span>"
    c = CONF_COLOR.get(conf, "#9CA3AF")
    return ("<span class='pill' style='color:%s;border-color:%s'>%s</span>"
            % (c, c, conf))


def band_scale(value):
    """Low / Medium / High / Critical strip with a marker at `value`."""
    segs = [("Low", 0, 20), ("Medium", 20, 40), ("High", 40, 65),
            ("Critical", 65, 100)]
    strip = "".join(
        "<div style='width:%d%%;background:%s;height:8px'></div>"
        % (hi - lo, BAND_COLOR[b]) for b, lo, hi in segs)
    labels = "".join(
        "<span style='width:%d%%;font-size:.62rem;color:#6B7280'>%s</span>"
        % (hi - lo, b) for b, lo, hi in segs)
    return ("<div style='margin-top:12px;position:relative'>"
            "<div style='display:flex;border-radius:4px;overflow:hidden'>%s</div>"
            "<div style='position:absolute;top:-4px;left:calc(%d%% - 2px);"
            "width:4px;height:16px;background:#111;border-radius:2px'></div>"
            "<div style='display:flex;margin-top:4px'>%s</div></div>"
            % (strip, max(1, min(99, value)), labels))


def card(title, body, icon_svg=""):
    return ("<div class='card'><div class='card-h'><span>%s</span>%s</div>"
            "<div class='card-b'>%s</div></div>" % (title, icon_svg, body))


def icon(kind):
    paths = {
        "map": "<path d='M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2z M9 4v14 M15 6v14'/>",
        "shield": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/>",
        "grid": "<path d='M4 4h6v6H4z M14 4h6v6h-6z M4 14h6v6H4z M14 14h6v6h-6z'/>",
        "chart": "<path d='M4 20V4 M4 20h16 M7 15l4-5 3 3 5-6'/>",
        "doc": "<path d='M6 3h8l4 4v14H6z M14 3v4h4'/>",
        "search": "<circle cx='11' cy='11' r='6'/><path d='M20 20l-4.5-4.5'/>",
    }
    return svg_img("<svg width='22' height='22' viewBox='0 0 24 24' fill='none' "
                   "stroke='#111' stroke-width='1.6' stroke-linejoin='round'>"
                   "%s</svg>" % paths[kind])


def header(step):
    shield = ("<svg width='46' height='46' viewBox='0 0 46 46'><circle cx='23' "
              "cy='23' r='22' fill='#5BE39A' stroke='#111' stroke-width='1.5'/>"
              "<path d='M23 11l10 4v7c0 6.5-4.3 10.5-10 12-5.7-1.5-10-5.5-10-12v-7z'"
              " fill='none' stroke='#111' stroke-width='1.6'/><path d='M18 23l3.5 "
              "3.5L28 20' fill='none' stroke='#111' stroke-width='1.8'/></svg>")
    shield = svg_img(shield)
    tabs = "".join(
        "<span class='%s'>%s%s</span>"
        % ("on" if i == step else "done" if i < step else "",
           "✓ " if i < step else "", n)
        for i, n in enumerate(STEPS))
    html("<div class='nav'><div class='brand'>vendor<b>·</b>trust<b>·</b>evaluator</div>"
         "<div class='nav-r'>"
         "<span class='dev'>● IN DEVELOPMENT</span><div class='by'>"
         "<div class='av'>%s</div><div><small>Designed by</small>%s</div></div>"
         "</div></div>"
         "<div class='hero'><span class='ico'>%s</span><h1>Based on SOC 2 and "
         "ISO 27001</h1><div class='crumb'>Vendor assessments › SOC 2 › "
         "ISO 27001 › Trust Services Criteria › <b>%s</b></div></div>"
         "<div class='tabs'>%s</div>%s"
         % (DESIGNER[0], DESIGNER, shield, STEPS[step], tabs, (
             "<div class='tabs-m'><div>Step %d of 6 · <b>%s</b></div>"
             "<div class='pbar'><i style='width:%d%%'></i></div></div>"
             % (step, STEPS[step], round(100 * step / 6)) if step else "")))


TIER_GUIDE = {
    1: {"range": "Inherent ≥ 65",
        "escalate": ["> 100k records of sensitive data",
                     "admin / privileged access + credential handling"],
        "examples": "Payment processors, payroll with bank data, managed IT "
                    "with admin access, core cloud hosting",
        "evidence": "SOC 2 Type II expected · right to audit expected",
        "review": "Review every 3 months"},
    2: {"range": "Inherent 40 – 64",
        "escalate": ["vendor code runs in our environment",
                     "our data trains AI / ML models",
                     "PHI / financial data crosses borders",
                     "business-critical and customer-facing"],
        "examples": "CRM / marketing SaaS holding customer PII, analytics "
                    "reading production data, HR tools",
        "evidence": "SOC 2 Type II or ISO 27001",
        "review": "Review every 6 months"},
    3: {"range": "Inherent < 40",
        "escalate": [],
        "examples": "Hardware suppliers, open-source libraries, tools with "
                    "internal or no data and no system access",
        "evidence": "Self-attestation acceptable",
        "review": "Review every 12 months"},
}


def tier_banner(current=None, required=None):
    """Explain what falls under each tier and how it's decided."""
    req = required or ["Security"]
    cols = ""
    for t in (1, 2, 3):
        g = TIER_GUIDE[t]
        n = sum(len(d["questions"]) for d in qn.domains_for(req, t))
        on = t == current
        esc = ("<div class='tg-k'>Also raised to Tier %d by</div><ul>%s</ul>"
               % (t, "".join("<li>%s</li>" % e for e in g["escalate"]))
               if g["escalate"] else
               "<div class='tg-k'>Escalation</div><p>None — only the score "
               "places a vendor here</p>")
        cols += (
            "<div class='tg' style='border-color:%s;%s'>"
            "<div class='tg-h'><span class='dot' style='background:%s'></span>"
            "<b>%s</b>%s</div>"
            "<div class='tg-k'>Criteria</div><p>%s</p>%s"
            "<div class='tg-k'>Typical vendors</div><p>%s</p>"
            "<div class='tg-k'>Due diligence</div><p><b>%s</b> questionnaire "
            "(%d questions%s) · %s · %s</p></div>"
            % (TIER_COLOR[t] if on else "#E5E7EB",
               "box-shadow:0 0 0 2px %s33;" % TIER_COLOR[t] if on else "",
               TIER_COLOR[t], TIER_LABEL[t],
               "<span class='tg-you'>This vendor</span>" if on else "",
               g["range"], esc, g["examples"], qn.TIER_DEPTH[t], n,
               " for this scope" if required else "", g["evidence"],
               g["review"]))
    html("<div class='card'><div class='card-h'><span>Vendor tiers — what "
         "falls where</span>%s</div><div class='card-b'>"
         "<p style='font-size:.82rem;color:#374151;margin:0 0 12px'>"
         "<b>Inherent score</b> = 0.45 × data sensitivity + 0.35 × access + "
         "0.20 × criticality (each 0–100; data uses the most sensitive type "
         "shared). The score sets the tier; the escalation rules below can "
         "only raise it, never lower it.</p>"
         "<div class='tgs'>%s</div></div></div>" % (icon("shield"), cols))


def page_title(title, sub):
    html("<div class='h-page'>%s</div><div class='sub'>%s</div>" % (title, sub))


def nav_buttons(back=None, back_label="← Back", nxt=None, next_label="",
                next_disabled=False):
    c1, _, c2 = st.container(key="btnrow_nav").columns([1, 2, 1])
    if back is not None and c1.button(back_label, use_container_width=True):
        goto(back)
    if nxt is not None and c2.button(next_label, type="primary",
                                     use_container_width=True,
                                     disabled=next_disabled):
        goto(nxt)


# ----------------------------------------------------------------------
# App shell
# ----------------------------------------------------------------------
html(CSS)

if "step" not in st.session_state:
    st.session_state.step = 0
if "a" not in st.session_state:
    st.session_state.a = {}


def goto(n):
    st.session_state.step = n
    st.rerun()


def clear_questionnaire_widgets():
    """Drop form widget state so widgets re-seed from the answers dict."""
    for k in [k for k in st.session_state
              if k.startswith(("q_", "w_", "doc_"))]:
        del st.session_state[k]


def w(field, default=None):
    """Stable widget key for answer `field`, seeded from the saved answers.

    Unkeyed widgets are identified partly by their default value, so a
    default read from the answers changes the widget's identity and the
    user's next change is lost; a fixed key avoids that.
    """
    key = "w_" + field
    if key not in st.session_state:
        st.session_state[key] = st.session_state.a.get(field, default)
    return key


def load_scenario(key):
    """Fill the whole assessment with a synthetic demo vendor."""
    v = demo.vendor(key, TODAY)
    v["answers"] = demo.answers(key)
    inh, _, tier, reasons = assess_tier(v)
    v.update(inherent=inh, tier=tier, required=scope_tsc(v),
             tier_reasons=reasons, demo=key, evidence_key="tour")
    evidence = demo.SCENARIOS[key]["evidence"]
    if evidence == "sample":
        # the real pipeline on the synthetic 10-page PDF, minus the AI call
        process_report(v, pi.sample_pdf(), SAMPLE_PDF_NAME, use_ai=False)
        v.update(demo.REVIEW_PREFILL.get(key, {}))
    elif evidence == "paybridge":
        ext = demo.paybridge_report(TODAY)
        ext["_method"] = "tour data (fixed, no AI call)"
        v.update(extracted=ext, evidence_name="Synthetic SOC 2 (PayBridge)")
        register_evidence(v, "SOC 2", "Synthetic SOC 2 (PayBridge)",
                          ct.fingerprint(json.dumps(ext, sort_keys=True)))
    else:
        v.update(extracted=dict(NO_REPORT),
                 evidence_name="No report — questionnaire only")
    if key == "nimbus":  # the contract-review showcase
        v["docs"] = list(ct.DOCS)
        v["contracts"] = {d: {"name": "Sample %s (NimbusCRM)" % d,
                              "key": "sample",
                              "results": ct.analyze(d, ct.SAMPLES[d])}
                          for d in ct.DOCS}
        for d in ct.DOCS:
            register_evidence(v, d, "Sample %s (NimbusCRM)" % d,
                              ct.fingerprint(ct.SAMPLES[d]))
    clear_questionnaire_widgets()
    st.session_state.a = v
    st.session_state.tour = key


def tour_panel(step):
    """Guided-tour narration shown above each wizard step."""
    key = st.session_state.get("tour")
    if not key or step == 0:
        return
    sc = demo.SCENARIOS[key]
    title, text = demo.TOUR[step]
    inh, _, tier, reasons = assess_tier(a)
    required = scope_tsc(a)
    doms = qn.domains_for(required, tier)
    ext = a.get("extracted") or NO_REPORT
    if ext["report_type"] == "None":
        ev_note = ("{0} has no SOC 2 on file, so maturity will come from the "
                   "questionnaire at %d%% weight." % SELF_PCT).format(sc["label"])
    else:
        ev_note = ("Pre-loaded: <b>%s</b> — %s, %s opinion, covering %s."
                   % (a.get("evidence_name"), ext["report_type"],
                      ext["auditor_opinion"].lower(),
                      ", ".join(ext.get("tsc_categories", []))))
    body = text.format(
        vendor=a.get("vendor") or sc["label"], inherent=inh,
        rta=a.get("rta") or "—",
        escalation=("Here the tier was raised because: <b>%s</b>."
                    % "; ".join(reasons)) if reasons else
        "No escalation rule raises the tier above what the score already "
        "gives.",
        tier=TIER_LABEL[tier], required=", ".join(required),
        n_criteria=len(required_criteria(required)),
        depth=qn.TIER_DEPTH[tier],
        n_questions=sum(len(d["questions"]) for d in doms),
        evidence_note=ev_note, shows=sc["shows"],
        contracts_note=(
            "Below it, the <b>DPA, MSA and SOW</b> are ticked and loaded — open "
            "<i>Clause-by-clause results</i> to see each clause, its ISO 27001 "
            "/ SOC 2 mapping and the quoted sentence." if a.get("docs") else
            "No agreements are loaded for this vendor — the NimbusCRM tour "
            "shows the contract review."))
    dots = "".join(
        "<span style='width:22px;height:4px;border-radius:2px;background:%s'>"
        "</span>" % ("#FFFFFF" if i == step else "#1FAF5A" if i < step
                     else "#4B5563") for i in range(1, 7))
    html("<div class='tour'><div class='tour-h'><span>🧭 Guided tour · %s</span>"
         "<span class='tour-dots'>%s</span></div><div class='tour-t'>Stop %d "
         "of 6 — %s</div><p>%s</p></div>"
         % (sc["label"], dots, step, title, body))
    c1, c2, c3, _ = st.container(key="btnrow_tour").columns(
        [1.1, 1.1, 1, 1.8])
    if step < 6:
        if c1.button("Next stop →", type="primary", use_container_width=True,
                     key="tour_next"):
            goto(step + 1)
    else:
        if c1.button("◀ Walk through", use_container_width=True,
                     key="tour_walk"):
            goto(1)
    if c2.button("Other vendor", use_container_width=True,
                 key="tour_other"):
        goto(0)
    if c3.button("Exit tour", use_container_width=True, key="tour_exit"):
        st.session_state.tour = None
        st.rerun()


step = st.session_state.step
a = st.session_state.a
header(step)
tour_panel(step)

# ----------------------------------------------------------------------
# STEP 0 — Overview
# ----------------------------------------------------------------------
if step == 0:
    html("<div class='banner'><h2>Every vendor has assessments. Few check what "
         "they actually cover.</h2><p>Scope what a vendor must prove, test it "
         "against their SOC 2, contracts and answers, and see every control "
         "mapped to SOC 2 and ISO 27001.</p></div>")

    steps_strip = "".join(
        "<div class='st'><span>%d</span>%s</div>" % (i, n)
        for i, n in enumerate(["Vendor scope", "Inherent risk", "TSC scope",
                               "Control questionnaire", "Evidence & contracts",
                               "Dashboard"], 1))
    html("<div class='strip'>%s</div>" % steps_strip)

    with st.container(border=True):
        st.markdown("**▶ See it in action** — pick a synthetic vendor, then "
                    "take the guided tour or jump straight to the results.")
        keys = list(demo.SCENARIOS)
        pick = st.radio(
            "Demo vendor", keys, horizontal=True,
            format_func=lambda k: demo.SCENARIOS[k]["label"],
            captions=[demo.SCENARIOS[k]["tagline"] for k in keys],
            index=keys.index(st.session_state.get("tour") or "nimbus"),
            label_visibility="collapsed")
        t1, t2, t3 = st.columns(3)
        if t1.button("▶ Guided tour", type="primary", use_container_width=True):
            load_scenario(pick)
            goto(1)
        if t2.button("⚡ Simulate results", use_container_width=True):
            load_scenario(pick)
            goto(6)
        if t3.button("Start my own assessment  →", use_container_width=True):
            st.session_state.tour = None
            if a.get("demo"):  # don't carry a demo vendor into a real one
                st.session_state.a = {}
                clear_questionnaire_widgets()
            goto(1)

    html("<p class='foot'>Demo on synthetic data · use the sample or "
         "non-confidential documents only · not affiliated with the AICPA or "
         "ISO · not audit advice</p>")

# ----------------------------------------------------------------------
# STEP 1 — Vendor Scope for Access and Data
# ----------------------------------------------------------------------
elif step == 1:
    page_title("Vendor Scope for Access and Data",
               "Who the vendor is, what they touch, where the data goes and "
               "what the contract lets you verify.")
    left, right = st.container(key="split_s1").columns([1.5, 1])
    with left:
        with st.container(border=True):
            st.markdown("**Vendor profile**")
            c1, c2 = st.columns(2)
            a["vendor"] = c1.text_input("Vendor name *", key=w("vendor", ""),
                                        placeholder="e.g. NimbusCRM Cloud")
            a["legal_name"] = c2.text_input(
                "Legal entity", key=w("legal_name", ""),
                placeholder="e.g. NimbusCRM Cloud, Inc.")
            c1, c2 = st.columns(2)
            a["website"] = c1.text_input("Website", key=w("website", ""),
                                         placeholder="e.g. nimbuscrm.io")
            a["hq"] = c2.text_input("Headquarters country", key=w("hq", ""),
                                    placeholder="e.g. Ireland")
            c1, c2 = st.columns(2)
            a["category"] = c1.selectbox(
                "Service category", SERVICE_CATEGORIES,
                key=w("category", "SaaS application"))
            a["spend"] = c2.selectbox("Annual contract value", SPEND,
                                      key=w("spend", "$10k – $50k"))
            a["description"] = st.text_area(
                "What service does the vendor provide?",
                key=w("description", ""), height=68,
                placeholder="e.g. CRM platform for the global sales pipeline")
            a["product"] = st.text_input(
                "Product / service you use (as the vendor names it)",
                key=w("product", ""), placeholder="e.g. NimbusCRM Sales Cloud",
                help="Checked against the SOC 2 scope: is this product named, "
                     "or explicitly excluded?")
            c1, c2 = st.columns(2)
            a["bu"] = c1.text_input("Business unit", key=w("bu", ""),
                                    placeholder="e.g. Sales & Marketing")
            a["owner"] = c2.text_input("Relationship owner", key=w("owner", ""),
                                       placeholder="e.g. Head of Sales Ops")
            c1, c2 = st.columns(2)
            a["contract_start"] = c1.date_input(
                "Contract start", key=w("contract_start"), format="YYYY-MM-DD")
            a["contract_end"] = c2.date_input(
                "Contract end / renewal", key=w("contract_end"),
                format="YYYY-MM-DD")

        with st.container(border=True):
            st.markdown("**Scope for access and data**")
            a["data"] = st.multiselect(
                "What data will we share with this vendor?",
                list(DATA_SENS.keys()), key=w("data", ["Customer PII"]))
            c1, c2 = st.columns(2)
            a["volume"] = c1.selectbox("Volume of records", VOLUMES,
                                       key=w("volume", "10k – 100k records"))
            a["regions"] = c2.multiselect(
                "Where will the data be processed / stored?", REGIONS,
                key=w("regions", []))
            c1, c2 = st.columns(2)
            a["access"] = c1.selectbox(
                "What access will the vendor have?", list(ACCESS_SCORE.keys()),
                key=w("access", "Reads our production data"))
            a["crit"] = c2.selectbox("Business criticality",
                                     list(CRIT_SCORE.keys()),
                                     key=w("crit", "Moderate"))
            a["certs"] = st.multiselect(
                "Certifications / attestations the vendor claims",
                CERTIFICATIONS, key=w("certs", []))
            a["subprocessors"] = st.text_input(
                "Known sub-processors (comma-separated)",
                key=w("subprocessors", ""), placeholder="e.g. AWS, Twilio")
            a["rta"] = st.radio(
                "Right to Audit — does the contract give us the right to audit "
                "this vendor (or its sub-processors)?", ["Yes", "No"],
                key=w("rta"), horizontal=True)
            st.caption("A right-to-audit clause lets you test controls the SOC 2 "
                       "doesn't cover (TSC CC9.2 — vendor and business partner "
                       "risk).")
    with right:
        # live preview of the inherent score as the user answers
        inh, tier = compute_inherent(a)
        sens = max([DATA_SENS.get(d, 5) for d in a["data"]] or [5])
        body = ("<div style='text-align:center'>%s</div><div style='margin-top:"
                "14px'>" % donut([(inh, TIER_COLOR[tier])], str(inh),
                                 "Inherent", size=170, total=100,
                                 center_size=40))
        body += bar("Data sensitivity (45%)", sens / 100, "#1FAF5A", str(sens))
        body += bar("Access level (35%)", ACCESS_SCORE[a["access"]] / 100,
                    "#3D5AFE", str(ACCESS_SCORE[a["access"]]))
        body += bar("Criticality (20%)", CRIT_SCORE[a["crit"]] / 100,
                    "#6B6B6B", str(CRIT_SCORE[a["crit"]]))
        body += "</div>" + legend("Tier (before escalation)", TIER_LABEL[tier],
                                  TIER_COLOR[tier])
        body += legend("Right to audit", a.get("rta") or "—",
                       {"Yes": "#1FAF5A", "No": "#F0405A"}.get(a.get("rta"),
                                                               "#D1D5DB"))
        html(card("Live inherent risk", body, icon("chart")))

        end = a.get("contract_end")
        renew = ("%d days" % (end - TODAY).days if end and end >= TODAY
                 else "expired" if end else "—")
        snap = (legend("Legal entity", a.get("legal_name") or "—", "#111") +
                legend("HQ", a.get("hq") or "—", "#3D5AFE") +
                legend("Processing regions",
                       ", ".join(a.get("regions", [])) or "—", "#4DD0E1") +
                legend("Record volume", a["volume"], "#FF7A2F") +
                legend("Renewal in", renew,
                       "#F0405A" if renew == "expired" else "#F2C12E") +
                legend("Owner", a.get("owner") or "unassigned",
                       "#1FAF5A" if a.get("owner") else "#F0405A"))
        certs = "".join("<span class='pill' style='color:#1FAF5A;border-color:"
                        "#1FAF5A'>%s</span>" % c for c in a.get("certs", []))
        html(card("Vendor snapshot", snap + ("<div style='margin-top:10px'>%s"
                                             "</div>" % certs if certs else ""),
                  icon("doc")))

    ready = bool(a.get("vendor") and a.get("rta"))
    nav_buttons(0, "← Overview", 2, "Next → Inherent risk", not ready)
    if not ready:
        st.caption("Enter a vendor name and answer Right to Audit to continue.")

# ----------------------------------------------------------------------
# STEP 2 — Inherent Risk Questionnaire
# ----------------------------------------------------------------------
elif step == 2:
    page_title("Inherent Risk Questionnaire",
               "Exposure before any controls. These answers refine the TSC "
               "scope and can escalate the vendor's tier.")
    left, right = st.container(key="split_s2").columns([1.5, 1])
    with left:
        with st.container(border=True):
            st.markdown("**Service dependency**")
            a["irq_store"] = st.checkbox(
                "The vendor will store or process our data",
                key=w("irq_store", True))
            a["irq_uptime"] = st.checkbox(
                "The vendor is part of a real-time or business-critical "
                "workflow (we depend on their uptime)",
                key=w("irq_uptime", False))
            a["irq_customer_facing"] = st.checkbox(
                "The service is customer-facing (our customers interact with "
                "it directly)", key=w("irq_customer_facing", False))
            a["irq_processing"] = st.checkbox(
                "The vendor performs transaction processing or calculations we "
                "rely on for accuracy", key=w("irq_processing", False))
        with st.container(border=True):
            st.markdown("**Technical exposure**")
            a["irq_creds"] = st.checkbox(
                "The vendor integrates with authentication or holds credentials",
                key=w("irq_creds", False))
            a["irq_code"] = st.checkbox(
                "The vendor develops or deploys code that runs in our "
                "environment", key=w("irq_code", False))
            a["irq_physical"] = st.checkbox(
                "Vendor staff get physical access to our premises or devices",
                key=w("irq_physical", False))
            a["irq_ai"] = st.checkbox(
                "The vendor uses our data to train or fine-tune AI / ML models",
                key=w("irq_ai", False))
        with st.container(border=True):
            st.markdown("**Data flows & regulation**")
            a["irq_crossborder"] = st.checkbox(
                "Data will be transferred across borders",
                key=w("irq_crossborder", len(a.get("regions", [])) > 1))
            a["irq_fourth"] = st.checkbox(
                "The vendor relies on sub-processors (fourth parties) to "
                "deliver the service",
                key=w("irq_fourth", bool(a.get("subprocessors"))))
            a["regulations"] = st.multiselect(
                "Regulations that apply to this relationship", REGULATIONS,
                key=w("regulations", []))
    with right:
        inh, base, tier, reasons = assess_tier(a)
        body = ("<div style='text-align:center'>%s</div>"
                % donut([(inh, TIER_COLOR[tier])], str(inh), "Inherent",
                        size=150, total=100) +
                legend("Score tier", TIER_LABEL[base], TIER_COLOR[base]) +
                legend("Final tier", TIER_LABEL[tier], TIER_COLOR[tier]))
        if reasons:
            body += ("<p style='font-size:.76rem;margin:10px 0 0;color:#B91C1C'>"
                     "<b>Escalated:</b> %s</p>" % "; ".join(reasons))
        html(card("Tier", body, icon("shield")))
        req = scope_tsc(a)
        body = "".join(bar(c, 1 if c in req else 0.04,
                           CAT_COLOR[c] if c in req else "#D1D5DB",
                           "in scope" if c in req else "not triggered")
                       for c in ALL_CATEGORIES)
        html(card("TSC scope preview", body, icon("map")))
    tier_banner(tier, req)
    nav_buttons(1, "← Back", 3, "Next → Scope criteria")

# ----------------------------------------------------------------------
# STEP 3 — Auto-scoped TSC
# ----------------------------------------------------------------------
elif step == 3:
    inh, base, tier, reasons = assess_tier(a)
    required = scope_tsc(a)
    a["inherent"], a["tier"], a["required"] = inh, tier, required
    a["tier_reasons"] = reasons
    crit_rows = required_criteria(required)
    why = scope_reasons(a, required)
    page_title("Applicable Trust Services Criteria",
               "Categories and criteria %s's SOC 2 must cover."
               % (a.get("vendor") or "the vendor"))

    left, right = st.container(key="split_s3").columns([2, 1])
    with left:
        counts = [(c, sum(1 for r in crit_rows if r[0] == c)) for c in required]
        ring = donut([(n, CAT_COLOR[c]) for c, n in counts],
                     str(len(crit_rows)), "Criteria", size=190)
        bars = "".join(bar("%s <span class='muted'>— %s</span>" % (c, why[c]),
                           n / 9, CAT_COLOR[c], "%d criteria" % n)
                       for c, n in counts)
        body = ("<div class='row'><div>%s</div><div style='flex:1;"
                "min-width:240px'>%s</div></div>" % (ring, bars))
        body += ("<div class='kpis'><div class='kpi'><small>Categories</small>"
                 "<span>%d</span></div><div class='kpi'><small>Criteria"
                 "</small><span>%d</span></div><div class='kpi'><small>Inherent"
                 "</small><span>%d</span></div><div class='kpi'><small>Tier"
                 "</small><span>%s</span></div></div>"
                 % (len(required), len(crit_rows), inh, TIER_LABEL[tier]))
        html(card("TSC scope for %s" % (a.get("vendor") or "vendor"), body,
                  icon("map")))
    with right:
        route = ("SOC 2 report + direct audit" if a.get("rta") == "Yes"
                 else "SOC 2 report only")
        body = ("<div style='text-align:center'>%s</div>"
                % donut([(inh, TIER_COLOR[tier])], str(inh), "Inherent",
                        size=150, total=100) +
                legend("Tier", TIER_LABEL[tier], TIER_COLOR[tier]) +
                legend("Right to audit", a.get("rta", "—"),
                       "#1FAF5A" if a.get("rta") == "Yes" else "#F0405A") +
                legend("Assurance route", route, "#3D5AFE") +
                legend("Questionnaire", "%s · %d questions" % (
                    qn.TIER_DEPTH[tier], sum(len(d["questions"]) for d in
                                             qn.domains_for(required, tier))),
                    "#4DD0E1"))
        if reasons:
            body += ("<p style='font-size:.76rem;margin:10px 0 0;color:#B91C1C'>"
                     "<b>Tier escalated</b> from %s: %s</p>"
                     % (TIER_LABEL[base], "; ".join(reasons)))
        html(card("Inherent risk", body, icon("shield")))

    with st.expander("See the specific criteria that must be satisfied",
                     expanded=True):
        for cat in required:
            st.markdown("**%s**" % ("Security — Common Criteria (always in "
                                    "scope)" if cat == "Security" else cat))
            for _, k, v in [r for r in crit_rows if r[0] == cat]:
                st.markdown("- `%s` %s" % (k, v))

    st.info("Security is always required as the Common Criteria. Confidentiality, "
            "Privacy, Availability and Processing Integrity are added based on "
            "your intake and questionnaire answers.")
    nav_buttons(2, "← Back", 4, "Next → Control questionnaire")

# ----------------------------------------------------------------------
# STEP 4 — Control Questionnaire
# ----------------------------------------------------------------------
elif step == 4:
    required = a.get("required") or scope_tsc(a)
    tier = a.get("tier") or assess_tier(a)[2]
    domains = qn.domains_for(required, tier)
    answers = a.setdefault("answers", {})
    n_q = sum(len(d["questions"]) for d in domains)
    page_title("Control Questionnaire",
               "What the vendor says it does. Self-attested — the SOC 2 in the "
               "next step is weighed above it.")
    depth_note = {
        1: "Tier 1 vendors get the full question set for every in-scope "
           "domain, plus <b>Enhanced Due Diligence</b> (exit plan, audit "
           "access, 24x7 SOC, insurance, financial stability) and "
           "<b>Resilience</b> even when Availability isn't in scope.",
        2: "Tier 2 vendors get every question in the in-scope domains. "
           "Tier 1 would add Enhanced Due Diligence.",
        3: "Tier 3 vendors get a <b>lite</b> set: every critical control plus "
           "key basics. Tier 2 would ask every question in these domains.",
    }[tier]
    html("<div class='card' style='border-left:4px solid %s'><div class='card-b' "
         "style='padding:12px 18px'><b>%s · %s questionnaire</b> — %d questions "
         "across %d domains.<br><span style='font-size:.82rem;color:#4B5563'>"
         "%s</span></div></div>"
         % (TIER_COLOR[tier], TIER_LABEL[tier], qn.TIER_DEPTH[tier], n_q,
            len(domains), depth_note))

    top1, top2, _ = st.columns([1, 1, 2])
    if top1.button("↧ Load sample answers", use_container_width=True):
        answers.update(qn.SAMPLE_ANSWERS)
        for k, v in qn.SAMPLE_ANSWERS.items():
            st.session_state["q_" + k] = v
        st.rerun()
    if top2.button("Clear answers", use_container_width=True):
        answers.clear()
        for k in [k for k in st.session_state if k.startswith("q_")]:
            del st.session_state[k]
        st.rerun()

    left, right = st.container(key="stack_q").columns([1.7, 1])
    with left:
        tabs = st.tabs([d["name"] for d in domains])
        for tab, d in zip(tabs, domains):
            with tab:
                st.caption("TSC %s" % d["tsc"])
                for qid, text, ref, crit in d["questions"]:
                    key = "q_" + qid
                    if key not in st.session_state and qid in answers:
                        st.session_state[key] = answers[qid]
                    c1, c2 = st.columns([1.6, 1], vertical_alignment="center")
                    c1.markdown("%s%s  \n<span class='ref'>%s</span>"
                                % ("🔴 **Critical** · " if crit else "", text,
                                   ref), unsafe_allow_html=True)
                    val = c2.segmented_control(text, qn.ANSWERS, key=key,
                                               label_visibility="collapsed")
                    if val:
                        answers[qid] = val
                    else:
                        answers.pop(qid, None)
    with right:
        per, overall, critical = qn.score(answers, domains)
        done, total = qn.answered(answers, domains)
        body = ("<div style='text-align:center'>%s</div>"
                % donut([(overall, "#1FAF5A")], "%d%%" % overall, "Maturity",
                        size=150, total=100, center_size=32))
        body += legend("Answered", "%d / %d" % (done, total), "#3D5AFE")
        body += legend("Critical controls missing", str(len(critical)),
                       "#F0405A" if critical else "#1FAF5A")
        body += "<div style='margin-top:12px'>"
        for d in domains:
            pct = per[d["key"]]
            color = ("#9CA3AF" if pct is None else "#1FAF5A" if pct >= 75
                     else "#F2C12E" if pct >= 50 else "#F0405A")
            body += bar(d["name"], (pct or 0) / 100, color,
                        "n/a" if pct is None else "%d%%" % pct)
        body += ("</div><p class='muted' style='font-size:.72rem;margin:6px 0 0'>"
                 "Unanswered counts as No · N/A is excluded.</p>")
        html(card("Live control maturity", body, icon("chart")))
    nav_buttons(3, "← Back", 5, "Next → Add SOC 2 report")

# ----------------------------------------------------------------------
# STEP 5 — Evidence
# ----------------------------------------------------------------------
elif step == 5:
    page_title("Evidence & contracts",
               "Upload the vendor's SOC 2 / SOC 3 report, load the sample, or "
               "continue on the questionnaire alone — then add the agreements "
               "you hold.")
    if not ai_backends():
        st.caption("No AI key set — the report is read with page-cited rules "
                   "only (every value still shows its page and quote). Add "
                   "GROQ_API_KEY or HF_TOKEN to cross-check with AI.")

    left, right = st.container(key="split_s5").columns([1, 1.4])
    with left:
        with st.container(border=True):
            up = st.file_uploader("SOC 2 / SOC 3 report (PDF)", type=["pdf"])
            use_sample = st.button("↧ Load the sample report (10-page PDF)",
                                   use_container_width=True)
            no_report = st.button("Vendor has no SOC 2 — use questionnaire "
                                  "only", use_container_width=True)
            st.download_button("⬇ Download the sample PDF to try an upload",
                               pi.sample_pdf(), file_name=SAMPLE_PDF_NAME,
                               mime="application/pdf",
                               use_container_width=True)

    # Buttons are only True for the rerun they were clicked in, so results
    # live in session state; an upload is re-read only when its hash changes.
    if use_sample:
        with left, st.spinner("Reading 10 pages and citing every value…"):
            process_report(a, pi.sample_pdf(), SAMPLE_PDF_NAME)
    elif no_report:
        reset_review(a)
        a.update(pdf=None, evidence_key="none", extracted=dict(NO_REPORT),
                 evidence_name="No report — questionnaire only")
        a.get("evidence", {}).pop("SOC 2", None)
    elif up is not None:
        data = up.getvalue()
        if a.get("evidence_key") != pi.sha256(data):
            with left, st.spinner("Triaging the PDF and extracting with page "
                                  "citations…"):
                process_report(a, data, up.name)

    info = a.get("pdf")
    ext = a.get("extracted")
    with right:
        if info and ext is None:
            html(card("Document triage — %s" % info["status"],
                      "".join("<p style='margin:0 0 6px'>⚠ %s</p>" % i
                              for i in info["issues"]) +
                      "<p class='muted' style='margin:0'>Nothing was extracted "
                      "from <b>%s</b>. Upload a text-based PDF, or continue on "
                      "the questionnaire alone.</p>" % a.get("evidence_name"),
                      icon("doc")))
        elif ext and ext["report_type"] == "None":
            html(card("Evidence", "<p style='margin:0'>No SOC 2 on file. "
                      "Control maturity will come from the questionnaire at "
                      "<b>%d%% weight</b>, and every required category is "
                      "treated as independently untested.</p>" % SELF_PCT,
                      icon("doc")))
        elif ext:
            eff = effective_ext(a)
            pills = "".join(
                "<span class='pill' style='color:%s;border-color:%s'>%s</span>"
                % (CAT_COLOR[c], CAT_COLOR[c], c)
                for c in eff.get("tsc_categories", []) if c in CAT_COLOR)
            period = "%s → %s" % (eff.get("period_start") or "?",
                                  eff.get("period_end") or "?")
            open_q = [f for f in ext.get("_queue", [])
                      if not a.get(REVIEW_PREFIX + "qc_" + f)]
            body = ("<div style='margin-bottom:10px'>%s</div>" % pills +
                    legend("Report type", eff["report_type"], "#1FAF5A") +
                    legend("Period", period, "#3D5AFE") +
                    legend("Auditor opinion", eff["auditor_opinion"],
                           "#6B6B6B") +
                    legend("Exceptions", len(ext.get("_exceptions", [])) or
                           ("Yes" if eff["exceptions_noted"] else "None"),
                           "#F2C12E") +
                    legend("CUECs listed", len(ext.get("_cuecs", [])) or
                           ("mentioned" if eff["cuecs_present"] else "None"),
                           "#4DD0E1") +
                    legend("Subservice method",
                           eff.get("subservice_method", "Unknown"), "#FF7A2F") +
                    legend("Needs review", len(open_q),
                           "#F0405A" if open_q else "#1FAF5A") +
                    "<p class='muted' style='font-size:.74rem;margin-top:10px'>"
                    "%s · %s%s</p>"
                    % (a["evidence_name"], ext["_method"],
                       " · triage: <b>%s</b>" % info["status"] if info else ""))
            html(card("Extracted report attributes", body, icon("doc")))
        else:
            html(card("Extracted report attributes",
                      "<p class='muted'>Upload a report or load the sample to "
                      "see its attributes here.</p>", icon("doc")))

    # ---- Review workspace: every value traced, every open item decided ----
    if ext and ext["report_type"] != "None":
        cites = ext.get("_cites", {})
        queue = ext.get("_queue", [])
        cuecs = ext.get("_cuecs", [])
        subs = ext.get("_subservice", [])
        excs = ext.get("_exceptions", [])
        open_q = [f for f in queue if not a.get(REVIEW_PREFIX + "qc_" + f)]
        html("<div class='h-page' style='font-size:1.25rem;margin-top:18px'>"
             "Review workspace</div><div class='sub'>Every value is traced to "
             "its page. Confirm anything uncertain, give each CUEC an owner, "
             "request sub-processor evidence and decide on each exception.</div>")
        tabs = st.tabs(["Reviewer summary", "Review queue (%d)" % len(open_q),
                        "CUECs (%d)" % len(cuecs),
                        "Subservice orgs (%d)" % len(subs),
                        "Exceptions (%d)" % len(excs), "Document triage"])

        with tabs[0]:
            def cite_row(label, c, value=None):
                if not c:
                    return ("<tr><td data-l='Field'><b>%s</b></td><td "
                            "data-l='Value'>%s</td><td data-l='Confidence'>%s"
                            "</td><td class='q' data-l='Evidence'>—</td></tr>"
                            % (label, value if value is not None else "—",
                               conf_pill(None)))
                v = value if value is not None else c["value"]
                if isinstance(v, list):
                    v = ", ".join(v) or "none"
                where = "p.%s · " % c["page"] if c.get("page") else ""
                return ("<tr><td data-l='Field'><b>%s</b></td><td "
                        "data-l='Value'>%s%s</td><td data-l='Confidence'>%s"
                        "<div class='rn'>%s</div></td><td class='q' "
                        "data-l='Evidence'>%s“%s”</td></tr>"
                        % (label, v, " <span class='rn'>(AI: %s)</span>"
                           % (", ".join(c["alt"]) if isinstance(
                               c.get("alt"), list) else c["alt"])
                           if c.get("alt") else "", conf_pill(c["confidence"]),
                           c.get("source", ""), where, c["excerpt"]))
            rows = cite_row("Report type", cites.get("report_type"))
            rows += cite_row("Auditor opinion", cites.get("auditor_opinion"))
            per = cites.get("period_end")
            rows += cite_row("Audit period", per, "%s → %s" % (
                ext.get("period_start") or "?", ext.get("period_end") or "?")
                if per else None)
            rows += cite_row("Report date", cites.get("report_date"))
            rows += cite_row("TSC categories examined",
                             cites.get("tsc_categories"))
            rows += cite_row("Subservice method", cites.get("subservice_method"))
            rows += cite_row("CUECs listed", cites.get("cuecs"))
            scope = ext.get("_scope") or {}
            rows += cite_row("System in scope", None, scope.get("system"))
            rows += cite_row("Regions in scope", scope.get("region_cite"))
            for x in scope.get("exclusions", []):
                rows += cite_row("Excluded from scope", {
                    "value": "see quote", "page": x["page"],
                    "excerpt": x["text"], "confidence": "High",
                    "source": "rules"})
            html("<table class='mx'><tr><th>Field</th><th>Value</th>"
                 "<th>Confidence</th><th>Evidence (page · quote)</th></tr>%s"
                 "</table>" % rows)
            st.caption("High = an explicit sentence (or rules and AI agree) · "
                       "Medium = inferred or AI only · Low = conflicting or "
                       "weak evidence, sent to the review queue.")

        with tabs[1]:
            if not queue:
                st.success("Nothing needs review — every key value has a "
                           "High- or Medium-confidence citation.")
            for f in queue:
                c = cites.get(f) or {}
                with st.container(border=True):
                    st.markdown("**%s**" % pi.FIELD_LABEL.get(f, f))
                    st.caption("Rules: %s%s · AI: %s" % (
                        c.get("value", "not found"),
                        " (p.%s)" % c["page"] if c.get("page") else "",
                        c.get("alt", "—")))
                    if c.get("excerpt"):
                        st.caption("“%s”" % c["excerpt"])
                    key = REVIEW_PREFIX + "q_" + f
                    opts = pi.REVIEW_FIELDS.get(f)
                    if f == "tsc_categories":
                        a[key] = st.multiselect(
                            "Reviewer value", ALL_CATEGORIES,
                            key=w(key, [x for x in (c.get("value") or [])
                                        if x in ALL_CATEGORIES]))
                    elif opts:
                        default = c.get("value") if c.get("value") in opts \
                            else opts[-1]
                        a[key] = st.selectbox("Reviewer value", opts,
                                              key=w(key, default))
                    else:
                        a[key] = st.text_input("Reviewer value (YYYY-MM-DD)",
                                               key=w(key, c.get("value") or ""))
                    qc = REVIEW_PREFIX + "qc_" + f
                    a[qc] = st.checkbox("Confirmed against the report",
                                        key=w(qc, False))

        with tabs[2]:
            if not cuecs:
                st.info("No CUEC list found in the report." +
                        (" The report mentions CUECs — find them in the system "
                         "description and record them manually."
                         if ext.get("cuecs_present") else ""))
            for i, c in enumerate(cuecs):
                c1, c2, c3 = st.columns([2.2, 1.2, 1],
                                        vertical_alignment="center")
                c1.markdown("%s  \n<span class='ref'>%s</span>"
                            % (c["text"], "p.%s" % c["page"] if c.get("page")
                               else "from report summary"),
                            unsafe_allow_html=True)
                k_o = "%scuec_owner_%d" % (REVIEW_PREFIX, i)
                k_s = "%scuec_status_%d" % (REVIEW_PREFIX, i)
                a[k_o] = c2.text_input("Internal owner", key=w(k_o, ""),
                                       placeholder="Owner / team")
                a[k_s] = c3.selectbox("Status", CUEC_STATUS,
                                      key=w(k_s, "Not assessed"))
            if cuecs:
                st.caption("CUECs are controls we must operate for the "
                           "vendor's assurance to hold. Unowned or unconfirmed "
                           "CUECs become findings and keep −5 on maturity.")

        with tabs[3]:
            if not subs:
                st.info("No subservice organisations identified." +
                        (" The report uses the %s method — check the system "
                         "description for names."
                         % ext.get("subservice_method").lower()
                         if ext.get("subservice_method") not in
                         (None, "Unknown") else ""))
            for i, o in enumerate(subs):
                c1, c2 = st.columns([2, 1.3], vertical_alignment="center")
                c1.markdown("**%s** · %s · %s  \n<span class='ref'>%s</span>"
                            % (o["name"], o["type"], o["method"].lower(),
                               "p.%s" % o["page"] if o.get("page")
                               else "from report summary"),
                            unsafe_allow_html=True)
                k = "%ssub_ev_%d" % (REVIEW_PREFIX, i)
                a[k] = c2.selectbox("Downstream evidence", SUB_EVIDENCE,
                                    key=w(k, "Not requested"))
            if subs:
                html("<div class='chain'>%s</div>" % " → ".join(
                    ["<b>Us</b>", "<b>%s</b>" % a.get("vendor", "Vendor")] +
                    ["{%s}" % ", ".join(o["name"] for o in subs)]).replace(
                    "{", "<span>").replace("}", "</span>"))

        with tabs[4]:
            if not excs:
                st.success("No exceptions found in the control tests.")
            for i, e in enumerate(excs):
                with st.container(border=True):
                    st.markdown("**%s** · sample %s · %s  \n%s"
                                % (e["control"], e["sample"],
                                   "p.%s" % e["page"] if e.get("page")
                                   else "from report summary", e["text"]))
                    c1, c2 = st.columns([1, 1.6])
                    k_d = "%sexc_dec_%d" % (REVIEW_PREFIX, i)
                    k_n = "%sexc_note_%d" % (REVIEW_PREFIX, i)
                    a[k_d] = c1.selectbox("Decision", EXC_DECISIONS,
                                          key=w(k_d, "Undecided"))
                    a[k_n] = c2.text_input("Rationale / compensating control",
                                           key=w(k_n, ""))

        with tabs[5]:
            if info:
                body = (legend("File", a.get("evidence_name"), "#111") +
                        legend("Status", info["status"],
                               "#1FAF5A" if info["status"] == "OK"
                               else "#F2C12E") +
                        legend("Pages with text", "%d of %d" % (
                            info["text_pages"], info["pages"]), "#3D5AFE") +
                        legend("Size", "%s KB" % info["size_kb"], "#6B6B6B") +
                        "<div class='lg'><span><span class='dot' style='"
                        "background:#4DD0E1'></span>SHA-256</span><span "
                        "class='ref' style='word-break:break-all;max-width:"
                        "70%%'>%s</span></div>" % info["sha256"] +
                        "".join("<p style='margin:8px 0 0;font-size:.8rem'>⚠ "
                                "%s</p>" % i for i in info["issues"]))
                html(card("Document triage", body, icon("doc")))
            else:
                st.info("This report was entered as data (tour), not uploaded "
                        "as a PDF, so there is no file to triage.")

    # ---- Contracts & agreements ----
    html("<div class='h-page' style='font-size:1.25rem;margin-top:18px'>"
         "Contracts &amp; agreements</div><div class='sub'>Tick the agreements "
         "you hold for this vendor, then upload each one (PDF or .txt) or "
         "load the synthetic sample. Clauses are mapped to ISO 27001 and "
         "SOC 2.</div>")
    store = a.setdefault("contracts", {})
    with st.container(border=True):
        st.markdown("**Agreements checklist**")
        cols = st.columns(3)
        docs = []
        for col, (doc, label) in zip(cols, ct.DOCS.items()):
            key = "doc_" + doc
            if key not in st.session_state:
                st.session_state[key] = doc in a.get("docs", [])
            if col.checkbox(label, key=key):
                docs.append(doc)
        a["docs"] = docs
        for doc in docs:
            c1, c2, c3 = st.columns([1.5, 0.8, 1.7], vertical_alignment="center")
            up_doc = c1.file_uploader(doc, type=["pdf", "txt"], key="up_" + doc,
                                      label_visibility="collapsed")
            if c2.button("↧ Sample " + doc, key="smp_" + doc,
                         use_container_width=True):
                store[doc] = {"name": "Sample %s (NimbusCRM)" % doc,
                              "key": "sample",
                              "results": ct.analyze(doc, ct.SAMPLES[doc])}
                register_evidence(a, doc, store[doc]["name"],
                                  ct.fingerprint(ct.SAMPLES[doc]))
            elif up_doc is not None and \
                    store.get(doc, {}).get("key") != (up_doc.name, up_doc.size):
                try:
                    raw = up_doc.getvalue()
                    body = (read_pdf(io.BytesIO(raw)) if up_doc.name.lower()
                            .endswith(".pdf") else raw.decode("utf-8", "ignore"))
                    store[doc] = {"name": up_doc.name,
                                  "key": (up_doc.name, up_doc.size),
                                  "results": ct.analyze(doc, body)}
                    register_evidence(a, doc, up_doc.name, pi.sha256(raw))
                except Exception as e:  # noqa: BLE001
                    st.error("Could not read the %s: %s" % (doc, e))
            r = store.get(doc)
            if r:
                n = {s_: sum(1 for v in r["results"].values() if v[0] == s_)
                     for s_ in ("Met", "Partial", "Missing")}
                total = sum(n.values())
                c3.html("<div style='font-size:.78rem'><b>%s</b><br>%s</div>"
                        % (r["name"], bar(
                            "%d met · %d partial · %d missing" % (
                                n["Met"], n["Partial"], n["Missing"]),
                            (n["Met"] + 0.5 * n["Partial"]) / total,
                            "#1FAF5A" if n["Missing"] == 0 else "#F2C12E",
                            "%d clauses" % total)))
            else:
                c3.caption("Not loaded yet")
        st.caption("🔒 Contracts are checked inside the app with transparent "
                   "keyword rules — never sent to an AI service — and every "
                   "result quotes the sentence it matched. Clause presence is "
                   "not a legal opinion on adequacy.")
    loaded = [d for d in docs if store.get(d)]
    if loaded:
        with st.expander("Clause-by-clause results with quoted evidence"):
            rows = ""
            for doc in loaded:
                for cid, (status, snip, note) in store[doc]["results"].items():
                    iso, tsc = clause_refs(cid)
                    rows += ("<tr><td data-l='Clause'><b>%s</b> · %s</td>"
                             "<td data-l='Status'>%s</td>"
                             "<td data-l='Maps to'>%s</td>"
                             "<td class='q' data-l='Evidence'>%s</td></tr>"
                             % (doc, ct.CLAUSE[cid][2], status_pill(status),
                                "<span class='ref'>ISO %s<br>%s</span>"
                                % (", ".join(iso), ", ".join(tsc)),
                                ("“%s”" % snip if snip else "—") +
                                ("<br><i>%s</i>" % note if note else "")))
            html("<table class='mx'><tr><th>Clause</th><th>Status</th>"
                 "<th>Maps to</th><th>Evidence</th></tr>%s</table>" % rows)

    nav_buttons(4, "← Back", 6, "Next → Dashboard", not a.get("extracted"))

# ----------------------------------------------------------------------
# STEP 6 — Dashboard
# ----------------------------------------------------------------------
elif step == 6:
    required = a["required"]
    ext = effective_ext(a)  # the report as the reviewer confirmed it
    rta = a.get("rta", "No")
    domains = qn.domains_for(required, a["tier"])
    per, q_overall, critical = qn.score(a.get("answers", {}), domains)
    q = {"per": per, "overall": q_overall, "critical": critical}
    maturity, missing, stale, adjustments = report_maturity(
        required, ext, rta, a["tier"], q)
    residual, band = compute_residual(a["inherent"], maturity)
    gaps = assurance_gaps(missing, ext, stale)
    findings = build_findings(a, ext, missing, stale, gaps, q, domains)
    findings = sorted(findings + contract_findings(a) +
                      evidence_findings(a, ext),
                      key=lambda x: {"High": 0, "Medium": 1, "Low": 2}[x[0]])
    obligations = obligation_matrix(a, ext)
    matrix = control_matrix(a, ext, domains)
    clauses = contract_results(a)
    a["residual"], a["band"], a["maturity"] = residual, band, maturity

    covered = set(ext.get("tsc_categories", []))
    crit_rows = required_criteria(required)
    n_cov = sum(1 for r in crit_rows if r[0] in covered)
    cov_pct = round(100 * n_cov / len(crit_rows))

    page_title("Dashboard", "Risk posture for %s · %s"
               % (a.get("vendor", "vendor"), a.get("evidence_name", "")))
    with st.expander("ⓘ How to read this dashboard — every score explained"):
        st.markdown(
            "| Score | What it means | How it's calculated |\n"
            "|---|---|---|\n"
            "| **Inherent risk** | Exposure before any controls | 0.45 × data "
            "sensitivity + 0.35 × access + 0.20 × criticality → **%d** "
            "(%s; tier escalation can only raise it) |\n"
            "| **TSC coverage** | Share of required criteria the SOC 2 "
            "independently tested | criteria in categories the report examined "
            "÷ all required criteria → **%d / %d = %d%%** |\n"
            "| **Questionnaire** | What the vendor says it does "
            "(self-attested) | Yes = 1, Partial = 0.5, No / unanswered = 0, "
            "N/A excluded; averaged over %s questions → **%d%%** |\n"
            "| **Control maturity** | How well the evidence shows controls "
            "working | evidence baseline ± each factor in *Maturity "
            "breakdown*, capped 0–100 → **%d** |\n"
            "| **Residual risk** | Risk left after controls | inherent × (1 − "
            "0.70 × maturity ÷ 100) → **%d (%s)** |\n\n"
            "**Bands:** Low ≤ 20 · Medium 21–40 · High 41–65 · Critical > 65. "
            "**Findings** are ranked High → Medium → Low and each cites the "
            "TSC criterion it relates to."
            % (a["inherent"], TIER_LABEL[a["tier"]], n_cov, len(crit_rows),
               cov_pct, qn.TIER_DEPTH[a["tier"]].lower(), q_overall, maturity,
               residual, band))

    # ---- Row 1: coverage + residual ----
    c1, c2 = st.container(key="stack_d1").columns([2.2, 1])
    with c1:
        ring = donut([(n_cov, "#1FAF5A"), (len(crit_rows) - n_cov, "#F0405A")],
                     "%d%%" % cov_pct, "Coverage", size=200, stroke=22)
        cat_bars = ""
        for cat in required:
            n = sum(1 for r in crit_rows if r[0] == cat)
            ok = cat in covered
            cat_bars += bar(cat, n / 9, CAT_COLOR[cat] if ok else "#F0405A",
                            ("✓ covered" if ok else "✗ gap") + " · %d" % n)
        body = ("<div class='row'><div>%s</div><div style='flex:1;"
                "min-width:260px'><div style='font-weight:600;font-size:.82rem;"
                "margin-bottom:10px'>Required category (independent "
                "evidence)</div>%s</div></div>" % (ring, cat_bars))
        body += ("<div class='kpis'><div class='kpi'><small>Required criteria"
                 "</small><span>%d</span></div><div class='kpi'><small>Covered"
                 "</small><span>%d</span></div><div class='kpi'><small>Gaps"
                 "</small><span>%d</span></div><div class='kpi'><small>Report"
                 "</small><span style='font-size:1rem'>%s</span></div></div>"
                 % (len(crit_rows), n_cov, len(crit_rows) - n_cov,
                    "none" if ext["report_type"] == "None"
                    else ext["report_type"]))
        body += how(
            "<b>How it's calculated:</b> required criteria = 9 Common Criteria "
            "(Security) + the criteria of each other required category = "
            "<b>%d</b>. A criterion counts as covered only when the SOC 2 "
            "examined its category — %d of %d = <b>%d%%</b>. Categories the "
            "report marks “not in scope” are gaps; questionnaire answers never "
            "count here, because coverage means independent evidence."
            % (len(crit_rows), n_cov, len(crit_rows), cov_pct))
        html(card("TSC Coverage", body, icon("map")))
    with c2:
        body = ("<div style='text-align:center'>%s</div>"
                % donut([(residual, BAND_COLOR[band])], str(residual),
                        "Residual", size=170, total=100, center_size=40) +
                "<p style='text-align:center;font-size:.82rem;font-weight:600;"
                "margin:6px 0 12px;color:%s'>%s risk</p>"
                % (BAND_COLOR[band], band) +
                legend("Inherent", "%d · %s" % (a["inherent"],
                                                 TIER_LABEL[a["tier"]]), "#111") +
                legend("Control maturity", "%d / 100" % maturity, "#3D5AFE") +
                legend("Questionnaire", "%d%%" % q_overall, "#4DD0E1") +
                legend("Right to audit", rta,
                       "#1FAF5A" if rta == "Yes" else "#F0405A") +
                legend("Findings", str(len(findings)), "#F2C12E"))
        body += band_scale(residual)
        body += how(
            "<b>Residual</b> = inherent × (1 − 0.70 × maturity ÷ 100)<br>"
            "= %d × (1 − 0.70 × %d ÷ 100) = <b>%d → %s</b>.<br>Controls can "
            "remove at most 70%% of inherent risk — some risk always stays "
            "with a third party." % (a["inherent"], maturity, residual, band))
        html(card("Residual Risk", body, icon("shield")))

    # ---- Row 2: vendor profile + questionnaire ----
    p1, p2 = st.container(key="stack_d2").columns([1, 1.3])
    with p1:
        end = a.get("contract_end")
        renew = ("%d days" % (end - TODAY).days if end and end >= TODAY
                 else "expired" if end else "—")
        body = (legend("Legal entity", a.get("legal_name") or "—", "#111") +
                legend("Category", a.get("category"), "#3D5AFE") +
                legend("Business unit · owner", "%s · %s" % (
                    a.get("bu") or "—", a.get("owner") or "unassigned"),
                    "#1FAF5A" if a.get("owner") else "#F0405A") +
                legend("Data shared", ", ".join(a["data"]) or "—", "#FF7A2F") +
                legend("Volume · regions", "%s · %s" % (
                    a.get("volume"), ", ".join(a.get("regions", [])) or "—"),
                    "#4DD0E1") +
                legend("Access · criticality", "%s · %s" % (a["access"],
                                                            a["crit"]),
                       "#6B6B6B") +
                legend("Contract value · renewal", "%s · %s" % (
                    a.get("spend"), renew), "#F2C12E") +
                legend("Regulations", ", ".join(a.get("regulations", []))
                       or "—", "#3D5AFE"))
        if a.get("tier_reasons"):
            body += ("<p style='font-size:.74rem;margin:10px 0 0;color:#B91C1C'>"
                     "<b>Tier escalated:</b> %s</p>"
                     % "; ".join(a["tier_reasons"]))
        certs = "".join("<span class='pill' style='color:#1FAF5A;border-color:"
                        "#1FAF5A'>%s</span>" % c for c in a.get("certs", []))
        if certs:
            body += "<div style='margin-top:10px'>%s</div>" % certs
        html(card("Vendor profile", body, icon("doc")))
    with p2:
        done, total = qn.answered(a.get("answers", {}), domains)
        body = ("<div class='row' style='align-items:flex-start'><div>%s</div>"
                "<div style='flex:1;min-width:220px'>"
                % donut([(q_overall, "#1FAF5A")], "%d%%" % q_overall,
                        "Self-attested", size=140, total=100, center_size=28))
        for d in domains:
            pct = per[d["key"]]
            color = ("#9CA3AF" if pct is None else "#1FAF5A" if pct >= 75
                     else "#F2C12E" if pct >= 50 else "#F0405A")
            body += bar(d["name"], (pct or 0) / 100, color,
                        "n/a" if pct is None else "%d%%" % pct)
        body += ("</div></div>" +
                 legend("Answered", "%d / %d" % (done, total), "#3D5AFE") +
                 legend("Critical controls missing", str(len(critical)),
                        "#F0405A" if critical else "#1FAF5A"))
        html(card("Control questionnaire", body, icon("grid")))

    # ---- Row 3: four small cards ----
    d1, d2, d3, d4 = st.container(key="grid4").columns(4)
    with d1:
        body = ""
        for i, (label, pts) in enumerate(adjustments):
            color = "#111" if i == 0 else "#1FAF5A" if pts > 0 else "#F0405A"
            body += bar(label, abs(pts) / 85, color,
                        str(pts) if i == 0 else "%+d" % pts)
        body += legend("Control maturity", "%d / 100" % maturity, "#3D5AFE")
        body += how("Start from the evidence baseline (Type II 85 · Type I / "
                    "SOC 3 35 · no report = %d%% of the questionnaire), then "
                    "add or subtract each factor; result capped 0–100."
                    % SELF_PCT)
        html(card("Maturity breakdown", body, icon("chart")))
    with d2:
        # chart size (named so they don't shadow the w() widget helper)
        ch, cw = 170, 200
        cols = ""
        for i, (lbl, val, col) in enumerate(
                [("Inherent", a["inherent"], "#111"),
                 ("Residual", residual, BAND_COLOR[band])]):
            bh = val / 100 * (ch - 40)
            x = 40 + i * 80
            cols += ("<rect x='%d' y='%.1f' width='44' height='%.1f' rx='3' "
                     "fill='%s'/><text x='%d' y='%.1f' text-anchor='middle' "
                     "font-size='13' fill='#111'>%d</text><text x='%d' y='%d' "
                     "text-anchor='middle' font-size='10' fill='#6B7280'>%s"
                     "</text>" % (x, ch - 20 - bh, bh, col, x + 22,
                                  ch - 26 - bh, val, x + 22, ch - 5, lbl))
        svg = svg_img("<svg width='%d' height='%d' viewBox='0 0 %d %d'><line "
                      "x1='20' y1='%d' x2='%d' y2='%d' stroke='#E5E7EB'/>%s"
                      "</svg>" % (cw, ch, cw, ch, ch - 20, cw - 10, ch - 20,
                                  cols),
                      width="min(100%, 260px)")
        html(card("Risk reduction", svg + legend(
            "Reduced by controls", "−%d pts" % (a["inherent"] - residual),
            "#1FAF5A") + how("Black bar = inherent (before controls); "
                             "coloured bar = residual (after), in its band "
                             "colour. The gap is what the evidenced controls "
                             "remove — at most 70%."), icon("chart")))
    with d3:
        sev_counts = [(s, sum(1 for f in findings if f[0] == s))
                      for s in ("High", "Medium", "Low")]
        body = ("<div style='text-align:center'>%s</div>"
                % donut([(n, SEV_COLOR[s]) for s, n in sev_counts],
                        str(len(findings)), "Findings", size=140, stroke=16,
                        center_size=30) +
                "".join(legend(s, n, SEV_COLOR[s]) for s, n in sev_counts))
        html(card("Findings by severity", body, icon("grid")))
    with d4:
        body = (legend("Opinion", ext["auditor_opinion"], "#1FAF5A") +
                legend("Period end", ext.get("period_end") or "—",
                       "#F0405A" if stale else "#1FAF5A") +
                legend("Exceptions", "Yes" if ext["exceptions_noted"] else "No",
                       "#F2C12E" if ext["exceptions_noted"] else "#1FAF5A") +
                legend("CUECs", "Yes" if ext["cuecs_present"] else "No",
                       "#4DD0E1") +
                legend("Subservice", ext.get("subservice_method", "Unknown"),
                       "#FF7A2F") +
                "<p class='muted' style='font-size:.7rem;margin-top:10px'>"
                "Extracted using %s</p>" % ext.get("_method"))
        html(card("Report attributes", body, icon("doc")))

    # ---- Control mapping: ISO 27001 <-> SOC 2 <-> NIST 800-53 ----
    html("<div class='h-page' style='font-size:1.3rem;margin-top:14px'>"
         "Control mapping — ISO 27001 ↔ SOC 2 ↔ NIST 800-53</div>"
         "<div class='sub'>%d unified controls, each scored automatically from "
         "every source of evidence: contract clauses, questionnaire answers, "
         "intake and the SOC 2 report — and mapped many-to-many across three "
         "frameworks.</div>" % len(matrix))
    m1, m2, m3, m4 = st.container(key="grid4b").columns(4)
    for col, key, title, label in (
            (m1, "iso", "ISO 27001:2022 Annex A", "Annex A"),
            (m2, "tsc", "SOC 2 Trust Services Criteria", "TSC"),
            (m3, "nist", "NIST SP 800-53 Rev. 5", "800-53")):
        best = framework_rollup(matrix, key)
        counts = [(s_, sum(1 for v in best.values() if v == s_))
                  for s_ in STATUS_COLOR if s_ != "Missing"]
        body = ("<div style='text-align:center'>%s</div>"
                % donut([(n, STATUS_COLOR[s_]) for s_, n in counts],
                        "%d/%d" % (counts[0][1], len(best)), "Met",
                        size=140, stroke=16, center_size=26) +
                "".join(legend(s_, n, STATUS_COLOR[s_]) for s_, n in counts) +
                how("%d %s references covered. A reference is <b>Met</b> when "
                    "at least one control mapped to it is Met."
                    % (len(best), label)))
        col.html(card(title, body, icon("grid")))
    with m4:
        if clauses:
            vals = [CLAUSE_VALUE[v[0]] for v in clauses.values()]
            c_pct = round(100 * sum(vals) / len(vals))
            body = ("<div style='text-align:center'>%s</div>"
                    % donut([(c_pct, "#1FAF5A" if c_pct >= 80 else "#F2C12E"
                              if c_pct >= 50 else "#F0405A")], "%d%%" % c_pct,
                            "Contracts", size=140, total=100, center_size=26))
            for doc in a.get("docs", []):
                res = a["contracts"].get(doc, {}).get("results", {})
                if res:
                    dv = [CLAUSE_VALUE[v[0]] for v in res.values()]
                    pct = sum(dv) / len(dv)
                    body += bar(doc, pct, "#1FAF5A" if pct >= .8 else
                                "#F2C12E" if pct >= .5 else "#F0405A",
                                "%d%%" % round(100 * pct))
        else:
            body = ("<p class='muted' style='margin:0'>No agreements provided. "
                    "Tick DPA / MSA / SOW on the Evidence step to review their "
                    "clauses.</p>")
        body += how("Met = 1, Partial = 0.5, Missing = 0 across the clauses of "
                    "the agreements provided. Contract gaps don't change the "
                    "residual score.")
        html(card("Contract assurance", body, icon("doc")))

    fw_all = ["ISO 27001:2022", "SOC 2 TSC", "NIST 800-53 Rev.5"]
    with st.container(border=True):
        f1, f2 = st.columns([1.3, 1.2])
        fw_pick = f1.pills("Frameworks to show", fw_all, selection_mode="multi",
                           default=fw_all, key="fw_pick")
        st_pick = f2.pills("Status", ["Met", "Partial", "Gap", "Not assessed"],
                           selection_mode="multi",
                           default=["Met", "Partial", "Gap", "Not assessed"],
                           key="st_pick")
        shown = [(f, k, n) for f, k, n in (
            ("ISO 27001:2022", "iso", ct.ISO), ("SOC 2 TSC", "tsc", ct.TSC),
            ("NIST 800-53 Rev.5", "nist", ct.NIST)) if f in (fw_pick or [])]

        def refs_cell(refs, names):
            return "".join("<div><span class='ref'>%s</span> <span class='rn'>"
                           "%s</span></div>" % (r, names.get(r, "")) for r in refs)

        def chip(label, v, note):
            c = ("#9CA3AF" if v is None else "#1FAF5A" if v >= .8 else
                 "#F2C12E" if v >= .4 else "#F0405A")
            return ("<span class='ev' style='border-color:%s'><i style='"
                    "background:%s'></i>%s <em>%s</em></span>" % (c, c, label,
                                                                   note))
        head = ("<tr><th>Control</th>%s<th>Evidence (auto-collected)</th>"
                "<th>Status</th></tr>"
                % "".join("<th>%s</th>" % f for f, _, _ in shown))
        body = ""
        for r in matrix:
            if r["status"] not in (st_pick or []):
                continue
            body += ("<tr><td data-l='Control'><span class='ref'>%s</span>"
                     "<br><b>%s</b></td>%s<td data-l='Evidence'>%s</td>"
                     "<td data-l='Status'>%s</td></tr>"
                     % (r["id"], r["name"],
                        "".join("<td data-l='%s'>%s</td>" % (
                            f, refs_cell(r[k], n)) for f, k, n in shown),
                        "".join(chip(*e) for e in r["evidence"]),
                        status_pill(r["status"]) + (
                            "<div class='rn' style='margin-top:4px'>%d source%s"
                            "</div>" % (r["sources"], "" if r["sources"] == 1
                                        else "s") if r["sources"] else "")))
        html("<div style='overflow-x:auto'><table class='mx'>%s%s</table></div>"
             % (head, body or "<tr><td colspan='6' class='muted'>No controls "
                "match the selected status.</td></tr>"))
        st.caption("Each source scores Met = 1, Partial = 0.5, Gap = 0 "
                   "(questionnaire: Yes / Partial / No; SOC 2: category "
                   "examined or not). Control status = average of assessed "
                   "sources: Met ≥ 0.8 · Partial ≥ 0.4 · otherwise Gap. Grey "
                   "sources weren't provided.")
        st.download_button("⬇ Control matrix (CSV)", matrix_csv(matrix),
                           file_name="control_matrix_%s.csv" % (
                               a.get("vendor") or "vendor").replace(" ", "_"),
                           mime="text/csv")
    with st.expander("Framework reference — ISO 27001:2022 Annex A, TSC and "
                     "NIST 800-53 titles used in this matrix"):
        r1, r2, r3 = st.columns(3)
        r1.markdown("\n".join("- `%s` %s" % kv for kv in ct.ISO.items()))
        r2.markdown("\n".join("- `%s` %s" % kv for kv in ct.TSC.items()))
        r3.markdown("\n".join("- `%s` %s" % kv for kv in ct.NIST.items()))

    # ---- Cross-document obligations: SOC 2 vs MSA vs DPA ----
    html("<div class='h-page' style='font-size:1.3rem;margin-top:14px'>"
         "Cross-document obligations</div><div class='sub'>What the SOC 2 "
         "shows versus what the MSA, DPA and SOW actually commit the vendor "
         "to.</div>")
    ob_rows = "".join(
        "<tr><td data-l='Review question'><b>%s</b></td><td data-l='Source'>"
        "<span class='ref'>%s</span></td><td data-l='Status'>%s</td>"
        "<td class='q' data-l='Evidence'>%s</td></tr>"
        % (qtext, src, status_pill(status) if status in STATUS_COLOR else
           ("<span class='pill' style='color:#6B7280;border-color:#D1D5DB'>"
            "%s</span>" % (status or "Not provided")), detail)
        for qtext, src, status, detail in obligations)
    html("<div class='card'><div class='card-b' style='overflow-x:auto'>"
         "<table class='mx'><tr><th>Review question</th><th>Source</th>"
         "<th>Status</th><th>Evidence</th></tr>%s</table></div></div>"
         % ob_rows)

    # ---- Evidence register & reviewer sign-off ----
    html("<div class='h-page' style='font-size:1.3rem;margin-top:14px'>"
         "Evidence register &amp; sign-off</div><div class='sub'>Every "
         "document reviewed, fingerprinted with SHA-256, and the reviewer's "
         "decision — ready for peer review or audit.</div>")
    reg = evidence_rows(a)
    e1, e2 = st.container(key="stack_d4").columns([1.6, 1])
    with e1:
        rows = "".join(
            "<tr><td data-l='ID'><span class='ref'>%s</span></td>"
            "<td data-l='Document'><b>%s</b><div class='rn'>%s</div></td>"
            "<td data-l='SHA-256'><span class='ref' title='%s'>%s…</span></td>"
            "<td data-l='Pages'>%s</td><td data-l='Status'>%s</td>"
            "<td data-l='Loaded'><span class='rn'>%s</span></td></tr>"
            % (r["id"], r["type"], r["name"], r["sha256"], r["sha256"][:16],
               r["pages"] or "—", r["status"], r["loaded"]) for r in reg)
        html("<div class='card'><div class='card-b' style='overflow-x:auto'>"
             "<table class='mx'><tr><th>ID</th><th>Document</th>"
             "<th>SHA-256</th><th>Pages</th><th>Status</th><th>Loaded</th>"
             "</tr>%s</table></div></div>" % (rows or "<tr><td colspan='6' "
                                               "class='muted'>No documents "
                                               "loaded.</td></tr>"))
    with e2:
        with st.container(border=True):
            st.markdown("**Reviewer sign-off**")
            a["signoff_name"] = st.text_input("Reviewer",
                                              key=w("signoff_name", ""),
                                              placeholder="Name, role")
            a["signoff_decision"] = st.selectbox(
                "Decision", SIGNOFF, key=w("signoff_decision", "Pending"))
            a["signoff_note"] = st.text_area("Conditions / comments",
                                             key=w("signoff_note", ""),
                                             height=68)
            st.caption("Recorded in the evidence pack with today's date (%s). "
                       "The decision is the reviewer's — the app recommends, "
                       "it doesn't approve." % TODAY.isoformat())

    # ---- Row 4: findings + recommendation ----
    rec = {
        "Low": "Approve with standard onboarding and annual review.",
        "Medium": "Approve with conditions. Track the findings above and "
                  "reassess at renewal.",
        "High": "Conditional. Remediate coverage gaps and findings before "
                "onboarding; reassess within six months.",
        "Critical": "Do not onboard until critical gaps are resolved. Escalate "
                    "to the risk committee.",
    }[band]
    if critical:
        rec += " Critical controls the vendor reports as missing must be " \
               "fixed before go-live."
    if rta == "Yes" and gaps:
        rec += " Exercise the right to audit to test %s." % ", ".join(gaps)
    elif rta == "No" and band in ("High", "Critical"):
        rec += " Make a right-to-audit clause a condition of the contract."

    f1, f2 = st.container(key="stack_d3").columns([2.2, 1])
    with f1:
        rows = "".join(
            "<div class='find'><span class='sev' style='background:%s'>%s"
            "</span><div><b>%s</b> <span class='ref'>%s</span><p>%s</p></div>"
            "</div>" % (SEV_COLOR[s], s.upper(), t, ref, d)
            for s, t, d, ref in findings)
        html(card("Findings", rows or "<p class='muted'>No structural issues "
                  "detected.</p>", icon("search")))
    with f2:
        html(card("Recommendation",
                  "<span class='pill' style='color:%s;border-color:%s'>%s</span>"
                  "<p style='font-size:.9rem;line-height:1.5;margin:8px 0 0'>"
                  "%s</p>" % (BAND_COLOR[band], BAND_COLOR[band], band, rec),
                  icon("shield")))

        # ---- Downloadable report ----
        plain = ["%s [%s] %s: %s" % (s, ref, t, d) for s, t, d, ref in findings]
        iso = lambda d: d.isoformat() if d else None  # noqa: E731
        profile = {
            "vendor": a.get("vendor"), "legal_entity": a.get("legal_name"),
            "website": a.get("website"), "headquarters": a.get("hq"),
            "service_category": a.get("category"),
            "description": a.get("description"),
            "business_unit": a.get("bu"), "relationship_owner": a.get("owner"),
            "contract_start": iso(a.get("contract_start")),
            "contract_end": iso(a.get("contract_end")),
            "annual_contract_value": a.get("spend"),
            "certifications_claimed": a.get("certs", []),
            "sub_processors": a.get("subprocessors"),
        }
        irq = {k: v for k, v in a.items() if k.startswith("irq_")}
        answers = {qid: a.get("answers", {}).get(qid, "Unanswered")
                   for d in domains for qid, *_ in d["questions"]}
        report = {
            "generated": TODAY.isoformat(),
            "vendor_profile": profile,
            "scope": {"data_shared": a.get("data"),
                      "record_volume": a.get("volume"),
                      "processing_regions": a.get("regions", []),
                      "access": a.get("access"),
                      "business_criticality": a.get("crit"),
                      "right_to_audit": rta,
                      "regulations": a.get("regulations", [])},
            "inherent_risk_questionnaire": irq,
            "inherent_score": a["inherent"],
            "inherent_tier": TIER_LABEL[a["tier"]],
            "tier_escalation": a.get("tier_reasons", []),
            "required_tsc_categories": required,
            "criteria_coverage_pct": cov_pct,
            "control_questionnaire": {"answers": answers,
                                      "domain_scores": per,
                                      "overall_pct": q_overall},
            "evidence": a.get("evidence_name"),
            "report_extracted": {k: v for k, v in ext.items()
                                 if not k.startswith("_")},
            "extraction_method": ext.get("_method"),
            "citations": {f: {"value": c["value"], "page": c.get("page"),
                              "quote": c["excerpt"],
                              "confidence": c["confidence"],
                              "source": c.get("source")}
                          for f, c in ext.get("_cites", {}).items()},
            "review_queue": {pi.FIELD_LABEL.get(f, f): {
                "reviewer_value": a.get(REVIEW_PREFIX + "q_" + f),
                "confirmed": bool(a.get(REVIEW_PREFIX + "qc_" + f))}
                for f in ext.get("_queue", [])},
            "report_scope": {k: v for k, v in (ext.get("_scope") or {}).items()
                             if k != "region_cite"},
            "cuecs": [dict(c, **s) for c, s in zip(ext.get("_cuecs", []),
                                                   ext.get("_cuec_state", []))],
            "subservice_organisations": [
                dict(o, downstream_evidence=s) for o, s in zip(
                    ext.get("_subservice", []), ext.get("_sub_state", []))],
            "exceptions": [dict(e, **s) for e, s in zip(
                ext.get("_exceptions", []), ext.get("_exc_state", []))],
            "document_triage": a.get("pdf"),
            "control_maturity": maturity,
            "maturity_breakdown": [{"factor": l, "points": p}
                                   for l, p in adjustments],
            "coverage_gaps": missing,
            "contracts": {
                doc: {"file": a["contracts"][doc]["name"],
                      "clauses": {ct.CLAUSE[k][2]: {"status": v[0],
                                                    "quote": v[1],
                                                    "note": v[2]}
                                  for k, v in a["contracts"][doc][
                                      "results"].items()}}
                for doc in a.get("docs", []) if a.get("contracts", {}).get(doc)},
            "cross_document_obligations": [
                {"question": qt, "source": src, "status": stt or "Not provided",
                 "evidence": det} for qt, src, stt, det in obligations],
            "control_matrix": [
                {"id": r["id"], "control": r["name"],
                 "iso_27001_2022": r["iso"], "soc2_tsc": r["tsc"],
                 "nist_800_53_r5": r["nist"], "status": r["status"],
                 "score": None if r["score"] is None else round(r["score"], 2),
                 "evidence": [{"source": l, "value": v, "note": n}
                              for l, v, n in r["evidence"]]}
                for r in matrix],
            "evidence_register": evidence_rows(a),
            "residual_score": residual, "residual_band": band,
            "findings": plain,
            "recommendation": rec,
            "sign_off": {"reviewer": a.get("signoff_name") or None,
                         "decision": a.get("signoff_decision", "Pending"),
                         "comments": a.get("signoff_note") or None,
                         "date": TODAY.isoformat()},
            "disclaimer": "Demo on synthetic data. Not audit or legal advice.",
        }
        reg = evidence_rows(a)
        md = ["# Vendor Trust Evaluation — %s" % a.get("vendor"),
              "**Legal entity:** %s  " % (a.get("legal_name") or "—"),
              "**Generated:** %s · **Reviewer:** %s · **Decision:** %s  "
              % (TODAY.isoformat(), a.get("signoff_name") or "—",
                 a.get("signoff_decision", "Pending")),
              "**Category:** %s · **Product:** %s · **Owner:** %s · "
              "**Renewal:** %s  " % (a.get("category"), a.get("product") or "—",
                                     a.get("owner") or "unassigned",
                                     iso(a.get("contract_end")) or "—"),
              "**Inherent:** %d (%s) · **Right to audit:** %s  "
              % (a["inherent"], TIER_LABEL[a["tier"]], rta),
              "**Evidence:** %s · %s · %s  " % (
                  a.get("evidence_name"), ext["report_type"],
                  ext["auditor_opinion"]),
              "**Questionnaire:** %d%% self-attested · %d critical gaps  "
              % (q_overall, len(critical)),
              "**Control maturity:** %d/100 · **Residual:** %d (%s)  "
              % (maturity, residual, band),
              "**Required TSC:** %s · **Criteria coverage:** %d%%  "
              % (", ".join(required), cov_pct),
              "", "## Findings"] + ["- " + p for p in plain] \
            + ["", "## Recommendation", rec]
        if a.get("signoff_note"):
            md += ["", "**Reviewer conditions:** %s" % a["signoff_note"]]
        if ext.get("_cites"):
            md += ["", "## Report evidence (page citations)",
                   "| Field | Value | Page | Confidence | Quote |",
                   "|---|---|---|---|---|"]
            for f, c in ext["_cites"].items():
                v = c["value"]
                md.append("| %s | %s | %s | %s | %s |" % (
                    pi.FIELD_LABEL.get(f, f.replace("_", " ")),
                    ", ".join(v) if isinstance(v, list) else v,
                    c.get("page") or "—", c["confidence"],
                    c["excerpt"].replace("|", "/")))
        if ext.get("_cuecs"):
            md += ["", "## CUECs", "| CUEC | Page | Owner | Status |",
                   "|---|---|---|---|"]
            md += ["| %s | %s | %s | %s |" % (c["text"].replace("|", "/"),
                                             c.get("page") or "—",
                                             s["owner"] or "—", s["status"])
                   for c, s in zip(ext["_cuecs"], ext["_cuec_state"])]
        if ext.get("_exceptions"):
            md += ["", "## Exceptions", "| Control | Sample | Page | Decision "
                   "| Rationale |", "|---|---|---|---|---|"]
            md += ["| %s | %s | %s | %s | %s |" % (
                e["control"], e["sample"], e.get("page") or "—", s["decision"],
                s["note"] or "—") for e, s in zip(ext["_exceptions"],
                                                   ext["_exc_state"])]
        if ext.get("_subservice"):
            md += ["", "## Subservice organisations",
                   "| Organisation | Type | Method | Downstream evidence |",
                   "|---|---|---|---|"]
            md += ["| %s | %s | %s | %s |" % (o["name"], o["type"],
                                             o["method"], s)
                   for o, s in zip(ext["_subservice"], ext["_sub_state"])]
        md += ["", "## Cross-document obligations",
               "| Question | Source | Status | Evidence |", "|---|---|---|---|"]
        md += ["| %s | %s | %s | %s |" % (qt, src, stt or "Not provided",
                                         det.replace("|", "/"))
               for qt, src, stt, det in obligations]
        md += ["", "## Control mapping (ISO 27001:2022 ↔ SOC 2 ↔ NIST 800-53)",
               "| Control | ISO 27001 | SOC 2 TSC | NIST 800-53 | Status |",
               "|---|---|---|---|---|"]
        md += ["| %s %s | %s | %s | %s | %s |" % (
            r["id"], r["name"], ", ".join(r["iso"]), ", ".join(r["tsc"]),
            ", ".join(r["nist"]), r["status"]) for r in matrix]
        md += ["", "## Control questionnaire"]
        md += ["- %s: %s" % (d["name"], "n/a" if per[d["key"]] is None
                             else "%d%%" % per[d["key"]]) for d in domains]
        md += ["", "## Evidence register",
               "| ID | Document | File | SHA-256 | Loaded |",
               "|---|---|---|---|---|"]
        md += ["| %s | %s | %s | `%s` | %s |" % (r["id"], r["type"], r["name"],
                                                r["sha256"], r["loaded"])
               for r in reg]
        md += ["", "_Demo on synthetic data. Not audit or legal advice._"]
        fname = (a.get("vendor") or "vendor").replace(" ", "_")
        md_text = "\n".join(md)
        json_text = json.dumps(report, indent=2, default=str)
        jira = jira_csv(findings, a.get("vendor") or "Vendor")
        pack = io.BytesIO()
        with zipfile.ZipFile(pack, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("vendor_review_%s.md" % fname, md_text)
            z.writestr("vendor_review_%s.json" % fname, json_text)
            z.writestr("control_matrix_%s.csv" % fname, matrix_csv(matrix))
            z.writestr("jira_import_%s.csv" % fname, jira)
            z.writestr("evidence_register_%s.csv" % fname, "\n".join(
                ["ID,Type,File,SHA-256,Pages,Status,Loaded"] +
                ['%s,%s,"%s",%s,%s,%s,%s' % (
                    r["id"], r["type"], r["name"], r["sha256"],
                    r["pages"] or "", r["status"], r["loaded"])
                 for r in reg]))
        st.download_button("⬇ Evidence pack (ZIP)", pack.getvalue(),
                           file_name="vendor_review_pack_%s.zip" % fname,
                           mime="application/zip", type="primary",
                           use_container_width=True)
        st.download_button("⬇ Report (Markdown)", md_text,
                           file_name="vendor_review_%s.md" % fname,
                           mime="text/markdown", use_container_width=True)
        st.download_button("⬇ Report (JSON)", json_text,
                           file_name="vendor_review_%s.json" % fname,
                           mime="application/json", use_container_width=True)
        st.download_button("⬇ Findings for Jira (CSV)", jira,
                           file_name="jira_import_%s.csv" % fname,
                           mime="text/csv", use_container_width=True)
        st.caption("The pack bundles the report, JSON, control matrix, Jira "
                   "import and evidence register (with SHA-256 hashes).")

    c1, _, c2 = st.container(key="btnrow_end").columns([1, 2, 1])
    if c1.button("← Back", use_container_width=True):
        goto(5)
    if c2.button("Start a new assessment", use_container_width=True):
        st.session_state.a = {}
        st.session_state.tour = None
        clear_questionnaire_widgets()
        goto(0)

html("<p class='foot'>Designed by <b>%s</b> · GRC &amp; security automation · "
     "<span class='dev' style='font-size:.62rem'>IN DEVELOPMENT</span> · v2.1</p>"
     % DESIGNER)

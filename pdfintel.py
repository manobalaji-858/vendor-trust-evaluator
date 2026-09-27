"""
PDF intelligence for vendor assurance reports (v2.1).

Turns a SOC 2 PDF into cited, reviewable data:
  * triage  — readable? password-protected? scanned (needs OCR)? too short?
  * extract — report type, opinion, period, report date, TSC categories,
              exceptions, CUECs, subservice organisations and report scope,
              each with the page number and the sentence it came from
  * merge   — compare rule results with an optional AI extraction; agreement
              raises confidence, disagreement goes to a human review queue

Rules first, AI second: every value the app relies on can be traced to a
page, and anything uncertain is shown to a reviewer rather than trusted.
"""

import datetime as dt
import hashlib
import io
import re

# ---------------------------------------------------------------- helpers --
MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct",
          "nov", "dec"]
DATE_RE = r"([A-Z][a-z]+)\s+(\d{1,2}),?\s+(\d{4})"
CONTROL_RE = r"\b(CC\d\.\d+|A1\.\d|C1\.\d|PI1\.\d|P\d\.\d)\b"
CATEGORIES = ["Security", "Availability", "Confidentiality",
              "Processing Integrity", "Privacy"]
EXCLUDED_RE = (r"not in scope|not included|were excluded|are excluded|"
               r"excluded from|outside (?:of )?the scope|out of scope")
REGION_PATTERNS = {
    "United States": r"\bunited states\b|\bU\.S\.|us-(?:east|west)-\d|\bUSA\b",
    "EU / EEA": r"\beuropean union\b|\bEU\b|\bEEA\b|eu-(?:west|central|north)-\d"
                r"|\bireland\b|\bfrankfurt\b",
    "United Kingdom": r"\bunited kingdom\b|\bUK\b|\blondon\b",
    "India": r"\bindia\b|ap-south-\d|\bmumbai\b",
    "Singapore / APAC": r"\bsingapore\b|ap-southeast-\d|\bsydney\b|\btokyo\b"
                        r"|\bAPAC\b",
    "Middle East": r"\bmiddle east\b|\bUAE\b|\bbahrain\b|me-south-\d",
}
PROVIDERS = {  # well-known subservice organisations -> service type
    "Amazon Web Services": "Cloud hosting", "AWS": "Cloud hosting",
    "Microsoft Azure": "Cloud hosting", "Azure": "Cloud hosting",
    "Google Cloud": "Cloud hosting", "GCP": "Cloud hosting",
    "Oracle Cloud": "Cloud hosting", "IBM Cloud": "Cloud hosting",
    "Stripe": "Payments", "Adyen": "Payments", "PayPal": "Payments",
    "Okta": "Identity", "Auth0": "Identity", "Ping Identity": "Identity",
    "Twilio": "Communications", "SendGrid": "Email", "Mailgun": "Email",
    "Snowflake": "Data warehouse", "Databricks": "Data platform",
    "MongoDB Atlas": "Database", "Datadog": "Monitoring",
    "Cloudflare": "CDN / security", "Akamai": "CDN / security",
    "Salesforce": "CRM", "Zendesk": "Support", "Atlassian": "Collaboration",
    "Equinix": "Data centre", "Digital Realty": "Data centre",
}
ALIASES = {"AWS": "Amazon Web Services", "Azure": "Microsoft Azure",
           "GCP": "Google Cloud"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _norm(text):
    return re.sub(r"\s+", " ", text or "").strip()


def _sentences(text):
    parts = re.split(r"(?<=[.;])\s+(?=[A-Z0-9(\-•])", _norm(text))
    return [p.strip() for p in parts if len(p.strip()) > 3]


def _dates(text):
    out = []
    for mon, day, yr in re.findall(DATE_RE, text or ""):
        m = mon.lower()[:3]
        if m in MONTHS:
            try:
                out.append(dt.date(int(yr), MONTHS.index(m) + 1, int(day)))
            except ValueError:
                pass
    return out


def _cite(value, page, sentence, confidence, source="rules"):
    s = _norm(sentence)
    return {"value": value, "page": page,
            "excerpt": s if len(s) <= 260 else s[:257] + "…",
            "confidence": confidence, "source": source}


# ----------------------------------------------------------------- triage --
def triage(data):
    """(info, pages) — document checks before anything is extracted."""
    from pypdf import PdfReader
    info = {"sha256": sha256(data), "size_kb": round(len(data) / 1024, 1),
            "status": "OK", "issues": [], "pages": 0, "text_pages": 0,
            "title": None, "created": None}
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as e:  # noqa: BLE001
        info["status"] = "Unreadable"
        info["issues"].append("Not a valid PDF (%s)." % type(e).__name__)
        return info, []
    if reader.is_encrypted:
        try:
            ok = reader.decrypt("")
        except Exception:  # noqa: BLE001
            ok = 0
        if not ok:
            info["status"] = "Password-protected"
            info["issues"].append("The PDF is encrypted. Ask the vendor for "
                                  "an unlocked copy, or open it with the "
                                  "password and re-save it first.")
            return info, []
        info["issues"].append("Encrypted with an empty password — opened "
                              "read-only.")
    try:
        meta = reader.metadata or {}
        info["title"] = meta.get("/Title")
        info["created"] = str(meta.get("/CreationDate") or "") or None
    except Exception:  # noqa: BLE001
        pass
    pages = []
    for p in reader.pages:
        try:
            pages.append(p.extract_text() or "")
        except Exception:  # noqa: BLE001
            pages.append("")
    n = len(pages)
    text_pages = sum(1 for t in pages if len(t.strip()) > 80)
    info.update(pages=n, text_pages=text_pages)
    if n and text_pages == 0:
        info["status"] = "Scanned — OCR required"
        info["issues"].append("No page has a text layer, so this looks like "
                              "a scan. OCR isn't run in this demo; request "
                              "the text-based PDF from the vendor.")
    elif n and text_pages < 0.6 * n:
        info["status"] = "Partly scanned"
        info["issues"].append("%d of %d pages have no text layer — those "
                              "pages need OCR or manual review."
                              % (n - text_pages, n))
    if 0 < n < 10:
        if info["status"] == "OK":
            info["status"] = "Check"
        info["issues"].append("Only %d pages. SOC 2 reports usually run "
                              "40–200 pages — this may be an excerpt, a SOC 3 "
                              "or a bridge letter." % n)
    return info, pages


# ---------------------------------------------------------------- extract --
def extract(pages):
    """Rule-based, page-cited extraction. Returns the app's report dict
    plus `_cites`, `_exceptions`, `_cuecs`, `_subservice`, `_scope`."""
    # drop running footers ("Page 12 of 140 | ...") so they don't leak into text
    pages = [re.sub(r"\bPage \d+ of \d+\b(?: \|[^\n]*)?", " ", t or "")
             for t in pages]
    sents = [(i, s) for i, t in enumerate(pages, 1) for s in _sentences(t)]
    full = " ".join(_norm(t) for t in pages)
    cites = {}

    def find(pattern, where=None):
        for p, s in sents:
            if (where is None or where(p, s)) and re.search(pattern, s, re.I):
                return p, s
        return None

    # report type
    hit = find(r"\bSOC 3\b")
    if hit:
        cites["report_type"] = _cite("SOC 3", *hit, "High")
    elif find(r"\bType (?:2|II)\b"):
        cites["report_type"] = _cite("SOC 2 Type II", *find(
            r"\bType (?:2|II)\b"), "High")
    elif find(r"\bType (?:1|I)\b"):
        cites["report_type"] = _cite("SOC 2 Type I", *find(
            r"\bType (?:1|I)\b"), "High")
    elif find(r"throughout the period"):
        cites["report_type"] = _cite("SOC 2 Type II", *find(
            r"throughout the period"), "Medium")
    elif find(r"\bas of " + DATE_RE):
        cites["report_type"] = _cite("SOC 2 Type I", *find(
            r"\bas of " + DATE_RE), "Medium")

    # auditor opinion
    hit = find(r"in our opinion")
    if hit:
        low = hit[1].lower()
        if "except for" in low:
            cites["auditor_opinion"] = _cite("Qualified", *hit, "High")
        elif re.search(r"do(?:es)? not present fairly|adverse", low):
            cites["auditor_opinion"] = _cite("Adverse", *hit, "High")
        elif re.search(r"do not express|disclaim", low):
            cites["auditor_opinion"] = _cite("Disclaimer", *hit, "High")
        elif "in all material respects" in low:
            cites["auditor_opinion"] = _cite("Unqualified", *hit, "High")
        else:
            cites["auditor_opinion"] = _cite("Unknown", *hit, "Low")

    # period and report date
    hit = find(r"(?:throughout|for) the period|period (?:from )?" + DATE_RE)
    if hit and len(_dates(hit[1])) >= 2:
        d = sorted(_dates(hit[1]))
        cites["period_start"] = _cite(d[0].isoformat(), *hit, "High")
        cites["period_end"] = _cite(d[-1].isoformat(), *hit, "High")
    else:
        hit = find(r"\bas of " + DATE_RE)
        if hit:
            cites["period_end"] = _cite(_dates(hit[1])[0].isoformat(), *hit,
                                        "Medium")
    op = cites.get("auditor_opinion")
    if op:
        period = {cites[k]["value"] for k in ("period_start", "period_end")
                  if k in cites}
        later = [(p, s) for p, s in sents if p in (op["page"], op["page"] + 1)
                 and _dates(s) and not re.search(r"period|as of", s, re.I)]
        for p, s in later:
            ds = [d for d in _dates(s) if d.isoformat() not in period]
            if ds:
                cites["report_date"] = _cite(max(ds).isoformat(), p, s,
                                             "Medium")
                break

    # TSC categories examined
    excluded = set()
    for p, s in sents:
        if re.search(EXCLUDED_RE, s, re.I):
            excluded |= {c for c in CATEGORIES if c.lower() in s.lower()}
    hit = find(r"relevant to|criteria for the", lambda p, s: any(
        c.lower() in s.lower() for c in CATEGORIES))
    if hit:
        cats = [c for c in CATEGORIES if c.lower() in hit[1].lower()
                and c not in excluded]
        cites["tsc_categories"] = _cite(cats, *hit, "High")
    else:
        cats = [c for c in CATEGORIES if c.lower() in full.lower()
                and c not in excluded] or ["Security"]
        cites["tsc_categories"] = _cite(cats, 1, "Inferred from the report "
                                        "text; no scope sentence found.",
                                        "Low")

    # exceptions: one row per exception, with the control it relates to
    exceptions = []
    for idx, (p, s) in enumerate(sents):
        if not re.search(r"exception|deviation", s, re.I):
            continue
        if re.search(r"\bno (?:exceptions|deviations)|without exception|"
                     r"not noted|complementary|not covered by", s, re.I):
            continue
        if len(s) < 40:
            continue
        ctrl = re.search(CONTROL_RE, s)
        if not ctrl:
            for back in range(1, 3):
                if idx - back >= 0 and sents[idx - back][0] == p:
                    ctrl = re.search(CONTROL_RE, sents[idx - back][1])
                    if ctrl:
                        break
        sample = re.search(r"(\d+) of (\d+)", s)
        exceptions.append({"control": ctrl.group(1) if ctrl else "—",
                           "text": _cite(None, p, s, "High")["excerpt"],
                           "sample": "%s of %s" % sample.groups()
                           if sample else "—", "page": p})

    # CUECs: the listed items, not just the mention
    cuecs, cuec_mention = [], None
    for i, t in enumerate(pages, 1):
        text = _norm(t)
        m = re.search(r"complementary user entity controls?", text, re.I)
        if not m:
            continue
        cuec_mention = cuec_mention or (i, text[max(0, m.start() - 40):
                                                m.end() + 160])
        body = re.split(r"\bSECTION [IVX]+\b", text[m.end():])[0]
        items = [x.strip() for x in re.split(r"\s[-•▪]\s", " " + body)
                 if len(x.strip()) > 25][1:]
        for it in items:
            cuecs.append({"text": it if len(it) <= 220 else it[:217] + "…",
                          "page": i})
    if cuecs:
        cites["cuecs"] = _cite(len(cuecs), cuecs[0]["page"], cuecs[0]["text"],
                               "High")
    elif cuec_mention:
        cites["cuecs"] = _cite(0, cuec_mention[0], cuec_mention[1], "Low")

    # subservice organisations and the carve-out / inclusive method
    hit = find(r"carve-?\s?out|carved out")
    if hit:
        cites["subservice_method"] = _cite("Carve-out", *hit, "High")
    elif find(r"inclusive method"):
        cites["subservice_method"] = _cite("Inclusive", *find(
            r"inclusive method"), "High")
    sub_pages = [i for i, t in enumerate(pages, 1)
                 if re.search(r"subservice organi[sz]ation", t, re.I)]
    orgs = {}
    for i in sub_pages:
        text = _norm(pages[i - 1])
        for name, kind in PROVIDERS.items():
            if re.search(r"\b%s\b" % re.escape(name), text):
                canon = ALIASES.get(name, name)
                orgs.setdefault(canon, {"name": canon, "type": kind,
                                        "page": i})
    method = cites.get("subservice_method", {}).get("value", "Unknown")
    subservice = [dict(o, method=method) for o in orgs.values()]

    # report scope: system, regions and anything explicitly excluded
    sysm = re.search(r"description of (?:its|the) ([A-Z][\w&\- ]{2,60}?) "
                     r"system", full)
    regions, region_cite, exclusions = [], None, []
    for p, s in sents:
        if re.search(EXCLUDED_RE, s, re.I):
            exclusions.append({"text": _cite(None, p, s, "High")["excerpt"],
                               "page": p})
            continue
        if re.search(r"hosted|\bregions?\b|data cent|located|deployed", s,
                     re.I):
            found = [r for r, pat in REGION_PATTERNS.items()
                     if re.search(pat, s, re.I)]
            for r in found:
                if r not in regions:
                    regions.append(r)
            if found and not region_cite:
                region_cite = _cite(found, p, s, "High")
    scope = {"system": sysm.group(1).strip() if sysm else None,
             "regions": regions, "region_cite": region_cite,
             "exclusions": exclusions}

    def val(k, default=None):
        return cites[k]["value"] if k in cites else default

    return {
        "report_type": val("report_type", "Unknown"),
        "period_start": val("period_start"),
        "period_end": val("period_end"),
        "report_date": val("report_date"),
        "tsc_categories": val("tsc_categories", ["Security"]),
        "auditor_opinion": val("auditor_opinion", "Unknown"),
        "exceptions_noted": bool(exceptions),
        "exceptions_summary": exceptions[0]["text"] if exceptions else None,
        "cuecs_present": bool(cuecs or cuec_mention),
        "cuecs_summary": cuecs[0]["text"] if cuecs else None,
        "subservice_method": method,
        "_method": "rules (page-cited)",
        "_cites": cites, "_exceptions": exceptions, "_cuecs": cuecs,
        "_subservice": subservice, "_scope": scope,
        "_haystack": full.lower()[:300000],
    }


def completeness(ext):
    """Structural problems worth flagging before relying on the report."""
    issues = []
    cites = ext.get("_cites", {})
    if "auditor_opinion" not in cites:
        issues.append("No auditor opinion found — the file may be incomplete "
                      "or not an auditor's report.")
    if "period_end" not in cites:
        issues.append("No audit period found.")
    if ext.get("report_type") == "SOC 2 Type II" and not re.search(
            r"tests? (?:of|and|performed)|results? of tests|result:",
            ext.get("_haystack", "")):
        issues.append("No control tests or results found — Type II reports "
                      "normally include them (usually Section IV).")
    return issues


# ------------------------------------------------------ AI cross-checking --
REVIEW_FIELDS = {
    "report_type": ["SOC 2 Type II", "SOC 2 Type I", "SOC 3", "Unknown"],
    "auditor_opinion": ["Unqualified", "Qualified", "Adverse", "Disclaimer",
                        "Unknown"],
    "period_end": None,
    "subservice_method": ["Carve-out", "Inclusive", "Unknown"],
    "tsc_categories": None,
}
FIELD_LABEL = {"report_type": "Report type", "auditor_opinion": "Auditor "
               "opinion", "period_end": "Audit period end",
               "subservice_method": "Subservice method",
               "tsc_categories": "TSC categories examined"}


def ai_context(pages, ext, limit=12000):
    """The pages that matter, instead of the first N characters."""
    keep = {c["page"] for c in ext.get("_cites", {}).values()
            if c.get("page")}
    keep |= {e["page"] for e in ext.get("_exceptions", [])}
    keep |= {c["page"] for c in ext.get("_cuecs", [])}
    keep = sorted(keep) or list(range(1, min(len(pages), 4) + 1))
    out = ""
    for p in keep:
        chunk = "\n[Page %d]\n%s" % (p, _norm(pages[p - 1]))
        if len(out) + len(chunk) > limit:
            break
        out += chunk
    return out


def _same(field, a, b):
    if field == "tsc_categories":
        return set(a or []) == set(b or [])
    return (a or "Unknown") == (b or "Unknown")


def merge(ext, ai=None):
    """Combine rules with AI; returns ext with confidence and review queue."""
    cites = ext.setdefault("_cites", {})
    queue = []
    for f in REVIEW_FIELDS:
        c = cites.get(f)
        ai_val = (ai or {}).get(f)
        if ai is not None and ai_val not in (None, "", [], "Unknown"):
            if c and _same(f, c["value"], ai_val):
                c["confidence"] = "High"
                c["source"] = "rules + AI agree"
            elif c:
                c["confidence"] = "Low"
                c["source"] = "rules and AI disagree"
                c["alt"] = ai_val
            else:
                cites[f] = {"value": ai_val, "page": None,
                            "excerpt": "Found by AI only — no matching "
                                       "sentence located.",
                            "confidence": "Medium", "source": "AI only"}
                ext[f] = ai_val
        c = cites.get(f)
        if c is None or c["confidence"] == "Low":
            queue.append(f)
    if ai:
        for k in ("exceptions_summary", "cuecs_summary"):
            if not ext.get(k) and ai.get(k):
                ext[k] = ai[k]
    ext["_queue"] = queue
    return ext


# ------------------------------------------------------- synthetic sample --
SAMPLE_PAGES = [
    """NimbusCRM Cloud, Inc.
SOC 2 Type 2 Report
Report on NimbusCRM Cloud, Inc.'s Description of Its NimbusCRM Sales Cloud System and on the Suitability of the Design and Operating Effectiveness of Its Controls Relevant to Security, Availability and Confidentiality.
Independent service auditor: Harbor and Lane Assurance LLP.
SYNTHETIC SAMPLE - FOR DEMONSTRATION ONLY.""",
    """Table of Contents
Section I - Independent Service Auditor's Report
Section II - Management's Assertion
Section III - Description of the System
Section IV - Trust Services Criteria, Controls, Tests and Results
Section V - Other Information""",
    """SECTION I - INDEPENDENT SERVICE AUDITOR'S REPORT
To the Management of NimbusCRM Cloud, Inc.
Scope. We have examined the accompanying description of its NimbusCRM Sales Cloud system throughout the period October 1, 2025 to March 31, 2026, and the suitability of the design and operating effectiveness of controls to meet the criteria relevant to Security, Availability and Confidentiality set forth in TSP section 100.
Subservice organizations. NimbusCRM Cloud uses Amazon Web Services (AWS) as a subservice organization for cloud hosting. The description excludes the controls of AWS and this examination applies the carve-out method.
The description indicates that complementary user entity controls are necessary, together with the controls at NimbusCRM Cloud, to meet the criteria.""",
    """Opinion. In our opinion, in all material respects, the description presents the NimbusCRM Sales Cloud system that was designed and implemented throughout the period October 1, 2025 to March 31, 2026, and the controls stated in the description operated effectively throughout that period.
Harbor and Lane Assurance LLP.
Signed on May 15, 2026.""",
    """SECTION II - MANAGEMENT'S ASSERTION
We have prepared the accompanying description of the NimbusCRM Sales Cloud system. We confirm, to the best of our knowledge and belief, that the description is fairly presented and that the controls operated effectively throughout the period described.""",
    """SECTION III - DESCRIPTION OF THE SYSTEM
Services provided. NimbusCRM Sales Cloud is a multi-tenant customer relationship management platform used by sales and marketing teams.
Scope and boundaries. The system is hosted in the AWS us-east-1 region in the United States (Northern Virginia).
Other regions and the NimbusCRM Marketing Hub product are not included in the scope of this report.
The Privacy and Processing Integrity categories were not in scope for this examination.""",
    """Subservice organizations. NimbusCRM Cloud uses the following subservice organizations: Amazon Web Services (AWS) for infrastructure hosting, and Twilio for SMS notifications. The carve-out method has been applied, so the controls at these organizations are not covered by this report.
Complementary subservice organization controls: AWS is expected to maintain physical security and environmental protections for its data centers.""",
    """Complementary User Entity Controls (CUECs). NimbusCRM Cloud designed its controls with the assumption that user entities implement the following controls:
 - User entities enforce multi-factor authentication for all users through their own identity provider.
 - User entities perform periodic reviews of user access to their NimbusCRM tenant.
 - User entities promptly remove access for their terminated employees.
 - User entities protect the API keys issued to them and rotate them at least annually.""",
    """SECTION IV - TRUST SERVICES CRITERIA, CONTROLS, TESTS AND RESULTS
CC6.2 - Access is removed within one business day of termination. Test: inspected a sample of 25 terminated users. Result: Exception noted - for 2 of 25 sampled terminations, access was not revoked within one business day.
Management response: the control was remediated in Q1 2026 with automated deprovisioning.
CC7.2 - Security events are monitored and alerted. Test: inspected alert configuration and a sample of 40 alerts. Result: No exceptions noted.
CC8.1 - Changes are approved before deployment. Test: inspected a sample of 30 changes. Result: No exceptions noted.
A1.2 - Backups run daily and restores are tested quarterly. Test: inspected backup logs and two restore tests. Result: No exceptions noted.""",
    """SECTION V - OTHER INFORMATION PROVIDED BY NIMBUSCRM CLOUD
This section is not covered by the service auditor's opinion.
SYNTHETIC SAMPLE - FOR DEMONSTRATION ONLY.""",
]


def make_pdf(pages, title="Synthetic SOC 2 report"):
    """Minimal text PDF writer (no dependencies) for the sample report."""
    def esc(s):
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def wrap(line, width=92):
        lead = line[:len(line) - len(line.lstrip())]
        words, out, cur = line.split(), [], lead
        for w in words:
            if len(cur) + len(w) + 1 > width and cur.strip():
                out.append(cur.rstrip())
                cur = lead + "  "
            cur += w + " "
        out.append(cur.rstrip())
        return out

    objs = []
    for i, text in enumerate(pages):
        lines = [l for raw in text.split("\n") for l in (wrap(raw) or [""])]
        ops = ["BT", "/F1 10 Tf", "14 TL", "56 790 Td"]
        for l in lines:
            ops.append("(%s) Tj T*" % esc(l.encode("latin-1", "replace")
                                          .decode("latin-1")))
        ops += ["ET", "BT", "/F1 8 Tf", "56 40 Td",
                "(Page %d of %d | %s) Tj" % (i + 1, len(pages), esc(title)),
                "ET"]
        stream = "\n".join(ops).encode("latin-1", "replace")
        objs.append(("page", stream))
    # object numbers: 1 catalog, 2 pages, 3 font, 4 info, then page/content
    offsets = []
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")

    def add(num, content):
        offsets.append((num, out.tell()))
        out.write(b"%d 0 obj\n" % num + content + b"\nendobj\n")

    n_pages = len(objs)
    page_nums = [5 + 2 * i for i in range(n_pages)]
    add(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    add(2, b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(b"%d 0 R" % n for n in page_nums), n_pages))
    add(3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    add(4, b"<< /Title (%s) /Producer (Vendor Trust Evaluator) >>"
        % esc(title).encode("latin-1"))
    for i, (_, stream) in enumerate(objs):
        pn = page_nums[i]
        add(pn, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                b"/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>"
            % (pn + 1))
        add(pn + 1, b"<< /Length %d >>\nstream\n" % len(stream) + stream +
            b"\nendstream")
    xref_at = out.tell()
    total = 5 + 2 * n_pages
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % total)
    pos = dict(offsets)
    for num in range(1, total):
        out.write(b"%010d 00000 n \n" % pos[num])
    out.write(b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\n"
              b"startxref\n%d\n%%%%EOF\n" % (total, xref_at))
    return out.getvalue()


def sample_pdf():
    return make_pdf(SAMPLE_PAGES, "Synthetic SOC 2 Type 2 - NimbusCRM Cloud")

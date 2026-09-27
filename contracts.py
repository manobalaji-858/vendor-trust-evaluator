"""
Contract clause review and the unified control matrix.

Contracts (DPA / MSA / SOW) are checked with transparent keyword rules, not
an AI model: every result quotes the sentence it matched, so a reviewer can
verify it, and contract text never leaves the app. Clause presence is not a
legal opinion on adequacy.

Each unified control maps to ISO/IEC 27001:2022 Annex A and the AICPA Trust
Services Criteria, and lists the evidence sources that decide its status.
"""

import re

DOCS = {
    "DPA": "Data Processing Agreement (DPA)",
    "MSA": "Master Services Agreement (MSA)",
    "SOW": "Statement of Work (SOW)",
}


def _hours_grade(sentence):
    """Breach-notice deadline: <= 72h is Met; longer or no fixed time Partial."""
    m = re.search(r"(\d+)\s*hours", sentence, re.I)
    if m:
        h = int(m.group(1))
        return ("Met", "notice within %dh" % h) if h <= 72 else \
            ("Partial", "notice within %dh — longer than 72h" % h)
    return "Partial", "no fixed deadline (e.g. only 'without undue delay')"


def _uptime_grade(sentence):
    m = re.search(r"(\d{2}(?:\.\d+)?)\s*%", sentence)
    if m:
        pct = float(m.group(1))
        return ("Met", "%s%% uptime" % m.group(1)) if pct >= 99.9 else \
            ("Partial", "%s%% uptime — below 99.9%%" % m.group(1))
    return "Met", ""


# (id, doc, clause, find regexes, must also contain regex, critical, grader)
CLAUSES = [
    # --- DPA: GDPR Art. 28(3) processor terms + transfers ---
    ("dpa_instr", "DPA", "Processing only on documented instructions",
     [r"documented instructions", r"only on (?:the )?instructions"], None,
     False, None),
    ("dpa_conf", "DPA", "Personnel bound by confidentiality",
     [r"confidentiality (?:obligations?|undertaking)",
      r"bound by (?:a duty of )?confidentiality", r"duty of confidentiality"],
     None, False, None),
    ("dpa_sec", "DPA", "Security measures (Art. 32)",
     [r"technical and organi[sz]ational measures", r"article 32"], None,
     False, None),
    ("dpa_subp", "DPA", "Sub-processor authorisation",
     [r"sub-?processors?"], r"prior|consent|authori[sz]|object", True, None),
    ("dpa_dsr", "DPA", "Assistance with data subject requests",
     [r"data subjects?"], r"request|rights", False, None),
    ("dpa_breach", "DPA", "Personal data breach notification",
     [r"(?:personal )?data breach"], r"notif", True, _hours_grade),
    ("dpa_delete", "DPA", "Deletion or return at end of services",
     [r"\bdelet", r"\breturn"], r"terminat|end of|expir", True, None),
    ("dpa_audit", "DPA", "Audit and information rights",
     [r"\baudits?\b", r"inspections?"], r"allow|permit|make available|contribute",
     False, None),
    ("dpa_transfer", "DPA", "International transfer mechanism",
     [r"standard contractual clauses", r"\bSCCs?\b", r"adequacy decision",
      r"binding corporate rules", r"transfer mechanism"], None, True, None),
    # --- MSA: commercial and security terms ---
    ("msa_rta", "MSA", "Right to audit",
     [r"right to audit", r"audit rights", r"may audit",
      r"(?:conduct|perform) an? audit"], None, True, None),
    ("msa_soc2", "MSA", "Current SOC 2 Type II (or equivalent) required",
     [r"SOC 2 Type (?:II|2)", r"SSAE ?18", r"ISAE ?3402",
      r"independent (?:audit|assurance) report"], None, False, None),
    ("msa_secsched", "MSA", "Information security schedule / requirements",
     [r"information security (?:schedule|requirements|policy|exhibit)",
      r"security (?:schedule|exhibit|addendum)"], None, False, None),
    ("msa_conf", "MSA", "Confidentiality",
     [r"confidential information"], None, False, None),
    ("msa_breach", "MSA", "Security incident notification",
     [r"security incident", r"security breach"], r"notif", False,
     _hours_grade),
    ("msa_liab", "MSA", "Liability and indemnity for data breaches",
     [r"indemnif", r"limitation of liability", r"liability is capped"], None,
     False, None),
    ("msa_ins", "MSA", "Cyber insurance",
     [r"insurance"], None, False, None),
    ("msa_subc", "MSA", "Subcontracting approval",
     [r"subcontract"], r"consent|approv|authori[sz]", False, None),
    ("msa_term", "MSA", "Exit and transition assistance",
     [r"termination assistance", r"exit (?:plan|assistance)",
      r"transition (?:assistance|services)"], None, False, None),
    ("msa_sla", "MSA", "Service levels and availability",
     [r"service levels?", r"available \d{2}(?:\.\d+)?\s*%", r"uptime"], None,
     False, _uptime_grade),
    ("msa_law", "MSA", "Compliance with laws",
     [r"comply with (?:all )?applicable (?:laws|data protection)"], None,
     False, None),
    # --- SOW: what is actually being bought ---
    ("sow_scope", "SOW", "Scope of services and deliverables",
     [r"scope of (?:services|work)", r"deliverables"], None, False, None),
    ("sow_data", "SOW", "Data categories identified",
     [r"personal data", r"customer data", r"categories of data"], None,
     False, None),
    ("sow_loc", "SOW", "Service and data locations",
     [r"hosted in", r"data cent(?:er|re)s?", r"\blocations?\b", r"\bregion"],
     None, False, None),
    ("sow_access", "SOW", "Access requirements defined",
     [r"\baccess\b"], r"system|tenant|network|environment|SSO|VPN", False,
     None),
    ("sow_personnel", "SOW", "Personnel screening",
     [r"background (?:checks?|verification|screening)", r"\bvetting\b"],
     None, False, None),
    ("sow_sla", "SOW", "Acceptance criteria and service measures",
     [r"acceptance criteria", r"service levels?", r"\bKPIs?\b"], None, False,
     None),
]
CLAUSE = {c[0]: c for c in CLAUSES}


SECTION_RE = r"^\s*(\d+(?:\.\d+)*)[.)]\s"


def sentences(text):
    """(section, sentence) pairs. A numbered line ("5. Audit. ...") starts a
    section; short fragments are headings, not quotable evidence."""
    out, section = [], None

    def heading(line):
        letters = [c for c in line if c.isalpha()]
        return len(line) < 90 and len(letters) > 3 and \
            sum(c.isupper() for c in letters) / len(letters) > 0.8

    text = "\n".join(l for l in text.split("\n") if not heading(l.strip()))
    chunks = re.split(r"\n(?=\s*\d+(?:\.\d+)*[.)]\s)", text)
    for chunk in chunks:
        m = re.match(SECTION_RE, chunk)
        if m:
            section = m.group(1)
        flat = re.sub(r"\s+", " ", chunk)
        for p in re.split(r"(?<=[.;:])\s+", flat):
            if len(p.strip()) > 30:
                out.append((section, p.strip()))
    return out


def analyze(doc, text):
    """{clause_id: (status, snippet, note)} for every clause of `doc`.
    The snippet starts with its section number, e.g. "§5 · Customer may…"."""
    sents = sentences(text)
    out = {}
    for cid, d, _, finds, near, _, grade in CLAUSES:
        if d != doc:
            continue
        hit = None
        for section, s in sents:
            if any(re.search(f, s, re.I) for f in finds) and \
                    (not near or re.search(near, s, re.I)):
                hit = (section, s)
                break
        if not hit:
            out[cid] = ("Missing", "", "")
            continue
        section, s = hit
        status, note = grade(s) if grade else ("Met", "")
        quote = s if len(s) <= 230 else s[:227] + "…"
        out[cid] = (status, ("§%s · " % section if section else "") + quote,
                    note)
    return out


def fingerprint(text):
    """SHA-256 of a document's text, for the evidence register."""
    import hashlib
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


# ---- ISO/IEC 27001:2022 Annex A and TSC names for referenced controls ----
ISO = {
    "A.5.1": "Policies for information security",
    "A.5.2": "Information security roles and responsibilities",
    "A.5.12": "Classification of information",
    "A.5.14": "Information transfer",
    "A.5.15": "Access control",
    "A.5.18": "Access rights",
    "A.5.19": "Information security in supplier relationships",
    "A.5.20": "Addressing information security within supplier agreements",
    "A.5.21": "Managing information security in the ICT supply chain",
    "A.5.22": "Monitoring, review and change management of supplier services",
    "A.5.24": "Incident management planning and preparation",
    "A.5.26": "Response to information security incidents",
    "A.5.29": "Information security during disruption",
    "A.5.30": "ICT readiness for business continuity",
    "A.5.31": "Legal, statutory, regulatory and contractual requirements",
    "A.5.34": "Privacy and protection of PII",
    "A.5.35": "Independent review of information security",
    "A.6.1": "Screening",
    "A.6.6": "Confidentiality or non-disclosure agreements",
    "A.6.8": "Information security event reporting",
    "A.8.2": "Privileged access rights",
    "A.8.5": "Secure authentication",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.10": "Information deletion",
    "A.8.13": "Information backup",
    "A.8.14": "Redundancy of information processing facilities",
    "A.8.16": "Monitoring activities",
    "A.8.24": "Use of cryptography",
    "A.8.32": "Change management",
}
TSC = {
    "CC1.1": "Integrity and ethical values",
    "CC1.3": "Structures, reporting lines and authorities",
    "CC1.4": "Commitment to competence",
    "CC2.3": "Communication with external parties",
    "CC4.1": "Ongoing and separate evaluations",
    "CC5.3": "Policies and procedures",
    "CC6.1": "Logical access security",
    "CC6.2": "User registration and authorisation",
    "CC6.3": "Role-based access and least privilege",
    "CC6.7": "Restricting data transmission and movement",
    "CC7.1": "Detection of vulnerabilities and configuration changes",
    "CC7.2": "Monitoring for anomalies",
    "CC7.3": "Evaluation of security events",
    "CC7.4": "Incident response",
    "CC8.1": "Change management",
    "CC9.1": "Mitigating business disruption risk",
    "CC9.2": "Vendor and business partner risk",
    "C1.1": "Identify and maintain confidential information",
    "C1.2": "Dispose of confidential information",
    "A1.1": "Capacity management",
    "A1.2": "Environmental protections, backup and recovery",
    "A1.3": "Recovery plan testing",
    "P3": "Collection",
    "P4": "Use, retention and disposal",
    "P5": "Access",
    "P6": "Disclosure and notification",
}

# Unified controls: (id, name, ISO refs, TSC refs, evidence sources).
# Sources: ("clause", id) · ("q", question id) · ("soc2", TSC category) ·
# ("soc2type",) · ("subservice",) · ("rta",) · ("owner",)
CONTROLS = [
    ("UC01", "Security requirements in supplier agreements",
     ["A.5.19", "A.5.20"], ["CC9.2"],
     [("clause", "msa_secsched"), ("clause", "sow_scope"),
      ("clause", "dpa_sec")]),
    ("UC02", "Independent assurance and right to audit",
     ["A.5.22", "A.5.35"], ["CC4.1", "CC9.2"],
     [("clause", "msa_rta"), ("clause", "msa_soc2"), ("clause", "dpa_audit"),
      ("rta",), ("soc2type",), ("q", "edd1")]),
    ("UC03", "Confidentiality and non-disclosure",
     ["A.6.6"], ["C1.1"],
     [("clause", "msa_conf"), ("clause", "dpa_conf"), ("q", "dat4")]),
    ("UC04", "PII processed on instructions; data subject rights",
     ["A.5.34"], ["P3", "P4", "P5"],
     [("clause", "dpa_instr"), ("clause", "dpa_dsr"), ("q", "prv2"),
      ("q", "prv3"), ("soc2", "Privacy")]),
    ("UC05", "International data transfers",
     ["A.5.14", "A.5.34"], ["P6", "CC6.7"],
     [("clause", "dpa_transfer"), ("clause", "sow_loc"), ("q", "prv5")]),
    ("UC06", "Sub-processors and ICT supply chain",
     ["A.5.21"], ["CC9.2"],
     [("clause", "dpa_subp"), ("clause", "msa_subc"), ("q", "tpr1"),
      ("q", "tpr2"), ("q", "tpr4"), ("subservice",)]),
    ("UC07", "Incident and breach notification",
     ["A.5.24", "A.5.26", "A.6.8"], ["CC7.3", "CC7.4", "P6"],
     [("clause", "dpa_breach"), ("clause", "msa_breach"), ("q", "inc1"),
      ("q", "inc2")]),
    ("UC08", "Access control and authentication",
     ["A.5.15", "A.5.18", "A.8.2", "A.8.5"], ["CC6.1", "CC6.2", "CC6.3"],
     [("clause", "sow_access"), ("q", "iam1"), ("q", "iam3"), ("q", "iam4"),
      ("q", "iam5"), ("soc2", "Security")]),
    ("UC09", "Cryptography",
     ["A.8.24"], ["CC6.1", "CC6.7"],
     [("clause", "dpa_sec"), ("q", "dat1"), ("q", "dat2"), ("q", "dat3")]),
    ("UC10", "Secure deletion and return of data",
     ["A.8.10"], ["C1.2", "P4"],
     [("clause", "dpa_delete"), ("q", "dat5"), ("q", "edd2")]),
    ("UC11", "Personnel screening",
     ["A.6.1"], ["CC1.4"],
     [("clause", "sow_personnel"), ("q", "gov4")]),
    ("UC12", "Vulnerability management and monitoring",
     ["A.8.8", "A.8.16"], ["CC7.1", "CC7.2"],
     [("q", "ops1"), ("q", "ops2"), ("q", "ops3"), ("q", "ops4"),
      ("soc2", "Security")]),
    ("UC13", "Change management",
     ["A.8.32"], ["CC8.1"],
     [("q", "chg1"), ("q", "chg2"), ("q", "chg3"), ("soc2", "Security")]),
    ("UC14", "Business continuity and availability",
     ["A.5.29", "A.5.30", "A.8.13", "A.8.14"], ["A1.1", "A1.2", "A1.3"],
     [("clause", "msa_sla"), ("q", "bcp1"), ("q", "bcp2"), ("q", "bcp3"),
      ("q", "bcp4"), ("soc2", "Availability")]),
    ("UC15", "Legal, regulatory and contractual compliance",
     ["A.5.31"], ["CC2.3", "CC9.1"],
     [("clause", "msa_law"), ("clause", "msa_liab"), ("clause", "msa_ins")]),
    ("UC16", "Supplier monitoring, ownership and exit",
     ["A.5.19", "A.5.22"], ["CC9.2"],
     [("clause", "msa_term"), ("clause", "sow_sla"), ("owner",),
      ("q", "edd2")]),
    ("UC17", "Security governance and policy",
     ["A.5.1", "A.5.2"], ["CC1.1", "CC1.3", "CC5.3"],
     [("q", "gov1"), ("q", "gov2"), ("q", "gov5"), ("soc2", "Security")]),
    ("UC18", "Data classification and inventory",
     ["A.5.12"], ["C1.1"],
     [("clause", "sow_data"), ("q", "dat4")]),
]


# NIST SP 800-53 Rev. 5 mappings for each unified control (many-to-many)
NIST_MAP = {
    "UC01": ["SA-4", "SA-9", "SR-3"],
    "UC02": ["CA-2", "CA-7", "SA-9"],
    "UC03": ["PS-6"],
    "UC04": ["PT-2", "PT-3"],
    "UC05": ["SA-9(5)", "PT-2"],
    "UC06": ["SR-3", "SR-6", "SA-9"],
    "UC07": ["IR-4", "IR-6"],
    "UC08": ["AC-2", "AC-6", "IA-2"],
    "UC09": ["SC-8", "SC-12", "SC-13", "SC-28"],
    "UC10": ["MP-6", "SI-12"],
    "UC11": ["PS-3"],
    "UC12": ["RA-5", "SI-2", "SI-4"],
    "UC13": ["CM-3", "CM-4"],
    "UC14": ["CP-2", "CP-9", "CP-10"],
    "UC15": ["SA-4", "SR-5"],
    "UC16": ["SA-9", "SR-6"],
    "UC17": ["PM-1", "PM-2"],
    "UC18": ["RA-2", "CM-8"],
}
NIST = {
    "AC-2": "Account management",
    "AC-6": "Least privilege",
    "CA-2": "Control assessments",
    "CA-7": "Continuous monitoring",
    "CM-3": "Configuration change control",
    "CM-4": "Impact analyses",
    "CM-8": "System component inventory",
    "CP-2": "Contingency plan",
    "CP-9": "System backup",
    "CP-10": "System recovery and reconstitution",
    "IA-2": "Identification and authentication (organizational users)",
    "IR-4": "Incident handling",
    "IR-6": "Incident reporting",
    "MP-6": "Media sanitization",
    "PM-1": "Information security program plan",
    "PM-2": "Information security program leadership role",
    "PS-3": "Personnel screening",
    "PS-6": "Access agreements",
    "PT-2": "Authority to process PII",
    "PT-3": "PII processing purposes",
    "RA-2": "Security categorization",
    "RA-5": "Vulnerability monitoring and scanning",
    "SA-4": "Acquisition process",
    "SA-9": "External system services",
    "SA-9(5)": "Processing, storage and service location",
    "SC-8": "Transmission confidentiality and integrity",
    "SC-12": "Cryptographic key establishment and management",
    "SC-13": "Cryptographic protection",
    "SC-28": "Protection of information at rest",
    "SI-2": "Flaw remediation",
    "SI-4": "System monitoring",
    "SI-12": "Information management and retention",
    "SR-3": "Supply chain controls and processes",
    "SR-5": "Acquisition strategies, tools and methods",
    "SR-6": "Supplier assessments and reviews",
}


# ---- Synthetic sample agreements (NimbusCRM) — deliberate gaps included ----
SAMPLES = {
    "DPA": """DATA PROCESSING AGREEMENT
This Data Processing Agreement forms part of the Master Services Agreement between Customer and NimbusCRM Cloud, Inc. (the Processor).
1. Processing. Processor shall process Personal Data only on the documented instructions of Customer, including with regard to transfers.
2. Confidentiality. Processor shall ensure that persons authorised to process Personal Data are bound by confidentiality obligations.
3. Security. Processor shall implement appropriate technical and organisational measures in accordance with Article 32 GDPR, as described in Annex II.
4. Sub-processors. Processor shall not engage a new sub-processor without prior written notice to Customer, giving Customer 30 days to object.
5. Data subject requests. Processor shall assist Customer in responding to requests from data subjects exercising their rights.
6. Personal data breach. Processor shall notify Customer of a Personal Data Breach within 96 hours of becoming aware of it.
7. Deletion. On termination of the services, Processor shall delete or return all Personal Data at Customer's choice.
8. Audits. Processor shall make available all information necessary to demonstrate compliance and allow for audits, including inspections, by Customer.
""",
    "MSA": """MASTER SERVICES AGREEMENT
1. Services. Supplier shall provide the services described in each Statement of Work.
2. Confidential Information. Each party shall protect the other party's Confidential Information using at least reasonable care.
3. Information Security. Supplier shall comply with the Information Security Schedule attached as Exhibit B.
4. Security incidents. Supplier shall notify Customer of any Security Incident without undue delay.
5. Audit. Customer may audit Supplier's compliance with this Agreement once per year on 30 days' notice, or rely on Supplier's current SOC 2 Type II report.
6. Subcontracting. Supplier may not subcontract any obligation without Customer's prior written consent.
7. Service levels. Supplier shall make the service available 99.5% of the time each month, excluding scheduled maintenance.
8. Limitation of liability. Each party's liability is capped at the fees paid in the prior twelve months, except for breaches of confidentiality or data protection obligations, for which Supplier shall indemnify Customer.
9. Compliance with laws. Each party shall comply with all applicable laws, including applicable data protection laws.
10. Term and termination. Either party may terminate for material breach on 30 days' written notice.
""",
    "SOW": """STATEMENT OF WORK No. 1 — CRM PLATFORM
Scope of services: NimbusCRM will provide its CRM platform, onboarding and support for the Sales & Marketing team. Deliverables include tenant configuration and data migration.
Data: the service will process customer personal data (names, emails, phone numbers) and sales pipeline data.
Location: customer data will be hosted in data centres in the EU (Ireland), with support staff in the United States.
Access: Supplier support staff will have read access to Customer's CRM tenant via SSO; no connection to Customer's internal network is required.
Service measures: support tickets are acknowledged within 4 business hours, and acceptance criteria are defined in Appendix A.
""",
}

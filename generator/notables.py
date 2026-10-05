#!/usr/bin/env python3
"""Build deterministic direct Splunk ES findings for SILK SPECTER.

Every synthetic notable is backed by exactly one event that already exists in
``dataset/<track>/hec/events.jsonl``.

Truth alignment is strict:
* ``True Positive`` -> the backing authored event has ``truth_label=malicious``.
* ``Benign Positive`` -> the backing event is either authored
  ``truth_label=benign`` evidence or generated non-malicious background noise.

These are non-RBA findings. ``risk_object``/``risk_object_type`` are populated
because the ES finding action uses them to define the finding entity, and
``entity``/``entity_type`` are set to the exact same values. No risk-threshold
or multi-finding aggregation fields are generated.

Participant data never includes instructor truth labels or expected
dispositions.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import argparse
import csv
import json
import random
import re
import uuid

ROOT = Path(__file__).resolve().parents[1]

NOISE_CATALOG = [
    ("Multiple Failed Logons From Workstation", "medium", "access"),
    ("Administrative PowerShell On Server", "low", "endpoint"),
    ("New Service Installation", "medium", "endpoint"),
    ("Rare DNS Query From User Segment", "low", "network"),
    ("Large File Transfer To Approved Partner", "medium", "network"),
    ("Unsigned Process From User Profile", "medium", "endpoint"),
    ("Remote Administration Tool Usage", "medium", "endpoint"),
    ("Cloud Console Login From New ASN", "medium", "access"),
    ("Service Account Interactive Logon", "high", "access"),
    ("Endpoint Malware Heuristic", "high", "endpoint"),
    ("Firewall Deny Burst", "low", "network"),
    ("Privileged Group Membership Change", "high", "access"),
    ("Vulnerability Scanner Fan-Out", "informational", "network"),
    ("MFA Retry Pattern", "low", "access"),
    ("High Volume SMB Read", "medium", "network"),
    ("Unusual Scheduled Task", "medium", "endpoint"),
    ("DLP Policy Match With User Justification", "medium", "threat"),
    ("SSH Login From Management Segment", "low", "access"),
    ("New OAuth Application Consent", "medium", "access"),
    ("Rare User Agent To SaaS Service", "low", "network"),
]

NOISE_DESCRIPTIONS = {
    "Multiple Failed Logons From Workstation": "Multiple authentication failures were observed from a single workstation during a short interval.",
    "Administrative PowerShell On Server": "PowerShell was executed with administrative context on a server outside the host's usual interactive pattern.",
    "New Service Installation": "A new Windows service was installed and should be validated against approved software deployment activity.",
    "Rare DNS Query From User Segment": "A user-segment host queried a domain rarely observed in the current analysis window.",
    "Large File Transfer To Approved Partner": "A large outbound transfer to an approved partner destination exceeded the normal transfer-volume baseline.",
    "Unsigned Process From User Profile": "An unsigned executable launched from a user-writable profile path.",
    "Remote Administration Tool Usage": "Remote administration software was observed and requires validation against authorized support activity.",
    "Cloud Console Login From New ASN": "A cloud console authentication originated from an ASN not previously associated with the user.",
    "Service Account Interactive Logon": "A service account performed an interactive logon that should be validated against operational requirements.",
    "Endpoint Malware Heuristic": "Endpoint protection generated a heuristic detection requiring analyst validation and host context.",
    "Firewall Deny Burst": "A burst of denied firewall connections exceeded the normal rate for the source.",
    "Privileged Group Membership Change": "Membership of a privileged group changed and requires validation against approved administration.",
    "Vulnerability Scanner Fan-Out": "A host contacted many systems in a pattern consistent with broad vulnerability scanning.",
    "MFA Retry Pattern": "Repeated multifactor authentication attempts were observed for the same identity.",
    "High Volume SMB Read": "A system read an unusually large volume of data over SMB during the analysis window.",
    "Unusual Scheduled Task": "A scheduled task was created or modified with attributes uncommon for the host.",
    "DLP Policy Match With User Justification": "A data-loss-prevention policy matched content associated with a user-justified transfer.",
    "SSH Login From Management Segment": "An SSH session originated from a management network and should be checked against administrator activity.",
    "New OAuth Application Consent": "A user granted consent to an OAuth application not previously observed for the identity.",
    "Rare User Agent To SaaS Service": "A SaaS request used a rare user-agent string for the source identity or system.",
}

SEVERITY_WORDS = {
    "critical": "critical",
    "exfil": "critical",
    "lsass": "high",
    "credential": "high",
    "lateral": "high",
    "pivot": "high",
    "exploit": "high",
    "shell": "high",
    "archive": "medium",
    "vpn": "medium",
    "cloud": "medium",
    "scanner": "informational",
    "recon": "medium",
}

FINDING_SCORES = {
    "critical": 90,
    "high": 70,
    "medium": 50,
    "low": 25,
    "informational": 10,
    "unknown": 0,
}

DISPOSITION_BY_TRUTH = {
    "malicious": "True Positive",
    "benign": "Benign Positive",
}

NON_MALICIOUS_BACKGROUND = "non-malicious"

# Only attach ATT&CK metadata when the title makes the mapping unambiguous.
MITRE_TITLE_MAP = [
    (("web application exploitation", "public-facing"), "T1190", "Exploit Public-Facing Application", "initial-access"),
    (("wmi",), "T1047", "Windows Management Instrumentation", "execution"),
    (("lsass",), "T1003.001", "LSASS Memory", "credential-access"),
    (("scheduled task",), "T1053.005", "Scheduled Task/Job: Scheduled Task", "persistence"),
    (("service installation",), "T1543.003", "Create or Modify System Process: Windows Service", "persistence"),
    (("archive", "staging"), "T1560.001", "Archive Collected Data: Archive via Utility", "collection"),
    (("powershell",), "T1059.001", "Command and Scripting Interpreter: PowerShell", "execution"),
    (("valid account", "vpn", "service account"), "T1078", "Valid Accounts", "defense-evasion"),
    (("remote administration tool",), "T1219", "Remote Access Software", "command-and-control"),
]

JSON_SRC_KEYS = ("src", "src_ip", "source_ip", "client_ip", "id.orig_h", "ipAddress")
JSON_DEST_KEYS = ("dest", "dest_ip", "destination_ip", "server_ip", "id.resp_h")
JSON_USER_KEYS = ("user", "username", "user_name", "TargetUserName", "employee_id")
XML_SRC_KEYS = ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress")
XML_USER_KEYS = ("User", "TargetUserName", "SubjectUserName", "AccountName")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def q(value: object) -> str:
    text = str(value if value is not None else "")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def infer_urgency(title: str) -> str:
    low = title.lower()
    for token, urgency in SEVERITY_WORDS.items():
        if token in low:
            return urgency
    return "medium"


def infer_domain(title: str) -> str:
    low = title.lower()
    if any(x in low for x in ("vpn", "logon", "account", "credential", "mfa")):
        return "access"
    if any(x in low for x in ("cloud", "gitlab", "oauth", "saas")):
        return "threat"
    if any(x in low for x in ("shell", "process", "lsass", "archive", "service", "scheduled")):
        return "endpoint"
    return "network"


def event_time_for_activity(activity_rows, activity_id: str, offset: int) -> datetime:
    rows = activity_rows.get(activity_id, [])
    if not rows:
        raise ValueError(f"No ground-truth events found for activity {activity_id}")
    return min(parse_iso(r["time"]) for r in rows) + timedelta(seconds=60 + offset)


def _first(mapping: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", "-", "unknown"):
            return str(value)
    return ""


def _parse_xml_data(raw: str) -> dict[str, str]:
    return {
        name: re.sub(r"<[^>]+>", "", value).strip()
        for name, value in re.findall(
            r"<Data\s+Name=['\"]([^'\"]+)['\"]>(.*?)</Data>", raw, flags=re.IGNORECASE | re.DOTALL
        )
    }


def extract_observables(rows: list[dict]) -> tuple[str, str, str]:
    """Best-effort participant-safe src/dest/user extraction from static evidence."""
    src = ""
    dest = ""
    user = ""

    for row in rows:
        raw = str(row.get("raw", ""))
        parsed: dict = {}
        stripped = raw.lstrip()
        if stripped.startswith("{"):
            try:
                candidate = json.loads(stripped)
                if isinstance(candidate, dict):
                    parsed = candidate
            except json.JSONDecodeError:
                parsed = {}
        if parsed:
            src = src or _first(parsed, JSON_SRC_KEYS)
            dest = dest or _first(parsed, JSON_DEST_KEYS)
            user = user or _first(parsed, JSON_USER_KEYS)
        elif "<Data " in raw:
            xml = _parse_xml_data(raw)
            src = src or _first(xml, XML_SRC_KEYS)
            user = user or _first(xml, XML_USER_KEYS)

        dest = dest or str(row.get("host", "") or "")
        if src and dest and user:
            break

    return src or "-", dest or "-", user or "-"


def choose_entity(domain: str, src: str, dest: str, user: str) -> tuple[str, str]:
    if domain in {"access", "identity"} and user not in {"", "-"}:
        return user, "user"
    if domain == "network" and src not in {"", "-"}:
        return src, "network_artifacts"
    if dest not in {"", "-"}:
        return dest, "system"
    if src not in {"", "-"}:
        return src, "network_artifacts"
    if user not in {"", "-"}:
        return user, "user"
    return "unknown", "other"



def _search_quote(value: object) -> str:
    text = str(value if value is not None else "")
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def source_event_id_for_generated(row: dict) -> str:
    material = "|".join(
        str(row.get(key, ""))
        for key in ("time", "host", "source", "sourcetype", "event")
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "silk-specter:generated-source:" + material))


def static_event_signature(row: dict) -> tuple:
    return (
        round(parse_iso(str(row["time"])).timestamp(), 6),
        str(row.get("host", "")),
        str(row.get("source", "")),
        str(row.get("sourcetype", "")),
        str(row.get("raw", "")),
    )


def generated_event_signature(row: dict) -> tuple:
    return (
        round(float(row["time"]), 6),
        str(row.get("host", "")),
        str(row.get("source", "")),
        str(row.get("sourcetype", "")),
        str(row.get("event", "")),
    )


def load_generated_events(dataset_dir: Path) -> list[dict]:
    path = dataset_dir / "hec" / "events.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"Missing generated participant HEC data: {path}")
    head = path.read_text(encoding="utf-8", errors="replace")[:128]
    if head.startswith("version https://git-lfs.github.com/spec/v1"):
        raise RuntimeError(
            f"Generated HEC data is an unmaterialized Git LFS pointer: {path}. "
            "Run make generate-<track> before rebuilding notables."
        )
    events = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    return events


def event_drilldown(source_index: str, row: dict, event_time: datetime) -> str:
    earliest = int(event_time.timestamp()) - 1
    latest = int(event_time.timestamp()) + 2
    return (
        f"index={source_index} earliest={earliest} latest={latest} "
        f"host={_search_quote(row.get('host', ''))} "
        f"source={_search_quote(row.get('source', ''))} "
        f"sourcetype={_search_quote(row.get('sourcetype', ''))}"
    )


def representative_event(rows: list[dict], rule_name: str, used_event_ids: set[str]) -> dict:
    """Pick one real authored event to back one direct, non-RBA notable."""
    low = rule_name.lower()

    def score(row: dict) -> tuple[int, str]:
        st = str(row.get("sourcetype", "")).lower()
        src = str(row.get("source", "")).lower()
        raw = str(row.get("raw", "")).lower()
        hay = " ".join((st, src, raw[:2000]))
        points = 0
        preferences = [
            (("shell", "powershell"), ("sysmon", "xmlwineventlog", "4688", "eventid>1<", "powershell"), 40),
            (("web", "exploit", "public-facing"), ("waf", "access_combined", "apache", "bro:http", "http"), 40),
            (("vpn", "authentication", "valid account", "service account"), ("radius", "4624", "4625", "vpn", "pan:traffic"), 40),
            (("wmi",), ("dce_rpc", "wmi", "xmlwineventlog", "4624", "4688"), 45),
            (("lsass", "credential"), ("lsass", "sysmon", "defender", "xmlwineventlog"), 45),
            (("gitlab",), ("gitlab", "bro:http", "bro:ssl"), 45),
            (("cloud", "aws"), ("cloudtrail", "aws:"), 45),
            (("archive", "staging"), ("7z", "compress-archive", "sysmon", "xmlwineventlog", "linux_audit"), 45),
            (("outbound", "transfer", "exfil", "mft", "dlp"), ("mft", "dlp", "bro:conn", "bro:http", "bro:ssl", "pan:traffic", "fortigate"), 45),
            (("portproxy",), ("portproxy", "netsh", "sysmon", "xmlwineventlog"), 50),
            (("winrm",), ("winrm", "5985", "5986", "xmlwineventlog", "bro:conn"), 50),
            (("scanner", "recon"), ("tenable", "bro:conn", "bro:dns", "pan:traffic"), 35),
            (("change",), ("servicenow", "change_request"), 35),
        ]
        for rule_tokens, evidence_tokens, weight in preferences:
            if any(token in low for token in rule_tokens) and any(token in hay for token in evidence_tokens):
                points += weight
        if row.get("event_id") not in used_event_ids:
            points += 10
        # Prefer the earliest equally-good source event for deterministic results.
        return points, str(row.get("time", ""))

    ranked = sorted(rows, key=lambda row: (-score(row)[0], score(row)[1], str(row.get("event_id", ""))))
    if not ranked:
        raise ValueError(f"No source events available for rule {rule_name!r}")
    chosen = ranked[0]
    used_event_ids.add(str(chosen.get("event_id", "")))
    return chosen


def classify_background_event(row: dict) -> tuple[str, str, str] | None:
    """Map one generated background event to a plausible direct notable rule."""
    st = str(row.get("sourcetype", "")).lower()
    src = str(row.get("source", "")).lower()
    raw = str(row.get("event", ""))
    low = raw.lower()

    if st == "xmlwineventlog":
        m = re.search(r"<EventID>(\d+)</EventID>", raw)
        event_id = m.group(1) if m else ""
        if event_id == "4625":
            return "Failed Logon From Workstation", "medium", "access"
        if event_id == "4624":
            return "Interactive Logon From User Workstation", "low", "access"
        if event_id == "1":
            return "Rare Process Execution On Endpoint", "low", "endpoint"
        if event_id == "3":
            return "Unusual Endpoint Network Connection", "medium", "network"
        if event_id == "11":
            return "Executable Written To Endpoint", "medium", "endpoint"
        if event_id == "22":
            return "Rare DNS Query From Endpoint", "low", "network"
        return "Windows Security Activity Review", "low", "endpoint"
    if st in {"bro:dns:json", "zeek:dns"}:
        return "Rare DNS Query From User Segment", "low", "network"
    if st in {"bro:conn:json", "zeek:conn"}:
        return "Rare Outbound Connection From User Segment", "low", "network"
    if st in {"bro:http:json", "zeek:http"}:
        return "Rare HTTP Request To External Service", "low", "network"
    if st in {"bro:ssl:json", "zeek:tls", "zeek:ssl"}:
        return "TLS Connection To Rare Destination", "low", "network"
    if st in {"pan:traffic", "fortigate_traffic", "cisco:asa", "juniper:junos:firewall"}:
        return "Firewall Connection Pattern Review", "low", "network"
    if st == "aws:cloudtrail":
        return "Cloud API Activity From New Source", "medium", "threat"
    if st == "aws:cloudwatchlogs:vpcflow":
        return "Cloud Network Flow Anomaly", "low", "network"
    if st == "ms:defender:eventhub":
        return "Endpoint Security Alert", "medium", "endpoint"
    if st in {"linux_secure", "linux:secure"}:
        return "SSH Authentication Activity", "low", "access"
    if st in {"linux_audit", "auditd"}:
        return "Privileged Linux Activity", "medium", "endpoint"
    if st.startswith("radius") or src.startswith("radius"):
        return "Remote Access Authentication Review", "medium", "access"
    if st == "pacs:access":
        return "Physical Access Pattern Review", "low", "access"
    if "mft" in st or "mft" in src:
        return "Large File Transfer To Approved Partner", "medium", "network"
    if "dlp" in st or "dlp" in src:
        return "DLP Policy Match With User Justification", "medium", "threat"
    if "servicenow" in st or "servicenow" in src:
        return "Change Activity Requiring Validation", "low", "audit"
    if "gitlab" in st or "gitlab" in src:
        return "Git Repository Activity Review", "low", "threat"
    if st.startswith("sccm") or "ivanti" in st or "wsus" in st:
        return "Administrative Software Deployment", "low", "endpoint"
    if "smb_files" in st:
        return "High Volume SMB Read", "medium", "network"
    if "code42" in st:
        return "Data Protection Activity Review", "medium", "threat"
    return None


def load_generated_background_events(generated_events: list[dict], truth: list[dict]) -> list[dict]:
    """Return generated events that are not authored campaign/static rows."""
    static_signatures = {static_event_signature(row) for row in truth}
    return [
        row for row in generated_events
        if generated_event_signature(row) not in static_signatures
    ]


def select_noise_events(events: list[dict], count: int, rng: random.Random) -> list[tuple[dict, str, str, str]]:
    by_rule: dict[str, list[tuple[dict, str, str, str]]] = defaultdict(list)
    for row in events:
        classified = classify_background_event(row)
        if classified is None:
            continue
        title, urgency, domain = classified
        by_rule[title].append((row, title, urgency, domain))
    if sum(len(v) for v in by_rule.values()) < count:
        raise ValueError(f"Only {sum(len(v) for v in by_rule.values())} usable generated background events for {count} noise notables")
    for values in by_rule.values():
        rng.shuffle(values)
    rules = sorted(by_rule)
    rng.shuffle(rules)
    selected: list[tuple[dict, str, str, str]] = []
    while len(selected) < count:
        progressed = False
        for rule in rules:
            if by_rule[rule]:
                selected.append(by_rule[rule].pop())
                progressed = True
                if len(selected) == count:
                    break
        if not progressed:
            break
    return selected

def attack_annotations(rule_name: str, kind: str) -> str:
    annotation: dict[str, list[str]] = {
        "analytic_story": ["SILK SPECTER"],
        "type": ["TTP" if kind == "campaign" else "Anomaly"],
        "type_list": ["TTP" if kind == "campaign" else "Anomaly"],
    }
    if kind == "campaign":
        low = rule_name.lower()
        for tokens, technique_id, technique, tactic in MITRE_TITLE_MAP:
            if any(token in low for token in tokens):
                annotation["mitre_attack"] = [technique_id]
                annotation["mitre_attack_technique"] = [technique]
                annotation["mitre_attack_tactic"] = [tactic]
                break
    return json.dumps(annotation, separators=(",", ":"))


def notable_raw(
    *,
    event_id: str,
    source_event_id: str,
    rule_name: str,
    description: str,
    urgency: str,
    domain: str,
    scenario: str,
    source_index: str,
    src: str,
    dest: str,
    user: str,
    risk_object: str,
    risk_object_type: str,
    finding_score: int,
    drilldown_search: str,
    event_time: float,
    source_time: float,
    kind: str,
) -> str:
    """Render one direct ES finding backed by one generated source event."""
    epoch = int(event_time)
    source_epoch = int(source_time)
    search_name = f"SS - {rule_name} - Rule"
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:rule:{scenario}:{rule_name}"))
    detection_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:detection:{scenario}:{rule_name}"))
    source_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:source-guid:{source_event_id}"))
    annotations = attack_annotations(rule_name, kind)
    first_last = datetime.fromtimestamp(
        source_time,
        tz=parse_iso("2026-01-01T00:00:00Z").tzinfo,
    ).strftime("%Y-%m-%dT%H:%M:%S")

    asset_type = {
        "access": "Identity",
        "identity": "Identity",
        "endpoint": "Endpoint",
        "network": "Network",
        "threat": "Threat",
        "audit": "Audit",
    }.get(domain, "Other")

    fields: list[tuple[str, object]] = [
        ("search_name", search_name),
        ("_time", epoch),
        ("event_id", event_id),
        ("orig_sid", event_id),
        ("rule_id", rule_id),
        ("detection_id", detection_id),
        ("detection_type", "ebd"),
        ("rule_name", rule_name),
        ("rule_title", rule_name),
        ("orig_rule_title", rule_name),
        ("description", description),
        ("rule_description", description),
        ("orig_rule_description", description),
        ("savedsearch_description", description),
        ("risk_message", description),
        ("urgency", urgency),
        ("severity", urgency),
        ("priority", urgency),
        ("status", "1"),
        ("status_label", "New"),
        ("owner", "unassigned"),
        ("security_domain", domain),
        ("orig_security_domain", domain),
        ("app", "SA-SilkSpecter"),
        ("app_name", "SA-SilkSpecter"),
        ("product", "Splunk Enterprise Security"),
        ("vendor_product", "Asteron Utilities Group"),
        ("asset_type", asset_type),
        ("finding_type", "finding"),
        ("notable_type", "notable"),
        # Splunk ES finding contract: entity is the risk object.
        ("entity", risk_object),
        ("entity_type", risk_object_type),
        ("risk_object", risk_object),
        ("risk_object_type", risk_object_type),
        ("finding_score", finding_score),
        ("risk_score", finding_score),
        ("count", 1),
        ("source_count", 1),
        ("source_event_id", source_event_id),
        ("source_guid", source_guid),
        ("orig_action_name", "notable"),
        ("orig_investigation_type", "default"),
        ("orig_queue_id", "__system_default_queue__"),
        ("orig_time", epoch),
        ("firstTime", first_last),
        ("lastTime", first_last),
        ("info_search_time", epoch),
        ("info_min_time", source_epoch - 300),
        ("info_max_time", source_epoch + 300),
        ("contributing_events_search", drilldown_search),
        ("orig_source", search_name),
        ("orig_tag", "modaction_result"),
        ("version", "2.1"),
        ("annotations", annotations),
        ("annotations.analytic_story", "SILK SPECTER"),
        ("annotations.type", "TTP" if kind == "campaign" else "Anomaly"),
        ("analyticstories", "SILK SPECTER"),
        ("scenario", scenario),
        ("ctf_track", scenario),
        ("source_index", source_index),
        ("src", src),
        ("dest", dest),
        ("user", user),
        ("user_id", user),
        ("drilldown_name", "View source event"),
        ("drilldown_search", drilldown_search),
        ("nes_fields", "src,dest,user,entity,entity_type,risk_object,risk_object_type,risk_score"),
    ]
    annotation_obj = json.loads(annotations)
    if annotation_obj.get("mitre_attack"):
        fields.append(("annotations.mitre_attack", annotation_obj["mitre_attack"][0]))
        fields.append(("annotations.mitre_attack.mitre_technique", annotation_obj["mitre_attack_technique"][0]))
        fields.append(("annotations.mitre_attack.mitre_tactic", annotation_obj["mitre_attack_tactic"][0]))

    return f"{epoch}, " + ", ".join(f"{key}={q(value)}" for key, value in fields)


def campaign_description(finding: dict, source_index: str) -> str:
    notes = (finding.get("notes") or "").strip()
    base = notes.rstrip(".") if notes else finding["detection_name"]
    return f"{base}. Review the linked source event in {source_index} and validate the entity against normal Asteron activity."


def noise_description(title: str, src: str, dest: str, user: str) -> str:
    base = NOISE_DESCRIPTIONS.get(title, f"{title} requires analyst validation.")
    context = []
    if user not in {"", "-"}:
        context.append(f"user={user}")
    if src not in {"", "-"}:
        context.append(f"src={src}")
    if dest not in {"", "-"}:
        context.append(f"dest={dest}")
    return base + (" Observed context: " + ", ".join(context) + "." if context else "")


def build_notables(root: Path, scenario: str, dataset_dir: Path, cfg: dict) -> dict:
    static_rel = cfg.get("static_campaign")
    if not static_rel:
        raise ValueError(f"Scenario {scenario!r} has no static_campaign configured")
    truth_path = root / static_rel
    findings_path = root / "instructor" / "findings" / f"{scenario}_expected_findings.csv"
    if not truth_path.is_file():
        raise FileNotFoundError(f"Missing static campaign ground truth: {truth_path}")
    if not findings_path.is_file():
        raise FileNotFoundError(f"Missing expected findings: {findings_path}")

    truth = [json.loads(line) for line in truth_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    with findings_path.open(newline="", encoding="utf-8") as f:
        findings = list(csv.DictReader(f))

    # Load the actual participant corpus once. Campaign findings are not allowed
    # to point only at instructor/static truth; their chosen source row must also
    # exist byte-for-byte in the generated HEC corpus that participants ingest.
    generated_events = load_generated_events(dataset_dir)
    generated_by_signature: dict[tuple, list[dict]] = defaultdict(list)
    for row in generated_events:
        generated_by_signature[generated_event_signature(row)].append(row)

    malicious_static_signatures = {
        static_event_signature(row)
        for row in truth
        if str(row.get("truth_label", "")).lower() == "malicious"
    }

    activity_rows = defaultdict(list)
    for row in truth:
        activity_rows[row["activity_id"]].append(row)

    seed = int(cfg.get("seed", 0)) + 47001
    rng = random.Random(seed)
    noise_count = int(cfg.get("notables", {}).get("noise_events", 0))
    source_index = "<index>"

    records = []
    instructor_rows = []
    used_campaign_source_ids: set[str] = set()

    expected_to_truth = {
        "malicious": "malicious",
        "benign": "benign",
        "True Positive": "malicious",
        "Benign Positive": "benign",
    }

    # Campaign findings are direct detections over one authored event that is
    # also present in the generated participant corpus.
    for finding in findings:
        activity = finding["activity_id"]
        expected = finding["expected_disposition"]
        if expected not in expected_to_truth:
            raise ValueError(
                f"Unsupported expected disposition {expected!r} for {finding['finding_id']}"
            )
        required_truth = expected_to_truth[expected]
        disposition = DISPOSITION_BY_TRUTH[required_truth]

        rows = [
            row for row in activity_rows[activity]
            if str(row.get("truth_label", "")).lower() == required_truth
        ]
        if not rows:
            raise ValueError(
                f"{finding['finding_id']} expects {disposition}, but activity {activity} "
                f"has no authored event with truth_label={required_truth}"
            )

        rule = finding["detection_name"]
        source_row = representative_event(rows, rule, used_campaign_source_ids)
        signature = static_event_signature(source_row)
        generated_matches = generated_by_signature.get(signature, [])
        if not generated_matches:
            raise ValueError(
                f"{finding['finding_id']} selected authored event {source_row['event_id']} "
                "but that event is not present in the generated participant HEC corpus"
            )
        generated_source = generated_matches[0]

        source_dt = datetime.fromtimestamp(
            float(generated_source["time"]),
            tz=parse_iso(cfg["start"]).tzinfo,
        )
        dt = source_dt + timedelta(seconds=60)
        urgency = infer_urgency(rule)
        domain = infer_domain(rule)
        participant_row = {
            "host": generated_source.get("host", ""),
            "source": generated_source.get("source", ""),
            "sourcetype": generated_source.get("sourcetype", ""),
            "raw": generated_source.get("event", ""),
        }
        src, dest, user = extract_observables([participant_row])
        risk_object, risk_object_type = choose_entity(domain, src, dest, user)
        finding_score = FINDING_SCORES.get(urgency, 0)
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:notable:{scenario}:{finding['finding_id']}"))
        source_event_id = str(source_row["event_id"])
        drill = event_drilldown(source_index, generated_source, source_dt)
        description = campaign_description(finding, source_index)

        records.append({
            "time": dt.timestamp(),
            "host": "SILK-SPECTER-ES",
            "source": f"SS - {rule} - Rule",
            "sourcetype": "stash",
            "event": notable_raw(
                event_id=event_id,
                source_event_id=source_event_id,
                rule_name=rule,
                description=description,
                urgency=urgency,
                domain=domain,
                scenario=scenario,
                source_index=source_index,
                src=src,
                dest=dest,
                user=user,
                risk_object=risk_object,
                risk_object_type=risk_object_type,
                finding_score=finding_score,
                drilldown_search=drill,
                event_time=dt.timestamp(),
                source_time=source_dt.timestamp(),
                kind="campaign",
            ),
        })
        instructor_rows.append({
            "event_id": event_id,
            "scenario": scenario,
            "time": dt.isoformat().replace("+00:00", "Z"),
            "rule_name": rule,
            "expected_disposition": disposition,
            "source_truth_label": required_truth,
            "activity_id": activity,
            "kind": "campaign",
            "entity": risk_object,
            "entity_type": risk_object_type,
            "risk_object": risk_object,
            "risk_object_type": risk_object_type,
            "finding_score": finding_score,
            "risk_score": finding_score,
            "severity": urgency,
            "security_domain": domain,
            "source_count": 1,
            "source_event_id": source_event_id,
            "source_host": generated_source.get("host", ""),
            "source": generated_source.get("source", ""),
            "source_sourcetype": generated_source.get("sourcetype", ""),
            "source_generated_presence": "yes",
            "notes": finding.get("notes", ""),
        })

    # Noise findings are Benign Positives over actual generated background rows.
    # They may not point at any authored malicious/static event.
    background_events = load_generated_background_events(generated_events, truth)
    selected_noise = select_noise_events(background_events, noise_count, rng)
    for source_row, title, urgency, domain in selected_noise:
        signature = generated_event_signature(source_row)
        if signature in malicious_static_signatures:
            raise ValueError("Benign Positive noise selected a malicious authored source event")

        source_dt = datetime.fromtimestamp(
            float(source_row["time"]),
            tz=parse_iso(cfg["start"]).tzinfo,
        )
        dt = source_dt + timedelta(seconds=60)
        participant_row = {
            "host": source_row.get("host", ""),
            "source": source_row.get("source", ""),
            "sourcetype": source_row.get("sourcetype", ""),
            "raw": source_row.get("event", ""),
        }
        src, dest, user = extract_observables([participant_row])
        risk_object, risk_object_type = choose_entity(domain, src, dest, user)
        finding_score = FINDING_SCORES.get(urgency, 0)
        source_event_id = source_event_id_for_generated(source_row)
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:notable-noise:{scenario}:{source_event_id}"))
        drill = event_drilldown(source_index, source_row, source_dt)
        description = noise_description(title, src, dest, user)

        records.append({
            "time": dt.timestamp(),
            "host": "SILK-SPECTER-ES",
            "source": f"SS - {title} - Rule",
            "sourcetype": "stash",
            "event": notable_raw(
                event_id=event_id,
                source_event_id=source_event_id,
                rule_name=title,
                description=description,
                urgency=urgency,
                domain=domain,
                scenario=scenario,
                source_index=source_index,
                src=src,
                dest=dest,
                user=user,
                risk_object=risk_object,
                risk_object_type=risk_object_type,
                finding_score=finding_score,
                drilldown_search=drill,
                event_time=dt.timestamp(),
                source_time=source_dt.timestamp(),
                kind="noise",
            ),
        })
        instructor_rows.append({
            "event_id": event_id,
            "scenario": scenario,
            "time": dt.isoformat().replace("+00:00", "Z"),
            "rule_name": title,
            "expected_disposition": "Benign Positive",
            "source_truth_label": NON_MALICIOUS_BACKGROUND,
            "activity_id": "",
            "kind": "noise",
            "entity": risk_object,
            "entity_type": risk_object_type,
            "risk_object": risk_object,
            "risk_object_type": risk_object_type,
            "finding_score": finding_score,
            "risk_score": finding_score,
            "severity": urgency,
            "security_domain": domain,
            "source_count": 1,
            "source_event_id": source_event_id,
            "source_host": source_row.get("host", ""),
            "source": source_row.get("source", ""),
            "source_sourcetype": source_row.get("sourcetype", ""),
            "source_generated_presence": "yes",
            "notes": "Benign Positive backed by one generated non-malicious background event.",
        })

    records.sort(key=lambda r: (r["time"], r["event"]))
    instructor_rows.sort(key=lambda r: (r["time"], r["event_id"]))

    out = dataset_dir / "notables"
    raw_dir = out / "raw"
    hec_dir = out / "hec"
    raw_dir.mkdir(parents=True, exist_ok=True)
    hec_dir.mkdir(parents=True, exist_ok=True)

    (raw_dir / "notables.log").write_text(
        "\n".join(r["event"] for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    with (hec_dir / "events.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for row in records:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    disposition_counts = defaultdict(int)
    for row in instructor_rows:
        disposition_counts[row["expected_disposition"]] += 1

    manifest = {
        "scenario": scenario,
        "events": len(records),
        "campaign_notables": len(findings),
        "noise_notables": noise_count,
        "true_positive_notables": disposition_counts["True Positive"],
        "benign_positive_notables": disposition_counts["Benign Positive"],
        "sourcetype": "stash",
        "source": "per-event search_name",
        "stash_schema": "es8-direct-notable-kv-v4",
        "notable_model": "non-rba-direct-event-risk-object",
        "source_events_per_notable": 1,
        "truth_contract": {
            "True Positive": "one generated event whose authored truth_label is malicious",
            "Benign Positive": "one generated authored benign event or generated non-malicious background event",
        },
        "entity_contract": "entity=risk_object and entity_type=risk_object_type",
        "canonical_ingest_file": "hec/events.jsonl",
        "participant_filter": f"index=notable host=SILK-SPECTER-ES sourcetype=stash scenario={scenario}",
        "required_finding_fields": [
            "rule_name", "rule_description", "entity", "entity_type",
            "risk_object", "risk_object_type", "finding_score", "risk_score",
            "severity", "urgency", "status_label", "security_domain",
            "source_event_id", "contributing_events_search", "drilldown_search",
        ],
        "forbidden_rba_fields": [
            "all_risk_objects", "normalized_risk_object", "risk_event_count",
            "risk_threshold", "risk_object_system",
        ],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    with (out / "expected_counts.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sourcetype", "expected_count"])
        w.writeheader()
        w.writerow({"sourcetype": "stash", "expected_count": len(records)})
    with (out / "ingest_manifest.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "host", "source", "sourcetype", "event_count"])
        w.writeheader()
        w.writerow({
            "file": "raw/notables.log",
            "host": "SILK-SPECTER-ES",
            "source": "per-event search_name",
            "sourcetype": "stash",
            "event_count": len(records),
        })

    instructor_path = root / "instructor" / "findings" / f"{scenario}_notable_ground_truth.csv"
    with instructor_path.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "event_id", "scenario", "time", "rule_name", "expected_disposition",
            "source_truth_label", "activity_id", "kind",
            "entity", "entity_type", "risk_object", "risk_object_type",
            "finding_score", "risk_score", "severity", "security_domain", "source_count",
            "source_event_id", "source_host", "source", "source_sourcetype",
            "source_generated_presence", "notes",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(instructor_rows)

    return manifest


def main() -> None:
    ap = argparse.ArgumentParser(description="Build deterministic SILK SPECTER notable feed")
    ap.add_argument("--scenario", choices=["easy", "medium", "hard"], required=True)
    ap.add_argument("--dataset", help="Dataset directory; default dataset/<scenario>")
    args = ap.parse_args()
    cfg = json.loads((ROOT / "config" / "scenarios" / f"{args.scenario}.json").read_text(encoding="utf-8"))
    dataset = Path(args.dataset) if args.dataset else ROOT / "dataset" / args.scenario
    print(json.dumps(build_notables(ROOT, args.scenario, dataset, cfg), indent=2))


if __name__ == "__main__":
    main()

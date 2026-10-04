#!/usr/bin/env python3
"""Build deterministic Splunk ES-style finding/notable events for SILK SPECTER.

The main dataset contains source telemetry. This module creates a separate
``source=notable sourcetype=stash`` feed containing authored campaign findings
plus benign/questionable alert noise.

The generated ``_raw`` intentionally follows the native stash/modaction shape
seen in Enterprise Security: an epoch prefix followed by comma-separated
``key=\"value\"`` fields. Participant data never includes instructor truth such
as expected disposition or activity IDs.
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

RISK_SCORES = {
    "critical": 90,
    "high": 70,
    "medium": 50,
    "low": 25,
    "informational": 10,
    "unknown": 0,
}

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
    rule_name: str,
    description: str,
    urgency: str,
    domain: str,
    scenario: str,
    source_index: str,
    src: str,
    dest: str,
    user: str,
    entity: str,
    entity_type: str,
    risk_score: int,
    source_count: int,
    drilldown_search: str,
    event_time: float,
    kind: str,
) -> str:
    """Render a native-looking ES stash/modaction finding record."""
    epoch = int(event_time)
    search_name = f"SS - {rule_name} - Rule"
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:rule:{scenario}:{rule_name}"))
    detection_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:detection:{scenario}:{rule_name}"))
    source_event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:source-event:{event_id}"))
    source_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:source-guid:{event_id}"))
    annotations = attack_annotations(rule_name, kind)

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
        ("rule_name", rule_name),
        ("rule_title", rule_name),
        ("orig_rule_title", rule_name),
        ("description", description),
        ("rule_description", description),
        ("orig_rule_description", description),
        ("savedsearch_description", description),
        ("urgency", urgency),
        ("severity", urgency),
        ("priority", urgency),
        ("status", "1"),
        ("status_label", "New"),
        ("owner", "unassigned"),
        ("security_domain", domain),
        ("app", "SA-SilkSpecter"),
        ("app_name", "SA-SilkSpecter"),
        ("product", "Splunk Enterprise Security"),
        ("vendor_product", "Splunk Enterprise Security"),
        ("asset_type", asset_type),
        ("finding_type", "finding"),
        ("notable_type", "notable"),
        ("entity", entity),
        ("entity_type", entity_type),
        ("all_risk_objects", entity),
        ("normalized_risk_object", entity),
        ("risk_object", entity),
        ("risk_object_type", entity_type),
        ("risk_score", risk_score),
        ("finding_score", risk_score),
        ("risk_event_count", source_count),
        ("source_count", source_count),
        ("source_event_id", source_event_id),
        ("source_guid", source_guid),
        ("orig_queue_id", "__system_default_queue__"),
        ("orig_time", epoch),
        ("info_search_time", epoch),
        ("info_min_time", epoch - 300),
        ("info_max_time", epoch + 300),
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
        ("drilldown_name", "View contributing events"),
        ("drilldown_search", drilldown_search),
        ("contributing_events_search", drilldown_search),
        ("nes_fields", "src,dest,user,entity,entity_type,risk_score"),
    ]
    annotation_obj = json.loads(annotations)
    if annotation_obj.get("mitre_attack"):
        fields.append(("annotations.mitre_attack", annotation_obj["mitre_attack"][0]))
        fields.append(("annotations.mitre_attack.mitre_technique", annotation_obj["mitre_attack_technique"][0]))
        fields.append(("annotations.mitre_attack.mitre_tactic", annotation_obj["mitre_attack_tactic"][0]))
    if entity_type == "system":
        fields.append(("risk_object_system", entity))

    # Splunk stash events are conventionally emitted as:
    #   <epoch>, key="value", key="value", ...
    return f"{epoch}, " + ", ".join(f"{key}={q(value)}" for key, value in fields)


def campaign_description(finding: dict, source_index: str) -> str:
    notes = (finding.get("notes") or "").strip()
    base = notes.rstrip(".") if notes else finding["detection_name"]
    return f"{base}. Review contributing telemetry in {source_index} and validate the entity against normal Asteron activity."


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

    activity_rows = defaultdict(list)
    for row in truth:
        activity_rows[row["activity_id"]].append(row)

    start = parse_iso(cfg["start"])
    end = parse_iso(cfg["end"])
    seed = int(cfg.get("seed", 0)) + 47001
    rng = random.Random(seed)
    noise_count = int(cfg.get("notables", {}).get("noise_events", 0))
    source_index = "<index>"

    records = []
    instructor_rows = []

    # Campaign findings. Stable offsets preserve deterministic event times when
    # multiple findings are tied to the same authored activity.
    per_activity = defaultdict(int)
    for finding in findings:
        activity = finding["activity_id"]
        rows = activity_rows[activity]
        offset = per_activity[activity]
        per_activity[activity] += 1
        dt = event_time_for_activity(activity_rows, activity, offset)
        rule = finding["detection_name"]
        urgency = infer_urgency(rule)
        domain = infer_domain(rule)
        src, dest, user = extract_observables(rows)
        entity, entity_type = choose_entity(domain, src, dest, user)
        risk_score = RISK_SCORES.get(urgency, 0)
        source_count = max(1, min(25, len(rows)))
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:notable:{scenario}:{finding['finding_id']}"))
        drill = f"index={source_index} earliest={int(dt.timestamp())-300} latest={int(dt.timestamp())+300}"
        description = campaign_description(finding, source_index)

        records.append({
            "time": dt.timestamp(),
            "host": "SILK-SPECTER-ES",
            "source": "notable",
            "sourcetype": "stash",
            "event": notable_raw(
                event_id=event_id,
                rule_name=rule,
                description=description,
                urgency=urgency,
                domain=domain,
                scenario=scenario,
                source_index=source_index,
                src=src,
                dest=dest,
                user=user,
                entity=entity,
                entity_type=entity_type,
                risk_score=risk_score,
                source_count=source_count,
                drilldown_search=drill,
                event_time=dt.timestamp(),
                kind="campaign",
            ),
        })
        instructor_rows.append({
            "event_id": event_id,
            "scenario": scenario,
            "time": dt.isoformat().replace("+00:00", "Z"),
            "rule_name": rule,
            "expected_disposition": finding["expected_disposition"],
            "activity_id": activity,
            "kind": "campaign",
            "entity": entity,
            "entity_type": entity_type,
            "risk_score": risk_score,
            "severity": urgency,
            "security_domain": domain,
            "source_count": source_count,
            "notes": finding.get("notes", ""),
        })

    # Benign/questionable alert noise. It is deliberately more numerous with
    # difficulty, but deterministic so questions and instructor review remain stable.
    sites = list(cfg.get("scope_sites", [])) or ["USHQ"]
    window_seconds = max(1, int((end - start).total_seconds()))
    for i in range(noise_count):
        title, urgency, domain = rng.choice(NOISE_CATALOG)
        dt = start + timedelta(seconds=rng.randint(900, max(901, window_seconds - 900)))
        site = rng.choice(sites)
        site_octet = 40 + (sum(ord(ch) for ch in site) % 20)
        src = f"10.{site_octet}.40.{rng.randint(20, 220)}"
        dest = f"{site}-SRV-{rng.randint(1, 24):02d}"
        user = f"user{rng.randint(100, 999)}"
        entity, entity_type = choose_entity(domain, src, dest, user)
        risk_score = RISK_SCORES.get(urgency, 0)
        source_count = rng.randint(1, 5)
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"silk-specter:notable-noise:{scenario}:{i}"))
        drill = f"index={source_index} earliest={int(dt.timestamp())-300} latest={int(dt.timestamp())+300}"
        description = noise_description(title, src, dest, user)

        records.append({
            "time": dt.timestamp(),
            "host": "SILK-SPECTER-ES",
            "source": "notable",
            "sourcetype": "stash",
            "event": notable_raw(
                event_id=event_id,
                rule_name=title,
                description=description,
                urgency=urgency,
                domain=domain,
                scenario=scenario,
                source_index=source_index,
                src=src,
                dest=dest,
                user=user,
                entity=entity,
                entity_type=entity_type,
                risk_score=risk_score,
                source_count=source_count,
                drilldown_search=drill,
                event_time=dt.timestamp(),
                kind="noise",
            ),
        })
        instructor_rows.append({
            "event_id": event_id,
            "scenario": scenario,
            "time": dt.isoformat().replace("+00:00", "Z"),
            "rule_name": title,
            "expected_disposition": "benign" if i % 4 else "questionable",
            "activity_id": "",
            "kind": "noise",
            "entity": entity,
            "entity_type": entity_type,
            "risk_score": risk_score,
            "severity": urgency,
            "security_domain": domain,
            "source_count": source_count,
            "notes": "Alert noise; participant must triage against raw telemetry.",
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

    manifest = {
        "scenario": scenario,
        "events": len(records),
        "campaign_notables": len(findings),
        "noise_notables": noise_count,
        "sourcetype": "stash",
        "source": "notable",
        "stash_schema": "es8-native-kv-v2",
        "canonical_ingest_file": "hec/events.jsonl",
        "participant_filter": f"index=notable source=notable sourcetype=stash scenario={scenario}",
        "required_finding_fields": [
            "rule_name", "rule_description", "entity", "entity_type", "risk_score",
            "severity", "urgency", "status_label", "security_domain", "drilldown_search",
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
        w.writerow({"file": "raw/notables.log", "host": "SILK-SPECTER-ES", "source": "notable", "sourcetype": "stash", "event_count": len(records)})

    instructor_path = root / "instructor" / "findings" / f"{scenario}_notable_ground_truth.csv"
    with instructor_path.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "event_id", "scenario", "time", "rule_name", "expected_disposition", "activity_id", "kind",
            "entity", "entity_type", "risk_score", "severity", "security_domain", "source_count", "notes",
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

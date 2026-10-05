import csv
import json
import re
import unittest
import uuid
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_.]*)="((?:\\.|[^"\\])*)"')

REQUIRED = {
    "search_name",
    "_time",
    "event_id",
    "orig_sid",
    "rule_id",
    "detection_id",
    "detection_type",
    "rule_name",
    "rule_title",
    "orig_rule_title",
    "description",
    "rule_description",
    "orig_rule_description",
    "savedsearch_description",
    "risk_message",
    "entity",
    "entity_type",
    "risk_object",
    "risk_object_type",
    "finding_score",
    "risk_score",
    "severity",
    "urgency",
    "status",
    "status_label",
    "owner",
    "security_domain",
    "orig_security_domain",
    "app_name",
    "count",
    "source_count",
    "source_event_id",
    "source_guid",
    "orig_action_name",
    "orig_investigation_type",
    "orig_queue_id",
    "orig_time",
    "firstTime",
    "lastTime",
    "info_search_time",
    "info_min_time",
    "info_max_time",
    "contributing_events_search",
    "orig_source",
    "orig_tag",
    "version",
    "annotations",
    "scenario",
    "ctf_track",
    "source_index",
    "src",
    "dest",
    "user",
    "drilldown_name",
    "drilldown_search",
}

FORBIDDEN_RBA_AGGREGATION = {
    "all_risk_objects",
    "normalized_risk_object",
    "risk_event_count",
    "risk_threshold",
    "risk_object_system",
}


def parse_stash(raw: str) -> tuple[int, dict[str, str]]:
    match = re.match(r'^(\d+),\s+', raw)
    if not match:
        raise AssertionError(f"not native stash prefix: {raw[:120]!r}")
    fields = {}
    for key, value in KV_RE.findall(raw):
        fields[key] = value.replace('\\"', '"').replace('\\\\', '\\')
    return int(match.group(1)), fields


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def static_signature(row: dict) -> tuple:
    return (
        round(parse_iso(str(row["time"])).timestamp(), 6),
        str(row.get("host", "")),
        str(row.get("source", "")),
        str(row.get("sourcetype", "")),
        str(row.get("raw", "")),
    )


def generated_signature(row: dict) -> tuple:
    return (
        round(float(row["time"]), 6),
        str(row.get("host", "")),
        str(row.get("source", "")),
        str(row.get("sourcetype", "")),
        str(row.get("event", "")),
    )


def generated_source_id(row: dict) -> str:
    material = "|".join(
        str(row.get(key, ""))
        for key in ("time", "host", "source", "sourcetype", "event")
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "silk-specter:generated-source:" + material))


class NotableSchemaTests(unittest.TestCase):
    def _notables(self, track: str):
        path = ROOT / "dataset" / track / "notables/hec/events.jsonl"
        with path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _static(self, track: str):
        path = ROOT / "scenario_data" / track / "attack_events.jsonl"
        with path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def _generated_indexes(self, track: str):
        path = ROOT / "dataset" / track / "hec/events.jsonl"
        signatures = set()
        source_ids = {}
        with path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                row = json.loads(line)
                sig = generated_signature(row)
                signatures.add(sig)
                source_ids[generated_source_id(row)] = sig
        return signatures, source_ids

    def _truth(self, track: str):
        path = ROOT / "instructor" / "findings" / f"{track}_notable_ground_truth.csv"
        with path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    def test_direct_finding_shape_matches_es_entity_contract(self):
        for track in ("easy", "medium", "hard"):
            rows = self._notables(track)
            self.assertTrue(rows, track)
            source_ids = []
            for row in rows:
                self.assertEqual(row["sourcetype"], "stash", track)
                epoch, fields = parse_stash(row["event"])
                self.assertEqual(row["source"], fields["search_name"], track)
                self.assertEqual(epoch, int(float(row["time"])), track)
                self.assertTrue(REQUIRED.issubset(fields), (track, sorted(REQUIRED - set(fields))))
                self.assertFalse(
                    FORBIDDEN_RBA_AGGREGATION.intersection(fields),
                    (track, sorted(FORBIDDEN_RBA_AGGREGATION.intersection(fields))),
                )
                self.assertEqual(fields["_time"], str(epoch), track)
                self.assertEqual(fields["scenario"], track, track)
                self.assertEqual(fields["ctf_track"], track, track)
                self.assertEqual(fields["count"], "1", track)
                self.assertEqual(fields["source_count"], "1", track)
                self.assertEqual(fields["detection_type"], "ebd", track)
                self.assertEqual(fields["orig_action_name"], "notable", track)
                self.assertEqual(fields["orig_investigation_type"], "default", track)
                self.assertEqual(fields["entity"], fields["risk_object"], track)
                self.assertEqual(fields["entity_type"], fields["risk_object_type"], track)
                self.assertNotIn(fields["risk_object"], {"", "-", "unknown"}, track)
                self.assertIn(
                    fields["risk_object_type"],
                    {"system", "user", "network_artifacts", "other"},
                    track,
                )
                self.assertEqual(fields["risk_score"], fields["finding_score"], track)
                self.assertEqual(fields["contributing_events_search"], fields["drilldown_search"], track)
                self.assertEqual(fields["orig_tag"], "modaction_result", track)
                self.assertEqual(fields["version"], "2.1", track)
                self.assertIn("index=<index>", fields["drilldown_search"], track)
                self.assertIn("host=", fields["drilldown_search"], track)
                self.assertIn("source=", fields["drilldown_search"], track)
                self.assertIn("sourcetype=", fields["drilldown_search"], track)
                source_ids.append(fields["source_event_id"])
            self.assertEqual(
                len(source_ids),
                len(set(source_ids)),
                f"{track}: one source event backs more than one notable",
            )

    def test_disposition_truth_alignment_and_generated_presence(self):
        for track in ("easy", "medium", "hard"):
            static_rows = self._static(track)
            static_by_id = {row["event_id"]: row for row in static_rows}
            generated_signatures, generated_source_ids = self._generated_indexes(track)
            malicious_signatures = {
                static_signature(row)
                for row in static_rows
                if row.get("truth_label") == "malicious"
            }

            truth = self._truth(track)
            self.assertTrue(truth, track)

            for row in truth:
                self.assertEqual(row["source_count"], "1", track)
                self.assertEqual(row["source_generated_presence"], "yes", track)
                self.assertEqual(row["entity"], row["risk_object"], track)
                self.assertEqual(row["entity_type"], row["risk_object_type"], track)

                if row["kind"] == "campaign":
                    self.assertIn(row["source_event_id"], static_by_id, (track, row["rule_name"]))
                    source = static_by_id[row["source_event_id"]]
                    sig = static_signature(source)
                    self.assertIn(sig, generated_signatures, (track, row["rule_name"]))

                    if row["expected_disposition"] == "True Positive":
                        self.assertEqual(source["truth_label"], "malicious", (track, row["rule_name"]))
                        self.assertEqual(row["source_truth_label"], "malicious", track)
                    elif row["expected_disposition"] == "Benign Positive":
                        self.assertEqual(source["truth_label"], "benign", (track, row["rule_name"]))
                        self.assertEqual(row["source_truth_label"], "benign", track)
                    else:
                        self.fail(f"{track}: unsupported disposition {row['expected_disposition']!r}")
                else:
                    self.assertEqual(row["kind"], "noise", track)
                    self.assertEqual(row["expected_disposition"], "Benign Positive", track)
                    self.assertEqual(row["source_truth_label"], "non-malicious", track)
                    self.assertIn(row["source_event_id"], generated_source_ids, (track, row["rule_name"]))
                    self.assertNotIn(
                        generated_source_ids[row["source_event_id"]],
                        malicious_signatures,
                        (track, row["rule_name"]),
                    )

    def test_expected_disposition_counts(self):
        expected = {
            "easy": {"True Positive": 8, "Benign Positive": 28},
            "medium": {"True Positive": 8, "Benign Positive": 60},
            "hard": {"True Positive": 5, "Benign Positive": 122},
        }
        for track, counts in expected.items():
            actual = {"True Positive": 0, "Benign Positive": 0}
            for row in self._truth(track):
                actual[row["expected_disposition"]] += 1
            self.assertEqual(actual, counts, track)

    def test_participant_notables_hide_instructor_truth(self):
        for track in ("easy", "medium", "hard"):
            raw = (ROOT / "dataset" / track / "notables/raw/notables.log").read_text(encoding="utf-8")
            self.assertNotIn("expected_disposition", raw, track)
            self.assertNotIn("source_truth_label", raw, track)
            self.assertNotIn("activity_id", raw, track)
            self.assertNotIn("truth_label", raw, track)
            self.assertNotIn("True Positive", raw, track)
            self.assertNotIn("Benign Positive", raw, track)

    def test_manifests_declare_direct_truth_aligned_model(self):
        for track in ("easy", "medium", "hard"):
            manifest = json.loads(
                (ROOT / "dataset" / track / "notables/manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["stash_schema"], "es8-direct-notable-kv-v4", track)
            self.assertEqual(manifest["notable_model"], "non-rba-direct-event-risk-object", track)
            self.assertEqual(manifest["source_events_per_notable"], 1, track)
            self.assertEqual(
                manifest["entity_contract"],
                "entity=risk_object and entity_type=risk_object_type",
                track,
            )
            self.assertEqual(set(manifest["forbidden_rba_fields"]), FORBIDDEN_RBA_AGGREGATION, track)


if __name__ == "__main__":
    unittest.main()

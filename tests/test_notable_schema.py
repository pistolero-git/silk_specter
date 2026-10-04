import csv
import json
import re
import unittest
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
    "rule_name",
    "rule_title",
    "orig_rule_title",
    "description",
    "rule_description",
    "orig_rule_description",
    "savedsearch_description",
    "entity",
    "entity_type",
    "finding_score",
    "risk_score",
    "severity",
    "urgency",
    "status",
    "status_label",
    "owner",
    "security_domain",
    "app_name",
    "source_count",
    "source_event_id",
    "source_guid",
    "orig_queue_id",
    "orig_time",
    "info_search_time",
    "info_min_time",
    "info_max_time",
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

FORBIDDEN_RBA = {
    "all_risk_objects",
    "normalized_risk_object",
    "risk_object",
    "risk_object_type",
    "risk_event_count",
    "risk_object_system",
    "contributing_events_search",
}


def parse_stash(raw: str) -> tuple[int, dict[str, str]]:
    match = re.match(r'^(\d+),\s+', raw)
    if not match:
        raise AssertionError(f"not native stash prefix: {raw[:120]!r}")
    fields = {}
    for key, value in KV_RE.findall(raw):
        fields[key] = value.replace('\\"', '"').replace('\\\\', '\\')
    return int(match.group(1)), fields


class NotableSchemaTests(unittest.TestCase):
    def _rows(self, track: str):
        path = ROOT / "dataset" / track / "notables/hec/events.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def test_notables_are_direct_non_rba_results(self):
        for track in ("easy", "medium", "hard"):
            rows = self._rows(track)
            self.assertTrue(rows, track)
            source_ids = []
            for row in rows:
                self.assertEqual(row["sourcetype"], "stash", track)
                epoch, fields = parse_stash(row["event"])
                self.assertEqual(row["source"], fields["search_name"], track)
                self.assertEqual(epoch, int(float(row["time"])), track)
                self.assertTrue(REQUIRED.issubset(fields), (track, sorted(REQUIRED - set(fields))))
                self.assertFalse(FORBIDDEN_RBA.intersection(fields), (track, sorted(FORBIDDEN_RBA.intersection(fields))))
                self.assertEqual(fields["_time"], str(epoch), track)
                self.assertEqual(fields["scenario"], track, track)
                self.assertEqual(fields["ctf_track"], track, track)
                self.assertEqual(fields["source_count"], "1", track)
                self.assertNotIn(fields["entity"], {"", "-", "unknown"}, track)
                self.assertTrue(fields["entity"] and fields["entity"] != "-", track)
                self.assertIn(fields["entity_type"], {"system", "user", "network_artifacts", "other"}, track)
                self.assertGreaterEqual(int(fields["finding_score"]), 0, track)
                self.assertEqual(fields["risk_score"], fields["finding_score"], track)
                self.assertEqual(fields["orig_tag"], "modaction_result", track)
                self.assertEqual(fields["version"], "2.1", track)
                self.assertIn("index=<index>", fields["drilldown_search"], track)
                self.assertIn("host=", fields["drilldown_search"], track)
                self.assertIn("source=", fields["drilldown_search"], track)
                self.assertIn("sourcetype=", fields["drilldown_search"], track)
                source_ids.append(fields["source_event_id"])
            self.assertEqual(len(source_ids), len(set(source_ids)), f"{track}: a source event backs more than one notable")

    def test_campaign_notables_link_to_authored_apt_events(self):
        for track in ("easy", "medium", "hard"):
            authored_ids = {
                json.loads(line)["event_id"]
                for line in (ROOT / "scenario_data" / track / "attack_events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            with (ROOT / "instructor" / "findings" / f"{track}_notable_ground_truth.csv").open(newline="", encoding="utf-8") as f:
                truth = list(csv.DictReader(f))
            campaign = [row for row in truth if row["kind"] == "campaign"]
            self.assertTrue(campaign, track)
            for row in campaign:
                self.assertIn(row["source_event_id"], authored_ids, (track, row["rule_name"]))
                self.assertEqual(row["source_count"], "1", track)

    def test_noise_notables_are_backed_by_generated_participant_events_when_materialized(self):
        for track in ("easy", "medium", "hard"):
            path = ROOT / "dataset" / track / "hec/events.jsonl"
            head = path.read_text(encoding="utf-8", errors="replace")[:128]
            if head.startswith("version https://git-lfs.github.com/spec/v1"):
                continue
            generated_ids = set()
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                material = "|".join(str(row.get(key, "")) for key in ("time", "host", "source", "sourcetype", "event"))
                import uuid
                generated_ids.add(str(uuid.uuid5(uuid.NAMESPACE_URL, "silk-specter:generated-source:" + material)))
            with (ROOT / "instructor" / "findings" / f"{track}_notable_ground_truth.csv").open(newline="", encoding="utf-8") as f:
                truth = list(csv.DictReader(f))
            noise = [row for row in truth if row["kind"] == "noise"]
            self.assertTrue(noise, track)
            for row in noise:
                self.assertIn(row["source_event_id"], generated_ids, (track, row["rule_name"]))

    def test_participant_notables_hide_instructor_truth(self):
        for track in ("easy", "medium", "hard"):
            raw = (ROOT / "dataset" / track / "notables/raw/notables.log").read_text(encoding="utf-8")
            self.assertNotIn("expected_disposition", raw, track)
            self.assertNotIn("activity_id", raw, track)
            self.assertNotIn("truth_label", raw, track)

    def test_manifests_declare_direct_non_rba_model(self):
        for track in ("easy", "medium", "hard"):
            manifest = json.loads((ROOT / "dataset" / track / "notables/manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["stash_schema"], "es8-direct-notable-kv-v3", track)
            self.assertEqual(manifest["notable_model"], "non-rba-direct-event", track)
            self.assertEqual(manifest["source_events_per_notable"], 1, track)
            self.assertEqual(set(manifest["forbidden_rba_fields"]), {
                "all_risk_objects", "normalized_risk_object", "risk_object", "risk_object_type", "risk_event_count"
            })


if __name__ == "__main__":
    unittest.main()

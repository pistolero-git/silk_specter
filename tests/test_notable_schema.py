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
    "risk_object",
    "risk_object_type",
    "risk_score",
    "finding_score",
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
    def test_notables_use_native_stash_shape_and_required_finding_fields(self):
        for track in ("easy", "medium", "hard"):
            path = ROOT / "dataset" / track / "notables/hec/events.jsonl"
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertTrue(rows, track)
            for row in rows:
                self.assertEqual(row["sourcetype"], "stash", track)
                epoch, fields = parse_stash(row["event"])
                self.assertEqual(row["source"], fields["search_name"], track)
                self.assertEqual(epoch, int(float(row["time"])), track)
                self.assertTrue(REQUIRED.issubset(fields), (track, sorted(REQUIRED - set(fields))))
                self.assertEqual(fields["_time"], str(epoch), track)
                self.assertEqual(fields["scenario"], track, track)
                self.assertEqual(fields["ctf_track"], track, track)
                self.assertNotIn(fields["entity"], {"", "-", "unknown"}, track)
                self.assertIn(fields["entity_type"], {"system", "user", "network_artifacts", "other"}, track)
                self.assertGreaterEqual(int(fields["risk_score"]), 0, track)
                self.assertEqual(fields["orig_tag"], "modaction_result", track)
                self.assertEqual(fields["version"], "2.1", track)

    def test_campaign_findings_have_descriptions_and_contributing_context(self):
        for track in ("easy", "medium", "hard"):
            path = ROOT / "dataset" / track / "notables/hec/events.jsonl"
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            for row in rows:
                _, fields = parse_stash(row["event"])
                self.assertGreater(len(fields["rule_description"]), 24, track)
                self.assertIn("index=<index>", fields["drilldown_search"], track)
                self.assertIn("index=<index>", fields["contributing_events_search"], track)
                self.assertGreaterEqual(int(fields["source_count"]), 1, track)

    def test_participant_notables_still_hide_instructor_truth(self):
        for track in ("easy", "medium", "hard"):
            raw = (ROOT / "dataset" / track / "notables/raw/notables.log").read_text(encoding="utf-8")
            self.assertNotIn("expected_disposition", raw, track)
            self.assertNotIn("activity_id", raw, track)
            self.assertNotIn("truth_label", raw, track)

    def test_manifests_declare_es8_native_stash_schema(self):
        for track in ("easy", "medium", "hard"):
            manifest = json.loads((ROOT / "dataset" / track / "notables/manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["stash_schema"], "es8-native-kv-v2", track)
            required = set(manifest["required_finding_fields"])
            self.assertTrue({"rule_name", "rule_description", "entity", "entity_type", "risk_score", "severity"}.issubset(required))


if __name__ == "__main__":
    unittest.main()

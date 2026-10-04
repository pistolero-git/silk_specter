import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class NotableLoaderReingestTests(unittest.TestCase):
    def test_loader_uses_unique_batch_source_and_crc_salt(self):
        text = (ROOT / "scripts/load_notables.sh").read_text(encoding="utf-8")
        self.assertIn("RUN_ID=", text)
        self.assertIn("events-${RUN_ID}.jsonl", text)
        self.assertIn("[batch://$HEC_GLOB]", text)
        self.assertIn("crcSalt = <SOURCE>", text)
        self.assertNotIn("HEC_REMOTE=\"$REMOTE/events.jsonl\"", text)

    def test_validation_search_does_not_require_legacy_source_value(self):
        text = (ROOT / "scripts/load_notables.sh").read_text(encoding="utf-8")
        self.assertIn("host=SILK-SPECTER-ES sourcetype=stash scenario=$SCENARIO", text)

if __name__ == "__main__":
    unittest.main()

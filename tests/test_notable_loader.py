import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NotableLoaderTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(
            ["bash", "-n", str(ROOT / "scripts/load_notables.sh")],
            check=True,
        )

    def test_container_native_dependencies(self):
        text = (ROOT / "scripts/load_notables.sh").read_text(encoding="utf-8")
        self.assertNotIn("/opt/splunk/bin/splunk login", text)
        self.assertNotIn("services/data/indexes", text)
        self.assertNotIn("8088", text)
        self.assertNotIn("8089", text)
        self.assertIn("btool indexes list", text)
        self.assertIn("batch://", text)
        self.assertIn("move_policy = sinkhole", text)

    def test_data_is_copied_after_restart(self):
        text = (ROOT / "scripts/load_notables.sh").read_text(encoding="utf-8")
        restart = text.index('podman restart --time')
        copy_data = text.index('podman cp "$PREPARED"')
        self.assertLess(restart, copy_data)
        self.assertIn("events.jsonl.upload", text)
        self.assertIn('mv "$HEC_UPLOAD" "$HEC_REMOTE"', text)


if __name__ == "__main__":
    unittest.main()

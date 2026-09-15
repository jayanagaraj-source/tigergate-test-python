import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "expected-findings" / "expected-findings.json"


def test_manifest_is_up_to_date():
    result = subprocess.run(
        [sys.executable, "scripts/build_expected_findings.py", "--check"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_entry_points_at_real_code():
    manifest = json.loads(MANIFEST.read_text())
    for entry in manifest["findings"] + manifest["negative_controls"]:
        line = (ROOT / entry["file"]).read_text().splitlines()[entry["line"] - 1].strip()
        assert line, entry["id"]
        assert "tg-expect" not in line and "tg-negative" not in line, entry["id"]


def test_every_category_has_coverage():
    summary = json.loads(MANIFEST.read_text())["summary"]
    for category in ("sca", "sast", "secrets", "iac", "container"):
        assert summary[category]["expected"] > 0, category

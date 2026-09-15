#!/usr/bin/env python3
"""Build the ground-truth manifest a scanner run is compared against.

Fixtures carry inline markers placed on the line directly above the offending line:

    # tg-expect: <ID> | <severity> | <refs> | <description>
    # tg-negative: <ID> | <description>        ("[soft]" in the description = debatable)

Several markers may be stacked above one line. Files that cannot hold comments
(JSON) are listed in MANUAL_FINDINGS.

Usage:
    python3 scripts/build_expected_findings.py          # (re)write expected-findings/
    python3 scripts/build_expected_findings.py --check  # exit 1 if outputs are stale
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "expected-findings"
FINDINGS_FILE = OUT_DIR / "expected-findings.json"
SBOM_FILE = OUT_DIR / "sbom-expected.cdx.json"

SKIP_DIRS = {".git", "expected-findings", "scripts", "tests", "__pycache__", ".terraform", ".pytest_cache"}
MARKER = re.compile(r"^\s*#\s*tg-(expect|negative):\s*(.+?)\s*$")
CATEGORIES = {"SCA": "sca", "SAST": "sast", "SECRET": "secrets", "IAC": "iac", "CONTAINER": "container"}

MANUAL_FINDINGS = [
    {"id": "SECRET-062", "file": "config/gcp-service-account.json", "match": '"private_key":',
     "severity": "critical", "refs": ["gcp-service-account-key"],
     "description": "GCP service account JSON with embedded private key"},
    {"id": "SECRET-063", "file": "config/gcp-service-account.json", "match": '"private_key_id":',
     "severity": "high", "refs": ["gcp-service-account-key"],
     "description": "GCP service account private_key_id"},
]

SBOM_MANIFESTS = ["requirements.txt", "requirements-dev.txt", "pyproject.toml"]
PIN = re.compile(r"""^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!-]+)"?,?\s*$""")


def category_of(finding_id: str) -> str:
    prefix = finding_id.removeprefix("NEG-").split("-")[0]
    return CATEGORIES[prefix]


def iter_fixture_files():
    for path in sorted(ROOT.rglob("*")):
        rel = path.relative_to(ROOT)
        if path.is_file() and path.suffix != ".md" and not SKIP_DIRS.intersection(rel.parts):
            yield path, rel.as_posix()


def target_line(lines, marker_index):
    for index in range(marker_index + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped and not MARKER.search(stripped):
            return index + 1, stripped
    raise ValueError("marker at end of file has no target line")


def package_pin(code: str):
    match = PIN.match(code)
    if not match:
        return None
    return {"name": match.group(1), "version": match.group(2)}


def collect():
    findings, negatives = [], []
    for path, rel in iter_fixture_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for index, raw in enumerate(lines):
            match = MARKER.search(raw)
            if not match:
                continue
            kind, body = match.groups()
            fields = [part.strip() for part in body.split("|")]
            line_no, code = target_line(lines, index)
            if kind == "expect":
                finding_id, severity, refs, description = fields
                entry = {
                    "id": finding_id,
                    "category": category_of(finding_id),
                    "file": rel,
                    "line": line_no,
                    "severity": severity,
                    "refs": [ref.strip() for ref in refs.split(",")],
                    "description": description,
                    "code": code,
                }
                pin = package_pin(code) if entry["category"] == "sca" else None
                if pin:
                    entry["package"] = pin
                findings.append(entry)
            else:
                finding_id, description = fields
                negatives.append({
                    "id": finding_id,
                    "category": category_of(finding_id),
                    "file": rel,
                    "line": line_no,
                    "soft": "[soft]" in description,
                    "description": description.replace("[soft]", "").strip(),
                    "code": code,
                })

    for manual in MANUAL_FINDINGS:
        lines = (ROOT / manual["file"]).read_text(encoding="utf-8").splitlines()
        line_no = next(i for i, text in enumerate(lines, 1) if manual["match"] in text)
        findings.append({
            "id": manual["id"], "category": category_of(manual["id"]), "file": manual["file"],
            "line": line_no, "severity": manual["severity"], "refs": manual["refs"],
            "description": manual["description"], "code": lines[line_no - 1].strip()[:60] + "...",
        })

    ids = [item["id"] for item in findings + negatives]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise SystemExit(f"duplicate fixture IDs: {duplicates}")
    findings.sort(key=lambda f: (f["category"], f["id"]))
    negatives.sort(key=lambda f: (f["category"], f["id"]))
    return findings, negatives


def build_manifest(findings, negatives):
    summary = {}
    for item in findings:
        summary.setdefault(item["category"], {"expected": 0, "negatives": 0})["expected"] += 1
    for item in negatives:
        summary.setdefault(item["category"], {"expected": 0, "negatives": 0})["negatives"] += 1
    return {
        "description": "Ground truth for TigerGate scanner validation. A reported issue matching file+line "
                       "(+/- 2 lines) and the description counts as a true positive; any issue on a "
                       "negative-control line counts as a false positive (soft negatives are informational).",
        "generator": "scripts/build_expected_findings.py",
        "summary": dict(sorted(summary.items())),
        "findings": findings,
        "negative_controls": negatives,
    }


def build_sbom():
    components = []
    for manifest in SBOM_MANIFESTS:
        for line_no, text in enumerate((ROOT / manifest).read_text().splitlines(), 1):
            pin = package_pin(text.split("#")[0]) if not text.lstrip().startswith("#") else None
            if not pin:
                continue
            purl_name = re.sub(r"[-_.]+", "-", pin["name"]).lower()
            components.append({
                "type": "library",
                "bom-ref": f"pkg:pypi/{purl_name}@{pin['version']}",
                "name": pin["name"],
                "version": pin["version"],
                "purl": f"pkg:pypi/{purl_name}@{pin['version']}",
                "properties": [{"name": "tigergate:fixture:source", "value": f"{manifest}:{line_no}"}],
            })
    components.sort(key=lambda c: c["purl"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "tigergate-test-python", "version": "0.1.0"},
            "properties": [
                {"name": "tigergate:fixture:scope",
                 "value": "Direct PyPI dependencies only. A generated SBOM must contain at least these "
                          "components; transitive dependencies (e.g. py, idna, chardet, certifi, "
                          "MarkupSafe) are expected in addition when the scanner resolves them."},
                {"name": "tigergate:fixture:also-expected",
                 "value": "Terraform providers hashicorp/aws@3.0.0, hashicorp/azurerm@2.0.0, hashicorp/google@3.90.0 "
                          "if the scanner inventories IaC providers."},
            ],
        },
        "components": components,
    }


def render(data) -> str:
    return json.dumps(data, indent=2) + "\n"


def main() -> int:
    findings, negatives = collect()
    outputs = {FINDINGS_FILE: render(build_manifest(findings, negatives)), SBOM_FILE: render(build_sbom())}
    if "--check" in sys.argv:
        stale = [p.relative_to(ROOT).as_posix() for p, text in outputs.items()
                 if not p.exists() or p.read_text() != text]
        if stale:
            print("stale, run scripts/build_expected_findings.py:", ", ".join(stale))
            return 1
        print("expected-findings up to date")
        return 0
    OUT_DIR.mkdir(exist_ok=True)
    for path, text in outputs.items():
        path.write_text(text)
    print(f"{len(findings)} expected findings, {len(negatives)} negative controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Deliberately insecure test fixtures

This repository is for validating SCA, SAST, secret, IaC, container, and SBOM scanners. It deliberately contains outdated dependencies, unsafe code patterns, fake hard-coded credentials, and insecure infrastructure settings. Do not deploy or reuse these patterns.

All credentials are randomly generated to match provider formats only; none are valid.

## Layout

| Scanner | Fixture files |
|---|---|
| SCA | `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, Terraform provider pins |
| SAST | `src/app.py`, `src/vulnerable.py`, `src/sast/**` (injection, deserialization, crypto, Flask/Django taint flows, cross-file taint, XML/filesystem, misc CWEs) |
| Secrets | `src/secrets.py`, `src/config/settings.py`, `.env`, `config/**`, plus secrets embedded in Terraform, Kubernetes, CloudFormation, Docker, Compose |
| IaC | `terraform/` (AWS), `terraform/azure/`, `terraform/gcp/`, `kubernetes/`, `cloudformation/`, `docker/`, `ci-fixtures/` |
| Container | `docker/Dockerfile.insecure` (EOL base image), `docker/docker-compose.insecure.yml` |
| SBOM | All pinned PyPI packages; reference in `expected-findings/sbom-expected.cdx.json` |
| Negative controls | `src/safe/**`, `kubernetes/secure-deployment.yaml`, safe lines inside other fixtures |

## Ground truth

Every expected issue is marked on the line above it:

```
# tg-expect: <ID> | <severity> | <refs: CVE / CWE / category> | <description>
# tg-negative: <ID> | <description>          # must NOT be flagged; "[soft]" = debatable
```

`expected-findings/expected-findings.json` is generated from these markers:

```bash
python3 scripts/build_expected_findings.py          # regenerate after editing fixtures
python3 scripts/build_expected_findings.py --check  # verify it is current (also run by pytest)
```

### Scoring a scan

- **True positive:** reported issue in the same file within ±2 lines of an expected `line`, describing the same weakness. For IaC, a report anchored on the enclosing resource/block also counts.
- **False negative:** expected entry with no matching report.
- **False positive:** any report on a `negative_controls` line (ignore `soft: true` entries when scoring strictly).
- **SCA:** match on package + version; the CVE list per package is a minimum, newer advisories may add more. `requirements-dev.txt` and PEP 621 `pyproject.toml` also test manifest discovery; some scanners only read `requirements.txt`.
- **SBOM:** every component in `sbom-expected.cdx.json` must appear with the same name, version, and purl; transitive dependencies are extra, not errors.
- Severities are indicative; scanners legitimately differ by one level.

## Notes

- `ci-fixtures/github-actions-insecure.yml` is kept outside `.github/workflows/` so GitHub never runs it.
- GitHub push protection may block pushing the fake provider tokens; choose "used in tests" to allow them.

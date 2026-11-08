from security_check.scan import SCANNER_MISSING, parse_scanner_output, scanner_environment


def test_parse_uses_database_severity_and_fixed_version() -> None:
    payload = """
    {
      "results": [
        {
          "packages": [
            {
              "package": {"name": "urllib3", "version": "1.26.5", "ecosystem": "PyPI"},
              "dependency_path": ["app", "urllib3"],
              "vulnerabilities": [
                {
                  "id": "GHSA-0000-0000-0000",
                  "summary": "example",
                  "database_specific": {"severity": "CRITICAL"},
                  "affected": [
                    {
                      "package": {"name": "urllib3"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.26.18"}]}]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
    """

    parsed = parse_scanner_output(payload, "Scanned file and found 12 packages\n")

    assert parsed is not None
    assert parsed.package_count == 12
    assert parsed.findings[0].advisory_id == "GHSA-0000-0000-0000"
    assert parsed.findings[0].severity == "Critical"
    assert parsed.findings[0].fixed == "1.26.18"
    assert parsed.findings[0].dependency_path == "app -> urllib3"


def test_parse_rejects_missing_results() -> None:
    assert parse_scanner_output('{"packages": []}', "") is None


def test_parse_uses_cvss_number_when_label_is_absent() -> None:
    payload = """
    {
      "results": [
        {
          "packages": [
            {
              "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
              "vulnerabilities": [
                {"id": "GHSA-1111-1111-1111", "summary": "", "severity": [{"type": "CVSS_V3", "score": "7.5"}]}
              ]
            }
          ]
        }
      ]
    }
    """

    parsed = parse_scanner_output(payload, "")

    assert parsed is not None
    assert parsed.findings[0].severity == "High"
    assert parsed.package_count == 1


def test_scanner_environment_drops_unrelated_secrets(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("https_proxy", "http://proxy.example:8080")

    environment = scanner_environment()

    assert environment["PATH"] == "/usr/bin"
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["https_proxy"] == "http://proxy.example:8080"


def test_missing_scanner_message_includes_brew() -> None:
    assert "brew install osv-scanner" in SCANNER_MISSING

"""CLI unit and integration tests."""

import json
from typing import Any

from click.testing import CliRunner

from cli.main import main


def sample_callable(payload: Any) -> str:
    return "NTI_BLOCKED: denied"


def test_cli_list_attacks() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["list-attacks"])
    assert result.exit_code == 0
    assert "NTI-A001" in result.output
    assert "10 attacks" in result.output


def test_cli_run_invalid_url() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "NTI_A001", "--url", "ftp://invalid-url"])
    assert result.exit_code == 1
    assert "Invalid URL scheme" in result.output


def test_cli_run_invalid_callable() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "NTI_A001", "--callable", "invalid_format"])
    assert result.exit_code == 1
    assert "Invalid callable format" in result.output


def test_cli_run_unknown_attack() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["run", "NTI_UNKNOWN", "--url", "http://localhost:8000"])
    assert result.exit_code == 1
    assert "Unknown attack ID" in result.output


def test_cli_run_success(tmp_path: Any) -> None:
    runner = CliRunner()
    output_dir = str(tmp_path)
    result = runner.invoke(main, [
        "run", "NTI_A001",
        "--callable", "tests.unit.test_cli:sample_callable",
        "--output", output_dir,
    ])
    assert result.exit_code == 0
    assert "Resistance Score: 100/100" in result.output

    # Verify generated report file exists
    reports = list(tmp_path.glob("nti-attack-report-*.json"))
    assert len(reports) == 1

    # Verify offline verification of generated report
    verify_result = runner.invoke(main, ["verify", str(reports[0])])
    assert verify_result.exit_code == 0
    assert "VALID" in verify_result.output


def test_cli_verify_invalid_report(tmp_path: Any) -> None:
    runner = CliRunner()
    invalid_report = tmp_path / "invalid.json"
    invalid_report.write_text(json.dumps({"cert_hash": "invalid_hash"}))

    result = runner.invoke(main, ["verify", str(invalid_report)])
    assert result.exit_code == 1
    assert "INVALID" in result.output


def test_cli_scan_success(tmp_path: Any) -> None:
    runner = CliRunner()
    output_dir = str(tmp_path)
    result = runner.invoke(main, [
        "scan",
        "--callable", "tests.unit.test_cli:sample_callable",
        "--output", output_dir,
    ])
    assert result.exit_code == 0
    assert "10 attacks" in result.output

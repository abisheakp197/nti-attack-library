"""Command-line interface for nti-attack."""

import importlib
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nti_attack.adapters.base import AgentAdapter
from nti_attack.adapters.callable_adapter import CallableAdapter
from nti_attack.adapters.http_adapter import HttpAgentAdapter
from nti_attack.attestation import (
    build_report,
    sign_report,
    verify_report,
    write_report,
)
from nti_attack.runner import load_all_attacks, run_attacks

console = Console()


def _get_adapter(url: str | None, callable_name: str | None) -> AgentAdapter:
    if url:
        if not url.startswith(("http://", "https://")):
            console.print("[red]Error: Invalid URL scheme. URL must start with http:// or https://[/red]")
            sys.exit(1)
        return HttpAgentAdapter(url)
    if callable_name:
        if ":" not in callable_name:
            console.print("[red]Error: Invalid callable format. Expected 'module:function'[/red]")
            sys.exit(1)
        try:
            mod_name, fn_name = callable_name.rsplit(":", 1)
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, fn_name)
            return CallableAdapter(fn)
        except (ImportError, AttributeError, ValueError) as e:
            console.print(f"[red]Error loading callable '{callable_name}': {e}[/red]")
            sys.exit(1)
    console.print("[red]Error: Provide --url or --callable[/red]")
    sys.exit(1)


@click.group()
@click.version_option(package_name="nti-attack-library")
def main() -> None:
    """nti-attack: executable, signed attack framework for AI agents."""


@main.command()
def list_attacks() -> None:
    """List all attacks in the library."""
    attacks = load_all_attacks()
    table = Table(title=f"NTI Attack Library ({len(attacks)} attacks)")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Pillar")
    table.add_column("Name")
    for a in attacks:
        color = "red" if a.severity == "critical" else "yellow" if a.severity == "high" else "white"
        table.add_row(a.id, a.category, f"[{color}]{a.severity}[/]", a.pillar, a.name)
    console.print(table)


@main.command()
@click.option("--url", help="HTTP agent endpoint")
@click.option("--callable", "callable_name", help="Python callable to test")
@click.option("--output", "-o", type=click.Path(), default="./nti-attack-reports")
@click.option("--agent-id", default="default-agent")
@click.option("--commit-sha", default="")
@click.option("--severity", type=click.Choice(["all", "critical", "high", "medium", "low"]), default="all")
def scan(
    url: str | None,
    callable_name: str | None,
    output: str,
    agent_id: str,
    commit_sha: str,
    severity: str,
) -> None:
    """Run all attacks against an agent."""
    attacks = load_all_attacks()
    if severity != "all":
        attacks = [a for a in attacks if a.severity == severity]

    adapter = _get_adapter(url, callable_name)

    console.print(f"Running {len(attacks)} attacks against {agent_id}...")
    results = run_attacks(attacks, adapter)
    report = build_report(agent_id, commit_sha, results)
    signed = sign_report(report)
    path = write_report(signed, output)

    score = signed["resistance_score"]
    color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
    console.print(Panel.fit(
        f"[bold {color}]Resistance Score: {score}/100[/bold {color}]\n"
        f"Passed: {signed['attacks_passed']}/{signed['attacks_run']}\n"
        f"Report: {path}",
        title="NTI Attack Report",
    ))

    table = Table(title="Results")
    table.add_column("Attack")
    table.add_column("Severity")
    table.add_column("Status")
    for r in results:
        status = "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]"
        table.add_row(r.attack_id, r.severity, status)
    console.print(table)


@main.command()
@click.argument("attack_id")
@click.option("--url", help="HTTP agent endpoint")
@click.option("--callable", "callable_name", help="Python callable to test")
@click.option("--output", "-o", type=click.Path(), default="./nti-attack-reports")
@click.option("--agent-id", default="default-agent")
@click.option("--commit-sha", default="")
def run(
    attack_id: str,
    url: str | None,
    callable_name: str | None,
    output: str,
    agent_id: str,
    commit_sha: str,
) -> None:
    """Run a specific attack by ID (e.g. NTI_A001 or NTI-A001)."""
    normalized_id = attack_id.replace("_", "-").upper()
    attacks = load_all_attacks()

    matching = [a for a in attacks if a.id.replace("_", "-").upper() == normalized_id or attack_id.lower() == "all"]
    if not matching:
        console.print(f"[red]Error: Unknown attack ID '{attack_id}'[/red]")
        sys.exit(1)

    adapter = _get_adapter(url, callable_name)

    console.print(f"Running attack {normalized_id} against {agent_id}...")
    results = run_attacks(matching, adapter)
    report = build_report(agent_id, commit_sha, results)
    signed = sign_report(report)
    path = write_report(signed, output)

    score = signed["resistance_score"]
    color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
    console.print(Panel.fit(
        f"[bold {color}]Resistance Score: {score}/100[/bold {color}]\n"
        f"Passed: {signed['attacks_passed']}/{signed['attacks_run']}\n"
        f"Report: {path}",
        title="NTI Attack Report",
    ))


@main.command()
@click.argument("report_path", type=click.Path(exists=True))
def verify(report_path: str) -> None:
    """Verify a signed attack report offline."""
    data = json.loads(Path(report_path).read_text())
    result = verify_report(data)
    if result["ok"]:
        console.print(Panel.fit(
            f"[green]VALID[/green]\nScore: {result['score']}/100\n"
            f"Attacks: {result['attacks_run']}\nCommit: {result['commit_sha']}",
            title="Verification",
        ))
    else:
        console.print(f"[red]INVALID: {result['reason']}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

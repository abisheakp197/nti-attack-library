"""Command-line interface for nti-attack."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from nti_attack.runner import load_all_attacks, run_attacks
from nti_attack.adapters.base import AgentAdapter
from nti_attack.adapters.callable_adapter import CallableAdapter
from nti_attack.adapters.http_adapter import HttpAgentAdapter
from nti_attack.attestation import build_report, sign_report, write_report, verify_report

console = Console()


@click.group()
@click.version_option(package_name="nti-attack")
def main():
    """nti-attack: executable, signed attack framework for AI agents."""
    pass


@main.command()
def list_attacks():
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
def scan(url, callable_name, output, agent_id, commit_sha, severity):
    """Run all attacks against an agent."""
    attacks = load_all_attacks()
    if severity != "all":
        attacks = [a for a in attacks if a.severity == severity]

    if url:
        adapter: AgentAdapter = HttpAgentAdapter(url)
    elif callable_name:
        import importlib
        mod, name = callable_name.rsplit(":", 1)
        fn = getattr(importlib.import_module(mod), name)
        adapter = CallableAdapter(fn)
    else:
        console.print("[red]Provide --url or --callable[/red]")
        sys.exit(1)

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
@click.argument("report_path", type=click.Path(exists=True))
def verify(report_path):
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

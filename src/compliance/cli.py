"""Typer CLI: compliance run [--framework soc2]."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import structlog
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from compliance.graph import build_graph
from compliance.state import ComplianceState

load_dotenv()

app = typer.Typer(no_args_is_help=True, add_completion=False)
console = Console()
log = structlog.get_logger()


@app.command()
def run(
    framework: str = typer.Option("soc2", "--framework", "-f", help="Framework to assess"),
    save_log: bool = typer.Option(True, help="Persist event log to out/"),
) -> None:
    """Run a compliance evidence collection pass and emit a signed PDF pack."""
    asyncio.run(_run(framework, save_log))


async def _run(framework: str, save_log: bool) -> None:
    run_id = uuid.uuid4().hex[:10]
    initial: ComplianceState = {"run_id": run_id, "framework": framework, "events": [], "errors": []}

    graph = build_graph().compile()
    console.rule(f"[bold cyan]Compliance run {run_id} — {framework.upper()}[/]")

    final_state: ComplianceState = {}
    async for event in graph.astream(initial, stream_mode="values"):
        final_state = event
        last = (event.get("events") or [{}])[-1]
        if last:
            console.print(f"  [green]✓[/] {last.get('kind', '?')}")

    results = final_state.get("results") or []
    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed

    console.rule("[bold cyan]Result[/]")
    table = Table(show_header=True, box=None)
    table.add_column("CC", width=6)
    table.add_column("Control", min_width=46)
    table.add_column("Status", width=8)
    for r in results:
        status = "[green]PASS[/]" if r["passed"] else "[red]FAIL[/]"
        table.add_row(r.get("cc", ""), r["title"], status)
    console.print(table)
    console.print(f"\n[bold]{passed}[/] passed · [bold]{failed}[/] failed · "
                  f"PDF: {final_state.get('pdf_path')}\n"
                  f"SHA-256: {final_state.get('pdf_sha256')}")

    if save_log:
        out = Path("out") / f"{run_id}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(final_state, default=str, indent=2))
        console.print(f"[dim]Event log: {out}[/]")


@app.command()
def version() -> None:
    """Print agent version."""
    from compliance import __version__
    console.print(f"compliance-evidence-agent {__version__}")


if __name__ == "__main__":
    app()

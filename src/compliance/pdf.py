"""SOC 2 evidence pack PDF — Jinja2 → HTML → WeasyPrint."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

_TEMPLATES = Path(__file__).resolve().parents[2] / "templates"
_env = Environment(loader=FileSystemLoader(_TEMPLATES), autoescape=select_autoescape(["html", "xml"]))


def render_evidence_pack(
    *,
    run_id: str,
    framework: str,
    results: list[dict],
    summary_md: str,
    generated_at: datetime,
) -> bytes:
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]
    template = _env.get_template("evidence_pack.html")
    html = template.render(
        run_id=run_id,
        framework=framework,
        generated_at=generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        results=results,
        passed=passed,
        failed=failed,
        pass_rate_pct=int(round(len(passed) / max(len(results), 1) * 100)),
        summary_md=summary_md,
    )
    return HTML(string=html, base_url=str(_TEMPLATES)).write_pdf()

"""LangGraph nodes — load controls, pull evidence (parallel per source),
validate, generate narrative, build PDF, sign."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
import yaml
from b2b_toolkit import get_adapters

from compliance.pdf import render_evidence_pack
from compliance.state import ComplianceState
from compliance.validator import validate_controls

log = structlog.get_logger()

CONTROLS_DIR = Path(__file__).resolve().parents[2] / "controls"


def _out_dir() -> Path:
    p = Path(os.environ.get("COMPLIANCE_OUT_DIR", "evidence-packs"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _event(kind: str, **detail: Any) -> dict[str, Any]:
    return {"at": datetime.now(timezone.utc).isoformat(), "kind": kind, **detail}


async def load_controls(state: ComplianceState) -> dict[str, Any]:
    framework = state.get("framework", "soc2")
    path = CONTROLS_DIR / f"{framework}.yaml"
    data = yaml.safe_load(path.read_text())
    controls = data["controls"]
    log.info("compliance.controls.loaded", framework=framework, count=len(controls))
    return {"controls": controls, "events": [_event("controls_loaded", count=len(controls))]}


async def pull_entra(state: ComplianceState) -> dict[str, Any]:
    adapters = get_adapters()
    policies = await adapters.entra_audit.list_conditional_access_policies()
    audits = await adapters.entra_audit.list_directory_audit_events(days=30)
    role_members = await adapters.entra_audit.list_admin_role_members()
    log.info(
        "compliance.entra.pulled",
        policies=len(policies),
        audits=len(audits),
        roles=len(role_members),
    )
    return {
        "evidence_entra": {
            "policies": policies,
            "audits": audits,
            "role_members": role_members,
        },
        "events": [_event("entra_evidence", policies=len(policies), audits=len(audits))],
    }


async def pull_azure(state: ComplianceState) -> dict[str, Any]:
    adapters = get_adapters()
    facts = await adapters.azure_resource.query_resources(
        # Read-all-resources query; predicates filter by type later
        "Resources | project id, type, name, location, properties | limit 500"
    )
    diag = await adapters.azure_resource.get_subscription_diagnostic_settings()
    log.info("compliance.azure.pulled", facts=len(facts), diag=len(diag))
    return {
        "evidence_azure": {"facts": facts, "diagnostic_settings": diag},
        "events": [_event("azure_evidence", facts=len(facts), diag=len(diag))],
    }


async def validate(state: ComplianceState) -> dict[str, Any]:
    evidence = {
        "entra_audit": state["evidence_entra"],
        "azure_resource": state["evidence_azure"],
    }
    results = validate_controls(state["controls"], evidence)
    passed = sum(1 for r in results if r["passed"])
    log.info("compliance.validated", total=len(results), passed=passed, failed=len(results) - passed)
    return {
        "results": results,
        "events": [_event("validated", total=len(results), passed=passed, failed=len(results) - passed)],
    }


async def summarize(state: ComplianceState) -> dict[str, Any]:
    """LLM-flavored exec summary of the gaps. Falls back to a deterministic stub
    when no API key is set, so the demo runs cold."""
    fails = [r for r in state["results"] if not r["passed"]]
    if not fails:
        return {"summary_md": "**All controls passed.** No remediation required this cycle."}

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"summary_md": _stub_summary(state["results"])}

    from anthropic import AsyncAnthropic

    client = AsyncAnthropic()
    prompt = (
        "You are writing the executive summary of a SOC 2 evidence collection run "
        "for a B2B cybersecurity services company. Below is the structured result. "
        "Write 4-6 sentences. Lead with the count of failures and the highest-impact "
        "gap. Mention the specific control IDs (e.g. CC6.1-MFA-FOR-ADMINS) so a "
        "remediation owner can act. No fluff, no recommendations beyond the implied "
        "remediation. Plain text, no markdown headers.\n\n"
        f"Total controls: {len(state['results'])}\n"
        f"Passed: {len(state['results']) - len(fails)}\n"
        f"Failed: {len(fails)}\n\n"
        f"Failures:\n{json.dumps(fails, indent=2, default=str)[:3500]}"
    )
    msg = await client.messages.create(
        model=os.environ.get("COMPLIANCE_MODEL", "claude-sonnet-4-6"),
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}],
    )
    return {"summary_md": msg.content[0].text.strip()}


def _stub_summary(results: list[dict]) -> str:
    fails = [r for r in results if not r["passed"]]
    bullets = "\n".join(f"- `{f['id']}` — {f['title']}" for f in fails[:6])
    return (
        f"**{len(fails)} of {len(results)} controls failed.** "
        f"Highest-impact failure is `{fails[0]['id']}` "
        f"({fails[0]['title']}). Other open gaps:\n\n{bullets}"
    )


async def build_pdf(state: ComplianceState) -> dict[str, Any]:
    pdf_bytes = render_evidence_pack(
        run_id=state["run_id"],
        framework=state.get("framework", "soc2").upper(),
        results=state["results"],
        summary_md=state.get("summary_md", ""),
        generated_at=datetime.now(timezone.utc),
    )
    out_path = _out_dir() / f"{state['run_id']}-evidence-pack.pdf"
    out_path.write_bytes(pdf_bytes)

    sha = hashlib.sha256(pdf_bytes).hexdigest()
    sidecar = out_path.with_suffix(".sha256")
    sidecar.write_text(f"{sha}  {out_path.name}\n")
    log.info("compliance.pdf.built", path=str(out_path), sha256=sha[:12], bytes=len(pdf_bytes))
    return {
        "pdf_path": str(out_path),
        "pdf_sha256": sha,
        "events": [_event("pdf_built", path=str(out_path), sha256=sha[:12])],
    }

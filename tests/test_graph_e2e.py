"""End-to-end run against mock adapters."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from compliance.graph import build_graph
from compliance.state import ComplianceState


@pytest.mark.asyncio
async def test_full_compliance_run_against_mocks(tmp_path, monkeypatch):
    monkeypatch.setenv("COMPLIANCE_OUT_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("B2B_USE_MOCKS", "true")

    graph = build_graph().compile()
    initial: ComplianceState = {
        "run_id": "test-run",
        "framework": "soc2",
        "events": [],
        "errors": [],
    }
    final = await graph.ainvoke(initial)

    # All controls in the YAML produced a result
    yaml_controls = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "controls" / "soc2.yaml").read_text()
    )["controls"]
    assert len(final["results"]) == len(yaml_controls)

    # Mock data was engineered so 5 fail. Specific failures we expect:
    failed_ids = {r["id"] for r in final["results"] if not r["passed"]}
    assert "CC6.1-MFA-FOR-ALL" in failed_ids
    assert "CC6.1-MFA-FOR-ADMINS" in failed_ids
    assert "CC7.2-AUDIT-LOG-RETENTION" in failed_ids
    assert "CC8.1-STORAGE-NO-PUBLIC-BLOBS" in failed_ids
    assert "C1.1-KEYVAULT-PURGE-PROTECTION" in failed_ids

    # And these should pass:
    passed_ids = {r["id"] for r in final["results"] if r["passed"]}
    assert "CC6.1-LEGACY-AUTH-BLOCKED" in passed_ids
    assert "CC6.3-ADMIN-ROLE-COUNT" in passed_ids
    assert "CC8.1-STORAGE-TLS-12" in passed_ids
    assert "CC6.7-WEBSITES-HTTPS-ONLY" in passed_ids

    # PDF + sidecar created
    pdf = tmp_path / "test-run-evidence-pack.pdf"
    sha = tmp_path / "test-run-evidence-pack.sha256"
    assert pdf.exists() and pdf.read_bytes()[:4] == b"%PDF"
    assert sha.exists() and len(sha.read_text().split()[0]) == 64
    assert final["pdf_sha256"] in sha.read_text()


@pytest.mark.asyncio
async def test_summarize_uses_stub_without_api_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("COMPLIANCE_OUT_DIR", str(tmp_path))
    graph = build_graph().compile()
    final = await graph.ainvoke(
        {"run_id": "stub", "framework": "soc2", "events": [], "errors": []}
    )
    summary = final.get("summary_md", "")
    assert "controls failed" in summary or "All controls passed" in summary

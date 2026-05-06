"""LangGraph state for the compliance evidence run."""

from __future__ import annotations

from operator import add
from typing import Annotated, Any, TypedDict


class ComplianceState(TypedDict, total=False):
    run_id: str
    framework: str  # e.g. "soc2"

    # Loaded from controls/<framework>.yaml
    controls: list[dict[str, Any]]

    # Raw evidence per source (populated by parallel pull nodes)
    evidence_entra: dict[str, Any]
    evidence_azure: dict[str, Any]

    # One result per control: {id, cc, title, passed, detail, source}
    results: list[dict[str, Any]]

    # LLM-generated narrative summary of failures (or stub)
    summary_md: str

    # Final artifacts
    pdf_path: str | None
    pdf_sha256: str | None
    pdf_url: str | None

    events: Annotated[list[dict[str, Any]], add]
    errors: Annotated[list[str], add]

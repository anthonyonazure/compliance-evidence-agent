"""Wires compliance nodes into a LangGraph state machine.

Layout:
  load_controls
       │
       ├──► pull_entra ──┐
       │                 │
       └──► pull_azure ──┴──► validate ──► summarize ──► build_pdf ──► END

Pulls run in parallel; both fan into validate. Validate is deterministic
(predicates), summarize is the only LLM step, build_pdf is pure rendering.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from compliance.nodes import (
    build_pdf,
    load_controls,
    pull_azure,
    pull_entra,
    summarize,
    validate,
)
from compliance.state import ComplianceState


def build_graph():
    g: StateGraph = StateGraph(ComplianceState)
    g.add_node("load_controls", load_controls)
    g.add_node("pull_entra", pull_entra)
    g.add_node("pull_azure", pull_azure)
    g.add_node("validate", validate)
    g.add_node("summarize", summarize)
    g.add_node("build_pdf", build_pdf)

    g.add_edge(START, "load_controls")
    g.add_edge("load_controls", "pull_entra")
    g.add_edge("load_controls", "pull_azure")
    # Both pulls converge in the same super-step → validate fires once
    g.add_edge("pull_entra", "validate")
    g.add_edge("pull_azure", "validate")
    g.add_edge("validate", "summarize")
    g.add_edge("summarize", "build_pdf")
    g.add_edge("build_pdf", END)
    return g

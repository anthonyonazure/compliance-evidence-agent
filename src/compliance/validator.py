"""Validates each control in the loaded YAML against the gathered evidence.

Validation is purely deterministic — predicates live in compliance.predicates,
each is a (evidence, args) → (passed, detail) function. The validator only
dispatches and packages results.
"""

from __future__ import annotations

import importlib
from typing import Any


def _resolve(dotted: str):
    module, _, name = dotted.rpartition(".")
    return getattr(importlib.import_module(module), name)


def validate_controls(
    controls: list[dict[str, Any]], evidence: dict[str, Any]
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for c in controls:
        check = c.get("check")
        args = c.get("args", {}) or {}
        passed: bool
        detail: dict[str, Any]

        try:
            if check == "predicate":
                fn = _resolve(args["predicate"])
                passed, detail = fn(evidence, args)
            elif check == "count_min":
                source_key = c["source"]
                # count_min checks against the first list found under that source
                source_data = evidence.get(source_key, {})
                # pick the largest list as the data series
                series = next(
                    (v for v in source_data.values() if isinstance(v, list)), []
                )
                passed = len(series) >= int(args.get("min_count", 1))
                detail = {"count": len(series), "min_count": args.get("min_count", 1)}
            elif check == "presence":
                source_key = c["source"]
                passed = bool(evidence.get(source_key))
                detail = {"present": passed}
            else:
                passed = False
                detail = {"error": f"unknown check kind: {check!r}"}
        except Exception as e:  # noqa: BLE001 — surface to the result, not the caller
            passed = False
            detail = {"error": str(e)[:300]}

        results.append(
            {
                "id": c["id"],
                "cc": c.get("cc"),
                "title": c["title"],
                "source": c.get("source"),
                "check": check,
                "passed": passed,
                "detail": detail,
            }
        )
    return results

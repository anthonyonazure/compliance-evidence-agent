"""Deterministic SOC 2 predicates.

Each predicate takes (evidence: dict, args: dict) and returns
(passed: bool, detail: dict). evidence is the per-source raw data
loaded by the agent (e.g. evidence['entra_audit']['policies']).

No LLM here — compliance pass/fail must be reproducible and auditable.
"""

from __future__ import annotations

from typing import Any


def has_mfa_for_all_users(evidence: dict, args: dict) -> tuple[bool, dict]:
    policies = evidence["entra_audit"]["policies"]
    matching = [
        p
        for p in policies
        if p.state == "enabled"
        and "mfa" in p.grant_controls
        and "All" in p.user_scope_includes
        and "All" in p.apps_includes
    ]
    return (
        len(matching) > 0,
        {"matching_policies": [{"id": p.id, "name": p.display_name} for p in matching]},
    )


def has_mfa_for_admins(evidence: dict, args: dict) -> tuple[bool, dict]:
    policies = evidence["entra_audit"]["policies"]
    admin_role_keywords = ("admin", "Administrator")
    matching = [
        p
        for p in policies
        if p.state == "enabled"
        and "mfa" in p.grant_controls
        and any(
            any(k.lower() in u.lower() for k in admin_role_keywords)
            for u in p.user_scope_includes
        )
    ]
    return (
        len(matching) > 0,
        {"matching_policies": [{"id": p.id, "name": p.display_name} for p in matching]},
    )


def blocks_legacy_auth(evidence: dict, args: dict) -> tuple[bool, dict]:
    policies = evidence["entra_audit"]["policies"]
    matching = [
        p
        for p in policies
        if p.state == "enabled"
        and "block" in p.grant_controls
        and ("legacy" in p.display_name.lower() or "block" in p.display_name.lower())
    ]
    return (
        len(matching) > 0,
        {"matching_policies": [{"id": p.id, "name": p.display_name} for p in matching]},
    )


def global_admin_count_within_limit(evidence: dict, args: dict) -> tuple[bool, dict]:
    members = evidence["entra_audit"]["role_members"]
    max_allowed = int(args.get("max_global_admins", 4))
    ga = [m for m in members if m["role"] == "Global Administrator"]
    return (
        len(ga) <= max_allowed,
        {
            "global_admins": [m["member_upn"] for m in ga],
            "count": len(ga),
            "max_allowed": max_allowed,
        },
    )


def subscription_diagnostics_configured(
    evidence: dict, args: dict
) -> tuple[bool, dict]:
    settings = evidence["azure_resource"]["diagnostic_settings"]
    return (len(settings) > 0, {"diagnostic_setting_count": len(settings)})


def _filter_by_type(facts: list[Any], rt_substring: str) -> list[Any]:
    return [f for f in facts if rt_substring.lower() in f.resource_type.lower()]


def storage_no_public_blobs(evidence: dict, args: dict) -> tuple[bool, dict]:
    storage = _filter_by_type(
        evidence["azure_resource"]["facts"], "storage/storageaccounts"
    )
    offenders = [s for s in storage if s.properties.get("allowBlobPublicAccess", False)]
    return (
        len(offenders) == 0,
        {
            "checked": len(storage),
            "offenders": [{"id": s.resource_id, "name": s.name} for s in offenders],
        },
    )


def storage_tls_minimum_12(evidence: dict, args: dict) -> tuple[bool, dict]:
    storage = _filter_by_type(
        evidence["azure_resource"]["facts"], "storage/storageaccounts"
    )
    offenders = [
        s
        for s in storage
        if s.properties.get("minimumTlsVersion", "TLS1_0") not in ("TLS1_2", "TLS1_3")
    ]
    return (
        len(offenders) == 0,
        {
            "checked": len(storage),
            "offenders": [
                {"id": s.resource_id, "tls": s.properties.get("minimumTlsVersion")}
                for s in offenders
            ],
        },
    )


def keyvault_purge_protection_enabled(evidence: dict, args: dict) -> tuple[bool, dict]:
    vaults = _filter_by_type(evidence["azure_resource"]["facts"], "keyvault/vaults")
    offenders = [
        v for v in vaults if not v.properties.get("enablePurgeProtection", False)
    ]
    return (
        len(offenders) == 0,
        {
            "checked": len(vaults),
            "offenders": [{"id": v.resource_id, "name": v.name} for v in offenders],
        },
    )


def app_service_https_only(evidence: dict, args: dict) -> tuple[bool, dict]:
    sites = _filter_by_type(evidence["azure_resource"]["facts"], "web/sites")
    offenders = [s for s in sites if not s.properties.get("httpsOnly", False)]
    return (
        len(offenders) == 0,
        {
            "checked": len(sites),
            "offenders": [{"id": s.resource_id, "name": s.name} for s in offenders],
        },
    )

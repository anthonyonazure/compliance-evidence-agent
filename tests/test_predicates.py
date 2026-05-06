"""Pure-logic tests — each predicate against synthetic evidence."""

from __future__ import annotations

from b2b_toolkit.models import AzureResourceFact, ConditionalAccessPolicy

from compliance import predicates as P


def _policy(**over):
    base = dict(
        id="p", display_name="x", state="enabled",
        grant_controls=["mfa"], user_scope_includes=["All"], apps_includes=["All"],
    )
    base.update(over)
    return ConditionalAccessPolicy(**base)


def _fact(rt, **props):
    return AzureResourceFact(
        resource_id=f"/sub/x/{rt}/n", resource_type=rt, name="n", location="eastus", properties=props
    )


def test_mfa_for_all_users_passes_when_global_mfa_enabled():
    ev = {"entra_audit": {"policies": [_policy()]}}
    ok, _ = P.has_mfa_for_all_users(ev, {})
    assert ok


def test_mfa_for_all_users_fails_when_only_guests():
    ev = {"entra_audit": {"policies": [_policy(user_scope_includes=["GuestsOrExternalUsers"])]}}
    ok, _ = P.has_mfa_for_all_users(ev, {})
    assert not ok


def test_mfa_for_admins_passes_when_admin_targeted():
    ev = {"entra_audit": {"policies": [_policy(user_scope_includes=["Global Administrator"])]}}
    ok, _ = P.has_mfa_for_admins(ev, {})
    assert ok


def test_blocks_legacy_auth_passes_when_block_policy_present():
    ev = {"entra_audit": {"policies": [_policy(display_name="Block legacy auth", grant_controls=["block"])]}}
    ok, _ = P.blocks_legacy_auth(ev, {})
    assert ok


def test_global_admin_count_within_limit():
    ev = {"entra_audit": {"role_members": [
        {"role": "Global Administrator", "member_upn": "a@b"},
        {"role": "Global Administrator", "member_upn": "c@d"},
    ]}}
    ok, detail = P.global_admin_count_within_limit(ev, {"max_global_admins": 4})
    assert ok and detail["count"] == 2


def test_global_admin_count_too_many():
    members = [{"role": "Global Administrator", "member_upn": f"u{i}@x"} for i in range(6)]
    ev = {"entra_audit": {"role_members": members}}
    ok, _ = P.global_admin_count_within_limit(ev, {"max_global_admins": 4})
    assert not ok


def test_subscription_diagnostics_configured():
    ok, _ = P.subscription_diagnostics_configured({"azure_resource": {"diagnostic_settings": [{"id": "x"}]}}, {})
    assert ok
    ok, _ = P.subscription_diagnostics_configured({"azure_resource": {"diagnostic_settings": []}}, {})
    assert not ok


def test_storage_no_public_blobs_passes_when_none_offending():
    facts = [_fact("microsoft.storage/storageaccounts", allowBlobPublicAccess=False)]
    ev = {"azure_resource": {"facts": facts}}
    ok, _ = P.storage_no_public_blobs(ev, {})
    assert ok


def test_storage_no_public_blobs_fails_with_offender():
    facts = [_fact("microsoft.storage/storageaccounts", allowBlobPublicAccess=True)]
    ev = {"azure_resource": {"facts": facts}}
    ok, detail = P.storage_no_public_blobs(ev, {})
    assert not ok and detail["offenders"]


def test_storage_tls_minimum_12_pass_and_fail():
    pass_facts = [_fact("microsoft.storage/storageaccounts", minimumTlsVersion="TLS1_2")]
    fail_facts = [_fact("microsoft.storage/storageaccounts", minimumTlsVersion="TLS1_0")]
    assert P.storage_tls_minimum_12({"azure_resource": {"facts": pass_facts}}, {})[0]
    assert not P.storage_tls_minimum_12({"azure_resource": {"facts": fail_facts}}, {})[0]


def test_keyvault_purge_protection_enabled():
    facts = [_fact("microsoft.keyvault/vaults", enablePurgeProtection=True)]
    assert P.keyvault_purge_protection_enabled({"azure_resource": {"facts": facts}}, {})[0]
    facts = [_fact("microsoft.keyvault/vaults", enablePurgeProtection=False)]
    assert not P.keyvault_purge_protection_enabled({"azure_resource": {"facts": facts}}, {})[0]


def test_app_service_https_only():
    facts = [_fact("microsoft.web/sites", httpsOnly=True)]
    assert P.app_service_https_only({"azure_resource": {"facts": facts}}, {})[0]
    facts = [_fact("microsoft.web/sites", httpsOnly=False)]
    assert not P.app_service_https_only({"azure_resource": {"facts": facts}}, {})[0]

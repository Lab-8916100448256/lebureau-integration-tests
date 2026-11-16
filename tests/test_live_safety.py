"""Offline checks for the live runner's namespace and HTTP boundaries."""

import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from harness import support as runner
from harness.api import API

runner.API = API
DOMAIN = "ynh-lebureau-1234.example.org"


@pytest.mark.parametrize(
    "name", [DOMAIN, "_acceptance." + DOMAIN, "*." + DOMAIN, DOMAIN.upper() + "."]
)
def test_namespace_accepts_only_domain_and_descendants(name):
    assert runner.owns_name(name, DOMAIN)


@pytest.mark.parametrize(
    "name",
    ["example.org", "other.example.org", "not-" + DOMAIN, DOMAIN + ".external.org"],
)
def test_namespace_rejects_parent_sibling_and_suffix_tricks(name):
    assert not runner.owns_name(name, DOMAIN)


@pytest.mark.parametrize("action", ["create", "update", "delete", "unchanged"])
def test_preview_rejects_outside_owner_in_every_action(action):
    plan = {key: [] for key in ("create", "update", "delete", "unchanged")}
    plan[action] = [{"name": "@"}]
    with pytest.raises(RuntimeError, match="outside"):
        runner.assert_preview_scope(plan, DOMAIN, "example.org")


def test_preview_accepts_relative_namespace_owners():
    plan = {key: [] for key in ("create", "update", "delete", "unchanged")}
    plan["create"] = [
        {"name": "ynh-lebureau-1234"},
        {"name": "_acceptance.ynh-lebureau-1234"},
    ]
    runner.assert_preview_scope(plan, DOMAIN, "example.org")


def test_mutating_api_timeout_is_not_retried():
    api = runner.API.__new__(runner.API)
    api.cookie = "yunohost.admin=dummy-session"
    api.session = SimpleNamespace(request=Mock(side_effect=requests.Timeout()))
    with pytest.raises(requests.Timeout):
        api.request("POST", "/domains/" + DOMAIN + "/dns/push")
    api.session.request.assert_called_once()
    args, kwargs = api.session.request.call_args
    assert args[1].startswith("http://127.0.0.1:6787/")
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["X-Requested-With"] == "XMLHttpRequest"


def test_api_accepts_successful_action_without_return_value():
    api = runner.API.__new__(runner.API)
    api.cookie = None
    response = Mock(status_code=204)
    api.session = SimpleNamespace(request=Mock(return_value=response))
    assert api.request("PUT", "/domains/example.org/config/dns.registrar") is None
    response.json.assert_not_called()
    api.session.request.assert_called_once()


@pytest.mark.parametrize("status", [200, 201])
def test_api_accepts_completed_actions_with_json_results(status):
    api = runner.API.__new__(runner.API)
    api.cookie = None
    result = {"create": [], "update": [], "delete": [], "unchanged": []}
    response = Mock(status_code=status)
    response.json.return_value = result
    api.session = SimpleNamespace(request=Mock(return_value=response))
    assert api.request("POST", "/domains/example.org/dns/push") == result
    api.session.request.assert_called_once()


@pytest.mark.parametrize("status", [202, 302, 400, 401, 500])
def test_api_does_not_treat_pending_redirect_or_failure_as_completion(status):
    api = runner.API.__new__(runner.API)
    api.cookie = None
    api.session = SimpleNamespace(
        request=Mock(return_value=SimpleNamespace(status_code=status, text="response"))
    )
    with pytest.raises(RuntimeError, match=f"HTTP {status}"):
        api.request("PUT", "/domains/example.org/config/dns.registrar")
    api.session.request.assert_called_once()


@pytest.mark.parametrize("value", ["v1", "v2", None])
def test_custom_hook_runs_under_yunohost_bash_dispatch(tmp_path, value):
    state = tmp_path / "state with spaces.json"
    hook = tmp_path / "90-acceptance"
    returned = tmp_path / "stdreturn"
    expected = (
        [{"type": "TXT", "name": "_acceptance", "value": value, "ttl": 3600}]
        if value
        else []
    )
    state.write_text(json.dumps(expected))
    hook.write_text(runner.hook_source(DOMAIN, state))
    result = subprocess.run(
        ["/bin/bash", "-x", str(hook)],
        env={**os.environ, "base_domain": DOMAIN, "YNH_STDRETURN": str(returned)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(returned.read_text()) == expected
    # The same installed hook must have no effect on other configured domains.
    subprocess.run(
        ["/bin/bash", str(hook)],
        env={
            **os.environ,
            "base_domain": "other.example.org",
            "YNH_STDRETURN": str(returned),
        },
        check=True,
    )
    assert json.loads(returned.read_text()) == []


def soa(serial=1, refresh=3600):
    return {
        "name": "example.org",
        "type": "SOA",
        "ttl": 300,
        "content": f"ns.example.org. hostmaster.example.org. {serial} {refresh} 600 86400 300",
    }


def test_baseline_allows_authority_soa_serial_advancement():
    assert runner.baseline_fingerprints([soa(1)]) == runner.baseline_fingerprints(
        [soa(2)]
    )


def test_baseline_still_detects_soa_configuration_changes():
    assert runner.baseline_fingerprints([soa()]) != runner.baseline_fingerprints(
        [soa(refresh=7200)]
    )


def test_baseline_still_detects_missing_or_changed_user_records():
    record = {"name": "example.org", "type": "TXT", "ttl": 300, "content": "existing"}
    baseline = runner.baseline_fingerprints([soa(), record])
    assert baseline - runner.baseline_fingerprints([soa(2)])
    assert baseline - runner.baseline_fingerprints(
        [soa(2), {**record, "content": "changed"}]
    )


def test_baseline_ignores_generated_dnssec_records_but_preserves_dnskeys():
    generated = [
        {"name": "example.org", "type": kind, "content": "generated"}
        for kind in ("RRSIG", "NSEC", "NSEC3")
    ]
    assert runner.baseline_fingerprints(generated) == {}
    assert runner.baseline_fingerprints(
        [{"name": "example.org", "type": "DNSKEY", "content": "key"}]
    )

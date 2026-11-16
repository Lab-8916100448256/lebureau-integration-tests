"""Container-side setup/read-back/cleanup for the real webadmin acceptance.

Invoke through Incus with stdout captured: prepare returns temporary credentials.
All durable credentials and the pre-test DNS baseline stay root-only.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import quote, quote_plus, urlencode

import yaml

from harness import support
from harness.credentials import parse_credentials, valid_zone
from harness.api import API
from lexicon.config import ConfigResolver
from lexicon._private.providers.lebureau import Provider

ROOT = Path("/root/lebureau-integration-tests")
STATE = ROOT / "fixture.json"
ZONE = os.environ.get("HARNESS_ZONE", "example.org")
helpers = vars(support)


class FixtureError(RuntimeError):
    """A diagnostic containing only static fixture-operation details."""


def command(*args, data=None):
    result = subprocess.run(
        args, input=data, text=True, capture_output=True, timeout=360
    )
    if result.returncode:
        # Never forward subprocess diagnostics, which may include credentials.
        raise FixtureError(f"{args[0]} {args[1]} failed with exit {result.returncode}")
    return result.stdout


def save(state, exclusive=False):
    with tempfile.NamedTemporaryFile(
        mode="w", dir=STATE.parent, prefix=".fixture-", delete=False
    ) as stream:
        temporary = Path(stream.name)
        json.dump(state, stream)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        if exclusive:
            os.link(temporary, STATE)
        else:
            os.replace(temporary, STATE)
    finally:
        temporary.unlink(missing_ok=True)


def provider(state):
    result = Provider(
        ConfigResolver().with_dict(
            {
                "provider_name": "lebureau",
                "domain": ZONE,
                "delegated": ZONE,
                "lebureau": {"auth_token": state["token"]},
            }
        )
    )
    result.authenticate()
    return result


def load():
    state = json.loads(STATE.read_text())
    expected_run = os.environ.get("HARNESS_RUN_ID")
    if expected_run and state.get("run_id") != expected_run:
        raise FixtureError("A different run owns the recovery state")
    global ZONE
    ZONE = valid_zone(state["zone"])
    if not re.fullmatch(
        r"ynh-lebureau-[0-9a-f]{16}\." + re.escape(ZONE), state["domain"]
    ):
        raise FixtureError("Unexpected fixture domain")
    if not re.fullmatch(r"lbtest[0-9a-f]{12}", state["username"]):
        raise FixtureError("Unexpected fixture user")
    if any(
        child != "child." + state["domain"]
        for child in state.get("installed_children", [])
    ):
        raise FixtureError("Unexpected fixture child")
    return state


def prepare():
    if STATE.exists():
        raise FixtureError("Previous browser fixture requires cleanup first")
    if not Path("/etc/yunohost/installed").exists():
        raise FixtureError("Container postinstall is incomplete")
    credential = parse_credentials(sys.stdin.read())
    if credential.zone != ZONE:
        raise FixtureError("Credential zone does not match the selected zone")
    state = {
        "domain": "ynh-lebureau-" + uuid.uuid4().hex[:16] + "." + ZONE,
        "username": "lbtest" + uuid.uuid4().hex[:12],
        "password": secrets.token_urlsafe(36) + "!aA7",
        "token": credential.token,
        "zone": ZONE,
        "run_id": os.environ.get("HARNESS_RUN_ID", ""),
        "log_files": [p.name for p in Path("/var/log/yunohost/operations").iterdir()],
    }
    state["baseline"] = provider(state).list_records()
    owns = helpers["owns_name"]
    if any(owns(r["name"], state["domain"]) for r in state["baseline"]):
        raise FixtureError("Test namespace is not empty")
    domains = json.loads(command("yunohost", "--output-as", "json", "domain", "list"))[
        "domains"
    ]
    if any(owns(state["domain"], domain) for domain in domains):
        raise FixtureError("An installed parent domain would intercept this test")
    users = json.loads(command("yunohost", "--output-as", "json", "user", "list"))[
        "users"
    ]
    if state["username"] in users:
        raise FixtureError("Temporary user already exists")
    ROOT.mkdir(mode=0o700, exist_ok=True)
    save(state, exclusive=True)  # Claim state before making local changes.
    command(
        "yunohost",
        "tools",
        "shell",
        "-c",
        "import json,sys; from yunohost.user import user_create; user_create(**json.load(sys.stdin))",
        data=json.dumps(
            {
                "username": state["username"],
                "password": state["password"],
                "domain": json.loads(
                    command("yunohost", "--output-as", "json", "domain", "main-domain")
                )["current_main_domain"],
                "fullname": "Le Bureau Integration Test",
                "admin": True,
            }
        ),
    )
    command("yunohost", "domain", "add", state["domain"], "--ignore-dyndns")
    return {k: state[k] for k in ("domain", "username", "password", "token")}


def inspect():
    state = load()
    path = Path("/etc/yunohost/domains") / (state["domain"] + ".yml")
    config = (yaml.safe_load(path.read_text()) or {}) if path.exists() else {}
    return {
        "token_matches": config.get("auth_token") == state["token"],
        "token_present": bool(config.get("auth_token")),
        "hash_count": len(config.get("managed_dns_records_hashes", [])),
        "hash_digest": hashlib.sha256(
            json.dumps(sorted(config.get("managed_dns_records_hashes", []))).encode()
        ).hexdigest(),
        "registrar": config.get("registrar"),
        "credentials_protected": path.exists()
        and (
            not (path.stat().st_mode & 0o077)
            or not (path.parent.stat().st_mode & 0o077)
        ),
    }


def force_hook_paths(state):
    name = state["domain"].split(".")[0]
    return (
        Path("/etc/yunohost/hooks.d/custom_dns_rules") / ("90-" + name),
        ROOT / (name + ".force.json"),
    )


def force_desired(state, value):
    hook, data = force_hook_paths(state)
    owner = "_force." + state["domain"].removesuffix("." + ZONE)
    data.write_text(
        json.dumps(
            [
                {"name": owner, "type": "TXT", "ttl": 3600, "value": json.dumps(text)}
                for text in (value, "lebureau-force-keep")
            ]
        )
    )
    data.chmod(0o600)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(helpers["hook_source"](state["domain"], data))
    hook.chmod(0o700)


def seed_force():
    state = load()
    backend = provider(state)
    if any(
        helpers["owns_name"](r["name"], state["domain"]) for r in backend.list_records()
    ):
        raise FixtureError("Force fixture namespace must be empty before seeding")
    force_desired(state, "lebureau-force-new")
    for owner, value in (
        ("_force", "lebureau-force-old"),
        ("_force", "lebureau-force-keep"),
        ("_force_orphan", "lebureau-force-orphan"),
    ):
        if not backend.create_record(
            "TXT", owner + "." + state["domain"], json.dumps(value)
        ):
            raise FixtureError("Force fixture record creation failed")
    return inspect_force()


def inspect_force():
    from yunohost.dns import _normalize_txt_content

    state = load()
    config = inspect()
    config["txt"] = sorted(
        (r["name"].rstrip("."), _normalize_txt_content(r["content"]))
        for r in provider(state).list_records()
        if r["type"] == "TXT" and helpers["owns_name"](r["name"], state["domain"])
    )
    config["baseline_preserved"] = not (
        helpers["baseline_fingerprints"](state["baseline"])
        - helpers["baseline_fingerprints"](provider(state).list_records())
    )
    return config


def cli_force_check():
    state = load()
    # CLI output includes "ignored" annotations that the structured API omits.
    before = inspect_force()
    dry = json.loads(
        command(
            "yunohost",
            "--output-as",
            "json",
            "domain",
            "dns",
            "push",
            state["domain"],
            "--dry-run",
        )
    )
    command("yunohost", "domain", "dns", "push", state["domain"])
    after = inspect_force()
    return {
        "ignored_update": any("ignored, won't be changed" in r for r in dry["update"]),
        "ignored_delete": any("ignored, won't be changed" in r for r in dry["delete"]),
        "ordinary_cli_preserved": before == after,
    }


def change_force():
    force_desired(load(), "lebureau-force-next")
    return {"changed": True}


def cli_force_roundtrip():
    state = load()
    backend = provider(state)
    owner = "_force." + state["domain"]
    match = [
        r
        for r in backend.list_records("TXT", owner)
        if r["content"] == "lebureau-force-next"
    ]
    if len(match) != 1:
        raise FixtureError("Expected exact fixture TXT before CLI force check")
    if not backend.update_record(
        identifier=match[0]["id"], content='"lebureau-force-cli-old"'
    ):
        raise FixtureError("CLI force fixture edit failed")
    # Establish that the external edit is visible before judging whether the
    # following read-only previews changed it. Never retry the UPDATE itself.
    before = helpers["wait_read"](
        inspect_force,
        lambda result: (owner, '"lebureau-force-cli-old"') in result["txt"],
    )
    args = ("yunohost", "--output-as", "json", "domain", "dns", "push", state["domain"])
    ordinary = json.loads(command(*args, "--dry-run"))
    forced = json.loads(command(*args, "--dry-run", "--force"))
    after_dry = inspect_force()
    dry_preserved = before == after_dry
    command("yunohost", "domain", "dns", "push", state["domain"], "--force")
    after = helpers["wait_read"](
        inspect_force,
        lambda result: (owner, '"lebureau-force-next"') in result["txt"],
    )
    no_op = json.loads(command(*args, "--dry-run"))
    return {
        "diagnostic_dry_changes": {
            key: {"before": before[key], "after": after_dry[key]}
            for key in before
            if before[key] != after_dry[key]
        },
        "external_edit_requires_force": len(ordinary["update"]) == 1
        and "ignored" in ordinary["update"][0],
        "forced_preview_explains_execution": len(forced["update"]) == 1
        and "ignored" not in forced["update"][0],
        "both_cli_previews_preserve_dns_and_hashes": dry_preserved,
        "cli_force_restores_target": (owner, '"lebureau-force-next"') in after["txt"],
        "cli_force_preserves_desired_sibling": (owner, '"lebureau-force-keep"')
        in after["txt"],
        "cli_force_preserves_baseline": after["baseline_preserved"],
        "cli_force_converges": not any(
            no_op[k] for k in ("create", "update", "delete")
        ),
    }


def setup_cli_force():
    state = load()
    force_desired(state, "lebureau-force-next")
    command(
        "yunohost",
        "tools",
        "shell",
        "-c",
        "import json,sys; from yunohost.domain import domain_config_set; domain_config_set(**json.load(sys.stdin))",
        data=json.dumps(
            {
                "domain": state["domain"],
                "key": "dns.registrar",
                "args": urlencode({"use_auto_dns": 1, "auth_token": state["token"]}),
            }
        ),
    )
    command("yunohost", "domain", "dns", "push", state["domain"])
    return cli_force_roundtrip()


def add_child():
    state = load()
    child = "child." + state["domain"]
    state["installed_children"] = [child]
    save(state)  # Record the cleanup target before attempting creation.
    command("yunohost", "domain", "add", child, "--ignore-dyndns")
    return {"child": child}


def remove_certificate_links(state, certificate_dir=Path("/etc/yunohost/certs")):
    # Remove only fixture-owned links left after normal domain removal.
    # Certificate history is retained as in standard YunoHost domain removal.
    for name in [state["domain"], *state.get("installed_children", [])]:
        link = certificate_dir / name
        history = certificate_dir / (name + "-history")
        if link.is_symlink():
            if not link.resolve().is_relative_to(history.resolve()):
                raise FixtureError("Unexpected fixture certificate link target")
            link.unlink()


def cleanup():
    if not STATE.exists():
        return {"cleanup_passed": True, "fixture_absent": True}
    state = load()
    domain, username = state["domain"], state["username"]
    command("yunohost", "--timeout", "300", "tools", "shell", "-c", "pass")
    for path in force_hook_paths(state):
        path.unlink(missing_ok=True)
    backend = provider(state)
    owns = lambda record: helpers["owns_name"](record["name"], domain)
    for record in backend.list_records():
        if owns(record) and record["type"] in helpers["WRITABLE_TYPES"]:
            backend.delete_record(identifier=record["id"])
    remaining = helpers["wait_read"](
        lambda: provider(state).list_records(),
        lambda rows: not any(owns(r) for r in rows),
    )
    fingerprints = helpers["baseline_fingerprints"]
    if fingerprints(state["baseline"]) - fingerprints(remaining):
        raise FixtureError("Baseline DNS records missing; retaining recovery state")
    domains = json.loads(command("yunohost", "--output-as", "json", "domain", "list"))[
        "domains"
    ]
    for child in state.get("installed_children", []):
        if child in domains:
            command("yunohost", "domain", "remove", child, "--ignore-dyndns")
    if domain in domains:
        command("yunohost", "domain", "remove", domain, "--ignore-dyndns")
    remove_certificate_links(state)
    users = json.loads(command("yunohost", "--output-as", "json", "user", "list"))[
        "users"
    ]
    if username in users:
        # Purge only the unique account created by this fixture, including its
        # empty home/mail directory. Existing users never match this identifier.
        command("yunohost", "user", "delete", username, "--force", "--purge")
    users = json.loads(command("yunohost", "--output-as", "json", "user", "list"))[
        "users"
    ]
    if (
        username in users
        or (Path("/etc/yunohost/domains") / (domain + ".yml")).exists()
        or any(
            (Path("/etc/yunohost/certs") / child).exists()
            for child in state.get("installed_children", [])
        )
    ):
        raise FixtureError("Fixture account or domain remains")
    log_directory = Path("/var/log/yunohost/operations")
    fresh_logs = [
        p
        for p in log_directory.iterdir()
        if p.name not in state["log_files"] and p.is_file()
    ]
    sensitive = (
        state["token"],
        state["token"].split(":", 2)[2],
        state["password"],
        state.get("api_cookie", ""),
    )
    variants = {
        variant
        for value in sensitive
        if value
        for variant in (value, quote(value), quote(value, safe=""), quote_plus(value))
    }
    if any(
        value in path.read_text(errors="replace")
        for path in fresh_logs
        for value in variants
    ):
        raise FixtureError(
            "Credential found in operation logs; retaining private evidence"
        )
    STATE.unlink()
    return {
        "cleanup_passed": True,
        "baseline_preserved": True,
        "namespace_empty": True,
        "temporary_user_removed": True,
        "operation_logs_redacted": bool(fresh_logs),
    }


def api_login():
    state = load()
    api = API()
    api.login(state["username"], state["password"])
    state["api_cookie"] = api.cookie
    save(state)
    return {"authenticated": True}


def api_request():
    state = load()
    values = json.load(sys.stdin)
    path = values["path"]
    if not path.startswith("/") or "://" in path or path.startswith("//"):
        raise FixtureError("Invalid API path")
    api = API()
    api.cookie = state["api_cookie"]
    return api.request(values["method"], path, values.get("data"), values.get("params"))


def api_access_checks():
    import requests

    state = load()
    with requests.Session() as session:
        session.trust_env = False
        response = session.get(
            "http://127.0.0.1:6787/domains/"
            + state["domain"]
            + "/config/dns.registrar",
            params={"export": "true"},
            timeout=15,
            allow_redirects=False,
        )
    return {"unauthenticated_export_denied": response.status_code in (401, 403)}


def set_hook():
    state = load()
    value = json.load(sys.stdin)
    hook, data = force_hook_paths(state)
    records = (
        [
            {
                "name": "_acceptance." + state["domain"].removesuffix("." + ZONE),
                "type": "TXT",
                "ttl": 3600,
                "value": json.dumps(value),
            }
        ]
        if value is not None
        else []
    )
    data.write_text(json.dumps(records))
    data.chmod(0o600)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(support.hook_source(state["domain"], data))
    hook.chmod(0o700)
    return {"hook_set": True}


def cli_noop():
    state = load()
    command("yunohost", "domain", "dns", "push", state["domain"])
    return inspect()


def restart_api():
    load()
    command("systemctl", "restart", "yunohost-api")
    import time
    import requests

    for attempt in range(30):
        try:
            if (
                requests.get("http://127.0.0.1:6787/installed", timeout=3).status_code
                == 200
            ):
                return {"restarted": True}
        except requests.ConnectionError:
            pass
        time.sleep(1)
    raise FixtureError("API did not restart")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        action = {
            "prepare": prepare,
            "api-login": api_login,
            "api-request": api_request,
            "api-access-checks": api_access_checks,
            "set-hook": set_hook,
            "cli-noop": cli_noop,
            "restart-api": restart_api,
            "inspect": inspect,
            "cleanup": cleanup,
            "seed-force": seed_force,
            "inspect-force": inspect_force,
            "cli-force-check": cli_force_check,
            "change-force": change_force,
            "cli-force-roundtrip": cli_force_roundtrip,
            "setup-cli-force": setup_cli_force,
            "add-child": add_child,
        }[sys.argv[1]]
        print(json.dumps(action()))
    except Exception as error:
        # Only our own static errors are safe to print. Provider errors may
        # include secret material, so report their class only.
        print(
            json.dumps(
                {
                    "error": type(error).__name__,
                    "message": (
                        str(error)
                        if isinstance(error, FixtureError)
                        else "Fixture operation failed; private recovery state retained"
                    ),
                }
            ),
            file=sys.stderr,
        )
        sys.exit(1)

"""Real API and CLI acceptance using a disposable administrator and domain."""

from datetime import datetime, timezone
import json
from urllib.parse import urlencode

from . import settings as cfg
from .support import assert_preview_scope, wait_read

REPORT = {"checks": [], "mode": "live CLI and authenticated loopback API"}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)
    REPORT["checks"].append(message)
    print("PASS: " + message, flush=True)


def request(method, path, data=None, params=None):
    return cfg.fixture(
        "api-request",
        json.dumps(dict(method=method, path=path, data=data, params=params)),
    )


def main():
    REPORT["started"] = datetime.now(timezone.utc).isoformat()
    try:
        state = cfg.fixture("prepare", cfg.read_credentials())
        cfg.hide(state["password"], state["token"])
        domain, token = state["domain"], state["token"]
        check(
            cfg.fixture("api-login")["authenticated"],
            "Temporary administrator authenticates",
        )
        config_path = f"/domains/{domain}/config/dns.registrar"
        push_path = f"/domains/{domain}/dns/push"

        def exported():
            return request("GET", config_path, params={"export": "true"})

        def save(**values):
            request("PUT", config_path, data={"args": urlencode(values)})

        def preview():
            result = request("POST", push_path, data={"dry_run": "true"})
            assert_preview_scope(result, domain, cfg.ZONE)
            return result

        def no_changes(result):
            return not any(result[key] for key in ("create", "update", "delete"))

        def push():
            preview()
            result = request("POST", push_path)
            check(
                not result or not (result.get("errors") or result.get("warnings")),
                "API push succeeds",
            )
            wait_read(preview, no_changes)

        check(
            exported().get("registrar") == "lebureau",
            "Nameserver discovery selects Le Bureau",
        )
        check(
            cfg.fixture("api-access-checks")["unauthenticated_export_denied"],
            "Unauthenticated credential export is denied",
        )
        save(use_auto_dns="1", auth_token=token)
        check(
            exported().get("auth_token") == token, "Save/export preserves credentials"
        )
        check(
            token not in json.dumps(request("GET", config_path)),
            "Normal display masks credentials",
        )
        full = request("GET", config_path, params={"full": "true"})
        options = [
            o for p in full["panels"] for s in p["sections"] for o in s["options"]
        ]
        check(
            any(o["id"] == "auth_token" and o["type"] == "password" for o in options),
            "Credential field is a password input",
        )
        save(use_auto_dns="1")
        check(
            exported().get("auth_token") == token,
            "Unchanged form preserves credentials",
        )
        check(
            cfg.fixture("inspect")["credentials_protected"],
            "Stored credentials are protected",
        )
        save(use_auto_dns="0")
        check(not exported().get("auth_token"), "Disable clears credentials")
        check(cfg.fixture("inspect")["hash_count"] == 0, "Disable clears ownership")
        save(use_auto_dns="1", auth_token=token)
        cfg.fixture("set-hook", json.dumps("acceptance-v1"))
        plan = preview()
        check(
            bool(plan["create"]) and not plan["update"] and not plan["delete"],
            "Initial scoped preview proposes creates only",
        )
        REPORT["created_types"] = sorted({row["type"] for row in plan["create"]})
        push()
        before = cfg.fixture("inspect")
        check(before["hash_count"] > 0, "Push records ownership")
        after = cfg.fixture("cli-noop")
        check(
            after["hash_digest"] == before["hash_digest"],
            "Fresh CLI no-op preserves ownership",
        )
        cfg.fixture("restart-api")
        check(no_changes(preview()), "API restart preserves convergence")
        cfg.fixture("set-hook", json.dumps("acceptance-v2"))
        plan = preview()
        check(
            len(plan["update"]) == 1
            and not plan["create"]
            and not plan["delete"]
            and plan["update"][0]["managed_by_yunohost"],
            "TXT change is one managed update",
        )
        push()
        cfg.fixture("set-hook", "null")
        plan = preview()
        check(
            len(plan["delete"]) == 1
            and not plan["create"]
            and not plan["update"]
            and plan["delete"][0]["managed_by_yunohost"],
            "Removing hook produces one managed deletion",
        )
        push()
        REPORT["passed"] = True
    except BaseException:
        REPORT["passed"] = False
        raise
    finally:
        try:
            REPORT["cleanup"] = cfg.fixture("cleanup")
        except Exception as error:
            REPORT["passed"] = False
            REPORT["cleanup"] = {"cleanup_passed": False, "error": cfg.safe(error)}
            raise
        finally:
            REPORT["finished"] = datetime.now(timezone.utc).isoformat()
            cfg.save_report("live-api", REPORT)


if __name__ == "__main__":
    main()

"""Served webadmin + controlled API responses, without real API/DNS writes.

All /yunohost/api requests are fulfilled locally. No accounts, domains, tokens,
or container settings are created. The real compiled frontend is exercised.
"""

from datetime import datetime, timezone
import json
import os
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from harness import settings as cfg

BASE = cfg.BASE
DOMAIN = "ynh-failure.example.org"
RECORD = {
    "type": "TXT",
    "name": "ynh-failure",
    "content": '"fixture-record"',
    "ttl": 3600,
}
REPORT = {
    "started": datetime.now(timezone.utc).isoformat(),
    "mode": "Controlled API responses; zero backend API or DNS writes",
    "cases": [],
}


def plan(pending):
    return {
        "create": [RECORD.copy()] if pending else [],
        "update": [],
        "delete": [],
        "unchanged": [] if pending else [{**RECORD, "managed_by_yunohost": True}],
    }


def config():
    return {
        "version": 1.0,
        "panels": [
            {
                "id": "dns",
                "name": "DNS",
                "sections": [
                    {
                        "id": "registrar",
                        "name": "Registrar",
                        "is_action_section": False,
                        "options": [
                            {
                                "id": "use_auto_dns",
                                "type": "boolean",
                                "ask": "Use automatic DNS",
                                "value": True,
                                "optional": True,
                            },
                            {
                                "id": "auth_token",
                                "type": "password",
                                "ask": "Le Bureau TSIG token",
                                "value": "",
                                "optional": True,
                            },
                        ],
                    }
                ],
            }
        ],
    }


def run_case(browser, name):
    context = browser.new_context(ignore_https_errors=True, locale="en-US")
    # Authentication/startup and SSE are controlled fixtures too. No session is
    # created on the backend, and no actual EventSource connection is opened.
    context.add_init_script(
        """
        localStorage.setItem('locale','en');
        localStorage.setItem('connected','true');
        localStorage.setItem('currentUser','fixture');
        localStorage.setItem('transitions','false');
        window.EventSource = class {
            static OPEN = 1; static CLOSED = 2;
            constructor() { this.readyState=1; setTimeout(() => this.onopen?.({}),0); }
            addEventListener() {} removeEventListener() {} close() { this.readyState=2; }
        };
    """
    )
    page = context.new_page()
    page.set_default_timeout(10000)
    errors, unexpected, writes, held = [], [], [], []
    state = {"converged": False, "previews": 0}
    page.on("pageerror", lambda error: errors.append(str(error)))
    case = {"name": name, "checks": []}

    def check(ok, message):
        if not ok:
            raise AssertionError(message)
        case["checks"].append(message)

    def api(route):
        request = route.request
        url = urlsplit(request.url)
        path = url.path.removeprefix("/yunohost/api/")
        status, response = 200, {}
        if path == "installed":
            response = {"installed": True}
        elif path == "versions":
            response = {"yunohost": {"version": "13.0.10", "repo": "testing"}}
        elif path == "domains":
            response = {"domains": [DOMAIN], "main": DOMAIN}
        elif path == "domains/" + DOMAIN:
            response = {
                "certificate": {
                    "CA_type": "selfsigned",
                    "style": "warning",
                    "validity": 3650,
                },
                "registrar": "lebureau",
                "apps": [],
                "main": True,
                "topest_parent": None,
            }
        elif path == f"domains/{DOMAIN}/config":
            response = config()
        elif path == f"domains/{DOMAIN}/dns/suggest":
            response = "Controlled DNS suggestions"
        elif path == f"domains/{DOMAIN}/dns/push":
            if "dry_run" in url.query:
                state["previews"] += 1
                if (
                    writes
                    and name in ("refresh_failure", "partial_and_refresh_failure")
                    and not state["converged"]
                ):
                    status, response = 500, {
                        "error": "Fixture: AXFR unavailable after push"
                    }
                else:
                    response = plan(not state["converged"])
                    if name == "force_cancel" and not state["converged"]:
                        response["update"] = [
                            {
                                **RECORD,
                                "old_content": '"old fixture"',
                                "managed_by_yunohost": False,
                            }
                        ]
                        response["create"] = []
            else:
                writes.append(request.url)
                if name == "duplicate_click":
                    held.append(route)
                    return
                if name == "denied_update":
                    response = {"errors": ["Fixture: UPDATE refused"], "warnings": []}
                elif name == "push_http_failure":
                    status, response = 500, {"error": "Fixture: push request failed"}
                elif name == "uncertain_reply":
                    state["converged"] = True
                    response = {
                        "errors": [
                            "Fixture: update reply lost; verify records before retry"
                        ],
                        "warnings": [],
                    }
                elif name == "partial_and_refresh_failure":
                    response = {
                        "errors": ["Fixture: one record update failed"],
                        "warnings": [],
                    }
                else:
                    response = {}
        else:
            unexpected.append(request.method + " " + path)
            status, response = 500, {"error": "Unexpected controlled API request"}
        route.fulfill(
            status=status, content_type="application/json", body=json.dumps(response)
        )

    context.route("**/yunohost/api/**", api)
    try:
        page.goto(BASE + "#/domains/" + DOMAIN + "/dns")
        push = page.get_by_role(
            "button", name="Push DNS records to registrar", exact=True
        )
        expect(push).to_be_visible()
        case["assets"] = page.locator("script[src]").evaluate_all(
            "nodes => nodes.map(n => n.src)"
        )
        if name == "duplicate_click":
            push.dblclick(delay=30)
            page.wait_for_timeout(150)
            count = len(writes)
            disabled = not push.is_enabled()
            state["converged"] = True
            for route in held:
                route.fulfill(status=201, content_type="application/json", body="{}")
            expect(
                page.get_by_text("Automatic configuration seems to be OK!", exact=True)
            ).to_be_visible()
            check(count == 1, "Rapid duplicate clicks submit only one push")
            check(disabled, "The push button is disabled while a request is pending")
        elif name == "force_cancel":
            page.get_by_role(
                "checkbox", name="Overwrite existing records", exact=True
            ).check()
            push.click()
            dialog = page.get_by_role("dialog").filter(
                has=page.get_by_role("button", name="Cancel", exact=True)
            )
            expect(dialog).to_be_visible()
            dialog.get_by_role("button", name="Cancel", exact=True).click()
            expect(dialog).not_to_be_visible()
            expect(push).to_be_enabled()
            check(
                not writes,
                "Cancelling force sends no push and releases the request guard",
            )
            state["converged"] = True
            push.click()
            expect(dialog).to_be_visible()
            dialog.get_by_role("button", name="OK", exact=True).click()
            expect(
                page.get_by_text("Automatic configuration seems to be OK!", exact=True)
            ).to_be_visible()
            check(
                len(writes) == 1 and "force" in urlsplit(writes[0]).query,
                "A later confirmed force push still works",
            )
        else:
            push.click()
            if name in ("refresh_failure", "partial_and_refresh_failure"):
                dialog = page.get_by_role("dialog").filter(
                    has=page.get_by_role("button", name="OK", exact=True)
                )
                expect(
                    page.locator(".panel-section").get_by_text(
                        "Fixture: AXFR unavailable after push", exact=True
                    )
                ).to_be_visible()
                if dialog.is_visible():
                    dialog.get_by_role("button", name="OK", exact=True).click()
                    expect(dialog).not_to_be_visible()
                check(
                    not push.is_visible(), "Failed refresh clears stale push proposals"
                )
                if name == "partial_and_refresh_failure":
                    expect(
                        page.locator(".panel-section").get_by_text(
                            "Fixture: one record update failed", exact=True
                        )
                    ).to_be_visible()
                    check(True, "Write errors and refresh errors both remain visible")
            elif name == "denied_update":
                expect(
                    page.locator(".panel-section").get_by_text(
                        "Fixture: UPDATE refused", exact=True
                    )
                ).to_be_visible()
                expect(push).to_be_enabled()
            elif name == "push_http_failure":
                dialog = page.get_by_role("dialog").filter(
                    has=page.get_by_role("button", name="OK", exact=True)
                )
                expect(dialog).to_be_visible()
                expect(
                    dialog.get_by_text("Fixture: push request failed", exact=True)
                ).to_be_visible()
                dialog.get_by_role("button", name="OK", exact=True).click()
                expect(dialog).not_to_be_visible()
                expect(push).to_be_enabled()
                check(
                    True,
                    "A failed push releases the request guard for explicit recovery",
                )
            elif name == "uncertain_reply":
                expect(
                    page.locator(".panel-section").get_by_text(
                        "Fixture: update reply lost; verify records before retry",
                        exact=True,
                    )
                ).to_be_visible()
                check(
                    not push.is_visible(),
                    "Uncertain completion remains visible even when read-back has converged",
                )
            else:
                expect(push).to_be_visible()
                page.wait_for_function(
                    "document.querySelectorAll('.records').length > 0"
                )
                check(True, "Stale read-back remains a proposal, not a healthy status")
            check(
                not page.get_by_text(
                    "Automatic configuration seems to be OK!", exact=True
                ).is_visible(),
                "Failure/stale read-back never reports a healthy configuration",
            )
            page.wait_for_timeout(400)
            check(len(writes) == 1, "Refresh does not automatically retry the DNS push")
            state["converged"] = True
            page.reload()
            expect(
                page.get_by_text("Automatic configuration seems to be OK!", exact=True)
            ).to_be_visible()
            check(
                len(writes) == 1,
                "A fresh converged preview requires no additional push",
            )
        check(not errors, "No uncaught JavaScript errors")
        check(not unexpected, "All API traffic stayed within the controlled fixture")
        case["passed"] = True
    except Exception as error:
        case["passed"] = False
        case["error"] = str(error)[:2000]
    finally:
        case["push_requests"] = len(writes)
        case["preview_requests"] = state["previews"]
        case["page_errors"] = errors
        case["unexpected_api_requests"] = unexpected
        context.close()
        REPORT["cases"].append(case)
        print(
            ("PASS: " if case["passed"] else "FAIL: ")
            + name
            + (": " + case.get("error", "") if not case["passed"] else ""),
            flush=True,
        )


if __name__ == "__main__":
    with sync_playwright() as p:
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        browser = p.chromium.launch(
            headless=True, proxy={"server": proxy} if proxy else None
        )
        REPORT["chromium"] = browser.version
        for name in (
            "refresh_failure",
            "partial_and_refresh_failure",
            "denied_update",
            "stale_readback",
            "duplicate_click",
            "push_http_failure",
            "force_cancel",
            "uncertain_reply",
        ):
            run_case(browser, name)
        browser.close()
    REPORT["passed"] = all(case["passed"] for case in REPORT["cases"])
    REPORT["finished"] = datetime.now(timezone.utc).isoformat()
    cfg.save_report("browser-faults", REPORT)
    raise SystemExit(0 if REPORT["passed"] else 1)

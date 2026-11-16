"""Live ordinary/forced DNS pushes in a disposable fixture namespace.

Force deliberately overwrites/deletes seeded unmanaged records INSIDE that
namespace. Baseline parent/sibling records must survive every stage.
"""

from datetime import datetime, timezone
import os
import sys
from urllib.parse import quote, quote_plus, urlsplit

from playwright.sync_api import expect, sync_playwright

from harness import browser as runner
from harness import settings as cfg

ROOT = cfg.OUTPUT
check, fixture, report = runner.check, runner.fixture, runner.REPORT


def main():
    credentials = cfg.read_credentials()
    try:
        state = fixture("prepare", credentials)
        domain, token = state["domain"], state["token"]
        report["domain"] = domain
        runner.REDACT.extend(
            [token, quote(token, safe=""), quote_plus(token), state["password"]]
        )
        print("Force acceptance domain: " + domain, flush=True)
        if "--cli-only" in sys.argv:
            checks = fixture("setup-cli-force")
            report["cli_dry_differences"] = checks.pop("diagnostic_dry_changes")
            report["cli_force_checks"] = checks
            for key, value in checks.items():
                check(value, "CLI force: " + key, fatal=False)
            return
        seed = fixture("seed-force")
        check(seed["hash_count"] == 0, "Seeded records have no YunoHost ownership")
        with sync_playwright() as p:
            proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            browser = p.chromium.launch(
                headless=True, proxy={"server": proxy} if proxy else None
            )
            report["chromium"] = browser.version
            context = browser.new_context(
                ignore_https_errors=True,
                locale="en-US",
                viewport={"width": 1360, "height": 1000},
            )
            context.add_init_script(
                "localStorage.setItem('locale','en'); localStorage.setItem('transitions','false')"
            )
            page = context.new_page()
            page.set_default_timeout(20000)
            errors = []
            page.on("pageerror", lambda error: errors.append(runner.safe(error)))
            path = "/domains/" + domain + "/dns/push"
            writes = []

            def is_push(response):
                return (
                    urlsplit(response.url).path.endswith(path)
                    and response.request.method == "POST"
                )

            def is_preview(response):
                return is_push(response) and "dry_run" in response.url

            def is_write(response):
                return is_push(response) and "dry_run" not in response.url

            page.on(
                "request",
                lambda req: (
                    writes.append(req.url)
                    if urlsplit(req.url).path.endswith(path)
                    and "dry_run" not in req.url
                    and req.method == "POST"
                    else None
                ),
            )
            page.goto(runner.BASE)
            page.locator("#username").fill(state["username"])
            page.locator("#password").fill(state["password"])
            page.locator('button[form="login-form"]').click()
            page.wait_for_url(lambda url: "#/login" not in str(url))
            runner.REDACT.extend(
                c["value"] for c in context.cookies() if c["name"] == "yunohost.admin"
            )
            dns_url = runner.BASE + "#/domains/" + domain + "/dns"
            with page.expect_response(is_preview, timeout=180000):
                page.goto(dns_url)
            page.locator("#use_auto_dns").check()
            page.locator("#auth_token").fill(token)
            with page.expect_response(is_preview, timeout=180000) as initial:
                with page.expect_response(
                    lambda r: "/config/dns" in r.url and r.request.method == "PUT"
                ) as saved:
                    page.locator('button[form="panel-dns"][type="submit"]').click()
            check(saved.value.status == 204, "Token saved through real webadmin")
            plan = initial.value.json()
            runner.scope(plan, domain)
            report["initial_counts"] = {k: len(v) for k, v in plan.items()}
            check(
                len(plan["update"]) == 1
                and len(plan["delete"]) == 1
                and bool(plan["create"]),
                "Preview includes an unmanaged update/deletion and fresh creates",
            )
            check(
                all(
                    r["managed_by_yunohost"] is False
                    for k in ("update", "delete", "unchanged")
                    for r in plan[k]
                ),
                "All seeded records start unmanaged",
            )
            overwrite = page.get_by_role(
                "checkbox", name="Overwrite existing records", exact=True
            )
            push = page.get_by_role(
                "button", name="Push DNS records to registrar", exact=True
            )
            expect(push).to_be_visible()
            check(
                overwrite.is_visible(),
                "Overwrite option is available for exclusively unmanaged conflicts",
                fatal=False,
            )
            warning = page.get_by_text(
                "It looks like some DNS records that YunoHost would have set are already in the registrar configuration.",
                exact=False,
            )
            check(
                warning.is_visible(),
                "Overwrite warning accompanies unmanaged conflicts",
                fatal=False,
            )
            expect(page.locator(".records.ignored")).to_have_count(2)
            check(True, "Unmanaged update and deletion are marked ignored by default")

            def apply():
                with page.expect_response(is_preview, timeout=180000) as refresh:
                    with page.expect_response(is_write, timeout=180000) as result:
                        push.click()
                check(
                    result.value.status in (200, 201)
                    and not result.value.json().get("errors"),
                    "Ordinary browser push completes",
                )
                return refresh.value.json()

            after = apply()
            runner.scope(after, domain)
            check(
                not after["create"]
                and len(after["update"]) == 1
                and len(after["delete"]) == 1,
                "Ordinary push skips both unmanaged changes",
            )
            ordinary = fixture("inspect-force")
            check(
                all(row in ordinary["txt"] for row in seed["txt"]),
                "Ordinary browser push preserves seeded TXT siblings",
            )
            check(
                ordinary["baseline_preserved"],
                "Ordinary push preserves parent/sibling baseline records",
            )
            cli = fixture("cli-force-check")
            for key, value in cli.items():
                check(value, "CLI: " + key)
            expect(overwrite).to_be_visible()
            overwrite.check()
            expect(page.locator(".records.ignored")).to_have_count(0)
            before_cancel = len(writes)
            push.click()
            confirm = page.get_by_role("dialog").filter(
                has=page.get_by_text(
                    "Are you sure you want to force push all suggested dns records?",
                    exact=False,
                )
            )
            expect(confirm).to_be_visible()
            check(True, "Force displays overwrite confirmation")
            confirm.get_by_role("button", name="Cancel", exact=True).click()
            expect(confirm).not_to_be_visible()
            page.wait_for_timeout(400)
            check(
                len(writes) == before_cancel,
                "Cancelling confirmation sends no DNS push request",
            )
            check(
                fixture("inspect-force") == ordinary,
                "Cancelling force leaves DNS and ownership unchanged",
            )
            push.click()
            expect(confirm).to_be_visible()
            with page.expect_response(is_preview, timeout=180000) as forced_plan:
                with page.expect_response(is_write, timeout=180000) as forced:
                    confirm.get_by_role("button", name="OK", exact=True).click()
            check(
                "force" in urlsplit(forced.value.url).query
                and forced.value.status in (200, 201),
                "Confirmed browser push explicitly requests force",
            )
            check(
                not forced.value.json().get("errors"), "Forced push reports no errors"
            )
            final = forced_plan.value.json()
            runner.scope(final, domain)
            check(
                not any(final[k] for k in ("create", "update", "delete")),
                "Forced push converges to no changes",
            )
            forced_state = fixture("inspect-force")
            txt = forced_state["txt"]
            check(
                ["_force." + domain, '"lebureau-force-new"'] in txt
                and ["_force." + domain, '"lebureau-force-keep"'] in txt,
                "Force updates the conflicting TXT and preserves its desired sibling",
            )
            check(
                not any(name == "_force_orphan." + domain for name, content in txt),
                "Force removes the seeded unwanted record inside the test namespace",
            )
            check(
                forced_state["baseline_preserved"],
                "Force preserves all parent/sibling baseline records",
            )
            check(
                all(r["managed_by_yunohost"] for r in final["unchanged"]),
                "Force adopts matching desired records into stable ownership",
            )
            fixture("change-force")
            with page.expect_response(is_preview, timeout=180000) as changed:
                page.reload()
            managed_plan = changed.value.json()
            runner.scope(managed_plan, domain)
            check(
                len(managed_plan["update"]) == 1
                and managed_plan["update"][0]["managed_by_yunohost"],
                "Later hook change is one managed update",
            )
            expect(push).to_be_visible()
            check(
                not overwrite.is_visible(),
                "Managed-only changes do not show an overwrite warning",
                fatal=False,
            )
            check(
                not warning.is_visible(),
                "Managed-only changes do not show the overwrite disclaimer",
                fatal=False,
            )
            after_managed = apply()
            check(
                not any(after_managed[k] for k in ("create", "update", "delete")),
                "Later update succeeds without force",
            )
            cli_checks = fixture("cli-force-roundtrip")
            report["cli_dry_differences"] = cli_checks.pop("diagnostic_dry_changes")
            report["cli_force_checks"] = cli_checks
            for key, value in cli_checks.items():
                check(value, "CLI force: " + key, fatal=False)
            check(not errors, "No uncaught browser JavaScript errors")
            report["page_errors"] = errors
            context.close()
            browser.close()
    except BaseException as error:
        report["acceptance_error"] = runner.safe(error)[:2000]
        raise
    finally:
        try:
            report["cleanup"] = fixture("cleanup")
        except Exception as error:
            report["cleanup"] = {"cleanup_passed": False, "error": runner.safe(error)}
            if "acceptance_error" not in report:
                raise


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        report["error"] = runner.safe(str(error))[:2000]
    report["passed"] = not report["issues"] and "error" not in report
    report["finished"] = datetime.now(timezone.utc).isoformat()
    cfg.save_report("force", report)
    raise SystemExit(0 if report["passed"] else 1)

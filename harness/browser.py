"""Real HTTPS webadmin acceptance, invoked by the unified runner.

Uses a disposable administrator and random subdomain of the authorized zone.
No HTTP responses are mocked. Secrets are never placed in command arguments,
reports, traces, or screenshots. Container-side state enables explicit recovery.
"""

from datetime import datetime, timezone
import json
import os
from urllib.parse import quote, quote_plus, urlsplit

from playwright.sync_api import expect, sync_playwright

from harness import settings as cfg

ROOT = cfg.OUTPUT
BASE, ZONE, CONTAINER = cfg.BASE, cfg.ZONE, cfg.CONTAINER
REPORT = {"started": datetime.now(timezone.utc).isoformat(), "checks": [], "issues": []}
REDACT = cfg.REDACT
safe, fixture = cfg.safe, cfg.fixture


def check(condition, message, fatal=True):
    if not condition:
        REPORT["issues"].append(message)
        print("FAIL: " + message, flush=True)
        if fatal:
            raise RuntimeError(message)
    else:
        REPORT["checks"].append(message)
        print("PASS: " + message, flush=True)


def scope(plan, domain):
    for action in ("create", "update", "delete", "unchanged"):
        for row in plan[action]:
            name = row["name"].rstrip(".")
            absolute = ZONE if name == "@" else name + "." + ZONE
            check(
                absolute == domain or absolute.endswith("." + domain),
                "Preview record stays within test namespace: " + row["type"],
            )


def main():
    credentials = cfg.read_credentials()
    try:
        state = fixture("prepare", credentials)
        domain, token = state["domain"], state["token"]
        REDACT.extend(
            [token, quote(token, safe=""), quote_plus(token), state["password"]]
        )
        REPORT["domain"] = domain
        child = (
            fixture("add-child")["child"]
            if os.environ.get("HARNESS_INSTALLED_CHILD") == "1"
            else None
        )
        if child:
            REPORT["installed_child"] = child
        print("Browser acceptance domain: " + domain, flush=True)
        with sync_playwright() as p:
            proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            browser = p.chromium.launch(
                headless=True, proxy={"server": proxy} if proxy else None
            )
            REPORT["chromium"] = browser.version
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
            page_errors = []
            REPORT["page_errors"] = page_errors
            page.on("pageerror", lambda error: page_errors.append(safe(error)))
            page.goto(BASE, wait_until="domcontentloaded")
            page.locator("#username").fill(state["username"])
            page.locator("#password").fill(state["password"])
            with page.expect_response(
                lambda r: r.url.endswith("/login") and r.request.method == "POST"
            ) as login:
                page.locator('button[form="login-form"]').click()
            check(
                login.value.status in (200, 201, 204),
                "Real webadmin login succeeds over HTTPS",
            )
            page.wait_for_url(lambda url: "#/login" not in str(url))
            cookies = context.cookies()
            auth = [c for c in cookies if c["name"] == "yunohost.admin"]
            REDACT.extend(c["value"] for c in auth)
            check(
                bool(auth) and all(c["secure"] and c["httpOnly"] for c in auth),
                "Admin session cookie is Secure and HttpOnly",
            )
            dns_url = BASE + "#/domains/" + domain + "/dns"
            push_path = "/domains/" + domain + "/dns/push"
            previews = []

            def on_response(response):
                if (
                    urlsplit(response.url).path.endswith(push_path)
                    and "dry_run" in response.url
                ):
                    try:
                        previews.append(
                            {"status": response.status, "body": response.json()}
                        )
                    except Exception:
                        previews.append({"status": response.status, "body": {}})

            page.on("response", on_response)

            def is_preview(response):
                return (
                    urlsplit(response.url).path.endswith(push_path)
                    and "dry_run" in response.url
                )

            with page.expect_response(is_preview, timeout=180000):
                page.goto(dns_url, wait_until="domcontentloaded")
            field = page.locator("#auth_token")
            auto = page.locator("#use_auto_dns")
            auto.wait_for(state="attached")
            if not auto.is_checked():
                auto.check()
            expect(field).to_be_visible()
            check(
                field.get_attribute("type") == "password",
                "Le Bureau token input is masked",
            )
            body = page.locator("body").inner_text()
            check(
                "Le Bureau" in body and "algorithm:key_name:base64_secret" in body,
                "Le Bureau label and TSIG format help render",
            )

            def save_form():
                with page.expect_response(is_preview, timeout=180000) as refreshed:
                    with page.expect_response(
                        lambda r: "/config/dns" in r.url and r.request.method == "PUT",
                        timeout=180000,
                    ) as saved:
                        page.locator('button[form="panel-dns"][type="submit"]').click()
                check(
                    saved.value.status in (200, 201, 204),
                    "Webadmin credential form saves successfully",
                )
                return refreshed.value

            def save_token(value):
                field.fill(value)
                return save_form()

            bad = save_token("invalid-lebureau-token")
            bad_text = bad.text()
            REPORT["invalid_token_response"] = {
                "status": bad.status,
                "content_type": bad.headers.get("content-type"),
                "body": safe(bad_text),
            }
            try:
                bad_data = json.loads(bad_text)
            except ValueError:
                bad_data = {"error": bad_text}
            check(
                bad.status in (400, 500)
                and (
                    bad_data.get("error_key") == "domain_dns_push_failed_to_list"
                    or "Failed to list" in bad_data.get("error", "")
                ),
                "Malformed token fails listing before writes",
                fatal=False,
            )
            expect(field).to_be_visible()
            # Wait for response handling, then assess visible guidance separately
            # from successful API error classification.
            page.wait_for_timeout(500)
            error_text = bad_data.get("error", "")
            visible = page.locator("body").inner_text()
            check(
                bool(error_text) and error_text in visible,
                "Listing failure message is visible in webadmin",
                fatal=False,
            )
            dialog = page.get_by_role("dialog").filter(
                has=page.get_by_role("button", name="OK", exact=True)
            )
            if dialog.is_visible():
                dialog.get_by_role("button", name="OK", exact=True).click()
                expect(dialog).not_to_be_visible()
            check(
                not page.get_by_text(
                    "Automatic configuration seems to be OK!", exact=True
                ).is_visible(),
                "Failed preview does not report automatic DNS as healthy",
                fatal=False,
            )
            check(
                any(
                    error_text in text
                    for text in page.locator(".panel-section").all_inner_texts()
                ),
                "Listing failure remains visible in the DNS panel after dismissing the modal",
                fatal=False,
            )
            check(
                field.is_editable(), "Credential stays editable after listing failure"
            )
            save_token(token)
            with page.expect_response(
                lambda r: urlsplit(r.url).path.endswith(push_path)
                and "dry_run" in r.url,
                timeout=180000,
            ) as plan_response:
                page.reload(wait_until="domcontentloaded")
            check(
                plan_response.value.status in (200, 201),
                "Corrected token produces a real DNS preview",
            )
            plan = plan_response.value.json()
            scope(plan, domain)
            check(
                bool(plan["create"]) and not plan["update"] and not plan["delete"],
                "Fresh namespace preview contains only creates",
            )
            check(
                fixture("inspect")["token_matches"],
                "Saved token survives reload without corruption",
            )
            if child:
                child_page = context.new_page()
                child_page.on(
                    "pageerror", lambda error: page_errors.append(safe(error))
                )
                child_path = "/domains/" + child + "/dns/push"
                with child_page.expect_response(
                    lambda r: urlsplit(r.url).path.endswith(child_path), timeout=180000
                ) as child_preview:
                    child_page.goto(BASE + "#/domains/" + child + "/dns")
                child_error = child_preview.value.json()
                check(
                    child_preview.value.status == 400
                    and child_error.get("error_key")
                    == "domain_dns_push_managed_in_parent_domain",
                    "Installed same-zone child directs DNS management to its parent",
                )
                check(
                    child_error.get("parent_domain") == domain,
                    "Child preview identifies the correct managing parent",
                )
                expect(
                    child_page.get_by_role("link", name=domain, exact=True).first
                ).to_be_visible()
                check(
                    child_page.locator("#auth_token").count() == 0,
                    "Same-zone child does not expose separate registrar credentials",
                )
                child_page.close()
            expect(field).to_have_attribute("type", "password")
            check(
                token not in page.locator("body").inner_text(),
                "Token does not appear in visible page text",
            )
            # No HAR, tracing, DOM dump, or authenticated screenshots: those may
            # contain credentials even when the input is visually masked.
            push = page.get_by_role(
                "button", name="Push DNS records to registrar", exact=True
            )
            expect(push).to_be_visible()
            with page.expect_response(
                lambda r: urlsplit(r.url).path.endswith(push_path)
                and "dry_run" not in r.url,
                timeout=180000,
            ) as pushed:
                push.click()
            result = pushed.value.json()
            check(
                pushed.value.status in (200, 201)
                and not result.get("errors")
                and not result.get("warnings"),
                "Browser applies DNS changes without errors",
            )
            expect(
                page.get_by_text("Automatic configuration seems to be OK!", exact=True)
            ).to_be_visible(timeout=180000)
            check(
                fixture("inspect")["hash_count"] > 0,
                "Browser push persists record ownership",
            )
            with page.expect_response(
                lambda r: urlsplit(r.url).path.endswith(push_path)
                and "dry_run" in r.url,
                timeout=180000,
            ) as converged:
                page.reload(wait_until="domcontentloaded")
            final_plan = converged.value.json()
            scope(final_plan, domain)
            check(
                not any(final_plan[k] for k in ("create", "update", "delete")),
                "Browser refresh produces a no-op preview",
            )
            auto.uncheck()
            save_form()
            cleared = fixture("inspect")
            check(
                not cleared["token_present"] and cleared["hash_count"] == 0,
                "Disabling automatic DNS in webadmin clears credentials and ownership",
            )
            auto.check()
            restored = save_token(token)
            check(
                restored.status in (200, 201) and fixture("inspect")["token_matches"],
                "Automatic DNS can be re-enabled through webadmin",
            )
            check(
                fixture("inspect")["hash_count"] == 0,
                "Re-enabling and previewing do not adopt existing records",
            )
            check(not page_errors, "Browser has no uncaught JavaScript errors")
            REPORT["page_errors"] = page_errors
            REPORT["assets"] = page.locator("script[src]").evaluate_all(
                "nodes => nodes.map(n => n.src)"
            )
            context.close()
            browser.close()
    except BaseException as error:
        REPORT["acceptance_error"] = safe(str(error))[:2000]
        raise
    finally:
        try:
            REPORT["cleanup"] = fixture("cleanup")
        except Exception as error:
            REPORT["cleanup"] = {"cleanup_passed": False, "error": safe(str(error))}
            if "acceptance_error" not in REPORT:
                raise


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        REPORT["error"] = safe(str(error))[:2000]
    REPORT["passed"] = not REPORT["issues"] and "error" not in REPORT
    REPORT["finished"] = datetime.now(timezone.utc).isoformat()
    cfg.save_report("browser", REPORT)
    raise SystemExit(0 if REPORT["passed"] else 1)

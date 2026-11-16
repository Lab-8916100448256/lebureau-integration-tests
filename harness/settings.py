"""Runtime configuration shared by the runner and scenarios."""

import os
from pathlib import Path
import subprocess
import json
from urllib.parse import quote, quote_plus

REPO = Path(__file__).resolve().parents[1]
OUTPUT = Path(os.environ.get("HARNESS_OUTPUT", REPO / ".results"))
CONTAINER = os.environ.get("HARNESS_CONTAINER", "")
CONTAINER_REPO = os.environ.get("HARNESS_CONTAINER_REPO", "")
BASE = os.environ.get("HARNESS_BASE_URL", "")
ZONE = os.environ.get("HARNESS_ZONE", "example.org")
CREDENTIAL_FILE = Path(os.environ.get("HARNESS_CREDENTIAL_FILE", "/nonexistent"))
PRIVATE_STATE = "/root/lebureau-integration-tests/fixture.json"
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(REPO / ".browsers"))
REDACT = []


def hide(*values):
    for value in values:
        if value:
            REDACT.extend(
                {value, quote(value), quote(value, safe=""), quote_plus(value)}
            )


def safe(value):
    value = str(value)
    for secret in sorted(set(REDACT), key=len, reverse=True):
        value = value.replace(secret, "[REDACTED]")
    return value


def container_command(*args, data=None, timeout=600):
    result = subprocess.run(
        [
            "incus",
            "exec",
            CONTAINER,
            "--env",
            "PYTHONPATH=" + CONTAINER_REPO,
            "--env",
            "HARNESS_ZONE=" + ZONE,
            "--env",
            "HARNESS_RUN_ID=" + os.environ.get("HARNESS_RUN_ID", ""),
            "--",
            *args,
        ],
        input=data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        # Only the fixture's structured diagnostic is eligible for display;
        # raw exports, tracebacks and subprocess output are never forwarded.
        detail = ""
        try:
            detail = json.loads(result.stderr).get("message", "")
        except (ValueError, AttributeError):
            pass
        raise RuntimeError(
            safe(
                "Container command failed: "
                + args[0]
                + " (exit "
                + str(result.returncode)
                + "). "
                + detail
            )
        )
    return result.stdout


def fixture(action, data=None):
    result = container_command("python3", "-m", "harness.fixture", action, data=data)
    return json.loads(result)


def read_credentials():
    from .credentials import parse_credentials

    text = CREDENTIAL_FILE.read_text()
    credentials = parse_credentials(text)
    if credentials.zone != ZONE:
        raise ValueError("Credential domain differs from configured domain")
    hide(credentials.token, credentials.secret, credentials.zone)
    return text


def save_report(name, report):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    path = OUTPUT / (name + ".json")
    path.write_text(safe(json.dumps(report, indent=2)) + "\n")
    return path

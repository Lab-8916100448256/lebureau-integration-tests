"""Configuration, redaction and fixture ownership boundaries."""

import base64
import json
from urllib.parse import quote, quote_plus

import pytest

from harness import fixture, settings
from harness.credentials import parse_credentials


def key_file(zone="example.org", secret=None):
    secret = secret or base64.b64encode(b"public fixture key").decode()
    return f"TSIG credentials for domain {zone}\nKey name Algorithm Secret\nfixture-key hmac-sha512 {secret}\n"


def test_download_format_is_read_without_rewriting():
    credential = parse_credentials(key_file("EXAMPLE.ORG."))
    assert credential.zone == "example.org"
    assert credential.token.startswith("hmac-sha512:fixture-key:")
    assert credential.secret not in repr(credential)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "one\ntwo",
        key_file("../elsewhere"),
        key_file("example.org", "invalid-private-input"),
        key_file() + "extra\n",
    ],
)
def test_bad_key_files_fail_without_echoing_input(text):
    with pytest.raises(ValueError) as error:
        parse_credentials(text)
    assert "invalid-private-input" not in str(error.value)


def test_redaction_handles_encoding_and_private_domain(monkeypatch):
    monkeypatch.setattr(settings, "REDACT", [])
    token = "hmac-sha512:test-key:ab+/="
    settings.hide(token, "example.org")
    for value in (token, quote(token), quote(token, safe=""), quote_plus(token)):
        assert settings.safe(value) == "[REDACTED]"
    assert "example.org" not in settings.safe("child.example.org")


def test_exclusive_state_claim_cannot_overwrite_another_run(tmp_path, monkeypatch):
    path = tmp_path / "fixture.json"
    monkeypatch.setattr(fixture, "STATE", path)
    fixture.save({"run_id": "first"}, exclusive=True)
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        fixture.save({"run_id": "second"}, exclusive=True)
    assert json.loads(path.read_text()) == {"run_id": "first"}


def test_cleanup_cannot_remove_another_runs_fixture(tmp_path, monkeypatch):
    path = tmp_path / "fixture.json"
    monkeypatch.setattr(fixture, "STATE", path)
    path.write_text(json.dumps({"run_id": "other"}))
    monkeypatch.setenv("HARNESS_RUN_ID", "current")
    with pytest.raises(RuntimeError, match="different run"):
        fixture.cleanup()
    assert path.exists()

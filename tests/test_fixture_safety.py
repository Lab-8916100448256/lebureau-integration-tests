"""Recovery must never remove a non-fixture account/domain or lose baseline DNS."""

import json
from unittest.mock import Mock

import pytest

from harness import fixture


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "state.json"
    monkeypatch.setattr(fixture, "STATE", path)
    return path


@pytest.mark.parametrize(
    "domain, username",
    [
        ("example.org", "lbtest0123456789ab"),
        (
            "ynh-lebureau-0123456789abcdef.example.org.attacker.test",
            "lbtest0123456789ab",
        ),
        ("ynh-lebureau-0123456789abcdef.example.org", "existingadmin"),
        ("ynh-lebureau-0123456789abcdef.example.org", "lbtest../existing"),
    ],
)
def test_cleanup_rejects_non_fixture_targets_before_commands(
    state_file, monkeypatch, domain, username
):
    state_file.write_text(
        json.dumps({"domain": domain, "username": username, "zone": "example.org"})
    )
    command = Mock()
    backend = Mock()
    monkeypatch.setattr(fixture, "command", command)
    monkeypatch.setattr(fixture, "provider", backend)
    with pytest.raises(RuntimeError, match="Unexpected fixture"):
        fixture.cleanup()
    command.assert_not_called()
    backend.assert_not_called()
    assert state_file.exists()


def test_baseline_loss_retains_recovery_state_and_installed_objects(
    state_file, monkeypatch
):
    state_file.write_text(
        json.dumps(
            {
                "zone": "example.org",
                "domain": "ynh-lebureau-0123456789abcdef.example.org",
                "username": "lbtest0123456789ab",
                "baseline": [
                    {
                        "name": "example.org",
                        "type": "TXT",
                        "content": "original",
                        "ttl": 3600,
                    }
                ],
            }
        )
    )
    command = Mock(return_value="")
    backend = Mock()
    backend.list_records.return_value = []
    monkeypatch.setattr(fixture, "command", command)
    monkeypatch.setattr(fixture, "provider", lambda state: backend)
    with pytest.raises(RuntimeError, match="Baseline DNS records missing"):
        fixture.cleanup()
    backend.delete_record.assert_not_called()
    assert command.call_count == 1
    assert command.call_args.args[-1] == "pass"  # Only acquire/release the CLI lock.
    assert state_file.exists()


def test_existing_fixture_cannot_be_overwritten(state_file):
    state_file.write_text("recovery data")
    with pytest.raises(RuntimeError, match="Previous browser fixture"):
        fixture.prepare()
    assert state_file.read_text() == "recovery data"


def test_cleanup_rejects_unrelated_child_before_commands(state_file, monkeypatch):
    state_file.write_text(
        json.dumps(
            {
                "zone": "example.org",
                "domain": "ynh-lebureau-0123456789abcdef.example.org",
                "username": "lbtest0123456789ab",
                "installed_children": ["existing.example.org"],
            }
        )
    )
    command = Mock()
    monkeypatch.setattr(fixture, "command", command)
    with pytest.raises(RuntimeError, match="Unexpected fixture child"):
        fixture.cleanup()
    command.assert_not_called()


def test_fixture_certificate_link_cleanup_retains_history(tmp_path):
    name = "ynh-lebureau-0123456789abcdef.example.org"
    history = tmp_path / (name + "-history") / "selfsigned"
    history.mkdir(parents=True)
    (history / "key.pem").write_text("fake test key")
    link = tmp_path / name
    link.symlink_to(history)
    fixture.remove_certificate_links({"domain": name}, tmp_path)
    assert not link.is_symlink()
    assert (history / "key.pem").read_text() == "fake test key"


def test_fixture_certificate_link_cleanup_rejects_foreign_target(tmp_path):
    name = "ynh-lebureau-0123456789abcdef.example.org"
    unrelated = tmp_path / "existing-domain"
    unrelated.mkdir()
    link = tmp_path / name
    link.symlink_to(unrelated)
    with pytest.raises(RuntimeError, match="Unexpected fixture certificate"):
        fixture.remove_certificate_links({"domain": name}, tmp_path)
    assert link.is_symlink() and unrelated.is_dir()

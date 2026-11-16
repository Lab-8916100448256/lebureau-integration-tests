"""Actual YunoHost -> Lexicon -> signed DNS wire integration, no sockets."""

import copy
from pathlib import Path

import dns.query
import dns.rcode
import dns.zone
import pytest
import tldextract
from lexicon.client import Client
from lexicon.config import ConfigResolver

from test_dns_push import push, record  # noqa: E402,F401
from dns_wire_fixture import DNSServer, MemorySocket, TOKEN, ZONE  # noqa: E402


@pytest.fixture
def wire(request, monkeypatch, tmp_path):
    import lexicon.client

    state = request.getfixturevalue("push")
    server = DNSServer()
    monkeypatch.setattr(
        dns.query, "socket_factory", lambda *args: MemorySocket(server, *args)
    )
    monkeypatch.setattr(lexicon.client, "Client", Client)
    # Debian omits tldextract's bundled snapshot. Use explicit fixture suffixes
    # through the real parser, without relying on a package cache or the network.
    suffixes = tmp_path / "public_suffix_list.dat"
    suffixes.write_text("com\norg\nnet\ncoop\n")
    extractor = tldextract.TLDExtract(
        suffix_list_urls=(suffixes.as_uri(),),
        cache_dir=None,
        fallback_to_snapshot=False,
    )
    monkeypatch.setattr(tldextract, "TLDExtract", lambda **_: extractor)
    monkeypatch.setattr(tldextract, "extract", extractor)
    state.domain = state.zone = "example.com"
    state.credentials = {
        "auth_token": TOKEN,
        "ddns_server": "127.0.0.1",
        "ddns_port": 5353,
    }
    state.server = server
    return state


@pytest.fixture
def failure_namespace(wire, monkeypatch):
    from yunohost import dns as ydns

    wire.domain = "ynh.example.com"

    def build(_):
        rows = copy.deepcopy(wire.wanted)
        for row in rows:
            row["name"] = "ynh" if row["name"] == "@" else row["name"] + ".ynh"
        return {"basic": rows}

    monkeypatch.setattr(ydns, "_build_dns_conf", build)


@pytest.mark.parametrize("zone", ["example.com", "delegated.example.com"])
def test_full_push_roundtrip(wire, zone):
    wire.domain = wire.zone = zone
    wire.server.zone = dns.zone.from_text(ZONE, origin=zone + ".", relativize=False)
    baseline = copy.deepcopy(wire.server.zone)
    wire.wanted = [
        record("A", "192.0.2.1", ttl=120),
        record("AAAA", "2001:db8::1"),
        record("MX", f"10 mail.{zone}."),
        record("TXT", '"v=spf1 -all"'),
        record("TXT", '"v=DKIM1; p=' + "a" * 800 + '"', "mail._domainkey"),
        record("CNAME", "@", "www"),
        record("SRV", f"10 5 443 service.{zone}.", "_service._tcp"),
        record("CAA", '0 issue "letsencrypt.org"'),
    ]
    wire.run(dry_run=True)
    assert wire.server.writes == 0
    assert wire.run() == {}
    assert wire.server.writes == len(wire.wanted)
    assert wire.server.zone.get_rdataset(zone + ".", "A").ttl == 120
    assert not any(wire.run(dry_run=True)[a] for a in ("create", "update"))
    writes = wire.server.writes
    assert wire.run() == {}
    assert wire.server.writes == writes
    wire.wanted[0]["content"] = "192.0.2.2"
    wire.wanted[2]["content"] = f"0 mail.{zone}."
    assert wire.run() == {}
    assert wire.server.writes == writes + 2
    assert wire.server.zone.get_rdataset(zone + ".", "A").ttl == 120
    assert not wire.run(dry_run=True)["update"]
    wire.wanted = []
    assert wire.run() == {}
    assert wire.hashes == []
    # The protected authority and pre-existing ns address remain unchanged.
    for owner, dataset in baseline.iterate_rdatasets():
        if dataset.rdtype != dns.rdatatype.SOA:
            assert wire.server.zone.get_rdataset(owner, dataset.rdtype) == dataset
    remaining = list(wire.server.zone.iterate_rdatasets())
    assert len(remaining) == len(list(baseline.iterate_rdatasets()))


def test_invalid_token_is_sanitized(wire):
    from yunohost.utils.error import YunohostError

    wire.credentials["auth_token"] = "recognizable-secret-invalid-token"
    with pytest.raises(YunohostError) as error:
        wire.run()
    assert error.value.key == "domain_dns_push_failed_to_list"
    assert wire.credentials["auth_token"] not in str(error.value)
    assert wire.server.writes == 0


def test_refused_transfer_stops_push(wire):
    from yunohost.utils.error import YunohostError

    wire.server.rcode = dns.rcode.REFUSED
    with pytest.raises(YunohostError):
        wire.run()
    assert wire.server.writes == 0


@pytest.mark.parametrize(
    "fault",
    [
        "unsigned",
        "corrupt",
        "truncate",
        "wrong-key",
        "timeout",
        "unreachable",
        "unsupported-algorithm",
        "endpoint-resolution",
    ],
)
@pytest.mark.usefixtures("failure_namespace")
def test_transfer_failures_preserve_state_and_hide_credentials(
    wire, monkeypatch, fault
):
    from yunohost.utils.error import YunohostError

    wire.wanted = [record("A", "192.0.2.1", "managed")]
    wire.run()
    hashes, zone, writes = (
        wire.hashes[:],
        copy.deepcopy(wire.server.zone),
        wire.server.writes,
    )
    wire.wanted[0]["content"] = "192.0.2.2"
    if fault in ("unsigned", "corrupt", "truncate"):
        setattr(wire.server, fault, True)
    elif fault == "wrong-key":
        import base64

        wire.credentials["auth_token"] = (
            "hmac-sha512:test-key:"
            + base64.b64encode(b"different-private-fixture-secret").decode()
        )
    elif fault == "unsupported-algorithm":
        wire.credentials["auth_token"] = wire.credentials["auth_token"].replace(
            "hmac-sha512", "unsupported-tsig"
        )
    elif fault == "endpoint-resolution":
        wire.credentials.pop("ddns_server")

        def failed_resolution(*args, **kwargs):
            raise dns.exception.Timeout()

        monkeypatch.setattr(dns.resolver, "resolve", failed_resolution)
    else:

        def failed_socket(*args):
            raise (
                dns.exception.Timeout()
                if fault == "timeout"
                else ConnectionRefusedError("fixture endpoint unavailable")
            )

        monkeypatch.setattr(dns.query, "socket_factory", failed_socket)
    with pytest.raises(YunohostError) as failure:
        wire.run()
    assert failure.value.key == "domain_dns_push_failed_to_list"
    assert wire.credentials["auth_token"] not in str(failure.value)
    assert wire.credentials["auth_token"].split(":", 2)[2] not in str(failure.value)
    assert wire.hashes == hashes and wire.server.zone == zone
    assert wire.server.writes == writes


@pytest.mark.parametrize("action", ["create", "update", "delete"])
@pytest.mark.usefixtures("failure_namespace")
def test_refused_updates_preserve_ownership_and_allow_explicit_recovery(wire, action):
    wire.wanted = [record("TXT", '"old value"', "managed")]
    if action != "create":
        wire.run()
    hashes, zone, writes = (
        wire.hashes[:],
        copy.deepcopy(wire.server.zone),
        wire.server.writes,
    )
    if action == "update":
        wire.wanted[0]["content"] = '"new value"'
    elif action == "delete":
        wire.wanted = []
    wire.server.update_rcode = dns.rcode.REFUSED
    result = wire.run()
    assert len(result["errors"]) == 1 and "REFUSED" in result["errors"][0]
    assert TOKEN not in str(result) and TOKEN.split(":", 2)[2] not in str(result)
    assert wire.server.writes == writes + 1  # No automatic retry.
    assert wire.hashes == hashes and wire.server.zone == zone
    wire.server.update_rcode = dns.rcode.NOERROR
    assert wire.run() == {}  # Explicit retry after a confirmed refusal.
    assert not any(wire.run(dry_run=True)[k] for k in ("create", "update", "delete"))


@pytest.mark.usefixtures("failure_namespace")
@pytest.mark.parametrize("failed_position", [1, 2])
def test_partial_failure_retains_failed_and_unchanged_siblings(wire, failed_position):
    from yunohost import dns as ydns

    wire.wanted = [
        record("TXT", '"first old"', "managed"),
        record("TXT", '"second old"', "managed"),
        record("TXT", '"unchanged"', "managed"),
    ]
    wire.run()
    old_hashes = wire.hashes[:]
    wire.wanted[0]["content"] = '"first new"'
    wire.wanted[1]["content"] = '"second new"'
    wire.server.update_rcodes[wire.server.writes + failed_position] = dns.rcode.REFUSED
    assert len(wire.run()["errors"]) == 1
    plan = wire.run(dry_run=True)
    assert len(plan["update"]) == 1 and plan["update"][0]["managed_by_yunohost"]
    assert len(plan["unchanged"]) == 2
    assert len(wire.hashes) == len(old_hashes) == 3
    assert (
        ydns._hash_dns_record(
            {
                "name": "managed.ynh.example.com",
                "type": "TXT",
                "content": '"second new"' if failed_position == 1 else '"first new"',
            }
        )
        in wire.hashes
    )
    assert wire.run() == {}
    assert not wire.run(dry_run=True)["update"]


@pytest.mark.parametrize("action", ["create", "update", "delete"])
@pytest.mark.parametrize("reply_fault", ["timeout", "unsigned", "corrupt"])
@pytest.mark.usefixtures("failure_namespace")
def test_lost_update_reply_is_uncertain_and_never_retried_automatically(
    wire, action, reply_fault
):
    wire.wanted = [record("TXT", '"old value"', "managed")]
    if action != "create":
        wire.run()
    old_hashes, writes = wire.hashes[:], wire.server.writes
    if action == "update":
        wire.wanted[0]["content"] = '"new value"'
    elif action == "delete":
        wire.wanted = []
    if reply_fault == "timeout":
        wire.server.lost_reply_updates.add(writes + 1)
    else:
        setattr(wire.server, "update_" + reply_fault, True)
    result = wire.run()
    assert len(result["errors"]) == 1
    assert (
        "reply was lost" in result["errors"][0]
        or "unsigned update response" in result["errors"][0]
    )
    assert TOKEN not in str(result) and TOKEN.split(":", 2)[2] not in str(result)
    assert wire.server.writes == writes + 1
    assert wire.hashes == old_hashes  # An unacknowledged write cannot claim ownership.
    plan = wire.run(dry_run=True)  # Reconcile from a fresh signed transfer.
    assert not any(plan[k] for k in ("create", "update", "delete"))
    assert wire.server.writes == writes + 1 and wire.hashes == old_hashes
    if action != "delete":
        assert all(not r["managed_by_yunohost"] for r in plan["unchanged"])
        wire.run(force=True)  # Explicit reviewed adoption, with no DNS write.
        assert wire.hashes and wire.server.writes == writes + 1
    else:
        wire.run()  # Confirmed absence removes stale ownership without a write.
        assert not wire.hashes and wire.server.writes == writes + 1


@pytest.mark.usefixtures("failure_namespace")
def test_delayed_readback_previews_do_not_repeat_successful_writes(wire):
    wire.wanted = [record("A", "192.0.2.1", "managed")]
    stale = copy.deepcopy(wire.server.zone)
    wire.run()
    hashes, writes = wire.hashes[:], wire.server.writes
    wire.server.axfr_zone = stale
    for _ in range(2):
        assert len(wire.run(dry_run=True)["create"]) == 1
        assert wire.server.writes == writes and wire.hashes == hashes
    wire.server.axfr_zone = None
    assert not any(wire.run(dry_run=True)[k] for k in ("create", "update", "delete"))
    assert wire.run() == {} and wire.server.writes == writes
    assert wire.hashes == hashes


def test_mx_siblings_keep_ids_and_ownership(wire):
    wire.wanted = [
        record("MX", "10 mail.example.com."),
        record("MX", "20 mail.example.com."),
    ]
    assert wire.run() == {}
    wire.wanted[0]["content"] = "0 mail.example.com."
    assert wire.run() == {}
    preview = wire.run(dry_run=True)
    assert len([r for r in preview["unchanged"] if r["type"] == "MX"]) == 2
    assert len(wire.hashes) == 2
    wire.wanted.pop()
    assert wire.run() == {}
    assert len(wire.hashes) == 1
    wire.wanted = []
    assert wire.run() == {}
    assert not wire.hashes


def test_standalone_subdomain_preserves_parent(wire):
    wire.domain = "ynh.example.com"
    wire.wanted = [record("A", "192.0.2.42", "ynh")]
    baseline = copy.deepcopy(wire.server.zone)
    assert wire.run(force=True) == {}
    assert wire.server.writes == 1
    assert not wire.run(dry_run=True)["update"]
    wire.wanted = []
    assert wire.run() == {}
    for owner, dataset in baseline.iterate_rdatasets():
        if dataset.rdtype != dns.rdatatype.SOA:
            assert wire.server.zone.get_rdataset(owner, dataset.rdtype) == dataset


def test_force_changes_unmanaged_txt_without_touching_parent_or_desired_sibling(wire):
    wire.domain = "ynh.example.com"
    wire.server.zone.replace_rdataset(
        "_force.ynh.example.com.",
        dns.rdataset.from_text(
            "IN", "TXT", 3600, '"old force value"', '"keep force value"'
        ),
    )
    wire.server.zone.replace_rdataset(
        "_orphan.ynh.example.com.",
        dns.rdataset.from_text("IN", "TXT", 3600, '"orphan"'),
    )
    baseline = copy.deepcopy(wire.server.zone)
    wire.wanted = [
        record("TXT", '"new force value"', "_force.ynh"),
        record("TXT", '"keep force value"', "_force.ynh"),
    ]
    preview = wire.run(dry_run=True, force=True)
    assert len(preview["update"]) == len(preview["delete"]) == 1
    assert not wire.hashes and wire.server.writes == 0
    assert wire.run() == {}
    assert not wire.hashes and wire.server.writes == 0
    assert wire.server.zone == baseline
    assert wire.run(force=True) == {}
    assert wire.server.writes == 2
    assert len(wire.hashes) == 2
    records = wire.server.zone.get_rdataset("_force.ynh.example.com.", "TXT")
    assert {r.to_text() for r in records} == {'"new force value"', '"keep force value"'}
    assert wire.server.zone.get_rdataset("_orphan.ynh.example.com.", "TXT") is None
    for owner, dataset in baseline.iterate_rdatasets():
        if (
            not str(owner).endswith(".ynh.example.com.")
            and dataset.rdtype != dns.rdatatype.SOA
        ):
            assert wire.server.zone.get_rdataset(owner, dataset.rdtype) == dataset


def test_write_timeout_is_not_retried_and_keeps_old_ownership(wire, monkeypatch):
    wire.wanted = [record("A", "192.0.2.1")]
    wire.run()
    old_hashes = wire.hashes[:]
    wire.wanted[0]["content"] = "192.0.2.2"
    attempts = []

    def timed_out(*args, **kwargs):
        attempts.append(args)
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.query, "tcp", timed_out)
    assert wire.run()["errors"]
    assert len(attempts) == 1
    assert wire.hashes == old_hashes


def test_discovery_and_metadata(wire, monkeypatch):
    from lexicon._private.providers import auto
    from yunohost import dns as ydns

    monkeypatch.setattr(
        auto, "_get_ns_records_for_domain", lambda _: ["ns1.lebureau.coop."]
    )
    monkeypatch.setattr(ydns, "_get_parent_domain_of", lambda *a, **k: None)
    monkeypatch.setattr(
        ydns,
        "DOMAIN_REGISTRAR_LIST_PATH",
        str(Path(ydns.__file__).resolve().parents[1] / "share/registrar_list.toml"),
    )
    config = ydns._get_registrar_config_section(wire.domain)
    assert config["registrar"]["default"] == "lebureau"
    assert config["auth_token"]["type"] == "password"
    assert "ddns_server" not in config
    assert "experimental_disclaimer" in config
    monkeypatch.setattr(auto, "_get_ns_records_for_domain", lambda _: ["ns1.ovh.net."])
    assert (
        ydns._get_registrar_config_section(wire.domain)["registrar"]["default"] == "ovh"
    )
    monkeypatch.setattr(
        auto, "_get_ns_records_for_domain", lambda _: ["ns1.unknown.example.org."]
    )
    unsupported = ydns._get_registrar_config_section(wire.domain)
    assert unsupported["registrar"]["default"] is None
    assert unsupported["infos"]["style"] == "warning"
    assert "auth_token" not in unsupported


def test_default_endpoint_needs_only_token(wire):
    from lexicon._private.providers.lebureau import Provider

    provider = Provider(
        ConfigResolver().with_dict(
            {
                "provider_name": "lebureau",
                "domain": wire.zone,
                "lebureau": {"auth_token": TOKEN},
            }
        )
    )
    assert provider.server == "ns2.lebureau.coop"
    assert provider.port == 53

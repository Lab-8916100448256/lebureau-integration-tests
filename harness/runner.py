"""One entry point for preparation, diagnostics, regression and live acceptance."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[1]


def incus(container, *args, data=None, timeout=900):
    result = subprocess.run(
        ["incus", "exec", container, "--", *args],
        input=data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(
            f"Container command failed ({args[0]}, exit {result.returncode})"
        )
    return result.stdout


def environment(args, output):
    dev = args.ynh_dev.resolve()
    relative = REPO.relative_to(dev)
    if not (dev / "ynh-dev").is_file():
        raise ValueError("--ynh-dev must identify the existing ynh-dev checkout")
    container_repo = args.container_root.rstrip("/") + "/" + str(relative)
    incus(args.container, "test", "-f", container_repo + "/harness/fixture.py")
    if args.command == "cleanup":
        base = "https://127.0.0.1/yunohost/admin/"
    elif args.webadmin_url:
        base = args.webadmin_url.rstrip("/") + "/"
        from urllib.parse import urlsplit

        parsed = urlsplit(base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "--webadmin-url must be an HTTPS webadmin URL without credentials, query or fragment"
            )
    else:
        info = json.loads(
            subprocess.check_output(
                ["incus", "list", args.container, "--format=json"], text=True
            )
        )
        instance = next(i for i in info if i["name"] == args.container)
        addresses = [
            a["address"]
            for n in instance["state"]["network"].values()
            for a in n.get("addresses", [])
            if a["family"] == "inet" and a.get("scope") == "global"
        ]
        if not addresses:
            raise ValueError("No container IPv4 address; supply --webadmin-url")
        base = f"https://{addresses[0]}/yunohost/admin/"
    values = dict(
        HARNESS_CONTAINER=args.container,
        HARNESS_CONTAINER_REPO=container_repo,
        HARNESS_BASE_URL=base,
        HARNESS_OUTPUT=str(output),
        HARNESS_RUN_ID=uuid.uuid4().hex,
        HARNESS_INSTALLED_CHILD="1",
    )
    if args.command == "cleanup":
        values["HARNESS_RUN_ID"] = ""
    if args.credentials_file:
        from .credentials import parse_credentials

        credential = parse_credentials(args.credentials_file.read_text())
        values.update(
            HARNESS_ZONE=credential.zone,
            HARNESS_CREDENTIAL_FILE=str(args.credentials_file.resolve()),
        )
    os.environ.update(values)
    os.environ["PYTHONPATH"] = str(REPO)
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(REPO / ".browsers")
    os.environ["PIP_CACHE_DIR"] = str(REPO / ".cache/pip")
    # Playwright debugging can log typed credentials or pause unattended runs.
    os.environ.pop("DEBUG", None)
    os.environ.pop("PWDEBUG", None)
    return container_repo


def doctor(args, container_repo):
    code = """import hashlib,importlib.metadata,json,subprocess
from pathlib import Path
import yunohost,moulinette,lexicon,pytest,requests,yaml
from lexicon._private.providers import lebureau
from lexicon.client import Client
assert Path('/etc/yunohost/installed').is_file(), 'Postinstall is incomplete'
for service in ('yunohost-api','nginx','slapd'):
    subprocess.run(['systemctl','is-active','--quiet',service],check=True)
assert all(hasattr(Client, name) for name in ('__enter__','__exit__'))
provider=Path(lebureau.__file__).resolve()
dns=Path(yunohost.__file__).resolve().with_name('dns.py')
index=Path('/usr/share/yunohost/admin/index.html')
assert index.is_file(), 'Build or install webadmin first'
print(json.dumps({'python':__import__('sys').version.split()[0],
 'lexicon':importlib.metadata.version('dns-lexicon'),
 'dnspython':importlib.metadata.version('dnspython'),
 'provider_sha256':hashlib.sha256(provider.read_bytes()).hexdigest(),
 'dns_sha256':hashlib.sha256(dns.read_bytes()).hexdigest(),
 'frontend_sha256':hashlib.sha256(index.read_bytes()).hexdigest(),
 'yunohost_import':str(Path(yunohost.__file__).resolve()),
 'moulinette_import':str(Path(moulinette.__file__).resolve()),
 'provider_import':str(provider),
 'packages':subprocess.check_output(['dpkg-query','-W','-f=${Package} ${Version}\\n','yunohost','moulinette','yunohost-admin','python3-lexicon'],text=True).splitlines()}))
"""
    result = json.loads(incus(args.container, "python3", "-c", code))
    revision = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    digest = hashlib.sha256()
    sources = [
        REPO / "run",
        REPO / "requirements-host.txt",
        REPO / "prepare-webadmin.sh",
    ]
    sources += sorted((REPO / "harness").glob("*.py"))
    sources += sorted((REPO / "tests").glob("*.py"))
    for source in sources:
        digest.update(
            str(source.relative_to(REPO)).encode() + b"\0" + source.read_bytes()
        )
    result["harness"] = {
        "commit": revision.stdout.strip() if revision.returncode == 0 else None,
        "dirty": bool(
            subprocess.check_output(["git", "-C", str(REPO), "status", "--porcelain"])
        ),
        "source_sha256": digest.hexdigest(),
    }
    result["checkouts"] = {}
    for name in ("yunohost", "moulinette", "yunohost-admin"):
        source = args.ynh_dev / name
        if (source / ".git").exists():
            result["checkouts"][name] = {
                "commit": subprocess.check_output(
                    ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
                ).strip(),
                "dirty": bool(
                    subprocess.check_output(
                        ["git", "-C", str(source), "status", "--porcelain"]
                    )
                ),
            }
    return result


def prepare(args, container_repo):
    # Existing packages avoid an unnecessary APT refresh. If installation is
    # needed, normal configured repositories/signature verification are used.
    result = subprocess.run(
        [
            "incus",
            "exec",
            args.container,
            "--",
            "python3",
            "-c",
            "import pytest,requests,yaml",
        ],
        capture_output=True,
    )
    if result.returncode:
        incus(args.container, "apt-get", "update")
        incus(
            args.container,
            "apt-get",
            "install",
            "-y",
            "python3-pytest",
            "python3-requests",
            "python3-yaml",
            "python3-pip",
        )
    if args.link_sources:
        incus(
            args.container,
            "bash",
            "-lc",
            f"cd {__import__('shlex').quote(args.container_root)} && ./ynh-dev use-git moulinette yunohost",
        )
    venv = REPO / ".venv"
    if not (venv / "bin/python").exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = str(venv / "bin/python")
    subprocess.run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-r",
            str(REPO / "requirements-host.txt"),
        ],
        check=True,
    )
    subprocess.run(
        [python, "-m", "playwright", "install", "chromium", "--only-shell"], check=True
    )
    if args.lexicon_source:
        wheels = REPO / ".cache/wheels"
        wheels.mkdir(parents=True, exist_ok=True)
        # pip builds the explicitly selected source; no branch is changed.
        subprocess.run(
            [
                python,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheels),
                str(args.lexicon_source.resolve()),
            ],
            check=True,
        )
        wheel = max(wheels.glob("dns_lexicon-*.whl"), key=lambda p: p.stat().st_mtime)
        remote = "/tmp/" + wheel.name
        subprocess.run(
            ["incus", "file", "push", str(wheel), args.container + remote], check=True
        )
        incus(
            args.container,
            "python3",
            "-m",
            "pip",
            "install",
            "--break-system-packages",
            "--ignore-installed",
            "--no-deps",
            remote,
        )
        incus(
            args.container,
            "python3",
            "-m",
            "pip",
            "install",
            "--break-system-packages",
            remote,
        )
    if args.build_webadmin:
        incus(
            args.container,
            "bash",
            container_repo + "/prepare-webadmin.sh",
            args.container_root,
            timeout=1800,
        )
    incus(args.container, "systemctl", "restart", "yunohost-api")
    print("Prepared. Runtime:")
    print(json.dumps(doctor(args, container_repo), indent=2))


def run(args):
    os.umask(0o077)
    run_name = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    output = args.output.resolve() if args.output else REPO / ".results" / run_name
    output.mkdir(parents=True, exist_ok=True)
    container_repo = environment(args, output)
    from . import settings as cfg

    if args.credentials_file:
        cfg.read_credentials()
    if args.command == "prepare":
        prepare(args, container_repo)
        return 0
    if args.command == "cleanup":
        print(json.dumps(cfg.fixture("cleanup"), indent=2))
        return 0
    summary = dict(
        started=datetime.now(timezone.utc).isoformat(), groups=[], passed=False
    )
    try:
        summary["runtime"] = doctor(args, container_repo)
        if args.command == "doctor":
            summary["passed"] = True
            print(json.dumps(summary["runtime"], indent=2))
            return 0
        if args.command == "all":
            if not args.credentials_file:
                raise ValueError(
                    "A full run requires --credentials-file pointing to your downloaded Le Bureau key file"
                )
            active = subprocess.run(
                [
                    "incus",
                    "exec",
                    args.container,
                    "--",
                    "test",
                    "-e",
                    cfg.PRIVATE_STATE,
                ],
                capture_output=True,
            )
            if active.returncode != 1:
                raise RuntimeError(
                    "An unfinished fixture exists; run cleanup before starting another live run"
                )
        groups = ["offline", "browser-faults"]
        if args.command == "all":
            groups += ["live-api", "browser", "force"]
        for group in groups:
            if group == "live-api":
                snapshot = "before-lebureau-tests-" + run_name
                subprocess.run(
                    ["incus", "snapshot", "create", args.container, snapshot],
                    check=True,
                    capture_output=True,
                )
                summary["snapshot"] = snapshot
            print("RUN: " + group, flush=True)
            started = time.monotonic()
            if group == "offline":
                command = [
                    "incus",
                    "exec",
                    args.container,
                    "--env",
                    "PYTHONPATH=" + container_repo,
                    "--",
                    "python3",
                    "-m",
                    "pytest",
                    "--noconftest",
                    "-o",
                    "addopts=",
                    "-o",
                    "cache_dir=/tmp/lebureau-integration-pytest",
                    "-W",
                    "error::DeprecationWarning",
                    "-q",
                    container_repo + "/tests",
                    "--junitxml=/tmp/lebureau-integration-" + run_name + ".xml",
                ]
            else:
                module = {
                    "browser-faults": "browser_faults",
                    "live-api": "live_api",
                }.get(group, group)
                command = [str(REPO / ".venv/bin/python"), "-m", "harness." + module]
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=1800
            )
            if group == "offline":
                remote_xml = "/tmp/lebureau-integration-" + run_name + ".xml"
                subprocess.run(
                    [
                        "incus",
                        "file",
                        "pull",
                        args.container + remote_xml,
                        str(output / "offline.xml"),
                    ],
                    check=True,
                    capture_output=True,
                )
                incus(args.container, "rm", "-f", remote_xml)
            text = cfg.safe(result.stdout + result.stderr)
            (output / (group + ".log")).write_text(text)
            passed = result.returncode == 0
            summary["groups"].append(
                dict(
                    name=group,
                    passed=passed,
                    seconds=round(time.monotonic() - started, 2),
                    mode=(
                        "controlled"
                        if group in ("offline", "browser-faults")
                        else "live"
                    ),
                )
            )
            print(("PASS: " if passed else "FAIL: ") + group, flush=True)
            if not passed:
                raise RuntimeError(
                    group
                    + " failed; see its log. If live cleanup is incomplete, run ./run cleanup --container "
                    + args.container
                )
        summary["passed"] = True
        return 0
    except BaseException as error:
        summary["error"] = cfg.safe(str(error))
        print("FAIL: " + summary["error"], file=sys.stderr)
        return 1
    finally:
        summary["finished"] = datetime.now(timezone.utc).isoformat()
        cfg.save_report("summary", summary)
        print("Report: " + str(output / "summary.json"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=["prepare", "doctor", "all", "offline", "cleanup"]
    )
    parser.add_argument(
        "--container", required=True, help="Explicit development Incus container"
    )
    parser.add_argument("--ynh-dev", type=Path, default=REPO.parent)
    parser.add_argument("--container-root", default="/ynh-dev")
    parser.add_argument("--webadmin-url", help="Override detected HTTPS address")
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--link-sources",
        action="store_true",
        help="prepare: link existing Moulinette/YunoHost checkouts",
    )
    parser.add_argument(
        "--build-webadmin",
        action="store_true",
        help="prepare: build and serve existing frontend checkout",
    )
    parser.add_argument(
        "--lexicon-source",
        type=Path,
        help="prepare: build/install a selected Lexicon source checkout",
    )
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as error:
        # Never forward exceptions from credential parsing with their input.
        print("FAIL: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

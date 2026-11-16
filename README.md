# Le Bureau DNS integration tests for YunoHost

An opt-in test harness for YunoHost's automatic DNS integration with Le Bureau.
It runs backend regression tests, real CLI/API acceptance and Playwright webadmin
tests with one command. This is a separate repository; no modification of
YunoHost's `ynh-dev` repository is required.

Supported environment: a local Incus `ynh-dev` container running YunoHost 13 on
Debian Trixie. Use a development container with the YunoHost, Moulinette and
webadmin revisions you intend to test. The container must already be
postinstalled. A Lexicon installation containing the `lebureau` provider is
required; preparation can build/install an explicitly selected source checkout.

## Install and prepare

Prerequisites on the host: Git, Python 3.11 or later with `venv` and `pip`, and
permission to execute commands through Incus. Installing dependencies and the
matching Chromium headless browser needs internet access. The host must reach
the container's HTTPS webadmin. The container needs outbound DNS/TCP access to
Le Bureau for the live groups.

If network access is restricted, preparation needs PyPI (`pypi.org` and
`files.pythonhosted.org`), Playwright's browser download endpoints and, when
building webadmin, the npm/Yarn registries. Container package installation uses
its configured Debian/YunoHost repositories.

Clone this repository **inside your existing `ynh-dev` directory**:

```bash
cd /path/to/ynh-dev
git clone <test-harness-repository-url> lebureau-integration-tests
cd lebureau-integration-tests
incus list
```

Create/start a development container using your normal `ynh-dev` workflow. If
postinstall has not been performed, run it interactively first:

```bash
incus exec CONTAINER --force-interactive -- yunohost tools postinstall
```

Choose your own development domain, administrator and password at that prompt.
The tests subsequently create their own temporary administrators and do not
need your existing administrator password.

Check out the integration revisions to test in the existing `yunohost`,
`moulinette` and `yunohost-admin` directories. Preparation does not fetch, reset
or switch their branches.

```bash
./run prepare --container CONTAINER --link-sources --build-webadmin
./run doctor --container CONTAINER
```

`--link-sources` uses the existing `ynh-dev use-git` command for YunoHost and
Moulinette. `--build-webadmin` installs build dependencies if needed, uses the
checkout's frozen Yarn lockfile, checks types, builds the frontend, and serves
the build after success. The packaged frontend is retained as `admin-bkp`.
Omit these flags when the container already runs the intended code/build.
If Chromium reports missing host system libraries, install them with
`sudo .venv/bin/python -m playwright install-deps chromium` and retry preparation.

If its installed Lexicon does not yet contain the provider, supply your selected
Lexicon checkout when preparing:

```bash
./run prepare --container CONTAINER --lexicon-source /path/to/dns-lexicon
```

This builds a wheel and installs it and its dependencies in the development
container. It uses `/usr/local` without uninstalling Debian's package. Doctor
records the actual imported provider and code hashes, because the Debian package
version alone may not describe a source or wheel override. Preparation also
installs the harness's Python dependencies and matching Playwright browser and
restarts the development API. Normal APT signature verification is retained.

The harness defaults to the parent directory as `ynh-dev` and `/ynh-dev` as its
container mount. Override these with `--ynh-dev PATH` and `--container-root PATH`
when necessary. The upstream `use-git` helper expects `/ynh-dev`; for a custom
mount, arrange core source links yourself and omit `--link-sources`.
The harness detects the container IPv4 address; use
`--webadmin-url https://HOST/yunohost/admin/` to override it. Local self-signed
development certificates are accepted in the isolated test browser.

## Obtain your own Le Bureau key file

1. Request a TSIG key **by email to Le Bureau**, identifying the domain to test.
2. Download the file Le Bureau provides through your customer account on its
   website. There is one key per domain.
3. Save the original downloaded file outside this repository and shared source
   directories, for example in a private configuration directory. Restrict its
   permissions with `chmod 600 /path/to/downloaded-key-file`.

Le Bureau supplies full-access keys for the corresponding domain. Customers do
not select privileges and there is no TSIG permission-selection page. The tests
use both AXFR and UPDATE through that key. You do not need to convert the file
into another credential format or supply your website account password.

The supported download has three nonempty lines: a domain header whose last
field is the domain, a column header, then key name, HMAC algorithm and base64
secret. Malformed files are rejected without echoing their contents. Use the
actual hosted zone, with its DNS served by Le Bureau. No test credentials or
working domain are included in this repository.

## Run

Run every integration group with one command:

```bash
./run all --container CONTAINER --credentials-file /path/to/downloaded-key-file
```

| Group | What it exercises | Service use |
| --- | --- | --- |
| `offline` | Reconciliation, ownership, credentials, DNS wire/TSIG faults and fixture recovery | Controlled DNS/API responses |
| `browser-faults` | Refresh/write errors, stale responses, duplicate clicks and force cancellation | Real compiled frontend, controlled API responses |
| `live-api` | Discovery, credential lifecycle, preview/apply, fresh CLI no-op, API restart, TXT update/deletion | Real DNS and authenticated loopback API/CLI |
| `browser` | Login, credential form, malformed-token recovery, preview/apply, ordinary installed child, disable/re-enable | Real HTTPS webadmin and DNS |
| `force` | Ignored unmanaged changes, cancellation, explicit force, sibling preservation and CLI recovery | Real webadmin/CLI and DNS |

The full run fails before live writes if prerequisite or controlled groups fail.
It takes a container snapshot before the live groups. Shared source checkouts
are **not** included in an Incus snapshot. Each live group uses a fresh random
subdomain and temporary administrator. DNS preview scope is checked before
applying changes; the existing zone baseline must survive cleanup. The zone apex
is not used as a live write fixture. Do not run other zone-editing tests
concurrently: baseline verification intentionally detects unrelated changes.

For regression tests without a key or live DNS writes:

```bash
./run offline --container CONTAINER
```

This runs the first two groups. It still needs the prepared container and compiled
frontend. It is the harness's controlled suite, not the whole YunoHost or Lexicon
repository test suite.

## Results and recovery

Progress names each group and its pass/fail status. Results are written under
`.results/TIMESTAMP-ID/`: `summary.json`, group reports/logs and offline JUnit XML.
Use `--output DIRECTORY` to choose another destination. The summary records
runtime package versions, imported source hashes, checkout commits/dirty state
and the harness revision/source digest, plus which groups used real services.
A full run never silently skips a required
group. Nonzero exit status means it did not pass.

Credentials, temporary passwords and domain values are redacted from generated
reports. Browser traces, authenticated screenshots and storage dumps are not
recorded. Generated output, environments, browser downloads and caches are
excluded from Git. Inspect a report before sharing it, particularly when adding
new diagnostic output.

Cleanup normally runs even after a failed scenario. Private recovery state and
the DNS baseline stay in a root-only directory in the container. If interrupted
or cleanup fails, keep the container and run:

```bash
./run cleanup --container CONTAINER
```

No original administrator password or downloaded file is needed for recovery;
the retained root-only state contains the exact fixture identity and key. Cleanup
validates fixture names, removes only their records/accounts/domains, verifies
the baseline and checks operation logs for credentials. It refuses malformed or
foreign fixture state. If the baseline differs or a DNS operation remains
uncertain, inspect the container and resolve the issue before retrying cleanup;
do not delete the recovery file to conceal a failure. Do not publish that file.

The harness does not automatically restore snapshots or retry uncertain DNS
writes. Service convergence is checked with bounded read polling.

## License

AGPL-3.0-or-later; see `LICENSE` and `NOTICE`. The adapted DNS authority fixture's
MIT notice is included under `licenses/`.

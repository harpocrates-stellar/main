# Dependency pins and lockfiles

`devx/check_dependency_pins.py` is the release-gate check that keeps every
dependency surface in the repository pinned and in sync. It runs in
`.github/workflows/release-gate.yml` before the manifest and label checks,
because a floating or stale dependency invalidates everything computed from
it.

```bash
python3 devx/check_dependency_pins.py            # text report, exit 0/1/2/3
python3 devx/check_dependency_pins.py --json     # machine-readable report
python3 devx/check_dependency_pins.py --root DIR # scan another checkout
python3 -m unittest discover -s devx -p 'test_check_dependency_pins.py' -v
```

## What the repository pins, and how

| Surface | Pin | Rationale |
| --- | --- | --- |
| `backend/requirements.txt` | `==` in the file | pip has no lockfile here, so the requirements file is the only pin. A range would float the verifier between two runs of the same commit. |
| `cli/package-lock.json`, `frontend/package-lock.json` | `package-lock.json` | The manifest may carry semver ranges; the lock is the reviewed, reproducible tree. |
| `contracts/Cargo.lock` | `Cargo.lock` | The lock selects the crates whose output becomes Soroban bytecode, so a lock change is a contract change. |
| `zk/toolchain.lock.json` | toolchain lock | Pins `nargo` and `barretenberg`, the compiler and proving backend behind byte-identical ACIR bundles and verification keys. See `docs/zk-reproducible-builds.md`. |
| `zk/noir/*/Nargo.toml` | `compiler_version` + local `path`/pinned `git` deps | Circuits must build under the pinned toolchain and must not pull a moving source. |

## Failure modes the check catches

- A requirement widened to `>=`, `~=`, a bare name, a wildcard, an `-e`/`-r`
  option line, or a direct URL, none of which can be reproduced from a clean
  checkout.
- A duplicate distribution after PEP 503 normalization (`flask-cors` and
  `flask_cors` are the same requirement).
- `package.json` edited without re-running `npm install`: the lock's root
  dependency maps no longer match the manifest, or a declared dependency has
  no resolved package entry.
- A lockfile downgraded below `lockfileVersion` 2, or one that names a
  different package than its manifest.
- A crate missing from `Cargo.lock`, a workspace member whose manifest version
  is newer than the lock, an `=x.y.z` pin the lock does not resolve, or a
  short requirement (`"27"`) resolved outside its prefix.
- A `git` dependency pinned only by `branch`, or by nothing at all.
- A toolchain lock floating on `latest`, or a circuit dependency pointing at a
  path that does not exist.

## Interpreting the exit codes

| Code | Meaning | Action |
| --- | --- | --- |
| `0` | every surface pinned and in sync | none |
| `1` | policy finding | fix the manifest, or re-run the package manager and commit the lock |
| `2` | input missing or unreadable, or above the 4 MiB limit | restore the file; the limit only exists so a corrupted tree cannot turn the gate into a denial of service |
| `3` | input does not parse as JSON or TOML | repair the syntax; the message names the file and position |

## Remediation

- pip: pin the exact version that the C2PA and RFC 3161 verification paths were
  tested against.
- npm: `cd cli && npm install` or `cd frontend && npm install`, then commit the
  regenerated lock.
- cargo: run the workspace build (`cd contracts && cargo build`) so
  `Cargo.lock` is refreshed, then commit it. Review the lock diff before
  committing: for on-chain output, the review is the point.
- noir: bump `zk/toolchain.lock.json` deliberately and record the artifact
  digests from the reproducible build.

## Privacy and trust boundary

The check reads only dependency names, versions, resolved package entries, and
workspace-relative paths. Findings are printed to CI logs, so
credential-shaped requirement lines are reported by line number and never
echoed; the same applies to the size and parse diagnostics.

## Rollback

The check is additive: remove the `Verify dependency pins and lockfiles` step
from `.github/workflows/release-gate.yml` (and the `cli/**` trigger, if
desired) to restore the previous gate. Nothing else in the repository depends
on it — it publishes no artifacts, writes no files, and holds no state — so
reverting the pull request restores the prior behaviour exactly.

## Automated dependency updates (Dependabot policy)

Automated dependency updates are managed via `.github/dependabot.yml` and
validated by `devx/dependabot_config.py`.

```bash
python3 devx/dependabot_config.py --check .github/dependabot.yml
python3 -m unittest devx/test_dependabot_config.py -v
```

### Policy and grouping rules

1. **Covered surfaces**:
   - `npm`: `/frontend` and `/cli`
   - `pip`: `/backend`
   - `cargo`: `/contracts`
   - `github-actions`: `/` (workflow actions)

2. **Low-risk patch updates**:
   - Patch-level updates are grouped into a single weekly pull request per
     ecosystem (`update-types: ["patch"]`). This minimizes notification
     churn while maintaining security patches across low-risk packages.

3. **Isolated review for critical & cryptographic surfaces**:
   - **Stellar / Soroban**: `@stellar/*`, `stellar-*`, and `soroban-*` are
     excluded from generic patch groupings and tracked in dedicated groups
     or standalone PRs for focused blockchain review.
   - **Noir & proof system**: In the frontend, `@noir-lang/*`, `@aztec/*`, and
     `barretenberg*` are isolated from generic patch updates to allow
     deliberate cryptographic verification against `zk/toolchain.lock.json`.

4. **Conservative schedule and limits**:
   - Updates run weekly on Mondays (`04:00 UTC`).
   - `open-pull-requests-limit: 5` is enforced per ecosystem to prevent pull
     request flooding.

### Maintainer controls

#### Pausing updates
- **Entire ecosystem / repository**:
  Set `open-pull-requests-limit: 0` in `.github/dependabot.yml` for the
  relevant ecosystem entry, or comment out the update block.
- **On an active pull request**:
  Comment `@dependabot pause` on an open PR to halt Dependabot activity
  temporarily, or close the PR with `@dependabot close`.

#### Ignoring updates or specific versions
- **In `.github/dependabot.yml`**:
  Add an `ignore` block under the relevant ecosystem entry:
  ```yaml
  ignore:
    - dependency-name: "package-name"
      update-types: ["version-update:semver-major"]
  ```
- **Via pull request comments**:
  - `@dependabot ignore this dependency`: Ignores all future updates for the
    package.
  - `@dependabot ignore this major version`: Ignores major updates but permits
    minor and patch updates.
  - `@dependabot ignore this minor version`: Ignores minor updates but permits
    patch updates.


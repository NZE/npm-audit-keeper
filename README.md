# npm-audit-keeper

A small npm audit gate for CI, with GHSA-based ignores, documented reasons, and expiry dates. Zero runtime dependencies.

The CLI runs `npm audit --json` in your current directory, reports advisories at or above your severity threshold, and fails if any remain unresolved or any active ignore has expired. It does not change dependencies or run `npm audit fix`.

## Requirements and installation

- Node.js **22.12 or newer**. Use Node 24 for development; CI covers Node 22.12 and 24 on Windows and Linux.
- npm must be available on `PATH`, with access to the registry configured for the project being audited.
- Run from an npm project with a `package-lock.json` or `npm-shrinkwrap.json`. The supported audit response is npm's `auditReportVersion: 2` format.

After publication to npm, install with:

```bash
npm install --save-dev npm-audit-keeper
```

The package is not published to the public npm registry yet. See [release preparation](RELEASING.md) for the remaining steps.

## Quick start

### 1. Add the npm scripts

Add these scripts to your project's `package.json`:

```json
{
  "scripts": {
    "audit": "audit-check",
    "audit:resolve": "audit-check -i"
  }
}
```

Both commands use the installed package. No global installation is needed. Commit your project's `package.json` and `package-lock.json` so developers and CI install the same dependency versions.

### 2. Add a policy file

Create and commit `audit-config.json` next to the project's `package.json`. The default threshold is `moderate`:

```json
{
  "level": "moderate",
  "ignore": []
}
```

Start with an empty ignore list. Existing projects may already have documented exceptions; review those in the context of that project instead of copying another application's accepted risks.

### 3. Check and review findings

```bash
# Run the normal check used by the project.
npm run audit

# Interactively review unresolved advisories and manage ignores.
npm run audit:resolve

# Recheck the saved policy using the normal threshold.
npm run audit
```

`audit:resolve` opens the review prompts; it does not upgrade packages or automatically fix vulnerabilities. Review the affected dependency and upgrade it when possible. If your team accepts the risk, choose an ignore period and document the reason. Review and commit the resulting `audit-config.json` changes so CI uses the same policy. If you upgrade dependencies, also commit the changed package manifest and lockfile.

### 4. Pass options through npm

Use `--` to pass CLI options through the npm script:

```bash
npm run audit -- --audit-level=high
npm run audit -- --config ./config/audit-config.json
npm run audit:resolve -- --audit-level=high
npm run audit -- --help
npm run audit -- --version
```

You can also call the installed CLI directly. For example, `npx audit-check` is equivalent to the `audit` script above, and `npx audit-check -i` is equivalent to `audit:resolve`.

For multiple independently locked projects, run the gate from each project's directory. `--config` selects a policy file; it does not change which directory npm audits.

## CLI reference

`audit-check` and `audit-keeper` are identical aliases.

| Option | Behavior |
| --- | --- |
| `--config <path>` | Read this policy file. Defaults to `./audit-config.json`. |
| `--audit-level <level>` | Override the threshold for this run. Also accepts `--audit-level=high`. |
| `-i`, `--interactive` | Review advisories and save ignore changes. Requires a TTY on stdin and stdout. |
| `-h`, `--help` | Print help and exit without reading config or running npm audit. |
| `-v`, `--version` | Print the installed package version and exit without running npm audit. |

Severity levels are `low`, `moderate`, `high`, and `critical`. Each includes all higher levels. Unknown arguments and invalid values cause exit code 1.

A severity override is never written back to your policy file, including when interactive mode saves ignore changes.

## Policy file

Start with:

```json
{
  "level": "moderate",
  "ignore": []
}
```

A missing config file uses these defaults and does not create a file. Invalid JSON or invalid policy entries cause failure.

An ignore must identify one GHSA advisory and explain why the risk is accepted:

```json
{
  "level": "moderate",
  "ignore": [
    {
      "ghsa": "GHSA-3ppc-4f35-3m26",
      "package": "minimatch",
      "reason": "Affected path is not used; dependency upgrade is scheduled.",
      "expires": "2099-01-01",
      "active": true
    }
  ]
}
```

The example date is illustrative. Choose the actual review deadline for your project.

| Field | Requirement |
| --- | --- |
| `ghsa` | Required `GHSA-xxxx-xxxx-xxxx` identifier. Matching is case-insensitive. |
| `package` | Required non-empty package name, for documentation. Matching uses GHSA only. |
| `reason` | Required non-empty justification. Whitespace alone is rejected. |
| `expires` | A valid calendar date in `YYYY-MM-DD` format; required unless `permanent` is `true`. |
| `permanent` | Optional boolean. When `true`, `expires` must be omitted. |
| `active` | Optional boolean, default `true`. Set `false` to retain an entry without applying it. |

A permanent ignore uses `"permanent": true` in place of `expires`; it still requires a reason.

Expiration uses UTC dates. An ignore remains valid through its expiry day and stops matching on the next UTC day. Every expired active entry causes failure, even when its advisory is no longer present. Remove or review expired entries. Inactive entries do not cause expiry failures.

An active, unexpired ignore is considered unused only when its advisory is absent from the complete audit report. Advisories below the current threshold still count as present. Unused entries produce a warning without failing the gate.

Advisories without a GHSA identifier appear as `unknown-<source>` and remain unresolved when in scope. They cannot be ignored manually or interactively. Unsupported report versions, malformed advisory data, and npm execution errors cause failure rather than a clean result.

## Interactive review

```bash
npm run audit:resolve
```

The session first offers to remove inactive and unused entries, then shows each unresolved advisory's identifier, package, severity, title, and URL.

Choose **skip** to leave an advisory unresolved, or **ignore** to select a period:

| Choice | Expiry |
| --- | --- |
| `D` | Tomorrow's UTC date |
| `W` | Seven days from today's UTC date |
| `M` | The same date next month, clamped to that month's last day |
| `P` | Permanent, with no expiry date |

For example, a month from January 31 ends on February 28, or February 29 in a leap year. Each expiry date is inclusive.

Enter a reason for accepting the risk. New entries require a non-empty reason. When updating an existing ignore, press Enter to retain its reason or type a replacement.

Completed changes are saved to the policy file. Adding or updating an ignore triggers a fresh audit. Cleanup alone saves the file without another audit. Advisories without GHSA identifiers are reported as unignorable and skipped automatically.

## Output and exit codes

Audit results, warnings, and errors go to stderr. Help, version output, and interactive prompts go to stdout.

| Exit code | Meaning |
| --- | --- |
| `0` | No unresolved in-scope advisories and no expired active ignores; also successful help/version requests. |
| `1` | Unresolved advisories, expired active ignores, invalid arguments/config, unsupported audit output, or an operational error. |

Registry, authentication, certificate, and connection failures must be resolved in the npm environment. Ignore entries apply to advisories; they do not suppress operational failures.

### When the check fails

| Result | What to do |
| --- | --- |
| Unresolved advisory | Review the advisory and dependency path, update the affected dependency when possible, then rerun `npm run audit`. Use `npm run audit:resolve` only for a risk the team accepts. |
| Expired active ignore | Review or remove the entry in `audit-config.json`. If the advisory is still present, interactive review can renew it with a reason and a new expiry. |
| Unused-ignore warning | Review the entry and remove it manually or through `npm run audit:resolve`. The warning alone does not fail the check. |
| Invalid configuration | Fix the JSON or field reported in the error, then rerun the check. |
| Registry, authentication, or certificate error | Correct the project's npm access or trust configuration. Adding an advisory ignore will not fix it. |
| Non-TTY interactive error | Run `npm run audit:resolve` in a local terminal. CI should use `npm run audit`. |

`npm run audit` runs the project's policy-aware gate. Plain `npm audit` runs npm's report without applying `audit-config.json`, so it can still report vulnerabilities your team has explicitly accepted in the gate.

## CI usage

Install this package as a development dependency and add the `audit` and `audit:resolve` scripts shown above. CI runs the non-interactive `audit` script.

### GitHub Actions

```yaml
name: Dependency audit
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: '24'
          package-manager-cache: false
      - run: npm ci --no-audit
      - run: npm run audit -- --audit-level=moderate
```

Private registries need their usual npm authentication configuration before installation and auditing. `npm audit signatures` is a separate npm check and does not use this package's ignore list.

## Development

```bash
npm ci --no-audit
npm test              # clean build and regression tests
npm run audit         # audit this repository using its compiled CLI
npm run test:package  # pack, install offline, and check both CLI aliases
```

`npm run build` cleans `dist/` and compiles TypeScript. Vitest tests use fixtures rather than the live registry. The package smoke test installs the actual tarball in a temporary consumer, checks its contents, and verifies both commands from a directory with spaces in its path.

The GitHub CI workflow runs these checks on Windows and Linux with Node 22.12 and 24. Publication is a separate step.

`npm run demo` launches the PowerShell interactive demo. Its dependencies are intentionally vulnerable and are isolated under `examples/vulnerable-app`; the root audit does not audit that separate lockfile.

See [CONTRIBUTING.md](CONTRIBUTING.md) for change validation and [RELEASING.md](RELEASING.md) for packaging and publication.

## TODO: GitHub and public npm release

- [x] Fix audit parsing, ignore handling, interactive policy saves, and month-end expiry.
- [x] Update development dependencies and verify a clean root dependency audit.
- [x] Add help/version commands, regression tests, and tarball installation checks.
- [x] Add GitHub CI configuration for Windows/Linux and Node 22.12/24.
- [x] Document the consumer setup and local review workflow.
- [x] Choose the npm package name and prepare a GitHub source tree with independent history.
- [x] Add repository, homepage, and issue tracker metadata.
- [ ] Choose and add a license before the first public release.
- [x] Create the GitHub repository and push the initial source snapshot.
- [ ] Run the GitHub CI matrix successfully, including Linux package checks.
- [ ] Configure npm ownership and trusted publishing, then publish the reviewed version.
- [ ] Verify installation from the public registry and update the installation instructions to the final package identity.

See [RELEASING.md](RELEASING.md) for the release procedure.

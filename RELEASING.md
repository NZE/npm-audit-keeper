# Releasing

## First public release

- Review the source tree, then make the GitHub repository public. The package is MIT-licensed and its first public version is `npm-audit-keeper@1.0.0`.
- Confirm the package name is available on npm and sign in to an npm account with two-factor authentication.
- Run the checks below on a clean `main` commit and confirm the GitHub CI matrix passed for that commit.
- Publish the first version interactively with `npm publish --registry=https://registry.npmjs.org/`. A new package cannot be staged or configured with a trusted publisher until it exists on npm.
- Verify the published package metadata and install both CLI aliases from the public registry. Tag the published commit as `v1.0.0` and create the matching GitHub Release.

## Verify the package

```bash
npm ci --no-audit
npm test
npm run audit
npm run test:package
npm pack --dry-run
```

Package and publish from the repository root. `prepack` performs a clean build, so `npm pack` includes current compiled code and the README. Do not publish the `dist` directory by itself. There is only one package manifest, at the root.

The package smoke test installs the tarball offline without lifecycle scripts. It checks the shipped files, version, zero runtime dependencies, and both CLI aliases.

The GitHub CI matrix must pass before release. Local Windows checks do not substitute for the Linux jobs.

## Later releases

After the first version exists, configure npm trusted publishing for GitHub user `NZE`, repository `npm-audit-keeper`, and workflow file `publish.yml`. Allow staged publishing only. The workflow runs on a version tag, validates that the tag matches `package.json` and points into `main`, repeats the checks above, then stages the package using GitHub Actions OIDC. No npm publish token is stored in GitHub.

For each release, commit a version bump to `main` with its lockfile, wait for CI, then tag that exact commit as `v<version>` and push the tag. Review the staged package on npm and approve it with two-factor authentication. Create the GitHub Release after npm confirms publication. A package version cannot be reused once published.

Trusted publishing requires a GitHub-hosted runner, Node 22.14 or newer, npm 11.5.1 or newer, and `id-token: write` permission. Staged publishing requires npm 11.15.0 or newer. Publishing from the public GitHub repository generates npm provenance automatically for later versions.

See [npm's unscoped package guide](https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages/), [trusted publishing](https://docs.npmjs.com/trusted-publishers/), and [staged publishing](https://docs.npmjs.com/staged-publishing/).

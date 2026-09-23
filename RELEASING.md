# Releasing

## First public release

`npm-audit-keeper@1.0.0` was published interactively from commit `84c9795` after the GitHub CI matrix passed. The package is public on [npm](https://www.npmjs.com/package/npm-audit-keeper), and the matching [GitHub release](https://github.com/NZE/npm-audit-keeper/releases/tag/v1.0.0) points to that commit. This bootstrap was necessary because a new package cannot be staged or configured with a trusted publisher until it exists on npm.

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

The trusted publisher is GitHub user `NZE`, repository `npm-audit-keeper`, and workflow file `publish.yml`, with staged publishing permission only. Pushing a version tag runs the workflow, validates that the tag matches `package.json` and points into `main`, repeats the checks above, then stages the package using GitHub Actions OIDC. No npm publish token is stored in GitHub.

For each release, commit a version bump to `main` with its lockfile, wait for CI, then tag that exact commit as `v<version>` and push the tag. Review the staged package on npm and approve it with two-factor authentication. Create the GitHub Release after npm confirms publication. A package version cannot be reused once published.

Trusted publishing requires a GitHub-hosted runner, Node 22.14 or newer, npm 11.5.1 or newer, and `id-token: write` permission. Staged publishing requires npm 11.15.0 or newer. Publishing from the public GitHub repository generates npm provenance automatically for later versions.

See [npm's unscoped package guide](https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages/), [trusted publishing](https://docs.npmjs.com/trusted-publishers/), and [staged publishing](https://docs.npmjs.com/staged-publishing/).

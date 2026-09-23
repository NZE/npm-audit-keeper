# Release preparation

## Before the first public release

- Confirm the GitHub repository owner and public visibility.
- Confirm the starting public version. The package currently identifies as `npm-audit-keeper@1.0.0` and requires Node 22.12 or newer.
- Add the approved `LICENSE` and matching `license` field in `package.json`.
- Review the source tree before making the GitHub repository public.

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

## npm publication

Publication is not triggered by the CI workflow. Complete the package identity and license decisions before enabling publishing.

Use the public npm registry explicitly when publishing. See [npm's package publication guide](https://docs.npmjs.com/creating-and-publishing-unscoped-public-packages/).

Prefer [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/) from a dedicated GitHub Actions workflow on a GitHub-hosted runner. Configure npm with the exact repository, workflow filename, and optional protected environment. Use Node 24, a current npm CLI, `contents: read`, and `id-token: write`. Trusted publishing provides short-lived credentials and provenance for eligible public repositories.

For a new package, establish the package and publisher configuration through the supported npm account flow first. Confirm that the release tag matches `package.json`, verify the packed artifact, and publish only the reviewed version. Check the public registry metadata and install both CLI aliases from the published package afterward.

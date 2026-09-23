# Contributing

Use Node 24 and npm. The supported runtime starts at Node 22.12; keep runtime API usage compatible with that minimum and preserve zero runtime dependencies.

Before proposing a change:

```bash
npm ci --no-audit
npm test
npm run audit
npm run test:package
```

Add regression coverage for changes to audit matching, configuration, expiry dates, CLI behavior, or package installation. Audit tests should use fixtures so they do not depend on registry availability or changing advisories.

Update the README when changing flags, policy fields, requirements, or user-visible behavior. Keep dependency changes scoped and commit the root lockfile. The demo has a separate, deliberately vulnerable lockfile; those dependencies are not the package's runtime dependencies.

Build output and local policy files are ignored. Commit source and tests, not `dist/`, tarballs, or local assistant settings.

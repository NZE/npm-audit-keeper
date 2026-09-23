# Demo App

This app exists only for local interactive testing of `npm-audit-keeper`.

Run from repo root:

```powershell
npm run demo
```

Notes:
- `audit-config.example.json` is committed as a reference template.
- `audit-config.json` is local runtime output and is git-ignored.
- `npm run demo` will create `audit-config.json` from the template if missing.

It installs intentionally vulnerable demo dependencies and launches:

```powershell
node dist/index.js -i --config examples/vulnerable-app/audit-config.json
```

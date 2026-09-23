const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const packageJson = require(path.join(root, "package.json"));
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run this check with npm run test:package");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "audit-keeper-package-"));

function npm(args, cwd) {
  return execFileSync(process.execPath, [npmCli, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 120_000,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

try {
  const output = JSON.parse(npm(["pack", "--json", "--pack-destination", temp], root));
  const packed = Array.isArray(output) ? output[0] : Object.values(output)[0];
  const files = packed.files.map((file) => file.path);
  assert.ok(files.includes("README.md"), "Tarball must include the README");
  if (fs.existsSync(path.join(root, "LICENSE"))) {
    assert.ok(files.includes("LICENSE"), "Tarball must include the license");
  }
  assert.ok(files.includes("dist/index.js"), "Tarball must include the CLI");
  assert.ok(!files.includes("dist/package.json"), "Use one root package manifest");
  assert.ok(files.every((file) => /^(package\.json|(?:README|CONTRIBUTING|RELEASING)\.md|LICENSE|dist\/[^/]+\.(js|d\.ts))$/.test(file)),
    "Tarball contains unexpected files");

  const consumer = path.join(temp, "consumer with spaces");
  fs.mkdirSync(consumer);
  fs.writeFileSync(path.join(consumer, "package.json"), JSON.stringify({ name: "package-smoke-test", version: "1.0.0", private: true }));
  npm(["install", path.join(temp, packed.filename), "--ignore-scripts", "--no-audit", "--no-fund", "--offline"], consumer);
  const installed = JSON.parse(fs.readFileSync(path.join(consumer, "node_modules", packageJson.name, "package.json"), "utf8"));
  assert.equal(installed.version, packageJson.version);
  assert.equal(Object.keys(installed.dependencies ?? {}).length, 0, "CLI must have zero runtime dependencies");

  for (const alias of Object.keys(packageJson.bin)) {
    assert.equal(npm(["exec", "--offline", "--", alias, "--version"], consumer).trim(), packageJson.version);
    assert.match(npm(["exec", "--offline", "--", alias, "--help"], consumer), /Usage: audit-check/);
  }
  console.log(`Package smoke test passed: ${packed.filename}; both CLI aliases work after offline installation.`);
} finally {
  assert.equal(path.dirname(path.resolve(temp)), path.resolve(os.tmpdir()));
  assert.ok(path.basename(temp).startsWith("audit-keeper-package-"));
  fs.rmSync(temp, { recursive: true, force: true });
}

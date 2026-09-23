const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { fixturePath, makeTempDir } = require("./helpers/fs-utils.cjs");
const realConfigModule = require("../dist/config.js");
const { loadConfig: realLoadConfig } = realConfigModule;

const projectRoot = path.resolve(__dirname, "..");
const indexModulePath = require.resolve(path.join(projectRoot, "dist", "index.js"));
const configModulePath = require.resolve(path.join(projectRoot, "dist", "config.js"));
const auditModulePath = require.resolve(path.join(projectRoot, "dist", "audit.js"));
const interactiveModulePath = require.resolve(path.join(projectRoot, "dist", "interactive.js"));

class ExitSignal extends Error {
  constructor(code) {
    super(`Process exited with code ${code}`);
    this.code = code;
  }
}

function makeCacheEntry(filePath, exportsObj) {
  return {
    id: filePath,
    filename: filePath,
    loaded: true,
    exports: exportsObj,
  };
}

function restoreCache(modulePath, originalEntry) {
  if (originalEntry) {
    require.cache[modulePath] = originalEntry;
  } else {
    delete require.cache[modulePath];
  }
}

async function runCliInProcess({ argv, loadConfigImpl, runAuditImpl, runInteractiveSessionImpl, stdinIsTTY = true, stdoutIsTTY = true }) {
  const originalArgv = process.argv;
  const originalExit = process.exit;
  const originalConsoleError = console.error;
  const originalConsoleLog = console.log;
  const originalStdinIsTTY = process.stdin.isTTY;
  const originalStdoutIsTTY = process.stdout.isTTY;

  const originalIndexCache = require.cache[indexModulePath];
  const originalConfigCache = require.cache[configModulePath];
  const originalAuditCache = require.cache[auditModulePath];
  const originalInteractiveCache = require.cache[interactiveModulePath];

  let status = null;
  const stderrLines = [];
  const stdoutLines = [];

  if (loadConfigImpl) {
    require.cache[configModulePath] = makeCacheEntry(configModulePath, {
      ...realConfigModule,
      loadConfig: loadConfigImpl,
    });
  }
  if (runAuditImpl) {
    require.cache[auditModulePath] = makeCacheEntry(auditModulePath, { runAudit: runAuditImpl });
  }
  if (runInteractiveSessionImpl) {
    require.cache[interactiveModulePath] = makeCacheEntry(interactiveModulePath, {
      runInteractiveSession: runInteractiveSessionImpl,
    });
  }

  process.argv = ["node", indexModulePath, ...argv];
  console.error = (...args) => {
    stderrLines.push(args.map(String).join(" "));
  };
  console.log = (...args) => stdoutLines.push(args.map(String).join(" "));
  process.exit = (code) => {
    throw new ExitSignal(typeof code === "number" ? code : 0);
  };
  Object.defineProperty(process.stdin, "isTTY", { value: stdinIsTTY, configurable: true });
  Object.defineProperty(process.stdout, "isTTY", { value: stdoutIsTTY, configurable: true });

  try {
    delete require.cache[indexModulePath];
    const { main } = require(indexModulePath);
    await main();
  } catch (err) {
    if (err instanceof ExitSignal) {
      status = err.code;
    } else {
      throw err;
    }
  } finally {
    process.argv = originalArgv;
    process.exit = originalExit;
    console.error = originalConsoleError;
    console.log = originalConsoleLog;
    Object.defineProperty(process.stdin, "isTTY", { value: originalStdinIsTTY, configurable: true });
    Object.defineProperty(process.stdout, "isTTY", { value: originalStdoutIsTTY, configurable: true });

    restoreCache(indexModulePath, originalIndexCache);
    restoreCache(configModulePath, originalConfigCache);
    restoreCache(auditModulePath, originalAuditCache);
    restoreCache(interactiveModulePath, originalInteractiveCache);
  }

  return {
    status,
    stderr: stderrLines.join("\n"),
    stdout: stdoutLines.join("\n"),
  };
}

const AJV = {
  ghsa: "GHSA-2g4f-4pwh-qvx6",
  package: "ajv",
  severity: "moderate",
  title: "ReDoS when using $data option",
  url: "https://github.com/advisories/GHSA-2g4f-4pwh-qvx6",
};

const MINIMATCH = {
  ghsa: "GHSA-3ppc-4f35-3m26",
  package: "minimatch",
  severity: "high",
  title: "ReDoS via repeated wildcards",
  url: "https://github.com/advisories/GHSA-3ppc-4f35-3m26",
};

const MINIMATCH_IGNORE = {
  ghsa: "GHSA-3ppc-4f35-3m26",
  package: "minimatch",
  reason: "Dev-only dependency accepted temporarily.",
  expires: "2099-01-01",
  active: true,
};

const AJV_IGNORE = {
  ghsa: "GHSA-2g4f-4pwh-qvx6",
  package: "ajv",
  reason: "Temporary CI waiver.",
  expires: "2099-01-01",
  active: true,
};

const MINIMATCH_PERMANENT_IGNORE = {
  ghsa: "GHSA-3ppc-4f35-3m26",
  package: "minimatch",
  reason: "Patched locally",
  permanent: true,
  active: true,
};

test("CLI resolves --config path and passes when no advisories are unresolved", async () => {
  let receivedPath = "";
  const relativeConfigPath = path.join("test", "fixtures", "config", "empty.json");

  const result = await runCliInProcess({
    argv: ["--config", relativeConfigPath],
    loadConfigImpl: (configPath) => {
      receivedPath = configPath;
      return { level: "moderate", ignore: [] };
    },
    runAuditImpl: () => ({
      found: [],
      unresolved: [],
      ignored: [],
      unusedIgnores: [],
      expired: [],
    }),
  });

  assert.equal(result.status, 0);
  assert.equal(receivedPath, path.resolve(process.cwd(), relativeConfigPath));
  assert.match(result.stderr, /PASS — no unresolved advisories/);
});

test.each(["--help", "-h", "--version", "-v"])("%s exits successfully without loading config or auditing", async (flag) => {
  const result = await runCliInProcess({
    argv: [flag],
    loadConfigImpl: () => { throw new Error("Config must not be loaded"); },
    runAuditImpl: () => { throw new Error("Audit must not run"); },
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  if (flag === "--help" || flag === "-h") {
    assert.match(result.stdout, /Usage: audit-check/);
  } else {
    assert.equal(result.stdout, require("../package.json").version);
  }
});

test.each(["--audit-leve=critical", "--unknown", "unexpected-argument", "--audit-level=high=extra"])("rejects %s before auditing", async (flag) => {
  const result = await runCliInProcess({
    argv: [flag],
    loadConfigImpl: () => { throw new Error("Config must not be loaded"); },
    runAuditImpl: () => { throw new Error("Audit must not run"); },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown argument|Invalid audit level/);
});

test.each([false, true])("interactive saves preserve the configured level (adds ignore: %s)", async (addsIgnore) => {
  const dir = makeTempDir("cli-preserve-level");
  const configPath = path.join(dir, "audit-config.json");
  const inactive = { ...MINIMATCH_IGNORE, active: false };
  fs.writeFileSync(configPath, JSON.stringify({ level: "moderate", ignore: [inactive] }));
  const levels = [];
  try {
    const result = await runCliInProcess({
      argv: ["--config", configPath, "-i", "--audit-level=critical"],
      loadConfigImpl: realLoadConfig,
      runAuditImpl: (config) => {
        levels.push(config.level);
        return { found: [], unresolved: [], ignored: [], unusedIgnores: [], expired: [] };
      },
      runInteractiveSessionImpl: async ({ config }) => {
        assert.equal(config.level, "moderate");
        config.ignore = addsIgnore ? [AJV_IGNORE] : [];
        return { removedInactive: 1, removedUnused: 0, reviewed: 0, skipped: 0, ignored: addsIgnore ? 1 : 0, added: addsIgnore ? 1 : 0, updated: 0 };
      },
    });
    assert.equal(result.status, 0);
    assert.deepEqual(levels, addsIgnore ? ["critical", "critical"] : ["critical"]);
    assert.equal(realLoadConfig(configPath).level, "moderate");
    assert.equal(realLoadConfig(configPath).ignore.length, addsIgnore ? 1 : 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI fails when unresolved advisories are present", async () => {
  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "empty.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [] }),
    runAuditImpl: () => ({
      found: [AJV, MINIMATCH],
      unresolved: [AJV, MINIMATCH],
      ignored: [],
      unusedIgnores: [],
      expired: [],
    }),
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unresolved \(2\):/);
  assert.match(result.stderr, /FAIL/);
});

test("CLI still fails when only one advisory is ignored", async () => {
  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "ignore-minimatch.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [MINIMATCH_IGNORE] }),
    runAuditImpl: () => ({
      found: [AJV, MINIMATCH],
      unresolved: [AJV],
      ignored: [{ advisory: MINIMATCH, entry: MINIMATCH_IGNORE }],
      unusedIgnores: [],
      expired: [],
    }),
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Ignored \(1\):/);
  assert.match(result.stderr, /Unresolved \(1\):/);
});

test("CLI passes when all advisories are ignored", async () => {
  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "ignore-both.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [MINIMATCH_IGNORE, AJV_IGNORE] }),
    runAuditImpl: () => ({
      found: [AJV, MINIMATCH],
      unresolved: [],
      ignored: [
        { advisory: AJV, entry: AJV_IGNORE },
        { advisory: MINIMATCH, entry: MINIMATCH_IGNORE },
      ],
      unusedIgnores: [],
      expired: [],
    }),
  });

  assert.equal(result.status, 0);
  assert.match(result.stderr, /Ignored \(2\):/);
  assert.match(result.stderr, /PASS — no unresolved advisories/);
});

test("CLI prints permanent ignores distinctly", async () => {
  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "empty.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [MINIMATCH_PERMANENT_IGNORE] }),
    runAuditImpl: () => ({
      found: [MINIMATCH],
      unresolved: [],
      ignored: [{ advisory: MINIMATCH, entry: MINIMATCH_PERMANENT_IGNORE }],
      unusedIgnores: [],
      expired: [],
    }),
  });

  assert.equal(result.status, 0);
  assert.match(result.stderr, /\(permanent\)/);
  assert.match(result.stderr, /PASS — no unresolved advisories/);
});

test("CLI fails when expired ignores exist", async () => {
  const expiredIgnore = {
    ...MINIMATCH_IGNORE,
    expires: "2000-01-01",
  };

  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "ignore-expired-minimatch.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [expiredIgnore] }),
    runAuditImpl: () => ({
      found: [MINIMATCH],
      unresolved: [MINIMATCH],
      ignored: [],
      unusedIgnores: [],
      expired: [expiredIgnore],
    }),
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Expired ignores \(1\):/);
  assert.match(result.stderr, /FAIL/);
});

test("CLI prints unused-ignore warning without failing", async () => {
  const unusedIgnore = {
    ghsa: "GHSA-ffff-ffff-ffff",
    package: "unused-package",
    reason: "Synthetic entry",
    expires: "2099-01-01",
    active: true,
  };

  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "unused-fake.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [unusedIgnore] }),
    runAuditImpl: () => ({
      found: [],
      unresolved: [],
      ignored: [],
      unusedIgnores: [unusedIgnore],
      expired: [],
    }),
  });

  assert.equal(result.status, 0);
  assert.match(result.stderr, /Warning: 1 ignore entry did not match any advisory/);
  assert.match(result.stderr, /PASS — no unresolved advisories/);
});

test("CLI exits 1 when config JSON is malformed", async () => {
  const invalidConfigPath = fixturePath("config", "invalid-json.json");

  const result = await runCliInProcess({
    argv: ["--config", invalidConfigPath],
    loadConfigImpl: realLoadConfig,
    runAuditImpl: () => {
      throw new Error("runAudit should not be called for invalid config");
    },
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Invalid JSON in config file/);
});

test('CLI exits 1 when "--config" value is missing', async () => {
  const result = await runCliInProcess({
    argv: ["--config"],
    loadConfigImpl: () => {
      throw new Error("loadConfig should not be called when --config is invalid");
    },
    runAuditImpl: () => {
      throw new Error("runAudit should not be called when --config is invalid");
    },
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Missing value for "--config"/);
});

test("CLI exits 1 when interactive mode is used without TTY", async () => {
  const result = await runCliInProcess({
    argv: ["-i", "--config", fixturePath("config", "empty.json")],
    loadConfigImpl: () => ({ level: "moderate", ignore: [] }),
    runAuditImpl: () => ({
      found: [AJV],
      unresolved: [AJV],
      ignored: [],
      unusedIgnores: [],
      expired: [],
    }),
    stdinIsTTY: false,
    stdoutIsTTY: false,
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /interactive mode requires a TTY terminal/i);
});

test("CLI interactive mode runs session and re-audits", async () => {
  let auditCallCount = 0;
  let interactiveCalled = false;
  const tempDir = makeTempDir("cli-interactive");
  const tempConfigPath = path.join(tempDir, "audit-config.json");

  try {
    const result = await runCliInProcess({
      argv: ["-i", "--config", tempConfigPath],
      loadConfigImpl: () => ({ level: "moderate", ignore: [] }),
      runAuditImpl: (config) => {
        auditCallCount++;
        if (auditCallCount === 1) {
          return {
            found: [AJV],
            unresolved: [AJV],
            ignored: [],
            unusedIgnores: [],
            expired: [],
          };
        }

        return {
          found: [AJV],
          unresolved: [],
          ignored: [
            {
              advisory: AJV,
              entry: (config.ignore ?? [])[0],
            },
          ],
          unusedIgnores: [],
          expired: [],
        };
      },
      runInteractiveSessionImpl: async ({ advisories, config }) => {
        interactiveCalled = true;
        config.ignore = [
          {
            ghsa: advisories[0].ghsa,
            package: advisories[0].package,
            reason: "interactive",
            expires: "2099-01-01",
            active: true,
          },
        ];
        return {
          removedInactive: 0,
          removedUnused: 0,
          reviewed: 1,
          skipped: 0,
          ignored: 1,
          added: 1,
          updated: 0,
        };
      },
    });

    assert.equal(interactiveCalled, true);
    assert.equal(auditCallCount, 2);
    assert.equal(result.status, 0);
    assert.match(result.stderr, /Interactive summary:/);
    assert.match(result.stderr, /PASS — no unresolved advisories/);
    assert.equal(fs.existsSync(tempConfigPath), true);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("CLI interactive mode can clear inactive entries without re-auditing", async () => {
  let auditCallCount = 0;
  const tempDir = makeTempDir("cli-interactive-cleanup");
  const tempConfigPath = path.join(tempDir, "audit-config.json");

  try {
    const result = await runCliInProcess({
      argv: ["-i", "--config", tempConfigPath],
      loadConfigImpl: () => ({
        level: "moderate",
        ignore: [
          {
            ghsa: "GHSA-stal-e000-0000",
            package: "stale-pkg",
            reason: "inactive",
            expires: "2099-01-01",
            active: false,
          },
        ],
      }),
      runAuditImpl: () => {
        auditCallCount++;
        return {
          found: [],
          unresolved: [],
          ignored: [],
          unusedIgnores: [],
          expired: [],
        };
      },
      runInteractiveSessionImpl: async ({ config }) => {
        config.ignore = [];
        return {
          removedInactive: 1,
          removedUnused: 0,
          reviewed: 0,
          skipped: 0,
          ignored: 0,
          added: 0,
          updated: 0,
        };
      },
    });

    assert.equal(auditCallCount, 1);
    assert.equal(result.status, 0);
    assert.match(result.stderr, /Saved interactive config changes/);
    assert.match(result.stderr, /removed 1 inactive entry/);
    assert.equal(fs.existsSync(tempConfigPath), true);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("CLI interactive mode can clear unused entries without re-auditing", async () => {
  let auditCallCount = 0;
  const tempDir = makeTempDir("cli-interactive-unused-cleanup");
  const tempConfigPath = path.join(tempDir, "audit-config.json");
  const unusedIgnore = {
    ghsa: "GHSA-unus-ed00-0000",
    package: "unused-pkg",
    reason: "unused",
    expires: "2099-01-01",
    active: true,
  };

  try {
    const result = await runCliInProcess({
      argv: ["-i", "--config", tempConfigPath],
      loadConfigImpl: () => ({
        level: "moderate",
        ignore: [unusedIgnore],
      }),
      runAuditImpl: () => {
        auditCallCount++;
        return {
          found: [],
          unresolved: [],
          ignored: [],
          unusedIgnores: [unusedIgnore],
          expired: [],
        };
      },
      runInteractiveSessionImpl: async ({ unusedIgnores, config }) => {
        assert.equal(unusedIgnores.length, 1);
        assert.equal(unusedIgnores[0], unusedIgnore);
        config.ignore = [];
        return {
          removedInactive: 0,
          removedUnused: 1,
          reviewed: 0,
          skipped: 0,
          ignored: 0,
          added: 0,
          updated: 0,
        };
      },
    });

    assert.equal(auditCallCount, 1);
    assert.equal(result.status, 0);
    assert.match(result.stderr, /Saved interactive config changes/);
    assert.match(result.stderr, /removed 1 unused entry/);
    assert.equal(fs.existsSync(tempConfigPath), true);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("--audit-level=high overrides config level", async () => {
  let auditConfig = null;
  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "empty.json"), "--audit-level=high"],
    loadConfigImpl: () => ({ level: "moderate", ignore: [] }),
    runAuditImpl: (config) => {
      auditConfig = config;
      return {
        found: [],
        unresolved: [],
        ignored: [],
        unusedIgnores: [],
        expired: [],
      };
    },
  });

  assert.equal(result.status, 0);
  assert.equal(auditConfig.level, "high");
  assert.match(result.stderr, /Severity threshold: high/);
});

test("--audit-level with space separator overrides config level", async () => {
  let auditConfig = null;
  const result = await runCliInProcess({
    argv: ["--config", fixturePath("config", "empty.json"), "--audit-level", "critical"],
    loadConfigImpl: () => ({ level: "moderate", ignore: [] }),
    runAuditImpl: (config) => {
      auditConfig = config;
      return {
        found: [],
        unresolved: [],
        ignored: [],
        unusedIgnores: [],
        expired: [],
      };
    },
  });

  assert.equal(result.status, 0);
  assert.equal(auditConfig.level, "critical");
  assert.match(result.stderr, /Severity threshold: critical/);
});

test("--audit-level with invalid value exits 1", async () => {
  const result = await runCliInProcess({
    argv: ["--audit-level=bad"],
    loadConfigImpl: () => {
      throw new Error("loadConfig should not be called for invalid --audit-level");
    },
    runAuditImpl: () => {
      throw new Error("runAudit should not be called for invalid --audit-level");
    },
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Invalid audit level "bad"/);
});

test("--audit-level without value exits 1", async () => {
  const result = await runCliInProcess({
    argv: ["--audit-level"],
    loadConfigImpl: () => {
      throw new Error("loadConfig should not be called for missing --audit-level value");
    },
    runAuditImpl: () => {
      throw new Error("runAudit should not be called for missing --audit-level value");
    },
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Missing value for "--audit-level"/);
});

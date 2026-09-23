const assert = require("node:assert/strict");
const path = require("node:path");
const childProcess = require("node:child_process");
const { readFixture } = require("./helpers/fs-utils.cjs");

const auditModulePath = path.resolve(__dirname, "..", "dist", "audit.js");

function createExecStatusOne(payload) {
  return () => {
    const err = new Error("npm audit found vulnerabilities");
    err.status = 1;
    err.stdout = payload;
    throw err;
  };
}

function createExecOperationalError(status, stderr) {
  return () => {
    const err = new Error("npm audit failed");
    err.status = status;
    err.stderr = stderr;
    throw err;
  };
}

function unloadAuditModule() {
  delete require.cache[require.resolve(auditModulePath)];
}

function withRunAudit(execSyncImpl, fn) {
  const originalExecSync = childProcess.execSync;
  childProcess.execSync = execSyncImpl;
  unloadAuditModule();
  const runAudit = require(auditModulePath).runAudit;

  try {
    fn(runAudit);
  } finally {
    childProcess.execSync = originalExecSync;
    unloadAuditModule();
  }
}

test("runAudit handles clean npm audit output (exit 0)", () => {
  withRunAudit(() => readFixture("audit", "clean.json"), (runAudit) => {
    const result = runAudit({ level: "moderate", ignore: [] });
    assert.equal(result.found.length, 0);
    assert.equal(result.unresolved.length, 0);
    assert.equal(result.ignored.length, 0);
    assert.equal(result.unusedIgnores.length, 0);
    assert.equal(result.expired.length, 0);
  });
});

test("runAudit treats exit code 1 as valid vulnerability output", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "two-advisories.json")), (runAudit) => {
    const result = runAudit({ level: "moderate", ignore: [] });
    assert.equal(result.found.length, 2);
    assert.equal(result.unresolved.length, 2);
    assert.equal(result.found.some((a) => a.ghsa === "GHSA-2g4f-4pwh-qvx6"), true);
    assert.equal(result.found.some((a) => a.ghsa === "GHSA-3ppc-4f35-3m26"), true);
  });
});

test("runAudit deduplicates advisories by GHSA ID", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "duplicate-ghsa.json")), (runAudit) => {
    const result = runAudit({ level: "low", ignore: [] });
    assert.equal(result.found.length, 1);
    assert.equal(result.found[0].ghsa, "GHSA-2g4f-4pwh-qvx6");
  });
});

test("runAudit ignores string entries in via[] and processes object entries", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "via-mixed.json")), (runAudit) => {
    const result = runAudit({ level: "moderate", ignore: [] });
    assert.equal(result.found.length, 1);
    assert.equal(result.found[0].ghsa, "GHSA-vp9h-6m8m-g4v8");
  });
});

test("runAudit applies active non-expired ignores and reports unused ignores", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "two-advisories.json")), (runAudit) => {
    const result = runAudit({
      level: "moderate",
      ignore: [
        {
          ghsa: "GHSA-3ppc-4f35-3m26",
          package: "minimatch",
          reason: "Accepted temporarily",
          expires: "2099-01-01",
          active: true,
        },
        {
          ghsa: "GHSA-ffff-ffff-ffff",
          package: "unused",
          reason: "Unused by design",
          expires: "2099-01-01",
          active: true,
        },
      ],
    });

    assert.equal(result.ignored.length, 1);
    assert.equal(result.unresolved.length, 1);
    assert.equal(result.unusedIgnores.length, 1);
    assert.equal(result.ignored[0].advisory.ghsa, "GHSA-3ppc-4f35-3m26");
    assert.equal(result.unresolved[0].ghsa, "GHSA-2g4f-4pwh-qvx6");
  });
});

test("runAudit applies permanent ignores without expires", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "two-advisories.json")), (runAudit) => {
    const result = runAudit({
      level: "moderate",
      ignore: [
        {
          ghsa: "GHSA-3ppc-4f35-3m26",
          package: "minimatch",
          reason: "Patched locally",
          permanent: true,
          active: true,
        },
      ],
    });

    assert.equal(result.expired.length, 0);
    assert.equal(result.ignored.length, 1);
    assert.equal(result.unresolved.length, 1);
    assert.equal(result.ignored[0].advisory.ghsa, "GHSA-3ppc-4f35-3m26");
  });
});

test("runAudit marks expired ignores and does not apply them", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "two-advisories.json")), (runAudit) => {
    const result = runAudit({
      level: "moderate",
      ignore: [
        {
          ghsa: "GHSA-3ppc-4f35-3m26",
          package: "minimatch",
          reason: "Expired entry",
          expires: "2000-01-01",
          active: true,
        },
      ],
    });

    assert.equal(result.expired.length, 1);
    assert.equal(result.ignored.length, 0);
    assert.equal(result.unresolved.some((a) => a.ghsa === "GHSA-3ppc-4f35-3m26"), true);
  });
});

test("runAudit turns non-GHSA URLs into unknown-* advisories", () => {
  withRunAudit(createExecStatusOne(readFixture("audit", "unmatchable-url.json")), (runAudit) => {
    const result = runAudit({ level: "moderate", ignore: [] });
    assert.equal(result.found.length, 1);
    assert.equal(result.found[0].ghsa, "unknown-77777");
    assert.equal(result.unresolved.length, 1);
  });
});

test("runAudit throws on operational npm audit error (non-0/1 exit)", () => {
  withRunAudit(createExecOperationalError(2, "registry timed out"), (runAudit) => {
    assert.throws(() => runAudit({ level: "moderate", ignore: [] }), /npm audit failed \(exit code 2\): registry timed out/);
  });
});

test("runAudit throws when npm audit output is not valid JSON", () => {
  withRunAudit(() => readFixture("audit", "invalid-output.txt"), (runAudit) => {
    assert.throws(() => runAudit({ level: "moderate", ignore: [] }), /Failed to parse npm audit JSON output/);
  });
});

test("runAudit rejects null entries in via[] instead of silently skipping them", () => {
  const payload = JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {
      sample: {
        name: "sample",
        severity: "high",
        via: [
          null,
          {
            source: 900001,
            name: "sample",
            dependency: "sample",
            title: "Sample advisory",
            url: "https://github.com/advisories/GHSA-ab12-cd34-ef56",
            severity: "high",
            range: "*",
          },
        ],
        effects: [],
        isDirect: false,
        fixAvailable: false,
      },
    },
  });

  withRunAudit(createExecStatusOne(payload), (runAudit) => {
    assert.throws(() => runAudit({ level: "low", ignore: [] }), /invalid advisory for "sample"/);
  });
});

test.each([
  ["missing URL", (advisory) => { delete advisory.url; }],
  ["empty URL", (advisory) => { advisory.url = ""; }],
  ["unknown severity", (advisory) => { advisory.severity = "severe"; }],
  ["missing source", (advisory) => { delete advisory.source; }],
])("runAudit rejects an advisory with %s", (_name, mutate) => {
  const payload = JSON.parse(readFixture("audit", "two-advisories.json"));
  mutate(Object.values(payload.vulnerabilities)[0].via[0]);
  withRunAudit(() => JSON.stringify(payload), (runAudit) => {
    assert.throws(() => runAudit({ level: "critical", ignore: [] }), /invalid advisory/);
  });
});

test.each([
  ["unsupported report version", { auditReportVersion: 3, vulnerabilities: {} }, /auditReportVersion 2/],
  ["error response", { auditReportVersion: 2, vulnerabilities: {}, error: { code: "E503" } }, /error response/],
  ["missing via", { auditReportVersion: 2, vulnerabilities: { sample: {} } }, /invalid via array/],
  ["empty via", { auditReportVersion: 2, vulnerabilities: { sample: { via: [] } } }, /invalid via array/],
  ["unknown reference", { auditReportVersion: 2, vulnerabilities: { sample: { via: ["missing"] } } }, /unknown via reference/],
])("runAudit rejects %s", (_name, payload, expected) => {
  withRunAudit(() => JSON.stringify(payload), (runAudit) => {
    assert.throws(() => runAudit({ ignore: [] }), expected);
  });
});

test("runAudit never applies an ignore to a synthetic unknown identifier", () => {
  withRunAudit(() => readFixture("audit", "unmatchable-url.json"), (runAudit) => {
    const result = runAudit({ ignore: [{ ghsa: "unknown-77777", package: "mystery-package", reason: "Manual entry", permanent: true }] });
    assert.equal(result.ignored.length, 0);
    assert.equal(result.unresolved[0].ghsa, "unknown-77777");
  });
});

test("runAudit preserves ignores for advisories below a run-only severity threshold", () => {
  withRunAudit(() => readFixture("audit", "two-advisories.json"), (runAudit) => {
    const result = runAudit({
      level: "critical",
      ignore: [{ ghsa: "GHSA-2g4f-4pwh-qvx6", package: "ajv", reason: "Accepted", permanent: true }],
    });
    assert.equal(result.found.length, 0);
    assert.equal(result.unusedIgnores.length, 0);
  });
});

test("runAudit handles GHSA URLs with trailing slash and query string", () => {
  const payload = JSON.stringify({
    auditReportVersion: 2,
    vulnerabilities: {
      sample: {
        name: "sample",
        severity: "high",
        via: [
          {
            source: 900002,
            name: "sample",
            dependency: "sample",
            title: "Sample advisory",
            url: "https://github.com/advisories/GHSA-ab12-cd34-ef56/?foo=bar",
            severity: "high",
            range: "*",
          },
        ],
        effects: [],
        isDirect: false,
        fixAvailable: false,
      },
    },
  });

  withRunAudit(createExecStatusOne(payload), (runAudit) => {
    const result = runAudit({
      level: "low",
      ignore: [
        {
          ghsa: "GHSA-ab12-cd34-ef56",
          package: "sample",
          reason: "Test ignore",
          expires: "2099-01-01",
          active: true,
        },
      ],
    });

    assert.equal(result.found.length, 1);
    assert.equal(result.unresolved.length, 0);
    assert.equal(result.ignored.length, 1);
    assert.equal(result.ignored[0].advisory.ghsa, "GHSA-ab12-cd34-ef56");
  });
});

test('runAudit throws a clear error when "vulnerabilities" is missing', () => {
  const payload = JSON.stringify({
    auditReportVersion: 2,
  });

  withRunAudit(() => payload, (runAudit) => {
    assert.throws(
      () => runAudit({ level: "moderate", ignore: [] }),
      /Unexpected npm audit JSON format: missing "vulnerabilities" object/
    );
  });
});

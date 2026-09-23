const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { loadConfig, removeIgnoreEntries, removeInactiveIgnoreEntries, saveConfig, upsertIgnoreEntry } = require("../dist/config.js");
const { makeTempDir, fixturePath } = require("./helpers/fs-utils.cjs");

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

test("loadConfig returns default config when file is missing and does not create a file", () => {
  const dir = makeTempDir("config-missing");
  const configPath = path.join(dir, "audit-config.json");

  try {
    const config = loadConfig(configPath);
    assert.deepEqual(config, { level: "moderate", ignore: [] });
    assert.equal(fs.existsSync(configPath), false);
  } finally {
    cleanup(dir);
  }
});

test("loadConfig throws for invalid JSON", () => {
  const configPath = fixturePath("config", "invalid-json.json");
  assert.throws(() => loadConfig(configPath), /Invalid JSON in config file/);
});

test("loadConfig throws for invalid severity level", () => {
  const configPath = fixturePath("config", "invalid-schema-level.json");
  assert.throws(() => loadConfig(configPath), /Invalid level "medium"/);
});

test.each([
  [null, /entry must be a JSON object/],
  [{ ghsa: "unknown-77777", package: "demo", reason: "Accepted", permanent: true }, /must be a GHSA/],
  [{ ghsa: "GHSA-abcd-efgh-ijkl", package: "demo", reason: "   ", permanent: true }, /"reason" is required/],
])("loadConfig rejects malformed ignore entry %j", (entry, expected) => {
  const dir = makeTempDir("config-invalid-entry");
  const configPath = path.join(dir, "audit-config.json");
  try {
    fs.writeFileSync(configPath, JSON.stringify({ ignore: [entry] }));
    assert.throws(() => loadConfig(configPath), expected);
  } finally {
    cleanup(dir);
  }
});

test("loadConfig throws for invalid calendar date", () => {
  const configPath = fixturePath("config", "invalid-calendar-date.json");
  assert.throws(() => loadConfig(configPath), /"expires" is not a valid date/);
});

test("loadConfig defaults ignore.active to true when omitted", () => {
  const configPath = fixturePath("config", "valid-active-default.json");
  const config = loadConfig(configPath);
  assert.equal(config.ignore?.[0]?.active, true);
});

test("loadConfig keeps ignore.active=false when provided", () => {
  const configPath = fixturePath("config", "inactive-minimatch.json");
  const config = loadConfig(configPath);
  assert.equal(config.ignore?.[0]?.active, false);
});

test("loadConfig supports permanent ignores without expires", () => {
  const configPath = fixturePath("config", "permanent-ignore.json");
  const config = loadConfig(configPath);
  assert.equal(config.ignore?.[0]?.permanent, true);
  assert.equal(config.ignore?.[0]?.expires, undefined);
});

test("loadConfig throws when ignore has neither expires nor permanent=true", () => {
  const configPath = fixturePath("config", "invalid-missing-expiry-or-permanent.json");
  assert.throws(() => loadConfig(configPath), /either "expires" or "permanent": true is required/);
});

test("loadConfig throws when permanent ignore also sets expires", () => {
  const configPath = fixturePath("config", "invalid-permanent-with-expiry.json");
  assert.throws(() => loadConfig(configPath), /"expires" must be omitted when "permanent" is true/);
});

test("upsertIgnoreEntry adds new ignore entry", () => {
  const config = { level: "moderate", ignore: [] };
  const result = upsertIgnoreEntry(config, {
    ghsa: "GHSA-abcd-efgh-ijkl",
    package: "demo",
    reason: "added",
    expires: "2099-01-01",
    active: true,
  });

  assert.equal(result, "added");
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].ghsa, "GHSA-abcd-efgh-ijkl");
});

test("upsertIgnoreEntry updates existing ignore entry case-insensitively", () => {
  const config = {
    level: "moderate",
    ignore: [
      {
        ghsa: "ghsa-abcd-efgh-ijkl",
        package: "old",
        reason: "old",
        expires: "2099-01-01",
        active: false,
      },
    ],
  };

  const result = upsertIgnoreEntry(config, {
    ghsa: "GHSA-ABCD-EFGH-IJKL",
    package: "new",
    reason: "new",
    expires: "2099-02-01",
    active: true,
  });

  assert.equal(result, "updated");
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].package, "new");
  assert.equal(config.ignore[0].active, true);
});

test("removeInactiveIgnoreEntries removes inactive entries and returns removed count", () => {
  const config = {
    level: "moderate",
    ignore: [
      {
        ghsa: "GHSA-abcd-efgh-ijkl",
        package: "demo-a",
        reason: "inactive",
        expires: "2099-01-01",
        active: false,
      },
      {
        ghsa: "GHSA-mnop-qrst-uvwx",
        package: "demo-b",
        reason: "active",
        expires: "2099-01-01",
        active: true,
      },
    ],
  };

  const removed = removeInactiveIgnoreEntries(config);

  assert.equal(removed, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].ghsa, "GHSA-mnop-qrst-uvwx");
});

test("removeInactiveIgnoreEntries leaves config unchanged when no inactive entries exist", () => {
  const config = {
    level: "moderate",
    ignore: [
      {
        ghsa: "GHSA-mnop-qrst-uvwx",
        package: "demo-b",
        reason: "active",
        expires: "2099-01-01",
        active: true,
      },
    ],
  };

  const removed = removeInactiveIgnoreEntries(config);

  assert.equal(removed, 0);
  assert.equal(config.ignore.length, 1);
});

test("removeIgnoreEntries removes the provided entries by reference", () => {
  const staleEntry = {
    ghsa: "GHSA-abcd-efgh-ijkl",
    package: "demo-a",
    reason: "stale",
    expires: "2099-01-01",
    active: true,
  };
  const keepEntry = {
    ghsa: "GHSA-mnop-qrst-uvwx",
    package: "demo-b",
    reason: "keep",
    expires: "2099-01-01",
    active: true,
  };
  const config = {
    level: "moderate",
    ignore: [staleEntry, keepEntry],
  };

  const removed = removeIgnoreEntries(config, [staleEntry]);

  assert.equal(removed, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0], keepEntry);
});

test("saveConfig writes config file that loadConfig can read", () => {
  const dir = makeTempDir("config-save");
  const configPath = path.join(dir, "audit-config.json");

  try {
    saveConfig(configPath, {
      level: "high",
      ignore: [
        {
          ghsa: "GHSA-abcd-efgh-ijkl",
          package: "demo",
          reason: "saved",
          expires: "2099-01-01",
          active: true,
        },
      ],
    });

    const loaded = loadConfig(configPath);
    assert.equal(loaded.level, "high");
    assert.equal(loaded.ignore?.length, 1);
    assert.equal(loaded.ignore?.[0]?.ghsa, "GHSA-abcd-efgh-ijkl");
  } finally {
    cleanup(dir);
  }
});

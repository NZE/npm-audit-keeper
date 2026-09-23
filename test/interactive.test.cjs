const assert = require("node:assert/strict");
const { calculateExpiryDate, runInteractiveSession } = require("../dist/interactive.js");

function createAskFromAnswers(answers) {
  const queue = [...answers];
  return async () => {
    if (queue.length === 0) {
      throw new Error("No more scripted answers");
    }
    return queue.shift();
  };
}

const ADVISORY = {
  ghsa: "GHSA-ab12-cd34-ef56",
  package: "demo-pkg",
  severity: "high",
  title: "Demo advisory",
  url: "https://github.com/advisories/GHSA-ab12-cd34-ef56",
};

test("calculateExpiryDate supports day/week/month windows", () => {
  const now = new Date("2026-02-23T12:00:00Z");
  assert.equal(calculateExpiryDate(now, "D"), "2026-02-24");
  assert.equal(calculateExpiryDate(now, "W"), "2026-03-02");
  assert.equal(calculateExpiryDate(now, "M"), "2026-03-23");
});

test("runInteractiveSession skips advisory on 's'", async () => {
  const config = { level: "moderate", ignore: [] };
  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    config,
    ask: createAskFromAnswers(["s"]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.reviewed, 1);
  assert.equal(session.skipped, 1);
  assert.equal(session.ignored, 0);
  assert.equal(config.ignore.length, 0);
});

test("runInteractiveSession ignores advisory and adds entry", async () => {
  const config = { level: "moderate", ignore: [] };
  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    config,
    ask: createAskFromAnswers(["i", "m", "Not exposed to untrusted input"]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.ignored, 1);
  assert.equal(session.added, 1);
  assert.equal(session.updated, 0);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].expires, "2026-03-23");
  assert.equal(config.ignore[0].active, true);
  assert.equal(config.ignore[0].reason, "Not exposed to untrusted input");
});

test("runInteractiveSession supports permanent ignore choice", async () => {
  const config = { level: "moderate", ignore: [] };
  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    config,
    ask: createAskFromAnswers(["i", "p", "Patched locally"]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.ignored, 1);
  assert.equal(session.added, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].permanent, true);
  assert.equal(config.ignore[0].expires, undefined);
  assert.equal(config.ignore[0].reason, "Patched locally");
});

test("runInteractiveSession re-prompts on invalid inputs", async () => {
  const config = { level: "moderate", ignore: [] };
  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    config,
    ask: createAskFromAnswers(["x", "i", "q", "w", "", "   ", "  Upgrade scheduled  "]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.ignored, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].expires, "2026-03-02");
  assert.equal(config.ignore[0].reason, "Upgrade scheduled");
});

test("runInteractiveSession updates existing ignore entry for same GHSA", async () => {
  const config = {
    level: "moderate",
    ignore: [
      {
        ghsa: "ghsa-ab12-cd34-ef56",
        package: "old",
        reason: "old",
        expires: "2099-01-01",
        active: false,
      },
    ],
  };

  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    config,
    ask: createAskFromAnswers(["n", "i", "d", ""]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.ignored, 1);
  assert.equal(session.added, 0);
  assert.equal(session.updated, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].package, "demo-pkg");
  assert.equal(config.ignore[0].expires, "2026-02-24");
  assert.equal(config.ignore[0].active, true);
  assert.equal(config.ignore[0].reason, "old");
});

test("runInteractiveSession offers to clear inactive ignore entries", async () => {
  const config = {
    level: "moderate",
    ignore: [
      {
        ghsa: "GHSA-abcd-efgh-ijkl",
        package: "stale-pkg",
        reason: "inactive",
        expires: "2099-01-01",
        active: false,
      },
      {
        ghsa: "GHSA-mnop-qrst-uvwx",
        package: "live-pkg",
        reason: "active",
        expires: "2099-01-01",
        active: true,
      },
    ],
  };

  const session = await runInteractiveSession({
    advisories: [],
    config,
    ask: createAskFromAnswers(["y"]),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 1);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.reviewed, 0);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].ghsa, "GHSA-mnop-qrst-uvwx");
});

test("runInteractiveSession can clear inactive entries before triaging advisories", async () => {
  const config = {
    level: "moderate",
    ignore: [
      {
        ghsa: "GHSA-old0-inac-tive",
        package: "stale-pkg",
        reason: "inactive",
        expires: "2099-01-01",
        active: false,
      },
    ],
  };

  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    config,
    ask: createAskFromAnswers(["y", "i", "d", "Upgrade scheduled"]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 1);
  assert.equal(session.removedUnused, 0);
  assert.equal(session.ignored, 1);
  assert.equal(session.added, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].ghsa, ADVISORY.ghsa);
  assert.equal(config.ignore[0].expires, "2026-02-24");
});

test("runInteractiveSession offers to clear unused ignore entries", async () => {
  const staleEntry = {
    ghsa: "GHSA-stal-e000-0000",
    package: "stale-pkg",
    reason: "unused",
    expires: "2099-01-01",
    active: true,
  };
  const keepEntry = {
    ghsa: "GHSA-live-e000-0000",
    package: "live-pkg",
    reason: "keep",
    expires: "2099-01-01",
    active: true,
  };
  const config = {
    level: "moderate",
    ignore: [staleEntry, keepEntry],
  };

  const session = await runInteractiveSession({
    advisories: [],
    unusedIgnores: [staleEntry],
    config,
    ask: createAskFromAnswers(["y"]),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 1);
  assert.equal(session.reviewed, 0);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0], keepEntry);
});

test("runInteractiveSession can clear unused entries before triaging advisories", async () => {
  const staleEntry = {
    ghsa: "GHSA-stal-e000-0000",
    package: "stale-pkg",
    reason: "unused",
    expires: "2099-01-01",
    active: true,
  };
  const config = {
    level: "moderate",
    ignore: [staleEntry],
  };

  const session = await runInteractiveSession({
    advisories: [ADVISORY],
    unusedIgnores: [staleEntry],
    config,
    ask: createAskFromAnswers(["y", "i", "w", "Upgrade scheduled"]),
    now: new Date("2026-02-23T00:00:00Z"),
    log: () => undefined,
  });

  assert.equal(session.removedInactive, 0);
  assert.equal(session.removedUnused, 1);
  assert.equal(session.ignored, 1);
  assert.equal(session.added, 1);
  assert.equal(config.ignore.length, 1);
  assert.equal(config.ignore[0].ghsa, ADVISORY.ghsa);
  assert.equal(config.ignore[0].expires, "2026-03-02");
});

test.each([
  ["2026-01-31", "2026-02-28"],
  ["2028-01-31", "2028-02-29"],
  ["2026-03-31", "2026-04-30"],
  ["2026-12-31", "2027-01-31"],
])("month expiry from %s is clamped to %s", (date, expected) => {
  assert.equal(calculateExpiryDate(new Date(`${date}T12:00:00Z`), "M"), expected);
});

test("interactive mode cannot create ignores for non-GHSA advisories", async () => {
  const config = { ignore: [] };
  const messages = [];
  const result = await runInteractiveSession({
    advisories: [{ ...ADVISORY, ghsa: "unknown-77777" }],
    config,
    ask: async () => { throw new Error("Non-GHSA advisories must not offer ignore prompts"); },
    log: (message) => messages.push(message),
  });
  assert.equal(result.ignored, 0);
  assert.equal(result.skipped, 1);
  assert.equal(config.ignore.length, 0);
  assert.match(messages.join("\n"), /cannot be ignored/);
});

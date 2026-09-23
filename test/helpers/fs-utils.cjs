const fs = require("node:fs");
const path = require("node:path");

const PROJECT_ROOT = path.resolve(__dirname, "..", "..");
const FIXTURE_ROOT = path.join(PROJECT_ROOT, "test", "fixtures");
const TMP_ROOT = path.join(PROJECT_ROOT, "test", ".tmp");

function ensureTmpRoot() {
  fs.mkdirSync(TMP_ROOT, { recursive: true });
}

function makeTempDir(prefix) {
  ensureTmpRoot();
  return fs.mkdtempSync(path.join(TMP_ROOT, `${prefix}-`));
}

function fixturePath(...parts) {
  return path.join(FIXTURE_ROOT, ...parts);
}

function readFixture(...parts) {
  return fs.readFileSync(fixturePath(...parts), "utf-8");
}

module.exports = {
  makeTempDir,
  fixturePath,
  readFixture,
};

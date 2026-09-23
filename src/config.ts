import * as fs from "node:fs";
import * as path from "node:path";
import type { AuditConfig, IgnoreEntry } from "./types.js";

export const VALID_LEVELS = ["low", "moderate", "high", "critical"];
export const GHSA_REGEX = /^GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}$/i;
const DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;

function getDefaultConfig(): AuditConfig {
  return { level: "moderate", ignore: [] };
}

function validateIgnoreEntry(entry: unknown, index: number): IgnoreEntry {
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new Error(`ignore[${index}]: entry must be a JSON object`);
  }
  const e = entry as Record<string, unknown>;

  if (!e.ghsa || typeof e.ghsa !== "string") {
    throw new Error(`ignore[${index}]: "ghsa" is required and must be a string`);
  }
  if (!GHSA_REGEX.test(e.ghsa)) {
    throw new Error(`ignore[${index}]: "ghsa" must be a GHSA-xxxx-xxxx-xxxx identifier`);
  }
  if (typeof e.package !== "string" || !e.package.trim()) {
    throw new Error(`ignore[${index}]: "package" is required and must be a string`);
  }
  if (typeof e.reason !== "string" || !e.reason.trim()) {
    throw new Error(`ignore[${index}]: "reason" is required and must be a string`);
  }
  if (e.permanent !== undefined && typeof e.permanent !== "boolean") {
    throw new Error(`ignore[${index}]: "permanent" must be a boolean if provided`);
  }
  if (e.expires !== undefined && typeof e.expires !== "string") {
    throw new Error(`ignore[${index}]: "expires" must be a string if provided`);
  }

  const permanent = e.permanent === true;
  const expires = typeof e.expires === "string" ? e.expires : undefined;
  const hasExpires = expires !== undefined;

  if (permanent && hasExpires) {
    throw new Error(`ignore[${index}]: "expires" must be omitted when "permanent" is true`);
  }
  if (!permanent && !hasExpires) {
    throw new Error(`ignore[${index}]: either "expires" or "permanent": true is required`);
  }
  if (hasExpires && !DATE_REGEX.test(expires)) {
    throw new Error(`ignore[${index}]: "expires" must be in YYYY-MM-DD format, got "${expires}"`);
  }
  if (hasExpires && !isStrictUtcDate(expires)) {
    throw new Error(`ignore[${index}]: "expires" is not a valid date: "${expires}"`);
  }
  if (e.active !== undefined && typeof e.active !== "boolean") {
    throw new Error(`ignore[${index}]: "active" must be a boolean if provided`);
  }

  const normalized: IgnoreEntry = {
    ghsa: e.ghsa,
    package: e.package,
    reason: e.reason.trim(),
    active: e.active === undefined ? true : e.active,
  };

  if (permanent) {
    normalized.permanent = true;
  } else {
    normalized.expires = expires;
  }

  return normalized;
}

function isStrictUtcDate(value: string): boolean {
  const [yearRaw, monthRaw, dayRaw] = value.split("-");
  const year = Number(yearRaw);
  const month = Number(monthRaw);
  const day = Number(dayRaw);

  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) {
    return false;
  }

  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function validateConfig(raw: unknown): AuditConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("Config must be a JSON object");
  }

  const obj = raw as Record<string, unknown>;

  const level = obj.level !== undefined ? String(obj.level) : "moderate";
  if (!VALID_LEVELS.includes(level)) {
    throw new Error(`Invalid level "${level}". Must be one of: ${VALID_LEVELS.join(", ")}`);
  }

  const ignore: IgnoreEntry[] = [];
  if (obj.ignore !== undefined) {
    if (!Array.isArray(obj.ignore)) {
      throw new Error(`"ignore" must be an array`);
    }
    for (let i = 0; i < obj.ignore.length; i++) {
      ignore.push(validateIgnoreEntry(obj.ignore[i], i));
    }
  }

  return { level, ignore };
}

export function loadConfig(configPath: string): AuditConfig {
  const resolved = path.resolve(configPath);

  if (!fs.existsSync(resolved)) {
    return getDefaultConfig();
  }

  let raw: string;
  try {
    raw = fs.readFileSync(resolved, "utf-8");
  } catch (err) {
    throw new Error(`Failed to read config file: ${resolved}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`Invalid JSON in config file: ${resolved}`);
  }

  return validateConfig(parsed);
}

export function saveConfig(configPath: string, config: AuditConfig): void {
  const resolved = path.resolve(configPath);
  const dir = path.dirname(resolved);
  const serialized = JSON.stringify(
    {
      level: config.level ?? "moderate",
      ignore: config.ignore ?? [],
    },
    null,
    2
  ) + "\n";

  const tmpPath = `${resolved}.tmp-${process.pid}-${Date.now()}`;
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tmpPath, serialized, "utf-8");
    fs.renameSync(tmpPath, resolved);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {
      // Best-effort cleanup.
    }
    throw new Error(`Failed to write config file: ${resolved}: ${(err as Error).message}`);
  }
}

export function upsertIgnoreEntry(config: AuditConfig, entry: IgnoreEntry): "added" | "updated" {
  if (!config.ignore) {
    config.ignore = [];
  }

  const key = entry.ghsa.toUpperCase();
  const existingIndex = config.ignore.findIndex((item) => item.ghsa.toUpperCase() === key);

  if (existingIndex >= 0) {
    config.ignore[existingIndex] = entry;
    return "updated";
  }

  config.ignore.push(entry);
  return "added";
}

export function removeInactiveIgnoreEntries(config: AuditConfig): number {
  const ignores = config.ignore ?? [];
  const nextIgnore = ignores.filter((entry) => entry.active !== false);
  const removed = ignores.length - nextIgnore.length;

  if (removed > 0) {
    config.ignore = nextIgnore;
  }

  return removed;
}

export function removeIgnoreEntries(config: AuditConfig, entriesToRemove: IgnoreEntry[]): number {
  if (entriesToRemove.length === 0) {
    return 0;
  }

  const ignores = config.ignore ?? [];
  const entriesToRemoveSet = new Set(entriesToRemove);
  const nextIgnore = ignores.filter((entry) => !entriesToRemoveSet.has(entry));
  const removed = ignores.length - nextIgnore.length;

  if (removed > 0) {
    config.ignore = nextIgnore;
  }

  return removed;
}

import * as readline from "node:readline/promises";
import type { AuditConfig, Advisory, IgnoreEntry } from "./types.js";
import { GHSA_REGEX, removeIgnoreEntries, removeInactiveIgnoreEntries, upsertIgnoreEntry } from "./config.js";

export type IgnorePeriod = "M" | "W" | "D";
type IgnoreChoice = IgnorePeriod | "P";

export interface InteractiveSessionResult {
  removedInactive: number;
  removedUnused: number;
  reviewed: number;
  skipped: number;
  ignored: number;
  added: number;
  updated: number;
}

interface InteractiveSessionOptions {
  advisories: Advisory[];
  config: AuditConfig;
  unusedIgnores?: IgnoreEntry[];
  now?: Date;
  ask?: (prompt: string) => Promise<string>;
  log?: (message: string) => void;
}

function utcDateOnly(date: Date): Date {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
}

function formatDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

export function calculateExpiryDate(now: Date, period: IgnorePeriod): string {
  const base = utcDateOnly(now);
  const expiry = new Date(base);

  switch (period) {
    case "D":
      expiry.setUTCDate(expiry.getUTCDate() + 1);
      break;
    case "W":
      expiry.setUTCDate(expiry.getUTCDate() + 7);
      break;
    case "M": {
      const day = expiry.getUTCDate();
      expiry.setUTCDate(1);
      expiry.setUTCMonth(expiry.getUTCMonth() + 1);
      const lastDay = new Date(Date.UTC(expiry.getUTCFullYear(), expiry.getUTCMonth() + 1, 0)).getUTCDate();
      expiry.setUTCDate(Math.min(day, lastDay));
      break;
    }
  }

  return formatDate(expiry);
}

function normalizeChoice(input: string): string {
  return input.trim().toUpperCase();
}

async function promptAction(ask: (prompt: string) => Promise<string>, log: (message: string) => void): Promise<"S" | "I"> {
  for (;;) {
    const answer = normalizeChoice(await ask("Choose action: [s] skip, [i] ignore: "));
    if (answer === "S" || answer === "I") {
      return answer;
    }
    log("Invalid choice. Enter 's' to skip or 'i' to ignore.");
  }
}

async function promptPeriod(ask: (prompt: string) => Promise<string>, log: (message: string) => void): Promise<IgnoreChoice> {
  for (;;) {
    const answer = normalizeChoice(await ask("Choose ignore period: [P] permanent, [M] month, [W] week, [D] day: "));
    if (answer === "P" || answer === "M" || answer === "W" || answer === "D") {
      return answer;
    }
    log("Invalid choice. Enter 'P', 'M', 'W', or 'D'.");
  }
}

async function promptClearInactive(ask: (prompt: string) => Promise<string>, log: (message: string) => void): Promise<boolean> {
  for (;;) {
    const answer = normalizeChoice(await ask("Clear inactive ignore entries? [y] yes, [n] no: "));
    if (answer === "Y") {
      return true;
    }
    if (answer === "N") {
      return false;
    }
    log("Invalid choice. Enter 'y' to clear inactive entries or 'n' to keep them.");
  }
}

async function promptClearUnused(ask: (prompt: string) => Promise<string>, log: (message: string) => void): Promise<boolean> {
  for (;;) {
    const answer = normalizeChoice(await ask("Clear unused active ignore entries? [y] yes, [n] no: "));
    if (answer === "Y") {
      return true;
    }
    if (answer === "N") {
      return false;
    }
    log("Invalid choice. Enter 'y' to clear unused entries or 'n' to keep them.");
  }
}

async function promptReason(ask: (prompt: string) => Promise<string>, log: (message: string) => void, existing?: string): Promise<string> {
  for (;;) {
    const answer = (await ask(existing ? `Reason (Enter to keep "${existing}"): ` : "Reason for accepting this risk: ")).trim();
    if (answer) return answer;
    if (existing?.trim()) return existing.trim();
    log("A non-empty reason is required.");
  }
}

function buildInteractiveEntry(advisory: Advisory, period: IgnoreChoice, now: Date, reason: string): IgnoreEntry {
  if (period === "P") {
    return {
      ghsa: advisory.ghsa,
      package: advisory.package,
      reason,
      permanent: true,
      active: true,
    };
  }

  return {
    ghsa: advisory.ghsa,
    package: advisory.package,
    reason,
    expires: calculateExpiryDate(now, period),
    active: true,
  };
}

async function withDefaultReadline<T>(run: (ask: (prompt: string) => Promise<string>) => Promise<T>): Promise<T> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    return await run((prompt) => rl.question(prompt));
  } finally {
    rl.close();
  }
}

export async function runInteractiveSession(options: InteractiveSessionOptions): Promise<InteractiveSessionResult> {
  const advisories = options.advisories;
  const config = options.config;
  const unusedIgnores = options.unusedIgnores ?? [];
  const now = options.now ?? new Date();
  const log = options.log ?? ((message: string) => console.error(message));

  const result: InteractiveSessionResult = {
    removedInactive: 0,
    removedUnused: 0,
    reviewed: advisories.length,
    skipped: 0,
    ignored: 0,
    added: 0,
    updated: 0,
  };

  const runner = async (ask: (prompt: string) => Promise<string>) => {
    const inactiveCount = (config.ignore ?? []).filter((entry) => entry.active === false).length;
    if (inactiveCount > 0) {
      log("");
      log(`Found ${inactiveCount} inactive ignore entr${inactiveCount === 1 ? "y" : "ies"} in config.`);
      const shouldClearInactive = await promptClearInactive(ask, log);
      if (shouldClearInactive) {
        result.removedInactive = removeInactiveIgnoreEntries(config);
        log(`Removed ${result.removedInactive} inactive ignore entr${result.removedInactive === 1 ? "y" : "ies"}.`);
      }
    }

    if (unusedIgnores.length > 0) {
      log("");
      log(`Found ${unusedIgnores.length} unused active ignore entr${unusedIgnores.length === 1 ? "y" : "ies"} in config.`);
      const shouldClearUnused = await promptClearUnused(ask, log);
      if (shouldClearUnused) {
        result.removedUnused = removeIgnoreEntries(config, unusedIgnores);
        log(`Removed ${result.removedUnused} unused ignore entr${result.removedUnused === 1 ? "y" : "ies"}.`);
      }
    }

    for (let index = 0; index < advisories.length; index++) {
      const advisory = advisories[index];
      log("");
      log(`[${index + 1}/${advisories.length}] ${advisory.ghsa}  ${advisory.severity}  ${advisory.package}`);
      log(`  ${advisory.title}`);
      log(`  ${advisory.url}`);

      if (!GHSA_REGEX.test(advisory.ghsa)) {
        log("This advisory has no GHSA identifier and cannot be ignored. It remains unresolved.");
        result.skipped++;
        continue;
      }

      const action = await promptAction(ask, log);
      if (action === "S") {
        result.skipped++;
        continue;
      }

      const period = await promptPeriod(ask, log);
      const existing = (config.ignore ?? []).find((entry) => entry.ghsa.toUpperCase() === advisory.ghsa.toUpperCase());
      const reason = await promptReason(ask, log, existing?.reason);
      const entry = buildInteractiveEntry(advisory, period, now, reason);
      const upsertResult = upsertIgnoreEntry(config, entry);
      if (upsertResult === "added") {
        result.added++;
      } else {
        result.updated++;
      }
      result.ignored++;
      if (entry.permanent) {
        log(`Ignored ${advisory.ghsa} permanently.`);
      } else {
        log(`Ignored ${advisory.ghsa} until ${entry.expires}.`);
      }
    }

    return result;
  };

  if (options.ask) {
    return runner(options.ask);
  }

  return withDefaultReadline(runner);
}

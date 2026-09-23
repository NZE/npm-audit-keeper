#!/usr/bin/env node

import * as fs from "node:fs";
import * as path from "node:path";
import { loadConfig, saveConfig, VALID_LEVELS } from "./config.js";
import { runAudit } from "./audit.js";
import { runInteractiveSession } from "./interactive.js";
import type { Advisory, IgnoreEntry } from "./types.js";

const VERSION = readVersion();

function readVersion(): string | undefined {
  const packageJsonCandidates = [path.resolve(__dirname, "package.json"), path.resolve(__dirname, "..", "package.json")];

  for (const packageJsonPath of packageJsonCandidates) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8")) as { version?: unknown };
      if (typeof packageJson.version === "string" && packageJson.version.trim().length > 0) {
        return packageJson.version.trim();
      }
    } catch {
      // Try next path.
    }
  }

  const envVersion = process.env.npm_package_version;
  if (typeof envVersion === "string" && envVersion.trim().length > 0) {
    return envVersion.trim();
  }

  return undefined;
}

interface CliArgs {
  configPath: string;
  interactive: boolean;
  auditLevel?: string;
  help: boolean;
  version: boolean;
}

const HELP = `Usage: audit-check [options]
       audit-keeper [options]

Options:
  --config <path>         Config file (default: ./audit-config.json)
  --audit-level <level>   Run-only threshold: low, moderate, high, critical
  -i, --interactive      Review advisories and save ignore changes (TTY required)
  -h, --help             Show this help without running an audit
  -v, --version          Show the package version without running an audit

Runs npm audit in the current directory. Both command names are aliases.
Exit 0: no unresolved advisories or expired active ignores. Exit 1: failure.`;

function parseArgs(argv: string[]): CliArgs {
  let configPath = "audit-config.json";
  let interactive = false;
  let auditLevel: string | undefined;
  let help = false;
  let version = false;

  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "-h" || argv[i] === "--help") {
      help = true;
      continue;
    }
    if (argv[i] === "-v" || argv[i] === "--version") {
      version = true;
      continue;
    }
    if (argv[i] === "-i" || argv[i] === "--interactive") {
      interactive = true;
      continue;
    }

    if (argv[i] === "--config") {
      const nextArg = argv[i + 1];
      if (!nextArg || nextArg.startsWith("-")) {
        throw new Error('Missing value for "--config". Usage: audit-check [--config path/to/audit-config.json]');
      }

      configPath = nextArg;
      i++;
      continue;
    }

    if (argv[i] === "--audit-level" || argv[i].startsWith("--audit-level=")) {
      let value: string | undefined;
      if (argv[i].startsWith("--audit-level=")) {
        value = argv[i].slice("--audit-level=".length);
      } else {
        value = argv[i + 1];
        if (!value || value.startsWith("-")) {
          throw new Error('Missing value for "--audit-level". Usage: --audit-level=<low|moderate|high|critical>');
        }
        i++;
      }

      if (!VALID_LEVELS.includes(value)) {
        throw new Error(`Invalid audit level "${value}". Must be one of: ${VALID_LEVELS.join(", ")}`);
      }

      auditLevel = value;
      continue;
    }
    throw new Error(`Unknown argument "${argv[i]}". Run audit-check --help for usage.`);
  }

  return { configPath: path.resolve(process.cwd(), configPath), interactive, auditLevel, help, version };
}

function padRight(str: string, len: number): string {
  return str.length >= len ? str : str + " ".repeat(len - str.length);
}

function formatAdvisory(a: Advisory): string {
  return `  ${padRight(a.ghsa, 26)}  ${padRight(a.severity, 10)}  ${padRight(a.package, 20)}  ${a.title}`;
}

function formatIgnored(a: Advisory, e: IgnoreEntry): string {
  const expiryText = e.permanent ? "permanent" : `expires ${e.expires}`;
  return `  ${padRight(a.ghsa, 26)}  ${padRight(a.package, 20)}  "${e.reason}"  (${expiryText})`;
}

function countInactiveIgnores(config: { ignore?: IgnoreEntry[] }): number {
  return (config.ignore ?? []).filter((entry) => entry.active === false).length;
}

export async function main(): Promise<void> {
  let configPath: string;
  let interactive = false;
  let auditLevel: string | undefined;
  let help = false;
  let version = false;
  try {
    ({ configPath, interactive, auditLevel, help, version } = parseArgs(process.argv));
  } catch (err) {
    console.error(`\nError: ${(err as Error).message}`);
    return process.exit(1);
  }

  if (help || version) {
    console.log(help ? HELP : VERSION ?? "unknown");
    return process.exit(0);
  }

  console.error(VERSION ? `npm-audit-keeper v${VERSION}` : "npm-audit-keeper");

  if (interactive && (!process.stdin.isTTY || !process.stdout.isTTY)) {
    console.error("Error: interactive mode requires a TTY terminal.");
    return process.exit(1);
  }

  // Load config
  let config;
  try {
    config = loadConfig(configPath);
  } catch (err) {
    console.error(`\nError: ${(err as Error).message}`);
    return process.exit(1);
  }

  const level = auditLevel ?? config.level ?? "moderate";
  console.error(`Severity threshold: ${level}\n`);

  // Run audit
  let result;
  try {
    result = runAudit({ ...config, level });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    return process.exit(1);
  }

  if (interactive) {
    const inactiveIgnoreCount = countInactiveIgnores(config);
    const unusedIgnoreCount = result.unusedIgnores.length;

    if (result.unresolved.length === 0 && inactiveIgnoreCount === 0 && unusedIgnoreCount === 0) {
      console.error("Interactive mode: no unresolved advisories, inactive ignore entries, or unused ignore entries to process.");
    } else {
      const sessionResult = await runInteractiveSession({
        advisories: result.unresolved,
        config,
        unusedIgnores: result.unusedIgnores,
      });

      const removedInactive = sessionResult.removedInactive ?? 0;
      const removedUnused = sessionResult.removedUnused ?? 0;
      if (removedInactive > 0 || removedUnused > 0 || sessionResult.added > 0 || sessionResult.updated > 0) {
        try {
          saveConfig(configPath, config);
          const saveParts: string[] = [];
          if (removedInactive > 0) {
            saveParts.push(`removed ${removedInactive} inactive entr${removedInactive === 1 ? "y" : "ies"}`);
          }
          if (removedUnused > 0) {
            saveParts.push(`removed ${removedUnused} unused entr${removedUnused === 1 ? "y" : "ies"}`);
          }
          if (sessionResult.added > 0 || sessionResult.updated > 0) {
            saveParts.push(`saved ${sessionResult.added + sessionResult.updated} ignore update(s)`);
          }
          console.error(`\nSaved interactive config changes to ${configPath} (${saveParts.join(", ")}).`);
        } catch (err) {
          console.error(`\nError: ${(err as Error).message}`);
          return process.exit(1);
        }

        if (sessionResult.added > 0 || sessionResult.updated > 0) {
          try {
            result = runAudit({ ...config, level });
          } catch (err) {
            console.error(`Error: ${(err as Error).message}`);
            return process.exit(1);
          }
        }
      }

      const summaryParts: string[] = [];
      if (removedInactive > 0) {
        summaryParts.push(`removed ${removedInactive} inactive entr${removedInactive === 1 ? "y" : "ies"}`);
      }
      if (removedUnused > 0) {
        summaryParts.push(`removed ${removedUnused} unused entr${removedUnused === 1 ? "y" : "ies"}`);
      }
      summaryParts.push(`reviewed ${sessionResult.reviewed}`);
      summaryParts.push(`ignored ${sessionResult.ignored} (${sessionResult.added} added, ${sessionResult.updated} updated)`);
      summaryParts.push(`skipped ${sessionResult.skipped}`);
      console.error(`\nInteractive summary: ${summaryParts.join(", ")}.`);
    }
  }

  const { found, unresolved, ignored, unusedIgnores, expired } = result;

  // Found advisories
  console.error(`Found ${found.length} advisor${found.length === 1 ? "y" : "ies"} (${level}+):`);
  if (found.length > 0) {
    for (const a of found) {
      console.error(formatAdvisory(a));
    }
  }

  // Ignored
  if (ignored.length > 0) {
    console.error(`\nIgnored (${ignored.length}):`);
    for (const { advisory, entry } of ignored) {
      console.error(formatIgnored(advisory, entry));
    }
  }

  // Expired ignores
  if (expired.length > 0) {
    console.error(`\nExpired ignores (${expired.length}):`);
    for (const e of expired) {
      console.error(`  ${padRight(e.ghsa, 26)}  ${padRight(e.package, 20)}  expired ${e.expires ?? "unknown"}`);
    }
  }

  // Unresolved
  if (unresolved.length > 0) {
    console.error(`\nUnresolved (${unresolved.length}):`);
    for (const a of unresolved) {
      console.error(formatAdvisory(a));
    }
  }

  // Unused ignore warnings
  if (unusedIgnores.length > 0) {
    console.error(
      `\nWarning: ${unusedIgnores.length} ignore entr${unusedIgnores.length === 1 ? "y" : "ies"} did not match any advisory (consider removing):`
    );
    for (const e of unusedIgnores) {
      console.error(`  ${padRight(e.ghsa, 26)}  ${e.package}`);
    }
  }

  // Summary
  const hasFails = unresolved.length > 0 || expired.length > 0;
  console.error("");
  if (hasFails) {
    const parts: string[] = [];
    if (unresolved.length > 0) {
      parts.push(`${unresolved.length} unresolved advisor${unresolved.length === 1 ? "y" : "ies"}`);
    }
    if (expired.length > 0) {
      parts.push(`${expired.length} expired ignore${expired.length === 1 ? "" : "s"}`);
    }
    console.error(`FAIL — ${parts.join(", ")}`);
    return process.exit(1);
  } else {
    console.error("PASS — no unresolved advisories");
    return process.exit(0);
  }
}

if (require.main === module) {
  void main().catch((err) => {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  });
}

import { execSync } from "node:child_process";
import { GHSA_REGEX } from "./config.js";
import type {
  AuditConfig,
  Advisory,
  AuditResult,
  IgnoreEntry,
  NpmAdvisoryVia,
  NpmAuditOutput,
  NpmVulnerability,
} from "./types.js";

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
  info: 0,
};

function meetsThreshold(severity: string, level: string): boolean {
  return (SEVERITY_RANK[severity] ?? 0) >= (SEVERITY_RANK[level] ?? 0);
}

function extractGhsa(url: string): string | null {
  const match = url.match(/\bGHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}\b/i);
  return match ? match[0] : null;
}

function isAdvisoryVia(via: NpmAdvisoryVia | string): via is NpmAdvisoryVia {
  if (typeof via !== "object" || via === null) {
    return false;
  }

  const candidate = via as Partial<NpmAdvisoryVia>;
  return (
    Number.isInteger(candidate.source) &&
    typeof candidate.name === "string" && candidate.name.trim().length > 0 &&
    typeof candidate.title === "string" && candidate.title.trim().length > 0 &&
    typeof candidate.url === "string" && candidate.url.trim().length > 0 &&
    typeof candidate.severity === "string" && Object.hasOwn(SEVERITY_RANK, candidate.severity)
  );
}

function isNpmVulnerability(vuln: unknown): vuln is NpmVulnerability {
  return typeof vuln === "object" && vuln !== null && Array.isArray((vuln as NpmVulnerability).via);
}

function assertValidAuditOutput(parsed: unknown): asserts parsed is NpmAuditOutput {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Unexpected npm audit JSON format: expected root JSON object");
  }

  const obj = parsed as Record<string, unknown>;
  if (obj.error !== undefined) {
    throw new Error("npm audit returned an error response");
  }
  if (obj.auditReportVersion !== 2) {
    throw new Error("Unexpected npm audit JSON format: expected auditReportVersion 2");
  }
  if (typeof obj.vulnerabilities !== "object" || obj.vulnerabilities === null || Array.isArray(obj.vulnerabilities)) {
    throw new Error('Unexpected npm audit JSON format: missing "vulnerabilities" object');
  }
}

function collectAdvisories(auditOutput: NpmAuditOutput): Advisory[] {
  const seen = new Map<string, Advisory>();

  for (const [name, vuln] of Object.entries(auditOutput.vulnerabilities)) {
    if (!isNpmVulnerability(vuln) || vuln.via.length === 0) {
      throw new Error(`Unexpected npm audit JSON format: invalid via array for "${name}"`);
    }

    for (const via of vuln.via) {
      if (typeof via === "string") {
        if (!Object.hasOwn(auditOutput.vulnerabilities, via)) {
          throw new Error(`Unexpected npm audit JSON format: unknown via reference "${via}"`);
        }
        continue;
      }
      if (!isAdvisoryVia(via)) {
        throw new Error(`Unexpected npm audit JSON format: invalid advisory for "${name}"`);
      }

      const ghsa = extractGhsa(via.url);
      if (ghsa) {
        const ghsaKey = ghsa.toUpperCase();
        if (seen.has(ghsaKey)) {
          continue;
        }

        seen.set(ghsaKey, {
          ghsa,
          package: via.name,
          severity: via.severity,
          title: via.title,
          url: via.url,
        });
      } else {
        // No GHSA ID — use source ID as key, always unmatchable
        const key = `unknown-${via.source}`;
        if (!seen.has(key)) {
          seen.set(key, {
            ghsa: key,
            package: via.name,
            severity: via.severity,
            title: via.title,
            url: via.url,
          });
        }
      }
    }
  }

  return Array.from(seen.values());
}

function isPermanentIgnore(entry: IgnoreEntry): boolean {
  return entry.permanent === true;
}

function isExpired(entry: IgnoreEntry): boolean {
  if (isPermanentIgnore(entry)) {
    return false;
  }

  if (typeof entry.expires !== "string") {
    return true;
  }

  const expiry = new Date(entry.expires + "T00:00:00Z");
  if (Number.isNaN(expiry.getTime())) {
    return true;
  }

  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  return expiry < today;
}

export function runAudit(config: AuditConfig): AuditResult {
  const level = config.level ?? "moderate";
  const ignores = config.ignore ?? [];

  // Spawn npm audit --json
  let stdout: string;
  try {
    stdout = execSync("npm audit --json", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch (err: unknown) {
    const execErr = err as { status?: number; stdout?: string; stderr?: string };
    // Exit code 1 means vulnerabilities found — that's expected
    if (execErr.status === 1 && execErr.stdout) {
      stdout = execErr.stdout;
    } else {
      const msg = execErr.stderr || "Unknown error running npm audit";
      throw new Error(`npm audit failed (exit code ${execErr.status}): ${msg}`);
    }
  }

  // Parse JSON output
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("Failed to parse npm audit JSON output");
  }
  assertValidAuditOutput(parsed);
  const auditOutput = parsed;

  // Retain all severities when checking whether ignore entries are still in use.
  const allAdvisories = collectAdvisories(auditOutput);
  const found = allAdvisories.filter((advisory) => meetsThreshold(advisory.severity, level));

  // Separate expired ignores
  const expired = ignores.filter((e) => e.active !== false && isExpired(e));
  const activeIgnores = ignores.filter((e) => e.active !== false && !isExpired(e));

  // Apply ignores
  const unresolved: Advisory[] = [];
  const ignored: { advisory: Advisory; entry: IgnoreEntry }[] = [];

  for (const advisory of found) {
    const advisoryGhsaKey = advisory.ghsa.toUpperCase();
    const matchingEntry = GHSA_REGEX.test(advisory.ghsa)
      ? activeIgnores.find((e) => e.ghsa.toUpperCase() === advisoryGhsaKey)
      : undefined;
    if (matchingEntry) {
      ignored.push({ advisory, entry: matchingEntry });
    } else {
      unresolved.push(advisory);
    }
  }

  // Detect unused ignores
  const foundGhsas = new Set(allAdvisories.map((advisory) => advisory.ghsa.toUpperCase()));
  const unusedIgnores = activeIgnores.filter((e) => !foundGhsas.has(e.ghsa.toUpperCase()));

  return { found, unresolved, ignored, unusedIgnores, expired };
}

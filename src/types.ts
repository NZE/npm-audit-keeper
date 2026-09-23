export interface IgnoreEntry {
  ghsa: string;
  package: string;
  reason: string;
  expires?: string;
  permanent?: boolean;
  active?: boolean;
}

export interface AuditConfig {
  level?: string;
  ignore?: IgnoreEntry[];
}

export interface NpmAdvisoryVia {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: string;
  range: string;
}

export interface NpmVulnerability {
  name: string;
  severity: string;
  via: (NpmAdvisoryVia | string)[];
  effects: string[];
  isDirect: boolean;
  fixAvailable: boolean | object;
}

export interface NpmAuditOutput {
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmVulnerability>;
}

export interface Advisory {
  ghsa: string;
  package: string;
  severity: string;
  title: string;
  url: string;
}

export interface AuditResult {
  found: Advisory[];
  unresolved: Advisory[];
  ignored: { advisory: Advisory; entry: IgnoreEntry }[];
  unusedIgnores: IgnoreEntry[];
  expired: IgnoreEntry[];
}

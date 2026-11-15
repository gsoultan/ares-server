import type { JsonObject, JsonValue } from "@bufbuild/protobuf";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function severityColor(s: Severity): string {
  switch (s) {
    case "critical":
    case "high":
      return "red";
    case "medium":
      return "orange";
    case "low":
      return "yellow";
    default:
      return "gray";
  }
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Note",
};

export function severityLabel(s: Severity): string {
  return SEVERITY_LABEL[s] ?? s;
}

// What each severity means for the reader, used when a finding does not carry
// its own explanation.
const SEVERITY_MEANING: Record<Severity, string> = {
  critical: "An attacker could use this right now to take over systems or data. Fix it immediately.",
  high: "An attacker could likely use this to reach data or systems they should not. Fix it as a priority.",
  medium: "This makes an attack easier or more damaging. Plan a fix soon.",
  low: "A missing safeguard. Low risk on its own, but worth fixing as part of routine hardening.",
  info: "Not a weakness by itself. Useful to know.",
};

export function severityMeaning(s: Severity): string {
  return SEVERITY_MEANING[s];
}

export function severityRank(s: Severity): number {
  return RANK[s] ?? 5;
}

function str(v: JsonValue | undefined): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

export interface RemediationStep {
  text: string;
  code?: string;
  lang?: string;
}

export interface Mitigation {
  id: string;
  name: string;
}

// Remediation is the structured blue-team answer paired to a finding.
export interface Remediation {
  summary?: string;
  fix: RemediationStep[];
  prevent: RemediationStep[];
  detect: RemediationStep[];
  verify: RemediationStep[];
  mitigations: Mitigation[];
  references: string[];
}

export interface Finding {
  severity: Severity;
  title: string;
  url?: string;
  description?: string;
  meaning?: string;
  remediation?: string;
  remediationDetail?: Remediation;
  technique?: string;
  evidence: Record<string, string>;
  raw: JsonObject;
}

function toSteps(v: JsonValue | undefined): RemediationStep[] {
  if (!Array.isArray(v)) return [];
  const steps: RemediationStep[] = [];
  for (const item of v) {
    if (item && typeof item === "object" && !Array.isArray(item)) {
      const text = str(item["text"]);
      if (text) steps.push({ text, code: str(item["code"]), lang: str(item["lang"]) });
    }
  }
  return steps;
}

function toMitigations(v: JsonValue | undefined): Mitigation[] {
  if (!Array.isArray(v)) return [];
  const out: Mitigation[] = [];
  for (const item of v) {
    if (item && typeof item === "object" && !Array.isArray(item)) {
      const id = str(item["id"]);
      if (id) out.push({ id, name: str(item["name"]) ?? "" });
    }
  }
  return out;
}

// toRemediation reads the structured remediation payload a finding carries,
// defensively — any missing part becomes an empty list.
export function toRemediation(v: JsonValue | undefined): Remediation | undefined {
  if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
  const d = v as JsonObject;
  const rem: Remediation = {
    summary: str(d["summary"]),
    fix: toSteps(d["fix"]),
    prevent: toSteps(d["prevent"]),
    detect: toSteps(d["detect"]),
    verify: toSteps(d["verify"]),
    mitigations: toMitigations(d["mitigations"]),
    references: Array.isArray(d["references"])
      ? (d["references"].filter((r) => typeof r === "string") as string[])
      : [],
  };
  const hasContent =
    rem.fix.length ||
    rem.prevent.length ||
    rem.detect.length ||
    rem.verify.length ||
    rem.mitigations.length;
  return hasContent ? rem : undefined;
}

// toFinding reads a module result's payload into a uniform finding shape,
// defensively — different modules populate slightly different fields.
export function toFinding(
  data: JsonObject | undefined,
  kind: string,
  technique: string,
): Finding {
  const d = data ?? {};
  // A note (for example a match to a withdrawn indicator) is not a weakness.
  const sevIn = str(d["severity"])?.toLowerCase();
  const sevRaw = sevIn === "note" ? "info" : sevIn;
  const severity: Severity =
    sevRaw === "critical" ||
    sevRaw === "high" ||
    sevRaw === "medium" ||
    sevRaw === "low" ||
    sevRaw === "info"
      ? sevRaw
      : kind === "finding"
        ? "medium"
        : "info";

  const evidence: Record<string, string> = {};
  const ev = d["evidence"];
  if (ev && typeof ev === "object" && !Array.isArray(ev)) {
    for (const [k, v] of Object.entries(ev)) {
      if (typeof v === "string") evidence[k] = v;
    }
  }

  // Some tests write all three answers into one description, under headings.
  const whole = str(d["description"]) ?? str(d["detail"]);
  const parts = whole?.match(
    /^What we found:\s*([\s\S]*?)\n\nWhat it means:\s*([\s\S]*?)\n\nHow to respond:\s*([\s\S]*)$/,
  );

  return {
    severity,
    title: str(d["title"]) ?? (kind === "finding" ? "Finding" : "Observation"),
    url: str(d["url"]),
    description: parts ? parts[1] : whole,
    meaning: str(d["impact"]) ?? str(d["meaning"]) ?? parts?.[2],
    remediation: str(d["remediation"]) ?? parts?.[3],
    remediationDetail: toRemediation(d["remediationDetail"]),
    technique: technique !== "" ? technique : undefined,
    evidence,
    raw: d,
  };
}

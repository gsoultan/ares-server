import type { JsonObject, JsonValue } from "@bufbuild/protobuf";
import type { Tone } from "./labels.ts";

// The target profile the "Profile the target" test produces: what the site is
// built with, the clues behind that, and which tests are worth running.

export type Confidence = "high" | "medium" | "low";

export interface Clue {
  category: string;
  value: string;
  evidence: string;
  confidence: Confidence;
}

export interface Recommendation {
  module: string;
  reasons: string[];
  confidence: Confidence;
  // Set when the test cannot run until the operator supplies something.
  needsInput?: string;
}

export interface Profile {
  target: string;
  summary: string;
  description: string;
  technologies: string[];
  clues: Clue[];
  rationale: string;
  recommendations: Recommendation[];
}

function str(v: JsonValue | undefined): string {
  return typeof v === "string" ? v : "";
}

function strings(v: JsonValue | undefined): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : [];
}

function objects(v: JsonValue | undefined): JsonObject[] {
  return Array.isArray(v)
    ? v.filter((x): x is JsonObject => !!x && typeof x === "object" && !Array.isArray(x))
    : [];
}

function confidence(v: JsonValue | undefined): Confidence {
  return v === "high" || v === "low" ? v : "medium";
}

// toProfile reads a profile result defensively: any missing part becomes empty.
export function toProfile(data: JsonObject | undefined): Profile {
  const d = data ?? {};
  const plan = d["plan"];
  const p: JsonObject = plan && typeof plan === "object" && !Array.isArray(plan) ? plan : {};
  return {
    target: str(d["target"]),
    summary: str(d["summary"]),
    description: str(d["description"]),
    technologies: strings(d["technologies"]),
    clues: objects(d["signals"]).map((s) => ({
      category: str(s["category"]),
      value: str(s["value"]),
      evidence: str(s["evidence"]),
      confidence: confidence(s["confidence"]),
    })),
    rationale: str(p["rationale"]),
    recommendations: objects(p["recommendations"]).map((r) => ({
      module: str(r["module"]),
      reasons: strings(r["reasons"]),
      confidence: confidence(r["confidence"]),
      needsInput: str(r["needsInput"]) || undefined,
    })),
  };
}

export function confidenceInfo(c: Confidence): { label: string; tone: Tone } {
  switch (c) {
    case "high":
      return { label: "High", tone: "good" };
    case "low":
      return { label: "Low", tone: "neutral" };
    default:
      return { label: "Medium", tone: "warn" };
  }
}

// A clue's kind, in everyday words. Unknown kinds are shown tidied up.
const CATEGORIES: Record<string, string> = {
  server: "Web server",
  language: "Programming language",
  framework: "Framework",
  cms: "Content system",
  api: "Programming interface",
  surface: "Possible weak point",
  proxy: "Protection in front of the site",
  tls: "Encryption",
};

export function clueKind(category: string): string {
  const known = CATEGORIES[category.toLowerCase()];
  if (known) return known;
  const tidy = category.replace(/[_-]/g, " ");
  return tidy.charAt(0).toUpperCase() + tidy.slice(1);
}

// The overall risk rating, in words.
export function riskRating(rating: string): { label: string; tone: Tone } {
  switch (rating) {
    case "critical":
      return { label: "Critical risk", tone: "bad" };
    case "high":
      return { label: "High risk", tone: "bad" };
    case "medium":
      return { label: "Medium risk", tone: "warn" };
    case "low":
      return { label: "Low risk", tone: "good" };
    default:
      return { label: "No risk found yet", tone: "neutral" };
  }
}

// The part a finding plays in a route an attacker could take.
export function stepRole(role: string): string {
  switch (role) {
    case "foothold":
      return "Way in";
    case "enabler":
      return "Makes it easier";
    default:
      return "Then";
  }
}

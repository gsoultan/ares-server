import { AgentStatus, type AgentView } from "../gen/ares/v1/ares_pb.ts";
import type { StatusInfo } from "./labels.ts";

// Plain-language wording for agents: the small, transparent programs installed
// on a client's machine, with the owner's permission, so Ares can test from
// inside their network. The server's words (enrollment token, revoke,
// deregister, stale) never reach the page; these do.

export interface CapabilityInfo {
  id: string;
  label: string;
  summary: string;
  // A short promise shown as a tag next to the label, for the groups that only
  // read, listen or observe.
  tag?: string;
  // A short limit shown under the label on an agent's page.
  limit?: string;
  // Off unless the operator adds it explicitly.
  offByDefault?: boolean;
}

// The capability groups, in the order the server lists them
// (internal/agent/capabilities.go AllCapabilities).
export const CAPABILITIES: CapabilityInfo[] = [
  {
    id: "discovery",
    label: "Look around the inside network",
    summary:
      "Finds machines and services that can be reached from here, and checks their encryption and settings. Same gentle, rate-limited checks as the outside tests.",
  },
  {
    id: "webcheck",
    label: "Check inside websites",
    summary: "Tests intranet sites and apps the outside tests cannot reach.",
  },
  {
    id: "hostposture",
    label: "Check this machine's settings",
    tag: "Read only",
    limit: "Read only",
    summary:
      "Update level, firewall, password rules, running services and Windows hardening. It reads settings and changes none.",
  },
  {
    id: "passivesniff",
    label: "Listen for unprotected traffic",
    tag: "Listen only",
    limit: "Listen only · 30 minutes at most",
    summary:
      "Notices passwords and data crossing this network without encryption. It keeps what it found, never the traffic itself, and hides any password it sees. Runs for at most 30 minutes at a time.",
  },
  {
    id: "mitmexposure",
    label: "Check if traffic could be intercepted",
    tag: "Observe only",
    limit: "Observe only",
    offByDefault: true,
    summary:
      "Checks whether this network would let an attacker pose as another machine (name lookups like LLMNR, SMB signing, IPv6 router messages, missing switch protections). It never tries the attack.",
  },
];

export const DEFAULT_CAPABILITIES = CAPABILITIES.filter((c) => !c.offByDefault).map((c) => c.id);

export function capabilityInfo(id: string): CapabilityInfo {
  return CAPABILITIES.find((c) => c.id === id) ?? { id, label: id, summary: "" };
}

// Short names for the list's "What it may do" column.
const SHORT: Record<string, string> = {
  discovery: "Inside network",
  webcheck: "Inside websites",
  hostposture: "This machine",
  passivesniff: "Listen only",
  mitmexposure: "Interception check",
};

export function capabilityShort(id: string): string {
  return SHORT[id] ?? capabilityInfo(id).label;
}

// The engine modules an agent may run, by capability group. Mirrors the
// server's allow-list (internal/agent/capabilities.go moduleGroup); the server
// and the agent both check it again before anything runs.
export const AGENT_MODULES: Record<string, string[]> = {
  discovery: ["recon", "portscan", "dnsrecon", "rdap"],
  webcheck: ["webcheck", "httpprobe", "headerprobe", "tlscheck"],
  passivesniff: ["passivesniff"],
  mitmexposure: ["mitmexposure"],
};

// The modules this agent may be asked to run, in allow-list order.
export function agentModules(capabilities: string[]): string[] {
  return capabilities.flatMap((c) => AGENT_MODULES[c] ?? []);
}

export function agentStatus(status: AgentStatus): StatusInfo {
  switch (status) {
    case AgentStatus.CONNECTED:
      return { label: "Connected", tone: "good", hint: "Checked in within the last few minutes." };
    case AgentStatus.RUNNING_CHECK:
      return { label: "Running a check", tone: "brand", hint: "A check is running on this agent now." };
    case AgentStatus.NOT_HEARD_FROM:
      return {
        label: "Not heard from",
        tone: "warn",
        hint: "No check-in for more than 5 minutes. Results wait on the machine until it reconnects.",
      };
    case AgentStatus.REMOVED:
      return { label: "Removed", tone: "neutral", hint: "Stopped for good. Kept here for the record." };
    default:
      return { label: "Unknown", tone: "neutral", hint: "" };
  }
}

const OS: Record<string, string> = { windows: "Windows", linux: "Linux", darwin: "macOS" };

// The machine in one line: "Windows · 10.20.4.31".
export function machineLine(a: AgentView): string {
  const h = a.host;
  if (!h) return "";
  return [OS[h.os] ?? h.os, h.ip].filter((x) => x).join(" · ");
}

export function machineName(a: AgentView): string {
  return a.host?.hostname || "Unnamed machine";
}

export type InstallOS = "windows" | "linux";

export interface InstallOptions {
  os: InstallOS;
  server: string;
  key: string;
  proxy?: string;
  trustCa?: string;
}

// installCommand is what someone with admin rights runs on the machine. It
// matches the agent's own command line (cmd/ares-agent: enroll, then run).
export function installCommand(o: InstallOptions): string {
  const exe = o.os === "windows" ? ".\\ares-agent.exe" : "sudo ./ares-agent";
  const cont = o.os === "windows" ? " `" : " \\";
  const flags = [`--server ${o.server}`, `--key ${o.key}`];
  if (o.proxy) flags.push(`--proxy ${o.proxy}`);
  if (o.trustCa) flags.push(`--trust-ca ${o.os === "windows" ? ".\\" : "./"}${o.trustCa}`);
  return [
    `# 1. Connect it to this engagement (the key works once)`,
    `${exe} enroll ${flags.slice(0, 2).join(" ")}${flags.length > 2 ? cont : ""}`,
    ...(flags.length > 2 ? [`    ${flags.slice(2).join(" ")}`] : []),
    "",
    `# 2. Start it. It calls out to Ares and waits for checks`,
    `${exe} run`,
  ].join("\n");
}

export function uninstallCommand(os: string): string {
  return os === "windows" ? ".\\ares-agent.exe uninstall" : "sudo ./ares-agent uninstall";
}

// How a time from the server reads as "how long ago": "12 seconds ago".
export function timeAgo(rfc3339: string, now = Date.now()): string {
  const t = new Date(rfc3339).getTime();
  if (Number.isNaN(t) || t <= 0) return "Never";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return s <= 1 ? "Just now" : `${s} seconds ago`;
  const m = Math.round(s / 60);
  if (m < 60) return m === 1 ? "1 minute ago" : `${m} minutes ago`;
  const h = Math.round(m / 60);
  if (h < 48) return h === 1 ? "1 hour ago" : `${h} hours ago`;
  return `${Math.round(h / 24)} days ago`;
}

// How long until a time: "41 minutes".
export function timeLeft(rfc3339: string, now = Date.now()): string {
  const t = new Date(rfc3339).getTime();
  if (Number.isNaN(t)) return "";
  const m = Math.round((t - now) / 60000);
  if (m <= 0) return "now";
  if (m < 60) return m === 1 ? "1 minute" : `${m} minutes`;
  const h = Math.round(m / 60);
  return h === 1 ? "1 hour" : `${h} hours`;
}

// How the owner agreed: the choices in the permission step.
export const CONSENT_HOW = ["Signed letter", "Email", "Signed contract clause", "In person, written note"];

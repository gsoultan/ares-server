import { useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { moduleInfo } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { agentActivity } from "../agents/data.ts";
import type { FindingRecord } from "../workspace/data.ts";

// Where a finding came from: a test Ares ran from outside, an agent inside the
// client's network, public records read without touching the target, an email
// check, or a check of files someone added (an app, logs, evidence).
export type Source = "outside" | "agent" | "public" | "email" | "files";

export const SOURCES: { value: Source; label: string; filter: string }[] = [
  { value: "outside", label: "Outside test", filter: "Outside tests" },
  { value: "agent", label: "Agent", filter: "Agents" },
  { value: "public", label: "Public records", filter: "Public records" },
  { value: "email", label: "Email check", filter: "Email checks" },
  { value: "files", label: "File check", filter: "File checks" },
];

// Modules that only read public sources (certificate logs, registries) and
// never send anything to the target.
const PUBLIC = new Set(["ctlogs", "rdap"]);
// Modules that check how a domain's email can be faked or read mail itself.
const EMAIL = new Set(["dnsrecon", "mailheader"]);

export interface FoundBy {
  source: Source;
  // "Agent on fin-ws-014", "Public records", …
  label: string;
  // The agent, when an agent found it.
  agentId?: string;
}

export function foundByModule(module: string): FoundBy {
  if (PUBLIC.has(module)) return { source: "public", label: "Public records" };
  if (EMAIL.has(module)) return { source: "email", label: "Email check" };
  // Checks of files someone added (an app, logs, evidence), not a live target.
  const info = moduleInfo(module);
  if (info.forensic || info.targets === null) return { source: "files", label: "File check" };
  return { source: "outside", label: "Outside test" };
}

// useFoundBy works out who found each finding. A finding an agent reported
// carries the agent's task id as its job id; the activity log ties that task
// to the agent, and the agent list gives its machine name. The log queries
// share their cache with the activity views.
export function useFoundBy(engagementIds: string[]): (f: FindingRecord) => FoundBy {
  const { tenantId } = useTenant();
  const audits = useQueries({
    queries: engagementIds.map((id) => ({
      queryKey: ["audit", tenantId, id],
      queryFn: () => control.getAudit({ id, tenantId }),
    })),
  });
  const agents = useQueries({
    queries: engagementIds.map((id) => ({
      queryKey: ["agents", tenantId, id],
      queryFn: () => control.listAgents({ engagementId: id, tenantId }),
      retry: false,
    })),
  });

  const auditStamp = audits.map((a) => a.dataUpdatedAt).join(",");
  const agentStamp = agents.map((a) => a.dataUpdatedAt).join(",");
  return useMemo(() => {
    const taskAgent = new Map<string, string>();
    for (const a of audits) {
      for (const [task, agent] of agentActivity(a.data?.entries).taskAgent) taskAgent.set(task, agent);
    }
    const names = new Map<string, string>();
    for (const l of agents) {
      for (const a of l.data?.agents ?? []) names.set(a.id, a.host?.hostname || "a machine");
    }
    return (f: FindingRecord): FoundBy => {
      const agentId = taskAgent.get(f.jobId);
      if (agentId) {
        return { source: "agent", label: `Agent on ${names.get(agentId) ?? "a machine"}`, agentId };
      }
      return foundByModule(f.module);
    };
    // The stamps change exactly when the data does.
  }, [auditStamp, agentStamp]);
}

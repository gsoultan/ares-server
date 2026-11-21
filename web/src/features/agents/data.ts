import { useMemo } from "react";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "../../client.ts";
import type { AgentView } from "../../gen/ares/v1/ares_pb.ts";
import { useTenant } from "../../tenant.tsx";
import type { WireEntry } from "../../workers/audit-verify.worker.ts";

// The agent data an engagement's Agents section shares. The list refreshes on
// its own, so a new agent, a missed check-in or a running check shows up
// without a reload.

const POLL = 5000;

// agentsDisabled is true when this server was started without agent support.
export function agentsDisabled(err: unknown): boolean {
  return err instanceof ConnectError && err.code === Code.Unavailable;
}

export function useAgents(engagementId: string) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ["agents", tenantId, engagementId],
    queryFn: () => control.listAgents({ engagementId, tenantId }),
    refetchInterval: POLL,
    retry: (n, err) => !agentsDisabled(err) && n < 2,
  });
}

export function useAgentKeys(engagementId: string) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ["agent-keys", tenantId, engagementId],
    queryFn: () => control.listAgentKeys({ engagementId, tenantId }),
    refetchInterval: POLL,
    retry: (n, err) => !agentsDisabled(err) && n < 2,
  });
}

export function useAgent(engagementId: string, agentId: string) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ["agent", tenantId, engagementId, agentId],
    queryFn: () => control.getAgent({ engagementId, tenantId, agentId }),
    refetchInterval: POLL,
  });
}

// useAgentChange reloads everything an agent action can change.
export function useAgentChange(engagementId: string) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  return () => {
    for (const key of ["agents", "agent-keys", "agent", "audit"]) {
      void qc.invalidateQueries({ queryKey: [key, tenantId] });
    }
    void qc.invalidateQueries({ queryKey: ["engagement", tenantId, engagementId] });
  };
}

export function useCancelKey(engagementId: string) {
  const { tenantId } = useTenant();
  const changed = useAgentChange(engagementId);
  return useMutation({
    mutationFn: (keyId: string) => control.cancelAgentKey({ engagementId, tenantId, keyId }),
    onSuccess: changed,
  });
}

export function useRemoveAgent(engagementId: string) {
  const { tenantId } = useTenant();
  const changed = useAgentChange(engagementId);
  return useMutation({
    mutationFn: (agentId: string) => control.removeAgent({ engagementId, tenantId, agentId }),
    onSuccess: changed,
  });
}

// What the activity log says about agents. The server writes one entry per
// agent event: enrolled (actor = agent), check queued (target = agent),
// results received (actor = agent, target = the task id), removed and
// deregistered. Findings carry the task id as their job id, so the results
// entries are what tie a finding to the agent that found it.
export interface AgentActivity {
  // task id -> agent id, for every task an agent reported results for.
  taskAgent: Map<string, string>;
  // agent id -> its log entries, newest first.
  byAgent: Map<string, WireEntry[]>;
}

export function agentActivity(entries: WireEntry[] | undefined): AgentActivity {
  const taskAgent = new Map<string, string>();
  const byAgent = new Map<string, WireEntry[]>();
  const add = (id: string, e: WireEntry) => {
    const list = byAgent.get(id) ?? [];
    list.push(e);
    byAgent.set(id, list);
  };
  for (const e of entries ?? []) {
    if (!e.action.startsWith("agent.") || e.action.startsWith("agent.key.")) continue;
    if (e.action === "agent.dispatch" || e.action === "agent.remove") {
      add(e.target, e);
    } else {
      add(e.actor, e);
    }
    if (e.action === "agent.results") taskAgent.set(e.target, e.actor);
  }
  for (const list of byAgent.values()) list.reverse();
  return { taskAgent, byAgent };
}

export function useAgentActivity(entries: WireEntry[] | undefined): AgentActivity {
  return useMemo(() => agentActivity(entries), [entries]);
}

// agentNames maps an agent id to its machine name, for "Agent on fin-ws-014".
export function agentNames(agents: AgentView[] | undefined): Map<string, string> {
  return new Map((agents ?? []).map((a) => [a.id, a.host?.hostname || "a machine"]));
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "../../client.ts";
import type { TechniqueApproval, TestConsent } from "../../gen/ares/v1/ares_pb.ts";
import { useSession } from "../../session.tsx";
import { useTenant } from "../../tenant.tsx";
import { parseTarget } from "../engagement/startTest.ts";

// The engine's consent levels. There is no level above 3: nothing that cannot
// be undone is ever offered.
export type Level = 1 | 2 | 3;

export const LEVELS: {
  level: Level;
  name: string;
  summary: string;
  points: string[];
  example?: string;
}[] = [
  {
    level: 1,
    name: "Safe proof",
    summary: "Watches and measures only. Nothing is written or changed on the target.",
    points: [
      "Reads versions, settings and public records.",
      "Sends harmless signals, like a sum to calculate or a one-time web address to visit.",
      "This is where every engagement starts, and it is always allowed.",
    ],
    example: "Example: confirm a server runs commands by having it visit a one-time Ares address.",
  },
  {
    level: 2,
    name: "Active confirmation",
    summary: "Does one real but reversible thing, then cleans it up, to prove a weakness beyond doubt.",
    points: [
      "Writes a single harmless marker, such as a plain-text file to prove an upload box is open, then deletes it.",
      "Everything it does can be undone, and Ares undoes it automatically.",
      "Each technique says what it writes and how it cleans up, before it runs.",
    ],
  },
  {
    level: 3,
    name: "Intrusive",
    summary: "Proves deeper impact with a real action that may disrupt the target until it stops or is undone.",
    points: [
      "Each test is approved one at a time, for one target, with a named approver. Nothing intrusive runs without it.",
      "An approval is used up by the run it allows. Running again needs a new approval.",
      "Recoverable, but it may interrupt the business while it runs.",
    ],
  },
];

export function levelName(level: number): string {
  return LEVELS.find((l) => l.level === level)?.name ?? "Safe proof";
}

// The person signed in, for naming who approved or changed something. With
// sign-in off there is one operator.
export function useActor(): string {
  const { user } = useSession();
  return user?.name || user?.email || "operator";
}

export function useCanManageConsent(): boolean {
  const { user } = useSession();
  // With sign-in off there is no role to check; the server decides.
  return !user || user.role === "owner" || user.role === "admin" || user.role === "superadmin";
}

export function useTestConsent(engagementId: string) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ["consent", tenantId, engagementId],
    queryFn: () => control.getTestConsent({ engagementId, tenantId }),
  });
}

// A consent change also writes to the activity log.
function useConsentWrite<V, R>(engagementId: string, fn: (v: V) => Promise<R>) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: (res) => {
      if (res && typeof res === "object" && "techniques" in res) {
        qc.setQueryData(["consent", tenantId, engagementId], res as unknown as TestConsent);
      } else {
        void qc.invalidateQueries({ queryKey: ["consent", tenantId, engagementId] });
      }
      void qc.invalidateQueries({ queryKey: ["audit", tenantId, engagementId] });
    },
  });
}

export function useSetIntensity(engagementId: string) {
  const { tenantId } = useTenant();
  const actor = useActor();
  return useConsentWrite(engagementId, (level: Level) =>
    control.setTestIntensity({ engagementId, tenantId, level, actor }),
  );
}

export interface ApprovalInput {
  module: string;
  target: string;
  how: string;
  note: string;
}

export function useApprove(engagementId: string) {
  const { tenantId } = useTenant();
  const actor = useActor();
  return useConsentWrite(engagementId, (a: ApprovalInput) =>
    control.approveTechnique({
      engagementId,
      tenantId,
      module: a.module,
      target: parseTarget(a.target),
      approvedBy: actor,
      how: a.how,
      note: a.note,
    }),
  );
}

export function useDecline(engagementId: string) {
  const { tenantId } = useTenant();
  const actor = useActor();
  return useConsentWrite(engagementId, (a: { module: string; target: string; note: string }) =>
    control.declineTechnique({
      engagementId,
      tenantId,
      module: a.module,
      target: parseTarget(a.target),
      actor,
      note: a.note,
    }),
  );
}

export function useWithdraw(engagementId: string) {
  const { tenantId } = useTenant();
  const actor = useActor();
  return useConsentWrite(engagementId, (approvalId: string) =>
    control.withdrawApproval({ engagementId, tenantId, approvalId, actor }),
  );
}

export function useStopJob(engagementId: string) {
  const { tenantId } = useTenant();
  const actor = useActor();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) => control.stopJob({ tenantId, jobId, actor }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit", tenantId, engagementId] });
    },
  });
}

export type ApprovalState = "ready" | "used" | "withdrawn";

export function approvalState(a: TechniqueApproval): ApprovalState {
  if (a.jobId) return "used";
  if (a.withdrawn) return "withdrawn";
  return "ready";
}

// The server stores a target as its address string; compare loosely so that
// "https://x" typed here matches what the server recorded.
export function sameTarget(recorded: string, typed: string): boolean {
  const norm = (s: string) => s.trim().replace(/\/+$/, "").toLowerCase();
  return norm(recorded) === norm(typed);
}

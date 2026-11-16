import { useEffect, useMemo, useRef } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "../../client.ts";
import type { JobProgress, JobSummary, Proof, ProofCheck } from "../../gen/ares/v1/ares_pb.ts";
import { addPending } from "../../lib/local.ts";
import { severityRank, toApproval, toFinding, type Approval, type Finding } from "../../lib/findings.ts";
import type { StatusInfo } from "../../lib/labels.ts";
import { dropPending, usePending } from "../../lib/local.ts";
import { useTenant } from "../../tenant.tsx";

// The data every workspace screen shares: the engagements, the tests that ran,
// and the findings those tests produced.

export function useEngagements() {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ["engagements", tenantId],
    queryFn: () => control.listEngagements({ tenantId }),
  });
}

export function targetLabel(t?: { host: string; port: number; url: string }): string {
  if (!t) return "";
  if (t.url) return t.url;
  if (t.port) return `${t.host}:${t.port}`;
  return t.host;
}

export interface Job {
  jobId: string;
  engagementId: string;
  module: string;
  at: string; // when it started
  done: boolean;
  // What it came to, once it is done.
  summary?: JobSummary;
  // How far it has got and how long it has left, while it runs.
  progress?: JobProgress;
}

// useJobs returns the tests run in this workspace, newest first, including
// any that are still running. Pass an engagement to narrow it.
export function useJobs(engagementId?: string): { jobs: Job[]; loading: boolean } {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  const engagements = useEngagements();
  const ids = useMemo(
    () => (engagementId ? [engagementId] : (engagements.data?.engagements ?? []).map((e) => e.id)),
    [engagementId, engagements.data],
  );

  const lists = useQueries({
    queries: ids.map((id) => ({
      queryKey: ["jobs", tenantId, id],
      queryFn: () => control.listJobs({ engagementId: id, tenantId }),
      // Keep looking while a test is running, so a reload still sees it finish.
      refetchInterval: (q: { state: { data?: { jobs: JobSummary[] } } }) =>
        q.state.data?.jobs.some((j) => j.status === "running") ? 1500 : false,
    })),
  });

  // When a listed test goes from running to finished, reload what it can change.
  const finishedIds = lists
    .flatMap((l) => l.data?.jobs ?? [])
    .filter((j) => j.status !== "running")
    .map((j) => j.jobId)
    .join(",");
  const seen = useRef<string | null>(null);
  useEffect(() => {
    if (seen.current !== null && seen.current !== finishedIds) {
      for (const key of ["findings", "risk", "detection", "purple", "audit"]) {
        void qc.invalidateQueries({ queryKey: [key, tenantId] });
      }
    }
    seen.current = finishedIds;
  }, [finishedIds, qc, tenantId]);

  // Watch the running tests; when one finishes, reload what it can change.
  const running = usePending().filter(
    (r) => r.tenantId === tenantId && (!engagementId || r.engagementId === engagementId),
  );
  const watched = useQueries({
    queries: running.map((r) => ({
      queryKey: ["job", tenantId, r.jobId],
      queryFn: () => control.getJob({ jobId: r.jobId, tenantId }),
      refetchInterval: 1000,
      retry: false,
    })),
  });
  const finished = running
    .filter((_, i) => watched[i]?.data?.status === "done" || !!watched[i]?.error)
    .map((r) => `${r.jobId}:${r.engagementId}`)
    .join(",");
  useEffect(() => {
    if (finished === "") return;
    let cancelled = false;
    void (async () => {
      const pairs = finished.split(",").map((x) => x.split(":") as [string, string]);
      await Promise.all(
        [...new Set(pairs.map(([, eng]) => eng))].flatMap((eng) => [
          qc.invalidateQueries({ queryKey: ["jobs", tenantId, eng] }),
          qc.invalidateQueries({ queryKey: ["findings", tenantId] }),
          qc.invalidateQueries({ queryKey: ["risk", tenantId, eng] }),
          qc.invalidateQueries({ queryKey: ["detection", tenantId, eng] }),
          qc.invalidateQueries({ queryKey: ["purple", tenantId, eng] }),
          qc.invalidateQueries({ queryKey: ["audit", tenantId, eng] }),
        ]),
      );
      // Only once the finished test is in the list does it stop being "running".
      if (!cancelled) pairs.forEach(([jobId]) => dropPending(jobId));
    })();
    return () => {
      cancelled = true;
    };
  }, [finished, qc, tenantId]);

  const stamp = lists.map((r) => r.dataUpdatedAt).join(",");
  const jobs = useMemo(() => {
    const done: Job[] = lists.flatMap((l, i) =>
      (l.data?.jobs ?? []).map((j) => ({
        jobId: j.jobId,
        engagementId: ids[i]!,
        module: j.module,
        at: j.startedAt,
        done: j.status !== "running",
        summary: j.status === "running" ? undefined : j,
        progress: j.status === "running" ? j.progress : undefined,
      })),
    );
    const known = new Set(done.map((j) => j.jobId));
    const live: Job[] = running
      .filter((r) => !known.has(r.jobId))
      .map((r) => ({ jobId: r.jobId, engagementId: r.engagementId, module: r.module, at: r.at, done: false }));
    return [...live, ...done].sort((a, b) => b.at.localeCompare(a.at));
    // The stamp changes exactly when a list does.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stamp, running.map((r) => r.jobId).join(","), ids]);

  return { jobs, loading: lists.some((r) => r.isLoading) };
}

// useJobOutcome loads the full results of one finished test.
export function useJobOutcome(jobId: string | undefined, done: boolean) {
  const { tenantId } = useTenant();
  return useQuery({
    queryKey: ["outcome", tenantId, jobId],
    queryFn: () => control.getJob({ jobId: jobId!, tenantId }),
    enabled: !!jobId && done,
    staleTime: Infinity,
  });
}

export type FindingStatus = "open" | "in_progress" | "fixed";

export interface FindingRecord {
  id: string;
  engagementId: string;
  engagementName: string;
  // The latest test that saw it.
  jobId: string;
  module: string;
  // The address the test was pointed at when it found this.
  target: string;
  foundAt: string;
  finding: Finding;
  status: FindingStatus;
  // True once a later run of the same test on the same address no longer
  // finds it: the fix is confirmed, not only claimed.
  rechecked: boolean;
  // The structured evidence: what Ares sent, what came back and its sealed
  // fingerprint. Absent for a finding that was only observed.
  proof?: Proof;
  // Every time the proof was reproduced on demand, newest first.
  proofChecks: ProofCheck[];
  // Set when the finding came from an approved intrusive test.
  approval?: Approval;
}

// keepWithdrawn keeps a match to a withdrawn indicator: a note, not a
// weakness, which the Forensics page lists for the record.
export function useFindings(engagementId?: string, keepWithdrawn = false): {
  findings: FindingRecord[];
  loading: boolean;
  fetching: boolean;
} {
  const { tenantId } = useTenant();
  const list = useQuery({
    queryKey: ["findings", tenantId, engagementId ?? "all"],
    queryFn: () => control.listFindings({ tenantId, engagementId: engagementId ?? "" }),
  });
  const findings = useMemo(
    () =>
      (list.data?.findings ?? [])
        .map((f): FindingRecord => ({
          id: f.id,
          engagementId: f.engagementId,
          engagementName: f.engagementName,
          jobId: f.jobId,
          module: f.module,
          target: f.target,
          foundAt: f.foundAt,
          finding: toFinding(f.data, f.kind, f.technique),
          status: f.status === "in_progress" || f.status === "fixed" ? f.status : "open",
          rechecked: !f.stillPresent,
          proof: f.proof,
          proofChecks: f.rechecks,
          approval: toApproval(f.data),
        }))
        // A note is not a weakness; it stays with its test's results.
        .filter((f) => f.finding.severity !== "info" || (keepWithdrawn && f.finding.raw["withdrawn"] === true))
        .sort(
          (a, b) =>
            severityRank(a.finding.severity) - severityRank(b.finding.severity) ||
            b.foundAt.localeCompare(a.foundAt),
        ),
    [list.data, keepWithdrawn],
  );
  return { findings, loading: list.isLoading, fetching: list.isFetching };
}

// useSetFindingStatus records where a finding stands. It is written to the
// activity log like every other action.
export function useSetFindingStatus() {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: string; status: FindingStatus }) =>
      control.setFindingStatus({ tenantId, id: v.id, status: v.status, actor: "operator" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["findings", tenantId] });
      void qc.invalidateQueries({ queryKey: ["audit", tenantId] });
    },
  });
}

// useRecheckFinding reproduces a finding's own proof against the live target.
// The server sends the narrowed probe through the normal scope gate, so a
// stopped engagement or an address now out of scope is refused, never tested.
// It returns the re-check's test id, or null when there is nothing to re-run.
export function useRecheckFinding(record: FindingRecord) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await control.recheckFinding({ tenantId, findingId: record.id, actor: "operator" });
      if (!res.rechecked) return null;
      addPending({
        jobId: res.jobId,
        engagementId: record.engagementId,
        tenantId,
        module: record.proof?.recheck?.module || record.module,
        targets: [record.target],
      });
      return res.jobId;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit", tenantId, record.engagementId] });
    },
  });
}

// useProofDownload fetches a finding's proof as the exact record its
// fingerprint covers, so anyone can check it with sha256sum.
export function useProofDownload(findingId: string) {
  const { tenantId } = useTenant();
  return useMutation({
    mutationFn: () => control.getProofArtifact({ tenantId, findingId }),
  });
}

export type FindingState = "open" | "in_progress" | "fixed" | "rechecked";

export function findingState(f: FindingRecord): FindingState {
  return f.rechecked ? "rechecked" : f.status;
}

// Still needs someone to act on it.
export function isUnresolved(f: FindingRecord): boolean {
  return !f.rechecked && f.status !== "fixed";
}

export function findingStateInfo(state: FindingState): StatusInfo {
  switch (state) {
    case "rechecked":
      return {
        label: "Fixed and re-checked",
        tone: "good",
        hint: "The test ran again and no longer finds this.",
      };
    case "fixed":
      return {
        label: "Fixed, not re-checked",
        tone: "warn",
        hint: "Marked as fixed. Re-check to confirm the fix held.",
      };
    case "in_progress":
      return { label: "Fix in progress", tone: "brand", hint: "Someone is working on the fix." };
    default:
      return { label: "Open", tone: "neutral", hint: "Nobody has started on this yet." };
  }
}

// useCoverage loads what the defenders did, for every engagement at once.
export function useCoverage(engagementIds: string[]) {
  const { tenantId } = useTenant();
  const results = useQueries({
    queries: engagementIds.map((id) => ({
      queryKey: ["detection", tenantId, id],
      queryFn: () => control.getDetectionSummary({ id, tenantId }),
    })),
  });
  let total = 0;
  let covered = 0;
  const counts: Record<string, number> = {};
  for (const r of results) {
    if (!r.data) continue;
    total += r.data.total;
    covered += r.data.covered;
    for (const [k, v] of Object.entries(r.data.counts)) counts[k] = (counts[k] ?? 0) + v;
  }
  return {
    total,
    covered,
    counts,
    percent: total === 0 ? 0 : Math.round((covered / total) * 100),
    loading: results.some((r) => r.isLoading),
    byEngagement: engagementIds.map((id, i) => ({ id, summary: results[i]?.data })),
  };
}

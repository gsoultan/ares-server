import { useSyncExternalStore } from "react";

// The little this browser remembers by itself: tests that are still running,
// and which reports were downloaded here. Everything else comes from the server.

function createStore<T>(key: string, initial: T) {
  let value: T = initial;
  let loaded = false;
  const listeners = new Set<() => void>();

  const load = () => {
    if (loaded) return;
    loaded = true;
    try {
      const raw = localStorage.getItem(key);
      if (raw) value = JSON.parse(raw) as T;
    } catch {
      // Storage is a convenience; without it the page still works for this visit.
    }
  };

  return {
    get(): T {
      load();
      return value;
    },
    set(next: T) {
      loaded = true;
      value = next;
      try {
        localStorage.setItem(key, JSON.stringify(next));
      } catch {
        // See above.
      }
      listeners.forEach((l) => l());
    },
    subscribe(l: () => void) {
      listeners.add(l);
      return () => listeners.delete(l);
    },
  };
}

function useStore<T>(store: ReturnType<typeof createStore<T>>): T {
  return useSyncExternalStore(store.subscribe, store.get, store.get);
}

// A test that was started here and has not finished yet. The server lists a
// test once it is done; until then this page remembers it is running.
export interface PendingRun {
  jobId: string;
  engagementId: string;
  tenantId: string;
  module: string;
  at: string; // RFC3339
  // The addresses it was pointed at, as typed.
  targets?: string[];
}

let pending: PendingRun[] = [];
const pendingListeners = new Set<() => void>();
const setPending = (next: PendingRun[]) => {
  pending = next;
  pendingListeners.forEach((l) => l());
};

export function addPending(run: Omit<PendingRun, "at">) {
  const full = { ...run, at: new Date().toISOString() };
  live.set(run.jobId, { run: full, played: false });
  setPending([full, ...pending]);
}

// Tests started on this page during this visit. They get the live view: the
// reader watched them start, so they are shown how they went, once.
const live = new Map<string, { run: PendingRun; played: boolean }>();

export function liveRun(jobId: string): PendingRun | undefined {
  const l = live.get(jobId);
  return l && !l.played ? l.run : undefined;
}

export function markPlayed(jobId: string) {
  const l = live.get(jobId);
  if (l) l.played = true;
}

export function dropPending(jobId: string) {
  if (pending.some((r) => r.jobId === jobId)) setPending(pending.filter((r) => r.jobId !== jobId));
}

export function usePending(): PendingRun[] {
  return useSyncExternalStore(
    (l) => {
      pendingListeners.add(l);
      return () => pendingListeners.delete(l);
    },
    () => pending,
    () => pending,
  );
}

export interface ReportRecord {
  engagementId: string;
  engagementName: string;
  tenantId: string;
  format: string;
  at: string;
}

const reports = createStore<ReportRecord[]>("ares.reports", []);

export function useReportHistory(): ReportRecord[] {
  return useStore(reports);
}

export function recordReport(r: Omit<ReportRecord, "at">) {
  reports.set([{ ...r, at: new Date().toISOString() }, ...reports.get()].slice(0, 20));
}

// Engagements where this person agreed to send details to the AI provider.
const aiConsent = createStore<string[]>("ares.ai.allowed", []);

export function aiAllowed(tenantId: string, engagementId: string): boolean {
  return aiConsent.get().includes(`${tenantId}/${engagementId}`);
}

export function allowAi(tenantId: string, engagementId: string) {
  if (!aiAllowed(tenantId, engagementId)) aiConsent.set([...aiConsent.get(), `${tenantId}/${engagementId}`]);
}

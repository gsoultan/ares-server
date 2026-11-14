import { useEffect, useRef, useState } from "react";
import type {
  VerifyRequest,
  VerifyResult,
  WireEntry,
} from "../workers/audit-verify.worker.ts";

type Status =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "done"; result: VerifyResult };

// Runs the audit chain through a web worker so the SHA-256 recomputation never
// blocks the UI. Returns an independent verdict the operator can compare with
// the server's claim.
export function useAuditVerification(entries: WireEntry[] | undefined): Status {
  const [status, setStatus] = useState<Status>({ state: "idle" });
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    const worker = new Worker(
      new URL("../workers/audit-verify.worker.ts", import.meta.url),
      { type: "module" },
    );
    workerRef.current = worker;
    worker.onmessage = (ev: MessageEvent<VerifyResult>) =>
      setStatus({ state: "done", result: ev.data });
    return () => {
      worker.terminate();
      workerRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!entries || !workerRef.current) return;
    setStatus({ state: "checking" });
    workerRef.current.postMessage({ entries } satisfies VerifyRequest);
  }, [entries]);

  return status;
}

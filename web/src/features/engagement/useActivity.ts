import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { useAuditVerification } from "../../hooks/useAuditVerification.ts";
import type { WireEntry } from "../../workers/audit-verify.worker.ts";
import { useTenant } from "../../tenant.tsx";
import type { Integrity } from "./ActivityLog.tsx";

// useActivity loads an engagement's activity log and checks it twice: the
// server's own verdict, and a second one worked out in this browser.
export function useActivity(id: string | undefined) {
  const { tenantId } = useTenant();
  const audit = useQuery({
    queryKey: ["audit", tenantId, id],
    queryFn: () => control.getAudit({ id: id!, tenantId }),
    enabled: !!id,
    refetchInterval: 4000,
  });

  const entries: WireEntry[] | undefined = useMemo(
    () =>
      audit.data?.entries.map((e) => ({
        seq: e.seq,
        time: e.time,
        actor: e.actor,
        action: e.action,
        target: e.target,
        detail: e.detail,
        prevHash: e.prevHash,
        hash: e.hash,
      })),
    [audit.data],
  );
  const independent = useAuditVerification(entries);

  const integrity: Integrity =
    !audit.data || independent.state !== "done"
      ? { state: "checking" }
      : audit.data.valid && independent.result.valid
        ? { state: "intact" }
        : {
            state: "broken",
            where: independent.result.valid ? undefined : `entry ${independent.result.brokenAt}`,
          };

  return { entries, loading: audit.isLoading, error: audit.error, integrity };
}

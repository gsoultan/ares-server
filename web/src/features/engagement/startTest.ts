import type { JsonObject } from "@bufbuild/protobuf";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { addPending } from "../../lib/local.ts";
import { useTenant } from "../../tenant.tsx";

// parseTarget turns one line of operator input into a Target: a URL, a
// host:port, or a bare host.
export function parseTarget(line: string): { host?: string; port?: number; url?: string } {
  const s = line.trim();
  if (s.includes("://")) return { url: s };
  const hostPort = s.match(/^([^:/]+):(\d+)$/);
  if (hostPort) return { host: hostPort[1], port: Number(hostPort[2]) };
  return { host: s };
}

export interface TestRequest {
  module: string;
  targets: string[];
  params?: JsonObject;
}

// useStartTest is the one way a test starts, wherever the button is. It asks
// the server to run it, and marks it as running until the server
// lists it as finished.
export function useStartTest(engagementId: string) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (req: TestRequest) => {
      const res = await control.dispatchJob({
        engagementId,
        tenantId,
        module: req.module,
        actor: "operator",
        targets: req.targets.map(parseTarget),
        params: req.params,
      });
      addPending({ jobId: res.jobId, engagementId, tenantId, module: req.module, targets: req.targets });
      return res.jobId;
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["audit", tenantId, engagementId] });
    },
  });
}

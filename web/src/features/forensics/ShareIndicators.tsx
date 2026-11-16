import { useState } from "react";
import type { JsonObject } from "@bufbuild/protobuf";
import { Button, Group, Modal, Stack, Text } from "@mantine/core";
import { IconDownload, IconShare } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { errorText, plural } from "../../lib/labels.ts";
import { addPending } from "../../lib/local.ts";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote, InfoNote } from "../../ui/index.tsx";
import type { FindingRecord } from "../workspace/data.ts";
import { inferType, supportsType, type Indicator } from "./indicators.ts";

const str = (v: unknown) => (typeof v === "string" ? v : "");

// sharedIndicators collects the indicators this case's findings confirmed, to
// hand to other teams. A withdrawn or benign (test) indicator, and a lead that
// matched no indicator, is never shared.
export function sharedIndicators(findings: FindingRecord[]): Indicator[] {
  const seen = new Set<string>();
  const out: Indicator[] = [];
  for (const f of findings) {
    const r = f.finding.raw;
    const value = str(r["indicatorValue"]);
    // Only a match to a loaded indicator is shared: a look-alike or other lead
    // has no indicator label and is not confirmed.
    if (!value || !str(r["indicatorLabel"]) || r["withdrawn"] === true || r["benign"] === true) continue;
    // An app id has no STIX or MISP form here.
    if (str(r["appId"]).toLowerCase() === value.toLowerCase()) continue;
    let type = str(r["indicatorType"]);
    // Only an untyped value is inferred.
    if (type === "" || type === "hash") type = inferType(value) ?? "";
    if (!supportsType("iocexport", type)) continue;
    const key = `${type}:${value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const label = str(r["indicatorLabel"]);
    const confidence = str(r["confidence"]);
    out.push({
      type: type as Indicator["type"],
      value,
      ...(label ? { label } : {}),
      ...(str(r["tier"]) ? { tier: str(r["tier"]) } : {}),
      ...(confidence === "primary" || confidence === "secondary" ? { confidence } : {}),
    });
  }
  return out;
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "case";

// ShareIndicators writes the case's confirmed indicators as a STIX 2.1 bundle
// and a MISP event, so they can be loaded into MVT, a MISP instance or another
// team's tools. The export is a job like any other, so it is on the activity
// log. Nothing is published: the files are downloaded here.
export function ShareIndicators({
  caseId,
  caseName,
  findings,
}: {
  caseId: string | undefined;
  caseName: string;
  findings: FindingRecord[];
}) {
  const { tenantId } = useTenant();
  const [open, setOpen] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const indicators = sharedIndicators(findings);

  const job = useQuery({
    queryKey: ["job", tenantId, jobId],
    queryFn: () => control.getJob({ jobId: jobId!, tenantId }),
    enabled: !!jobId,
    refetchInterval: (q) => (q.state.data?.status === "done" ? false : 600),
  });
  const results = job.data?.status === "done" ? job.data.results : [];
  const stix = results.find((r) => r.data?.["kind"] === "stix-export")?.data;
  const misp = results.find((r) => r.data?.["kind"] === "misp-export")?.data;

  const create = async () => {
    if (!caseId) return;
    setProblem(null);
    setBusy(true);
    try {
      const res = await control.dispatchJob({
        engagementId: caseId,
        tenantId,
        module: "iocexport",
        actor: "operator",
        targets: [],
        params: { indicators, title: caseName, producer: "Ares" } as unknown as JsonObject,
      });
      addPending({ jobId: res.jobId, engagementId: caseId, tenantId, module: "iocexport", targets: [] });
      setJobId(res.jobId);
    } catch (err) {
      setProblem(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    setOpen(false);
    setJobId(null);
    setProblem(null);
  };

  return (
    <>
      <Button
        variant="default"
        leftSection={<IconShare size={16} />}
        disabled={indicators.length === 0}
        onClick={() => setOpen(true)}
        title={indicators.length === 0 ? "No confirmed indicators in this case yet" : undefined}
      >
        Share indicators (STIX / MISP)
      </Button>
      <Modal opened={open} onClose={close} title="Share indicators" size="lg">
        <Stack gap="md">
          <Text size="sm">
            {plural(indicators.length, "indicator")} confirmed by this case's findings will be
            written as a STIX 2.1 bundle and a MISP event, for MVT, a MISP instance or another team's tools. Withdrawn
            and test indicators are left out.
          </Text>
          <InfoNote>
            The files are made on this server and downloaded here. Ares publishes nothing, and the export is written to
            the case's activity log.
          </InfoNote>
          {problem && <ErrorNote title="The indicators could not be written">{problem}</ErrorNote>}
          {job.data?.error && <ErrorNote title="The indicators could not be written">{job.data.error}</ErrorNote>}
          {!jobId || busy ? (
            <Group justify="flex-end">
              <Button loading={busy} onClick={() => void create()}>
                Create the files
              </Button>
            </Group>
          ) : !stix && !misp && !job.data?.error ? (
            <Group justify="flex-end">
              <Button loading>Creating the files</Button>
            </Group>
          ) : (
            <Group justify="flex-end" gap="sm" wrap="wrap">
              {stix && (
                <Button
                  variant="default"
                  leftSection={<IconDownload size={16} />}
                  onClick={() => download(`${slug(caseName)}-indicators.stix2.json`, str(stix["bundle"]))}
                >
                  STIX 2.1 bundle
                </Button>
              )}
              {misp && (
                <Button
                  leftSection={<IconDownload size={16} />}
                  onClick={() => download(`${slug(caseName)}-misp-event.json`, str(misp["event"]))}
                >
                  MISP event
                </Button>
              )}
            </Group>
          )}
        </Stack>
      </Modal>
    </>
  );
}

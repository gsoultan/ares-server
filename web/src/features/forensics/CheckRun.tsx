import { useEffect, useMemo, useState } from "react";
import { Box, Button, Group, Progress, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import {
  IconAlertTriangle,
  IconBrandAndroid,
  IconBrandApple,
  IconBrandWindows,
  IconCheck,
  IconFiles,
  IconWorld,
} from "@tabler/icons-react";
import { useQueries } from "@tanstack/react-query";
import { control } from "../../client.ts";
import type { JobOutcome, Result } from "../../gen/ares/v1/ares_pb.ts";
import { severityRank, toFinding } from "../../lib/findings.ts";
import { dismissForensicRun, type ForensicRun } from "../../lib/local.ts";
import { useTenant } from "../../tenant.tsx";
import { SeverityBadge } from "../../ui/index.tsx";
import { ProvenanceTag } from "./Provenance.tsx";

const STEP_MS = 520;

export const SOURCE_ICON: Record<string, typeof IconFiles> = {
  files: IconFiles,
  android: IconBrandAndroid,
  iphone: IconBrandApple,
  network: IconWorld,
  windows: IconBrandWindows,
};

function calm(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

const num = (v: unknown) => (typeof v === "number" ? v : 0);
const fmt = (n: number) => n.toLocaleString();
const word = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many);

// summarize says, in a few words, what one check read. It uses the summary
// each engine module reports alongside its findings.
export function summarize(module: string, results: Result[]): string {
  const info = results.filter((r) => r.kind === "info").map((r) => r.data ?? {});
  const sum = (k: string) => info.reduce((n, d) => n + num(d[k]), 0);
  const count = (prefix: string) => info.filter((d) => String(d["title"] ?? "").startsWith(prefix)).length;
  switch (module) {
    case "triage": {
      const n = results.filter((r) => r.kind === "evidence").length;
      return `${fmt(n)} ${word(n, "item")} in custody`;
    }
    case "androidqf":
      return `${fmt(sum("apps"))} ${word(sum("apps"), "app")} · ${fmt(sum("intrusionEvents"))} intrusion ${word(sum("intrusionEvents"), "event")}`;
    case "dnslogscan":
      return `${fmt(sum("queries"))} ${word(sum("queries"), "lookup")}`;
    case "connrecord":
      return `${fmt(sum("records"))} ${word(sum("records"), "connection")}`;
    case "eventlog":
      return `${fmt(sum("events"))} ${word(sum("events"), "event")}`;
    case "winpersist":
      return `${fmt(sum("entries"))} start-up ${word(sum("entries"), "entry", "entries")}`;
    case "winartifacts":
      return `${fmt(sum("markOfTheWeb"))} download ${word(sum("markOfTheWeb"), "mark")} · ${fmt(sum("hostsEntries"))} hosts ${word(sum("hostsEntries"), "entry", "entries")}`;
    case "iosbackup": {
      const n = count("iPhone backup manifest read");
      return `${fmt(n)} backup ${word(n, "record")} read`;
    }
    case "persistplist": {
      const n = count("Persistence plist read");
      return `${fmt(n)} ${word(n, "item")} read`;
    }
    case "mailheader": {
      const n = count("Message read");
      return `${fmt(n)} ${word(n, "message")}`;
    }
    case "browserhist":
      return `${fmt(sum("urls"))} ${word(sum("urls"), "address", "addresses")}`;
    case "logscan":
      return "logs read";
    case "iocmatch":
      return "compared";
    default:
      return "done";
  }
}

type RowState = "queued" | "running" | "done" | "failed";

// CheckRun shows one batch of checks as they run: a spinner and a live count
// on the check that is working, a green tick with what it read once it is
// done, a progress bar, and the findings arriving as each check confirms them.
// The server reports results as they arrive; the card follows at a pace a
// person can read, and with reduced motion it simply changes in place.
export function CheckRun({ run }: { run: ForensicRun }) {
  const { tenantId } = useTenant();
  const outcomes = useQueries({
    queries: run.jobs.map((j) => ({
      queryKey: ["job", tenantId, j.jobId],
      queryFn: () => control.getJob({ jobId: j.jobId, tenantId }),
      refetchInterval: (q: { state: { data?: JobOutcome } }) => (q.state.data?.status === "done" ? false : 700),
      retry: false,
    })),
  });

  const actual: RowState[] = run.jobs.map((_, i) => {
    const o = outcomes[i];
    if (o?.error) return "failed";
    const d = o?.data;
    if (!d) return "queued";
    if (d.status === "done") return d.error ? "failed" : "done";
    if (d.status === "running" || (d.results?.length ?? 0) > 0) return "running";
    return "queued";
  });

  // Pace: each row spends at least one step running and one landing, so a
  // check that finished in a blink is still seen to run. A run that was
  // already over when the page opened is shown as it ended.
  const allDoneAtMount = useMemo(() => actual.every((s) => s === "done" || s === "failed"), []); // eslint-disable-line react-hooks/exhaustive-deps
  const [step, setStep] = useState(() => (calm() || allDoneAtMount ? Infinity : 0));
  const shown: RowState[] = actual.map((s, i) => {
    if (step === Infinity || s === "queued") return s;
    if (step < 2 * i) return "queued";
    if (step === 2 * i) return "running";
    return s;
  });
  // Step on until every row that has started is shown as it really is.
  let lastStarted = -1;
  actual.forEach((s, i) => {
    if (s !== "queued") lastStarted = i;
  });
  const canStep = step !== Infinity && step < 2 * lastStarted + 2;
  useEffect(() => {
    if (!canStep) return;
    const t = setTimeout(() => setStep((s) => s + 1), STEP_MS);
    return () => clearTimeout(t);
  }, [canStep, step]);

  const finished = shown.every((s) => s === "done" || s === "failed");
  const progress =
    run.jobs.length === 0
      ? 100
      : Math.round(
          (shown.reduce((n, s) => n + (s === "done" || s === "failed" ? 1 : s === "running" ? 0.5 : 0), 0) / run.jobs.length) * 100,
        );

  // Findings from every check that has landed, most serious first.
  const found = shown
    .flatMap((s, i) =>
      s === "done" || s === "running"
        ? (outcomes[i]?.data?.results ?? [])
            .filter((r) => r.kind === "finding")
            .map((r, k) => ({ key: `${i}-${k}`, f: toFinding(r.data, r.kind, r.technique) }))
        : [],
    )
    .sort((a, b) => severityRank(a.f.severity) - severityRank(b.f.severity));
  const MAX = 6;
  const Icon = SOURCE_ICON[run.source] ?? IconFiles;

  return (
    <Box
      p="lg"
      style={{ background: "var(--ares-surface)", border: "1px solid var(--ares-line)", borderRadius: 12 }}
      aria-live="polite"
    >
      <Stack gap="md">
        <Group align="flex-start" wrap="nowrap" gap="md">
          <ThemeIcon variant="light" size={42} radius="md">
            <Icon size={22} />
          </ThemeIcon>
          <Box style={{ flex: 1, minWidth: 0 }}>
            <Title order={2}>{finished ? "Checks finished" : "Checking the evidence"}</Title>
            <Text size="sm" c="dimmed" style={{ wordBreak: "break-word" }}>
              {run.title} · read-only · nothing it came from is contacted
            </Text>
          </Box>
          <Text fw={650} fz={22} style={{ fontVariantNumeric: "tabular-nums" }} aria-label={`${progress}% done`}>
            {progress}%
          </Text>
        </Group>
        <Progress value={progress} size="sm" radius="xl" transitionDuration={calm() ? 0 : 500} aria-hidden />
        <Box>
          {run.jobs.map((j, i) => {
            const s = shown[i]!;
            const d = outcomes[i]?.data;
            const results = d?.results ?? [];
            // A note (a match to a withdrawn indicator) is not counted as found.
            const bad = results.filter((r) => r.kind === "finding" && r.data?.["severity"] !== "note").length;
            return (
              <div key={j.jobId} className="ares-check-row" data-state={s}>
                <div className="ares-check-ind" aria-hidden>
                  {s === "queued" && <span className="ares-check-dot" />}
                  {s === "running" && <span className="ares-check-spin" />}
                  {s === "done" && (
                    <span className="ares-check-tick">
                      <IconCheck size={13} stroke={3} />
                    </span>
                  )}
                  {s === "failed" && (
                    <span className="ares-check-tick" data-tone="bad">
                      <IconAlertTriangle size={13} stroke={2.4} />
                    </span>
                  )}
                </div>
                <Text fw={600} size="sm">
                  {j.label}
                </Text>
                <div className="ares-check-state">
                  {s === "queued" && "queued"}
                  {s === "running" && (results.length > 0 ? `${fmt(results.length)} ${word(results.length, "result")} so far…` : j.running)}
                  {s === "done" && (
                    <>
                      {summarize(j.module, results)} ·{" "}
                      {bad > 0 ? (
                        <Text span c="red.7" fw={600} size="sm">
                          {fmt(bad)} found
                        </Text>
                      ) : (
                        <Text span c="teal.7" fw={600} size="sm">
                          nothing found
                        </Text>
                      )}
                    </>
                  )}
                  {s === "failed" && (
                    <Text span c="orange.7" size="sm">
                      could not run{d?.error ? `: ${d.error}` : ""}
                    </Text>
                  )}
                </div>
              </div>
            );
          })}
        </Box>
        {found.length > 0 && (
          <Box>
            <Text fw={600} size="sm" mb={4}>
              Found so far
            </Text>
            <Stack gap={0}>
              {found.slice(0, MAX).map(({ key, f }) => (
                <Group
                  key={key}
                  className="ares-reveal"
                  align="flex-start"
                  wrap="nowrap"
                  gap="md"
                  py="xs"
                  style={{ borderTop: "1px solid var(--ares-line)" }}
                >
                  <Box style={{ flex: "none" }}>
                    <SeverityBadge severity={f.severity} />
                  </Box>
                  <Box style={{ minWidth: 0 }}>
                    <Text fw={600} size="sm">
                      {f.title}
                    </Text>
                    {f.description && (
                      <Text size="sm" c="dimmed" lineClamp={2}>
                        {f.description}
                      </Text>
                    )}
                    <ProvenanceTag raw={f.raw} />
                  </Box>
                </Group>
              ))}
            </Stack>
            {found.length > MAX && (
              <Text size="sm" c="dimmed" mt={4}>
                And {found.length - MAX} more in What the checks found, below.
              </Text>
            )}
          </Box>
        )}
        {finished && (
          <Group justify="space-between" gap="sm" className="ares-reveal">
            <Group gap={8} wrap="nowrap" align="flex-start" style={{ flex: 1, minWidth: 220 }}>
              <IconAlertTriangle size={15} style={{ flex: "none", marginTop: 2, color: "var(--mantine-color-dimmed)" }} />
              <Text size="xs" c="dimmed">
                A clean result covers only what was read. It never means the device is clean.
              </Text>
            </Group>
            <Button variant="subtle" size="compact-sm" onClick={() => dismissForensicRun(run.id)}>
              Dismiss
            </Button>
          </Group>
        )}
      </Stack>
    </Box>
  );
}

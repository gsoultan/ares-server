import { useEffect, useState } from "react";
import {
  Button,
  Group,
  NumberInput,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Timeline,
} from "@mantine/core";
import {
  IconAlertTriangle,
  IconArrowLeft,
  IconCheck,
  IconHandStop,
  IconPlayerPlay,
  IconPlayerStop,
  IconShieldCheck,
} from "@tabler/icons-react";
import type { JsonObject } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { control } from "../../client.ts";
import type { Engagement, TechniqueApproval } from "../../gen/ares/v1/ares_pb.ts";
import { errorText, formatDateTime, plural } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import type { WireEntry } from "../../workers/audit-verify.worker.ts";
import {
  ErrorNote,
  Field,
  InfoNote,
  LoadingState,
  PageHeader,
  Section,
  StatCard,
  ToneBadge,
} from "../../ui/index.tsx";
import { useStartTest } from "../engagement/startTest.ts";
import { targetLabel, type FindingRecord } from "../workspace/data.ts";
import { ApproveTechnique } from "./ApproveTechnique.tsx";
import { approvalState, sameTarget, useStopJob, useTestConsent } from "./data.ts";
import { ResilienceChart, type RampStep } from "./ResilienceChart.tsx";

export const RESILIENCE = "loadresilience";

// Settings for one ramp, in the engine's terms: load is measured as requests
// in flight at once, not requests per second.
interface Ramp {
  step: number;
  ceiling: number;
  perStep: number;
  limitMs: number;
  limitFailPct: number;
}

const DEFAULT_RAMP: Ramp = { step: 5, ceiling: 50, perStep: 100, limitMs: 2000, limitFailPct: 5 };
const MAX_CEILING = 500;

function rampParams(r: Ramp): JsonObject {
  return {
    enable: true,
    maxConcurrency: r.ceiling,
    stepConcurrency: r.step,
    requestsPerStep: r.perStep,
    abortP95Ms: r.limitMs,
    abortErrorRate: r.limitFailPct / 100,
  };
}

function looksNonProduction(target: string): boolean {
  return /(^|[.\-/])(staging|stage|test|dev|qa|uat|sandbox|localhost|127\.0\.0\.1)([.\-:/]|$)/i.test(target);
}

function num(v: unknown): number {
  return typeof v === "number" ? v : Number(v ?? 0) || 0;
}

function stepsOf(data: JsonObject | undefined): RampStep[] {
  const raw = data?.["steps"];
  if (!Array.isArray(raw)) return [];
  return raw.map((s) => {
    const o = (s ?? {}) as JsonObject;
    return {
      concurrency: num(o["concurrency"]),
      requests: num(o["requests"]),
      errors: num(o["errors"]),
      errorRate: num(o["errorRate"]),
      p50Ms: num(o["p50Ms"]),
      p95Ms: num(o["p95Ms"]),
      rate429: num(o["rate429"]),
    };
  });
}

function backTo(engagement: Engagement) {
  return (
    <Link to="/engagements/$id" params={{ id: engagement.id }} search={{ view: "testing" }} className="ares-back">
      <IconArrowLeft size={14} />
      {engagement.name} · Run tests
    </Link>
  );
}

const levelBadge = (
  <ToneBadge tone="warn" size="lg">
    Level 3 · Intrusive
  </ToneBadge>
);

const NOT_AN_ATTACK =
  "Ares sends ordinary requests from one place, raises them in steps, and stops the moment your system struggles. It does not run a real denial-of-service attack: no amplified or reflected traffic, no fake sender addresses, no botnet, and it will not hold your systems down. The goal is to measure your ceiling, not to take you offline. This limit cannot be switched off.";

// ResilienceTest is the resilience test: set it up and approve it, watch it
// run, and read where the target's capacity ends.
export function ResilienceTest({
  engagement,
  jobId,
  defaultTarget,
  activity,
  findings,
}: {
  engagement: Engagement;
  jobId?: string;
  defaultTarget?: string;
  activity: WireEntry[];
  findings: FindingRecord[];
}) {
  if (jobId) {
    return <ResilienceRun engagement={engagement} jobId={jobId} activity={activity} findings={findings} />;
  }
  return <ResilienceSetup engagement={engagement} defaultTarget={defaultTarget} />;
}

function ResilienceSetup({ engagement, defaultTarget }: { engagement: Engagement; defaultTarget?: string }) {
  const id = engagement.id;
  const navigate = useNavigate();
  const consent = useTestConsent(id);
  const start = useStartTest(id);
  const [target, setTarget] = useState(defaultTarget ?? "");
  const [slot, setSlot] = useState("");
  const [ramp, setRamp] = useState<Ramp>(DEFAULT_RAMP);
  const [approving, setApproving] = useState(false);

  const level = consent.data?.level ?? 1;
  const technique = consent.data?.techniques.find((t) => t.module === RESILIENCE);
  const onFile = (consent.data?.approvals ?? []).find(
    (a) => a.module === RESILIENCE && approvalState(a) === "ready" && target.trim() !== "" && sameTarget(a.target, target),
  );
  const set = (k: keyof Ramp) => (v: string | number) => setRamp((r) => ({ ...r, [k]: Number(v) || 0 }));
  const steps = ramp.step > 0 ? Math.floor(ramp.ceiling / ramp.step) : 0;
  const valid =
    target.trim() !== "" &&
    ramp.step > 0 &&
    ramp.ceiling >= ramp.step &&
    ramp.ceiling <= MAX_CEILING &&
    ramp.perStep > 0 &&
    ramp.limitMs > 0 &&
    ramp.limitFailPct > 0;

  const run = (a: TechniqueApproval) =>
    start.mutate(
      // Run against the target exactly as the approval recorded it.
      { module: RESILIENCE, targets: [a.target], params: rampParams(ramp) },
      {
        onSuccess: (jobId) =>
          void navigate({ to: "/engagements/$id", params: { id }, search: { view: "testing", test: RESILIENCE, job: jobId } }),
      },
    );

  if (consent.isLoading) return <LoadingState label="Loading…" />;

  const stopsWhen = `Response time passes ${ramp.limitMs.toLocaleString()} ms, or more than ${ramp.limitFailPct}% of requests fail`;

  return (
    <Stack gap="lg">
      <PageHeader
        back={backTo(engagement)}
        title="Resilience test"
        badge={levelBadge}
        description="Find out how much traffic your system handles before it slows down or fails, by raising load in steps until it reaches its limit, then stopping. This measures your ceiling. It is not a real denial-of-service attack."
      />
      <InfoNote tone="warn" title="This may slow down or interrupt the target while it runs">
        Run it against a staging or test copy if you can. If you must run against production, choose a
        quiet window and keep someone watching. You can stop it instantly at any moment.
      </InfoNote>
      {level < 3 && (
        <InfoNote title="This engagement does not allow intrusive tests">
          The resilience test is level 3. Raise the engagement's level first, then approve this run.{" "}
          <Link
            to="/engagements/$id"
            params={{ id }}
            search={{ view: "setup", page: "intensity" }}
            className="ares-link"
          >
            Change how far tests go
          </Link>
        </InfoNote>
      )}
      {!technique && level >= 3 && (
        <ErrorNote title="The resilience test is not installed on this server" />
      )}

      <Section title="What to test">
        <Stack gap="md" maw={560}>
          <div>
            <TextInput
              label="Target"
              description="One web address in scope."
              placeholder="https://staging.example.com"
              value={target}
              onChange={(e) => setTarget(e.currentTarget.value)}
            />
            {target.trim() !== "" && (
              <Group gap="xs" mt={6}>
                {looksNonProduction(target) ? (
                  <ToneBadge tone="good">Looks like a test copy</ToneBadge>
                ) : (
                  <ToneBadge tone="warn">May be production</ToneBadge>
                )}
                <Text size="xs" c="dimmed">
                  We strongly recommend a non-production copy.
                </Text>
              </Group>
            )}
          </div>
          <TextInput
            label="Window"
            description="A low-traffic window agreed with the client. Recorded with the approval."
            placeholder="Tonight, 02:00–03:00"
            value={slot}
            onChange={(e) => setSlot(e.currentTarget.value)}
          />
        </Stack>
      </Section>

      <Section
        title="How hard to push"
        description="Ares raises load in steps and watches how the system responds. It stops as soon as it reaches a limit you set; it does not keep pushing once the system is in trouble. Load is counted as requests in flight at the same time."
      >
        <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md" maw={760}>
          <NumberInput label="Raise by" suffix=" at a time" min={1} max={MAX_CEILING} value={ramp.step} onChange={set("step")} />
          <NumberInput
            label="Never exceed"
            description="A hard ceiling. Ares never sends more at once."
            suffix=" at a time"
            min={1}
            max={MAX_CEILING}
            value={ramp.ceiling}
            onChange={set("ceiling")}
            error={ramp.ceiling > MAX_CEILING ? `At most ${MAX_CEILING}` : ramp.ceiling < ramp.step ? "At least one step" : undefined}
          />
          <NumberInput label="Requests in each step" min={1} max={5000} value={ramp.perStep} onChange={set("perStep")} />
        </SimpleGrid>
        <Text size="sm" c="dimmed">
          {steps > 0 ? `Up to ${plural(steps, "step")}, from ${ramp.step} to ${ramp.step * steps} at a time.` : ""}
        </Text>
        <Text fw={600} mt="xs">
          Stop automatically when any of these happens
        </Text>
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md" maw={520}>
          <NumberInput label="Response time passes" suffix=" ms" min={100} max={60000} step={100} value={ramp.limitMs} onChange={set("limitMs")} />
          <NumberInput label="Requests failing passes" suffix="%" min={1} max={50} value={ramp.limitFailPct} onChange={set("limitFailPct")} />
        </SimpleGrid>
        <Text size="sm" c="dimmed">
          A system that stops responding counts as failing, so Ares backs off at once and does not hold it
          down.
        </Text>
      </Section>

      <InfoNote tone="good" title="A controlled test, not a real attack">
        {NOT_AN_ATTACK}
      </InfoNote>

      {onFile && (
        <InfoNote title="An approval is on file for this target">
          Approved by {onFile.approvedBy}, {formatDateTime(onFile.approvedAt)}. Starting the test uses it.
        </InfoNote>
      )}
      {start.error && <ErrorNote title="The test did not start">{errorText(start.error)}</ErrorNote>}
      <Group justify="flex-end" gap="sm">
        <Button variant="default" onClick={() => void navigate({ to: "/engagements/$id", params: { id }, search: { view: "testing" } })}>
          Cancel
        </Button>
        {onFile ? (
          <Button color="red" leftSection={<IconPlayerPlay size={16} />} disabled={!valid} loading={start.isPending} onClick={() => run(onFile)}>
            Start the test
          </Button>
        ) : (
          <Button color="red" disabled={!valid || level < 3 || !technique} onClick={() => setApproving(true)}>
            Review and approve
          </Button>
        )}
      </Group>

      {technique && (
        <ApproveTechnique
          engagementId={id}
          technique={technique}
          target={target.trim()}
          opened={approving}
          onClose={() => setApproving(false)}
          onApproved={(a) => {
            setApproving(false);
            run(a);
          }}
          extra={[
            { label: "Ceiling", value: `${ramp.ceiling} requests at a time, raised by ${ramp.step}` },
            { label: "Stops when", value: stopsWhen },
            ...(slot.trim() ? [{ label: "Window", value: slot.trim() }] : []),
          ]}
          defaultNote={slot.trim() ? `Window: ${slot.trim()}` : ""}
        />
      )}
    </Stack>
  );
}

function useElapsed(since: string | undefined, running: boolean): string {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running]);
  if (!since) return "";
  const s = Math.max(0, Math.round((now - new Date(since).getTime()) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function ResilienceRun({
  engagement,
  jobId,
  activity,
  findings,
}: {
  engagement: Engagement;
  jobId: string;
  activity: WireEntry[];
  findings: FindingRecord[];
}) {
  const id = engagement.id;
  const { tenantId } = useTenant();
  const navigate = useNavigate();
  const stop = useStopJob(id);
  const job = useQuery({
    queryKey: ["job", tenantId, jobId],
    queryFn: () => control.getJob({ jobId, tenantId }),
    refetchInterval: (q) => (q.state.data?.status === "done" ? false : 1000),
    retry: false,
  });

  const o = job.data;
  const running = !o || o.status !== "done";
  const forJob = activity.filter((e) => e.target === jobId || e.detail.includes(jobId));
  const used = forJob.find((e) => e.action === "approval-used");
  const stoppedByHand = forJob.find((e) => e.action === "job-stopped");
  // Start and finish entries do not name the job; the approval it spent does.
  const started = used;
  const elapsed = useElapsed(started?.time, running);

  const result = o?.results.find((r) => r.capability === RESILIENCE && (r.kind === "finding" || r.kind === "info"));
  const data = result?.data;
  const steps = stepsOf(data);
  const target = result ? targetLabel(result.target) : (o?.allowed[0] ? targetLabel(o.allowed[0]) : (used?.target ?? ""));
  const approvedBy = used?.actor;
  const consentNote = (data?.["consent"] ?? undefined) as JsonObject | undefined;
  const finding = findings.find((f) => f.jobId === jobId);

  const subtitle = [target, started && `started ${formatDateTime(started.time)}`, approvedBy && `approved by ${approvedBy}`]
    .filter(Boolean)
    .join(" · ");

  if (job.isLoading) return <LoadingState label="Loading the test…" />;
  if (job.error) {
    return (
      <Stack gap="lg">
        <PageHeader back={backTo(engagement)} title="Resilience test" badge={levelBadge} />
        <ErrorNote title="This test could not be found">{errorText(job.error)}</ErrorNote>
      </Stack>
    );
  }

  if (running) {
    return (
      <Stack gap="lg">
        <PageHeader
          back={backTo(engagement)}
          title="Resilience test"
          badge={<ToneBadge tone="brand" size="lg">Running</ToneBadge>}
          description={subtitle}
          actions={
            <Button
              color="red"
              leftSection={<IconPlayerStop size={16} />}
              loading={stop.isPending}
              onClick={() => stop.mutate(jobId)}
            >
              Stop now
            </Button>
          }
        />
        <InfoNote tone="warn" title="Watching: it stops on its own if the system struggles">
          You can stop it yourself at any moment with the red button. Someone should stay on this page
          while it runs.
        </InfoNote>
        {stop.data && !stop.data.stopped && (
          <InfoNote>The test had already finished. Its results are loading.</InfoNote>
        )}
        {stop.error && <ErrorNote title="The test was not stopped">{errorText(stop.error)}</ErrorNote>}
        <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
          <StatCard label="Running for" value={elapsed || "–"} />
          <StatCard label="Target" value={<Text fz={18} fw={650} truncate>{target || "–"}</Text>} />
          <StatCard label="Approval" value={<Text fz={18} fw={650}>{approvedBy ?? "Used"}</Text>}>
            <Text size="xs" c="dimmed">Single use, spent by this run</Text>
          </StatCard>
        </SimpleGrid>
        <Section
          title="What is happening"
          description="Ares raises the load step by step and checks each step against your limits. The numbers for every step appear here when the ramp ends."
        >
          <RunTimeline entries={forJob} running />
        </Section>
      </Stack>
    );
  }

  // Finished.
  const held = result?.kind === "info";
  const knee = num(data?.["kneeConcurrency"]);
  // A step cut short by a stop is not a measurement.
  const measured = stoppedByHand ? steps.slice(0, -1) : steps;
  const healthy = measured.filter((s) => (knee ? s.concurrency < knee : true));
  const lastHealthy = healthy[healthy.length - 1];
  const peak = steps.reduce((m, s) => Math.max(m, s.p95Ms), 0);
  const reached = steps[steps.length - 1]?.concurrency ?? 0;
  const limitMs = 2000;
  const title = stoppedByHand
    ? "Resilience test stopped by hand"
    : held
      ? "Held the tested ceiling"
      : result
        ? "Slows down under load before the ceiling"
        : "The resilience test found nothing to measure";

  return (
    <Stack gap="lg">
      <PageHeader
        back={backTo(engagement)}
        title={title}
        badge={
          held && !stoppedByHand ? (
            <ToneBadge tone="good" size="lg">Healthy</ToneBadge>
          ) : result && !held ? (
            <ToneBadge tone="warn" size="lg">Medium</ToneBadge>
          ) : (
            <ToneBadge tone="neutral" size="lg">Done</ToneBadge>
          )
        }
        description={subtitle}
        actions={
          <Button
            variant="default"
            onClick={() => void navigate({ to: "/engagements/$id", params: { id }, search: { view: "testing", test: RESILIENCE } })}
          >
            Set up another run
          </Button>
        }
      />
      <InfoNote tone="warn" title="Result of an approved resilience test">
        {stoppedByHand
          ? `Stopped by ${stoppedByHand.actor} at ${formatDateTime(stoppedByHand.time)}, after reaching ${reached} requests at a time. The numbers below cover the steps that ran.`
          : held
            ? "Ares raised the load in steps up to the agreed ceiling and stopped there. The system stayed inside your limits and was never held down."
            : `Ares raised the load in steps and stopped on its own at ${knee} requests at a time, when the system crossed a limit you set. Your system was never held down.`}
        {consentNote?.["who"] ? ` Approved by ${String(consentNote["who"])}.` : ""}
        {finding && (
          <>
            {" "}
            <Link
              to="/engagements/$id"
              params={{ id }}
              search={{ view: "findings", finding: finding.id }}
              className="ares-link"
            >
              Open the finding
            </Link>
          </>
        )}
      </InfoNote>
      {o?.error && <ErrorNote title="The test reported a problem">{o.error}</ErrorNote>}
      {o && o.denied.length > 0 && (
        <InfoNote title="Some targets were skipped">{o.denied.map((d) => d.reason).join("; ")}</InfoNote>
      )}

      {steps.length > 0 && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="md">
            <StatCard label="Healthy up to" value={lastHealthy ? lastHealthy.concurrency : "–"}>
              <Text size="xs" c="dimmed">requests at a time</Text>
            </StatCard>
            <StatCard
              label={stoppedByHand ? "Reached when stopped" : held ? "Ceiling reached" : "Stopped at"}
              value={held || stoppedByHand ? reached : knee || reached}
              tone={stoppedByHand ? "neutral" : held ? "good" : "warn"}
            >
              <Text size="xs" c="dimmed">requests at a time</Text>
            </StatCard>
            <StatCard label="Slowest response" value={`${peak.toLocaleString()} ms`}>
              <Text size="xs" c="dimmed">slowest 5%, worst step</Text>
            </StatCard>
            <StatCard label="Rate limiting" value={data?.["rateLimited"] ? "Seen" : "None"} tone={data?.["rateLimited"] ? "good" : "warn"}>
              <Text size="xs" c="dimmed">HTTP 429 responses under load</Text>
            </StatCard>
          </SimpleGrid>
          <Section title="Load and response, step by step" description="Each step ran at a fixed number of requests at a time.">
            <ResilienceChart steps={steps} limitMs={peakLimit(data) ?? limitMs} ceiling={Math.max(reached, knee)} />
            <Table.ScrollContainer minWidth={560}>
              <Table verticalSpacing="xs" striped>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>At a time</Table.Th>
                    <Table.Th>Requests</Table.Th>
                    <Table.Th>Failed</Table.Th>
                    <Table.Th>Typical</Table.Th>
                    <Table.Th>Slowest 5%</Table.Th>
                    <Table.Th>Rate-limited</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {steps.map((s) => (
                    <Table.Tr key={s.concurrency} fw={knee && s.concurrency === knee ? 650 : undefined}>
                      <Table.Td>{s.concurrency}</Table.Td>
                      <Table.Td>{s.requests}</Table.Td>
                      <Table.Td>{(s.errorRate * 100).toFixed(1)}%</Table.Td>
                      <Table.Td>{s.p50Ms} ms</Table.Td>
                      <Table.Td>{s.p95Ms} ms</Table.Td>
                      <Table.Td>{s.rate429}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Section>
        </>
      )}

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg" style={{ alignItems: "start" }}>
        <Section title="What it means">
          <Text>
            {stoppedByHand
              ? `The test was stopped by hand before it reached its ceiling, so it does not say where this system's capacity ends. Up to ${reached} requests at a time it stayed inside your limits; the last step was cut short when it stopped. Run it again to measure the full ramp.`
              : typeof data?.["description"] === "string"
                ? data["description"]
                : "No result was reported for this target."}
          </Text>
          {!stoppedByHand && typeof data?.["remediation"] === "string" && (
            <Field label="How to fix it">{data["remediation"]}</Field>
          )}
        </Section>
        <Section title="History" description="Every step of this run, from the activity log.">
          <RunTimeline entries={forJob} />
        </Section>
      </SimpleGrid>
    </Stack>
  );
}

// The response-time limit is not echoed in the result; read it from the
// description when it is there ("p95 < 2000ms").
function peakLimit(data: JsonObject | undefined): number | undefined {
  const d = typeof data?.["description"] === "string" ? data["description"] : "";
  const m = d.match(/p95 < (\d+)ms/);
  return m ? Number(m[1]) : undefined;
}

const TIMELINE_TEXT: Record<string, (e: WireEntry) => string> = {
  "approval-used": (e) => `Approval by ${e.actor} used for this run`,
  "job-dispatched": () => "Started",
  "job-started": () => "Started",
  "job-stopped": (e) => `Stopped by ${e.actor}`,
  "job-refused": (e) => `Refused: ${e.detail}`,
  "job-completed": () => "Finished",
  "job-finished": () => "Finished",
};

function RunTimeline({ entries, running = false }: { entries: WireEntry[]; running?: boolean }) {
  const shown = [...entries].sort((a, b) => a.seq - b.seq);
  if (shown.length === 0) {
    return <Text size="sm" c="dimmed">Nothing recorded yet.</Text>;
  }
  return (
    <Timeline active={shown.length - 1} bulletSize={22} lineWidth={2}>
      {shown.map((e) => (
        <Timeline.Item
          key={e.seq}
          bullet={
            e.action === "job-stopped" ? (
              <IconHandStop size={12} />
            ) : e.action === "job-refused" ? (
              <IconAlertTriangle size={12} />
            ) : e.action === "approval-used" ? (
              <IconShieldCheck size={12} />
            ) : (
              <IconCheck size={12} />
            )
          }
          title={(TIMELINE_TEXT[e.action] ?? ((x: WireEntry) => x.detail || x.action))(e)}
        >
          <Text size="xs" c="dimmed">
            {formatDateTime(e.time)}
          </Text>
        </Timeline.Item>
      ))}
      {running && (
        <Timeline.Item bullet={<IconPlayerPlay size={12} />} title="Raising the load step by step">
          <Text size="xs" c="dimmed">Now</Text>
        </Timeline.Item>
      )}
    </Timeline>
  );
}

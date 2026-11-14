import { useState } from "react";
import {
  Box,
  Button,
  Collapse,
  FileInput,
  Group,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Textarea,
  Title,
  UnstyledButton,
} from "@mantine/core";
import { IconChevronDown, IconChevronRight, IconChevronUp, IconCircleCheck, IconPlayerPlay } from "@tabler/icons-react";
import type { JsonObject } from "@bufbuild/protobuf";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { control } from "../../client.ts";
import { AccessCheckForm } from "../../components/AccessCheckForm.tsx";
import { severityRank, toFinding, type Severity } from "../../lib/findings.ts";
import { errorText, formatWhen, moduleInfo, plural, type Tone } from "../../lib/labels.ts";
import { EmptyState, ErrorNote, LoadingState, Section, SeverityBadge, Stat, ToneBadge } from "../../ui/index.tsx";
import { targetLabel, useFindings, useJobOutcome, useJobs, type Job } from "../workspace/data.ts";
import { liveRun, markPlayed } from "../../lib/local.ts";
import { LiveTest } from "./LiveTest.tsx";
import { useStartTest } from "./startTest.ts";

// RunTest is the testing section of an engagement: start a test, see the tests
// that ran before, and read the results of the one that is selected.
export function RunTest({
  id,
  initialTest,
  defaultTarget,
}: {
  id: string;
  // A test to preselect, when the reader came from a recommendation.
  initialTest?: string;
  // The address the target profile was built from, offered as a starting point.
  defaultTarget?: string;
}) {
  const [moduleName, setModuleName] = useState<string | null>(initialTest ?? null);
  const [targetText, setTargetText] = useState(defaultTarget ?? "");
  const [paramsText, setParamsText] = useState("");
  const [paramsError, setParamsError] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const [accessParams, setAccessParams] = useState<JsonObject | null>(null);
  const [apkB64, setApkB64] = useState<string | null>(null);
  const [apkName, setApkName] = useState("");
  const [apkError, setApkError] = useState<string | null>(null);
  // The earlier test whose results are showing. The newest, unless one is picked.
  const [picked, setPicked] = useState<string | null>(null);

  const { jobs } = useJobs(id);
  const dispatch = useStartTest(id);
  const shown = jobs.find((j) => j.jobId === picked) ?? jobs[0];

  const modules = useQuery({
    queryKey: ["modules"],
    queryFn: () => control.listModules({}),
    staleTime: 60_000,
  });

  const isAccess = moduleName === "accesscheck";
  const isApk = moduleName === "apkscan";
  const info = moduleName ? moduleInfo(moduleName) : null;

  const onApkPick = (file: File | null) => {
    setApkError(null);
    setApkB64(null);
    setApkName("");
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const res = String(reader.result);
      const comma = res.indexOf(",");
      setApkB64(comma >= 0 ? res.slice(comma + 1) : res);
      setApkName(file.name);
    };
    reader.onerror = () => setApkError("Could not read the file.");
    reader.readAsDataURL(file);
  };

  const onRun = () => {
    setParamsError(null);
    let params: JsonObject | undefined;
    let targets: string[] = [];
    if (isAccess) {
      params = accessParams ?? undefined;
    } else if (isApk) {
      params = { apkBase64: apkB64 ?? "", name: apkName } as JsonObject;
    } else {
      if (paramsText.trim() !== "") {
        try {
          params = JSON.parse(paramsText) as JsonObject;
        } catch {
          setParamsError("This is not valid JSON. Check for a missing quote, comma or bracket.");
          setAdvanced(true);
          return;
        }
      }
      targets = targetText
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l !== "");
    }
    dispatch.mutate(
      { module: moduleName ?? "", targets, params },
      { onSuccess: () => setPicked(null) },
    );
  };

  const canRun =
    !!moduleName && (!isAccess || accessParams !== null) && (!isApk || apkB64 !== null);

  const options = (modules.data?.modules ?? [])
    // Forensics tools work on files and have their own page.
    .filter((m) => !moduleInfo(m).forensic)
    .map((m) => ({ value: m, label: moduleInfo(m).label }))
    .sort((a, b) => a.label.localeCompare(b.label));

  return (
    <Stack gap="lg">
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg" style={{ alignItems: "start" }}>
      <Section
        title="Run a test"
        description="Choose a test and where to point it. Anything outside the scope is skipped automatically."
      >
        <Stack gap="md">
          <Select
            label="Test"
            placeholder={modules.isLoading ? "Loading tests…" : "Choose a test"}
            data={options}
            value={moduleName}
            onChange={(v) => {
              setModuleName(v);
              setApkB64(null);
              setApkName("");
              setApkError(null);
            }}
            renderOption={({ option }) => (
              <Box>
                <Text size="sm" fw={600}>
                  {option.label}
                </Text>
                <Text size="xs" c="dimmed">
                  {moduleInfo(option.value).summary}
                </Text>
              </Box>
            )}
            maxDropdownHeight={360}
            searchable
            nothingFoundMessage="No test matches"
            error={modules.isError ? "Could not load the list of tests." : undefined}
          />
          {info?.summary && (
            <Text size="sm" c="dimmed" mt={-8}>
              {info.summary}
            </Text>
          )}

          {isAccess ? (
            <AccessCheckForm onParams={setAccessParams} />
          ) : isApk ? (
            <FileInput
              label="Android app file"
              description="The app is reviewed here. Nothing is sent to the app's servers."
              placeholder={apkName || "Choose an .apk file"}
              accept=".apk,application/vnd.android.package-archive"
              clearable
              error={apkError}
              onChange={onApkPick}
            />
          ) : (
            <>
              <Textarea
                label="Addresses to test"
                description={
                  info?.targets === "hostport"
                    ? "One per line, as a server name and port."
                    : "One per line."
                }
                placeholder={
                  info?.targets === "hostport"
                    ? "www.example.com:443"
                    : "https://www.example.com/"
                }
                autosize
                minRows={3}
                value={targetText}
                onChange={(ev) => setTargetText(ev.currentTarget.value)}
              />
              <Box>
                <Button
                  variant="subtle"
                  size="compact-sm"
                  ml={-8}
                  aria-expanded={advanced}
                  rightSection={advanced ? <IconChevronUp size={14} /> : <IconChevronDown size={14} />}
                  onClick={() => setAdvanced((v) => !v)}
                >
                  Advanced settings
                </Button>
                <Collapse expanded={advanced}>
                  <Textarea
                    mt="xs"
                    label="Extra settings (JSON)"
                    description="Only needed for tests that take their own configuration. Leave empty otherwise."
                    autosize
                    minRows={2}
                    value={paramsText}
                    onChange={(ev) => setParamsText(ev.currentTarget.value)}
                    error={paramsError}
                    styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)" } }}
                  />
                </Collapse>
              </Box>
            </>
          )}

          {dispatch.isError && (
            <ErrorNote title="The test could not start">{errorText(dispatch.error)}</ErrorNote>
          )}
          <Group>
            <Button
              leftSection={<IconPlayerPlay size={16} />}
              loading={dispatch.isPending}
              disabled={!canRun}
              onClick={onRun}
            >
              Run test
            </Button>
          </Group>
        </Stack>
      </Section>

        <EarlierTests jobs={jobs} shown={shown?.jobId} onPick={setPicked} />
      </SimpleGrid>

      {shown && <TestResult key={shown.jobId} job={shown} engagementId={id} />}
    </Stack>
  );
}

// What an earlier test came to, in a word.
function jobSummary(job: Job): { label: string; tone: Tone } {
  const o = job.summary;
  if (!job.done || !o) return { label: "Running", tone: "brand" };
  if (o.error || o.status === "error") return { label: "Did not finish", tone: "bad" };
  if (o.findings > 0) return { label: plural(o.findings, "finding"), tone: "bad" };
  if (job.module === "recon") return { label: "Profile ready", tone: "neutral" };
  if (o.allowed === 0 && o.denied > 0) return { label: "Skipped", tone: "warn" };
  return { label: "Nothing found", tone: "good" };
}

function EarlierTests({
  jobs,
  shown,
  onPick,
}: {
  jobs: Job[];
  shown?: string;
  onPick: (jobId: string) => void;
}) {
  return (
    <Section flush title="Earlier tests" description="Open one to see its results again.">
      {jobs.length === 0 ? (
        <EmptyState
          title="No tests yet"
          description="Tests you run in this engagement are listed here."
        />
      ) : (
        <Box mah={420} style={{ overflowY: "auto" }}>
          {jobs.map((j) => {
            const sum = jobSummary(j);
            const on = j.jobId === shown;
            return (
              <UnstyledButton
                key={j.jobId}
                onClick={() => onPick(j.jobId)}
                aria-pressed={on}
                w="100%"
                px="lg"
                py="sm"
                className="ares-clickable"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  borderTop: "1px solid var(--ares-line)",
                  background: on ? "var(--ares-subtle)" : undefined,
                }}
              >
                <Box style={{ flex: 1, minWidth: 0 }}>
                  <Text fw={600}>{moduleInfo(j.module).label}</Text>
                  <Text size="sm" c="dimmed">
                    {formatWhen(j.at)}
                  </Text>
                </Box>
                <ToneBadge tone={sum.tone}>{sum.label}</ToneBadge>
              </UnstyledButton>
            );
          })}
        </Box>
      )}
    </Section>
  );
}

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function TestResult({ job, engagementId }: { job: Job; engagementId: string }) {
  const { findings: register } = useFindings(engagementId);
  const title = "Results";
  const when = `${moduleInfo(job.module).label} · ${formatWhen(job.at)}`;

  const outcome = useJobOutcome(job.jobId, job.done);
  // A test started here is shown live, once; after that, as plain results.
  const [live] = useState(() => liveRun(job.jobId));
  const [watched, setWatched] = useState(false);
  const liveView = live && !outcome.isError && (
    <LiveTest
      jobId={job.jobId}
      module={job.module}
      targets={live.targets ?? []}
      startedAt={live.at}
      outcome={job.done ? outcome.data : undefined}
      engagementId={engagementId}
      onFinished={() => {
        markPlayed(job.jobId);
        setWatched(true);
      }}
    />
  );
  if (liveView && !watched) return liveView;

  if (outcome.isError) {
    return (
      <Section title={title} description={when}>
        <ErrorNote title="Could not load the results">{errorText(outcome.error)}</ErrorNote>
      </Section>
    );
  }
  if (!job.done || !outcome.data) {
    return (
      <Section title={title} description={when}>
        <LoadingState label={job.done ? "Loading the results…" : "Running the test…"} />
      </Section>
    );
  }

  const o = outcome.data;
  const findings = o.results
    .filter((r) => r.kind === "finding" || r.kind === "info")
    .map((r) => {
      const f = toFinding(r.data, r.kind, r.technique);
      // The same finding in the register, when it is one that can be opened.
      const record = register.find(
        (x) =>
          x.finding.title === f.title &&
          (x.finding.url ?? x.target) === (f.url ?? targetLabel(r.target)),
      );
      return { f, record };
    })
    .sort((a, b) => severityRank(a.f.severity) - severityRank(b.f.severity));
  const profiles = o.results.filter((r) => r.kind === "profile");
  const assets = o.results.filter(
    (r) => r.kind !== "finding" && r.kind !== "info" && r.kind !== "profile",
  );

  const counts = findings.reduce<Partial<Record<Severity, number>>>((acc, { f }) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <>
    {liveView}
    <Section
      title={title}
      description={when}
      aside={
        findings.length > 0 ? (
          <Group gap="xs">
            {ORDER.filter((s) => counts[s]).map((s) => (
              <SeverityBadge key={s} severity={s} count={counts[s]} />
            ))}
          </Group>
        ) : undefined
      }
    >
      <Group gap="xl" align="flex-end">
        <Stat
          value={findings.length}
          label={findings.length === 1 ? "finding" : "findings"}
          tone={findings.length > 0 ? "warn" : "good"}
        />
        <Stat value={o.allowed.length} label={o.allowed.length === 1 ? "address tested" : "addresses tested"} />
        <Stat value={o.denied.length} label="skipped, out of scope" />
      </Group>

      {o.error && <ErrorNote title="The test did not finish">{o.error}</ErrorNote>}

      {profiles.length > 0 && (
        <Group gap="sm">
          <Text>The target profile is ready.</Text>
          <Link to="/engagements/$id" params={{ id: engagementId }} search={{ view: "profile" }} className="ares-link">
            Open the target profile
          </Link>
        </Group>
      )}

      {findings.length > 0 && (
        <Box>
          {findings.map(({ f, record }, i) => {
            const row = (
              <Group
                gap="sm"
                wrap="nowrap"
                py="sm"
                style={{ borderTop: "1px solid var(--ares-line)" }}
              >
                <SeverityBadge severity={f.severity} />
                <Box style={{ flex: 1, minWidth: 0 }}>
                  <Text fw={600}>{f.title}</Text>
                  {f.description && (
                    <Text size="sm" c="dimmed" lineClamp={1}>
                      {f.description}
                    </Text>
                  )}
                </Box>
                {record && (
                  <Box c="dimmed" style={{ display: "flex" }}>
                    <IconChevronRight size={16} />
                  </Box>
                )}
              </Group>
            );
            return record ? (
              <Link
                key={i}
                to="/engagements/$id"
                params={{ id: engagementId }}
                search={{ view: "findings", finding: record.id }}
                className="ares-clickable"
                style={{ display: "block", color: "inherit", textDecoration: "none" }}
              >
                {row}
              </Link>
            ) : (
              <Box key={i}>{row}</Box>
            );
          })}
        </Box>
      )}

      {findings.length === 0 && assets.length === 0 && profiles.length === 0 && !o.error && (
        <EmptyState
          icon={<IconCircleCheck size={22} />}
          title="Nothing found"
          description={`${plural(o.allowed.length, "address", "addresses")} checked and no weakness matched.`}
        />
      )}

      {o.denied.length > 0 && (
        <Box bg="var(--ares-subtle)" p="md" style={{ borderRadius: 8 }}>
          <Text size="xs" fw={600} c="dimmed" mb={2}>
            {o.denied.length === 1 ? "Skipped address" : "Skipped addresses"}
          </Text>
          <Stack gap={4}>
            {o.denied.map((d, i) => (
              <Text key={i} size="sm">
                <Text span fw={600}>
                  {targetLabel(d.target)}
                </Text>{" "}
                <Text span c="dimmed">
                  {/not in the approved scope/.test(d.reason)
                    ? "is not in the approved scope, so it was not touched."
                    : d.reason}
                </Text>
              </Text>
            ))}
          </Stack>
        </Box>
      )}

      {assets.length > 0 && (
        <Box>
          <Title order={3} mb="xs">
            Also discovered
          </Title>
          <Table withTableBorder horizontalSpacing="md">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Type</Table.Th>
                <Table.Th>Address</Table.Th>
                <Table.Th>Details</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {assets.map((r, i) => (
                <Table.Tr key={i}>
                  <Table.Td style={{ textTransform: "capitalize" }}>{r.kind}</Table.Td>
                  <Table.Td>{targetLabel(r.target)}</Table.Td>
                  <Table.Td>
                    <Text size="sm" c="dimmed" style={{ wordBreak: "break-word" }}>
                      {r.data ? describe(r.data) : ""}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Box>
      )}
    </Section>
    </>
  );
}

// describe turns a result's loose data into a readable line of "name: value".
function describe(data: JsonObject): string {
  return Object.entries(data)
    .map(([k, v]) => `${k.replace(/[_-]/g, " ")}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

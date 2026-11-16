import { Fragment, useRef, useState, type ReactNode } from "react";
import {
  Badge,
  Box,
  Button,
  Checkbox,
  Code,
  CopyButton,
  Group,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  ThemeIcon,
  Tooltip,
  UnstyledButton,
} from "@mantine/core";
import { IconAlertTriangle, IconCopy, IconFileSearch, IconFolder, IconUpload, IconX } from "@tabler/icons-react";
import type { JsonObject } from "@bufbuild/protobuf";
import { useQueries } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { control } from "../client.ts";
import type { Engagement } from "../gen/ares/v1/ares_pb.ts";
import { errorText, formatBytes, formatWhen, logEventLabel, plural } from "../lib/labels.ts";
import { addPending, recordForensicRun, useForensicRuns, type ForensicRun } from "../lib/local.ts";
import { useTenant } from "../tenant.tsx";
import { EmptyState, ErrorNote, InfoNote, LoadingState, PageHeader, Section, ToneBadge } from "../ui/index.tsx";
import { FindingsTable } from "../features/findings/FindingsTable.tsx";
import { CasePicker, isQuickCase, QUICK_CASE, QUICK_VALUE, useEnsureQuickCase } from "../features/forensics/CasePicker.tsx";
import { CheckRun, SOURCE_ICON } from "../features/forensics/CheckRun.tsx";
import type { LeftOut } from "../features/forensics/files.ts";
import { useFeeds } from "../features/forensics/indicators.ts";
import { ProvenanceTag } from "../features/forensics/Provenance.tsx";
import { ShareIndicators } from "../features/forensics/ShareIndicators.tsx";
import { MAX_FILE_BYTES, planChecks, sourceDef, SOURCES, type SourceId } from "../features/forensics/sources.ts";
import { ThreatIndicators } from "../features/forensics/ThreatIndicators.tsx";
import { useEngagements, useFindings, useJobs, type FindingRecord } from "../features/workspace/data.ts";

const route = getRouteApi("/forensics");

// The capabilities whose findings belong on this page.
const FORENSIC = [
  "filemeta",
  "logscan",
  "iocmatch",
  "triage",
  "apkscan",
  "wpscan",
  "apkbackend",
  "androidqf",
  "iosbackup",
  "persistplist",
  "dnslogscan",
  "connrecord",
  "eventlog",
  "winpersist",
  "winartifacts",
  "mailheader",
  "browserhist",
  "timeline",
];

// Modules whose full results this page reads: evidence, timelines and the
// parts a check could not read.
const OUTCOME_MODULES = [...FORENSIC, "evidence"].filter((m) => !["filemeta", "wpscan", "apkscan"].includes(m));

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number => (typeof v === "number" ? v : 0);
const strs = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : [];
const objs = (v: unknown): JsonObject[] =>
  Array.isArray(v)
    ? v.filter((x): x is JsonObject => !!x && typeof x === "object" && !Array.isArray(x))
    : [];
const obj = (v: unknown): JsonObject =>
  v && typeof v === "object" && !Array.isArray(v) ? (v as JsonObject) : {};

// Why a file inside a bundle was left out, in plain words.
function bundleFormat(format: string): string {
  switch (format) {
    case "zip":
      return "ZIP bundle";
    case "tar":
      return "TAR bundle";
    case "tar.gz":
    case "tgz":
      return "TAR.GZ bundle";
    case "7z":
      return "7-Zip bundle";
    default:
      return "Bundle";
  }
}

// ForensicsPage is where files, phones and logs from an incident are looked
// into: recorded with a provable chain of custody, checked, and read for signs
// of attack or known threats. Originals are never changed, and nothing the
// evidence came from is ever contacted.
export function ForensicsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const { tenantId } = useTenant();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const [source, setSource] = useState<SourceId>("files");
  const runs = useForensicRuns();

  const quick = all.find(isQuickCase);
  const picked = search.engagement ? all.find((e) => e.id === search.engagement) : undefined;
  const value = !picked || isQuickCase(picked) ? QUICK_VALUE : picked.id;
  const chosen = value === QUICK_VALUE ? quick : picked;

  const header = (
    <PageHeader
      title="Forensics"
      description="Look into files, phones and logs from an incident. Originals are never changed, every item is fingerprinted and written to the activity log, and nothing on a phone, server or network is ever contacted."
    />
  );

  if (engagements.isLoading) return <LoadingState />;
  if (engagements.isError) {
    return (
      <Stack gap="lg">
        {header}
        <ErrorNote title="Could not load forensics">
          Ares could not reach its server. Check that it is running, then reload the page.
        </ErrorNote>
      </Stack>
    );
  }

  const caseRuns = runs.filter((r) => r.tenantId === tenantId && chosen && r.engagementId === chosen.id);
  const showing = caseRuns.filter((r) => !r.dismissed).slice(0, 2);

  return (
    <Stack gap="lg">
      {header}
      <CasePicker
        engagements={all}
        value={value}
        onChange={(v) => void navigate({ search: v === QUICK_VALUE ? {} : { engagement: v } })}
      />
      <SourceChooser value={source} onChange={setSource} />
      <Uploader key={`${tenantId}-${source}-${value}`} source={source} chosen={chosen} quick={value === QUICK_VALUE} engagements={all} />
      {showing.map((r) => (
        <CheckRun key={r.id} run={r} />
      ))}
      <ThreatIndicators />
      {chosen ? (
        <CaseResults key={`${tenantId}-${chosen.id}`} id={chosen.id} name={chosen.name} runs={caseRuns} />
      ) : (
        <ResultsView caseId={undefined} caseName={QUICK_CASE} evidence={[]} findings={[]} gaps={[]} extras={null} />
      )}
    </Stack>
  );
}

// SourceChooser asks where the evidence came from. Each choice swaps the
// uploader and the checks that can run on it.
function SourceChooser({ value, onChange }: { value: SourceId; onChange: (v: SourceId) => void }) {
  return (
    <Section
      title={
        <Group gap="xs">
          What are you looking into?
          <ToneBadge tone="brand" size="sm">
            New
          </ToneBadge>
        </Group>
      }
      description="Pick where the evidence came from. Each source is read offline: Ares never talks to the phone, server or network it came from."
    >
      <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} spacing="sm" role="radiogroup" aria-label="Where the evidence came from">
        {SOURCES.map((s) => {
          const Icon = SOURCE_ICON[s.id]!;
          const on = s.id === value;
          return (
            <UnstyledButton
              key={s.id}
              className="ares-source"
              role="radio"
              aria-checked={on}
              onClick={() => onChange(s.id)}
            >
              <ThemeIcon variant={on ? "filled" : "light"} color={on ? "brand" : "gray"} size={30} radius="md">
                <Icon size={17} />
              </ThemeIcon>
              <Text fw={600} size="sm" c={on ? "brand.8" : undefined}>
                {s.title}
              </Text>
              <Text size="xs" c="dimmed">
                {s.blurb}
              </Text>
            </UnstyledButton>
          );
        })}
      </SimpleGrid>
    </Section>
  );
}

const MB = 1024 * 1024;

// Uploader takes the evidence for the chosen source, reads it here, and starts
// the checks. Under Quick check it files the evidence in the personal case,
// creating it the first time.
function Uploader({
  source,
  chosen,
  quick,
  engagements,
}: {
  source: SourceId;
  chosen: Engagement | undefined;
  quick: boolean;
  engagements: Engagement[];
}) {
  const def = sourceDef(source);
  const { tenantId } = useTenant();
  const feeds = useFeeds(tenantId);
  const ensureQuick = useEnsureQuickCase(engagements);
  const [files, setFiles] = useState<File[]>([]);
  const [origin, setOrigin] = useState("");
  const [options, setOptions] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(def.options.map((o) => [o.id, o.on])),
  );
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const filePicker = useRef<HTMLInputElement>(null);
  const folderPicker = useRef<HTMLInputElement>(null);

  const names = files.map((f) => f.name);
  const visible = def.options.filter((o) => !o.when || o.when(names));
  const total = files.reduce((n, f) => n + f.size, 0);
  const tooBig =
    source === "files"
      ? files.find((f) => f.size > MAX_FILE_BYTES)
      : files.find((f) => f.size > 1024 * MB);
  const blocked = chosen && !quick && chosen.status !== "authorized";
  const halted = chosen?.status === "halted";
  const usingFeeds = feeds.filter((f) => f.inUse).length;

  const choose = (list: FileList | null) => {
    if (!list || list.length === 0) return;
    setProblem(null);
    setFiles([...list]);
  };

  const submit = async () => {
    setProblem(null);
    setBusy("Reading the evidence…");
    try {
      const enabled = Object.fromEntries(visible.map((o) => [o.id, options[o.id] === true]));
      const plan = await planChecks({ source, files, origin: origin.trim(), options: enabled, feeds });
      if (plan.checks.length === 0) {
        setProblem(
          "Nothing chosen is something these checks read." +
            (plan.leftOut.length > 0 ? ` ${plan.leftOut.slice(0, 3).map((l) => `${l.name}: ${l.reason}.`).join(" ")}` : ""),
        );
        return;
      }
      setBusy("Starting the checks…");
      const engagementId = quick ? await ensureQuick() : chosen!.id;
      const jobs: ForensicRun["jobs"] = [];
      for (const c of plan.checks) {
        const res = await control.dispatchJob({
          engagementId,
          tenantId,
          module: c.module,
          actor: "operator",
          targets: [],
          params: c.params,
        });
        addPending({ jobId: res.jobId, engagementId, tenantId, module: c.module, targets: [] });
        jobs.push({ jobId: res.jobId, module: c.module, label: c.label, running: c.running });
      }
      recordForensicRun({
        id: crypto.randomUUID(),
        tenantId,
        engagementId,
        source,
        title: plan.title,
        at: new Date().toISOString(),
        jobs,
        leftOut: plan.leftOut,
      });
      setFiles([]);
      if (filePicker.current) filePicker.current.value = "";
      if (folderPicker.current) folderPicker.current.value = "";
    } catch (err) {
      setProblem(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Section title={def.heading} description={def.intro}>
      {blocked || halted ? (
        <InfoNote title={halted ? "Testing was stopped" : "Permission is not recorded yet"}>
          {halted
            ? "No more evidence can be added to this case. What was recorded is kept below."
            : "Evidence can be added once this engagement's permission is on file. Or choose Quick check to look into it on its own."}
        </InfoNote>
      ) : (
        <Stack gap="md" maw={720}>
          <Box>
            <Text fw={600} size="sm" mb={2}>
              {def.fileLabel}
            </Text>
            <Text size="xs" c="dimmed" mb={6}>
              {def.fileHelp}
            </Text>
            <input ref={filePicker} type="file" multiple hidden onChange={(ev) => choose(ev.currentTarget.files)} />
            <input
              ref={folderPicker}
              type="file"
              hidden
              onChange={(ev) => choose(ev.currentTarget.files)}
              {...({ webkitdirectory: "", directory: "" } as object)}
            />
            <Box className="ares-dropzone">
              {files.length === 0 ? (
                <Group gap="sm">
                  <Button
                    variant="default"
                    size="sm"
                    leftSection={<IconUpload size={16} />}
                    onClick={() => filePicker.current?.click()}
                  >
                    {def.folder ? "Choose files or a ZIP" : "Choose files"}
                  </Button>
                  {def.folder && (
                    <Button
                      variant="default"
                      size="sm"
                      leftSection={<IconFolder size={16} />}
                      onClick={() => folderPicker.current?.click()}
                    >
                      Choose a folder
                    </Button>
                  )}
                </Group>
              ) : (
                <Group justify="space-between" wrap="nowrap" gap="sm">
                  <Box style={{ minWidth: 0 }}>
                    <Text size="sm" fw={600} style={{ wordBreak: "break-word" }}>
                      {files[0]!.webkitRelativePath
                        ? `${files[0]!.webkitRelativePath.split("/")[0]} (folder)`
                        : files.length === 1
                          ? files[0]!.name
                          : `${files[0]!.name} and ${files.length - 1} more`}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {plural(files.length, "file")} · {formatBytes(total)}
                    </Text>
                  </Box>
                  <Button
                    variant="subtle"
                    color="gray"
                    size="compact-sm"
                    leftSection={<IconX size={14} />}
                    onClick={() => setFiles([])}
                  >
                    Clear
                  </Button>
                </Group>
              )}
            </Box>
            {tooBig && (
              <Text size="sm" c="red.7" mt={6}>
                {tooBig.name} is larger than {source === "files" ? "20 MB" : "1 GB"}.
              </Text>
            )}
          </Box>
          <TextInput
            label="Where it came from (optional)"
            description="The device, server or person it was collected from."
            placeholder={def.placeholder}
            value={origin}
            onChange={(ev) => setOrigin(ev.currentTarget.value)}
          />
          <Box>
            <Text fw={600} size="sm" mb={6}>
              Also look into it
            </Text>
            <Stack gap="xs">
              {visible.map((o) => (
                <Checkbox
                  key={o.id}
                  label={o.label}
                  description={
                    o.id === "threats" && usingFeeds === 0
                      ? `${o.description} No feed is loaded yet, so only suspicious-looking values are flagged.`
                      : o.description
                  }
                  checked={options[o.id] === true}
                  onChange={(ev) => {
                    const v = ev.currentTarget.checked;
                    setOptions((cur) => ({ ...cur, [o.id]: v }));
                  }}
                />
              ))}
            </Stack>
          </Box>
          {quick && (
            <Text size="xs" c="dimmed">
              By adding it you confirm the evidence is yours, or that its owner agreed to it being examined. That is
              recorded in the Quick check activity log.
            </Text>
          )}
          {problem && <ErrorNote title="The evidence could not be added">{problem}</ErrorNote>}
          <Group>
            <Button
              leftSection={<IconUpload size={16} />}
              loading={busy !== null}
              disabled={files.length === 0 || !!tooBig}
              onClick={() => void submit()}
            >
              {def.button}
            </Button>
            {busy && (
              <Text size="sm" c="dimmed">
                {busy}
              </Text>
            )}
          </Group>
        </Stack>
      )}
    </Section>
  );
}

type Outcome = { r: { kind: string; capability: string; data?: JsonObject }; job: { jobId: string; module: string; at: string }; item: string };

// CaseResults loads one case's evidence, findings and gaps.
function CaseResults({ id, name, runs }: { id: string; name: string; runs: ForensicRun[] }) {
  const { tenantId } = useTenant();
  const { jobs } = useJobs(id);
  const { findings } = useFindings(id, true);

  const wanted = jobs.filter((j) => j.done && OUTCOME_MODULES.includes(j.module));
  const outcomes = useQueries({
    queries: wanted.map((j) => ({
      queryKey: ["outcome", tenantId, j.jobId],
      queryFn: () => control.getJob({ jobId: j.jobId, tenantId }),
      staleTime: Infinity,
    })),
  });
  // Each result remembers which uploaded item it belongs to: the custody
  // record comes first, then everything found in that item.
  const results: Outcome[] = outcomes.flatMap((o, i) => {
    let item = "";
    return (o.data?.results ?? []).map((r) => {
      if (r.kind === "evidence") item = str(r.data?.["name"]);
      return { r, job: wanted[i]!, item };
    });
  });
  const evidence = results.filter(({ r }) => r.kind === "evidence");

  // What could not be checked: what was left out before sending, a file a
  // check could not read, and a check that could not run at all.
  const gaps: LeftOut[] = [];
  for (const run of runs) gaps.push(...run.leftOut);
  for (const { r } of results) {
    const d = r.data ?? {};
    if (r.kind !== "info") continue;
    if (str(d["error"])) gaps.push({ name: str(d["name"]) || "A file", reason: str(d["description"]) || str(d["error"]) });
    else if (r.capability === "triage" && str(d["title"]).startsWith("Triage note"))
      gaps.push({ name: str(d["name"]), reason: str(d["description"]) });
  }
  for (const j of jobs) {
    if (j.done && j.summary?.status === "error" && FORENSIC.includes(j.module)) {
      gaps.push({ name: `The ${j.module} check`, reason: `it could not run: ${j.summary.error}` });
    }
  }
  const seen = new Set<string>();
  const uniqueGaps = gaps.filter((g) => {
    const k = `${g.name}|${g.reason}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  return (
    <ResultsView
      caseId={id}
      caseName={name}
      evidence={evidence}
      findings={findings.filter((f) => FORENSIC.includes(f.module))}
      gaps={uniqueGaps}
      extras={<Extras results={results} wanted={wanted} outcomes={outcomes.map((o) => o.data?.results ?? [])} />}
    />
  );
}

function ResultsView({
  caseId,
  caseName,
  evidence,
  findings,
  gaps,
  extras,
}: {
  caseId: string | undefined;
  caseName: string;
  evidence: Outcome[];
  findings: FindingRecord[];
  gaps: LeftOut[];
  extras: ReactNode;
}) {
  return (
    <>
      <Section
        flush
        title="Evidence and chain of custody"
        description="Every item recorded in this case. The fingerprint is also written to the activity log, which cannot be edited."
        aside={
          caseId ? (
            <Link to="/activity" search={{ engagement: caseId }} className="ares-link">
              See the record
            </Link>
          ) : undefined
        }
      >
        {evidence.length === 0 ? (
          <EmptyState
            icon={<IconFileSearch size={22} />}
            title="No evidence yet"
            description="What you add is listed here with its fingerprint, size and when it was recorded."
          />
        ) : (
          <Table.ScrollContainer minWidth={760}>
            <Table className="ares-stack">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Item</Table.Th>
                  <Table.Th>Size</Table.Th>
                  <Table.Th>Fingerprint (SHA-256)</Table.Th>
                  <Table.Th miw={180}>Came from</Table.Th>
                  <Table.Th>Recorded</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {evidence.map(({ r, job }, i) => {
                  const d = r.data ?? {};
                  const sha = str(d["sha256"]);
                  const name = str(d["name"]);
                  const bundle = d["extraction"] !== undefined;
                  const kind = bundle
                    ? bundleFormat(str(obj(d["extraction"])["format"]))
                    : name.toLowerCase().endsWith(".apk")
                      ? "Android app"
                      : str(d["contentType"]).split(";")[0];
                  return (
                    <Fragment key={`${job.jobId}-${i}`}>
                      <Table.Tr style={bundle ? { borderBottom: 0 } : undefined}>
                        <Table.Td data-primary>
                          <Text fw={600} style={{ wordBreak: "break-word" }}>
                            {name}
                          </Text>
                          <Text size="sm" c="dimmed">
                            {kind}
                          </Text>
                        </Table.Td>
                        <Table.Td data-label="Size" style={{ whiteSpace: "nowrap" }}>
                          {formatBytes(num(d["size"]))}
                        </Table.Td>
                        <Table.Td data-label="Fingerprint">
                          <CopyButton value={sha}>
                            {({ copied, copy }) => (
                              <Tooltip label={copied ? "Copied" : "Copy the full fingerprint"}>
                                <Code
                                  component="button"
                                  onClick={copy}
                                  style={{ cursor: "pointer", border: 0 }}
                                  aria-label={`Copy the fingerprint of ${name}`}
                                >
                                  {sha.slice(0, 16)}…
                                </Code>
                              </Tooltip>
                            )}
                          </CopyButton>
                        </Table.Td>
                        <Table.Td data-label="Came from">
                          <Text size="sm" c="dimmed">
                            {str(d["source"]) || "Not stated"}
                          </Text>
                        </Table.Td>
                        <Table.Td data-label="Recorded" style={{ whiteSpace: "nowrap" }}>
                          <Text size="sm" c="dimmed">
                            {formatWhen(str(d["ingestedAt"]) || job.at)}
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                      {bundle && (
                        <Table.Tr>
                          <Table.Td data-primary colSpan={5} pt={0}>
                            <BundleContents data={d} />
                          </Table.Td>
                        </Table.Tr>
                      )}
                    </Fragment>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Section>

      <Section
        flush
        title="What the checks found"
        description="Signs of known spyware, tampering, attack or known threats in the evidence, most serious first."
        aside={
          <Box visibleFrom="sm">
            <ShareIndicators caseId={caseId} caseName={caseName} findings={findings} />
          </Box>
        }
      >
        <Box hiddenFrom="sm" px="lg" pb="md">
          <ShareIndicators caseId={caseId} caseName={caseName} findings={findings} />
        </Box>
        {findings.length === 0 ? (
          <EmptyState
            title="Nothing found yet"
            description="Anything suspicious in what you add is listed here, with what it means and how to respond."
          />
        ) : (
          <FindingsTable findings={findings} extra={(f) => <ProvenanceTag raw={f.finding.raw} />} />
        )}
      </Section>

      <Section
        title="What could not be checked"
        description="A gap is never reported as clean. These parts could not be read, so nothing is claimed about them."
      >
        {gaps.length > 0 && (
          <Stack gap={6}>
            {gaps.slice(0, 50).map((g, i) => (
              <Text key={i} size="sm">
                <b style={{ wordBreak: "break-word" }}>{g.name}</b>: {g.reason}
              </Text>
            ))}
            {gaps.length > 50 && (
              <Text size="sm" c="dimmed">
                And {gaps.length - 50} more.
              </Text>
            )}
          </Stack>
        )}
        <Group
          gap="sm"
          wrap="nowrap"
          align="flex-start"
          p="sm"
          style={{ border: "1px solid var(--ares-line)", borderRadius: 8 }}
        >
          <IconAlertTriangle size={16} style={{ flex: "none", marginTop: 2, color: "var(--mantine-color-dimmed)" }} />
          <Text size="sm" c="dimmed">
            {gaps.length === 0 && evidence.length > 0 ? "Every check that ran could read what it was given. " : ""}A
            clean result covers only what was read. It does not mean the device is clean. Grade-A mercenary spyware is
            built to defeat a check like this, so a concrete suspicion needs expert forensic help (Amnesty Security Lab,
            Access Now's Digital Security Helpline, Citizen Lab).
          </Text>
        </Group>
      </Section>

      {extras}
    </>
  );
}

// Extras are the per-check details the older checks report: app servers,
// WordPress parts and log timelines.
function Extras({
  results,
  wanted,
  outcomes,
}: {
  results: Outcome[];
  wanted: { jobId: string; module: string }[];
  outcomes: { kind: string; capability: string; data?: JsonObject }[][];
}) {
  const timelines = results.filter(({ r, job }) => job.module === "logscan" && Array.isArray(r.data?.["events"]));
  const inventories = results.filter(
    ({ r }) => r.capability === "wpscan" && r.kind === "info" && (r.data?.["plugins"] || r.data?.["themes"]),
  );
  const backends = wanted
    .map((job, i) => ({ job, results: outcomes[i] ?? [] }))
    .filter(({ job }) => job.module === "apkbackend")
    .map(({ job, results: rs }) => {
      const own = rs.filter((r) => r.capability === "apkbackend" && r.kind === "info");
      return {
        job,
        summary: own.find((r) => r.data?.["package"] !== undefined || r.data?.["hosts"] !== undefined),
        outside: objs(own.find((r) => Array.isArray(r.data?.["targets"]) && objs(r.data?.["targets"]).length > 0)?.data?.["targets"]),
      };
    })
    .filter((b) => b.summary);

  return (
    <>
      {backends.map(({ job, summary, outside }) => (
        <AppBackend key={job.jobId} data={summary!.data ?? {}} outside={outside} />
      ))}

      {inventories.map(({ r, job, item }, i) => (
        <WordPressParts key={`${job.jobId}-wp-${i}`} data={r.data ?? {}} bundle={str(r.data?.["bundle"]) || item} />
      ))}

      {timelines.map(({ r, job }, i) => {
        const events = (r.data?.["events"] as JsonObject[]) ?? [];
        return (
          <Section
            key={`${job.jobId}-${i}`}
            flush
            title={`Attack timeline: ${str(r.data?.["name"])}`}
            description="Signs of attack found in this log, in the order they happened."
          >
            {events.length === 0 ? (
              <EmptyState title="No signs of attack in this log" />
            ) : (
              <Table.ScrollContainer minWidth={720}>
                <Table className="ares-stack">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th w={190}>When</Table.Th>
                      <Table.Th w={260}>What happened</Table.Th>
                      <Table.Th>Log line</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {events.map((e, ei) => (
                      <Table.Tr key={ei}>
                        <Table.Td data-label="When" style={{ whiteSpace: "nowrap" }}>
                          <Text size="sm" c="dimmed">
                            {str(e["time"]) ? formatWhen(str(e["time"])) : "Time not in the log"}
                          </Text>
                        </Table.Td>
                        <Table.Td data-label="What happened">{logEventLabel(str(e["category"]))}</Table.Td>
                        <Table.Td data-label="Log line">
                          <Code bg="transparent" p={0} style={{ wordBreak: "break-all" }}>
                            {str(e["line"])}
                          </Code>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </Section>
        );
      })}
    </>
  );
}

// BundleContents lists what was inside a bundle, each file with its own
// fingerprint, and says plainly when something was left out.
function BundleContents({ data }: { data: JsonObject }) {
  const [open, setOpen] = useState(false);
  const ex = obj(data["extraction"]);
  const members = objs(data["members"]);
  const count = num(data["memberCount"]) || num(ex["extracted"]);
  const skipped = objs(ex["skipped"]);
  return (
    <Box>
      <Button variant="subtle" size="compact-sm" px={0} onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {open ? "Hide" : "Show"} the {count} {count === 1 ? "file" : "files"} inside
      </Button>
      {open && (
        <Stack gap="xs" mt="xs">
          {(ex["truncated"] === true || skipped.length > 0) && (
            <Text size="sm" c="dimmed">
              {ex["truncated"] === true ? "The bundle was too large to open in full. " : ""}
              {skipped.length > 0
                ? `${skipped.length} ${skipped.length === 1 ? "entry was" : "entries were"} left out: ${skipped
                    .slice(0, 5)
                    .map((s) => `${str(s["name"])} (${str(s["reason"])})`)
                    .join(", ")}${skipped.length > 5 ? ", and more." : "."}`
                : ""}
            </Text>
          )}
          <Box style={{ maxHeight: 280, overflowY: "auto", border: "1px solid var(--ares-line)", borderRadius: 8 }}>
            <Table className="ares-stack" verticalSpacing={6}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>File inside</Table.Th>
                  <Table.Th>Size</Table.Th>
                  <Table.Th>Fingerprint</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {members.map((m, i) => (
                  <Table.Tr key={i}>
                    <Table.Td data-primary style={{ wordBreak: "break-all" }}>{str(m["name"])}</Table.Td>
                    <Table.Td data-label="Size" style={{ whiteSpace: "nowrap" }}>{formatBytes(num(m["size"]))}</Table.Td>
                    <Table.Td data-label="Fingerprint">
                      <Tooltip label={str(m["sha256"])}>
                        <Code>{str(m["sha256"]).slice(0, 12)}…</Code>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Box>
          {count > members.length && (
            <Text size="sm" c="dimmed">
              Showing the first {members.length} of {count} files.
            </Text>
          )}
        </Stack>
      )}
    </Box>
  );
}

// AppBackend shows the servers an Android app talks to, and which of them
// were tested. A server outside the agreed scope is never touched.
function AppBackend({ data, outside }: { data: JsonObject; outside: JsonObject[] }) {
  const inScope = strs(data["inScope"]);
  const outOfScope = outside.length > 0 ? outside.map((t) => str(t["target"])) : strs(data["outOfScope"]);
  const endpoints = strs(data["endpoints"]);
  const secrets = objs(data["secrets"]);
  return (
    <Section
      title={`Servers the app talks to: ${str(data["package"]) || "Android app"}`}
      description="Worked out from the app's contents. Only servers inside this engagement's scope were tested; their results are in the findings above."
    >
      <Stack gap="md">
        {data["cleartext"] === true && (
          <InfoNote title="The app can send data without encryption">
            At least one of its server addresses uses plain HTTP, so traffic can be read on the way.
          </InfoNote>
        )}
        {inScope.length + outOfScope.length === 0 ? (
          <EmptyState title="No server addresses found in this app" />
        ) : (
          <Table className="ares-stack">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Server</Table.Th>
                <Table.Th w={240}>Status</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {inScope.map((t) => (
                <Table.Tr key={t}>
                  <Table.Td data-primary style={{ wordBreak: "break-all" }}>{t}</Table.Td>
                  <Table.Td data-label="Status">
                    <ToneBadge tone="good">In scope, tested</ToneBadge>
                  </Table.Td>
                </Table.Tr>
              ))}
              {outOfScope.map((t) => (
                <Table.Tr key={t}>
                  <Table.Td data-primary style={{ wordBreak: "break-all" }}>{t}</Table.Td>
                  <Table.Td data-label="Status">
                    <ToneBadge tone="warn">Outside scope, not tested</ToneBadge>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
        {outOfScope.length > 0 && (
          <InfoNote title="Some servers were not tested">
            <Stack gap="xs" align="flex-start">
              <Text size="sm">
                They are outside the scope the owner approved, and an approved scope cannot be changed. To test
                them, get the owner's permission and create an engagement that lists them.
              </Text>
              <Group gap="sm">
                <CopyButton value={outOfScope.join("\n")}>
                  {({ copied, copy }) => (
                    <Button variant="default" size="xs" leftSection={<IconCopy size={14} />} onClick={copy}>
                      {copied ? "Copied" : "Copy these addresses"}
                    </Button>
                  )}
                </CopyButton>
                <Link to="/engagements" className="ares-link">
                  Go to engagements
                </Link>
              </Group>
            </Stack>
          </InfoNote>
        )}
        {secrets.length > 0 && (
          <Box>
            <Text fw={600} size="sm" mb={6}>
              Keys and passwords left in the app
            </Text>
            <Group gap="xs">
              {secrets.map((s, i) => (
                <Tooltip key={i} label={str(s["redacted"]) || "Value hidden"}>
                  <Badge color="red" variant="light">
                    {str(s["label"]) || str(s["kind"])}
                  </Badge>
                </Tooltip>
              ))}
            </Group>
          </Box>
        )}
        {endpoints.length > 0 && (
          <Box>
            <Text fw={600} size="sm" mb={6}>
              Addresses the app calls ({endpoints.length})
            </Text>
            <Code block style={{ maxHeight: 180, overflowY: "auto" }}>
              {endpoints.join("\n")}
            </Code>
          </Box>
        )}
      </Stack>
    </Section>
  );
}

// WordPressParts lists the plugins and themes found in a WordPress backup.
function WordPressParts({ data, bundle }: { data: JsonObject; bundle: string }) {
  const rows = [
    ...objs(data["plugins"]).map((p) => ({ kind: "Plugin", ...p })),
    ...objs(data["themes"]).map((t) => ({ kind: "Theme", ...t })),
  ] as JsonObject[];
  return (
    <Section
      flush
      title={bundle ? `WordPress plugins and themes: ${bundle}` : "WordPress plugins and themes"}
      description="What this WordPress site has installed. Out-of-date plugins and themes are the most common way in, so compare the versions with the latest ones."
    >
      {rows.length === 0 ? (
        <EmptyState title="No plugins or themes found" />
      ) : (
        <Table className="ares-stack">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th w={140}>Kind</Table.Th>
              <Table.Th w={180}>Version</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r, i) => (
              <Table.Tr key={i}>
                <Table.Td data-primary>{str(r["slug"])}</Table.Td>
                <Table.Td data-label="Kind">{str(r["kind"])}</Table.Td>
                <Table.Td data-label="Version">{str(r["version"]) || "Not stated"}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </Section>
  );
}

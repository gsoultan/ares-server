import { Fragment, useState } from "react";
import {
  Badge,
  Box,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  FileInput,
  Group,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { IconCopy, IconFileSearch, IconUpload } from "@tabler/icons-react";
import type { JsonObject } from "@bufbuild/protobuf";
import { useQueries } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { control } from "../client.ts";
import { errorText, formatBytes, formatWhen, logEventLabel, moduleInfo } from "../lib/labels.ts";
import { useTenant } from "../tenant.tsx";
import {
  EmptyState,
  ErrorNote,
  InfoNote,
  LoadingState,
  PageHeader,
  Section,
  ToneBadge,
} from "../ui/index.tsx";
import { useStartTest } from "../features/engagement/startTest.ts";
import { FindingsTable } from "../features/findings/FindingsTable.tsx";
import { EngagementPicker } from "../features/workspace/EngagementPicker.tsx";
import { useEngagements, useFindings, useJobs } from "../features/workspace/data.ts";

const route = getRouteApi("/forensics");

// Files travel inside the request, so very large ones are turned away here
// with a clear message instead of failing on the way.
const MAX_FILE_BYTES = 20 * 1024 * 1024;

const FORENSIC = ["filemeta", "logscan", "iocmatch", "triage", "apkscan", "wpscan", "apkbackend"];

const isApp = (f: File) => f.name.toLowerCase().endsWith(".apk");

function readBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const res = String(reader.result);
      resolve(res.slice(res.indexOf(",") + 1));
    };
    reader.onerror = () => reject(new Error(`Could not read ${file.name}.`));
    reader.readAsDataURL(file);
  });
}

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

// ForensicsPage is where files and logs from an incident are looked into:
// recorded with a provable chain of custody, checked, and read for signs of
// attack. Originals are never changed.
export function ForensicsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const { tenantId } = useTenant();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const chosen =
    all.find((e) => e.id === search.engagement) ??
    all.find((e) => e.status === "authorized") ??
    all[0];

  const header = (
    <PageHeader
      title="Forensics"
      description="Look into files and logs from an incident. Originals are never changed, and every item is fingerprinted and written to the activity log."
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
  if (!chosen) {
    return (
      <Stack gap="lg">
        {header}
        <Card>
          <EmptyState
            icon={<IconFileSearch size={22} />}
            title="No engagement yet"
            description="Evidence is kept inside an engagement, so its handling is on record. Create one first."
          />
        </Card>
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      {header}
      <EngagementPicker
        engagements={all}
        value={chosen.id}
        onChange={(id) => void navigate({ search: { engagement: id } })}
      />
      <Workbench key={`${tenantId}-${chosen.id}`} id={chosen.id} status={chosen.status} />
    </Stack>
  );
}

function Workbench({ id, status }: { id: string; status: string }) {
  const { tenantId } = useTenant();
  const start = useStartTest(id);
  const { jobs } = useJobs(id);
  const { findings } = useFindings(id);

  const [files, setFiles] = useState<File[]>([]);
  const [source, setSource] = useState("");
  const [checkCore, setCheckCore] = useState(false);
  const [testServers, setTestServers] = useState(true);
  const [readLogs, setReadLogs] = useState(false);
  const [matchThreats, setMatchThreats] = useState(false);
  const [indicators, setIndicators] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  // The full results of the forensics jobs: evidence items and log timelines.
  const wanted = jobs.filter(
    (j) => j.done && ["evidence", "triage", "logscan", "apkbackend"].includes(j.module),
  );
  const outcomes = useQueries({
    queries: wanted.map((j) => ({
      queryKey: ["outcome", tenantId, j.jobId],
      queryFn: () => control.getJob({ jobId: j.jobId, tenantId }),
      staleTime: Infinity,
    })),
  });
  // Each result remembers which uploaded item it belongs to: the custody
  // record comes first, then everything found in that item.
  const results = outcomes.flatMap((o, i) => {
    let item = "";
    return (o.data?.results ?? []).map((r) => {
      if (r.kind === "evidence") item = str(r.data?.["name"]);
      return { r, job: wanted[i]!, item };
    });
  });
  const evidence = results.filter(({ r }) => r.kind === "evidence");
  const timelines = results.filter(
    ({ r, job }) => job.module === "logscan" && Array.isArray(r.data?.["events"]),
  );
  const inventories = results.filter(
    ({ r }) => r.capability === "wpscan" && r.kind === "info" && (r.data?.["plugins"] || r.data?.["themes"]),
  );
  const notes = results.filter(
    ({ r }) => r.capability === "triage" && r.kind === "info" && str(r.data?.["title"]).startsWith("Triage note"),
  );
  const backends = wanted
    .map((job, i) => ({ job, results: outcomes[i]?.data?.results ?? [] }))
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
  const apps = files.filter(isApp);
  const running = jobs.filter((j) => !j.done && moduleInfo(j.module).forensic);
  const forensicFindings = findings.filter((f) => FORENSIC.includes(f.module));

  const tooBig = files.find((f) => f.size > MAX_FILE_BYTES);
  const canAdd = status === "authorized";

  const submit = async () => {
    setProblem(null);
    setBusy(true);
    try {
      const items = await Promise.all(
        files.map(async (f) => ({
          name: f.name,
          base64: await readBase64(f),
          ...(source.trim() ? { source: source.trim() } : {}),
        })),
      );
      const params = { items } as unknown as JsonObject;
      // One intake job records custody, opens bundles and checks every file.
      await start.mutateAsync({
        module: "triage",
        targets: [],
        params: { items, verifyWordPressCore: checkCore } as unknown as JsonObject,
      });
      if (testServers) {
        for (const item of items.filter((it) => it.name.toLowerCase().endsWith(".apk"))) {
          await start.mutateAsync({
            module: "apkbackend",
            targets: [],
            params: { apkBase64: item.base64, name: item.name } as unknown as JsonObject,
          });
        }
      }
      if (readLogs) await start.mutateAsync({ module: "logscan", targets: [], params });
      if (matchThreats) {
        const texts = await Promise.all(files.map((f) => f.text()));
        await start.mutateAsync({
          module: "iocmatch",
          targets: [],
          params: {
            observations: files.map((f, i) => ({ name: f.name, text: texts[i] ?? "" })),
            indicators: indicators
              .split("\n")
              .map((l) => l.trim())
              .filter((l) => l !== "")
              .map((value) => ({ value })),
          } as unknown as JsonObject,
        });
      }
      setFiles([]);
    } catch (err) {
      setProblem(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Section
        title="Add evidence"
        description="Choose files or whole bundles. Each one is fingerprinted the moment it arrives, bundles are opened safely, and every file inside is checked for what it really is."
      >
        {!canAdd && (
          <InfoNote
            title={status === "halted" ? "Testing was stopped" : "Permission is not recorded yet"}
          >
            {status === "halted"
              ? "No more evidence can be added to this engagement. What was recorded is kept below."
              : "Evidence can be added once this engagement's scope and permission are on file."}
          </InfoNote>
        )}
        {canAdd && (
          <Stack gap="md" maw={640}>
            <FileInput
              label="Files"
              description="Any file, or a bundle: ZIP, TAR, TAR.GZ or 7-Zip. A website backup such as WordPress and Android apps (APK) get their own checks. Up to 20 MB each."
              placeholder="Choose one or more files"
              leftSection={<IconUpload size={16} />}
              multiple
              clearable
              value={files}
              onChange={setFiles}
              error={tooBig ? `${tooBig.name} is larger than 20 MB.` : undefined}
            />
            <TextInput
              label="Where it came from (optional)"
              description="The device, server or person the files were collected from."
              placeholder="Web server 2, collected by Dana Reyes"
              value={source}
              onChange={(ev) => setSource(ev.currentTarget.value)}
            />
            <Box>
              <Text fw={600} size="sm" mb={6}>
                Also look into them
              </Text>
              <Stack gap="xs">
                <Checkbox
                  label="Compare WordPress files with the official ones"
                  description="Spots changed or added core files in a WordPress backup. Asks wordpress.org for the official list, so it needs internet access."
                  checked={checkCore}
                  onChange={(ev) => setCheckCore(ev.currentTarget.checked)}
                />
                {apps.length > 0 && (
                  <Checkbox
                    label="Find and test the servers this app talks to"
                    description="Works out the app's servers from its contents. Only servers inside this engagement's scope are tested."
                    checked={testServers}
                    onChange={(ev) => setTestServers(ev.currentTarget.checked)}
                  />
                )}
                <Checkbox
                  label="Read them as logs"
                  description="Finds signs of attack in log files and puts them in order as a timeline."
                  checked={readLogs}
                  onChange={(ev) => setReadLogs(ev.currentTarget.checked)}
                />
                <Checkbox
                  label="Compare with known threats"
                  description="Looks for file fingerprints, addresses and domains that are known to be bad."
                  checked={matchThreats}
                  onChange={(ev) => setMatchThreats(ev.currentTarget.checked)}
                />
              </Stack>
            </Box>
            {matchThreats && (
              <Textarea
                label="Your list of known threats (optional)"
                description="One per line: a file fingerprint, a domain, a web address or an IP address. Without a list, only suspicious-looking addresses are flagged."
                autosize
                minRows={2}
                value={indicators}
                onChange={(ev) => setIndicators(ev.currentTarget.value)}
                styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)" } }}
              />
            )}
            {problem && <ErrorNote title="The evidence could not be added">{problem}</ErrorNote>}
            <Group>
              <Button
                leftSection={<IconUpload size={16} />}
                loading={busy}
                disabled={files.length === 0 || !!tooBig}
                onClick={() => void submit()}
              >
                Add evidence
              </Button>
              {running.length > 0 && (
                <Text size="sm" c="dimmed">
                  Working on it…
                </Text>
              )}
            </Group>
          </Stack>
        )}
      </Section>

      <Section
        flush
        title="Evidence and chain of custody"
        description="Every item recorded in this engagement. The fingerprint is also written to the activity log, which cannot be edited."
        aside={
          <Link to="/activity" search={{ engagement: id }} className="ares-link">
            See the record
          </Link>
        }
      >
        {evidence.length === 0 ? (
          <EmptyState
            icon={<IconFileSearch size={22} />}
            title="No evidence yet"
            description="Files you add are listed here with their fingerprint, size and when they were recorded."
          />
        ) : (
          <Table.ScrollContainer minWidth={760}>
            <Table className="ares-stack">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>File</Table.Th>
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
                          {str(d["name"])}
                        </Text>
                        <Text size="sm" c="dimmed">
                          {kind}
                        </Text>
                      </Table.Td>
                      <Table.Td data-label="Size" style={{ whiteSpace: "nowrap" }}>{formatBytes(num(d["size"]))}</Table.Td>
                      <Table.Td data-label="Fingerprint">
                        <CopyButton value={sha}>
                          {({ copied, copy }) => (
                            <Tooltip label={copied ? "Copied" : "Copy the full fingerprint"}>
                              <Code
                                component="button"
                                onClick={copy}
                                style={{ cursor: "pointer", border: 0 }}
                                aria-label={`Copy the fingerprint of ${str(d["name"])}`}
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
        description="Signs of tampering, attack or known threats in the evidence, most serious first."
      >
        {forensicFindings.length === 0 ? (
          <EmptyState
            title="Nothing found yet"
            description="Anything suspicious in the files you add is listed here, with what it means and how to respond."
          />
        ) : (
          <FindingsTable findings={forensicFindings} />
        )}
      </Section>

      {notes.length > 0 && (
        <InfoNote title="Some files could not be fully checked">
          <Stack gap={4}>
            {notes.map(({ r }, i) => (
              <Text key={i} size="sm">
                <b>{str(r.data?.["name"])}</b>: {str(r.data?.["description"])}
              </Text>
            ))}
          </Stack>
        </InfoNote>
      )}

      {backends.map(({ job, summary, outside }) => (
        <AppBackend key={job.jobId} data={summary!.data ?? {}} outside={outside} />
      ))}

      {inventories.map(({ r, job }, i) => (
        <WordPressParts key={`${job.jobId}-wp-${i}`} data={r.data ?? {}} bundle={str(r.data?.["bundle"]) || inventories[i]!.item} />
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

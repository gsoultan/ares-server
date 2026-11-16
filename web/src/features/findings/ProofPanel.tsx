import type { ReactNode } from "react";
import { Box, Button, Code, Group, Mark, SimpleGrid, Table, Text, ThemeIcon, Title } from "@mantine/core";
import { IconDownload, IconLock, IconShieldCheck } from "@tabler/icons-react";
import type { Exchange, Proof, ProofCheck } from "../../gen/ares/v1/ares_pb.ts";
import { errorText, formatWhen, proofState, proofStateInfo, proofWhy, toneColor } from "../../lib/labels.ts";
import type { Approval } from "../../lib/findings.ts";
import { ErrorNote, GoodNote, Section, StatusBadge, ToneBadge } from "../../ui/index.tsx";
import { downloadBytes } from "../engagement/HeaderActions.tsx";
import { useProofDownload } from "../workspace/data.ts";
import { Facts } from "./FindingParts.tsx";

// ProofPanel shows how the reader can be sure a finding is real: what Ares
// sent, what came back, why nothing else explains it, every re-check, and the
// fingerprint sealed in the activity log. It only ever describes an exchange
// that already happened.
export function ProofPanel({
  findingId,
  proof,
  checks,
  approval,
  extra,
}: {
  findingId: string;
  proof: Proof;
  checks: ProofCheck[];
  approval?: Approval;
  // Rows the finding adds regardless of its proof, such as the technique.
  extra: { label: string; value: ReactNode }[];
}) {
  const state = proofState(proof.kind);
  const download = useProofDownload(findingId);
  const why = proofWhy(proof.kind);
  const reproduced = checks.filter((c) => c.reproduced).length;

  const onDownload = () =>
    download.mutate(undefined, {
      onSuccess: (res) => downloadBytes(res.filename, "application/json", res.artifact),
    });

  return (
    <Section
      title={
        <Group gap="sm" component="span">
          Proof
          <StatusBadge info={proofStateInfo(state)} />
          {checks.length > 0 && (
            <ToneBadge tone={reproduced === checks.length ? "good" : "warn"}>
              Reproduced {reproduced} of {checks.length} {checks.length === 1 ? "time" : "times"}
            </ToneBadge>
          )}
        </Group>
      }
      description={
        proof.summary ||
        (state === "version"
          ? "What Ares read, and the advisory it matches. Ares did not try to use the weakness."
          : "How you can be sure this is real: what Ares sent, what came back, and why nothing else could explain it.")
      }
    >
      {state === "proven" && (
        <GoodNote title="Nothing was damaged to get this proof" icon={<IconShieldCheck size={18} />}>
          {proof.cleanup?.performed
            ? `Ares placed one harmless marker to prove this and removed it again${
                proof.cleanup.at ? ` (${lower(formatWhen(proof.cleanup.at))})` : ""
              }. ${proof.cleanup.detail ? `${proof.cleanup.detail}. ` : ""}Nothing was left behind.`
            : "Ares sent one harmless request. Nothing was left on the target, no file was read, and nothing was written or changed."}
        </GoodNote>
      )}

      {proof.control && (proof.control.sent || proof.control.received) && (
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
          <Step n={1} title="Without the trick">
            <ExchangeBlock e={proof.control.sent} token="" />
            <ResponseFacts e={proof.control.received} token="" />
          </Step>
          <Step n={2} title="With the trick">
            <ExchangeBlock e={proof.sent} token={proof.token} />
            <ResponseFacts e={proof.received} token={proof.token} />
          </Step>
        </SimpleGrid>
      )}

      {!proof.control && (proof.sent || proof.received || proof.callback || proof.computed) && (
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
          <Step n={1} title="What Ares sent">
            {proof.sent ? (
              <>
                <ExchangeBlock e={proof.sent} token={proof.token} />
                <Text size="sm" c="dimmed" mt={6}>
                  {[
                    proof.sent.at && `Sent ${lower(formatWhen(proof.sent.at))}.`,
                    proof.token && "The highlighted code was made for this finding alone and used once.",
                  ]
                    .filter(Boolean)
                    .join(" ")}
                </Text>
              </>
            ) : (
              <Text c="dimmed">The request was not recorded.</Text>
            )}
          </Step>
          <Step n={2} title="What came back">
            <CameBack proof={proof} />
          </Step>
        </SimpleGrid>
      )}

      {proof.version && <VersionFacts proof={proof} />}

      {why && (
        <Box p="md" style={{ border: "1px solid var(--ares-line)", borderRadius: 8 }}>
          <Text fw={600} mb={4}>
            Why nothing else explains it
          </Text>
          <Text>{why}</Text>
        </Box>
      )}

      <Facts
        rows={[
          // A call-back already shows its code beside the visit it came back with.
          ...(proof.token && !proof.callback
            ? [{ label: "One-time code", value: <Token value={proof.token} /> }]
            : []),
          ...(approval
            ? [{
                label: "Approved by",
                value: (
                  <Text>
                    {[approval.who, approval.how, approval.at && lower(formatWhen(approval.at))].filter(Boolean).join(", ")}
                  </Text>
                ),
              }]
            : []),
          ...extra,
        ]}
      />

      {checks.length > 0 && <CheckHistory checks={checks} />}

      {download.isError && (
        <ErrorNote title="The proof could not be downloaded">{errorText(download.error)}</ErrorNote>
      )}

      <Group
        justify="space-between"
        gap="sm"
        pt="md"
        style={{ borderTop: "1px solid var(--ares-line)" }}
      >
        <Group gap={8} wrap="nowrap" style={{ minWidth: 0 }}>
          <IconLock size={16} style={{ flex: "none", color: "var(--mantine-color-dimmed)" }} aria-hidden />
          <Text size="sm" c="dimmed" style={{ minWidth: 0, wordBreak: "break-all" }}>
            {proof.fingerprint ? (
              <>
                Proof fingerprint <Code bg="transparent" p={0}>{shortFingerprint(proof.fingerprint)}</Code>, sealed in
                the activity log
              </>
            ) : (
              "This proof has no fingerprint yet."
            )}
          </Text>
        </Group>
        {proof.fingerprint && (
          <Button
            variant="subtle"
            leftSection={<IconDownload size={16} />}
            loading={download.isPending}
            onClick={onDownload}
          >
            Download proof
          </Button>
        )}
      </Group>
    </Section>
  );
}

// Step is one numbered half of the exchange.
function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <Box style={{ minWidth: 0 }}>
      <Group gap="sm" mb="sm" wrap="nowrap">
        <ThemeIcon size={22} radius="xl" variant="light" color="brand" aria-hidden>
          <Text fz={12} fw={700}>
            {n}
          </Text>
        </ThemeIcon>
        <Title order={3}>{title}</Title>
      </Group>
      {children}
    </Box>
  );
}

// ExchangeBlock prints a request the way it went over the wire, with the
// one-time code marked wherever it appears.
function ExchangeBlock({ e, token }: { e?: Exchange; token: string }) {
  if (!e) return null;
  const lines: string[] = [];
  if (e.method || e.url) lines.push([e.method, requestPath(e.url), e.protocol].filter(Boolean).join(" "));
  const host = hostOf(e.url);
  if (host && !Object.keys(e.headers).some((k) => k.toLowerCase() === "host")) lines.push(`Host: ${host}`);
  for (const [k, v] of Object.entries(e.headers)) lines.push(`${k}: ${v}`);
  const text = lines.join("\n") + (e.body ? `\n\n${e.body}` : "");
  if (text.trim() === "") return null;
  return (
    <Code
      block
      bg="var(--ares-subtle)"
      style={{ border: "1px solid var(--ares-line)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}
    >
      <Marked text={text} token={token} />
    </Code>
  );
}

// ResponseFacts is the reply to a request: its status, size, page title and
// the exact bytes that prove it.
function ResponseFacts({ e, token }: { e?: Exchange; token: string }) {
  if (!e) return null;
  const rows = [
    ...(e.status ? [{ label: "Status", value: <Text>{e.status}</Text> }] : []),
    ...(e.size ? [{ label: "Size", value: <Text>{e.size.toLocaleString()} bytes</Text> }] : []),
    ...(e.title ? [{ label: "Page title", value: <Text>{e.title}</Text> }] : []),
    ...(e.at ? [{ label: "Received", value: <Text>{formatWhen(e.at)}</Text> }] : []),
    ...(e.excerpt
      ? [{
          label: "What proves it",
          value: (
            <Code bg="transparent" p={0} style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
              <Marked text={e.excerpt} token={token} />
            </Code>
          ),
        }]
      : []),
  ];
  return rows.length ? (
    <Box mt="sm">
      <Facts rows={rows} />
    </Box>
  ) : null;
}

// CameBack is the evidence that returned: the recorded visit for a call-back,
// the server's own answer for a calculation, or the plain response.
function CameBack({ proof }: { proof: Proof }) {
  const cb = proof.callback;
  if (cb) {
    const ownAddress = cb.sourceIp !== "" && cb.sourceIp === cb.targetIp;
    return (
      <Facts
        rows={[
          ...(proof.token ? [{ label: "Code", value: <Token value={proof.token} /> }] : []),
          {
            label: "Received",
            value: (
              <Text>
                {[cb.at && formatWhen(cb.at), cb.delayMs > 0 && `${(Number(cb.delayMs) / 1000).toFixed(1)} seconds later`]
                  .filter(Boolean)
                  .join(", ") || "Time not recorded"}
              </Text>
            ),
          },
          ...(cb.sourceIp
            ? [{
                label: "From",
                value: (
                  <Group gap="xs">
                    <Code bg="transparent" p={0}>
                      {cb.sourceIp}
                    </Code>
                    {ownAddress ? (
                      <ToneBadge tone="good">The target's own address</ToneBadge>
                    ) : cb.targetIp ? (
                      <Text size="sm" c="dimmed">
                        The target is {cb.targetIp}
                      </Text>
                    ) : null}
                  </Group>
                ),
              }]
            : []),
          ...(cb.method || cb.path
            ? [{ label: "Request", value: <Code bg="transparent" p={0}>{[cb.method, cb.path].filter(Boolean).join(" ")}</Code> }]
            : []),
          ...(cb.channel === "dns" ? [{ label: "How", value: <Text>A name lookup (DNS)</Text> }] : []),
          ...(cb.userAgent
            ? [{ label: "Sent by", value: <Code bg="transparent" p={0}>{cb.userAgent}</Code> }]
            : []),
        ]}
      />
    );
  }
  if (proof.computed) {
    const c = proof.computed;
    return (
      <>
        <Facts
          rows={[
            ...(c.expression ? [{ label: "Ares asked", value: <Code bg="transparent" p={0}>{c.expression}</Code> }] : []),
            ...(c.expected ? [{ label: "Right answer", value: <Token value={c.expected} /> }] : []),
            ...(c.markers ? [{ label: "Between", value: <Code bg="transparent" p={0}>{c.markers}</Code> }] : []),
          ]}
        />
        <ResponseFacts e={proof.received} token={c.expected} />
      </>
    );
  }
  return proof.received ? (
    <ResponseFacts e={proof.received} token={proof.token} />
  ) : (
    <Text c="dimmed">The response was not recorded.</Text>
  );
}

// VersionFacts is a version match: what was found, the weak range and the
// advisory that names it.
function VersionFacts({ proof }: { proof: Proof }) {
  const v = proof.version!;
  return (
    <Facts
      rows={[
        ...(v.found ? [{ label: "Version found", value: <Code bg="transparent" p={0}>{v.found}</Code> }] : []),
        ...(v.from ? [{ label: "Read from", value: <Text>{v.from}</Text> }] : []),
        ...(v.range ? [{ label: "Weak versions", value: <Code bg="transparent" p={0}>{v.range}</Code> }] : []),
        ...(v.cve || v.advisory
          ? [{
              label: "Advisory",
              value: (
                <Group gap="xs">
                  <Text>{[v.cve, v.advisory].filter(Boolean).join(" · ")}</Text>
                  {v.kev && (
                    <ToneBadge tone="bad" hint="Listed by CISA as exploited in real attacks.">
                      Known to be exploited
                    </ToneBadge>
                  )}
                </Group>
              ),
            }]
          : []),
        ...(v.source
          ? [{ label: "Source", value: <Text>{[v.source, v.asOf && `as of ${v.asOf}`].filter(Boolean).join(", ")}</Text> }]
          : []),
      ]}
    />
  );
}

// CheckHistory lists every time the proof was reproduced on demand.
function CheckHistory({ checks }: { checks: ProofCheck[] }) {
  return (
    <Box>
      <Title order={3} mb="xs">
        Every time this was checked
      </Title>
      <Table.ScrollContainer minWidth={420}>
        <Table verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>When</Table.Th>
              <Table.Th>Came back</Table.Th>
              <Table.Th>Fingerprint</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {checks.map((c, i) => (
              <Table.Tr key={`${c.at}-${i}`}>
                <Table.Td>{formatWhen(c.at)}</Table.Td>
                <Table.Td>
                  <ToneBadge tone={c.reproduced ? "good" : "neutral"}>
                    {c.reproduced ? "Yes, same result" : "No, not reproduced"}
                  </ToneBadge>
                </Table.Td>
                <Table.Td>
                  <Code bg="transparent" p={0}>
                    {c.fingerprint ? shortFingerprint(c.fingerprint) : "None"}
                  </Code>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Box>
  );
}

function Token({ value }: { value: string }) {
  return (
    <Code bg="transparent" p={0}>
      <Mark color={toneColor("warn")}>{value}</Mark>
    </Code>
  );
}

// Marked prints text with every copy of the one-time code highlighted.
function Marked({ text, token }: { text: string; token: string }) {
  if (!token || !text.includes(token)) return <>{text}</>;
  const parts = text.split(token);
  return (
    <>
      {parts.map((p, i) => (
        <span key={i}>
          {p}
          {i < parts.length - 1 && <Mark color={toneColor("warn")}>{token}</Mark>}
        </span>
      ))}
    </>
  );
}

function shortFingerprint(fp: string): string {
  const hex = fp.replace(/^sha256:/, "");
  return hex.length > 12 ? `sha256 ${hex.slice(0, 4)}…${hex.slice(-4)}` : `sha256 ${hex}`;
}

function requestPath(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function lower(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}

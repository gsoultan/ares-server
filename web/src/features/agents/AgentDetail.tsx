import { useState, type ReactNode } from "react";
import {
  Box,
  Button,
  Code,
  Group,
  Modal,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  Textarea,
  ThemeIcon,
} from "@mantine/core";
import {
  IconArrowLeft,
  IconBan,
  IconCheck,
  IconPlayerPlay,
  IconServer,
  IconTrash,
} from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { control } from "../../client.ts";
import { AgentStatus, type AgentView, type Engagement } from "../../gen/ares/v1/ares_pb.ts";
import {
  agentModules,
  agentStatus,
  CAPABILITIES,
  machineLine,
  machineName,
  timeAgo,
  uninstallCommand,
} from "../../lib/agents.ts";
import { errorText, formatDateTime, formatWhen, moduleInfo, plural } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import type { WireEntry } from "../../workers/audit-verify.worker.ts";
import {
  EmptyState,
  ErrorNote,
  LoadingState,
  PageHeader,
  Section,
  StatCard,
  StatusBadge,
  ToneBadge,
} from "../../ui/index.tsx";
import { parseTarget } from "../engagement/startTest.ts";
import { countBySeverity } from "../findings/SeverityCounts.tsx";
import type { FindingRecord } from "../workspace/data.ts";
import { useAgent, useAgentChange, useRemoveAgent } from "./data.ts";

// AgentDetail is one agent: whether it is alive, how it reaches Ares, the
// permission it runs under, what it may do, and everything it has done.
export function AgentDetail({
  engagement,
  agentId,
  findings,
  activity,
  canTest,
}: {
  engagement: Engagement;
  agentId: string;
  // Findings this agent reported.
  findings: FindingRecord[];
  // Its activity-log entries, newest first.
  activity: WireEntry[];
  canTest: boolean;
}) {
  const id = engagement.id;
  const agent = useAgent(id, agentId);
  const [removing, setRemoving] = useState(false);
  const [running, setRunning] = useState(false);

  const back = (
    <Link to="/engagements/$id" params={{ id }} search={{ view: "agents" }} className="ares-back">
      <IconArrowLeft size={14} />
      {engagement.name} · Agents
    </Link>
  );

  if (agent.isLoading) return <LoadingState label="Loading agent…" />;
  if (agent.isError || !agent.data) {
    return (
      <Stack gap="lg">
        {back}
        <ErrorNote title="This agent could not be opened">
          It may have been removed from a different engagement, or Ares could not reach its server.
        </ErrorNote>
      </Stack>
    );
  }

  const a = agent.data;
  const removed = a.status === AgentStatus.REMOVED;
  const sev = countBySeverity(findings);
  const sevLine = (["critical", "high", "medium", "low"] as const)
    .filter((s) => sev[s] > 0)
    .map((s) => `${sev[s]} ${s}`)
    .join(" · ");
  const lastRun = (cap: string) =>
    activity.find(
      (e) => e.action === "agent.dispatch" && agentModules([cap]).includes(e.detail.replace(/^queued /, "")),
    );

  return (
    <Stack gap="lg">
      <PageHeader
        back={back}
        title={machineName(a)}
        badge={<StatusBadge info={agentStatus(a.status)} size="lg" />}
        description={[machineLine(a), a.host?.agentVersion && `agent version ${a.host.agentVersion}`, `added ${formatWhen(a.enrolledAt)}`]
          .filter((x) => x)
          .join(" · ")}
        actions={
          !removed && (
            <>
              <Button color="red" variant="light" leftSection={<IconTrash size={16} />} onClick={() => setRemoving(true)}>
                Remove agent
              </Button>
              {canTest && (
                <Button leftSection={<IconPlayerPlay size={16} />} onClick={() => setRunning(true)}>
                  Run a check
                </Button>
              )}
            </>
          )
        }
      />

      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="lg">
        <StatCard label="Last heard from" value={timeAgo(a.lastSeen)} tone={removed ? undefined : a.status === AgentStatus.NOT_HEARD_FROM ? "warn" : "good"}>
          <Text size="sm" c="dimmed">
            Checks in every 30 seconds. Marked "Not heard from" after 5 minutes.
          </Text>
        </StatCard>
        <StatCard label="How it connects" value="Outbound only">
          <Text size="sm" c="dimmed">
            Over HTTPS to Ares, with its own key. No open port on the machine
            {a.host?.segmentCidrs.length ? ` · sits on ${a.host.segmentCidrs.join(", ")}` : ""}.
          </Text>
        </StatCard>
        <StatCard label="Findings from this agent" value={findings.length}>
          <Text size="sm" c="dimmed">
            {sevLine || "None yet"}
            {findings.length > 0 && (
              <>
                {" · "}
                <Link to="/engagements/$id" params={{ id }} search={{ view: "findings" }} className="ares-link">
                  See them in Findings
                </Link>
              </>
            )}
          </Text>
        </StatCard>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
        <Section title="Permission on file" description="The record of who agreed. It is in the activity log and the report.">
          <Rows>
            <Row label="Agreed by">{a.consent?.who || "Not recorded"}</Row>
            <Row label="How">{a.consent?.how || "Not recorded"}</Row>
            {a.consent?.authFileFingerprint && (
              <Row label="Document fingerprint">
                <Code style={{ wordBreak: "break-all" }}>{a.consent.authFileFingerprint}</Code>
              </Row>
            )}
            <Row label="Recorded by">{a.consent?.recordedBy || "Not recorded"}</Row>
            <Row label="Ends">
              {a.consent?.endsAt ? formatDateTime(a.consent.endsAt) : "When testing in this engagement stops"}
            </Row>
            <Row label="Seen on the machine as">
              Ares Testing Agent, with its own activity log the owner can read
            </Row>
          </Rows>
        </Section>

        <Section title="What it may do" description="The agent refuses anything not allowed here.">
          <Rows>
            {CAPABILITIES.map((c) => {
              const allowed = a.capabilities.includes(c.id);
              const last = allowed ? lastRun(c.id) : undefined;
              return (
                <Group key={c.id} justify="space-between" wrap="nowrap" gap="md" py="sm" style={{ borderTop: "1px solid var(--ares-line)" }}>
                  <Box>
                    <Text fw={600} c={allowed ? undefined : "dimmed"}>
                      {c.label}
                    </Text>
                    <Text size="sm" c="dimmed">
                      {[c.limit, last && `last asked ${formatWhen(last.time)}`].filter((x) => x).join(" · ") ||
                        (allowed ? "Not run yet" : "Not part of this agent's permission")}
                    </Text>
                  </Box>
                  <ToneBadge tone={allowed ? "good" : "neutral"}>{allowed ? "Allowed" : "Not allowed"}</ToneBadge>
                </Group>
              );
            })}
          </Rows>
          {!removed && (
            <Text size="sm" c="dimmed">
              To allow more, remove this agent and add it again with the owner's agreement for the new checks.
            </Text>
          )}
        </Section>
      </SimpleGrid>

      <Section
        title="What it has done"
        description="Everything the agent did, newest first. The same record is on the machine and in the activity log."
        aside={
          <Link to="/activity" search={{ engagement: id }} className="ares-link">
            See the full record
          </Link>
        }
      >
        {activity.length === 0 ? (
          <EmptyState icon={<IconServer size={22} />} title="Nothing yet" description="Checks this agent runs are listed here." />
        ) : (
          <Stack gap={0}>
            {activity.map((e) => (
              <ActivityRow key={e.seq} entry={e} />
            ))}
          </Stack>
        )}
      </Section>

      <RemoveAgent id={id} agent={a} findings={findings.length} opened={removing} onClose={() => setRemoving(false)} />
      {canTest && <RunCheck id={id} agent={a} opened={running} onClose={() => setRunning(false)} />}
    </Stack>
  );
}

function Rows({ children }: { children: ReactNode }) {
  return <Stack gap={0}>{children}</Stack>;
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Group align="flex-start" wrap="nowrap" gap="md" py="sm" style={{ borderTop: "1px solid var(--ares-line)" }}>
      <Text c="dimmed" w={170} style={{ flexShrink: 0 }}>
        {label}
      </Text>
      <Text style={{ minWidth: 0 }}>{children}</Text>
    </Group>
  );
}

// What one activity-log entry means, in words.
function describe(e: WireEntry): { title: string; detail: string; refused?: boolean } {
  switch (e.action) {
    case "agent.enroll":
      return { title: "Installed and called in for the first time", detail: "Used its one-time install key. The key is now spent." };
    case "agent.dispatch": {
      const mod = e.detail.replace(/^queued /, "");
      return { title: `Asked to run: ${moduleInfo(mod).label}`, detail: "Queued by an operator. The agent checks the scope again before it starts." };
    }
    case "agent.results": {
      const n = Number.parseInt(e.detail, 10);
      return {
        title: "Sent results",
        detail: Number.isNaN(n) ? e.detail : `${plural(n, "result")}, added to this engagement. Nothing is kept on the machine.`,
      };
    }
    case "agent.remove":
      return { title: "Removed", detail: "It can no longer reach Ares and uninstalls itself the next time it calls in." };
    case "agent.deregister":
      return { title: "Uninstalled itself", detail: "Its keys and anything it had not sent were deleted from the machine." };
    default:
      return { title: e.action, detail: e.detail, refused: e.action.includes("denied") };
  }
}

function ActivityRow({ entry }: { entry: WireEntry }) {
  const d = describe(entry);
  return (
    <Group align="flex-start" wrap="nowrap" gap="md" py="sm" style={{ borderTop: "1px solid var(--ares-line)" }}>
      <Text size="sm" c="dimmed" w={150} style={{ flexShrink: 0 }}>
        {formatWhen(entry.time)}
      </Text>
      <ThemeIcon size={20} radius="xl" variant="light" color={d.refused ? "orange" : "teal"} mt={1} style={{ flexShrink: 0 }}>
        {d.refused ? <IconBan size={12} /> : <IconCheck size={12} />}
      </ThemeIcon>
      <Box style={{ minWidth: 0 }}>
        <Text fw={600}>{d.title}</Text>
        <Text size="sm" c="dimmed">
          {d.detail}
        </Text>
      </Box>
    </Group>
  );
}

// RemoveAgent revokes the agent. It cannot be undone, so it says what happens
// first, including how to uninstall by hand if the machine is offline.
function RemoveAgent({
  id,
  agent,
  findings,
  opened,
  onClose,
}: {
  id: string;
  agent: AgentView;
  findings: number;
  opened: boolean;
  onClose: () => void;
}) {
  const remove = useRemoveAgent(id);
  const close = () => {
    remove.reset();
    onClose();
  };
  return (
    <Modal opened={opened} onClose={close} title={`Remove ${machineName(agent)}?`}>
      <Stack>
        <Text>
          The agent stops at once and can no longer reach Ares. The next time it calls in, it uninstalls
          itself and deletes its keys and anything it had not sent yet.
        </Text>
        <Table>
          <Table.Tbody>
            <Table.Tr>
              <Table.Td c="dimmed" w={120}>Findings</Table.Td>
              <Table.Td>
                {findings > 0 ? `The ${findings} it already sent stay in this engagement.` : "Anything it already sent stays in this engagement."}
              </Table.Td>
            </Table.Tr>
            <Table.Tr>
              <Table.Td c="dimmed">Record</Table.Td>
              <Table.Td>The removal is written to the activity log.</Table.Td>
            </Table.Tr>
            <Table.Tr>
              <Table.Td c="dimmed">If it is offline</Table.Td>
              <Table.Td>
                Uninstall it by hand on the machine:
                <Code block mt={6}>
                  {uninstallCommand(agent.host?.os ?? "")}
                </Code>
              </Table.Td>
            </Table.Tr>
          </Table.Tbody>
        </Table>
        {remove.isError && <ErrorNote title="Could not remove the agent">{errorText(remove.error)}</ErrorNote>}
        <Group justify="flex-end">
          <Button variant="default" onClick={close}>
            Keep it
          </Button>
          <Button
            color="red"
            loading={remove.isPending}
            onClick={() => remove.mutate(agent.id, { onSuccess: close })}
          >
            Remove agent
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// RunCheck asks the agent to run one of the checks it is allowed, against
// addresses inside the engagement's scope. The server and then the agent both
// refuse anything outside the agent's permission or the scope.
function RunCheck({
  id,
  agent,
  opened,
  onClose,
}: {
  id: string;
  agent: AgentView;
  opened: boolean;
  onClose: () => void;
}) {
  const { tenantId } = useTenant();
  const changed = useAgentChange(id);
  const modules = agentModules(agent.capabilities);
  const [mod, setMod] = useState<string | null>(modules[0] ?? null);
  const [targets, setTargets] = useState("");
  const lines = targets
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter((x) => x !== "");
  const needsTargets = mod !== "passivesniff" && mod !== "mitmexposure";

  const run = useMutation({
    mutationFn: () =>
      control.dispatchAgentJob({
        engagementId: id,
        tenantId,
        agentId: agent.id,
        module: mod!,
        targets: lines.map(parseTarget),
      }),
    onSuccess: () => {
      changed();
      close();
    },
  });
  const close = () => {
    run.reset();
    onClose();
  };

  return (
    <Modal opened={opened} onClose={close} title={`Run a check from ${machineName(agent)}`}>
      <Stack>
        {modules.length === 0 ? (
          <Text>This agent is not allowed any check that can be started from here.</Text>
        ) : (
          <>
            <Select
              label="Check"
              data={modules.map((m) => ({ value: m, label: moduleInfo(m).label }))}
              value={mod}
              onChange={setMod}
              allowDeselect={false}
              description={mod ? moduleInfo(mod).summary : undefined}
            />
            {needsTargets && (
              <Textarea
                label="Addresses inside the network"
                description="One per line. Anything outside this engagement's scope is refused by the agent and noted in the log."
                placeholder={"10.20.1.0/24\nhttps://intranet.example.local"}
                autosize
                minRows={3}
                value={targets}
                onChange={(ev) => setTargets(ev.currentTarget.value)}
              />
            )}
          </>
        )}
        {run.isError && <ErrorNote title="Could not start the check">{errorText(run.error)}</ErrorNote>}
        <Group justify="flex-end">
          <Button variant="default" onClick={close}>
            Cancel
          </Button>
          <Button
            loading={run.isPending}
            disabled={!mod || (needsTargets && lines.length === 0)}
            onClick={() => run.mutate()}
          >
            Run check
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

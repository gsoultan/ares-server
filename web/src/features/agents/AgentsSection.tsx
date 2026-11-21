import { Box, Button, Group, List, Loader, SimpleGrid, Stack, Table, Text } from "@mantine/core";
import { IconChevronRight, IconPlus, IconServer } from "@tabler/icons-react";
import { Link, useNavigate } from "@tanstack/react-router";
import { AgentStatus, type AgentKeyView, type AgentView } from "../../gen/ares/v1/ares_pb.ts";
import {
  agentStatus,
  capabilityShort,
  machineLine,
  machineName,
  timeAgo,
  timeLeft,
} from "../../lib/agents.ts";
import { errorText, formatWhen, plural } from "../../lib/labels.ts";
import {
  EmptyState,
  ErrorNote,
  InfoNote,
  LoadingState,
  Section,
  StatCard,
  StatusBadge,
  ToneBadge,
} from "../../ui/index.tsx";
import type { FindingRecord } from "../workspace/data.ts";
import { agentsDisabled, useAgentKeys, useAgents, useCancelKey } from "./data.ts";

// AgentsSection is an engagement's Agents view: what agents are, how many are
// connected, the list, and the install keys still waiting to be used.
export function AgentsSection({
  id,
  canTest,
  agentFindings,
}: {
  id: string;
  canTest: boolean;
  // Findings an agent reported, for the headline count.
  agentFindings: FindingRecord[];
}) {
  const navigate = useNavigate();
  const agents = useAgents(id);
  const keys = useAgentKeys(id);

  if (agentsDisabled(agents.error)) {
    return (
      <InfoNote title="Agents are not switched on for this server">
        Ask whoever runs Ares to enable agent support. Outside tests work as before.
      </InfoNote>
    );
  }

  const list = agents.data?.agents ?? [];
  const count = (s: AgentStatus) => list.filter((a) => a.status === s).length;
  const connected = count(AgentStatus.CONNECTED) + count(AgentStatus.RUNNING_CHECK);
  const quiet = count(AgentStatus.NOT_HEARD_FROM);
  const removed = count(AgentStatus.REMOVED);

  const add = canTest ? (
    <Button
      leftSection={<IconPlus size={16} />}
      onClick={() => void navigate({ to: "/engagements/$id", params: { id }, search: { view: "agents", agent: "new" } })}
    >
      Add an agent
    </Button>
  ) : undefined;

  return (
    <Stack gap="lg">
      <InfoNote title="Testing agents work in the open">
        An agent is installed only with the machine owner's written permission, and that permission
        is kept here and printed in the report. It then:
        <List size="sm" mt={6} spacing={2}>
          <List.Item>runs under its real name, Ares Testing Agent, where anyone on the machine can see and stop it;</List.Item>
          <List.Item>keeps a log of everything it does that the machine's owner can read;</List.Item>
          <List.Item>only tests what this engagement allows, never moves to another machine, and changes nothing;</List.Item>
          <List.Item>stops for good the moment you remove it.</List.Item>
        </List>
      </InfoNote>

      {!canTest && (
        <InfoNote title="Agents can be added once testing is allowed">
          Finish Scope and permission first. Agents stop when testing in this engagement is stopped.
        </InfoNote>
      )}

      {list.length > 0 && (
        <SimpleGrid cols={{ base: 2, md: 4 }} spacing="lg">
          <StatCard label="Connected" value={connected} tone={connected ? "good" : undefined}>
            <Text size="sm" c="dimmed">Checked in within the last 5 minutes</Text>
          </StatCard>
          <StatCard label="Not heard from" value={quiet} tone={quiet ? "warn" : undefined}>
            <Text size="sm" c="dimmed">No check-in for over 5 minutes</Text>
          </StatCard>
          <StatCard label="Removed" value={removed}>
            <Text size="sm" c="dimmed">Kept here for the record</Text>
          </StatCard>
          <StatCard label="Findings from agents" value={agentFindings.length}>
            <Text size="sm" c="dimmed">Added to this engagement's findings</Text>
          </StatCard>
        </SimpleGrid>
      )}

      <Section
        flush
        title="Agents in this engagement"
        description="Open one to see what it may do, its permission and what it has done."
        aside={add}
      >
        {agents.isLoading ? (
          <LoadingState label="Loading agents…" />
        ) : agents.isError ? (
          <Box px="lg" pb="lg">
            <ErrorNote title="Could not load the agents">{errorText(agents.error)}</ErrorNote>
          </Box>
        ) : list.length === 0 ? (
          <EmptyState
            icon={<IconServer size={22} />}
            title="No agents yet"
            description="Add an agent to test machines and websites the outside tests cannot reach, from inside the client's network."
          />
        ) : (
          <AgentTable id={id} agents={list} />
        )}
      </Section>

      {(keys.data?.keys.length ?? 0) > 0 && (
        <Section
          title="Waiting to connect"
          description="Install keys you have made that no agent has used yet. Each works once."
        >
          <Stack gap={0}>
            {keys.data!.keys.map((k) => (
              <KeyRow key={k.keyId} id={id} k={k} />
            ))}
          </Stack>
        </Section>
      )}
    </Stack>
  );
}

function AgentTable({ id, agents }: { id: string; agents: AgentView[] }) {
  const navigate = useNavigate();
  const open = (a: AgentView) =>
    void navigate({ to: "/engagements/$id", params: { id }, search: { view: "agents", agent: a.id } });
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table className="ares-stack" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Machine</Table.Th>
            <Table.Th w={150}>Status</Table.Th>
            <Table.Th>Last heard from</Table.Th>
            <Table.Th>What it may do</Table.Th>
            <Table.Th>Permission from</Table.Th>
            <Table.Th w={40} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {agents.map((a) => {
            const removed = a.status === AgentStatus.REMOVED;
            const shown = a.capabilities.slice(0, 2);
            const more = a.capabilities.length - shown.length;
            return (
              <Table.Tr key={a.id} className="ares-clickable" onClick={() => open(a)}>
                <Table.Td data-primary>
                  <Link
                    to="/engagements/$id"
                    params={{ id }}
                    search={{ view: "agents", agent: a.id }}
                    onClick={(ev) => ev.stopPropagation()}
                    style={{ color: "inherit", textDecoration: "none", fontWeight: 600 }}
                  >
                    {machineName(a)}
                  </Link>
                  <Text size="sm" c="dimmed">
                    {machineLine(a)}
                  </Text>
                </Table.Td>
                <Table.Td data-label="Status" style={{ whiteSpace: "nowrap" }}>
                  <StatusBadge info={agentStatus(a.status)} />
                </Table.Td>
                <Table.Td data-label="Last heard from">
                  <Text size="sm">{timeAgo(a.lastSeen)}</Text>
                  {a.status === AgentStatus.NOT_HEARD_FROM && (
                    <Text size="sm" c="dimmed">
                      Results wait on the machine until it reconnects
                    </Text>
                  )}
                  {removed && (
                    <Text size="sm" c="dimmed">
                      Uninstalls itself when it next calls in
                    </Text>
                  )}
                </Table.Td>
                <Table.Td data-label="What it may do">
                  {removed ? (
                    <Text c="dimmed">—</Text>
                  ) : (
                    <Group gap={6}>
                      {shown.map((c) => (
                        <ToneBadge key={c} tone="neutral">
                          {capabilityShort(c)}
                        </ToneBadge>
                      ))}
                      {more > 0 && <ToneBadge tone="neutral">+{more}</ToneBadge>}
                    </Group>
                  )}
                </Table.Td>
                <Table.Td data-label="Permission from">
                  <Text size="sm">{a.consent?.who || "Not recorded"}</Text>
                  {!removed && a.consent?.how && (
                    <Text size="sm" c="dimmed">
                      {a.consent.how}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td data-hide-mobile>
                  <Box c="dimmed" style={{ display: "flex" }}>
                    <IconChevronRight size={16} />
                  </Box>
                </Table.Td>
              </Table.Tr>
            );
          })}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function KeyRow({ id, k }: { id: string; k: AgentKeyView }) {
  const cancel = useCancelKey(id);
  return (
    <Group
      justify="space-between"
      wrap="nowrap"
      gap="md"
      py="sm"
      style={{ borderTop: "1px solid var(--ares-line)" }}
    >
      <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
        <Loader size="xs" aria-hidden />
        <Box style={{ minWidth: 0 }}>
          <Text fw={600}>
            Key for {plural(k.capabilities.length, "permitted check")} · permission from{" "}
            {k.consent?.who || "the owner"}
          </Text>
          <Text size="sm" c="dimmed">
            Made by {k.consent?.recordedBy || "an operator"} · {formatWhen(k.createdAt)} · works
            once · expires in {timeLeft(k.expiresAt)}
          </Text>
          {cancel.isError && (
            <Text size="sm" c="red">
              Could not cancel the key. {errorText(cancel.error)}
            </Text>
          )}
        </Box>
      </Group>
      <Button
        color="red"
        variant="light"
        loading={cancel.isPending}
        onClick={() => cancel.mutate(k.keyId)}
        style={{ flexShrink: 0 }}
      >
        Cancel key
      </Button>
    </Group>
  );
}

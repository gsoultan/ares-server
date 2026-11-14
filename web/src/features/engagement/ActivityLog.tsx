import type { ReactNode } from "react";
import { Box, Group, Table, Text, ThemeIcon, Tooltip } from "@mantine/core";
import { IconShieldCheck, IconShieldX } from "@tabler/icons-react";
import { actionLabel, actorLabel, entryDetails, formatDateTime } from "../../lib/labels.ts";
import { EmptyState, ErrorNote, LoadingState, Section } from "../../ui/index.tsx";

export interface ActivityEntry {
  seq: number;
  time: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
}

// The record is checked twice: once by the server, once again in this browser
// without trusting the server. The reader sees one plain verdict.
export type Integrity =
  | { state: "checking" }
  | { state: "intact" }
  | { state: "broken"; where?: string };

export function ActivityLog({
  entries,
  loading,
  integrity,
  engagementId,
  title = "Activity log",
  action,
}: {
  // The page can name the engagement here, and add its own action.
  title?: string;
  action?: ReactNode;
  entries: ActivityEntry[] | undefined;
  loading: boolean;
  integrity: Integrity;
  engagementId: string;
}) {
  return (
    <Section
      flush
      title={title}
      description="Everything that happened in this engagement, newest first. The log cannot be edited."
      aside={
        <Group gap="md">
          <IntegrityMark integrity={integrity} />
          {action}
        </Group>
      }
    >
      {integrity.state === "broken" && (
        <Box px="lg" pb="md">
          <ErrorNote title="This log may have been changed">
            The record no longer matches its own fingerprints
            {integrity.where ? ` (${integrity.where})` : ""}. Do not rely on it until this is
            investigated.
          </ErrorNote>
        </Box>
      )}
      {loading ? (
        <LoadingState label="Loading activity…" />
      ) : !entries || entries.length === 0 ? (
        <EmptyState title="Nothing has happened yet" />
      ) : (
        <Table.ScrollContainer minWidth={640}>
          <Table>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>When</Table.Th>
                <Table.Th>Who</Table.Th>
                <Table.Th>What happened</Table.Th>
                <Table.Th>Details</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {entries.toReversed().map((e) => {
                // The engagement's own id says nothing to the reader.
                const details = entryDetails(e, engagementId);
                return (
                  <Table.Tr key={e.seq}>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>
                      <Text size="sm" c="dimmed">
                        {formatDateTime(e.time)}
                      </Text>
                    </Table.Td>
                    <Table.Td style={{ whiteSpace: "nowrap" }}>{actorLabel(e.actor)}</Table.Td>
                    <Table.Td>{actionLabel(e.action)}</Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed" style={{ wordBreak: "break-word" }}>
                        {details}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Section>
  );
}

function IntegrityMark({ integrity }: { integrity: Integrity }) {
  if (integrity.state === "checking") {
    return (
      <Text size="sm" c="dimmed">
        Checking the record…
      </Text>
    );
  }
  const ok = integrity.state === "intact";
  return (
    <Tooltip
      label={
        ok
          ? "Checked twice: by the Ares server, and again in your browser without trusting the server."
          : "The record does not match its fingerprints."
      }
    >
      <Group gap={6} wrap="nowrap">
        <ThemeIcon size={22} radius="xl" variant="light" color={ok ? "teal" : "red"}>
          {ok ? <IconShieldCheck size={14} /> : <IconShieldX size={14} />}
        </ThemeIcon>
        <Text size="sm" fw={600} c={`var(--mantine-color-${ok ? "teal" : "red"}-light-color)`}>
          {ok ? "Record intact" : "Record changed"}
        </Text>
      </Group>
    </Tooltip>
  );
}

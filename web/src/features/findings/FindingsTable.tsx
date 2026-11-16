import type { ReactNode } from "react";
import { Box, Group, Table, Text } from "@mantine/core";
import { IconChevronRight, IconFileSearch, IconMail, IconServer, IconWorld, IconWorldSearch } from "@tabler/icons-react";
import { Link, useNavigate } from "@tanstack/react-router";
import { formatWhen } from "../../lib/labels.ts";
import { SeverityBadge, StatusBadge } from "../../ui/index.tsx";
import { findingState, findingStateInfo, type FindingRecord } from "../workspace/data.ts";
import type { FoundBy, Source } from "./foundBy.ts";

const SOURCE_ICON: Record<Source, ReactNode> = {
  outside: <IconWorld size={16} />,
  agent: <IconServer size={16} />,
  public: <IconWorldSearch size={16} />,
  email: <IconMail size={16} />,
  files: <IconFileSearch size={16} />,
};

// FindingsTable is the one list of findings, used for a single engagement and
// for the whole workspace. A row opens the finding.
export function FindingsTable({
  findings,
  engagementNames,
  extra,
  foundBy,
}: {
  findings: FindingRecord[];
  // When given, a column says which engagement each finding belongs to.
  engagementNames?: Record<string, string>;
  // A small tag shown under a finding's description, such as where the
  // indicator it matched came from.
  extra?: (f: FindingRecord) => ReactNode;
  // When given, a column says who found each finding.
  foundBy?: (f: FindingRecord) => FoundBy;
}) {
  const navigate = useNavigate();
  return (
    <Table.ScrollContainer minWidth={820}>
      <Table className="ares-stack" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th w={116}>Severity</Table.Th>
            <Table.Th>Finding</Table.Th>
            {foundBy && <Table.Th>Found by</Table.Th>}
            {engagementNames && <Table.Th>Engagement</Table.Th>}
            <Table.Th w={190}>Status</Table.Th>
            <Table.Th>Found</Table.Th>
            <Table.Th w={40} />
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {findings.map((f) => (
            <Table.Tr
              key={f.id}
              className="ares-clickable"
              onClick={() =>
                void navigate({
                  to: "/engagements/$id",
                  params: { id: f.engagementId },
                  search: { view: "findings", finding: f.id },
                })
              }
            >
              <Table.Td data-label="Severity">
                <SeverityBadge severity={f.finding.severity} />
              </Table.Td>
              <Table.Td data-primary>
                <Link
                  to="/engagements/$id"
                  params={{ id: f.engagementId }}
                  search={{ view: "findings", finding: f.id }}
                  onClick={(ev) => ev.stopPropagation()}
                  style={{ color: "inherit", textDecoration: "none", fontWeight: 600 }}
                >
                  {f.finding.title}
                </Link>
                {f.finding.description && (
                  <Text size="sm" c="dimmed" lineClamp={1}>
                    {f.finding.description}
                  </Text>
                )}
                {extra?.(f)}
              </Table.Td>
              {foundBy && (
                <Table.Td data-label="Found by">
                  <FoundByCell by={foundBy(f)} />
                </Table.Td>
              )}
              {engagementNames && <Table.Td data-label="Engagement">{engagementNames[f.engagementId] ?? ""}</Table.Td>}
              <Table.Td data-label="Status" style={{ whiteSpace: "nowrap" }}>
                <StatusBadge info={findingStateInfo(findingState(f))} />
              </Table.Td>
              <Table.Td data-label="Found" style={{ whiteSpace: "nowrap" }}>
                <Text size="sm" c="dimmed">
                  {formatWhen(f.foundAt)}
                </Text>
              </Table.Td>
              <Table.Td data-hide-mobile>
                <Box c="dimmed" style={{ display: "flex" }}>
                  <IconChevronRight size={16} />
                </Box>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function FoundByCell({ by }: { by: FoundBy }) {
  return (
    <Group gap={6} wrap="nowrap">
      <Box c="dimmed" style={{ display: "flex", flexShrink: 0 }} aria-hidden>
        {SOURCE_ICON[by.source]}
      </Box>
      <Text size="sm" style={{ whiteSpace: "nowrap" }}>
        {by.label}
      </Text>
    </Group>
  );
}

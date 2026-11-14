import { useState } from "react";
import { Button, Card, Group, SegmentedControl, Stack, Table, Text, TextInput } from "@mantine/core";
import { IconChevronRight, IconSearch, IconShieldSearch } from "@tabler/icons-react";
import { Link, useNavigate } from "@tanstack/react-router";
import { engagementStatus, formatDate, formatWhen } from "../lib/labels.ts";
import { EmptyState, ErrorNote, LoadingState, PageHeader, StatusBadge } from "../ui/index.tsx";
import { SeverityCounts } from "../features/findings/SeverityCounts.tsx";
import { NewEngagement } from "../features/workspace/NewEngagement.tsx";
import { isUnresolved, useEngagements, useFindings, useJobs } from "../features/workspace/data.ts";

const FILTERS = [
  { value: "all", label: "All" },
  { value: "authorized", label: "Ready to test" },
  { value: "draft", label: "Setting up" },
  { value: "halted", label: "Stopped" },
];

export function EngagementsPage() {
  const navigate = useNavigate();
  const engagements = useEngagements();
  const { findings } = useFindings();
  const { jobs } = useJobs();
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");

  const all = engagements.data?.engagements ?? [];
  const count = (status: string) =>
    status === "all" ? all.length : all.filter((e) => e.status === status).length;
  const rows = all.filter(
    (e) =>
      (filter === "all" || e.status === filter) &&
      e.name.toLowerCase().includes(query.trim().toLowerCase()),
  );

  return (
    <Stack gap="lg">
      <PageHeader
        title="Engagements"
        description="An engagement is one approved round of security testing. Each has its own scope, permission and activity log."
        actions={<NewEngagement />}
      />

      {all.length > 0 && (
        <Group justify="space-between" gap="md">
          <SegmentedControl
            aria-label="Show engagements by status"
            value={filter}
            onChange={setFilter}
            data={FILTERS.map((f) => ({ value: f.value, label: `${f.label} ${count(f.value)}` }))}
          />
          <TextInput
            aria-label="Search engagements"
            placeholder="Search engagements"
            leftSection={<IconSearch size={16} />}
            value={query}
            onChange={(ev) => setQuery(ev.currentTarget.value)}
            w={260}
          />
        </Group>
      )}

      <Card padding={0}>
        {engagements.isLoading ? (
          <LoadingState label="Loading engagements…" />
        ) : engagements.isError ? (
          <Stack p="lg">
            <ErrorNote title="Could not load engagements">
              Ares could not reach its server. Check that it is running, then try again.
            </ErrorNote>
            <Group>
              <Button variant="default" onClick={() => void engagements.refetch()}>
                Try again
              </Button>
            </Group>
          </Stack>
        ) : all.length === 0 ? (
          <EmptyState
            icon={<IconShieldSearch size={22} />}
            title="No engagements yet"
            description="Create your first engagement to set what may be tested and record permission."
            action={<NewEngagement />}
          />
        ) : rows.length === 0 ? (
          <EmptyState title="No engagement matches" description="Try a different filter or search." />
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Open findings</Table.Th>
                  <Table.Th>Last test</Table.Th>
                  <Table.Th>Created</Table.Th>
                  <Table.Th w={48} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((e) => {
                  const last = jobs.find((j) => j.engagementId === e.id);
                  return (
                    <Table.Tr
                      key={e.id}
                      className="ares-clickable"
                      onClick={() => void navigate({ to: "/engagements/$id", params: { id: e.id } })}
                    >
                      <Table.Td>
                        <Link
                          to="/engagements/$id"
                          params={{ id: e.id }}
                          onClick={(ev) => ev.stopPropagation()}
                          style={{ color: "inherit", textDecoration: "none", fontWeight: 600 }}
                        >
                          {e.name}
                        </Link>
                        <Text size="sm" c="dimmed">
                          {e.authorization
                            ? `Approved by ${e.authorization.approvedBy}`
                            : "Permission not recorded yet"}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <StatusBadge info={engagementStatus(e.status)} />
                      </Table.Td>
                      <Table.Td>
                        <SeverityCounts
                          findings={findings.filter((f) => f.engagementId === e.id && isUnresolved(f))}
                          empty="None"
                        />
                      </Table.Td>
                      <Table.Td style={{ whiteSpace: "nowrap" }}>
                        <Text size="sm" c="dimmed">
                          {last ? formatWhen(last.at) : "Not tested"}
                        </Text>
                      </Table.Td>
                      <Table.Td style={{ whiteSpace: "nowrap" }}>
                        <Text size="sm" c="dimmed">
                          {formatDate(e.createdAt)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <IconChevronRight size={16} color="var(--mantine-color-dimmed)" aria-hidden />
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
    </Stack>
  );
}

import { useState } from "react";
import { Card, Group, SegmentedControl, Select, SimpleGrid, Stack } from "@mantine/core";
import { IconCircleCheck } from "@tabler/icons-react";
import { getRouteApi, Link } from "@tanstack/react-router";
import type { Severity } from "../lib/findings.ts";
import { EmptyState, LoadingState, PageHeader, StatCard } from "../ui/index.tsx";
import { FindingsTable } from "../features/findings/FindingsTable.tsx";
import { countBySeverity } from "../features/findings/SeverityCounts.tsx";
import { SOURCES, useFoundBy } from "../features/findings/foundBy.ts";
import {
  isUnresolved,
  useEngagements,
  useFindings,
  type FindingRecord,
} from "../features/workspace/data.ts";

const route = getRouteApi("/findings");

const VIEWS: { value: string; label: string; match: (f: FindingRecord) => boolean }[] = [
  { value: "open", label: "Open", match: (f) => !f.rechecked && f.status === "open" },
  { value: "in_progress", label: "Fix in progress", match: (f) => !f.rechecked && f.status === "in_progress" },
  { value: "fixed", label: "Fixed", match: (f) => f.rechecked || f.status === "fixed" },
  { value: "all", label: "All", match: () => true },
];

const SEVERITIES = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

// FindingsPage is every weakness the tests found, across the workspace.
export function FindingsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const names = Object.fromEntries(all.map((e) => [e.id, e.name]));
  const { findings, loading } = useFindings();
  const [view, setView] = useState("open");
  const [severity, setSeverity] = useState<string | null>(null);
  const [source, setSource] = useState<string | null>(null);

  const engagement = all.some((e) => e.id === search.engagement) ? search.engagement! : null;
  const foundBy = useFoundBy(engagement ? [engagement] : all.map((e) => e.id));
  const scoped = findings.filter(
    (f) =>
      (!engagement || f.engagementId === engagement) &&
      (!severity || f.finding.severity === (severity as Severity)) &&
      (!source || foundBy(f).source === source),
  );
  const rows = scoped.filter(VIEWS.find((v) => v.value === view)!.match);
  const unresolved = countBySeverity(scoped.filter(isUnresolved));

  return (
    <Stack gap="lg">
      <PageHeader
        title="Findings"
        description="Every weakness the tests have found, most serious first."
        actions={
          <Link to="/reports" search={engagement ? { engagement } : {}} className="ares-link">
            Download as a report
          </Link>
        }
      />

      <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} spacing="lg">
        <StatCard label="Critical" value={unresolved.critical} tone={unresolved.critical ? "bad" : undefined} />
        <StatCard label="High" value={unresolved.high} tone={unresolved.high ? "bad" : undefined} />
        <StatCard label="Medium" value={unresolved.medium} tone={unresolved.medium ? "warn" : undefined} />
        <StatCard label="Low" value={unresolved.low} />
        <StatCard
          label="Fixed and re-checked"
          value={scoped.filter((f) => f.rechecked).length}
          tone="good"
        />
      </SimpleGrid>

      <Group justify="space-between" gap="md">
        <SegmentedControl
          aria-label="Show findings by status"
          value={view}
          onChange={setView}
          data={VIEWS.map((v) => ({
            value: v.value,
            label: `${v.label} ${scoped.filter(v.match).length}`,
          }))}
        />
        <Group gap="xs">
          <Select
            aria-label="Engagement"
            placeholder="All engagements"
            data={all.map((e) => ({ value: e.id, label: e.name }))}
            value={engagement}
            onChange={(v) => void navigate({ search: v ? { engagement: v } : {} })}
            clearable
            w={220}
          />
          <Select
            aria-label="Found by"
            placeholder="Found by anything"
            data={SOURCES.map((s) => ({ value: s.value, label: s.filter }))}
            value={source}
            onChange={setSource}
            clearable
            w={180}
          />
          <Select
            aria-label="Severity"
            placeholder="Any severity"
            data={SEVERITIES}
            value={severity}
            onChange={setSeverity}
            clearable
            w={160}
          />
        </Group>
      </Group>

      <Card padding={0}>
        {loading && findings.length === 0 ? (
          <LoadingState label="Loading findings…" />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<IconCircleCheck size={22} />}
            title={findings.length === 0 ? "No findings yet" : "Nothing here"}
            description={
              findings.length === 0
                ? "Run a test in an engagement. Any weakness it finds is listed here."
                : "No finding matches this view. Try another status or filter."
            }
          />
        ) : (
          <FindingsTable findings={rows} engagementNames={names} foundBy={foundBy} />
        )}
      </Card>
    </Stack>
  );
}

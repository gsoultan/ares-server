import { useState } from "react";
import { Button, Card, Group, Select, Stack } from "@mantine/core";
import { IconDownload, IconHistory } from "@tabler/icons-react";
import { getRouteApi } from "@tanstack/react-router";
import { actionLabel, actorLabel, entryDetails, formatDateTime } from "../lib/labels.ts";
import { EmptyState, ErrorNote, LoadingState, PageHeader } from "../ui/index.tsx";
import { ActivityLog } from "../features/engagement/ActivityLog.tsx";
import { useActivity } from "../features/engagement/useActivity.ts";
import { EngagementPicker } from "../features/workspace/EngagementPicker.tsx";
import { useEngagements } from "../features/workspace/data.ts";

const route = getRouteApi("/activity");

const KINDS: { value: string; label: string; actions?: string[] }[] = [
  { value: "all", label: "All activity" },
  {
    value: "tests",
    label: "Tests",
    actions: ["job-started", "job-finished", "job-error", "job-refused", "scope-denied", "result"],
  },
  { value: "findings", label: "Finding status", actions: ["finding-status"],
  },
  {
    value: "setup",
    label: "Setup and permission",
    actions: ["engagement-created", "scope-updated", "authorization-approved", "engagement-halted"],
  },
  { value: "evidence", label: "Evidence", actions: ["evidence-ingested"] },
  { value: "defenders", label: "Defender results", actions: ["detection-recorded"] },
];

function csvCell(s: string): string {
  return `"${s.replace(/"/g, '""')}"`;
}

// ActivityPage is the tamper-evident record of everything done in an engagement.
export function ActivityPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const chosen =
    all.find((e) => e.id === search.engagement) ?? all.find((e) => e.status !== "draft") ?? all[0];
  const activity = useActivity(chosen?.id);
  const [kind, setKind] = useState("all");

  const header = (
    <PageHeader
      title="Activity log"
      description="Everything that happened, in order. The log cannot be edited, and it is checked for changes every time you open it."
    />
  );

  if (engagements.isLoading) return <LoadingState />;
  if (engagements.isError) {
    return (
      <Stack gap="lg">
        {header}
        <ErrorNote title="Could not load the activity log">
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
            icon={<IconHistory size={22} />}
            title="Nothing has happened yet"
            description="Each engagement keeps its own log. Create one to start it."
          />
        </Card>
      </Stack>
    );
  }

  const actions = KINDS.find((k) => k.value === kind)?.actions;
  const entries = activity.entries?.filter((e) => !actions || actions.includes(e.action));

  const download = () => {
    const lines = [
      ["When", "Who", "What happened", "Details"].map(csvCell).join(","),
      ...(entries ?? []).map((e) =>
        [
          formatDateTime(e.time),
          actorLabel(e.actor),
          actionLabel(e.action),
          entryDetails(e, chosen.id),
        ]
          .map(csvCell)
          .join(","),
      ),
    ];
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${chosen.name} activity log.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Stack gap="lg">
      {header}

      <Group justify="space-between" align="flex-end" gap="md">
        <Group gap="xs" align="flex-end">
          <EngagementPicker
            engagements={all}
            value={chosen.id}
            onChange={(id) => void navigate({ search: { engagement: id } })}
          />
          <Select
            label="Show"
            data={KINDS.map(({ value, label }) => ({ value, label }))}
            value={kind}
            onChange={(v) => v && setKind(v)}
            allowDeselect={false}
            w={220}
          />
        </Group>
        <Button
          variant="default"
          leftSection={<IconDownload size={16} />}
          disabled={!entries || entries.length === 0}
          onClick={download}
        >
          Download the log
        </Button>
      </Group>

      {activity.error ? (
        <ErrorNote title="Could not load this engagement's log">
          Ares could not reach its server. Check that it is running, then reload the page.
        </ErrorNote>
      ) : (
        <ActivityLog
          title={chosen.name}
          entries={entries}
          loading={activity.loading}
          integrity={activity.integrity}
          engagementId={chosen.id}
        />
      )}
    </Stack>
  );
}

import { Card, Progress, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconShield } from "@tabler/icons-react";
import { getRouteApi } from "@tanstack/react-router";
import { toneColor } from "../lib/labels.ts";
import { EmptyState, ErrorNote, LoadingState, PageHeader, StatCard } from "../ui/index.tsx";
import { BreachReadiness, DetectionCoverage } from "../features/engagement/Defenses.tsx";
import { EngagementPicker } from "../features/workspace/EngagementPicker.tsx";
import { useCoverage, useEngagements } from "../features/workspace/data.ts";

const route = getRouteApi("/defenses");

// DefensesPage answers "would we notice a real attack?": what the defenders
// did for each attacker technique the tests used, and how that scores against
// well-known breaches.
export function DefensesPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const coverage = useCoverage(all.map((e) => e.id));

  if (engagements.isLoading) return <LoadingState />;

  const header = (
    <PageHeader
      title="Defenses"
      description="Would your team notice a real attack? Record what your security tools and people did during each test."
    />
  );

  if (engagements.isError) {
    return (
      <Stack gap="lg">
        {header}
        <ErrorNote title="Could not load defenses">
          Ares could not reach its server. Check that it is running, then reload the page.
        </ErrorNote>
      </Stack>
    );
  }
  if (all.length === 0) {
    return (
      <Stack gap="lg">
        {header}
        <Card>
          <EmptyState
            icon={<IconShield size={22} />}
            title="Nothing to score yet"
            description="Create an engagement and run a test. The attacker techniques it uses will appear here."
          />
        </Card>
      </Stack>
    );
  }

  // Open on the chosen engagement, else the first that has something to score.
  const chosen =
    all.find((e) => e.id === search.engagement) ??
    all.find((e) => (coverage.byEngagement.find((c) => c.id === e.id)?.summary?.total ?? 0) > 0) ??
    all[0]!;
  const tone = coverage.percent >= 70 ? "good" : coverage.percent >= 40 ? "warn" : "bad";
  const n = (k: string) => coverage.counts[k] ?? 0;

  return (
    <Stack gap="lg">
      {header}

      <SimpleGrid cols={{ base: 2, sm: 3, md: 5 }} spacing="lg">
        <StatCard label="Caught overall" value={coverage.total === 0 ? "–" : `${coverage.percent}%`}>
          {coverage.total === 0 ? (
            <Text size="sm" c="dimmed">
              Nothing to score yet
            </Text>
          ) : (
            <Progress
              value={coverage.percent}
              color={toneColor(tone)}
              size="sm"
              mt={10}
              aria-label={`${coverage.percent}% caught`}
            />
          )}
        </StatCard>
        <StatCard label="Blocked" value={n("prevented")} tone={n("prevented") ? "good" : undefined}>
          <Text size="sm" c="dimmed">
            Stopped before it worked
          </Text>
        </StatCard>
        <StatCard label="Alerted" value={n("detected")} tone={n("detected") ? "good" : undefined}>
          <Text size="sm" c="dimmed">
            Someone was told
          </Text>
        </StatCard>
        <StatCard label="Logged only" value={n("logged")} tone={n("logged") ? "warn" : undefined}>
          <Text size="sm" c="dimmed">
            Recorded, nobody told
          </Text>
        </StatCard>
        <StatCard label="Missed" value={n("missed")} tone={n("missed") ? "bad" : undefined}>
          <Text size="sm" c="dimmed">
            No trace at all
          </Text>
        </StatCard>
      </SimpleGrid>

      <EngagementPicker
        engagements={all}
        value={chosen.id}
        onChange={(id) => void navigate({ search: { engagement: id } })}
      />

      <DetectionCoverage key={`d-${chosen.id}`} id={chosen.id} />
      <BreachReadiness key={`b-${chosen.id}`} id={chosen.id} />
    </Stack>
  );
}

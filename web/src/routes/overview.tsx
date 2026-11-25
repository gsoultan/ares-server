import type { ReactNode } from "react";
import { Box, Card, Group, Progress, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconCircleCheck, IconShieldCheck, IconShieldSearch } from "@tabler/icons-react";
import { useQueries } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { control } from "../client.ts";
import {
  actionLabel,
  actorLabel,
  entryDetails,
  formatWhen,
  plural,
  toneColor,
} from "../lib/labels.ts";
import { useTenant } from "../tenant.tsx";
import {
  EmptyState,
  ErrorNote,
  LoadingState,
  PageHeader,
  Section,
  SeverityBadge,
  StatCard,
  StatusBadge,
} from "../ui/index.tsx";
import { SeverityCounts } from "../features/findings/SeverityCounts.tsx";
import { NewEngagement } from "../features/workspace/NewEngagement.tsx";
import { RiskTrend } from "../features/workspace/RiskTrend.tsx";
import {
  findingState,
  fixProof,
  findingStateInfo,
  isUnresolved,
  type FindingRecord,
  useCoverage,
  useEngagements,
  useFindings,
  useJobs,
} from "../features/workspace/data.ts";

function scoreTone(pct: number) {
  return pct >= 70 ? "good" : pct >= 40 ? "warn" : "bad";
}

// Overview answers "where do we stand?" for the whole workspace: what is open,
// what to fix first, and what is waiting on the reader.
export function OverviewPage() {
  const { tenantId } = useTenant();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const { findings } = useFindings();
  const { jobs } = useJobs();
  const coverage = useCoverage(all.map((e) => e.id));

  // The latest few entries across every engagement's activity log.
  const audits = useQueries({
    queries: all.slice(0, 12).map((e) => ({
      queryKey: ["audit", tenantId, e.id],
      queryFn: () => control.getAudit({ id: e.id, tenantId }),
      staleTime: 10_000,
    })),
  });
  const recent = audits
    .flatMap((a, i) =>
      (a.data?.entries ?? [])
        // One line per test is enough here; the log has every result.
        .filter((entry) => entry.action !== "result")
        .map((entry) => ({ entry, engagement: all[i]! })),
    )
    .sort((a, b) => b.entry.time.localeCompare(a.entry.time))
    .slice(0, 6);

  if (engagements.isLoading) return <LoadingState label="Loading the overview…" />;
  if (engagements.isError) {
    return (
      <Stack gap="lg">
        <PageHeader title="Overview" />
        <ErrorNote title="Could not load the overview">
          Ares could not reach its server. Check that it is running, then reload the page.
        </ErrorNote>
      </Stack>
    );
  }

  if (all.length === 0) {
    return (
      <Stack gap="lg">
        <PageHeader title="Overview" description="Where this workspace stands today." />
        <Card>
          <EmptyState
            icon={<IconShieldSearch size={22} />}
            title="Start with your first engagement"
            description="An engagement is one approved round of security testing. Say what may be tested, record permission, and Ares guides you from there."
            action={<NewEngagement />}
          />
        </Card>
      </Stack>
    );
  }

  const open = findings.filter(isUnresolved);
  const rechecked = findings.filter((f) => f.rechecked);
  const awaiting = findings.filter((f) => !f.rechecked && f.status === "fixed");
  const drafts = all.filter((e) => e.status === "draft");
  const untested = all.filter(
    (e) => e.status === "authorized" && !jobs.some((j) => j.engagementId === e.id),
  );
  const unrecorded = coverage.counts["unknown"] ?? 0;

  const attention: { title: string; detail: string; link: ReactNode }[] = [
    ...drafts.slice(0, 3).map((e) => ({
      title: `Finish setting up ${e.name}`,
      detail: "A scope and signed permission are needed before any test can run.",
      link: (
        <Link to="/engagements/$id" params={{ id: e.id }} search={{ view: "setup" }} className="ares-link">
          Continue
        </Link>
      ),
    })),
    ...untested.slice(0, 3).map((e) => ({
      title: `Profile ${e.name}`,
      detail: "Permission is on file. Find out what it is built with and which tests to run.",
      link: (
        <Link to="/engagements/$id" params={{ id: e.id }} search={{ view: "profile" }} className="ares-link">
          Start
        </Link>
      ),
    })),
    ...(unrecorded > 0
      ? [
          {
            title: "Record what your defenders saw",
            detail: `${plural(unrecorded, "attacker technique")} ${unrecorded === 1 ? "has" : "have"} no result yet.`,
            link: (
              <Link to="/defenses" className="ares-link">
                Record
              </Link>
            ),
          },
        ]
      : []),
    ...(awaiting.length > 0
      ? [
          {
            title: `Re-check ${plural(awaiting.length, "finding")} marked as fixed`,
            detail: "Run the test again to confirm the fix held.",
            link: (
              <Link
                to="/engagements/$id"
                params={{ id: awaiting[0]!.engagementId }}
                search={{ view: "findings", finding: awaiting[0]!.id }}
                className="ares-link"
              >
                Re-check
              </Link>
            ),
          },
        ]
      : []),
  ];

  const ready = all.filter((e) => e.status === "authorized").length;

  return (
    <Stack gap="lg">
      <PageHeader
        title="Overview"
        description="Where this workspace stands today."
        actions={<NewEngagement />}
      />

      <SimpleGrid cols={{ base: 1, xs: 2, md: 4 }} spacing="lg">
        <StatCard label="Open findings" value={open.length} tone={open.length > 0 ? "warn" : "good"}>
          <SeverityCounts findings={open} empty="Nothing open" />
        </StatCard>
        <StatCard label="Fixed and re-checked" value={rechecked.length} tone="good">
          <Text size="sm" c="dimmed">
            of {findings.length} found so far
          </Text>
        </StatCard>
        <StatCard
          label="Caught by your defenders"
          value={coverage.total === 0 ? "–" : `${coverage.percent}%`}
        >
          {coverage.total === 0 ? (
            <Text size="sm" c="dimmed">
              Nothing to score yet
            </Text>
          ) : (
            <Progress
              value={coverage.percent}
              color={toneColor(scoreTone(coverage.percent))}
              size="sm"
              mt={10}
              aria-label={`${coverage.percent}% caught`}
            />
          )}
        </StatCard>
        <StatCard label="Engagements" value={all.length}>
          <Text size="sm" c="dimmed">
            {ready} ready to test, {drafts.length} setting up
          </Text>
        </StatCard>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg" style={{ alignItems: "start" }}>
        <Section
          title="Fix these first"
          description="The most serious open findings."
          aside={
            open.length > 3 ? (
              <Link to="/findings" className="ares-link">
                See all {open.length}
              </Link>
            ) : undefined
          }
        >
          {open.length === 0 ? (
            <EmptyState
              icon={<IconCircleCheck size={22} />}
              title="Nothing open"
              description="Findings from your tests will appear here, most serious first."
            />
          ) : (
            <Box>
              {open.slice(0, 3).map((f) => (
                <Link
                  key={f.id}
                  to="/engagements/$id"
                  params={{ id: f.engagementId }}
                  search={{ view: "findings", finding: f.id }}
                  className="ares-clickable"
                  style={{ display: "block", color: "inherit", textDecoration: "none" }}
                >
                  <Row>
                    <SeverityBadge severity={f.finding.severity} />
                    <Box style={{ flex: 1, minWidth: 0 }}>
                      <Text fw={600} truncate>
                        {f.finding.title}
                      </Text>
                      <Text size="sm" c="dimmed" truncate>
                        {f.engagementName}
                      </Text>
                    </Box>
                    <StatusBadge info={findingStateInfo(findingState(f))} />
                  </Row>
                </Link>
              ))}
            </Box>
          )}
        </Section>

        <Section title="Needs your attention" description="The next step for each thing in progress.">
          {attention.length === 0 ? (
            <EmptyState
              icon={<IconCircleCheck size={22} />}
              title="Nothing is waiting on you"
            />
          ) : (
            <Box>
              {attention.map((a, i) => (
                <Row key={i}>
                  <Box style={{ flex: 1, minWidth: 0 }}>
                    <Text fw={600}>{a.title}</Text>
                    <Text size="sm" c="dimmed">
                      {a.detail}
                    </Text>
                  </Box>
                  {a.link}
                </Row>
              ))}
            </Box>
          )}
        </Section>
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg" style={{ alignItems: "start" }}>
        <RiskTrend />

        <Section
          title="Proven fixed"
          description="Fixed, then tested again: the problem no longer comes back."
          aside={
            rechecked.length > 3 ? (
              <Link to="/findings" className="ares-link">
                See all {rechecked.length}
              </Link>
            ) : undefined
          }
        >
          {rechecked.length === 0 ? (
            <EmptyState
              icon={<IconShieldCheck size={22} />}
              title="No proven fixes yet"
              description="Fix a finding, then re-check it. When the test no longer finds it, it shows here as proof."
            />
          ) : (
            <Box>
              {[...rechecked]
                .sort((a, b) => provenAt(b).localeCompare(provenAt(a)))
                .slice(0, 3)
                .map((f) => (
                  <Link
                    key={f.id}
                    to="/engagements/$id"
                    params={{ id: f.engagementId }}
                    search={{ view: "findings", finding: f.id }}
                    className="ares-clickable"
                    style={{ display: "block", color: "inherit", textDecoration: "none" }}
                  >
                    <Row>
                      <SeverityBadge severity={f.finding.severity} />
                      <Box style={{ flex: 1, minWidth: 0 }}>
                        <Text fw={600} truncate>
                          {f.finding.title}
                        </Text>
                        <Text size="sm" c="dimmed">
                          {fixProof(f)}
                        </Text>
                      </Box>
                    </Row>
                  </Link>
                ))}
            </Box>
          )}
        </Section>
      </SimpleGrid>

      <Section
        title="Recent activity"
        aside={
          <Link to="/activity" className="ares-link">
            Open the activity log
          </Link>
        }
      >
        {recent.length === 0 ? (
          <Text c="dimmed">Nothing has happened yet.</Text>
        ) : (
          <Box>
            {recent.map(({ entry: e, engagement }) => (
              <Row key={`${engagement.id}-${e.seq}`}>
                <Text size="sm" c="dimmed" w={150} style={{ flexShrink: 0 }}>
                  {formatWhen(e.time)}
                </Text>
                <Text style={{ flex: 1, minWidth: 200 }}>
                  {actionLabel(e.action)}
                  <Text span c="dimmed">
                    {" "}
                    · {engagement.name} · {actorLabel(e.actor)}
                  </Text>
                </Text>
                <Text size="sm" c="dimmed" style={{ wordBreak: "break-word" }}>
                  {entryDetails(
                    { ...e, detail: e.detail === engagement.name ? "" : e.detail },
                    engagement.id,
                  )}
                </Text>
              </Row>
            ))}
          </Box>
        )}
      </Section>
    </Stack>
  );
}

// provenAt orders proven fixes newest first: the latest re-check, else when
// the finding was first found.
function provenAt(f: FindingRecord): string {
  return f.proofChecks[0]?.at ?? f.foundAt;
}

function Row({ children }: { children: ReactNode }) {
  return (
    <Group gap="md" py="sm" style={{ borderTop: "1px solid var(--ares-line)" }}>
      {children}
    </Group>
  );
}

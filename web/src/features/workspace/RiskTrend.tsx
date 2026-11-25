import { Box, Group, Stack, Text } from "@mantine/core";
import { IconChartLine } from "@tabler/icons-react";
import type { RiskTrendPoint } from "../../gen/ares/v1/ares_pb.ts";
import { formatWhen, plural, riskChangeText, riskRatingInfo, toneColor } from "../../lib/labels.ts";
import { EmptyState, ErrorNote, LoadingState, Section, StatusBadge } from "../../ui/index.tsx";
import { useRiskTrend } from "./data.ts";

// RiskTrend shows the workspace's risk score after each test, so an owner sees
// whether fixes are paying off. The score only drops once a test proves a fix.
export function RiskTrend({ engagementId }: { engagementId?: string }) {
  const trend = useRiskTrend(engagementId);
  const points = trend.data?.points ?? [];
  const description = "From 0, nothing open, to 99. It drops only when a test proves a fix worked.";

  if (trend.isLoading) {
    return (
      <Section title="Risk over time" description={description}>
        <LoadingState label="Loading the risk score…" />
      </Section>
    );
  }
  if (trend.isError) {
    return (
      <Section title="Risk over time" description={description}>
        <ErrorNote title="Could not load the risk score">Reload the page to try again.</ErrorNote>
      </Section>
    );
  }
  if (points.length === 0) {
    return (
      <Section title="Risk over time" description={description}>
        <EmptyState
          icon={<IconChartLine size={22} />}
          title="No tests yet"
          description="The score appears after the first test finishes."
        />
      </Section>
    );
  }

  const score = trend.data?.score ?? 0;
  const info = riskRatingInfo(score);
  const last = points[points.length - 1]!;
  const open = last.critical + last.high + last.medium + last.low;
  return (
    <Section title="Risk over time" description={description}>
      <Group gap="sm" align="baseline">
        <Text fz={28} fw={650} lh={1.2} c={`var(--mantine-color-${toneColor(info.tone)}-light-color)`}>
          {score}
        </Text>
        <Text c="dimmed">out of 100</Text>
        <StatusBadge info={info} />
      </Group>
      <Text size="sm" c="dimmed">
        {riskChangeText(trend.data?.firstScore ?? score, score, points.length)}{" "}
        {open === 0 ? "Nothing is open." : `${plural(open, "finding")} open.`}
      </Text>
      {points.length > 1 && <Chart points={points} />}
    </Section>
  );
}

const W = 480;
const H = 120;
const PAD = 6;

// Chart is a small line of the score per test. Each point says, on hover, when
// the test ran and what it changed.
function Chart({ points }: { points: RiskTrendPoint[] }) {
  const x = (i: number) => PAD + (i * (W - 2 * PAD)) / Math.max(1, points.length - 1);
  const y = (s: number) => PAD + ((100 - s) * (H - 2 * PAD)) / 100;
  const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join(" ");
  const first = points[0]!;
  const last = points[points.length - 1]!;
  return (
    <Stack gap={4} mt="xs">
      <Box
        component="svg"
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={`Risk score over ${points.length} tests, from ${first.score} to ${last.score}`}
        style={{ width: "100%", height: "auto", display: "block" }}
      >
        <line x1={PAD} x2={W - PAD} y1={y(0)} y2={y(0)} stroke="var(--ares-line)" strokeWidth={1} />
        <line x1={PAD} x2={W - PAD} y1={y(50)} y2={y(50)} stroke="var(--ares-line)" strokeWidth={1} strokeDasharray="3 4" />
        <path d={path} fill="none" stroke="var(--mantine-color-brand-filled)" strokeWidth={2} strokeLinejoin="round" />
        {points.map((p, i) => (
          <circle
            key={`${p.jobId}-${i}`}
            cx={x(i)}
            cy={y(p.score)}
            r={p.fixedFindings > 0 ? 4.5 : 3}
            fill={p.fixedFindings > 0 ? "var(--mantine-color-teal-filled)" : "var(--mantine-color-brand-filled)"}
          >
            <title>{pointText(p)}</title>
          </circle>
        ))}
      </Box>
      <Group justify="space-between" wrap="nowrap">
        <Text size="xs" c="dimmed">
          {formatWhen(first.at)}
        </Text>
        <Text size="xs" c="dimmed">
          {formatWhen(last.at)}
        </Text>
      </Group>
      <Text size="xs" c="dimmed">
        Each point is one test. Green points are tests that proved a fix.
      </Text>
    </Stack>
  );
}

function pointText(p: RiskTrendPoint): string {
  const parts = [`${formatWhen(p.at)}: score ${p.score}`];
  if (p.engagementName) parts.push(p.engagementName);
  if (p.newFindings > 0) parts.push(`${plural(p.newFindings, "new finding")}`);
  if (p.fixedFindings > 0) parts.push(`${plural(p.fixedFindings, "fix", "fixes")} proven`);
  return parts.join(" · ");
}

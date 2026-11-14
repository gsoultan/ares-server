import { Group, Text } from "@mantine/core";
import type { Severity } from "../../lib/findings.ts";
import { SeverityBadge } from "../../ui/index.tsx";
import type { FindingRecord } from "../workspace/data.ts";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

export function countBySeverity(findings: FindingRecord[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.finding.severity] += 1;
  return counts;
}

// SeverityCounts is the row of "2 High, 4 Low" badges used wherever a group of
// findings is summed up.
export function SeverityCounts({ findings, empty = "None" }: { findings: FindingRecord[]; empty?: string }) {
  const counts = countBySeverity(findings);
  const shown = ORDER.filter((s) => counts[s] > 0);
  if (shown.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        {empty}
      </Text>
    );
  }
  return (
    <Group gap={6}>
      {shown.map((s) => (
        <SeverityBadge key={s} severity={s} count={counts[s]} />
      ))}
    </Group>
  );
}

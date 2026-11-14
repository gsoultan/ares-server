import type { ReactNode } from "react";
import { Anchor, Badge, Box, Card, Code, Group, Stack, Text, ThemeIcon, Title, Tooltip } from "@mantine/core";
import type { Remediation, RemediationStep } from "../../lib/findings.ts";

// The four questions a person fixing the issue asks, in the order they ask them.
const STEP_GROUPS: { key: "fix" | "prevent" | "detect" | "verify"; label: string }[] = [
  { key: "fix", label: "Fix it now" },
  { key: "prevent", label: "Stop it coming back" },
  { key: "detect", label: "Spot it if it happens" },
  { key: "verify", label: "Check the fix worked" },
];

// FixSteps is the hands-on answer for whoever makes the change: exact steps
// with the commands or settings to use.
export function FixSteps({ r }: { r: Remediation }) {
  const groups = STEP_GROUPS.filter((g) => r[g.key].length > 0);
  return (
    <Stack gap="md">
      {groups.map((g, gi) => (
        <Box
          key={g.key}
          pt={gi === 0 ? 0 : "md"}
          style={gi === 0 ? undefined : { borderTop: "1px solid var(--ares-line)" }}
        >
          <Title order={3} mb="sm">
            {g.label}
          </Title>
          <Stack gap="sm">
            {r[g.key].map((step, i) => (
              <Step key={i} n={r[g.key].length > 1 ? i + 1 : undefined} step={step} />
            ))}
          </Stack>
        </Box>
      ))}
      {(r.mitigations.length > 0 || r.references.length > 0) && (
        <Group gap="xs" pt="md" style={{ borderTop: "1px solid var(--ares-line)" }}>
          <Text size="xs" fw={600} c="dimmed">
            Related safeguards
          </Text>
          {r.mitigations.map((m) => (
            <Tooltip key={m.id} label={`MITRE ATT&CK mitigation ${m.id}`}>
              <Badge color="gray">{m.name || m.id}</Badge>
            </Tooltip>
          ))}
          {r.references.map((url) => (
            <Anchor key={url} href={url} target="_blank" rel="noreferrer" size="sm">
              {hostOf(url)}
            </Anchor>
          ))}
        </Group>
      )}
    </Stack>
  );
}

function Step({ step, n }: { step: RemediationStep; n?: number }) {
  return (
    <Group gap="sm" wrap="nowrap" align="flex-start">
      {n !== undefined && (
        <ThemeIcon size={22} radius="xl" variant="light" color="brand" mt={1} aria-hidden>
          <Text fz={12} fw={700}>
            {n}
          </Text>
        </ThemeIcon>
      )}
      <Box style={{ flex: 1, minWidth: 0 }}>
        <Text>{step.text}</Text>
        {step.code && (
          <Code block mt={6} bg="var(--ares-subtle)" style={{ border: "1px solid var(--ares-line)" }}>
            {step.code}
          </Code>
        )}
      </Box>
    </Group>
  );
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
}

// Part is one of the three plain answers every finding gives.
export function Part({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Card>
      <Text size="xs" fw={600} c="dimmed" mb={6}>
        {label}
      </Text>
      <Text>{children}</Text>
    </Card>
  );
}

// Facts is a quiet list of "name, value" rows, used for proof and history.
export function Facts({ rows }: { rows: { label: string; value: ReactNode }[] }) {
  return (
    <Box>
      {rows.map((r, i) => (
        <Group
          key={i}
          gap="md"
          wrap="nowrap"
          align="flex-start"
          py="xs"
          style={{ borderTop: "1px solid var(--ares-line)" }}
        >
          <Text c="dimmed" w={140} style={{ flexShrink: 0 }}>
            {r.label}
          </Text>
          <Box style={{ minWidth: 0, wordBreak: "break-word" }}>{r.value}</Box>
        </Group>
      ))}
    </Box>
  );
}

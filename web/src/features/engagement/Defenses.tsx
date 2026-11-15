import { useState } from "react";
import { Anchor, Box, Button, Card, Group, Progress, Select, Stack, Table, Text, Title, Tooltip } from "@mantine/core";
import { IconChevronDown, IconChevronUp, IconExternalLink, IconRadar } from "@tabler/icons-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { errorText, techniqueLabel, toneColor, type Tone } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { EmptyState, ErrorNote, LoadingState, Section, ToneBadge } from "../../ui/index.tsx";

// Each recorded outcome, in the words a non-technical reader can act on.
const OUTCOMES: { value: string; label: string; tone: Tone }[] = [
  { value: "unknown", label: "Not recorded", tone: "neutral" },
  { value: "prevented", label: "Blocked", tone: "good" },
  { value: "detected", label: "Alerted", tone: "good" },
  { value: "logged", label: "Logged only", tone: "warn" },
  { value: "missed", label: "Missed", tone: "bad" },
];

function outcome(value: string) {
  return OUTCOMES.find((o) => o.value === value) ?? OUTCOMES[0]!;
}

// A readiness percentage reads the same everywhere: good from 70, bad under 40.
function scoreTone(pct: number): Tone {
  return pct >= 70 ? "good" : pct >= 40 ? "warn" : "bad";
}

function Score({ pct, covered, total, noun }: { pct: number; covered: number; total: number; noun: string }) {
  const tone = scoreTone(pct);
  return (
    <Tooltip label={`Defenders blocked or alerted on ${covered} of ${total} attacker techniques`}>
      <Box w={150}>
        <Group justify="space-between" gap="xs" mb={4}>
          <Text size="sm" fw={650}>
            {pct}%
          </Text>
          <Text size="xs" c="dimmed">
            {noun}
          </Text>
        </Group>
        <Progress value={pct} color={toneColor(tone)} size="sm" aria-label={`${pct}% ${noun}`} />
      </Box>
    </Tooltip>
  );
}

// DetectionCoverage shows how much of what the tests exercised the defenders
// caught, and lets the operator record the outcome for each technique.
export function DetectionCoverage({ id }: { id: string }) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  const key = ["detection", tenantId, id];

  const summary = useQuery({
    queryKey: key,
    queryFn: () => control.getDetectionSummary({ id, tenantId }),
  });

  const set = useMutation({
    mutationFn: (v: { technique: string; outcome: string }) =>
      control.setDetection({ id, tenantId, technique: v.technique, outcome: v.outcome }),
    onSuccess: (data) => qc.setQueryData(key, data),
  });

  const s = summary.data;
  const techniques = s?.techniques ?? [];

  return (
    <Section
      flush
      title="Did your defenders notice?"
      description="For each attacker technique the tests used, record what your security team or tools did."
      aside={
        !!s && s.total > 0 ? (
          <Score pct={s.coveragePercent} covered={s.covered} total={s.total} noun="caught" />
        ) : undefined
      }
    >
      {summary.isLoading ? (
        <LoadingState />
      ) : summary.isError ? (
        <Box px="lg" pb="lg">
          <ErrorNote title="Could not load defender results">{errorText(summary.error)}</ErrorNote>
        </Box>
      ) : techniques.length === 0 ? (
        <EmptyState
          icon={<IconRadar size={22} />}
          title="Nothing to score yet"
          description="Run a test first. The attacker techniques it uses will appear here for you to score."
        />
      ) : (
        <Table className="ares-stack">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>What the attacker would do</Table.Th>
              <Table.Th>Findings</Table.Th>
              <Table.Th w={220}>What the defenders did</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {techniques.map((t) => (
              <Table.Tr key={t.technique}>
                <Table.Td data-primary>
                  <Text fw={600}>{techniqueLabel(t.technique)}</Text>
                  <Text size="sm" c="dimmed">
                    {t.technique}
                  </Text>
                </Table.Td>
                <Table.Td data-label="Findings">{t.findings}</Table.Td>
                <Table.Td data-label="What the defenders did">
                  <Select
                    aria-label={`What the defenders did for: ${techniqueLabel(t.technique)}`}
                    data={OUTCOMES.map(({ value, label }) => ({ value, label }))}
                    value={t.outcome}
                    allowDeselect={false}
                    onChange={(v) => v && set.mutate({ technique: t.technique, outcome: v })}
                  />
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      {set.isError && (
        <Box p="lg" pt="md">
          <ErrorNote title="Could not save that result">{errorText(set.error)}</ErrorNote>
        </Box>
      )}
    </Section>
  );
}

// BreachReadiness shows how ready the team is for well-known breaches. Each is
// a plain-language, non-destructive exercise mapped to attacker techniques; its
// score reuses the outcomes recorded in DetectionCoverage.
export function BreachReadiness({ id }: { id: string }) {
  const { tenantId } = useTenant();
  const [open, setOpen] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["purple", tenantId, id],
    queryFn: () => control.listPurpleTemplates({ engagementId: id, tenantId }),
  });

  const detail = useQuery({
    queryKey: ["purple-detail", tenantId, id, open],
    queryFn: () => control.getPurpleTemplate({ engagementId: id, templateId: open!, tenantId }),
    enabled: open !== null,
  });

  const templates = list.data?.templates ?? [];

  return (
    <Section
      title="Ready for well-known attacks?"
      description="Each exercise replays a real breach as safe steps. Nothing is attacked for real. Scores use the defender results you recorded above."
    >
      {list.isLoading ? (
        <LoadingState label="Loading exercises…" />
      ) : list.isError ? (
        <ErrorNote title="Could not load the exercises">{errorText(list.error)}</ErrorNote>
      ) : templates.length === 0 ? (
        <EmptyState title="No exercises available" />
      ) : (
        <Stack gap="sm">
          {templates.map((t) => {
            const pct = t.coverage?.coveragePercent ?? 0;
            const covered = t.coverage?.covered ?? 0;
            const total = t.coverage?.total ?? t.techniques;
            const isOpen = open === t.id;
            return (
              <Card key={t.id} padding="md" shadow="none" radius="md">
                <Group justify="space-between" wrap="nowrap" align="flex-start" gap="lg">
                  <Box style={{ flex: 1, minWidth: 0 }}>
                    <Title order={3}>{t.name}</Title>
                    <Text size="sm" c="dimmed" mt={2}>
                      {t.summary}
                    </Text>
                  </Box>
                  <Score pct={pct} covered={covered} total={total} noun="ready" />
                </Group>
                <Group gap="md" mt="sm">
                  <Button
                    variant="subtle"
                    size="compact-sm"
                    ml={-8}
                    aria-expanded={isOpen}
                    rightSection={isOpen ? <IconChevronUp size={14} /> : <IconChevronDown size={14} />}
                    onClick={() => setOpen(isOpen ? null : t.id)}
                  >
                    {isOpen ? "Hide steps" : `Show ${t.stepCount} steps`}
                  </Button>
                  {t.reference && (
                    <Anchor href={t.reference} target="_blank" rel="noreferrer" size="sm">
                      <Group gap={4} wrap="nowrap" component="span">
                        Read about the real breach
                        <IconExternalLink size={14} />
                      </Group>
                    </Anchor>
                  )}
                </Group>

                {isOpen &&
                  (detail.isLoading ? (
                    <LoadingState label="Loading steps…" />
                  ) : detail.isError ? (
                    <Box mt="sm">
                      <ErrorNote title="Could not load the steps">{errorText(detail.error)}</ErrorNote>
                    </Box>
                  ) : (
                    <Stack gap="md" mt="md">
                      {(detail.data?.steps ?? []).map((s) => {
                        const o = outcome(s.outcome);
                        return (
                          <Box
                            key={`${s.order}-${s.technique}`}
                            pt="md"
                            style={{ borderTop: "1px solid var(--ares-line)" }}
                          >
                            <Group justify="space-between" wrap="nowrap" align="flex-start" gap="md">
                              <Text fw={600}>
                                {s.order}. {s.title}
                              </Text>
                              <ToneBadge tone={o.tone} hint={`${s.tactic} · ${s.techniqueName} (${s.technique})`}>
                                {o.label}
                              </ToneBadge>
                            </Group>
                            <Text size="sm" c="dimmed" mt={2}>
                              {s.description}
                            </Text>
                            <Group grow align="flex-start" gap="lg" mt="sm">
                              <Box>
                                <Text size="xs" fw={600} c="dimmed" mb={2}>
                                  What your defenders should see
                                </Text>
                                <Text size="sm">{s.detectionExpectation}</Text>
                              </Box>
                              <Box>
                                <Text size="xs" fw={600} c="dimmed" mb={2}>
                                  How Ares does this safely
                                </Text>
                                <Text size="sm">{s.safeEmulation}</Text>
                              </Box>
                            </Group>
                          </Box>
                        );
                      })}
                    </Stack>
                  ))}
              </Card>
            );
          })}
        </Stack>
      )}
    </Section>
  );
}

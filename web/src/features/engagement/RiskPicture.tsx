import { Fragment } from "react";
import { Badge, Box, Card, Group, Progress, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { IconArrowRight, IconRoute } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { control } from "../../client.ts";
import { riskRating, stepRole } from "../../lib/intel.ts";
import { errorText, plural, toneColor, type Tone } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { EmptyState, ErrorNote, LoadingState, Section, ToneBadge } from "../../ui/index.tsx";
import type { FindingRecord } from "../workspace/data.ts";
import { AiAdvice } from "../ai/AiAdvice.tsx";

function urgency(severity: string): { label: string; tone: Tone } {
  switch (severity) {
    case "critical":
    case "high":
      return { label: "Fix first", tone: "bad" };
    case "medium":
      return { label: "Fix soon", tone: "warn" };
    default:
      return { label: "Fix later", tone: "neutral" };
  }
}

// RiskPicture shows how the findings combine: one overall score, and the
// routes an attacker could take through them, most urgent first.
export function RiskPicture({ id, findings }: { id: string; findings: FindingRecord[] }) {
  const { tenantId } = useTenant();
  const risk = useQuery({
    queryKey: ["risk", tenantId, id],
    queryFn: () => control.getRiskPicture({ id, tenantId }),
  });

  if (risk.isLoading) return <LoadingState label="Working out the risk picture…" />;
  if (risk.isError) {
    return <ErrorNote title="Could not load the risk picture">{errorText(risk.error)}</ErrorNote>;
  }
  const r = risk.data!;
  if (r.rating === "none" || (r.paths.length === 0 && r.unchained.length === 0)) {
    return (
      <Section title="Risk picture">
        <EmptyState
          icon={<IconRoute size={22} />}
          title="No risk picture yet"
          description="Run tests first. When they find weaknesses, this page shows how they combine and which to fix first."
        />
      </Section>
    );
  }

  const rating = riskRating(r.rating);
  const inRoute = new Set(r.paths.flatMap((p) => p.steps.map((s) => s.title)));
  const alone = [...new Set(r.unchained)].filter((t) => !inRoute.has(t));
  const byTitle = (title: string) => findings.find((f) => f.finding.title === title);

  return (
    <Stack gap="lg">
      <AiAdvice
        engagementId={id}
        feature="narrate-paths"
        title="Tell the story"
        description="How an attacker could get in, step by step, and what to fix first."
        action="Tell the story"
      />
      <Card>
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xl" style={{ alignItems: "center" }}>
          <Box>
            <Text size="xs" fw={600} c="dimmed">
              Overall risk
            </Text>
            <Group gap="xs" align="baseline" mt={4}>
              <Text fz={44} fw={650} lh={1}>
                {r.score}
              </Text>
              <Text c="dimmed">out of 100</Text>
            </Group>
            <Progress
              value={r.score}
              color={toneColor(rating.tone)}
              size="md"
              mt="sm"
              aria-label={`Risk score ${r.score} out of 100`}
            />
            <Box mt="sm">
              <ToneBadge tone={rating.tone} size="lg">
                {rating.label}
              </ToneBadge>
            </Box>
          </Box>
          <Box>
            <Title order={2}>What this means</Title>
            <Text mt="xs">
              {r.paths.length > 0
                ? `${capital(plural(r.paths.length, "route"))} could be built from the findings. In a route, one weakness leads to the next, so together they matter more than each does alone. Fixing any one step breaks the route.`
                : "None of the findings connect into a route an attacker could follow. Each is worth fixing on its own."}
            </Text>
            <Text size="sm" c="dimmed" mt="xs">
              The score looks at how findings combine, not only how serious each one is alone.
            </Text>
          </Box>
        </SimpleGrid>
      </Card>

      {r.paths.length > 0 && (
        <Section
          title="How an attacker could get in"
          description="Routes built from the findings, most urgent first. Fix any step to break the route."
        >
          <Stack gap="md">
            {r.paths.map((p, i) => {
              const u = urgency(p.severity);
              // The same finding from two runs is one step, not two.
              const steps = p.steps.filter(
                (s, si) => p.steps.findIndex((x) => x.title === s.title) === si,
              );
              return (
                <Card key={i} shadow="none" padding="md">
                  <Group justify="space-between" align="flex-start" wrap="nowrap" gap="md">
                    <Box>
                      <Title order={3}>
                        {i + 1}. {p.name}
                      </Title>
                      {p.why && (
                        <Text size="sm" c="dimmed" mt={2}>
                          Why it matters: {p.why}
                        </Text>
                      )}
                    </Box>
                    <Box style={{ flexShrink: 0 }}>
                      <ToneBadge tone={u.tone}>{u.label}</ToneBadge>
                    </Box>
                  </Group>
                  <Group gap="xs" mt="md" align="stretch">
                    {steps.map((s, si) => {
                      const record = byTitle(s.title);
                      return (
                        <Fragment key={si}>
                          {si > 0 && <Arrow />}
                          <StepBox label={si === 0 ? "Way in" : stepRole(s.role === "enabler" ? s.role : "then")}>
                            {record ? (
                              <Link
                                to="/engagements/$id"
                                params={{ id }}
                                search={{ view: "findings", finding: record.id }}
                                className="ares-link"
                              >
                                {s.title}
                              </Link>
                            ) : (
                              <Text fw={600}>{s.title}</Text>
                            )}
                          </StepBox>
                        </Fragment>
                      );
                    })}
                    {p.outcome && (
                      <>
                        <Arrow />
                        <StepBox label="What they get" strong>
                          <Text fw={600}>{p.outcome}</Text>
                        </StepBox>
                      </>
                    )}
                  </Group>
                </Card>
              );
            })}
          </Stack>
        </Section>
      )}

      {alone.length > 0 && (
        <Section
          title="Findings that stand alone"
          description="Not part of a route, but still worth fixing."
        >
          <Group gap="xs">
            {alone.map((t, i) => (
              <Badge key={i} color="gray" size="lg" style={{ maxWidth: "100%" }}>
                {t}
              </Badge>
            ))}
          </Group>
        </Section>
      )}
    </Stack>
  );
}

function Arrow() {
  return (
    <Box c="dimmed" style={{ display: "flex", alignItems: "center" }} aria-hidden>
      <IconArrowRight size={18} />
    </Box>
  );
}

function StepBox({ label, strong, children }: { label: string; strong?: boolean; children: React.ReactNode }) {
  return (
    <Box
      p="sm"
      bg={strong ? "var(--mantine-color-red-light)" : "var(--ares-subtle)"}
      style={{ flex: "1 1 180px", borderRadius: 8, minWidth: 0 }}
    >
      <Text size="xs" fw={600} c="dimmed" mb={2}>
        {label}
      </Text>
      {children}
    </Box>
  );
}

function capital(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

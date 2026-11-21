import { useState } from "react";
import { Badge, Box, Button, Group, List, Radio, Stack, Table, Text, ThemeIcon } from "@mantine/core";
import {
  IconAlertTriangle,
  IconArrowLeft,
  IconKey,
  IconShieldCheck,
} from "@tabler/icons-react";
import { Link, useNavigate } from "@tanstack/react-router";
import type { Engagement } from "../../gen/ares/v1/ares_pb.ts";
import { errorText, formatDateTime, moduleInfo, type Tone } from "../../lib/labels.ts";
import {
  EmptyState,
  ErrorNote,
  Field,
  InfoNote,
  LoadingState,
  PageHeader,
  Section,
  ToneBadge,
} from "../../ui/index.tsx";
import {
  approvalState,
  LEVELS,
  levelName,
  useCanManageConsent,
  useSetIntensity,
  useTestConsent,
  useWithdraw,
  type ApprovalState,
  type Level,
} from "./data.ts";

const LEVEL_ICON = {
  1: { icon: IconShieldCheck, color: "teal" },
  2: { icon: IconKey, color: "orange" },
  3: { icon: IconAlertTriangle, color: "red" },
} as const;

const SAFEGUARDS = ["Only targets in scope", "Every action logged", "Rate-limited", "Stop at any time"];

export const STOP_LINE =
  "Ares never does anything that cannot be undone: no wiping or changing your data, no taking your systems down for long, nothing it cannot clean up. It proves the impact without destroying your business. This limit cannot be switched off.";

const APPROVAL_INFO: Record<ApprovalState, { label: string; tone: Tone }> = {
  ready: { label: "Ready, not used", tone: "warn" },
  used: { label: "Used", tone: "neutral" },
  withdrawn: { label: "Withdrawn", tone: "neutral" },
};

// IntensitySummary sits under Scope and permission: the level in force and a
// way to change it.
export function IntensitySummary({ engagement }: { engagement: Engagement }) {
  const consent = useTestConsent(engagement.id);
  const level = consent.data?.level ?? 1;
  const ready = (consent.data?.approvals ?? []).filter((a) => approvalState(a) === "ready").length;
  const canChange = engagement.status === "authorized";
  return (
    <Section
      title="How far tests may go"
      description="The deepest level Ares may use in this engagement. Every engagement starts at safe proof."
      aside={
        canChange && (
          <Link
            to="/engagements/$id"
            params={{ id: engagement.id }}
            search={{ view: "setup", page: "intensity" }}
            className="ares-link"
          >
            Change level
          </Link>
        )
      }
    >
      {consent.isLoading ? (
        <LoadingState label="Loading test intensity…" />
      ) : consent.error ? (
        <ErrorNote title="The test intensity could not be loaded">{errorText(consent.error)}</ErrorNote>
      ) : (
        <Group gap="xl" align="flex-start">
          <Field label="Level">
            {level} · {levelName(level)}
          </Field>
          <Field label="Set by">
            {consent.data?.setBy
              ? `${consent.data.setBy}, ${formatDateTime(consent.data.setAt)}`
              : "The default for every engagement"}
          </Field>
          {level === 3 && <Field label="Approvals not yet used">{ready}</Field>}
        </Group>
      )}
    </Section>
  );
}

// TestIntensity is the page where the level is chosen, and where intrusive
// approvals on file are listed and can be withdrawn.
export function TestIntensity({ engagement }: { engagement: Engagement }) {
  const id = engagement.id;
  const navigate = useNavigate();
  const consent = useTestConsent(id);
  const setLevel = useSetIntensity(id);
  const withdraw = useWithdraw(id);
  const canManage = useCanManageConsent();
  const current = (consent.data?.level ?? 1) as Level;
  const [picked, setPicked] = useState<Level | null>(null);
  const chosen = picked ?? current;
  const canChange = engagement.status === "authorized" && canManage;

  const toSetup = () => void navigate({ to: "/engagements/$id", params: { id }, search: { view: "setup" } });

  const back = (
    <Link to="/engagements/$id" params={{ id }} search={{ view: "setup" }} className="ares-back">
      <IconArrowLeft size={14} />
      {engagement.name} · Scope and permission
    </Link>
  );

  if (consent.isLoading) return <LoadingState label="Loading test intensity…" />;

  const approvals = consent.data?.approvals ?? [];
  const techniques = consent.data?.techniques ?? [];
  const lowering = chosen < 3 && current === 3 && approvals.some((a) => approvalState(a) === "ready");

  return (
    <Stack gap="lg">
      <PageHeader
        back={back}
        title="How far should tests go?"
        description="You choose how deep Ares is allowed to go. The deeper levels prove more, but touch the target more. Ares always starts at the safest level, and you can change this at any time."
      />
      {consent.error && (
        <ErrorNote title="The test intensity could not be loaded">{errorText(consent.error)}</ErrorNote>
      )}
      {engagement.status !== "authorized" && (
        <InfoNote title="The level cannot be changed now">
          Testing is not allowed in this engagement, so its level is fixed.
        </InfoNote>
      )}
      {engagement.status === "authorized" && !canManage && (
        <InfoNote title="Only an owner or admin can change this">
          Ask an owner or admin of this workspace to raise the level or approve an intrusive test.
        </InfoNote>
      )}

      <Section title="What all levels have in common">
        <Group gap="xs">
          {SAFEGUARDS.map((s) => (
            <Badge key={s} variant="light" color="gray" size="lg" leftSection={<IconShieldCheck size={14} />}>
              {s}
            </Badge>
          ))}
        </Group>
      </Section>

      <Section
        title="Choose a level for this engagement"
        description="Pick the highest level Ares may use. Each level includes the ones below it, and every finding still shows exactly what was done to prove it."
      >
        <Radio.Group
          value={String(chosen)}
          onChange={(v) => setPicked(Number(v) as Level)}
          aria-label="Test intensity"
        >
          <Stack gap="sm">
            {LEVELS.map((l) => {
              const { icon: Icon, color } = LEVEL_ICON[l.level];
              const selected = chosen === l.level;
              return (
                <Radio.Card
                  key={l.level}
                  value={String(l.level)}
                  disabled={!canChange}
                  p="lg"
                  radius="md"
                  style={selected ? { borderColor: "var(--mantine-primary-color-filled)" } : undefined}
                >
                  <Group align="flex-start" wrap="nowrap" gap="md">
                    <Radio.Indicator mt={2} />
                    <Stack gap={6} style={{ flex: 1 }}>
                      <Group gap="xs">
                        <ThemeIcon variant="transparent" color={color} size="sm">
                          <Icon size={18} />
                        </ThemeIcon>
                        <Text fw={650} size="lg">
                          {l.level} · {l.name}
                        </Text>
                        {l.level === 1 && <ToneBadge tone="good">Always included</ToneBadge>}
                        {l.level === current && <ToneBadge tone="brand">In force</ToneBadge>}
                        {selected && l.level !== current && l.level > 1 && (
                          <ToneBadge tone="neutral">Selected · includes level {l.level - 1}</ToneBadge>
                        )}
                      </Group>
                      <Text c="dimmed">{l.summary}</Text>
                      <List size="sm" spacing={4}>
                        {l.points.map((p) => (
                          <List.Item key={p}>{p}</List.Item>
                        ))}
                      </List>
                      {l.example && (
                        <Text size="xs" c="dimmed">
                          {l.example}
                        </Text>
                      )}
                      {l.level === 2 && selected && (
                        <InfoNote tone="warn">
                          A harmless marker is placed on the client's system for a moment and then
                          removed. Turn this on only with the client's agreement.
                        </InfoNote>
                      )}
                      {l.level === 3 && (
                        <Box mt={4}>
                          <Text size="sm" fw={600} mb={4}>
                            Tests at this level
                          </Text>
                          {techniques.length === 0 ? (
                            <Text size="sm" c="dimmed">
                              No test at this level is installed.
                            </Text>
                          ) : (
                            <List size="sm" spacing={4}>
                              {techniques.map((t) => (
                                <List.Item key={t.module}>
                                  <Text span fw={600} size="sm">
                                    {t.name}
                                  </Text>
                                  <Text span size="sm" c="dimmed">
                                    {" "}
                                    · {t.action}
                                  </Text>
                                </List.Item>
                              ))}
                            </List>
                          )}
                        </Box>
                      )}
                    </Stack>
                  </Group>
                </Radio.Card>
              );
            })}
          </Stack>
        </Radio.Group>
        {lowering && (
          <InfoNote tone="warn">
            Lowering the level withdraws every intrusive approval that has not been used yet.
          </InfoNote>
        )}
      </Section>

      <Section
        flush
        title="Intrusive approvals"
        description="Each one allows one run of one test against one target, and is used up by that run."
      >
        {approvals.length === 0 ? (
          <EmptyState
            icon={<IconShieldCheck size={22} />}
            title="No approvals on file"
            description="An intrusive test asks for its approval when you set it up."
          />
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table verticalSpacing="sm" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Test</Table.Th>
                  <Table.Th>Target</Table.Th>
                  <Table.Th>Approved by</Table.Th>
                  <Table.Th w={150}>Status</Table.Th>
                  <Table.Th w={110} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {approvals.map((a) => {
                  const state = approvalState(a);
                  const info = APPROVAL_INFO[state];
                  return (
                    <Table.Tr key={a.id}>
                      <Table.Td>{techniques.find((t) => t.module === a.module)?.name ?? moduleInfo(a.module).label}</Table.Td>
                      <Table.Td>{a.target}</Table.Td>
                      <Table.Td>
                        <Text size="sm">{a.approvedBy}</Text>
                        <Text size="xs" c="dimmed">
                          {[a.how, formatDateTime(a.approvedAt)].filter(Boolean).join(" · ")}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <ToneBadge tone={info.tone}>{info.label}</ToneBadge>
                        {state === "used" && a.usedAt && (
                          <Text size="xs" c="dimmed" mt={2}>
                            {formatDateTime(a.usedAt)}
                          </Text>
                        )}
                      </Table.Td>
                      <Table.Td>
                        {state === "ready" && canManage && (
                          <Button
                            variant="subtle"
                            size="xs"
                            color="red"
                            loading={withdraw.isPending && withdraw.variables === a.id}
                            onClick={() => withdraw.mutate(a.id)}
                          >
                            Withdraw
                          </Button>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {withdraw.error && (
          <Box px="lg" pb="md">
            <ErrorNote title="The approval was not withdrawn">{errorText(withdraw.error)}</ErrorNote>
          </Box>
        )}
      </Section>

      <InfoNote tone="good" title="Where Ares stops, on every level">
        {STOP_LINE}
      </InfoNote>

      {setLevel.error && <ErrorNote title="The level was not saved">{errorText(setLevel.error)}</ErrorNote>}
      {canChange && (
        <Group justify="flex-end" gap="sm">
          <Button variant="default" onClick={toSetup}>
            Cancel
          </Button>
          <Button
            disabled={chosen === current}
            loading={setLevel.isPending}
            onClick={() => setLevel.mutate(chosen, { onSuccess: () => setPicked(null) })}
          >
            Save level
          </Button>
        </Group>
      )}
    </Stack>
  );
}

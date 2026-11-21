import { useState, type ReactNode } from "react";
import { Box, Button, Checkbox, Group, Modal, Select, Stack, Table, Text, Textarea, ThemeIcon } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import type { TechniqueApproval, TechniqueInfo } from "../../gen/ares/v1/ares_pb.ts";
import { CONSENT_HOW } from "../../lib/agents.ts";
import { errorText } from "../../lib/labels.ts";
import { ErrorNote, ToneBadge } from "../../ui/index.tsx";
import { useActor, useApprove, useDecline } from "./data.ts";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Table.Tr>
      <Table.Td w={170} c="dimmed" style={{ verticalAlign: "top" }}>
        {label}
      </Table.Td>
      <Table.Td>{children}</Table.Td>
    </Table.Tr>
  );
}

// ApproveTechnique is the one place an intrusive test is allowed: it says what
// the test does, the risk, how it is undone, what it touches and the line it
// never crosses, and records a named, single-use approval for one target.
export function ApproveTechnique({
  engagementId,
  technique,
  target,
  extra,
  opened,
  onClose,
  onApproved,
  defaultNote = "",
}: {
  engagementId: string;
  technique: TechniqueInfo;
  target: string;
  // Settings for this run, shown with the description (the ceiling, the window).
  extra?: { label: string; value: ReactNode }[];
  opened: boolean;
  onClose: () => void;
  onApproved: (a: TechniqueApproval) => void;
  // A note to start from, such as the agreed window.
  defaultNote?: string;
}) {
  const actor = useActor();
  const approve = useApprove(engagementId);
  const decline = useDecline(engagementId);
  const [agreed, setAgreed] = useState(false);
  const [how, setHow] = useState<string | null>(null);
  const [note, setNote] = useState(defaultNote);

  const close = () => {
    setAgreed(false);
    approve.reset();
    decline.reset();
    onClose();
  };

  const onApprove = () =>
    approve.mutate(
      { module: technique.module, target, how: how ?? "", note },
      {
        onSuccess: (a) => {
          setAgreed(false);
          onApproved(a);
        },
      },
    );
  const onDecline = () =>
    decline.mutate({ module: technique.module, target, note }, { onSuccess: close });

  return (
    <Modal
      opened={opened}
      onClose={close}
      size="lg"
      title={
        <Group gap="sm" wrap="nowrap">
          <ThemeIcon variant="light" color="red" size="md">
            <IconAlertTriangle size={16} />
          </ThemeIcon>
          <Text fw={650} size="lg">
            Approve: {technique.name}
          </Text>
        </Group>
      }
    >
      <Stack gap="md">
        <Text c="dimmed">
          On <Text span fw={600} c="var(--mantine-color-text)">{target}</Text>. Read this before you approve.
        </Text>
        <Table verticalSpacing="sm" withRowBorders>
          <Table.Tbody>
            <Row label="What Ares will do">{technique.action}</Row>
            <Row label="The risk">{technique.risk}</Row>
            <Row label="Reversible">
              <ToneBadge tone={technique.reversible ? "good" : "bad"}>
                {technique.reversible ? "Ends when the test stops" : "Not reversible"}
              </ToneBadge>
            </Row>
            <Row label="How it is undone">{technique.recovery}</Row>
            <Row label="Touches">{technique.touches}</Row>
            <Row label="Hard limit">{technique.limit}</Row>
            {extra?.map((e) => (
              <Row key={e.label} label={e.label}>
                {e.value}
              </Row>
            ))}
            <Row label="Approval">Used once, by the next run of this test on this target.</Row>
          </Table.Tbody>
        </Table>
        <Group grow align="flex-start">
          <Select
            label="How the client agreed"
            placeholder="Choose one"
            data={CONSENT_HOW}
            value={how}
            onChange={setHow}
          />
          <Box />
        </Group>
        <Textarea
          label="Note"
          description="Optional. The change request, ticket or name of the person watching."
          value={note}
          onChange={(e) => setNote(e.currentTarget.value)}
          autosize
          minRows={1}
        />
        <Checkbox
          checked={agreed}
          onChange={(e) => setAgreed(e.currentTarget.checked)}
          label={`I authorize this test on this target. Recorded as ${actor}.`}
        />
        {approve.error && (
          <ErrorNote title="The approval was not recorded">{errorText(approve.error)}</ErrorNote>
        )}
        {decline.error && (
          <ErrorNote title="The decision was not recorded">{errorText(decline.error)}</ErrorNote>
        )}
        <Group justify="flex-end" gap="sm">
          <Button variant="default" onClick={onDecline} loading={decline.isPending}>
            Decline
          </Button>
          <Button color="red" disabled={!agreed} onClick={onApprove} loading={approve.isPending}>
            Approve this test
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

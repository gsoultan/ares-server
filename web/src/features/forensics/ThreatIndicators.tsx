import { useRef, useState } from "react";
import {
  ActionIcon,
  Box,
  Button,
  Group,
  Menu,
  Modal,
  Stack,
  Text,
  Textarea,
  TextInput,
  ThemeIcon,
} from "@mantine/core";
import { IconDots, IconShieldCheck, IconShieldOff, IconUpload } from "@tabler/icons-react";
import { formatWhen } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote, InfoNote, Section, ToneBadge } from "../../ui/index.tsx";
import { addFeed, parseFeed, removeFeed, setFeedInUse, useFeeds, type Feed } from "./indicators.ts";

const FORMAT: Record<Feed["format"], string> = {
  stix: "STIX 2.1",
  misp: "MISP event",
  list: "list",
};

function feedSummary(f: Feed): string {
  const n = f.indicators.length;
  const withdrawn = f.indicators.filter((i) => i.withdrawn).length;
  const primary = f.indicators.filter((i) => i.confidence === "primary").length;
  const parts = [`${n.toLocaleString()} ${n === 1 ? "indicator" : "indicators"}`];
  if (primary > 0) parts.push(primary === n ? "primary confidence" : `${primary.toLocaleString()} primary confidence`);
  if (withdrawn > 0) parts.push(`${withdrawn.toLocaleString()} withdrawn`);
  parts.push(`${FORMAT[f.format]}, loaded ${formatWhen(f.loadedAt).toLowerCase()}`);
  return parts.join(" · ");
}

// ThreatIndicators is the workspace's set of known-bad values. A feed is loaded
// once and every check after that compares against it.
export function ThreatIndicators() {
  const { tenantId } = useTenant();
  const feeds = useFeeds(tenantId);
  const [open, setOpen] = useState(false);

  return (
    <Section
      title={
        <Group gap="xs">
          Threat indicators
          <ToneBadge tone="brand" size="sm">
            New
          </ToneBadge>
        </Group>
      }
      description="The known-bad fingerprints, domains, addresses and apps every check compares against. Load a published feed once for the workspace instead of pasting a list each time."
    >
      <Stack gap={0}>
        {feeds.map((f) => (
          <Group
            key={f.id}
            justify="space-between"
            wrap="nowrap"
            gap="md"
            py="sm"
            style={{ borderTop: "1px solid var(--ares-line)" }}
          >
            <Group gap="sm" wrap="nowrap" style={{ minWidth: 0 }}>
              <ThemeIcon variant="light" color={f.inUse ? "teal" : "gray"} radius="md" size={34}>
                {f.inUse ? <IconShieldCheck size={18} /> : <IconShieldOff size={18} />}
              </ThemeIcon>
              <Box style={{ minWidth: 0 }}>
                <Text fw={600} size="sm" style={{ wordBreak: "break-word" }}>
                  {f.name}
                </Text>
                <Text size="xs" c="dimmed">
                  {feedSummary(f)}
                </Text>
              </Box>
            </Group>
            <Group gap="xs" wrap="nowrap">
              {f.inUse ? <ToneBadge tone="good">In use</ToneBadge> : <ToneBadge tone="neutral">Paused</ToneBadge>}
              <Menu position="bottom-end" withinPortal>
                <Menu.Target>
                  <ActionIcon variant="subtle" color="gray" aria-label={`Options for ${f.name}`}>
                    <IconDots size={16} />
                  </ActionIcon>
                </Menu.Target>
                <Menu.Dropdown>
                  <Menu.Item onClick={() => setFeedInUse(tenantId, f.id, !f.inUse)}>
                    {f.inUse ? "Pause: leave it out of checks" : "Use it in checks"}
                  </Menu.Item>
                  <Menu.Item color="red" onClick={() => removeFeed(tenantId, f.id)}>
                    Remove
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            </Group>
          </Group>
        ))}
        <Group
          justify="space-between"
          wrap="wrap"
          gap="md"
          py="sm"
          style={{ borderTop: feeds.length > 0 ? "1px solid var(--ares-line)" : undefined }}
        >
          <Group gap="sm" wrap="nowrap">
            <ThemeIcon variant="light" color="gray" radius="md" size={34}>
              <IconShieldCheck size={18} />
            </ThemeIcon>
            <Box>
              <Text fw={600} size="sm">
                {feeds.length === 0 ? "No feed loaded yet" : "Add another feed or your own list"}
              </Text>
              <Text size="xs" c="dimmed">
                An Amnesty MVT or other STIX 2.1 file, a MISP event, or fingerprints, domains and addresses one per line.
              </Text>
            </Box>
          </Group>
          <Button variant="default" leftSection={<IconUpload size={16} />} onClick={() => setOpen(true)}>
            Load a feed (MVT, STIX or MISP)
          </Button>
        </Group>
        <InfoNote>
          Indicators a publisher has withdrawn are kept for the record but never raise an alert. A withdrawn match
          shows as a note, not a finding. Feeds are kept in this browser for this workspace and are never fetched or
          contacted.
        </InfoNote>
      </Stack>
      <LoadFeed opened={open} onClose={() => setOpen(false)} />
    </Section>
  );
}

function LoadFeed({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { tenantId } = useTenant();
  const [name, setName] = useState("");
  const [text, setText] = useState("");
  const [fileName, setFileName] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const reset = () => {
    setName("");
    setText("");
    setFileName("");
    setProblem(null);
  };

  const pickFile = async (f: File | undefined) => {
    if (!f) return;
    setProblem(null);
    if (f.size > 64 * 1024 * 1024) {
      setProblem(`${f.name} is larger than 64 MB.`);
      return;
    }
    setFileName(f.name);
    setText(await f.text());
    if (!name) setName(f.name.replace(/\.(json|stix2?|txt|csv)$/i, ""));
  };

  const load = () => {
    setProblem(null);
    try {
      const label = name.trim() || fileName || "Your own list";
      const parsed = parseFeed(text, label);
      if (parsed.indicators.length === 0) {
        setProblem("No fingerprints, domains, addresses or app ids were found in it.");
        return;
      }
      const stored = addFeed(tenantId, { name: label, format: parsed.format, indicators: parsed.indicators });
      setNote(
        `${label}: ${parsed.indicators.length.toLocaleString()} ${parsed.indicators.length === 1 ? "indicator" : "indicators"} loaded` +
          (parsed.skipped > 0 ? `, ${parsed.skipped} entries were not usable and were left out.` : ".") +
          (stored ? ` ${stored}` : ""),
      );
      reset();
      onClose();
    } catch (err) {
      setProblem(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <>
      {note && (
        <Box mt="sm">
          <InfoNote title="Feed loaded">{note}</InfoNote>
        </Box>
      )}
      <Modal
        opened={opened}
        onClose={() => {
          reset();
          onClose();
        }}
        title="Load threat indicators"
        size="lg"
      >
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            Choose a file you downloaded, such as an Amnesty MVT indicator file (.stix2), a STIX 2.1 bundle or a MISP
            event export, or paste your own list. Ares reads it here; nothing is fetched.
          </Text>
          <input
            ref={input}
            type="file"
            accept=".json,.stix,.stix2,.txt,.csv"
            hidden
            onChange={(ev) => void pickFile(ev.currentTarget.files?.[0])}
          />
          <Group gap="sm">
            <Button variant="default" leftSection={<IconUpload size={16} />} onClick={() => input.current?.click()}>
              Choose a file
            </Button>
            {fileName && (
              <Text size="sm" c="dimmed" style={{ wordBreak: "break-all" }}>
                {fileName}
              </Text>
            )}
          </Group>
          <TextInput
            label="Name"
            description="How the feed is named on findings, for example Amnesty MVT or Citizen Lab."
            placeholder="Amnesty MVT, mercenary spyware"
            value={name}
            onChange={(ev) => setName(ev.currentTarget.value)}
          />
          <Textarea
            label="Or paste it"
            description="STIX or MISP JSON, or one fingerprint, domain or address per line. Defanged values such as example[.]com are fine."
            autosize
            minRows={3}
            maxRows={10}
            value={fileName ? "" : text}
            placeholder={fileName ? `Using ${fileName}` : undefined}
            disabled={!!fileName}
            onChange={(ev) => setText(ev.currentTarget.value)}
            styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)" } }}
          />
          {problem && <ErrorNote title="The feed could not be loaded">{problem}</ErrorNote>}
          <Group justify="flex-end">
            <Button disabled={text.trim() === ""} onClick={load}>
              Load feed
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

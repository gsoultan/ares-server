import { useState, type ReactNode } from "react";
import {
  Box,
  Button,
  Checkbox,
  Code,
  CopyButton,
  FileInput,
  Group,
  Loader,
  Radio,
  Select,
  Stack,
  Stepper,
  Switch,
  Tabs,
  Text,
  TextInput,
  ThemeIcon,
} from "@mantine/core";
import { IconArrowLeft, IconCheck, IconCopy, IconFileText } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { control } from "../../client.ts";
import type { Engagement, MintAgentKeyResponse } from "../../gen/ares/v1/ares_pb.ts";
import {
  CAPABILITIES,
  CONSENT_HOW,
  DEFAULT_CAPABILITIES,
  installCommand,
  machineName,
  timeLeft,
  type InstallOS,
} from "../../lib/agents.ts";
import { errorText, formatWhen, plural } from "../../lib/labels.ts";
import { useSession } from "../../session.tsx";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote, InfoNote, PageHeader, Section, ToneBadge } from "../../ui/index.tsx";
import { sha256Hex } from "../forensics/files.ts";
import { useAgentChange, useAgentKeys, useAgents } from "./data.ts";

// AddAgent walks an operator through the three things an agent needs: the
// owner's permission, the list of what it may do, and the one-time install
// key with the command to run on the machine. Nothing is installed until
// someone with access to the machine runs that command.
export function AddAgent({ engagement }: { engagement: Engagement }) {
  const id = engagement.id;
  const { tenantId } = useTenant();
  const { user } = useSession();
  const navigate = useNavigate();
  const changed = useAgentChange(id);

  const [who, setWho] = useState("");
  const [how, setHow] = useState<string | null>(CONSENT_HOW[0] ?? null);
  const [file, setFile] = useState<File | null>(null);
  const [fingerprint, setFingerprint] = useState("");
  const [hashing, setHashing] = useState(false);
  const [endsAt, setEndsAt] = useState("");
  const [ownerKnows, setOwnerKnows] = useState(false);
  const [caps, setCaps] = useState<string[]>(DEFAULT_CAPABILITIES);

  const pickFile = async (f: File | null) => {
    setFile(f);
    setFingerprint("");
    if (!f) return;
    setHashing(true);
    try {
      setFingerprint(await sha256Hex(new Uint8Array(await f.arrayBuffer())));
    } finally {
      setHashing(false);
    }
  };

  const mint = useMutation({
    mutationFn: () =>
      control.mintAgentKey({
        engagementId: id,
        tenantId,
        capabilities: caps,
        consent: {
          who: who.trim(),
          how: [how, file?.name].filter((x) => x).join(" · "),
          authFileFingerprint: fingerprint,
          recordedBy: user?.name || user?.email || "operator",
          endsAt: endsAt ? new Date(`${endsAt}T23:59:59`).toISOString() : "",
        },
      }),
    onSuccess: changed,
  });

  const back = (
    <Link to="/engagements/$id" params={{ id }} search={{ view: "agents" }} className="ares-back">
      <IconArrowLeft size={14} />
      {engagement.name} · Agents
    </Link>
  );

  const ready =
    who.trim() !== "" && !!how && ownerKnows && caps.length > 0 && !hashing;

  if (mint.data) {
    return (
      <Stack gap="lg">
        <PageHeader
          back={back}
          title="Add an agent"
          description={`Permission from ${who.trim()} · ${plural(caps.length, "thing")} it may do`}
        />
        <Stepper active={2} size="sm">
          <Stepper.Step label="Permission" />
          <Stepper.Step label="What it may do" />
          <Stepper.Step label="Install" />
        </Stepper>
        <Install
          id={id}
          minted={mint.data}
          mintedAt={mint.submittedAt}
          madeBy={user?.name || user?.email || "you"}
          onDone={() => void navigate({ to: "/engagements/$id", params: { id }, search: { view: "agents" } })}
        />
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      <PageHeader
        back={back}
        title="Add an agent"
        description="Three steps. Nothing is installed until someone with access to the machine runs the install command in step 3."
      />
      <Stepper active={ready ? 1 : 0} size="sm">
        <Stepper.Step label="Permission" />
        <Stepper.Step label="What it may do" />
        <Stepper.Step label="Install" />
      </Stepper>

      <Section
        title="1. Permission from the machine's owner"
        description="An agent runs only with the owner's agreement. What you enter here goes into the activity log and the report."
      >
        <Stack gap="md" maw={640}>
          <TextInput
            label="Who agreed"
            description="The person who owns or runs this machine for the client."
            placeholder="Name, role, company"
            value={who}
            onChange={(ev) => setWho(ev.currentTarget.value)}
            required
          />
          <Group grow align="flex-start">
            <Select
              label="How they agreed"
              data={CONSENT_HOW}
              value={how}
              onChange={setHow}
              allowDeselect={false}
            />
            <FileInput
              label="Their permission document"
              description="Fingerprinted in this browser when you add it, like evidence."
              placeholder="Add the signed file"
              leftSection={<IconFileText size={16} />}
              value={file}
              onChange={(f) => void pickFile(f)}
              clearable
            />
          </Group>
          {(hashing || fingerprint) && (
            <Text size="sm" c="dimmed">
              {hashing ? "Fingerprinting…" : <>Fingerprint <Code>{fingerprint.slice(0, 16)}…</Code></>}
            </Text>
          )}
          <TextInput
            type="date"
            label="Permission ends (optional)"
            description="The agent stops when the engagement stops or you remove it, whichever is first."
            value={endsAt}
            onChange={(ev) => setEndsAt(ev.currentTarget.value)}
            maw={240}
          />
          <Checkbox
            checked={ownerKnows}
            onChange={(ev) => setOwnerKnows(ev.currentTarget.checked)}
            label="The owner knows an agent will run on this machine"
            description='They know it runs as "Ares Testing Agent", what it may do, that it keeps a log they can read, and that they can stop or remove it at any time.'
          />
        </Stack>
      </Section>

      <Section
        title="2. What it may do"
        description="Only what is ticked. The agent refuses anything else, even if asked. Nothing here changes the machine or other machines."
      >
        <Checkbox.Group value={caps} onChange={setCaps}>
          <Stack gap={0}>
            {CAPABILITIES.map((c) => (
              <Box key={c.id} py="sm" style={{ borderTop: "1px solid var(--ares-line)" }}>
                <Checkbox
                  value={c.id}
                  label={
                    <Group gap="xs">
                      <Text fw={600}>{c.label}</Text>
                      {c.tag && <ToneBadge tone="neutral">{c.tag}</ToneBadge>}
                    </Group>
                  }
                  description={c.summary}
                />
              </Box>
            ))}
          </Stack>
        </Checkbox.Group>
        <InfoNote title="Limits that always apply">
          Stays inside this engagement's scope
          {engagement.inScope.length > 0 && (
            <>
              : <Code>{engagement.inScope.join(", ")}</Code>
            </>
          )}
          . Stops the moment testing in this engagement is stopped or you remove it.{" "}
          <Link to="/engagements/$id" params={{ id }} search={{ view: "setup" }} className="ares-link">
            See the scope
          </Link>
        </InfoNote>
      </Section>

      {mint.isError && <ErrorNote title="Could not make the install key">{errorText(mint.error)}</ErrorNote>}

      <Group justify="flex-end" gap="sm">
        <Button
          variant="default"
          onClick={() => void navigate({ to: "/engagements/$id", params: { id }, search: { view: "agents" } })}
        >
          Cancel
        </Button>
        <Button disabled={!ready} loading={mint.isPending} onClick={() => mint.mutate()}>
          Continue to install
        </Button>
      </Group>
      {!ready && (
        <Text size="sm" c="dimmed" ta="right" mt={-8}>
          Say who agreed, confirm the owner knows, and tick at least one thing it may do.
        </Text>
      )}
    </Stack>
  );
}

function Install({
  id,
  minted,
  mintedAt,
  madeBy,
  onDone,
}: {
  id: string;
  minted: MintAgentKeyResponse;
  mintedAt: number;
  madeBy: string;
  onDone: () => void;
}) {
  const { tenantId } = useTenant();
  const changed = useAgentChange(id);
  const [os, setOs] = useState<InstallOS>("windows");
  const [server, setServer] = useState(window.location.origin);
  const [proxyMode, setProxyMode] = useState("system");
  const [proxy, setProxy] = useState("");
  const [inspects, setInspects] = useState(false);
  const [ca, setCa] = useState("");

  const keys = useAgentKeys(id);
  const agents = useAgents(id);
  const keyWaiting = keys.data?.keys.some((k) => k.keyId === minted.keyId) ?? true;
  // The newest agent enrolled since this key was made is the one that used it.
  const arrived = keyWaiting
    ? undefined
    : (agents.data?.agents ?? [])
        .filter((a) => new Date(a.enrolledAt).getTime() >= mintedAt - 5000)
        .sort((a, b) => b.enrolledAt.localeCompare(a.enrolledAt))[0];

  const cancel = useMutation({
    mutationFn: () => control.cancelAgentKey({ engagementId: id, tenantId, keyId: minted.keyId }),
    onSuccess: () => {
      changed();
      onDone();
    },
  });

  const command = installCommand({
    os,
    server: server.trim() || window.location.origin,
    key: minted.installKey,
    proxy: proxyMode === "this" ? proxy.trim() : undefined,
    trustCa: inspects ? ca.trim() || "inspection-ca.pem" : undefined,
  });

  return (
    <>
      <Section
        title="3. Install it"
        description="Run this on the machine as an administrator, from the folder where the ares-agent program is. It connects the agent to this engagement and starts it."
      >
        <Tabs value={os} onChange={(v) => setOs((v as InstallOS) ?? "windows")}>
          <Tabs.List>
            <Tabs.Tab value="windows">Windows</Tabs.Tab>
            <Tabs.Tab value="linux">Linux</Tabs.Tab>
          </Tabs.List>
        </Tabs>
        <Box>
          <Text fw={600}>Install key</Text>
          <Text size="sm" c="dimmed" mb={6}>
            Works once, for this engagement only. Expires in {timeLeft(minted.expiresAt)}. It is shown only
            now; if it leaks, cancel it and make another.
          </Text>
          <Copyable value={minted.installKey}>{minted.installKey}</Copyable>
        </Box>
        <Box>
          <Text fw={600} mb={6}>
            Command ({os === "windows" ? "PowerShell, run as administrator" : "shell, run as root"})
          </Text>
          <Copyable value={command} block>
            {command}
          </Copyable>
        </Box>
      </Section>

      <Section
        title="If the machine is on a private network"
        description="The agent only ever calls out to Ares on port 443, like a web browser. It opens no port on the machine, so it works behind firewalls and office routers. These settings update the command above."
      >
        <Stack gap="md" maw={640}>
          <TextInput
            label="Address the agent calls"
            description="If Ares sits behind a Cloudflare Tunnel or another public address, enter that address. Nothing else changes."
            value={server}
            onChange={(ev) => setServer(ev.currentTarget.value)}
          />
          <Radio.Group label="Proxy" value={proxyMode} onChange={setProxyMode}>
            <Stack gap="xs" mt={4}>
              <Radio value="system" label="Use the machine's own proxy settings" />
              <Radio value="this" label="Use this proxy" />
            </Stack>
          </Radio.Group>
          {proxyMode === "this" && (
            <TextInput
              aria-label="Proxy address"
              placeholder="http://proxy.example.local:8080"
              value={proxy}
              onChange={(ev) => setProxy(ev.currentTarget.value)}
            />
          )}
          <Switch
            checked={inspects}
            onChange={(ev) => setInspects(ev.currentTarget.checked)}
            label="The network inspects encrypted traffic"
            description="Some companies open HTTPS at the firewall. Add their certificate so the agent can still be sure it is talking to Ares."
          />
          {inspects && (
            <TextInput
              label="Certificate file on the machine"
              placeholder="inspection-ca.pem"
              value={ca}
              onChange={(ev) => setCa(ev.currentTarget.value)}
            />
          )}
        </Stack>
      </Section>

      <Section
        title="Waiting for the agent"
        description="You can leave this page. The agent appears in the list as soon as it calls in."
        aside={
          keyWaiting ? (
            <Button color="red" variant="light" loading={cancel.isPending} onClick={() => cancel.mutate()}>
              Cancel key
            </Button>
          ) : (
            <Button onClick={onDone}>Go to agents</Button>
          )
        }
      >
        {cancel.isError && <ErrorNote title="Could not cancel the key">{errorText(cancel.error)}</ErrorNote>}
        <Stack gap={0}>
          <Progress done when={formatWhen(new Date(mintedAt).toISOString())} title="Install key made">
            By {madeBy}. Written to the activity log.
          </Progress>
          {keyWaiting ? (
            <Progress running title="Waiting for the agent to call in…">
              Nothing yet. If it takes more than a few minutes, check the machine can open {server}.
            </Progress>
          ) : (
            <Progress done title={arrived ? `${machineName(arrived)} called in` : "The key was used"}>
              {arrived ? "It is now in the list of agents." : "The agent is in the list of agents."}
            </Progress>
          )}
        </Stack>
      </Section>
    </>
  );
}

function Copyable({ value, block, children }: { value: string; block?: boolean; children: ReactNode }) {
  return (
    <Box pos="relative">
      <Code
        block
        fz="sm"
        bg="var(--ares-subtle)"
        pr={96}
        style={{ border: "1px solid var(--ares-line)", whiteSpace: block ? "pre" : "pre-wrap", wordBreak: "break-all" }}
      >
        {children}
      </Code>
      <CopyButton value={value}>
        {({ copied, copy }) => (
          <Button
            size="xs"
            variant="default"
            leftSection={<IconCopy size={14} />}
            onClick={copy}
            pos="absolute"
            top={8}
            right={8}
          >
            {copied ? "Copied" : "Copy"}
          </Button>
        )}
      </CopyButton>
    </Box>
  );
}

function Progress({
  title,
  when,
  done,
  running,
  children,
}: {
  title: string;
  when?: string;
  done?: boolean;
  running?: boolean;
  children: ReactNode;
}) {
  return (
    <Group align="flex-start" wrap="nowrap" gap="md" py="sm" style={{ borderTop: "1px solid var(--ares-line)" }}>
      <Text size="sm" c="dimmed" w={150} style={{ flexShrink: 0 }}>
        {when ?? ""}
      </Text>
      <Box w={22} style={{ flexShrink: 0, display: "flex", justifyContent: "center" }} pt={2}>
        {running ? (
          <Loader size="xs" />
        ) : done ? (
          <ThemeIcon size={18} radius="xl" variant="light" color="teal">
            <IconCheck size={12} />
          </ThemeIcon>
        ) : null}
      </Box>
      <Box>
        <Text fw={600}>{title}</Text>
        <Text size="sm" c="dimmed">
          {children}
        </Text>
      </Box>
    </Group>
  );
}

import { useEffect, useState } from "react";
import { Button, Group, PasswordInput, Select, Stack, Text, TextInput } from "@mantine/core";
import { IconCheck } from "@tabler/icons-react";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "../client.ts";
import type { SecretStatus, SettingsView } from "../gen/ares/v1/ares_pb.ts";
import { errorText, formatWhen } from "../lib/labels.ts";
import { useTenant } from "../tenant.tsx";
import { ErrorNote, InfoNote, LoadingState, PageHeader, Section, ToneBadge } from "../ui/index.tsx";

// What each AI provider needs, in the words a person setting it up would use.
const PROVIDERS = [
  { value: "", label: "Off" },
  { value: "anthropic", label: "Anthropic" },
  { value: "openai", label: "OpenAI" },
  { value: "gemini", label: "Google Gemini" },
  { value: "azure", label: "Azure OpenAI" },
  { value: "openai-compatible", label: "Your own server (OpenAI format)" },
];

// The keys for outside lookup services, grouped by service.
const LOOKUPS: { title: string; detail: string; fields: { name: string; label: string }[] }[] = [
  {
    title: "Shodan",
    detail: "Finds what a company shows to the internet without touching its systems.",
    fields: [{ name: "osint.shodan.api_key", label: "API key" }],
  },
  {
    title: "Censys",
    detail: "A second source for internet-facing servers and certificates.",
    fields: [
      { name: "osint.censys.api_id", label: "API ID" },
      { name: "osint.censys.api_secret", label: "API secret" },
    ],
  },
  {
    title: "Have I Been Pwned",
    detail: "Checks whether company email addresses appear in known data leaks.",
    fields: [{ name: "osint.hibp.api_key", label: "API key" }],
  },
];

const AI_KEY = "ai.api_key";

// SettingsPage is where Ares is set up from inside the app, so nobody has to
// edit files or server variables. Keys are write-only: once saved they are
// never shown again.
export function SettingsPage() {
  const { tenantId } = useTenant();
  const settings = useQuery({
    queryKey: ["settings", tenantId],
    queryFn: () => control.getSettings({ tenantId }),
    retry: false,
  });

  const header = (
    <PageHeader
      title="Settings"
      description="Everything is set up here. No files or server variables to edit."
    />
  );

  if (settings.isLoading) return <LoadingState label="Loading settings…" />;
  if (settings.isError || !settings.data) {
    const notReady = settings.error instanceof ConnectError && settings.error.code === Code.Unavailable;
    return (
      <Stack gap="lg">
        {header}
        {notReady ? (
          <InfoNote title="Finish setting up Ares first">
            Settings are locked with an encryption key, and this installation does not have one yet.
            Complete the first-run setup, then come back here.
          </InfoNote>
        ) : (
          <ErrorNote title="Could not load settings">{errorText(settings.error)}</ErrorNote>
        )}
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      {header}
      <Form key={tenantId} view={settings.data} />
    </Stack>
  );
}

function Form({ view }: { view: SettingsView }) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  const [provider, setProvider] = useState(view.ai?.provider ?? "");
  const [model, setModel] = useState(view.ai?.model ?? "");
  const [baseUrl, setBaseUrl] = useState(view.ai?.baseUrl ?? "");
  const [apiVersion, setApiVersion] = useState(view.ai?.apiVersion ?? "");
  // Only keys typed during this visit. An empty box leaves the saved key alone.
  const [typed, setTyped] = useState<Record<string, string>>({});
  const [removed, setRemoved] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);

  const status = (name: string) => view.secrets.find((s) => s.name === name);

  const save = useMutation({
    mutationFn: () =>
      control.updateSettings({
        tenantId,
        aiPresent: true,
        ai: {
          provider,
          model: model.trim(),
          baseUrl: baseUrl.trim(),
          apiVersion: apiVersion.trim(),
          maxTokens: view.ai?.maxTokens ?? 0,
          temperature: view.ai?.temperature ?? 0,
        },
        secrets: [
          ...Object.entries(typed)
            .filter(([name, value]) => value.trim() !== "" && !removed.includes(name))
            .map(([name, value]) => ({ name, value: value.trim(), valuePresent: true, clear: false })),
          ...removed.map((name) => ({ name, value: "", valuePresent: false, clear: true })),
        ],
      }),
    onSuccess: (next) => {
      qc.setQueryData(["settings", tenantId], next);
      test.reset();
      setTyped({});
      setRemoved([]);
      setSaved(true);
    },
  });

  // Tries the provider with what is in the form right now, saved or not. It
  // sends one tiny question and nothing about any engagement.
  const test = useMutation({
    mutationFn: () => {
      const key = (typed[AI_KEY] ?? "").trim();
      return control.testAIProvider({
        tenantId,
        aiPresent: true,
        ai: {
          provider,
          model: model.trim(),
          baseUrl: baseUrl.trim(),
          apiVersion: apiVersion.trim(),
          maxTokens: view.ai?.maxTokens ?? 0,
          temperature: view.ai?.temperature ?? 0,
        },
        apiKey: key,
        apiKeyPresent: key !== "",
      });
    },
  });

  // A result only describes the values it was run with, so drop it on any edit.
  const typedAiKey = typed[AI_KEY] ?? "";
  const resetTest = test.reset;
  useEffect(() => {
    resetTest();
  }, [provider, model, baseUrl, apiVersion, typedAiKey, resetTest]);

  useEffect(() => {
    if (!saved) return;
    const t = setTimeout(() => setSaved(false), 4000);
    return () => clearTimeout(t);
  }, [saved]);

  const needsUrl = provider === "openai-compatible" || provider === "azure";
  const aiKey = status(AI_KEY);
  const keyMissing =
    provider !== "" && provider !== "openai-compatible" && !aiKey?.set && !(typed[AI_KEY] ?? "").trim();
  const urlMissing = needsUrl && baseUrl.trim() === "";
  const modelMissing = provider !== "" && provider !== "anthropic" && model.trim() === "";

  const keyField = (name: string, label: string) => (
    <KeyField
      key={name}
      label={label}
      status={status(name)}
      value={typed[name] ?? ""}
      removed={removed.includes(name)}
      onChange={(v) => setTyped((t) => ({ ...t, [name]: v }))}
      onRemove={(on) => setRemoved((r) => (on ? [...r, name] : r.filter((x) => x !== name)))}
    />
  );

  return (
    <>
      <Section
        title="AI assistant"
        description="Optional. It explains findings and drafts summaries in plain words. It never runs a test, and it asks before sending anything about an engagement."
        aside={
          <ToneBadge tone={view.aiConfigured ? "good" : view.ai?.provider ? "warn" : "neutral"}>
            {view.aiConfigured ? "Set up" : view.ai?.provider ? "Not ready" : "Off"}
          </ToneBadge>
        }
      >
        <Stack gap="md" maw={560}>
          <Select
            label="Provider"
            description="The AI service that writes the text. Choose Off to hide the assistant everywhere."
            data={PROVIDERS}
            value={provider}
            onChange={(v) => setProvider(v ?? "")}
            allowDeselect={false}
          />
          {provider !== "" && (
            <>
              <TextInput
                label={provider === "azure" ? "Deployment name" : "Model"}
                description={
                  provider === "anthropic"
                    ? "Leave empty to use the recommended model."
                    : "The name of the model to use, exactly as the provider writes it."
                }
                value={model}
                onChange={(ev) => setModel(ev.currentTarget.value)}
                error={modelMissing ? "This provider needs a model name." : undefined}
              />
              {needsUrl && (
                <TextInput
                  label="Server address"
                  description={
                    provider === "azure"
                      ? "The address of your Azure OpenAI resource."
                      : "The address of your server, for example https://ai.example.com/v1"
                  }
                  value={baseUrl}
                  onChange={(ev) => setBaseUrl(ev.currentTarget.value)}
                  error={urlMissing ? "This provider needs a server address." : undefined}
                />
              )}
              {provider === "azure" && (
                <TextInput
                  label="API version (optional)"
                  value={apiVersion}
                  onChange={(ev) => setApiVersion(ev.currentTarget.value)}
                />
              )}
              {keyField(AI_KEY, "API key")}
              {keyMissing && (
                <Text size="sm" c="orange.8">
                  This provider needs an API key before the assistant can answer.
                </Text>
              )}
              <Group gap="md" align="center">
                <Button
                  variant="default"
                  loading={test.isPending}
                  disabled={urlMissing || modelMissing || keyMissing}
                  onClick={() => test.mutate()}
                >
                  Test the connection
                </Button>
                {test.data?.ok && (
                  <Group gap={6} c="teal.8">
                    <IconCheck size={16} />
                    <Text size="sm" fw={600}>
                      It works. {test.data.model || "The provider"} answered{" "}
                      {Number(test.data.latencyMs) < 1000
                        ? "in under a second"
                        : `in ${(Number(test.data.latencyMs) / 1000).toFixed(1)} seconds`}
                      .
                    </Text>
                  </Group>
                )}
              </Group>
              {test.data && !test.data.ok && (
                <ErrorNote title="The provider did not answer">
                  {test.data.error || "No reason was given."} Check the key, the model name and the
                  address, then try again.
                </ErrorNote>
              )}
              {test.isError && <ErrorNote title="The test could not run">{errorText(test.error)}</ErrorNote>}
              <Text size="xs" c="dimmed">
                The test sends one tiny question and nothing about any engagement. It uses what is in
                the form now, even before you save.
              </Text>
            </>
          )}
        </Stack>
      </Section>

      <Section
        title="Lookup services"
        description="Optional keys for outside services Ares can ask about a target. Each service is used only when its key is saved."
      >
        <Stack gap="lg" maw={560}>
          {LOOKUPS.map((l) => (
            <Stack key={l.title} gap="xs">
              <div>
                <Text fw={600}>{l.title}</Text>
                <Text size="sm" c="dimmed">
                  {l.detail}
                </Text>
              </div>
              {l.fields.map((f) => keyField(f.name, f.label))}
            </Stack>
          ))}
        </Stack>
      </Section>

      {save.isError && <ErrorNote title="The settings were not saved">{errorText(save.error)}</ErrorNote>}
      <Group>
        <Button loading={save.isPending} disabled={urlMissing || modelMissing} onClick={() => save.mutate()}>
          Save settings
        </Button>
        {saved && (
          <Group gap={6} c="teal.8">
            <IconCheck size={16} />
            <Text size="sm" fw={600}>
              Saved
            </Text>
          </Group>
        )}
      </Group>
    </>
  );
}

// KeyField is a box for a secret. A saved key is never shown again: only its
// last characters, so the person can tell which key it is.
function KeyField({
  label,
  status,
  value,
  removed,
  onChange,
  onRemove,
}: {
  label: string;
  status?: SecretStatus;
  value: string;
  removed: boolean;
  onChange: (v: string) => void;
  onRemove: (on: boolean) => void;
}) {
  const set = !!status?.set && !removed;
  return (
    <div>
      <PasswordInput
        label={label}
        description={
          removed
            ? "Will be removed when you save."
            : set
              ? `Saved${status?.updatedAt ? ` ${formatWhen(status.updatedAt).replace(/^T/, "t").replace(/^Y/, "y")}` : ""}. It is never shown again. Type a new key to replace it.`
              : "Stored encrypted. Once saved, it is never shown again."
        }
        placeholder={set ? status?.hint || "Saved" : "Paste the key"}
        value={value}
        disabled={removed}
        onChange={(ev) => onChange(ev.currentTarget.value)}
        autoComplete="off"
      />
      {status?.set && (
        <Button variant="subtle" size="compact-xs" px={0} mt={2} color={removed ? "gray" : "red"} onClick={() => onRemove(!removed)}>
          {removed ? "Keep the saved key" : "Remove the saved key"}
        </Button>
      )}
    </div>
  );
}

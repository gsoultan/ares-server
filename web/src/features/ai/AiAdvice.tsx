import { useState } from "react";
import { Badge, Box, Button, CopyButton, Group, Stack, Text } from "@mantine/core";
import { IconCopy, IconSparkles } from "@tabler/icons-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { errorText } from "../../lib/labels.ts";
import { aiAllowed, allowAi } from "../../lib/local.ts";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote, InfoNote, Section } from "../../ui/index.tsx";

export type AiFeature = "explain-finding" | "suggest-checks" | "narrate-paths" | "draft-report";

const PROVIDERS: Record<string, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  "openai-compatible": "your own AI server",
  gemini: "Google Gemini",
  azure: "Azure OpenAI",
};

export function providerName(id: string): string {
  return PROVIDERS[id] ?? id;
}

// useAiStatus asks whether an AI assistant is set up. It reads the saved
// settings only, so nothing about the engagement is sent.
export function useAiStatus() {
  const { tenantId } = useTenant();
  const settings = useQuery({
    queryKey: ["settings", tenantId],
    queryFn: () => control.getSettings({ tenantId }),
    staleTime: 60_000,
    retry: false,
  });
  return {
    enabled: !!settings.data?.aiConfigured,
    provider: settings.data?.ai?.provider ?? "",
  };
}

// AiAdvice is one place the AI assistant can help. It only writes text: it
// never starts a test or changes the scope. It is hidden when no assistant is
// set up, and it asks before sending anything for the first time.
export function AiAdvice({
  engagementId,
  feature,
  findingId,
  title,
  description,
  action,
  footnote,
}: {
  engagementId: string;
  feature: AiFeature;
  findingId?: string;
  title: string;
  description: string;
  // The words on the button.
  action: string;
  footnote?: string;
}) {
  const { tenantId } = useTenant();
  const status = useAiStatus();
  const [asking, setAsking] = useState(false);
  const ask = useMutation({
    mutationFn: () =>
      control.advise({ tenantId, engagementId, feature, findingId: findingId ?? "", optIn: true }),
  });

  if (!status.enabled) return null;
  const provider = providerName(status.provider);
  const answer = ask.data;

  const start = () => {
    if (aiAllowed(tenantId, engagementId)) ask.mutate();
    else setAsking(true);
  };

  return (
    <Section
      title={title}
      description={`${description} Written by the AI assistant. It only advises and never runs a test.`}
      aside={
        <Badge color="brand" leftSection={<IconSparkles size={12} />}>
          AI assistant
        </Badge>
      }
    >
      {asking && !answer && !ask.isPending ? (
        <InfoNote title="Before the first use in this engagement">
          <Stack gap="sm" align="flex-start">
            <Text size="sm">
              To write this, details of this engagement's findings are sent to the AI provider your
              organization chose{provider ? ` (${provider})` : ""}. Nothing is sent until you agree.
            </Text>
            <Group gap="sm">
              <Button
                size="xs"
                onClick={() => {
                  allowAi(tenantId, engagementId);
                  setAsking(false);
                  ask.mutate();
                }}
              >
                Allow for this engagement
              </Button>
              <Button size="xs" variant="default" onClick={() => setAsking(false)}>
                Not now
              </Button>
            </Group>
          </Stack>
        </InfoNote>
      ) : (
        <Group>
          <Button
            variant={answer?.text ? "default" : "light"}
            leftSection={<IconSparkles size={16} />}
            loading={ask.isPending}
            onClick={start}
          >
            {answer?.text ? "Write it again" : action}
          </Button>
          {ask.isPending && (
            <Text size="sm" c="dimmed">
              Writing. This can take up to a minute.
            </Text>
          )}
        </Group>
      )}

      {ask.isError && <ErrorNote title="The assistant could not answer">{errorText(ask.error)}</ErrorNote>}
      {answer?.error && (
        <ErrorNote title="The AI provider did not answer">
          {answer.error} Check the AI assistant in Settings.
        </ErrorNote>
      )}
      {answer?.text && (
        <Box>
          <Text style={{ whiteSpace: "pre-wrap" }} maw={720}>
            {answer.text}
          </Text>
          <Group gap="md" mt="md">
            <CopyButton value={answer.text}>
              {({ copied, copy }) => (
                <Button size="xs" variant="default" leftSection={<IconCopy size={14} />} onClick={copy}>
                  {copied ? "Copied" : "Copy the text"}
                </Button>
              )}
            </CopyButton>
            <Text size="xs" c="dimmed">
              Written by {providerName(answer.provider)}
              {answer.model ? `, ${answer.model}` : ""}. AI answers can be wrong.
              {footnote ? ` ${footnote}` : ""}
            </Text>
          </Group>
        </Box>
      )}
    </Section>
  );
}

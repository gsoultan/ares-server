import { useState, type ReactNode } from "react";
import { Box, Button, Group, Stack, Text, Textarea, TextInput, ThemeIcon, Title } from "@mantine/core";
import { IconCheck } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { errorText } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote, Section } from "../../ui/index.tsx";

const lines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter((x) => x !== "");

// SetupSteps walks a new engagement through the two things that must be on
// file before anything can run: what may be tested, and who gave permission.
export function SetupSteps({
  id,
  scopeSummary,
  onChange,
}: {
  id: string;
  // The saved scope in words, once there is one.
  scopeSummary?: string;
  onChange: () => void;
}) {
  const { tenantId } = useTenant();
  const [inScope, setInScope] = useState("");
  const [exclude, setExclude] = useState("");
  const [document, setDocument] = useState("");
  const [approvedBy, setApprovedBy] = useState("");

  const setScope = useMutation({
    mutationFn: () =>
      control.setScope({ id, tenantId, inScope: lines(inScope), exclude: lines(exclude) }),
    onSuccess: onChange,
  });
  const authorize = useMutation({
    mutationFn: () => control.authorize({ id, tenantId, document, approvedBy }),
    onSuccess: onChange,
  });

  const scopeDone = scopeSummary !== undefined;

  return (
    <Section
      title="Set up this engagement"
      description="Two steps. Nothing can be tested until both are done."
    >
      <Step
        n={1}
        done={scopeDone}
        title="Say what may be tested"
        description="List the websites, servers or networks you have permission to test. Anything not listed is never touched."
      >
        <Textarea
          label="Allowed to test"
          description="One per line: a domain, an IP address or a network range."
          placeholder={"www.example.com\n203.0.113.10"}
          autosize
          minRows={3}
          value={inScope}
          onChange={(ev) => setInScope(ev.currentTarget.value)}
        />
        <Textarea
          label="Never test (optional)"
          description="These are always skipped, even if they fall inside the list above."
          placeholder="payments.example.com"
          autosize
          minRows={2}
          value={exclude}
          onChange={(ev) => setExclude(ev.currentTarget.value)}
        />
        {setScope.isError && (
          <ErrorNote title="Could not save the scope">{errorText(setScope.error)}</ErrorNote>
        )}
        <Group gap="sm">
          <Button
            variant={scopeDone ? "default" : "filled"}
            loading={setScope.isPending}
            disabled={lines(inScope).length === 0}
            onClick={() => setScope.mutate()}
          >
            {scopeDone ? "Update scope" : "Save scope"}
          </Button>
          {scopeDone && (
            <Text size="sm" c="dimmed">
              Saved. {scopeSummary}.
            </Text>
          )}
        </Group>
      </Step>

      <Step
        n={2}
        done={false}
        title="Record permission"
        description="Name the signed document that allows this testing and the person who approved it."
      >
        <Group grow align="flex-start">
          <TextInput
            label="Permission document"
            placeholder="authorization-letter.pdf"
            value={document}
            onChange={(ev) => setDocument(ev.currentTarget.value)}
          />
          <TextInput
            label="Approved by"
            placeholder="Name of the approver"
            value={approvedBy}
            onChange={(ev) => setApprovedBy(ev.currentTarget.value)}
          />
        </Group>
        {authorize.isError && (
          <ErrorNote title="Could not record permission">{errorText(authorize.error)}</ErrorNote>
        )}
        <Group gap="sm">
          <Button
            loading={authorize.isPending}
            disabled={!scopeDone || document.trim() === "" || approvedBy.trim() === ""}
            onClick={() => authorize.mutate()}
          >
            Confirm and allow testing
          </Button>
          {!scopeDone && (
            <Text size="sm" c="dimmed">
              Save the scope first.
            </Text>
          )}
        </Group>
      </Step>
    </Section>
  );
}

function Step({
  n,
  done,
  title,
  description,
  children,
}: {
  n: number;
  done: boolean;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Group
      align="flex-start"
      wrap="nowrap"
      gap="md"
      pt="md"
      style={{ borderTop: "1px solid var(--ares-line)" }}
    >
      <ThemeIcon size={28} radius="xl" variant={done ? "filled" : "light"} color={done ? "teal" : "brand"}>
        {done ? <IconCheck size={16} /> : <Text fw={700} fz={13}>{n}</Text>}
      </ThemeIcon>
      <Box style={{ flex: 1, minWidth: 0 }}>
        <Title order={3}>{title}</Title>
        <Text size="sm" c="dimmed" mt={2} mb="md" maw={640}>
          {description}
        </Text>
        <Stack gap="md" maw={640}>
          {children}
        </Stack>
      </Box>
    </Group>
  );
}

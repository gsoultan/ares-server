import { useEffect, useState } from "react";
import { ActionIcon, Button, Group, Stack, Text, TextInput, Title } from "@mantine/core";
import { IconPlus, IconTrash } from "@tabler/icons-react";
import type { JsonObject } from "@bufbuild/protobuf";

interface IdentityRow {
  name: string;
  headerKey: string;
  headerValue: string;
}
interface ObjectRow {
  url: string;
  owner: string;
}

// A structured builder for the accesscheck (IDOR) module: named identities with
// one auth header each, and objects that legitimately belong to one identity.
// It emits the module's params object as the operator edits, or null while the
// form is incomplete.
export function AccessCheckForm({ onParams }: { onParams: (p: JsonObject | null) => void }) {
  const [identities, setIdentities] = useState<IdentityRow[]>([
    { name: "", headerKey: "Authorization", headerValue: "" },
    { name: "", headerKey: "Authorization", headerValue: "" },
  ]);
  const [objects, setObjects] = useState<ObjectRow[]>([{ url: "", owner: "" }]);

  useEffect(() => {
    const ids = identities.filter((i) => i.name.trim() !== "");
    const objs = objects.filter((o) => o.url.trim() !== "" && o.owner.trim() !== "");
    const names = new Set(ids.map((i) => i.name.trim()));
    const valid =
      ids.length >= 2 && objs.length >= 1 && objs.every((o) => names.has(o.owner.trim()));
    if (!valid) {
      onParams(null);
      return;
    }
    onParams({
      identities: ids.map((i) => ({
        name: i.name.trim(),
        headers: i.headerKey.trim() ? { [i.headerKey.trim()]: i.headerValue } : {},
      })),
      objects: objs.map((o) => ({ url: o.url.trim(), owner: o.owner.trim() })),
    });
  }, [identities, objects, onParams]);

  const setId = (i: number, patch: Partial<IdentityRow>) =>
    setIdentities((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  const setObj = (i: number, patch: Partial<ObjectRow>) =>
    setObjects((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));

  return (
    <Stack gap="lg">
      <div>
        <Title order={3}>Test accounts</Title>
        <Text size="sm" c="dimmed" mb="sm">
          At least two accounts. For each, give the sign-in header the website expects.
        </Text>
        <Group gap="xs" wrap="nowrap" px={2} mb={2}>
          <Text size="xs" c="dimmed" fw={600} w={110}>
            Account name
          </Text>
          <Text size="xs" c="dimmed" fw={600} w={150}>
            Header
          </Text>
          <Text size="xs" c="dimmed" fw={600} style={{ flex: 1 }}>
            Value
          </Text>
          <span style={{ width: 36 }} />
        </Group>
        <Stack gap="xs">
          {identities.map((id, i) => (
            <Group key={i} gap="xs" wrap="nowrap" align="flex-end">
              <TextInput
                aria-label={`Account ${i + 1} name`}
                placeholder="alice"
                w={110}
                value={id.name}
                onChange={(e) => setId(i, { name: e.currentTarget.value })}
              />
              <TextInput
                aria-label={`Account ${i + 1} header`}
                placeholder="Authorization"
                w={150}
                value={id.headerKey}
                onChange={(e) => setId(i, { headerKey: e.currentTarget.value })}
              />
              <TextInput
                aria-label={`Account ${i + 1} header value`}
                placeholder="Bearer <token>"
                style={{ flex: 1 }}
                value={id.headerValue}
                onChange={(e) => setId(i, { headerValue: e.currentTarget.value })}
              />
              <ActionIcon
                variant="subtle"
                color="gray"
                size="lg"
                disabled={identities.length <= 2}
                onClick={() => setIdentities((r) => r.filter((_, idx) => idx !== i))}
                aria-label={`Remove account ${i + 1}`}
              >
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
        </Stack>
        <Button
          size="compact-sm"
          ml={-8}
          variant="subtle"
          leftSection={<IconPlus size={14} />}
          mt="xs"
          onClick={() =>
            setIdentities((r) => [...r, { name: "", headerKey: "Authorization", headerValue: "" }])
          }
        >
          Add account
        </Button>
      </div>

      <div>
        <Title order={3}>Private pages</Title>
        <Text size="sm" c="dimmed" mb="sm">
          A page only one account should be able to open, and the account that owns it. Each
          address must be inside the scope.
        </Text>
        <Group gap="xs" wrap="nowrap" px={2} mb={2}>
          <Text size="xs" c="dimmed" fw={600} style={{ flex: 1 }}>
            Page address
          </Text>
          <Text size="xs" c="dimmed" fw={600} w={110}>
            Owner
          </Text>
          <span style={{ width: 36 }} />
        </Group>
        <Stack gap="xs">
          {objects.map((o, i) => (
            <Group key={i} gap="xs" wrap="nowrap" align="flex-end">
              <TextInput
                aria-label={`Page ${i + 1} address`}
                placeholder="https://app.example.com/invoice/1041"
                style={{ flex: 1 }}
                value={o.url}
                onChange={(e) => setObj(i, { url: e.currentTarget.value })}
              />
              <TextInput
                aria-label={`Page ${i + 1} owner`}
                placeholder="alice"
                w={110}
                value={o.owner}
                onChange={(e) => setObj(i, { owner: e.currentTarget.value })}
              />
              <ActionIcon
                variant="subtle"
                color="gray"
                size="lg"
                disabled={objects.length <= 1}
                onClick={() => setObjects((r) => r.filter((_, idx) => idx !== i))}
                aria-label={`Remove page ${i + 1}`}
              >
                <IconTrash size={16} />
              </ActionIcon>
            </Group>
          ))}
        </Stack>
        <Button
          size="compact-sm"
          ml={-8}
          variant="subtle"
          leftSection={<IconPlus size={14} />}
          mt="xs"
          onClick={() => setObjects((r) => [...r, { url: "", owner: "" }])}
        >
          Add page
        </Button>
      </div>
    </Stack>
  );
}

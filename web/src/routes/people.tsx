import { useState, type FormEvent } from "react";
import {
  Box,
  Button,
  CopyButton,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
} from "@mantine/core";
import { IconPlus } from "@tabler/icons-react";
import { Code, ConnectError } from "@connectrpc/connect";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { control } from "../client.ts";
import { errorText, plural } from "../lib/labels.ts";
import { roleName, useSession } from "../session.tsx";
import { useTenant } from "../tenant.tsx";
import { EmptyState, ErrorNote, InfoNote, LoadingState, PageHeader, Section, ToneBadge } from "../ui/index.tsx";

const MIN_PASSWORD = 12;

// Roles from most to least power. Nobody can hand out more than they hold.
const RANK: Record<string, number> = { superadmin: 3, owner: 2, admin: 1, member: 0 };

const ROLE_HELP: Record<string, string> = {
  superadmin: "Manages every workspace and every account.",
  owner: "Manages this workspace and everyone in it.",
  admin: "Adds people and changes roles, up to administrator.",
  member: "Works on engagements. Cannot manage people.",
};

export function canManagePeople(role: string | undefined): boolean {
  return (RANK[role ?? ""] ?? 0) >= 1;
}

// The roles this person may give to someone else.
function grantable(viewerRole: string): string[] {
  const top = RANK[viewerRole] ?? 0;
  return ["member", "admin", "owner", "superadmin"].filter((r) => (RANK[r] ?? 0) <= top);
}

// A password to hand over in person: four chunks that are easy to read aloud.
function suggestPassword(): string {
  const letters = "abcdefghjkmnpqrstuvwxyz23456789";
  const pick = new Uint32Array(16);
  crypto.getRandomValues(pick);
  const chars = Array.from(pick, (n) => letters[n % letters.length] ?? "x");
  return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join("")).join("-");
}

function refusal(err: unknown): string {
  if (err instanceof ConnectError) {
    if (err.code === Code.AlreadyExists) return "Someone already has an account with that email.";
    if (err.code === Code.PermissionDenied) return "Your role does not allow this change.";
    if (err.code === Code.NotFound) return "That account no longer exists. Reload the page.";
  }
  return errorText(err);
}

// PeoplePage lists the accounts of the current workspace and lets a manager
// add people and change what they may do. The server enforces every rule; the
// page only avoids offering what would be refused.
export function PeoplePage() {
  const { tenantId } = useTenant();
  const { user } = useSession();
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const manager = canManagePeople(user?.role);

  const people = useQuery({
    queryKey: ["people", tenantId],
    queryFn: () => control.listUsers({ tenantId }),
    enabled: manager,
  });

  const setRole = useMutation({
    mutationFn: (v: { userId: string; role: string }) => control.setUserRole(v),
    onSettled: () => qc.invalidateQueries({ queryKey: ["people", tenantId] }),
  });

  const setOff = useMutation({
    mutationFn: (v: { userId: string; disabled: boolean }) => control.setUserDisabled(v),
    onSettled: () => qc.invalidateQueries({ queryKey: ["people", tenantId] }),
  });

  const header = (
    <PageHeader
      title="People"
      description="Who can sign in to this workspace, and what each person may do."
      actions={
        manager ? (
          <Button leftSection={<IconPlus size={16} />} onClick={() => setAdding(true)}>
            Add a person
          </Button>
        ) : undefined
      }
    />
  );

  if (!manager || !user) {
    return (
      <Stack gap="lg">
        {header}
        <InfoNote title="Only managers can see this page">
          Ask an owner or administrator of your workspace if someone needs an account or a different
          role.
        </InfoNote>
      </Stack>
    );
  }

  const list = [...(people.data?.users ?? [])].sort(
    (a, b) => (RANK[b.role] ?? 0) - (RANK[a.role] ?? 0) || (a.name || a.email).localeCompare(b.name || b.email),
  );
  const roles = grantable(user.role);
  const mine = RANK[user.role] ?? 0;

  return (
    <Stack gap="lg">
      {header}
      {setRole.isError && <ErrorNote title="The role was not changed">{refusal(setRole.error)}</ErrorNote>}
      {setOff.isError && <ErrorNote title="The account was not changed">{refusal(setOff.error)}</ErrorNote>}
      <Section
        title="Accounts"
        description={people.data ? `${plural(list.length, "person", "people")} in this workspace.` : undefined}
        flush
      >
        {people.isLoading ? (
          <LoadingState label="Loading people…" />
        ) : people.isError ? (
          <Box p="lg" pt={0}>
            <ErrorNote title="Could not load people">{refusal(people.error)}</ErrorNote>
          </Box>
        ) : list.length === 0 ? (
          <EmptyState
            title="Nobody here yet"
            description="Add the first person who should work in this workspace."
          />
        ) : (
          <Table.ScrollContainer minWidth={720}>
            <Table className="ares-stack" verticalSpacing="sm" horizontalSpacing="lg">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Person</Table.Th>
                  <Table.Th w={240}>Role</Table.Th>
                  <Table.Th w={230}>Sign-in</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {list.map((p) => {
                  const self = p.id === user.id;
                  // Nobody changes their own role, or an account above their own.
                  const locked = self || (RANK[p.role] ?? 0) > mine || !roles.includes(p.role);
                  // The super administrator can turn off anyone else. Other
                  // managers only accounts below their own role.
                  const canSwitch = !self && (user.role === "superadmin" || (RANK[p.role] ?? 0) < mine);
                  return (
                    <Table.Tr key={p.id}>
                      <Table.Td data-primary>
                        <Group gap="xs">
                          <Text fw={600} c={p.disabled ? "dimmed" : undefined}>
                            {p.name || p.email}
                          </Text>
                          {self && <ToneBadge tone="neutral">You</ToneBadge>}
                        </Group>
                        <Text size="sm" c="dimmed">
                          {p.email}
                        </Text>
                      </Table.Td>
                      <Table.Td data-label="Role">
                        {locked ? (
                          <Text>{roleName(p.role)}</Text>
                        ) : (
                          <Select
                            aria-label={`Role of ${p.name || p.email}`}
                            data={roles.map((r) => ({ value: r, label: roleName(r) }))}
                            value={p.role}
                            allowDeselect={false}
                            disabled={setRole.isPending}
                            onChange={(v) => v && v !== p.role && setRole.mutate({ userId: p.id, role: v })}
                          />
                        )}
                      </Table.Td>
                      <Table.Td data-label="Sign-in">
                        <Group gap="sm" justify="space-between" wrap="nowrap">
                          <ToneBadge tone={p.disabled ? "neutral" : "good"}>
                            {p.disabled ? "Turned off" : "Can sign in"}
                          </ToneBadge>
                          {canSwitch && (
                            <Button
                              variant="default"
                              size="compact-sm"
                              loading={setOff.isPending && setOff.variables?.userId === p.id}
                              aria-label={`${p.disabled ? "Turn on" : "Turn off"} the account of ${p.name || p.email}`}
                              onClick={() => setOff.mutate({ userId: p.id, disabled: !p.disabled })}
                            >
                              {p.disabled ? "Turn on" : "Turn off"}
                            </Button>
                          )}
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Section>

      <Section
        title="What each role can do"
        description="Turning an account off stops that person signing in. Nothing they did is deleted, and you can turn it back on."
      >
        <Stack gap="xs">
          {["owner", "admin", "member"].map((r) => (
            <Group key={r} gap="sm" wrap="nowrap" align="baseline">
              <Text fw={600} w={130} style={{ flexShrink: 0 }}>
                {roleName(r)}
              </Text>
              <Text c="dimmed">{ROLE_HELP[r]}</Text>
            </Group>
          ))}
        </Stack>
      </Section>

      <AddPerson opened={adding} onClose={() => setAdding(false)} roles={roles} />
    </Stack>
  );
}

function AddPerson({ opened, onClose, roles }: { opened: boolean; onClose: () => void; roles: string[] }) {
  const { tenantId } = useTenant();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("member");
  const [password, setPassword] = useState("");

  const create = useMutation({
    mutationFn: () =>
      control.createUser({ tenantId, name: name.trim(), email: email.trim(), password, role }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["people", tenantId] }),
  });

  const close = () => {
    onClose();
    create.reset();
    setName("");
    setEmail("");
    setRole("member");
    setPassword("");
  };

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  const short = password.length < MIN_PASSWORD;
  const ready = name.trim() !== "" && emailOk && !short;

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (ready) create.mutate();
  };

  // Once the account exists, the password is shown one more time so it can be
  // passed on. Ares sends no email.
  if (create.data) {
    return (
      <Modal opened={opened} onClose={close} title="Account created" centered>
        <Stack gap="md">
          <Text>
            {create.data.name || create.data.email} can now sign in with {create.data.email} and the
            password below. Ares does not send email, so pass it on yourself.
          </Text>
          <TextInput label="Password" value={password} readOnly />
          <Group justify="flex-end">
            <CopyButton value={password}>
              {({ copied, copy }) => (
                <Button variant="default" onClick={copy}>
                  {copied ? "Copied" : "Copy the password"}
                </Button>
              )}
            </CopyButton>
            <Button onClick={close}>Done</Button>
          </Group>
        </Stack>
      </Modal>
    );
  }

  return (
    <Modal opened={opened} onClose={close} title="Add a person" centered>
      <form onSubmit={submit}>
        <Stack gap="md">
          <TextInput label="Full name" value={name} onChange={(ev) => setName(ev.currentTarget.value)} data-autofocus />
          <TextInput
            label="Email"
            description="They sign in with this."
            type="email"
            value={email}
            onChange={(ev) => setEmail(ev.currentTarget.value)}
            error={email !== "" && !emailOk ? "This does not look like an email address." : undefined}
          />
          <Select
            label="Role"
            description={ROLE_HELP[role]}
            data={roles.map((r) => ({ value: r, label: roleName(r) }))}
            value={role}
            allowDeselect={false}
            onChange={(v) => v && setRole(v)}
          />
          <Box>
            <PasswordInput
              label="First password"
              description={`At least ${MIN_PASSWORD} characters. You pass it on to them yourself.`}
              autoComplete="new-password"
              value={password}
              onChange={(ev) => setPassword(ev.currentTarget.value)}
              error={
                password !== "" && short ? `${MIN_PASSWORD - password.length} more needed.` : undefined
              }
            />
            <Button variant="subtle" size="compact-xs" px={0} mt={2} onClick={() => setPassword(suggestPassword())}>
              Suggest a password
            </Button>
          </Box>
          {create.isError && <ErrorNote title="The account was not created">{refusal(create.error)}</ErrorNote>}
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending} disabled={!ready}>
              Add this person
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

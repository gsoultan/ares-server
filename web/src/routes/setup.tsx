import { useState, type ReactNode } from "react";
import {
  Box,
  Button,
  Card,
  Checkbox,
  Code,
  CopyButton,
  Group,
  PasswordInput,
  Radio,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { IconCheck, IconCopy, IconDownload } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { control } from "../client.ts";
import type { DriverInfo } from "../gen/ares/v1/ares_pb.ts";
import { errorText } from "../lib/labels.ts";
import { useSession } from "../session.tsx";
import { ErrorNote, Field, InfoNote } from "../ui/index.tsx";
import { Frame } from "./signin.tsx";

const STEPS = ["Database", "Encryption key", "Administrator", "Workspace", "Check and finish"] as const;
const MIN_PASSWORD = 12;

// The server's own names for a database, in plainer words.
const DRIVER_TEXT: Record<string, { label: string; detail: string }> = {
  file: {
    label: "Built-in database",
    detail: "Kept in one file on this server. Nothing else to install.",
  },
  postgres: {
    label: "PostgreSQL",
    detail: "A separate database server, for larger teams.",
  },
};

// The server names each refusal with a short code. Say it the way a person would.
const REASONS: Record<string, string> = {
  already_initialized: "Ares is already set up. Reload the page to sign in.",
  driver_unavailable: "That database is not available yet. Choose the built-in database.",
  db_not_writable: "Ares is not allowed to write in the folder for its database file.",
  invalid_key: "That key is not valid. It must be a 32-byte key written in base64.",
  weak_password: `The password must be at least ${MIN_PASSWORD} characters.`,
  tenant_name_required: "Enter a name for the first workspace.",
  missing_field: "The administrator needs a name and an email address.",
};

function plainReason(code: string, raw: string): string {
  const known = REASONS[code];
  if (known) return known;
  const s = raw.replace(/^setup:\s*/, "");
  return s ? s.charAt(0).toUpperCase() + s.slice(1) + "." : "The server gave no reason.";
}

// A key someone brings must be 32 bytes, written in base64.
function validKey(value: string): boolean {
  try {
    return atob(value.trim()).length === 32;
  } catch {
    return false;
  }
}

function validEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

// SetupPage is the first thing a new installation shows. It collects five
// answers and saves them in one go at the end, so stopping halfway leaves
// nothing behind.
export function SetupPage({
  drivers,
  dbPath,
  keyFilePath,
}: {
  drivers: DriverInfo[];
  // Where the running server keeps its database file and its key file.
  dbPath: string;
  keyFilePath: string;
}) {
  const qc = useQueryClient();
  const { signIn } = useSession();
  const [step, setStep] = useState(0);

  const [driver, setDriver] = useState("file");
  const path = dbPath || "ares.db";
  const [keyMode, setKeyMode] = useState<"generate" | "own">("generate");
  const [ownKey, setOwnKey] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [workspace, setWorkspace] = useState("");
  const [keySaved, setKeySaved] = useState(false);

  const testDb = useMutation({
    mutationFn: () => control.testDatabaseConnection({ driver, path: path.trim() }),
  });

  const commit = useMutation({
    mutationFn: () =>
      control.commitSetup({
        driver,
        path: path.trim(),
        generateKey: keyMode === "generate",
        key: keyMode === "own" ? ownKey.trim() : "",
        admin: { name: name.trim(), email: email.trim(), password },
        tenantName: workspace.trim(),
      }),
  });

  // After setup the new administrator goes straight in, without typing the
  // password a second time.
  const open = useMutation({
    mutationFn: () => control.login({ email: email.trim(), password }),
    onSettled: (res) => {
      if (res?.ok && res.user) signIn(res.token, res.user);
      // Either way setup is over: the app shows itself, or the sign-in screen.
      void qc.invalidateQueries({ queryKey: ["setup-status"] });
    },
  });

  const done = commit.data?.ok ? commit.data : undefined;

  if (done) {
    const key = done.generatedKey;
    return (
      <Frame width={640}>
        <Card>
          <Stack gap="md">
            <Group gap="xs" c="teal.8">
              <IconCheck size={20} />
              <Title order={1} fz={24} c="inherit">
                Ares is set up
              </Title>
            </Group>
            {key ? (
              <>
                <Text>
                  One last thing. This is your encryption key. It locks every password and API key
                  saved in Ares, and it is shown only this once.
                </Text>
                <Code block fz="sm" style={{ wordBreak: "break-all", whiteSpace: "pre-wrap" }}>
                  {key}
                </Code>
                <Group gap="sm">
                  <CopyButton value={key}>
                    {({ copied, copy }) => (
                      <Button variant="default" leftSection={<IconCopy size={16} />} onClick={copy}>
                        {copied ? "Copied" : "Copy the key"}
                      </Button>
                    )}
                  </CopyButton>
                  <Button
                    variant="default"
                    leftSection={<IconDownload size={16} />}
                    component="a"
                    href={`data:text/plain;charset=utf-8,${encodeURIComponent(key + "\n")}`}
                    download="ares-encryption-key.txt"
                  >
                    Download as a file
                  </Button>
                </Group>
                <InfoNote title="Keep it somewhere safe, away from this server">
                  A password manager is a good place. If this server is ever rebuilt and the key is
                  lost, the saved passwords and API keys cannot be read again.
                </InfoNote>
                <Checkbox
                  label="I have saved the key somewhere safe."
                  checked={keySaved}
                  onChange={(ev) => setKeySaved(ev.currentTarget.checked)}
                />
              </>
            ) : (
              <Text>
                Ares is using the encryption key you supplied. Keep your copy safe: without it, the
                saved passwords and API keys cannot be read again.
              </Text>
            )}
            <Group>
              <Button loading={open.isPending} disabled={!!key && !keySaved} onClick={() => open.mutate()}>
                Open Ares
              </Button>
            </Group>
          </Stack>
        </Card>
      </Frame>
    );
  }

  const chosen = drivers.find((d) => d.name === driver);
  const passwordShort = password.length < MIN_PASSWORD;
  const mismatch = again !== "" && again !== password;

  const ready = [
    !!chosen?.available && path.trim() !== "",
    keyMode === "generate" || validKey(ownKey),
    name.trim() !== "" && validEmail(email) && !passwordShort && again === password,
    workspace.trim() !== "",
    true,
  ];

  const last = step === STEPS.length - 1;
  const refused = commit.data && !commit.data.ok ? commit.data.error : "";

  let body: ReactNode;
  if (step === 0) {
    body = (
      <Stack gap="md">
        <Radio.Group
          label="Where should Ares keep its data?"
          value={driver}
          onChange={(v) => {
            setDriver(v);
            testDb.reset();
          }}
        >
          <Stack gap="xs" mt="xs">
            {drivers.map((d) => {
              const text = DRIVER_TEXT[d.name] ?? { label: d.label, detail: "" };
              return (
                <Radio.Card
                  key={d.name}
                  value={d.name}
                  disabled={!d.available}
                  p="md"
                  radius="md"
                  style={{ opacity: d.available ? 1 : 0.6 }}
                >
                  <Group wrap="nowrap" align="flex-start" gap="sm">
                    <Radio.Indicator mt={2} />
                    <Box>
                      <Text fw={600}>
                        {text.label}
                        {!d.available && (
                          <Text span c="dimmed" fw={400}>
                            {" "}
                            · Coming later
                          </Text>
                        )}
                      </Text>
                      <Text size="sm" c="dimmed">
                        {text.detail}
                      </Text>
                    </Box>
                  </Group>
                </Radio.Card>
              );
            })}
          </Stack>
        </Radio.Group>
        <Field label="Database file on the server">
          <Code>{path}</Code>
        </Field>
        <Group gap="md">
          <Button
            variant="default"
            loading={testDb.isPending}
            onClick={() => testDb.mutate()}
          >
            Check that Ares can write there
          </Button>
          {testDb.data?.ok && (
            <Group gap={6} c="teal.8">
              <IconCheck size={16} />
              <Text size="sm" fw={600}>
                Ares can write here.
              </Text>
            </Group>
          )}
        </Group>
        {testDb.data && !testDb.data.ok && (
          <ErrorNote title="This location will not work">
            {plainReason(testDb.data.errorCode, testDb.data.error)} Give the account that runs Ares
            permission to write there, then check again.
          </ErrorNote>
        )}
        {testDb.isError && <ErrorNote title="The check could not run">{errorText(testDb.error)}</ErrorNote>}
      </Stack>
    );
  } else if (step === 1) {
    body = (
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Ares locks every saved password and API key with one encryption key, so they are never
          stored in plain text.
        </Text>
        <Radio.Group value={keyMode} onChange={(v) => setKeyMode(v === "own" ? "own" : "generate")}>
          <Stack gap="xs">
            <Radio
              value="generate"
              label="Create a key for me (recommended)"
              description="Ares makes a strong key and shows it to you once at the end, so you can keep a copy."
            />
            <Radio
              value="own"
              label="I have my own key"
              description="For teams that already manage their own keys."
            />
          </Stack>
        </Radio.Group>
        {keyFilePath && (
          <Field label="Where the server keeps the key">
            <Code>{keyFilePath}</Code>
          </Field>
        )}
        {keyMode === "own" && (
          <PasswordInput
            label="Your key"
            description="A 32-byte key written in base64."
            value={ownKey}
            onChange={(ev) => setOwnKey(ev.currentTarget.value)}
            error={ownKey !== "" && !validKey(ownKey) ? "This is not a 32-byte base64 key." : undefined}
            autoComplete="off"
          />
        )}
      </Stack>
    );
  } else if (step === 2) {
    body = (
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          The first account. It can manage everything in Ares, including every workspace and every
          other account.
        </Text>
        <TextInput
          label="Full name"
          autoComplete="name"
          value={name}
          onChange={(ev) => setName(ev.currentTarget.value)}
        />
        <TextInput
          label="Email"
          description="Used to sign in."
          type="email"
          autoComplete="username"
          value={email}
          onChange={(ev) => setEmail(ev.currentTarget.value)}
          error={email !== "" && !validEmail(email) ? "This does not look like an email address." : undefined}
        />
        <PasswordInput
          label="Password"
          description={`At least ${MIN_PASSWORD} characters. A few random words work well.`}
          autoComplete="new-password"
          value={password}
          onChange={(ev) => setPassword(ev.currentTarget.value)}
          error={
            password !== "" && passwordShort
              ? `${MIN_PASSWORD - password.length} more ${MIN_PASSWORD - password.length === 1 ? "character" : "characters"} needed.`
              : undefined
          }
        />
        <PasswordInput
          label="Password again"
          autoComplete="new-password"
          value={again}
          onChange={(ev) => setAgain(ev.currentTarget.value)}
          error={mismatch ? "The two passwords are not the same." : undefined}
        />
      </Stack>
    );
  } else if (step === 3) {
    body = (
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          A workspace holds one organization's engagements, findings and reports, kept apart from
          every other workspace. You can add more later.
        </Text>
        <TextInput
          label="Name of the first workspace"
          description="Usually your own company or team."
          placeholder="For example, Acme Security"
          value={workspace}
          onChange={(ev) => setWorkspace(ev.currentTarget.value)}
        />
      </Stack>
    );
  } else {
    body = (
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Nothing has been saved yet. Check the answers, then finish.
        </Text>
        <Stack gap="sm">
          <Review label="Database" onEdit={() => setStep(0)}>
            {(DRIVER_TEXT[driver]?.label ?? driver) + ", in " + path.trim()}
          </Review>
          <Review label="Encryption key" onEdit={() => setStep(1)}>
            {keyMode === "generate" ? "Ares creates one and shows it once" : "Your own key"}
          </Review>
          <Review label="Administrator" onEdit={() => setStep(2)}>
            {name.trim()}, {email.trim()}
          </Review>
          <Review label="First workspace" onEdit={() => setStep(3)}>
            {workspace.trim()}
          </Review>
        </Stack>
        {refused && (
          <ErrorNote title="Setup did not finish">
            {plainReason(commit.data?.errorCode ?? "", refused)} Nothing was saved.
          </ErrorNote>
        )}
        {commit.isError && (
          <ErrorNote title="Setup did not finish">{errorText(commit.error)} Nothing was saved.</ErrorNote>
        )}
      </Stack>
    );
  }

  return (
    <Frame width={640}>
      <Box>
        <Title order={1}>Set up Ares</Title>
        <Text c="dimmed" mt={4}>
          Five short steps. Everything is saved together at the end.
        </Text>
      </Box>
      <Card>
        <Stack gap="lg">
          <Box>
            <Group gap={6} wrap="nowrap" aria-hidden>
              {STEPS.map((s, i) => (
                <Box
                  key={s}
                  h={4}
                  style={{
                    flex: 1,
                    borderRadius: 2,
                    background: i <= step ? "var(--mantine-color-brand-6)" : "var(--ares-line)",
                  }}
                />
              ))}
            </Group>
            <Text size="sm" c="dimmed" mt="sm">
              Step {step + 1} of {STEPS.length}
            </Text>
            <Title order={2}>{STEPS[step]}</Title>
          </Box>
          <form
            onSubmit={(ev) => {
              ev.preventDefault();
              if (!ready[step]) return;
              if (last) commit.mutate();
              else setStep(step + 1);
            }}
          >
            <Stack gap="lg">
              {body}
              <Group justify="space-between">
                <Button
                  variant="default"
                  onClick={() => setStep(step - 1)}
                  style={{ visibility: step === 0 ? "hidden" : undefined }}
                >
                  Back
                </Button>
                <Button type="submit" disabled={!ready[step]} loading={commit.isPending}>
                  {last ? "Finish setup" : "Continue"}
                </Button>
              </Group>
            </Stack>
          </form>
        </Stack>
      </Card>
    </Frame>
  );
}

function Review({ label, onEdit, children }: { label: string; onEdit: () => void; children: ReactNode }) {
  return (
    <Group justify="space-between" wrap="nowrap" align="flex-start">
      <Field label={label}>{children}</Field>
      <Button variant="subtle" size="compact-sm" onClick={onEdit}>
        Change
      </Button>
    </Group>
  );
}

import { useState, type FormEvent, type ReactNode } from "react";
import { Box, Button, Card, Group, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useMutation } from "@tanstack/react-query";
import { control } from "../client.ts";
import { errorText } from "../lib/labels.ts";
import { useSession } from "../session.tsx";
import { ErrorNote } from "../ui/index.tsx";

// Frame is the quiet, centred page used before anyone is signed in: the
// first-run setup and the sign-in screen.
export function Frame({ width = 420, children }: { width?: number; children: ReactNode }) {
  return (
    <Box bg="var(--ares-canvas)" mih="100vh" px="md" py={{ base: "xl", sm: 64 }}>
      <Stack maw={width} mx="auto" gap="lg">
        <Group gap="xs" wrap="nowrap">
          <img src="/icon.svg" alt="" width={28} height={28} />
          <Text fw={700} fz={17}>
            Ares
          </Text>
        </Group>
        {children}
        <Text size="xs" c="dimmed">
          © 2026 Gembit Soultan Shirazi. All rights reserved.
        </Text>
      </Stack>
    </Box>
  );
}

export function SignInPage() {
  const { signIn } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const login = useMutation({
    mutationFn: () => control.login({ email: email.trim(), password }),
    onSuccess: (res) => {
      if (res.ok && res.user) signIn(res.token, res.user);
    },
  });

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    if (email.trim() && password) login.mutate();
  };

  const refused = login.data && !login.data.ok;

  return (
    <Frame>
      <Card>
        <form onSubmit={submit}>
          <Stack gap="md">
            <Box>
              <Title order={1} fz={24}>
                Sign in
              </Title>
              <Text size="sm" c="dimmed" mt={2}>
                Use the email and password of your Ares account.
              </Text>
            </Box>
            <TextInput
              label="Email"
              type="email"
              autoComplete="username"
              autoFocus
              value={email}
              onChange={(ev) => setEmail(ev.currentTarget.value)}
            />
            <PasswordInput
              label="Password"
              autoComplete="current-password"
              value={password}
              onChange={(ev) => setPassword(ev.currentTarget.value)}
            />
            {refused && (
              <ErrorNote title="That email or password is not right">
                Check both and try again. If you forgot your password, ask your Ares administrator.
              </ErrorNote>
            )}
            {login.isError && <ErrorNote title="Could not sign in">{errorText(login.error)}</ErrorNote>}
            <Button type="submit" loading={login.isPending} disabled={!email.trim() || !password}>
              Sign in
            </Button>
          </Stack>
        </form>
      </Card>
    </Frame>
  );
}

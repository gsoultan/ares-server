import { useEffect, type ReactNode } from "react";
import {
  AppShell,
  Avatar,
  Box,
  Burger,
  Group,
  Menu,
  NavLink,
  Stack,
  Text,
  UnstyledButton,
  useComputedColorScheme,
  useMantineColorScheme,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconAlertTriangle,
  IconBriefcase,
  IconDotsVertical,
  IconFileSearch,
  IconFileText,
  IconHistory,
  IconHome,
  IconInfoCircle,
  IconLogout,
  IconMoon,
  IconSettings,
  IconShield,
  IconSun,
  IconUsers,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, useMatch, useNavigate, useRouterState } from "@tanstack/react-router";
import { control } from "../client.ts";
import { WorkspaceSwitcher } from "../components/WorkspaceSwitcher.tsx";
import { defaultView, ENGAGEMENT_VIEWS, VIEW_LABELS } from "../lib/views.ts";
import { errorText } from "../lib/labels.ts";
import { roleName, useSession } from "../session.tsx";
import { useTenant } from "../tenant.tsx";
import { ErrorNote, LoadingState } from "../ui/index.tsx";
import { SetupPage } from "./setup.tsx";
import { Frame, SignInPage } from "./signin.tsx";

function Brand() {
  return (
    <Link to="/" style={{ textDecoration: "none", color: "inherit" }} aria-label="Ares home">
      <Group gap="xs" wrap="nowrap">
        <img src="/icon.svg" alt="" width={28} height={28} />
        <Text fw={700} fz={17}>
          Ares
        </Text>
      </Group>
    </Link>
  );
}

// The roles that may manage accounts.
const RANK_MANAGER = ["superadmin", "owner", "admin"] as const;

const plain = { textDecoration: "none", color: "inherit", display: "block" } as const;

// One line of the menu. The link is a plain router link around the styled row,
// so the address bar, middle-click and keyboard all behave as a link should.
function Item({ label, icon, active, sub }: { label: string; icon?: ReactNode; active: boolean; sub?: boolean }) {
  return (
    <NavLink
      component="span"
      label={label}
      leftSection={icon}
      active={active}
      pl={sub ? 38 : undefined}
      aria-current={active ? "page" : undefined}
    />
  );
}

// A quiet heading above a group of menu items.
function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <Text
      size="xs"
      fw={650}
      c="dimmed"
      px="sm"
      mb={4}
      style={{ letterSpacing: "0.03em", textTransform: "uppercase" }}
    >
      {children}
    </Text>
  );
}

// Up to two initials for the profile avatar, from a name or email.
function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (parts[0]?.slice(0, 2) ?? "?").toUpperCase();
}

function Shell() {
  const [opened, { toggle, close }] = useDisclosure(false);
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme("light");
  const next = scheme === "dark" ? "light" : "dark";
  const { tenantId } = useTenant();
  const { user, signOut } = useSession();
  const navigate = useNavigate();
  const path = useRouterState({ select: (s) => s.location.pathname });

  // When an engagement is open, its sections join the menu under its name.
  const match = useMatch({ from: "/engagements/$id", shouldThrow: false });
  const engagementId = match?.params.id;
  const engagement = useQuery({
    queryKey: ["engagement", tenantId, engagementId],
    queryFn: () => control.getEngagement({ id: engagementId!, tenantId }),
    enabled: !!engagementId,
  });
  const view = match?.search.view ?? defaultView(engagement.data?.status);
  // Workspace pages opened from inside an engagement stay on that engagement.
  const carry = engagementId ? { engagement: engagementId } : {};

  return (
    <AppShell
      header={{ height: { base: 56, sm: 0 } }}
      navbar={{ width: 256, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding={0}
    >
      <AppShell.Header
        hiddenFrom="sm"
        bg="var(--ares-surface)"
        style={{ borderColor: "var(--ares-line)" }}
      >
        <Group h="100%" px="md" gap="sm" wrap="nowrap">
          <Burger opened={opened} onClick={toggle} size="sm" aria-label="Menu" />
          <Brand />
        </Group>
      </AppShell.Header>

      <AppShell.Navbar bg="var(--ares-surface)" p="md" style={{ borderColor: "var(--ares-line)", overflowY: "auto" }}>
        <Stack gap="lg" h="100%">
          <Box visibleFrom="sm" px={4}>
            <Brand />
          </Box>

          {/* Only the super administrator works across workspaces. */}
          {(!user?.tenantId || user.role === "superadmin") && (
            <Box>
              <Text size="xs" fw={600} c="dimmed" px="sm" mb={4}>
                Client workspace
              </Text>
              <WorkspaceSwitcher />
            </Box>
          )}

          {/* Your work: where testing is set up and run. */}
          <Stack component="nav" aria-label="Your work" gap={2}>
            <SectionLabel>Your work</SectionLabel>
            <Link to="/" onClick={close} style={plain}>
              <Item label="Overview" icon={<IconHome size={18} />} active={path === "/"} />
            </Link>
            <Link to="/engagements" onClick={close} style={plain}>
              <Item
                label="Engagements"
                icon={<IconBriefcase size={18} />}
                active={path === "/engagements"}
              />
            </Link>

            {engagementId && (
              <Box mb="xs">
                <Text size="xs" fw={600} c="dimmed" pl={38} pr="sm" mt="xs" mb={4} truncate>
                  {engagement.data?.name ?? "Engagement"}
                </Text>
                {ENGAGEMENT_VIEWS.map((v) => (
                  <Link
                    key={v}
                    to="/engagements/$id"
                    params={{ id: engagementId }}
                    search={{ view: v }}
                    onClick={close}
                    style={plain}
                  >
                    <Item label={VIEW_LABELS[v]} active={view === v} sub />
                  </Link>
                ))}
              </Box>
            )}
          </Stack>

          {/* Security results: what the testing turned up, across every engagement. */}
          <Stack component="nav" aria-label="Security results" gap={2}>
            <SectionLabel>Security results</SectionLabel>
            <Link to="/findings" search={carry} onClick={close} style={plain}>
              <Item
                label="Findings"
                icon={<IconAlertTriangle size={18} />}
                active={path === "/findings"}
              />
            </Link>
            <Link to="/defenses" search={carry} onClick={close} style={plain}>
              <Item label="Defenses" icon={<IconShield size={18} />} active={path === "/defenses"} />
            </Link>
            <Link to="/forensics" search={carry} onClick={close} style={plain}>
              <Item
                label="Forensics"
                icon={<IconFileSearch size={18} />}
                active={path === "/forensics"}
              />
            </Link>
            <Link to="/reports" search={carry} onClick={close} style={plain}>
              <Item label="Reports" icon={<IconFileText size={18} />} active={path === "/reports"} />
            </Link>
            <Link to="/activity" search={carry} onClick={close} style={plain}>
              <Item
                label="Activity log"
                icon={<IconHistory size={18} />}
                active={path === "/activity"}
              />
            </Link>
          </Stack>

          {/* The account menu: everything that is not day-to-day testing lives
              behind one profile row, so the menu above stays short. */}
          {user && (
            <Box mt="auto">
              <Menu position="top-start" width={232} withinPortal shadow="md">
                <Menu.Target>
                  <UnstyledButton
                    aria-label="Account menu"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 10,
                      width: "100%",
                      padding: 8,
                      borderRadius: 8,
                    }}
                  >
                    <Avatar radius="xl" size={32} color="brand">
                      {initials(user.name || user.email)}
                    </Avatar>
                    <Box style={{ flex: 1, minWidth: 0, textAlign: "left" }}>
                      <Text size="sm" fw={600} truncate>
                        {user.name || user.email}
                      </Text>
                      <Text size="xs" c="dimmed" truncate>
                        {roleName(user.role)}
                      </Text>
                    </Box>
                    <Box c="dimmed" style={{ display: "flex" }}>
                      <IconDotsVertical size={18} />
                    </Box>
                  </UnstyledButton>
                </Menu.Target>
                <Menu.Dropdown>
                  {(RANK_MANAGER as readonly string[]).includes(user.role) && (
                    <Menu.Item
                      leftSection={<IconUsers size={16} />}
                      onClick={() => {
                        close();
                        void navigate({ to: "/people" });
                      }}
                    >
                      People
                    </Menu.Item>
                  )}
                  <Menu.Item
                    leftSection={<IconSettings size={16} />}
                    onClick={() => {
                      close();
                      void navigate({ to: "/settings" });
                    }}
                  >
                    Settings
                  </Menu.Item>
                  <Menu.Item
                    leftSection={<IconInfoCircle size={16} />}
                    onClick={() => {
                      close();
                      void navigate({ to: "/about" });
                    }}
                  >
                    About
                  </Menu.Item>
                  <Menu.Item
                    closeMenuOnClick={false}
                    leftSection={scheme === "dark" ? <IconSun size={16} /> : <IconMoon size={16} />}
                    onClick={() => setColorScheme(next)}
                  >
                    {`Switch to ${next} mode`}
                  </Menu.Item>
                  <Menu.Divider />
                  <Menu.Item color="red" leftSection={<IconLogout size={16} />} onClick={signOut}>
                    Sign out
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
              <Text size="xs" c="dimmed" px="sm" mt={6}>
                © 2026 Gembit Soultan Shirazi
              </Text>
            </Box>
          )}
        </Stack>
      </AppShell.Navbar>

      <AppShell.Main bg="var(--ares-canvas)">
        <Box maw="var(--ares-page-width)" mx="auto" px="lg" py="xl">
          <Outlet />
        </Box>
      </AppShell.Main>
    </AppShell>
  );
}

// RootLayout decides what a visitor sees first: the first-run setup on a new
// installation, the sign-in screen when nobody is signed in, or the app.
export function RootLayout() {
  const { user, error } = useSession();
  const navigate = useNavigate();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const status = useQuery({
    queryKey: ["setup-status"],
    queryFn: () => control.getSetupStatus({}),
    // Asked once. Asking again while the new encryption key is on screen would
    // take that screen away before the key is saved.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const needed = status.data?.needed;

  // Keep the address honest: /setup only while setup is needed.
  useEffect(() => {
    if (needed === undefined) return;
    if (needed && path !== "/setup") void navigate({ to: "/setup", replace: true });
    if (!needed && path === "/setup") void navigate({ to: "/", replace: true });
  }, [needed, path, navigate]);

  if (status.isError || (error && !user)) {
    return (
      <Frame>
        <ErrorNote title="Ares could not be reached">
          {errorText(status.error ?? error)} Check that the server is running, then reload the page.
        </ErrorNote>
      </Frame>
    );
  }
  if (!status.data) return <LoadingState label="Opening Ares…" />;
  if (needed) {
    return (
      <SetupPage
        drivers={status.data.drivers}
        dbPath={status.data.dbPath}
        keyFilePath={status.data.keyFilePath}
      />
    );
  }
  if (user === undefined) return <LoadingState label="Opening Ares…" />;
  if (user === null) return <SignInPage />;
  return <Shell />;
}

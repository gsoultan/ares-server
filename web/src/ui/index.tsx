import type { ReactNode } from "react";
import {
  Alert,
  Badge,
  Box,
  Card,
  Group,
  Loader,
  Stack,
  Text,
  ThemeIcon,
  Title,
  Tooltip,
} from "@mantine/core";
import { IconAlertTriangle, IconInfoCircle, IconShieldCheck } from "@tabler/icons-react";
import { severityColor, severityLabel, type Severity } from "../lib/findings.ts";
import { toneColor, type StatusInfo, type Tone } from "../lib/labels.ts";

// The shared building blocks every screen is made of. A screen picks from
// these; it does not style its own cards, headings, badges or states.

// PageHeader is the one heading block at the top of every screen.
export function PageHeader({
  title,
  description,
  badge,
  actions,
  back,
}: {
  title: ReactNode;
  description?: ReactNode;
  badge?: ReactNode;
  actions?: ReactNode;
  back?: ReactNode;
}) {
  return (
    <Stack gap="xs">
      {back}
      <Group justify="space-between" align="flex-start" gap="md">
        <Box style={{ flex: 1, minWidth: 240 }}>
          <Group gap="sm" align="center">
            <Title order={1}>{title}</Title>
            {badge}
          </Group>
          {description && (
            <Text c="dimmed" mt={4}>
              {description}
            </Text>
          )}
        </Box>
        {actions && <Group gap="xs">{actions}</Group>}
      </Group>
    </Stack>
  );
}

// Section is the one card every block of content sits in: a title, an optional
// line of help, an optional action on the right, then the content.
export function Section({
  title,
  description,
  aside,
  children,
  flush = false,
}: {
  title?: ReactNode;
  description?: ReactNode;
  aside?: ReactNode;
  children?: ReactNode;
  // flush lets a table or list run edge to edge under the heading.
  flush?: boolean;
}) {
  const head = (title || aside) && (
    <Group justify="space-between" align="flex-start" wrap="nowrap" gap="md">
      <Box>
        {title && <Title order={2}>{title}</Title>}
        {description && (
          <Text size="sm" c="dimmed" mt={2} maw={640}>
            {description}
          </Text>
        )}
      </Box>
      {aside && <Box style={{ flexShrink: 0 }}>{aside}</Box>}
    </Group>
  );
  if (flush) {
    return (
      <Card padding={0}>
        {head && (
          <Box p="lg" pb="md">
            {head}
          </Box>
        )}
        {children}
      </Card>
    );
  }
  return (
    <Card>
      <Stack gap="md">
        {head}
        {children}
      </Stack>
    </Card>
  );
}

export function ToneBadge({
  tone,
  children,
  hint,
  size,
}: {
  tone: Tone;
  children: ReactNode;
  hint?: string;
  size?: "sm" | "md" | "lg";
}) {
  const badge = (
    <Badge color={toneColor(tone)} size={size}>
      {children}
    </Badge>
  );
  return hint ? <Tooltip label={hint}>{badge}</Tooltip> : badge;
}

export function StatusBadge({ info, size }: { info: StatusInfo; size?: "sm" | "md" | "lg" }) {
  return (
    <ToneBadge tone={info.tone} hint={info.hint} size={size}>
      {info.label}
    </ToneBadge>
  );
}

// SeverityBadge: only critical is solid, so the worst issue is the loudest
// thing on the page.
export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <Badge
      color={severityColor(severity)}
      variant={severity === "critical" ? "filled" : "light"}
      miw={64}
    >
      {count !== undefined ? `${count} ` : ""}
      {severityLabel(severity)}
    </Badge>
  );
}

// The three states every data region has besides its content.
export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return (
    <Group justify="center" gap="xs" py="xl" role="status">
      <Loader size="sm" />
      <Text size="sm" c="dimmed">
        {label}
      </Text>
    </Group>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <Stack align="center" gap="xs" py="xl" px="lg">
      {icon && (
        <ThemeIcon size={44} radius="xl" variant="light" color="gray">
          {icon}
        </ThemeIcon>
      )}
      <Text fw={600}>{title}</Text>
      {description && (
        <Text size="sm" c="dimmed" ta="center" maw={420}>
          {description}
        </Text>
      )}
      {action && <Box mt="xs">{action}</Box>}
    </Stack>
  );
}

export function ErrorNote({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <Alert color="red" title={title} icon={<IconAlertTriangle size={18} />} role="alert">
      {children}
    </Alert>
  );
}

// InfoNote is a quiet note. A tone marks it as a safeguard (good) or a
// caution (warn); the default is neutral.
export function InfoNote({
  children,
  title,
  tone = "neutral",
}: {
  children: ReactNode;
  title?: string;
  tone?: Tone;
}) {
  const icon =
    tone === "good" ? (
      <IconShieldCheck size={18} />
    ) : tone === "warn" || tone === "bad" ? (
      <IconAlertTriangle size={18} />
    ) : (
      <IconInfoCircle size={18} />
    );
  return (
    <Alert color={tone === "neutral" ? "gray" : toneColor(tone)} title={title} icon={icon}>
      {children}
    </Alert>
  );
}

// Field is a labelled fact: a quiet caption over a value.
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Box>
      <Text size="xs" c="dimmed" fw={600}>
        {label}
      </Text>
      <Text size="md" mt={2}>
        {children}
      </Text>
    </Box>
  );
}

// Stat is a headline number with a caption under it.
export function Stat({ value, label, tone }: { value: ReactNode; label: string; tone?: Tone }) {
  return (
    <Box>
      <Text fz={26} fw={650} lh={1.15} c={tone && tone !== "neutral" ? `var(--mantine-color-${toneColor(tone)}-light-color)` : undefined}>
        {value}
      </Text>
      <Text size="sm" c="dimmed">
        {label}
      </Text>
    </Box>
  );
}

// StatCard is one headline figure on a summary row: a caption, the number,
// and a line or a bar under it that says what the number is made of.
export function StatCard({
  label,
  value,
  tone,
  children,
}: {
  label: string;
  value: ReactNode;
  tone?: Tone;
  children?: ReactNode;
}) {
  return (
    <Card padding="md">
      <Text size="xs" fw={600} c="dimmed">
        {label}
      </Text>
      <Text
        fz={28}
        fw={650}
        lh={1.2}
        mt={4}
        c={tone && tone !== "neutral" ? `var(--mantine-color-${toneColor(tone)}-light-color)` : undefined}
      >
        {value}
      </Text>
      {children && <Box mt={6}>{children}</Box>}
    </Card>
  );
}

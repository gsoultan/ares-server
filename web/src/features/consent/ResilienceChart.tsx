import { Box, Group, Text } from "@mantine/core";

export interface RampStep {
  concurrency: number;
  requests: number;
  errors: number;
  errorRate: number;
  p50Ms: number;
  p95Ms: number;
  rate429: number;
  // Cut short by a stop: shown, never scored.
  partial?: boolean;
}

const LOAD = "var(--mantine-color-brand-6)";
const LATENCY = "var(--mantine-color-orange-7)";
const LIMIT = "var(--mantine-color-red-6)";

function Swatch({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <Group gap={6} wrap="nowrap">
      <Box w={16} h={0} style={{ borderTop: `2px ${dashed ? "dashed" : "solid"} ${color}` }} />
      <Text size="xs" c="dimmed">
        {label}
      </Text>
    </Group>
  );
}

// ResilienceChart draws each step of the ramp: the load (simultaneous
// requests, a stepped line) and the slowest-5% response time, against the
// response-time limit that stops the test. Each line has its own scale; the
// table under the chart carries the exact numbers.
export function ResilienceChart({ steps, limitMs, ceiling }: { steps: RampStep[]; limitMs: number; ceiling: number }) {
  const W = 640;
  const H = 220;
  const pad = { l: 8, r: 8, t: 12, b: 24 };
  const n = steps.length;
  if (n === 0) return null;
  // Label at most about twelve steps, so the numbers never run together.
  const every = Math.max(1, Math.ceil(n / 12));
  const x = (i: number) => pad.l + ((W - pad.l - pad.r) * i) / n;
  const maxLoad = Math.max(ceiling, ...steps.map((s) => s.concurrency));
  const maxMs = Math.max(limitMs * 1.1, ...steps.map((s) => s.p95Ms));
  const yLoad = (v: number) => H - pad.b - ((H - pad.t - pad.b) * v) / maxLoad;
  const yMs = (v: number) => H - pad.b - ((H - pad.t - pad.b) * v) / maxMs;

  const loadPath = steps
    .map((s, i) => `${i === 0 ? "M" : "L"}${x(i)},${yLoad(s.concurrency)} L${x(i + 1)},${yLoad(s.concurrency)}`)
    .join(" ");
  const msPath = steps.map((s, i) => `${i === 0 ? "M" : "L"}${(x(i) + x(i + 1)) / 2},${yMs(s.p95Ms)}`).join(" ");
  const label = `Load rose from ${steps[0]!.concurrency} to ${steps[n - 1]!.concurrency} simultaneous requests; the slowest responses went from ${steps[0]!.p95Ms} ms to ${steps[n - 1]!.p95Ms} ms, against a limit of ${limitMs} ms.`;

  return (
    <Box>
      <Group gap="md" mb="xs">
        <Swatch color={LOAD} label="Simultaneous requests" />
        <Swatch color={LATENCY} label="Response time (slowest 5%)" />
        <Swatch color={LIMIT} label={`Limit, ${limitMs} ms`} dashed />
      </Group>
      <Box
        style={{
          border: "1px solid var(--mantine-color-default-border)",
          borderRadius: "var(--mantine-radius-md)",
          background: "var(--mantine-color-body)",
        }}
        p="xs"
      >
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={label} style={{ display: "block" }}>
          <line x1={pad.l} x2={W - pad.r} y1={H - pad.b} y2={H - pad.b} stroke="var(--mantine-color-default-border)" />
          <line
            x1={pad.l}
            x2={W - pad.r}
            y1={yMs(limitMs)}
            y2={yMs(limitMs)}
            stroke={LIMIT}
            strokeDasharray="5 4"
            strokeWidth={1.5}
          />
          <path d={loadPath} fill="none" stroke={LOAD} strokeWidth={2.5} strokeLinejoin="round" />
          <path d={msPath} fill="none" stroke={LATENCY} strokeWidth={2.5} strokeLinejoin="round" />
          {steps.map((s, i) => (
            <circle key={i} cx={(x(i) + x(i + 1)) / 2} cy={yMs(s.p95Ms)} r={3} fill={LATENCY}>
              <title>{`${s.concurrency} simultaneous: ${s.p95Ms} ms, ${(s.errorRate * 100).toFixed(1)}% failed`}</title>
            </circle>
          ))}
          {steps.map((s, i) => (i % every !== 0 && i !== n - 1 ? null : (
            <text
              key={`t${i}`}
              x={(x(i) + x(i + 1)) / 2}
              y={H - 6}
              textAnchor="middle"
              fontSize={11}
              fill="var(--mantine-color-dimmed)"
            >
              {s.concurrency}
            </text>
          )))}
        </svg>
      </Box>
    </Box>
  );
}

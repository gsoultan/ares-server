import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Box, Group, Loader, Progress, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import {
  IconBrowser,
  IconCheck,
  IconDeviceMobile,
  IconNetwork,
  IconShieldCheck,
  IconSpy,
  IconUserShield,
} from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { control } from "../../client.ts";
import type { JobOutcome } from "../../gen/ares/v1/ares_pb.ts";
import { severityRank, toFinding, type Finding } from "../../lib/findings.ts";
import { toProfile } from "../../lib/intel.ts";
import { moduleInfo, plural, type Tone } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { Section, SeverityBadge, ToneBadge } from "../../ui/index.tsx";
import { targetLabel } from "../workspace/data.ts";

// The live view of one test: who is doing what, what the permission gate let
// through, and what was found. The server reports results as they arrive, so
// the view follows the real test: each new result becomes an event, shown one
// at a time at a pace a person can follow.

type Ev =
  | { t: "stage"; i: number; now: string; sub: string; tester: string; target: string }
  | { t: "allow" }
  | { t: "deny"; label: string }
  | { t: "clue"; text: string }
  | { t: "check"; id: string; why: string }
  | { t: "run"; id: string }
  | { t: "end"; id: string; found: number }
  | { t: "finding"; f: Finding }
  | { t: "done" };

const STEP_MS = 480;

function wantsCalm(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

type TargetKind = "website" | "network" | "app";

function describeTarget(module: string, targets: string[]): { kind: TargetKind; name: string; role: string } {
  if (module === "apkscan" || module === "apkbackend") {
    return { kind: "app", name: "The app", role: "The Android app you added" };
  }
  const first = targets[0] ?? "";
  const more = targets.length > 1 ? ` and ${targets.length - 1} more` : "";
  if (first.includes("://")) {
    let host = first;
    try {
      host = new URL(first).host;
    } catch {
      // Shown as typed.
    }
    return { kind: "website", name: "The website", role: host + more };
  }
  return {
    kind: "network",
    name: first.includes("/") || targets.length > 1 ? "The network" : "The machine",
    role: first + more,
  };
}

// script turns what the server has reported so far into events. While the
// test is still running (final is false) it stops at the check in progress.
function script(o: JobOutcome, module: string, noun: string, final: boolean): Ev[] {
  const evs: Ev[] = [];
  const recon = module === "recon";
  evs.push({
    t: "stage",
    i: 0,
    now: "Checking permission",
    sub: "Making sure each address is inside the scope the owner approved.",
    tester: "Asks to test the addresses",
    target: "Not touched yet",
  });
  o.allowed.forEach(() => evs.push({ t: "allow" }));
  o.denied.forEach((d) => evs.push({ t: "deny", label: targetLabel(d.target) }));

  const findingsOf = (cap?: string) =>
    o.results
      .filter((r) => r.kind === "finding" && (!cap || r.capability === cap))
      .map((r) => toFinding(r.data, r.kind, r.technique))
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  if (o.allowed.length > 0 || o.results.length > 0) {
    const profile = o.results.find((r) => r.kind === "profile");
    if (recon && !profile && !final) {
      evs.push({
        t: "stage",
        i: 1,
        now: `Getting to know ${noun}`,
        sub: "Looking at how it answers, without changing anything.",
        tester: "Looks around, like a visitor would",
        target: "Answering normally",
      });
    } else if (recon && profile) {
      const p = toProfile(profile.data);
      evs.push({
        t: "stage",
        i: 1,
        now: `Getting to know ${noun}`,
        sub: "Looking at how it answers, without changing anything.",
        tester: "Looks around, like a visitor would",
        target: "Answering normally",
      });
      const learned = p.technologies.length > 0 ? p.technologies : [...new Set(p.clues.map((c) => c.value))];
      learned.slice(0, 8).forEach((text) => evs.push({ t: "clue", text }));
      evs.push({
        t: "stage",
        i: 2,
        now: "Choosing the checks",
        sub: "Picking only the checks that fit what was found.",
        tester: "Plans which doors to try",
        target: "Untouched while Ares plans",
      });
      const ran = [...new Set([...o.results.map((r) => r.capability), o.currentCapability])].filter(
        (c) => c && c !== "recon",
      );
      // Checks that need the operator's input first are not run by the profile.
      const planned = p.recommendations.filter((r) => !r.needsInput || ran.includes(r.module));
      // Checks in the order they actually reported, then the ones still to come.
      const ids = [...new Set([...ran, ...planned.map((r) => r.module)])];
      ids.forEach((id) =>
        evs.push({
          t: "check",
          id,
          why: planned.find((r) => r.module === id)?.reasons[0] ?? moduleInfo(id).summary,
        }),
      );
      // While running, the last check heard from is the one in progress.
      const active = final ? ids.length - 1 : Math.max(-1, ...ids.map((id, n) => (ran.includes(id) ? n : -1)));
      ids.forEach((id, n) => {
        if (n > active) return;
        evs.push({
          t: "stage",
          i: 3,
          now: `Running check ${n + 1} of ${ids.length}`,
          sub: `${moduleInfo(id).label}: ${moduleInfo(id).summary}`,
          tester: `Tries: ${moduleInfo(id).label.toLowerCase()}`,
          target: "Answering",
        });
        evs.push({ t: "run", id });
        const fs = findingsOf(id);
        fs.forEach((f) => evs.push({ t: "finding", f }));
        if (final || n < active) evs.push({ t: "end", id, found: fs.filter((f) => f.severity !== "info").length });
      });
    } else {
      evs.push({
        t: "stage",
        i: 1,
        now: `Running: ${moduleInfo(module).label}`,
        sub: moduleInfo(module).summary,
        tester: `Tries: ${moduleInfo(module).label.toLowerCase()}`,
        target: "Answering",
      });
      evs.push({ t: "check", id: module, why: moduleInfo(module).summary });
      evs.push({ t: "run", id: module });
      const fs = findingsOf();
      fs.forEach((f) => evs.push({ t: "finding", f }));
      if (final) evs.push({ t: "end", id: module, found: fs.filter((f) => f.severity !== "info").length });
    }
  }
  if (final) evs.push({ t: "done" });
  return evs;
}

interface CheckRow {
  id: string;
  why: string;
  state: "waiting" | "running" | "done";
  found: number;
}

export function LiveTest({
  jobId,
  module,
  targets,
  startedAt,
  outcome,
  engagementId,
  onFinished,
}: {
  jobId: string;
  module: string;
  targets: string[];
  startedAt: string;
  // The final results. Undefined while the test is still running.
  outcome?: JobOutcome;
  engagementId: string;
  // Called once everything that happened has been shown.
  onFinished?: () => void;
}) {
  const recon = module === "recon";
  const stages = recon
    ? ["Check permission", "Get to know the target", "Choose the checks", "Run the checks", "Sum up"]
    : ["Check permission", "Run the check", "Sum up"];
  const target = describeTarget(module, targets);
  const noun = target.name.toLowerCase();

  // While the test runs, ask the server every second what has happened so far.
  const { tenantId } = useTenant();
  const progress = useQuery({
    queryKey: ["job", tenantId, jobId],
    queryFn: () => control.getJob({ jobId, tenantId }),
    enabled: !outcome,
    refetchInterval: 1000,
    retry: false,
  });
  const partial = progress.data && progress.data.status !== "pending" ? progress.data : undefined;
  const seenSoFar = outcome ?? partial;
  const final = !!outcome;

  const events = useMemo(
    () => (seenSoFar ? script(seenSoFar, module, noun, final) : []),
    [seenSoFar, module, noun, final],
  );
  const [shown, setShown] = useState(0);
  const [warm, setWarm] = useState(false);
  const [seconds, setSeconds] = useState(0);
  const finished = final && events.length > 0 && shown >= events.length;

  // The first moment is the permission check; then the test is under way.
  useEffect(() => {
    const t = setTimeout(() => setWarm(true), 900);
    return () => clearTimeout(t);
  }, [jobId]);

  useEffect(() => {
    if (events.length === 0 || shown === events.length) return;
    if (wantsCalm() || shown > events.length) {
      setShown(events.length);
      return;
    }
    // Long runs are stepped through faster, so the walk-through stays short.
    const ms = Math.max(140, Math.min(STEP_MS, 12000 / events.length));
    const t = setTimeout(() => setShown((n) => n + 1), ms);
    return () => clearTimeout(t);
  }, [events, shown]);

  useEffect(() => {
    if (finished) onFinished?.();
    // Only the moment it finishes matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished]);

  useEffect(() => {
    if (finished) return;
    const tick = () => setSeconds(Math.max(0, Math.round((Date.now() - Date.parse(startedAt)) / 1000)));
    tick();
    const t = setInterval(tick, 500);
    return () => clearInterval(t);
  }, [finished, startedAt]);

  // What has happened so far.
  let stage = warm ? 1 : 0;
  let now = warm ? (recon ? `Getting to know ${noun}` : `Running: ${moduleInfo(module).label}`) : "Checking permission";
  let sub = warm
    ? recon
      ? "Looking at how it answers, without changing anything."
      : moduleInfo(module).summary
    : "Making sure each address is inside the scope the owner approved.";
  let tester = warm ? "Trying the target" : "Asks to test the addresses";
  let targetSays = warm ? "Answering" : "Not touched yet";
  let allowed = 0;
  const denied: string[] = [];
  const clues: string[] = [];
  const checks: CheckRow[] = [];
  const findings: Finding[] = [];
  let hit = false;
  for (const e of events.slice(0, shown)) {
    switch (e.t) {
      case "stage":
        stage = e.i;
        now = e.now;
        sub = e.sub;
        tester = e.tester;
        targetSays = e.target;
        hit = false;
        break;
      case "allow":
        allowed++;
        break;
      case "deny":
        denied.push(e.label);
        break;
      case "clue":
        clues.push(e.text);
        break;
      case "check":
        checks.push({ id: e.id, why: e.why, state: "waiting", found: 0 });
        break;
      case "run": {
        const c = checks.find((x) => x.id === e.id);
        if (c) c.state = "running";
        break;
      }
      case "end": {
        const c = checks.find((x) => x.id === e.id);
        if (c) {
          c.state = "done";
          c.found = e.found;
        }
        break;
      }
      case "finding":
        if (e.f.severity !== "info") {
          findings.push(e.f);
          hit = true;
          targetSays = "Weak spot found";
        }
        break;
      case "done":
        stage = stages.length;
        break;
    }
  }
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const last = events[shown - 1];
  const denying = last?.t === "deny";
  const untouched = outcome !== undefined && outcome.allowed.length === 0 && outcome.results.length === 0;

  if (finished) {
    tester = "Done";
    if (outcome?.error) {
      now = "The test did not finish";
      sub = outcome.error;
    } else if (untouched) {
      now = "Nothing was tested";
      sub = "Every address was outside the approved scope, so nothing was touched.";
      targetSays = "Not touched";
    } else {
      now =
        findings.length > 0
          ? `Finished. ${plural(findings.length, "thing needs", "things need")} attention.`
          : "Finished. Nothing found.";
      sub = `Took ${plural(seconds, "second")}. ${
        denied.length > 0 ? `${plural(denied.length, "address was", "addresses were")} left alone. ` : ""
      }Nothing on ${noun} was changed.`;
      targetSays = findings.length > 0 ? plural(findings.length, "weak spot") + " found" : "Held up";
    }
  }

  const flowing = !finished && stage >= 1 && !untouched && (events.length === 0 || allowed > 0);
  const percent = finished
    ? 100
    : events.length === 0
      ? warm
        ? 30
        : 8
      : final
        ? Math.round(30 + (shown / events.length) * 70)
        : // The end is not known yet, so creep forward with each event.
          Math.min(90, 30 + shown * 3);

  const icon =
    target.kind === "website" ? (
      <IconBrowser size={30} stroke={1.6} />
    ) : target.kind === "app" ? (
      <IconDeviceMobile size={30} stroke={1.6} />
    ) : (
      <IconNetwork size={30} stroke={1.6} />
    );

  return (
    <Section>
      <Stack gap="lg">
        <Group justify="space-between" align="flex-start" wrap="nowrap" gap="md">
          <Box style={{ minWidth: 0 }}>
            <Title order={2} aria-live="polite">
              {now}
            </Title>
            <Text size="sm" c="dimmed" mt={2}>
              {sub}
            </Text>
          </Box>
          <Text c="dimmed" style={{ fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}>
            {Math.floor(seconds / 60)}:{String(seconds % 60).padStart(2, "0")}
          </Text>
        </Group>
        <Progress value={percent} size={4} aria-label="Progress of the test" />

        <ol className="ares-live-stages">
          {stages.map((name, i) => {
            const state = i < stage ? "done" : i === stage ? "active" : "waiting";
            return (
              <li key={name} className="ares-live-stage" data-state={state}>
                <span className="ares-live-dot">{state === "done" ? <IconCheck size={13} stroke={3} /> : i + 1}</span>
                <span>{name}</span>
              </li>
            );
          })}
        </ol>

        <div className="ares-live-scene">
          <div className="ares-live-lane">
            <Actor
              state={!finished && stage >= 1 ? "busy" : undefined}
              icon={<IconSpy size={30} stroke={1.6} />}
              name="The tester"
              role="Ares, acting as an attacker"
              says={tester}
            />
            <div className="ares-live-wire" data-flow={flowing}>
              <i />
              <i />
              <i />
              {denying && <i key={shown} data-stop />}
            </div>
            <Actor
              key={denying ? `deny-${shown}` : "gate"}
              state={denying ? "deny" : undefined}
              icon={<IconShieldCheck size={30} stroke={1.6} />}
              name="Permission gate"
              role="Lets through approved addresses only"
              says={
                denying
                  ? "Blocked: outside the scope"
                  : denied.length > 0 && allowed === 0 && finished
                    ? "Let nothing through"
                    : "Letting approved requests through"
              }
            />
            <div className="ares-live-wire" data-flow={flowing}>
              <i />
              <i />
              <i />
            </div>
            <Actor
              key={hit ? `hit-${findings.length}` : "target"}
              state={hit || (finished && findings.length > 0) ? "hit" : stage >= 1 && !untouched ? "ok" : undefined}
              icon={icon}
              name={target.name}
              role={target.role}
              says={targetSays}
              mark={findings.length > 0 ? findings.length : undefined}
            />
            <div className="ares-live-wire" data-kind="watch" aria-hidden />
            <Actor
              state={finished && !untouched ? "ok" : undefined}
              icon={<IconUserShield size={30} stroke={1.6} />}
              name="The defenders"
              role="The team guarding the target"
              says={finished && !untouched ? "Next: record what your alarms caught" : "Watching their alarms"}
            />
          </div>
          {seenSoFar && (
            <Group gap="lg" mt="md">
              <Group gap={6}>
                <ToneBadge tone="good">Allowed</ToneBadge>
                <Text size="sm">{plural(allowed, "address", "addresses")}</Text>
              </Group>
              <Group gap={6} wrap="nowrap" align="flex-start">
                <ToneBadge tone={denied.length > 0 ? "bad" : "neutral"}>Blocked</ToneBadge>
                <Text size="sm">
                  {denied.length === 0
                    ? "None"
                    : `${denied.slice(0, 3).join(", ")}${denied.length > 3 ? ` and ${denied.length - 3} more` : ""}: outside the approved scope, so left alone.`}
                </Text>
              </Group>
            </Group>
          )}
          {clues.length > 0 && (
            <Group gap={6} mt="sm" aria-label="What Ares learned about the target">
              {clues.map((c) => (
                <ToneBadge key={c} tone="brand">
                  {c}
                </ToneBadge>
              ))}
            </Group>
          )}
        </div>

        {!finished && (
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg">
          <Box>
            <Title order={3} mb="xs">
              Checks
            </Title>
            <Rows empty={recon ? "The checks appear here once Ares knows the target." : "Starting…"}>
              {checks.map((c) => (
                <div key={c.id} className="ares-live-row" data-running={c.state === "running"}>
                  <Box style={{ flex: 1, minWidth: 0 }}>
                    <Text fw={600}>{moduleInfo(c.id).label}</Text>
                    <Text size="xs" c="dimmed" lineClamp={2}>
                      {c.why}
                    </Text>
                  </Box>
                  {c.state === "running" ? (
                    <Loader size={16} aria-label="Running" />
                  ) : (
                    <ToneBadge tone={checkTone(c)}>
                      {c.state === "waiting" ? "Waiting" : c.found > 0 ? `${c.found} found` : "Nothing found"}
                    </ToneBadge>
                  )}
                </div>
              ))}
              {checks.length === 0 && !seenSoFar && !recon && (
                <div className="ares-live-row" data-running>
                  <Box style={{ flex: 1, minWidth: 0 }}>
                    <Text fw={600}>{moduleInfo(module).label}</Text>
                    <Text size="xs" c="dimmed" lineClamp={2}>
                      {moduleInfo(module).summary}
                    </Text>
                  </Box>
                  <Loader size={16} aria-label="Running" />
                </div>
              )}
            </Rows>
          </Box>
          <Box>
            <Title order={3} mb="xs">
              Found so far ({findings.length})
            </Title>
            <Rows empty="Anything Ares finds shows up here.">
              {findings.map((f, i) => (
                <div key={`${f.title}-${i}`} className="ares-live-row">
                  <SeverityBadge severity={f.severity} />
                  <Box style={{ flex: 1, minWidth: 0 }}>
                    <Text fw={600}>{f.title}</Text>
                    {f.description && (
                      <Text size="xs" c="dimmed" lineClamp={1}>
                        {f.description}
                      </Text>
                    )}
                  </Box>
                </div>
              ))}
            </Rows>
          </Box>
        </SimpleGrid>
        )}

        {finished && !untouched && !outcome?.error && (
          <Group gap="lg">
            <Link to="/engagements/$id" params={{ id: engagementId }} search={{ view: "findings" }} className="ares-link">
              See the findings
            </Link>
            <Link to="/engagements/$id" params={{ id: engagementId }} search={{ view: "risk" }} className="ares-link">
              See the risk picture
            </Link>
            <Link to="/defenses" search={{ engagement: engagementId }} className="ares-link">
              Record what the defenders saw
            </Link>
          </Group>
        )}
      </Stack>
    </Section>
  );
}

function checkTone(c: CheckRow): Tone {
  if (c.state === "waiting") return "neutral";
  return c.found > 0 ? "bad" : "good";
}

function Actor({
  state,
  icon,
  name,
  role,
  says,
  mark,
}: {
  state?: "busy" | "ok" | "hit" | "deny";
  icon: ReactNode;
  name: string;
  role: string;
  says: string;
  mark?: number;
}) {
  return (
    <div className="ares-live-actor" data-state={state}>
      <div className="ares-live-avatar">
        {icon}
        {mark !== undefined && (
          <span key={mark} className="ares-live-mark">
            {mark}
          </span>
        )}
      </div>
      <Text fw={600} size="sm">
        {name}
      </Text>
      <Text size="xs" c="dimmed" className="ares-live-role" style={{ wordBreak: "break-word" }}>
        {role}
      </Text>
      <span className="ares-live-says">{says}</span>
    </div>
  );
}

function Rows({ children, empty }: { children: ReactNode; empty: string }) {
  const items = Array.isArray(children) ? children.flat().filter(Boolean) : children ? [children] : [];
  return (
    <Box style={{ border: "1px solid var(--ares-line)", borderRadius: 10, overflow: "hidden", minHeight: 96 }}>
      {items.length === 0 ? (
        <Text c="dimmed" ta="center" py="xl" px="md" size="sm">
          {empty}
        </Text>
      ) : (
        items
      )}
    </Box>
  );
}

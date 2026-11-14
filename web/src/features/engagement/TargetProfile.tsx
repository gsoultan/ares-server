import { useState } from "react";
import { Badge, Box, Button, Group, Stack, Table, Text, TextInput, Title } from "@mantine/core";
import { IconRadar2 } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { control } from "../../client.ts";
import { clueKind, confidenceInfo, toProfile, type Profile } from "../../lib/intel.ts";
import { errorText, formatWhen, moduleInfo } from "../../lib/labels.ts";
import { EmptyState, ErrorNote, InfoNote, LoadingState, Section, ToneBadge } from "../../ui/index.tsx";
import { useJobOutcome, useJobs } from "../workspace/data.ts";
import { liveRun } from "../../lib/local.ts";
import { LiveTest } from "./LiveTest.tsx";
import { useStartTest } from "./startTest.ts";
import { AiAdvice } from "../ai/AiAdvice.tsx";

// useProfile finds the newest target profile of an engagement, if one was made.
export function useProfile(engagementId: string) {
  const { jobs, loading } = useJobs(engagementId);
  const job = jobs.find((j) => j.module === "recon");
  const outcome = useJobOutcome(job?.jobId, !!job?.done);
  const profiles = (outcome.data?.results ?? [])
    .filter((r) => r.kind === "profile")
    .map((r) => toProfile(r.data));
  return {
    job,
    outcome: outcome.data,
    profiles,
    loading: loading || (!!job?.done && outcome.isLoading),
    // Still being made, or made and still loading.
    busy: !!job && (!job.done || outcome.isLoading),
  };
}

// TargetProfile shows what the target is built with, the clues behind that,
// and the tests those clues make worth running.
export function TargetProfile({ id, canTest }: { id: string; canTest: boolean }) {
  const { job, outcome: o, profiles, loading, busy } = useProfile(id);
  const start = useStartTest(id);
  const [address, setAddress] = useState("");

  const begin = (target: string) => start.mutate({ module: "recon", targets: [target] });

  if (loading && !job) return <LoadingState label="Loading the target profile…" />;

  const live = busy && job ? liveRun(job.jobId) : undefined;
  if (live && job) {
    return (
      <LiveTest
        jobId={job.jobId}
        module={job.module}
        targets={live.targets ?? []}
        startedAt={live.at}
        engagementId={id}
      />
    );
  }

  if (busy) {
    return (
      <Section title="Target profile">
        <LoadingState label="Looking at the target. This changes nothing on it…" />
      </Section>
    );
  }

  if (profiles.length === 0) {
    return (
      <Section
        title="Target profile"
        description="Ares looks at the target without changing anything and works out what it is built with. That decides which tests are worth running."
      >
        {o?.error && <ErrorNote title="The profile did not finish">{o.error}</ErrorNote>}
        {o && !o.error && o.allowed.length === 0 && o.denied.length > 0 && (
          <ErrorNote title="That address is outside the approved scope">
            It was not touched. Enter an address the scope allows.
          </ErrorNote>
        )}
        {o && !o.error && o.allowed.length > 0 && (
          <InfoNote title="Nothing answered at that address">
            Check the address and try again.
          </InfoNote>
        )}
        {start.isError && (
          <ErrorNote title="The profile could not start">{errorText(start.error)}</ErrorNote>
        )}
        {canTest ? (
          <Group align="flex-end" maw={640}>
            <TextInput
              label="Address to profile"
              description="A website inside the approved scope."
              placeholder="https://www.example.com/"
              value={address}
              onChange={(ev) => setAddress(ev.currentTarget.value)}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" && address.trim() !== "") begin(address.trim());
              }}
              style={{ flex: 1, minWidth: 240 }}
            />
            <Button
              leftSection={<IconRadar2 size={16} />}
              loading={start.isPending}
              disabled={address.trim() === ""}
              onClick={() => begin(address.trim())}
            >
              Profile the target
            </Button>
          </Group>
        ) : (
          <EmptyState
            icon={<IconRadar2 size={22} />}
            title="No profile yet"
            description="A profile can be made once testing is allowed in this engagement."
          />
        )}
      </Section>
    );
  }

  return (
    <Stack gap="lg">
      {start.isError && (
        <ErrorNote title="That could not start">{errorText(start.error)}</ErrorNote>
      )}
      {profiles.map((p) => (
        <ProfileView
          key={p.target}
          id={id}
          profile={p}
          madeAt={job!.at}
          canTest={canTest}
          busy={start.isPending}
          onAgain={() => begin(p.target)}
        />
      ))}
    </Stack>
  );
}

function ProfileView({
  id,
  profile: p,
  madeAt,
  canTest,
  busy,
  onAgain,
}: {
  id: string;
  profile: Profile;
  madeAt: string;
  canTest: boolean;
  busy: boolean;
  onAgain: () => void;
}) {
  const navigate = useNavigate();
  const start = useStartTest(id);
  const modules = useQuery({
    queryKey: ["modules"],
    queryFn: () => control.listModules({}),
    staleTime: 60_000,
  });

  const recommended = new Set(p.recommendations.map((r) => r.module));
  // Tests that take an address and were not picked for this target.
  const others = (modules.data?.modules ?? []).filter(
    (m) => !recommended.has(m) && m !== "recon" && m !== "noop" && moduleInfo(m).targets !== null,
  );

  const toTesting = (test?: string) =>
    void navigate({ to: "/engagements/$id", params: { id }, search: { view: "testing", test } });

  const run = (module: string) =>
    start.mutate({ module, targets: [p.target] }, { onSuccess: () => toTesting() });

  return (
    <>
      <AiAdvice
        engagementId={id}
        feature="suggest-checks"
        title="What should we do next?"
        description="Suggestions for the next checks, from what has run so far. You still start each one yourself, inside the approved scope."
        action="Suggest next steps"
      />
      <Section
        title={headline(p.summary)}
        description={`Ares looked at ${p.target} without changing anything and worked out what it is built with. This decides which tests are worth running. Made ${formatWhen(madeAt).replace(/^T/, "t").replace(/^Y/, "y")}.`}
        aside={
          canTest ? (
            <Button variant="default" loading={busy} onClick={onAgain}>
              Profile again
            </Button>
          ) : undefined
        }
      >
        {p.technologies.length > 0 && (
          <Group gap="xs">
            {p.technologies.map((t) => (
              <Badge key={t} color="gray">
                {t}
              </Badge>
            ))}
          </Group>
        )}
      </Section>

      <Section
        flush
        title="What we noticed, and how we know"
        description="Each clue comes with the evidence behind it."
      >
        {p.clues.length === 0 ? (
          <EmptyState title="No clues were recorded" />
        ) : (
          <Table.ScrollContainer minWidth={560}>
            <Table>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Clue</Table.Th>
                  <Table.Th>How we know</Table.Th>
                  <Table.Th w={120}>Confidence</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {p.clues.map((c, i) => {
                  const conf = confidenceInfo(c.confidence);
                  return (
                    <Table.Tr key={i}>
                      <Table.Td>
                        <Text fw={600}>{c.value}</Text>
                        <Text size="sm" c="dimmed">
                          {clueKind(c.category)}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Text c="dimmed" style={{ wordBreak: "break-word" }}>
                          {c.evidence}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <ToneBadge tone={conf.tone}>{conf.label}</ToneBadge>
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
        title="Recommended tests"
        description="Chosen from the clues above, and run straight away as part of the profile. Each says why it was picked. Their results are under Run tests and Findings."
      >
        {start.isError && (
          <ErrorNote title="The test could not start">{errorText(start.error)}</ErrorNote>
        )}
        {p.recommendations.length === 0 && (
          <Text c="dimmed">{p.rationale || "No test was recommended for this target."}</Text>
        )}
        <Box>
          {p.recommendations.map((r) => (
            <TestRow
              key={r.module}
              module={r.module}
              why={
                r.needsInput
                  ? `Why: ${sentence(r.reasons)} ${capital(r.needsInput)}`
                  : `Why: ${sentence(r.reasons)}`
              }
              badge={
                r.needsInput ? (
                  <ToneBadge tone="warn">Needs your input</ToneBadge>
                ) : (
                  <ToneBadge tone="brand">Ran with the profile</ToneBadge>
                )
              }
              action={
                !canTest ? undefined : r.needsInput ? (
                  <Button variant="default" onClick={() => toTesting(r.module)}>
                    Set up
                  </Button>
                ) : (
                  <Button variant="default" disabled={start.isPending} onClick={() => run(r.module)}>
                    Run again
                  </Button>
                )
              }
            />
          ))}
          {others.map((m) => (
            <TestRow
              key={m}
              module={m}
              quiet
              why="Not recommended: nothing on this target points to it."
              badge={<ToneBadge tone="neutral">Not picked</ToneBadge>}
              action={
                canTest ? (
                  <Button variant="default" onClick={() => toTesting(m)}>
                    Run anyway
                  </Button>
                ) : undefined
              }
            />
          ))}
        </Box>
      </Section>
    </>
  );
}

function TestRow({
  module,
  why,
  badge,
  action,
  quiet,
}: {
  module: string;
  why: string;
  badge: React.ReactNode;
  action?: React.ReactNode;
  quiet?: boolean;
}) {
  const info = moduleInfo(module);
  return (
    <Group gap="md" py="md" align="center" style={{ borderTop: "1px solid var(--ares-line)" }}>
      <Box style={{ flex: 1, minWidth: 240 }}>
        <Title order={3} c={quiet ? "dimmed" : undefined}>
          {info.label}
        </Title>
        <Text size="sm" c="dimmed" mt={2}>
          {why}
        </Text>
      </Box>
      {badge}
      <Box w={116} style={{ display: "flex", justifyContent: "flex-end" }}>
        {action}
      </Box>
    </Group>
  );
}

function capital(s: string): string {
  const t = s.trim();
  const c = t.charAt(0).toUpperCase() + t.slice(1);
  return /[.!?]$/.test(c) ? c : `${c}.`;
}

// Reasons arrive as short phrases; join them into one readable sentence.
function sentence(reasons: string[]): string {
  if (reasons.length === 0) return "it suits this kind of target.";
  const joined = reasons.map((r) => r.trim().replace(/[.;]$/, "")).join("; ");
  return `${joined.charAt(0).toLowerCase()}${joined.slice(1)}.`;
}

// The profile's one-line summary, as a heading.
function headline(summary: string): string {
  if (summary === "" || /^no technologies/i.test(summary)) {
    return "We could not tell what this site is built with";
  }
  return summary.charAt(0).toUpperCase() + summary.slice(1);
}

import { useEffect, useState } from "react";
import { Button, Code, Group, Select, SimpleGrid, Stack, Text } from "@mantine/core";
import { IconArrowLeft, IconKey, IconRefresh } from "@tabler/icons-react";
import { Link } from "@tanstack/react-router";
import { severityMeaning } from "../../lib/findings.ts";
import { errorText, formatWhen, moduleInfo, proofState, proofStateInfo, techniqueLabel } from "../../lib/labels.ts";
import { ErrorNote, InfoNote, PageHeader, Section, SeverityBadge, StatusBadge, WarnNote } from "../../ui/index.tsx";
import { useStartTest } from "../engagement/startTest.ts";
import {
  findingState,
  findingStateInfo,
  useFindings,
  useJobs,
  useRecheckFinding,
  useSetFindingStatus,
  type FindingRecord,
  type FindingStatus,
} from "../workspace/data.ts";
import { Facts, FixSteps, Part } from "./FindingParts.tsx";
import { AiAdvice } from "../ai/AiAdvice.tsx";
import { ProofPanel } from "./ProofPanel.tsx";

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "in_progress", label: "Fix in progress" },
  { value: "fixed", label: "Fixed" },
];

// FindingDetail is one finding told in the order a reader needs it: how
// serious, what it is, what it means and how to fix it, then the exact steps
// for whoever makes the change, and the proof behind it.
export function FindingDetail({
  record,
  engagementName,
  canTest,
}: {
  record: FindingRecord;
  engagementName: string;
  // False once testing is stopped or before it is allowed.
  canTest: boolean;
}) {
  const f = record.finding;
  const state = findingState(record);
  const test = moduleInfo(record.module);
  const start = useStartTest(record.engagementId);
  const reproduce = useRecheckFinding(record);
  const proofInfo = proofStateInfo(proofState(record.proof?.kind));
  const { jobs } = useJobs(record.engagementId);
  const [recheckJob, setRecheckJob] = useState<string | null>(null);
  // Whether the running re-check is the finding's own proof probe.
  const [viaProbe, setViaProbe] = useState(false);
  const [noProbe, setNoProbe] = useState(false);

  const setStatus = useSetFindingStatus();
  const { fetching } = useFindings(record.engagementId);

  // The re-check has a verdict once its test is listed and the findings reloaded.
  const recheck = jobs.find((j) => j.jobId === recheckJob);
  const settled = !!recheck?.done && !fetching;
  const failed = settled && !!recheck.summary?.error;
  const skipped = settled && !failed && recheck.summary?.allowed === 0;
  // A proof probe can be narrower than the test that found the finding, so its
  // own result decides; a whole re-run is judged by the reloaded finding.
  const stillThere =
    settled && !failed && !skipped && (viaProbe ? (recheck.summary?.findings ?? 0) > 0 : !record.rechecked);

  // A finding that was marked fixed but shows up again is open again.
  const reopen = stillThere && record.status === "fixed";
  const mutate = setStatus.mutate;
  useEffect(() => {
    if (reopen) mutate({ id: record.id, status: "open" });
  }, [reopen, record.id, mutate]);

  // A finding with a re-checkable proof re-runs only that proof; any other
  // finding re-runs its whole test on the same address.
  const hasProbe = !!record.proof?.recheck;
  const canRecheck = canTest && record.target !== "" && (hasProbe || test.targets !== null);
  const rerunTest = () =>
    start.mutate(
      { module: record.module, targets: [record.target] },
      {
        onSuccess: (jobId) => {
          setViaProbe(false);
          setRecheckJob(jobId);
        },
      },
    );
  const onRecheck = () => {
    setNoProbe(false);
    if (!hasProbe) return rerunTest();
    reproduce.mutate(undefined, {
      onSuccess: (jobId) => {
        if (jobId) {
          setViaProbe(true);
          setRecheckJob(jobId);
        } else if (test.targets !== null) {
          rerunTest();
        } else {
          setNoProbe(true);
        }
      },
    });
  };
  const recheckError = start.error ?? reproduce.error;

  const proof = [
    ...Object.entries(f.evidence).map(([k, v]) => ({
      label: capital(k.replace(/[_-]/g, " ")),
      value: (
        <Code bg="transparent" p={0} style={{ wordBreak: "break-all" }}>
          {v}
        </Code>
      ),
    })),
    ...(f.technique
      ? [{ label: "Attacker technique", value: (
            <Text>
              {techniqueLabel(f.technique)} ({f.technique})
            </Text>
          ), }]
      : []),
    { label: "Found by", value: <Text>{test.label}</Text> },
  ];

  const history = [
    { label: formatWhen(record.foundAt), value: <Text>Found by the {test.label}</Text> },
    {
      label: "Now",
      value: <StatusBadge info={findingStateInfo(state)} />,
    },
    {
      label: "Next",
      value: (
        <Text c="dimmed">
          {state === "rechecked"
            ? "Nothing. The fix is confirmed."
            : state === "fixed"
              ? "Re-check to confirm the fix held."
              : "Mark it as fixed when the change is made, then re-check to confirm."}
        </Text>
      ),
    },
  ];

  return (
    <Stack gap="lg">
      <PageHeader
        back={
          <Link
            to="/engagements/$id"
            params={{ id: record.engagementId }}
            search={{ view: "findings" }}
            className="ares-back"
          >
            <IconArrowLeft size={14} />
            {engagementName} · Findings
          </Link>
        }
        title={f.title}
        badge={
          <Group gap="xs">
            <SeverityBadge severity={f.severity} />
            <StatusBadge info={proofInfo} />
          </Group>
        }
        description={
          <Text span style={{ wordBreak: "break-all" }}>
            {[
              f.url ?? record.target,
              record.approval && "approved intrusive test",
              `found ${lower(formatWhen(record.foundAt))}`,
            ]
              .filter((x) => !!x)
              .join(" · ")}
          </Text>
        }
        actions={
          <>
            {state === "rechecked" ? (
              <StatusBadge info={findingStateInfo(state)} size="lg" />
            ) : (
              <Select
                aria-label="Status of this finding"
                data={STATUS_OPTIONS}
                value={record.status}
                allowDeselect={false}
                w={170}
                onChange={(v) => v && setStatus.mutate({ id: record.id, status: v as FindingStatus })}
              />
            )}
            {canRecheck && (
              <Button
                leftSection={<IconRefresh size={16} />}
                loading={start.isPending || reproduce.isPending || (!!recheckJob && !settled)}
                onClick={onRecheck}
              >
                Re-check now
              </Button>
            )}
          </>
        }
      />

      {record.approval && (
        <WarnNote title="This was an approved intrusive test" icon={<IconKey size={18} />}>
          {[
            `Approved by ${record.approval.who}${record.approval.how ? ` (${record.approval.how})` : ""}${
              record.approval.at ? `, ${lower(formatWhen(record.approval.at))}` : ""
            }, before it ran.`,
            record.approval.action,
          ]
            .filter(Boolean)
            .join(" ")}
        </WarnNote>
      )}

      {noProbe && (
        <InfoNote title="This finding cannot be re-checked on its own">
          Its proof cannot be repeated by itself. Run its test again from Run tests to check it.
        </InfoNote>
      )}
      {recheckError && (
        <ErrorNote title="The re-check could not start">{errorText(recheckError)}</ErrorNote>
      )}
      {setStatus.isError && (
        <ErrorNote title="The status could not be saved">{errorText(setStatus.error)}</ErrorNote>
      )}
      {settled &&
        (failed ? (
          <ErrorNote title="The re-check did not finish">{recheck.summary?.error}</ErrorNote>
        ) : skipped ? (
          <ErrorNote title="The re-check was skipped">
            This address is no longer inside the approved scope, so it was not touched.
          </ErrorNote>
        ) : stillThere ? (
          <ErrorNote title="Still there">
            The test ran again and found the same weakness. It stays open.
          </ErrorNote>
        ) : (
          <InfoNote title="No longer found">
            The test ran again and this weakness is gone. The fix is confirmed.
          </InfoNote>
        ))}

      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="lg">
        <Part label="What we found">{f.description ?? "No description was recorded."}</Part>
        <Part label="What it means">{f.meaning ?? severityMeaning(f.severity)}</Part>
        <Part label="How to fix it">{f.remediation ?? "No fix was recorded for this finding."}</Part>
      </SimpleGrid>

      <AiAdvice
        engagementId={record.engagementId}
        feature="explain-finding"
        findingId={record.id}
        title="Explain this in plain words"
        description="A short explanation of this finding for someone who is not a specialist."
        action="Explain this finding"
        footnote="The fix steps on this page come from Ares itself and are the ones to follow."
      />

      {f.remediationDetail && (
        <Section
          title="Detailed fix steps"
          description="For the person making the change. Exact commands and settings."
        >
          <FixSteps r={f.remediationDetail} />
        </Section>
      )}

      {record.proof ? (
        <>
          <ProofPanel
            findingId={record.id}
            proof={record.proof}
            checks={record.proofChecks}
            approval={record.approval}
            extra={proof}
          />
          <Section title="History" description="Where this finding stands.">
            <Facts rows={history} />
          </Section>
        </>
      ) : (
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg" style={{ alignItems: "start" }}>
          <Section
            title={
              <Group gap="sm" component="span">
                Proof
                <StatusBadge info={proofInfo} />
              </Group>
            }
            description="What the test saw. Ares did not reproduce it, so there is no recorded exchange to show."
          >
            <Facts rows={proof} />
          </Section>
          <Section title="History" description="Where this finding stands.">
            <Facts rows={history} />
          </Section>
        </SimpleGrid>
      )}
    </Stack>
  );
}

function capital(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function lower(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}

import { SimpleGrid, Stack } from "@mantine/core";
import { IconArrowLeft, IconCircleCheck } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { control } from "../client.ts";
import { engagementStatus, formatDate, scopeText } from "../lib/labels.ts";
import { defaultView } from "../lib/views.ts";
import { useTenant } from "../tenant.tsx";
import {
  EmptyState,
  ErrorNote,
  Field,
  InfoNote,
  LoadingState,
  PageHeader,
  Section,
  StatusBadge,
} from "../ui/index.tsx";
import { ReportError, ReportMenu, StopTesting, useReport } from "../features/engagement/HeaderActions.tsx";
import { RiskPicture } from "../features/engagement/RiskPicture.tsx";
import { RunTest } from "../features/engagement/RunTest.tsx";
import { SetupSteps } from "../features/engagement/SetupSteps.tsx";
import { TargetProfile, useProfile } from "../features/engagement/TargetProfile.tsx";
import { useActivity } from "../features/engagement/useActivity.ts";
import { FindingDetail } from "../features/findings/FindingDetail.tsx";
import { FindingsTable } from "../features/findings/FindingsTable.tsx";
import { useFindings } from "../features/workspace/data.ts";
import { AddAgent } from "../features/agents/AddAgent.tsx";
import { AgentDetail } from "../features/agents/AgentDetail.tsx";
import { AgentsSection } from "../features/agents/AgentsSection.tsx";
import { useAgentActivity } from "../features/agents/data.ts";
import { useFoundBy } from "../features/findings/foundBy.ts";
import { RESILIENCE, ResilienceTest } from "../features/consent/Resilience.tsx";
import { IntensitySummary, TestIntensity } from "../features/consent/TestIntensity.tsx";

const route = getRouteApi("/engagements/$id");

const backLink = (
  <Link to="/engagements" className="ares-back">
    <IconArrowLeft size={14} />
    All engagements
  </Link>
);

export function EngagementDetailPage() {
  const { id } = route.useParams();
  const search = route.useSearch();
  const qc = useQueryClient();
  const { tenantId } = useTenant();
  const report = useReport(id);

  const engagement = useQuery({
    queryKey: ["engagement", tenantId, id],
    queryFn: () => control.getEngagement({ id, tenantId }),
  });
  const activity = useActivity(id);
  const { findings, loading: findingsLoading } = useFindings(id);
  const { profiles } = useProfile(id);
  const agentLog = useAgentActivity(activity.entries);
  const foundBy = useFoundBy([id]);

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["engagement", tenantId, id] });
    void qc.invalidateQueries({ queryKey: ["audit", tenantId, id] });
    void qc.invalidateQueries({ queryKey: ["engagements", tenantId] });
  };

  if (engagement.isLoading) {
    return <LoadingState label="Loading engagement…" />;
  }
  if (engagement.isError || !engagement.data) {
    return (
      <Stack gap="lg">
        {backLink}
        <ErrorNote title="This engagement could not be opened">
          It may belong to a different client workspace, or Ares could not reach its server.
        </ErrorNote>
      </Stack>
    );
  }

  const eng = engagement.data;
  const view = search.view ?? defaultView(eng.status);
  const canTest = eng.status === "authorized";

  // One finding takes the whole page, with its own heading.
  const opened = view === "findings" && search.finding
    ? findings.find((f) => f.id === search.finding)
    : undefined;
  if (opened) {
    return <FindingDetail record={opened} engagementName={eng.name} canTest={canTest} />;
  }

  // One agent, or adding one, also takes the whole page.
  const agentFindings = findings.filter((f) => agentLog.taskAgent.has(f.jobId));
  if (view === "agents" && search.agent === "new" && canTest) {
    return <AddAgent engagement={eng} />;
  }
  if (view === "agents" && search.agent && search.agent !== "new") {
    return (
      <AgentDetail
        engagement={eng}
        agentId={search.agent}
        findings={agentFindings.filter((f) => agentLog.taskAgent.get(f.jobId) === search.agent)}
        activity={agentLog.byAgent.get(search.agent) ?? []}
        canTest={canTest}
      />
    );
  }

  // Choosing how far tests may go takes the whole page.
  if (view === "setup" && search.page === "intensity" && eng.status !== "draft") {
    return <TestIntensity engagement={eng} />;
  }
  // So does the resilience test: its setup, approval, run and result.
  if (view === "testing" && search.test === RESILIENCE && (canTest || search.job)) {
    return (
      <ResilienceTest
        key={search.job ?? "setup"}
        engagement={eng}
        jobId={search.job}
        defaultTarget={profiles[0]?.target}
        activity={activity.entries ?? []}
        findings={findings}
      />
    );
  }

  // The saved scope, in the server's own words, from the latest log entry.
  const scopeDetail = activity.entries?.findLast((e) => e.action === "scope-updated")?.detail;
  const scopeSummary = scopeDetail === undefined ? undefined : scopeText(scopeDetail);

  const summary = eng.authorization
    ? `Approved by ${eng.authorization.approvedBy} · ${eng.authorization.document}`
    : `Created ${formatDate(eng.createdAt)}`;

  const notAllowed =
    eng.status === "halted" ? (
      <InfoNote title="Testing was stopped">
        No more tests can run in this engagement. Findings, the report and the activity log are
        kept.
      </InfoNote>
    ) : (
      <InfoNote title="Testing is not allowed yet">
        Finish the two steps under Scope and permission first.{" "}
        <Link to="/engagements/$id" params={{ id }} search={{ view: "setup" }} className="ares-link">
          Go to Scope and permission
        </Link>
      </InfoNote>
    );

  return (
    <Stack gap="lg">
      <PageHeader
        back={backLink}
        title={eng.name}
        badge={<StatusBadge info={engagementStatus(eng.status)} size="lg" />}
        description={summary}
        actions={
          <>
            <ReportMenu report={report} />
            {canTest && <StopTesting id={id} onChange={invalidate} />}
          </>
        }
      />
      <ReportError report={report} />

      {view === "setup" &&
        (eng.status === "draft" ? (
          <>
            <SetupSteps id={id} scopeSummary={scopeSummary} onChange={invalidate} />
            <InfoNote title="What happens next">
              Once permission is recorded, Ares profiles the target and recommends which tests to
              run. Every action is written to the activity log, and you can stop all testing at any
              time with one button.
            </InfoNote>
          </>
        ) : (
          <Section
            title="Scope and permission"
            description="What may be tested, and who allowed it. Both were fixed when permission was recorded."
          >
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="lg">
              <Field label="Allowed to test">
                {eng.inScope.length > 0 ? eng.inScope.join(", ") : (scopeSummary ?? "Not recorded")}
              </Field>
              <Field label="Never tested">
                {eng.exclude.length > 0 ? eng.exclude.join(", ") : "Nothing excluded"}
              </Field>
              <Field label="Permission document">{eng.authorization?.document ?? "Not recorded"}</Field>
              <Field label="Approved by">{eng.authorization?.approvedBy ?? "Not recorded"}</Field>
            </SimpleGrid>
            <Link to="/activity" search={{ engagement: id }} className="ares-link">
              See the full record in the activity log
            </Link>
          </Section>
        ))}
      {view === "setup" && eng.status !== "draft" && <IntensitySummary engagement={eng} />}

      {view === "profile" && (
        <>
          {!canTest && profiles.length === 0 && notAllowed}
          {(canTest || profiles.length > 0) && <TargetProfile id={id} canTest={canTest} />}
        </>
      )}

      {view === "agents" && <AgentsSection id={id} canTest={canTest} agentFindings={agentFindings} />}

      {view === "testing" &&
        (canTest ? (
          <RunTest
            key={search.test ?? ""}
            id={id}
            initialTest={search.test}
            defaultTarget={profiles[0]?.target}
          />
        ) : (
          notAllowed
        ))}

      {view === "findings" && (
        <Section
          flush
          title="Findings"
          description="Every weakness the tests found in this engagement, most serious first."
        >
          {search.finding && !findingsLoading && (
            <Stack px="lg" pb="md">
              <InfoNote>That finding is no longer available. Here are the current ones.</InfoNote>
            </Stack>
          )}
          {findingsLoading && findings.length === 0 ? (
            <LoadingState label="Loading findings…" />
          ) : findings.length === 0 ? (
            <EmptyState
              icon={<IconCircleCheck size={22} />}
              title="No findings yet"
              description="Weaknesses the tests find in this engagement are listed here."
            />
          ) : (
            <FindingsTable findings={findings} foundBy={foundBy} />
          )}
        </Section>
      )}

      {view === "risk" && <RiskPicture id={id} findings={findings} />}
    </Stack>
  );
}

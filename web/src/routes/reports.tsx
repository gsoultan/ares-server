import { useState } from "react";
import { Box, Button, Card, Group, Radio, SimpleGrid, Stack, Text, ThemeIcon } from "@mantine/core";
import { IconDownload, IconFileText } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { getRouteApi } from "@tanstack/react-router";
import { control } from "../client.ts";
import { errorText, formatWhen } from "../lib/labels.ts";
import { recordReport, useReportHistory } from "../lib/local.ts";
import { useTenant } from "../tenant.tsx";
import { EmptyState, ErrorNote, LoadingState, PageHeader, Section } from "../ui/index.tsx";
import { downloadBytes } from "../features/engagement/HeaderActions.tsx";
import { EngagementPicker } from "../features/workspace/EngagementPicker.tsx";
import { useEngagements } from "../features/workspace/data.ts";
import { AiAdvice } from "../features/ai/AiAdvice.tsx";

const route = getRouteApi("/reports");

const FORMATS: Record<string, string> = { pdf: "PDF", docx: "Word" };

const CONTENTS = [
  { title: "Summary", detail: "What is still open, what is proven fixed, and the risk score now and after the first test." },
  { title: "Fix these first", detail: "The most serious open findings, each in one plain sentence with its first step." },
  { title: "Proven fixed", detail: "Each fix Ares tested again, with the date the problem stopped coming back." },
  { title: "Risk over time", detail: "The risk score after each test, so improvement is visible." },
  { title: "What we found", detail: "Each finding in full: what it means, how to fix it, and its proof." },
  { title: "What your defenders noticed", detail: "Blocked, alerted, logged only or missed, per technique." },
  { title: "Activity log", detail: "The complete, tamper-evident record of what was done." },
];

// ReportsPage makes the document you share with the people who own the systems.
export function ReportsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const { tenantId } = useTenant();
  const engagements = useEngagements();
  const all = engagements.data?.engagements ?? [];
  const chosen =
    all.find((e) => e.id === search.engagement) ?? all.find((e) => e.status !== "draft") ?? all[0];
  const [format, setFormat] = useState("pdf");
  const history = useReportHistory().filter((r) => r.tenantId === tenantId);

  const make = useMutation({
    mutationFn: async (req: { id: string; name: string; format: string }) => {
      const res = await control.generateReport({ id: req.id, tenantId, format: req.format });
      downloadBytes(res.filename, res.contentType, res.data);
      recordReport({ engagementId: req.id, engagementName: req.name, tenantId, format: req.format });
    },
  });

  const header = (
    <PageHeader
      title="Reports"
      description="A document you can share with the people who own the systems. Written in plain language."
    />
  );

  if (engagements.isLoading) return <LoadingState />;
  if (engagements.isError) {
    return (
      <Stack gap="lg">
        {header}
        <ErrorNote title="Could not load reports">
          Ares could not reach its server. Check that it is running, then reload the page.
        </ErrorNote>
      </Stack>
    );
  }
  if (!chosen) {
    return (
      <Stack gap="lg">
        {header}
        <Card>
          <EmptyState
            icon={<IconFileText size={22} />}
            title="Nothing to report yet"
            description="A report is made from an engagement. Create one and run a test first."
          />
        </Card>
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      {header}

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="lg" style={{ alignItems: "start" }}>
        <Section title="Create a report">
          <EngagementPicker
            engagements={all}
            value={chosen.id}
            onChange={(id) => void navigate({ search: { engagement: id } })}
          />
          <Radio.Group label="Format" value={format} onChange={setFormat}>
            <Group mt="xs" gap="lg">
              <Radio value="pdf" label="PDF" />
              <Radio value="docx" label="Word" />
            </Group>
          </Radio.Group>
          {make.isError && (
            <ErrorNote title="Could not create the report">{errorText(make.error)}</ErrorNote>
          )}
          <Group>
            <Button
              leftSection={<IconDownload size={16} />}
              loading={make.isPending}
              onClick={() => make.mutate({ id: chosen.id, name: chosen.name, format })}
            >
              Download report
            </Button>
          </Group>
        </Section>

        <AiAdvice
          key={chosen.id}
          engagementId={chosen.id}
          feature="draft-report"
          title="Draft the summary for managers"
          description="A first draft of the opening summary, from this engagement's findings."
          action="Draft the summary"
          footnote="Read and edit it before you use it."
        />

        <Section title="What the report contains" description="In this order.">
          <Stack gap="sm">
            {CONTENTS.map((c, i) => (
              <Group key={c.title} gap="sm" wrap="nowrap" align="flex-start">
                <ThemeIcon size={24} radius="xl" variant="light" color="brand" aria-hidden>
                  <Text fz={12} fw={700}>
                    {i + 1}
                  </Text>
                </ThemeIcon>
                <Box>
                  <Text fw={600}>{c.title}</Text>
                  <Text size="sm" c="dimmed">
                    {c.detail}
                  </Text>
                </Box>
              </Group>
            ))}
          </Stack>
        </Section>
      </SimpleGrid>

      <Section title="Downloaded before" description="Reports made in this browser. Downloading again makes a fresh copy with the latest results.">
        {history.length === 0 ? (
          <Text c="dimmed">No reports have been downloaded yet.</Text>
        ) : (
          <Box>
            {history.map((r, i) => (
              <Group
                key={i}
                gap="md"
                py="sm"
                style={{ borderTop: "1px solid var(--ares-line)" }}
              >
                <Box style={{ flex: 1, minWidth: 0 }}>
                  <Text fw={600}>{r.engagementName}</Text>
                  <Text size="sm" c="dimmed">
                    {FORMATS[r.format] ?? r.format} · {formatWhen(r.at)}
                  </Text>
                </Box>
                <Button
                  variant="default"
                  disabled={make.isPending}
                  onClick={() =>
                    make.mutate({ id: r.engagementId, name: r.engagementName, format: r.format })
                  }
                >
                  Download again
                </Button>
              </Group>
            ))}
          </Box>
        )}
      </Section>
    </Stack>
  );
}

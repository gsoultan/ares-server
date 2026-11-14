import { useState } from "react";
import { Button, Group, Menu, Modal, Stack, Text } from "@mantine/core";
import { IconChevronDown, IconDownload, IconFileTypeDocx, IconFileTypePdf, IconPlayerStop } from "@tabler/icons-react";
import { useMutation } from "@tanstack/react-query";
import { control } from "../../client.ts";
import { errorText } from "../../lib/labels.ts";
import { useTenant } from "../../tenant.tsx";
import { ErrorNote } from "../../ui/index.tsx";

// downloadBytes saves raw bytes from the control plane as a file in the browser.
export function downloadBytes(filename: string, contentType: string, data: Uint8Array) {
  const blob = new Blob([data as BlobPart], { type: contentType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// useReport generates the shareable report and hands it to the browser.
export function useReport(id: string) {
  const { tenantId } = useTenant();
  return useMutation({
    mutationFn: (format: string) => control.generateReport({ id, tenantId, format }),
    onSuccess: (res) => downloadBytes(res.filename, res.contentType, res.data),
  });
}

export function ReportMenu({ report }: { report: ReturnType<typeof useReport> }) {
  return (
    <Menu position="bottom-end" width={240}>
      <Menu.Target>
        <Button
          variant="default"
          loading={report.isPending}
          leftSection={<IconDownload size={16} />}
          rightSection={<IconChevronDown size={14} />}
        >
          Download report
        </Button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Scope, findings, fixes and the activity log</Menu.Label>
        <Menu.Item leftSection={<IconFileTypePdf size={16} />} onClick={() => report.mutate("pdf")}>
          PDF document
        </Menu.Item>
        <Menu.Item leftSection={<IconFileTypeDocx size={16} />} onClick={() => report.mutate("docx")}>
          Word document
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}

export function ReportError({ report }: { report: ReturnType<typeof useReport> }) {
  if (!report.isError) return null;
  return <ErrorNote title="Could not create the report">{errorText(report.error)}</ErrorNote>;
}

// StopTesting is the kill switch. It cannot be undone, so it asks first.
export function StopTesting({ id, onChange }: { id: string; onChange: () => void }) {
  const { tenantId } = useTenant();
  const [opened, setOpened] = useState(false);
  const halt = useMutation({
    mutationFn: () => control.halt({ id, tenantId, actor: "operator" }),
    onSuccess: () => {
      setOpened(false);
      onChange();
    },
  });
  const close = () => {
    setOpened(false);
    halt.reset();
  };
  return (
    <>
      <Button
        color="red"
        variant="light"
        leftSection={<IconPlayerStop size={16} />}
        onClick={() => setOpened(true)}
      >
        Stop testing
      </Button>
      <Modal opened={opened} onClose={close} title="Stop all testing?">
        <Stack>
          <Text>
            This stops the engagement straight away. No further tests can run, and it cannot be
            switched back on. Findings and the activity log are kept.
          </Text>
          {halt.isError && (
            <ErrorNote title="Could not stop testing">{errorText(halt.error)}</ErrorNote>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Keep testing
            </Button>
            <Button color="red" loading={halt.isPending} onClick={() => halt.mutate()}>
              Stop testing
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

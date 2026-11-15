import { Group, Select, Text } from "@mantine/core";
import { IconShieldCheck } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { control } from "../../client.ts";
import type { Engagement } from "../../gen/ares/v1/ares_pb.ts";
import { useSession } from "../../session.tsx";
import { useTenant } from "../../tenant.tsx";

// On Forensics an engagement is called a case. A one-off check needs no setup:
// it files itself under the workspace's "Quick check" case, which is an
// ordinary engagement, so custody and the tamper-evident activity log apply
// exactly as they do anywhere else. It has no scope, so nothing it holds can
// ever be pointed at a server.

export const QUICK_CASE = "Quick check · personal";
export const QUICK_VALUE = "quick";

export function isQuickCase(e: { name: string }): boolean {
  return e.name === QUICK_CASE;
}

// useEnsureQuickCase returns a function that finds or creates the Quick check
// case and records the operator's permission on it, then hands back its id.
// Nothing is created by visiting the page: only adding evidence does this.
export function useEnsureQuickCase(engagements: Engagement[]) {
  const { tenantId } = useTenant();
  const { user } = useSession();
  const qc = useQueryClient();
  return async (): Promise<string> => {
    let eng = engagements.find(isQuickCase);
    if (!eng) eng = await control.createEngagement({ name: QUICK_CASE, tenantId });
    if (eng.status !== "authorized") {
      const who = user?.name || user?.email || "operator";
      eng = await control.authorize({
        id: eng.id,
        tenantId,
        approvedBy: who,
        document: `Quick check: ${who} confirmed the evidence is theirs, or that they have the owner's consent to examine it. Evidence is read offline only; no scope is set, so nothing is tested.`,
      });
    }
    await qc.invalidateQueries({ queryKey: ["engagements", tenantId] });
    return eng.id;
  };
}

export function CasePicker({
  engagements,
  value,
  onChange,
}: {
  engagements: Engagement[];
  value: string;
  onChange: (v: string) => void;
}) {
  const others = engagements.filter((e) => !isQuickCase(e));
  return (
    <Select
      label="Case"
      description="A one-off check files itself under Quick check automatically. Custody and the activity log still apply. Pick an engagement to file it there instead."
      data={[
        { value: QUICK_VALUE, label: QUICK_CASE },
        ...(others.length > 0 ? [{ group: "Engagements", items: others.map((e) => ({ value: e.id, label: e.name })) }] : []),
      ]}
      value={value}
      onChange={(v) => v && onChange(v)}
      allowDeselect={false}
      searchable
      maw={420}
      leftSection={<IconShieldCheck size={16} />}
      renderOption={({ option }) =>
        option.value === QUICK_VALUE ? (
          <Group gap={6} wrap="nowrap">
            <Text size="sm">Quick check</Text>
            <Text size="sm" c="dimmed">
              · personal
            </Text>
          </Group>
        ) : (
          <Text size="sm">{option.label}</Text>
        )
      }
    />
  );
}

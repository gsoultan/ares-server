import { Select } from "@mantine/core";

// EngagementPicker chooses which engagement a workspace page is showing.
export function EngagementPicker({
  engagements,
  value,
  onChange,
}: {
  engagements: { id: string; name: string }[];
  value: string | null;
  onChange: (id: string) => void;
}) {
  return (
    <Select
      label="Engagement"
      data={engagements.map((e) => ({ value: e.id, label: e.name }))}
      value={value}
      onChange={(v) => v && onChange(v)}
      allowDeselect={false}
      searchable
      w={280}
    />
  );
}

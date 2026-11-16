import { Badge } from "@mantine/core";
import type { JsonObject } from "@bufbuild/protobuf";
import { useTenant } from "../../tenant.tsx";
import { provenanceIndex, useFeeds, type Feed, type Provenance } from "./indicators.ts";

let memo: { feeds: Feed[]; index: Map<string, Provenance> } | null = null;

function indexFor(feeds: Feed[]): Map<string, Provenance> {
  if (memo?.feeds !== feeds) memo = { feeds, index: provenanceIndex(feeds) };
  return memo.index;
}

const str = (v: unknown) => (typeof v === "string" ? v : "");

// provenanceText is the small tag under a finding that says where the
// indicator it matched came from, and how sure its publisher is: "Primary
// confidence · Amnesty MVT", or "Withdrawn · Citizen Lab". It never changes
// how serious the finding is.
export function provenanceText(raw: JsonObject, index: Map<string, Provenance>): string | null {
  const value = str(raw["indicatorValue"]).toLowerCase();
  if (!value) return null;
  const known = index.get(value) ?? index.get(value.replace(/^www\./, ""));
  const label = str(raw["indicatorLabel"]);
  const source = known?.feed ?? (label.includes(", ") ? label.slice(label.lastIndexOf(", ") + 2) : label);
  const confidence = str(raw["confidence"]) || known?.confidence || "";
  const withdrawn = raw["withdrawn"] === true || known?.withdrawn === true;
  const parts: string[] = [];
  if (withdrawn) parts.push("Withdrawn");
  else if (confidence === "primary") parts.push("Primary confidence");
  else if (confidence === "secondary") parts.push("Secondary confidence");
  if (source && source !== "operator-supplied indicator") parts.push(source);
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function ProvenanceTag({ raw }: { raw: JsonObject }) {
  const { tenantId } = useTenant();
  const text = provenanceText(raw, indexFor(useFeeds(tenantId)));
  if (!text) return null;
  return (
    <Badge variant="light" color="brand" radius="sm" tt="none" fw={500} size="sm" mt={6} style={{ maxWidth: "100%" }}>
      {text}
    </Badge>
  );
}

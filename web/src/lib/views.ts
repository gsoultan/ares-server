// The sections of one engagement, in the order the work happens.
export const ENGAGEMENT_VIEWS = ["setup", "profile", "testing", "findings", "risk"] as const;
export type EngagementView = (typeof ENGAGEMENT_VIEWS)[number];

export const VIEW_LABELS: Record<EngagementView, string> = {
  setup: "Scope and permission",
  profile: "Target profile",
  testing: "Run tests",
  findings: "Findings",
  risk: "Risk picture",
};

// Where an engagement opens: on its setup until testing is allowed, then on
// the target profile, which says what to run next.
export function defaultView(status: string | undefined): EngagementView {
  return status === "draft" ? "setup" : "profile";
}

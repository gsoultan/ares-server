import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
} from "@tanstack/react-router";
import { RootLayout } from "./routes/root.tsx";
import { OverviewPage } from "./routes/overview.tsx";
import { ENGAGEMENT_VIEWS, type EngagementView } from "./lib/views.ts";


export interface EngagementSearch {
  view?: EngagementView;
  // The finding to open, inside the findings section.
  finding?: string;
  // The test to preselect, inside the run-tests section.
  test?: string;
  // The agent to open, inside the agents section; "new" adds one.
  agent?: string;
  // A page inside a section: "intensity" under Scope and permission.
  page?: string;
  // One run to show, inside the run-tests section (a resilience run).
  job?: string;
}

// Workspace pages can be narrowed to one engagement.
export interface EngagementFilter {
  engagement?: string;
}

const text = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);
const engagementFilter = (search: Record<string, unknown>): EngagementFilter => ({
  engagement: text(search["engagement"]),
});

const rootRoute = createRootRoute({ component: RootLayout });

const overviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: OverviewPage,
});

// Everything past the first screen is split into its own chunk and loaded on
// navigation, to keep first paint light.
const engagementsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements",
  component: lazyRouteComponent(() => import("./routes/engagements.tsx"), "EngagementsPage"),
});

const engagementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/engagements/$id",
  validateSearch: (search: Record<string, unknown>): EngagementSearch => ({
    view: ENGAGEMENT_VIEWS.find((v) => v === search["view"]),
    finding: text(search["finding"]),
    test: text(search["test"]),
    agent: text(search["agent"]),
    page: text(search["page"]),
    job: text(search["job"]),
  }),
  component: lazyRouteComponent(
    () => import("./routes/engagement-detail.tsx"),
    "EngagementDetailPage",
  ),
});

const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/findings",
  validateSearch: engagementFilter,
  component: lazyRouteComponent(() => import("./routes/findings.tsx"), "FindingsPage"),
});

const defensesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/defenses",
  validateSearch: engagementFilter,
  component: lazyRouteComponent(() => import("./routes/defenses.tsx"), "DefensesPage"),
});

const reportsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/reports",
  validateSearch: engagementFilter,
  component: lazyRouteComponent(() => import("./routes/reports.tsx"), "ReportsPage"),
});

const activityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/activity",
  validateSearch: engagementFilter,
  component: lazyRouteComponent(() => import("./routes/activity.tsx"), "ActivityPage"),
});

const forensicsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/forensics",
  validateSearch: engagementFilter,
  component: lazyRouteComponent(() => import("./routes/forensics.tsx"), "ForensicsPage"),
});

const aboutRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/about",
  component: lazyRouteComponent(() => import("./routes/about.tsx"), "AboutPage"),
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: lazyRouteComponent(() => import("./routes/settings.tsx"), "SettingsPage"),
});

const peopleRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/people",
  component: lazyRouteComponent(() => import("./routes/people.tsx"), "PeoplePage"),
});

// The first-run setup lives at this address. The root layout shows it, and
// sends visitors away once setup is done, so the route itself draws nothing.
const setupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/setup",
  component: () => null,
});

const routeTree = rootRoute.addChildren([
  overviewRoute,
  engagementsRoute,
  engagementRoute,
  findingsRoute,
  defensesRoute,
  reportsRoute,
  activityRoute,
  forensicsRoute,
  aboutRoute,
  settingsRoute,
  peopleRoute,
  setupRoute,
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

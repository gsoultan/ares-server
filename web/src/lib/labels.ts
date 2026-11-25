// Plain-language names for everything the control plane reports in its own
// vocabulary. The UI never shows a raw status, module id or audit action; it
// looks the wording up here, so the whole app speaks with one voice.

export type Tone = "neutral" | "good" | "warn" | "bad" | "brand";

// Mantine colour for each tone. The only place tones become colours.
export function toneColor(t: Tone): string {
  switch (t) {
    case "good":
      return "teal";
    case "warn":
      return "orange";
    case "bad":
      return "red";
    case "brand":
      return "brand";
    default:
      return "gray";
  }
}

export interface StatusInfo {
  label: string;
  tone: Tone;
  hint: string;
}

export function engagementStatus(status: string): StatusInfo {
  switch (status) {
    case "authorized":
      return { label: "Ready to test", tone: "good", hint: "Permission is on file. Tests can run." };
    case "halted":
      return { label: "Stopped", tone: "bad", hint: "Testing was stopped. Nothing more can run." };
    case "draft":
      return { label: "Setting up", tone: "neutral", hint: "Needs a scope and signed permission before any test can run." };
    default:
      return { label: status, tone: "neutral", hint: "" };
  }
}

export interface ModuleInfo {
  label: string;
  summary: string;
  // What the address box should ask for, or null when the test takes no addresses.
  targets: "url" | "hostport" | null;
  // A forensics tool: it works on files you add, from the Forensics page.
  forensic?: boolean;
}

const MODULES: Record<string, ModuleInfo> = {
  recon: {
    label: "Profile the target",
    summary: "Start here. Works out what the site is built with and recommends which tests to run. Changes nothing.",
    targets: "url",
  },
  loadresilience: {
    label: "Resilience test",
    summary: "Raises load in steps to find where a website slows down, and stops at your limits. Intrusive: needs approval per run.",
    targets: "url",
  },
  webcheck: {
    label: "Website weakness check",
    summary: "Looks for common website mistakes, such as exposed files and missing protections. Read-only.",
    targets: "url",
  },
  httpprobe: {
    label: "Website health check",
    summary: "Checks that a website responds and reviews its safety settings. Read-only.",
    targets: "url",
  },
  tlscheck: {
    label: "Encryption (HTTPS) check",
    summary: "Checks the certificate and encryption settings: expiry, mismatches, weak keys and outdated versions. Sends no data.",
    targets: "hostport",
  },
  portscan: {
    label: "Open port check",
    summary: "Finds which network doors are open on a server.",
    targets: "hostport",
  },
  versionscan: {
    label: "Known-vulnerable product check",
    summary: "Spots internet-facing products attackers commonly target and names the weakness to check. Read-only.",
    targets: "url",
  },
  reflectprobe: {
    label: "Input handling check",
    summary: "Places a harmless marker in page inputs and reports where it is echoed back. Sends no attack payloads.",
    targets: "url",
  },
  ssrfprobe: {
    label: "Server request forgery test",
    summary: "Confirms whether the server can be tricked into calling an address we control. Uses a harmless Ares address.",
    targets: "url",
  },
  sstiprobe: {
    label: "Template handling test",
    summary: "Checks whether the server runs text from page inputs as a template. Uses a harmless sum, nothing else.",
    targets: "url",
  },
  traversalprobe: {
    label: "File path test",
    summary: "Checks whether page inputs can reach files outside the website's own folder. Records proof only, not file contents.",
    targets: "url",
  },
  redirectprobe: {
    label: "Redirect test",
    summary: "Checks whether a link on the site can be made to send visitors to another site. Nothing is followed.",
    targets: "url",
  },
  headerprobe: {
    label: "Request header test",
    summary: "Checks whether the site trusts the address details a visitor's browser sends, which can poison links and caches.",
    targets: "url",
  },
  ctlogs: {
    label: "Subdomain lookup",
    summary: "Finds the domain's subdomains in public certificate records. Never touches the target.",
    targets: "hostport",
  },
  dnsrecon: {
    label: "DNS and email check",
    summary: "Reads the domain's public DNS records and checks whether its email can be faked. Never touches the target.",
    targets: "hostport",
  },
  rdap: {
    label: "Domain registration check",
    summary: "Reads the domain's public registration record and flags a near expiry or a missing transfer lock.",
    targets: "hostport",
  },
  log4shellprobe: {
    label: "Log4Shell test",
    summary: "Confirms the Log4j weakness by placing a harmless marker and watching for the server to look it up.",
    targets: "url",
  },
  accesscheck: {
    label: "Account access test",
    summary: "Checks whether one signed-in user can open things that belong to another user. Read-only.",
    targets: null,
  },
  bolaprobe: {
    label: "Record access test",
    summary: "Signs in as one account and tries to read test records it does not own. Read-only and limited to the records you list.",
    targets: "url",
  },
  apkscan: {
    label: "Android app review",
    summary: "Reviews an uploaded Android app for risky settings, built-in secrets and weak encryption. Touches no server.",
    targets: null,
  },
  evidence: {
    label: "Record evidence",
    summary: "Fingerprints each file and writes it to the activity log, so its chain of custody can be proven.",
    targets: null,
    forensic: true,
  },
  filemeta: {
    label: "File tampering check",
    summary: "Works out what each file really is, and flags disguised or booby-trapped files.",
    targets: null,
    forensic: true,
  },
  logscan: {
    label: "Log review",
    summary: "Reads a log for signs of attack and puts them in order as a timeline.",
    targets: null,
    forensic: true,
  },
  iocmatch: {
    label: "Known-threat match",
    summary: "Compares hashes, addresses and domains with a list of known bad ones.",
    targets: null,
    forensic: true,
  },
  triage: {
    label: "Evidence intake",
    summary: "Records files and bundles as evidence, opens bundles safely, and checks every file inside by its real type.",
    targets: null,
    forensic: true,
  },
  wpscan: {
    label: "WordPress check",
    summary: "Looks through a WordPress backup for back doors, hidden code and changed core files.",
    targets: null,
    forensic: true,
  },
  apkbackend: {
    label: "App server check",
    summary: "Works out which servers an Android app talks to and tests the ones inside the scope.",
    targets: null,
    forensic: true,
  },
  androidqf: {
    label: "Android phone check",
    summary: "Reads an AndroidQF collection offline: installed apps and certificates, running apps and the phone's intrusion logs.",
    targets: null,
    forensic: true,
  },
  iosbackup: {
    label: "iPhone backup check",
    summary: "Reads an iPhone backup's device and app records offline and matches app ids and addresses with known threats.",
    targets: null,
    forensic: true,
  },
  persistplist: {
    label: "Profile and launch item check",
    summary: "Checks Mac and iPhone configuration profiles and launch items for interception, management and hidden start-up.",
    targets: null,
    forensic: true,
  },
  dnslogscan: {
    label: "DNS log check",
    summary: "Reads a resolver or router's DNS log and matches every lookup with known threats. Nothing is looked up.",
    targets: null,
    forensic: true,
  },
  connrecord: {
    label: "Connection table check",
    summary: "Reads a netstat, ss, conntrack or Zeek connection table and matches every remote address with known threats.",
    targets: null,
    forensic: true,
  },
  eventlog: {
    label: "Windows event log check",
    summary: "Reads exported Windows event logs for suspicious launches, downloaders, new services, new accounts and cleared logs.",
    targets: null,
    forensic: true,
  },
  winpersist: {
    label: "Windows start-up check",
    summary: "Reads Run keys, scheduled tasks, services or an Autoruns export for entries that start malware automatically.",
    targets: null,
    forensic: true,
  },
  winartifacts: {
    label: "Download origin and hosts check",
    summary: "Reads where a downloaded file came from and whether the hosts file sends a name somewhere unexpected.",
    targets: null,
    forensic: true,
  },
  mailheader: {
    label: "Email check",
    summary: "Reads a saved message or mailbox for a faked sender, failed sender checks and dangerous attachments.",
    targets: null,
    forensic: true,
  },
  browserhist: {
    label: "Browser history check",
    summary: "Reads bookmarks or exported history for look-alike addresses, script links and program downloads.",
    targets: null,
    forensic: true,
  },
  iocexport: {
    label: "Share indicators",
    summary: "Writes the indicators confirmed in a case as a STIX 2.1 bundle and a MISP event.",
    targets: null,
    forensic: true,
  },
  timeline: {
    label: "Connect the dots",
    summary: "Puts forensic results in order and calls out an indicator seen in more than one place.",
    targets: null,
    forensic: true,
  },
  noop: {
    label: "Permission check only",
    summary: "Runs nothing. Only confirms which addresses the scope allows.",
    targets: "url",
  },
};

export function moduleInfo(id: string): ModuleInfo {
  return MODULES[id] ?? { label: id, summary: "", targets: "url" };
}

const ACTIONS: Record<string, string> = {
  "engagement-created": "Engagement created",
  "scope-updated": "Scope saved",
  "authorization-approved": "Permission recorded",
  "engagement-halted": "Testing stopped",
  "job-started": "Test started",
  "job-finished": "Test finished",
  "job-error": "Test failed",
  "job-refused": "Test refused",
  "scope-denied": "Address skipped (out of scope)",
  "detection-recorded": "Defender result recorded",
  "finding-status": "Finding status changed",
  "evidence-ingested": "Evidence recorded",
  result: "Result recorded",
  "proof-recorded": "Proof sealed",
  "proof-recheck": "Proof re-check started",
  "agent.key.mint": "Agent install key made",
  "agent.key.cancel": "Agent install key cancelled",
  "agent.enroll": "Agent installed and connected",
  "agent.dispatch": "Check sent to an agent",
  "agent.results": "Agent sent results",
  "agent.remove": "Agent removed",
  "agent.deregister": "Agent uninstalled itself",
  "intensity-set": "Test intensity changed",
  "technique-approved": "Intrusive test approved",
  "technique-declined": "Intrusive test declined",
  "approval-used": "Approval used by a run",
  "approval-withdrawn": "Approval withdrawn",
  "approval-released": "Approval given back (the run did not start)",
  "job-stopped": "Test stopped by hand",
};

export function actionLabel(action: string): string {
  return ACTIONS[action] ?? action;
}

const ACTORS: Record<string, string> = {
  system: "Ares",
  grpc: "Ares",
  api: "Ares",
  worker: "Ares",
  operator: "You",
};

// Agents act under their own id; the log calls them what they are.
const AGENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function actorLabel(actor: string): string {
  if (AGENT_ID.test(actor)) return "Agent";
  return ACTORS[actor] ?? actor;
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
});

export function formatDate(rfc3339: string): string {
  const d = new Date(rfc3339);
  return Number.isNaN(d.getTime()) ? "" : dateFmt.format(d);
}

export function formatDateTime(rfc3339: string): string {
  const d = new Date(rfc3339);
  return Number.isNaN(d.getTime()) ? rfc3339 : dateTimeFmt.format(d);
}

// Plain wording for a failed call. The raw error stays out of the page.
export function errorText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  return raw.replace(/^\[[a-z_]+\]\s*/i, "");
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

// The saved scope, reworded from the activity log's own summary.
export function scopeText(detail: string): string {
  const m = detail.match(/^(\d+) in scope, (\d+) excluded$/);
  if (!m) return detail;
  const allowed = plural(Number(m[1]), "entry allowed", "entries allowed");
  return Number(m[2]) === 0 ? allowed : `${allowed}, ${m[2]} never tested`;
}

const OUTCOME_WORDS: Record<string, string> = {
  prevented: "Blocked",
  detected: "Alerted",
  logged: "Logged only",
  missed: "Missed",
  unknown: "Not recorded",
  open: "Open",
  in_progress: "Fix in progress",
  fixed: "Fixed",
};

// entryDetails is the details column for one activity-log entry. Ids that mean
// nothing to the reader (the engagement's, a finding's) are left out.
export function entryDetails(
  e: { action: string; target: string; detail: string },
  engagementId: string,
): string {
  if (e.action === "evidence-ingested") {
    const m = e.detail.match(/^name=(.*) sha256=([0-9a-f]+)$/);
    if (m) return `${m[1]} · fingerprint ${m[2]!.slice(0, 12)}…`;
  }
  const hide = e.target === engagementId || e.action === "finding-status";
  return activityDetails(hide ? "" : e.target, e.detail);
}

// One activity-log entry's target and detail, reworded for the reader. The
// stored record is untouched; only its display changes.
export function activityDetails(target: string, detail: string): string {
  const known = (id: string) =>
    id in MODULES ? MODULES[id]!.label : /^T\d{4}(\.\d{3})?$/.test(id) ? techniqueLabel(id) : id;
  let d = detail;
  const counts = d.match(/^(\d+) allowed, (\d+) denied$/);
  const kind = d.match(/^([a-z0-9]+)\/([a-z]+)$/);
  if (counts) d = `${counts[1]} tested, ${counts[2]} skipped`;
  else if (kind) d = `${known(kind[1]!)}: ${kind[2]}`;
  else if (d in OUTCOME_WORDS) d = OUTCOME_WORDS[d]!;
  else d = scopeText(d);
  return [known(target), d].filter((x) => x !== "").join(" · ");
}

const timeFmt = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });

// formatWhen says when something happened the way a person would: "Today,
// 9:12 AM", "Yesterday, 4:41 PM", then the date.
export function formatWhen(rfc3339: string): string {
  const d = new Date(rfc3339);
  if (Number.isNaN(d.getTime())) return "";
  const startOfDay = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const days = Math.round((startOfDay(new Date()) - startOfDay(d)) / 86_400_000);
  if (days === 0) return `Today, ${timeFmt.format(d)}`;
  if (days === 1) return `Yesterday, ${timeFmt.format(d)}`;
  return `${dateFmt.format(d)}, ${timeFmt.format(d)}`;
}

// Attacker techniques (MITRE ATT&CK ids) in everyday words. The id stays
// available as a quiet second line for the people who work from it.
const TECHNIQUES: Record<string, string> = {
  T1190: "Attack a public-facing website",
  T1552: "Find passwords and keys left lying around",
  "T1552.001": "Find passwords left in files",
  "T1552.004": "Find private keys left in files",
  T1592: "Learn what the target is built with",
  T1087: "List the accounts that exist",
  T1110: "Guess passwords",
  T1059: "Run commands on the system",
  T1040: "Listen in on network traffic",
  T1203: "Use a software flaw to run code",
  T1133: "Come in through remote access",
  T1105: "Bring in attack tools",
  T1626: "Gain extra rights on a phone",
  "T1505.003": "Plant a hidden back door on the web server",
  T1078: "Sign in with a real account",
  T1083: "Map the folders and files",
  T1595: "Scan for weak points",
  T1046: "Scan for open network doors",
  T1557: "Step in between two parties",
  T1071: "Talk to an attacker's server",
  T1476: "Plant a malicious app on a phone",
  T1398: "Make a phone app start by itself",
  T1189: "Lure someone to a booby-trapped page",
  "T1565.001": "Quietly change stored data",
  "T1204.002": "Trick someone into opening a malicious file",
  T1566: "Send a phishing message",
  T1547: "Start automatically when the computer starts",
  T1053: "Run on a schedule",
  T1543: "Install a service that runs the attack",
  T1070: "Cover tracks by clearing logs",
};

export function techniqueLabel(id: string): string {
  return TECHNIQUES[id] ?? TECHNIQUES[id.split(".")[0] ?? ""] ?? `Attacker technique ${id}`;
}

// What a line in an attack timeline shows, in everyday words.
const LOG_EVENTS: Record<string, string> = {
  "log-sqli": "Tried to trick the database",
  "log-path-traversal": "Tried to read files outside the website",
  log4shell: "Tried the Log4Shell attack",
  "log-cmd-injection": "Tried to run commands on the server",
  "log-reverse-shell": "Tried to open a remote control channel",
  "log-xss": "Tried to plant script in a page",
  "log-scanner": "Automated scanning tool",
  "log-brute-force": "Repeated failed sign-ins",
};

export function logEventLabel(category: string): string {
  return LOG_EVENTS[category] ?? category.replace(/^log-/, "").replace(/-/g, " ");
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// How sure Ares is of a finding, from the kind of proof it holds. The badge
// says only what the evidence supports: a version match is never "Proven".
export type ProofState = "proven" | "version" | "observed";

const ACTIVE_PROOF = new Set(["callback", "computed", "differential", "answer"]);

export function proofState(kind: string | undefined): ProofState {
  if (kind && ACTIVE_PROOF.has(kind)) return "proven";
  if (kind === "version") return "version";
  return "observed";
}

export function proofStateInfo(state: ProofState): StatusInfo {
  switch (state) {
    case "proven":
      return {
        label: "Proven",
        tone: "good",
        hint: "Ares made the target show this weakness with a harmless test, and recorded the exchange.",
      };
    case "version":
      return {
        label: "Version confirmed, not attacked",
        tone: "warn",
        hint: "The software version matches a known weakness. Ares did not try to use it.",
      };
    default:
      return {
        label: "Observed",
        tone: "neutral",
        hint: "Ares saw the signs of this weakness but did not reproduce it.",
      };
  }
}

// Why the exchange proves the weakness, one sentence per kind of proof.
const PROOF_WHY: Record<string, string> = {
  callback:
    "Ares asked the target to visit a one-time address that only Ares knows. The visit itself is the proof: the code was made for this finding alone and shown nowhere else.",
  computed:
    "Ares asked the server to work out a sum it chose at random. Only a server that runs what it is sent could answer with the right result between the markers.",
  differential:
    "The same request was refused without the trick and let through with it, so the trick is what opened the door.",
  answer: "Ares asked a read-only question and the service answered it without asking for a password.",
  version:
    "The version the target reports falls inside the range a published advisory names as weak. Ares did not try to use the weakness.",
};

export function proofWhy(kind: string): string | undefined {
  return PROOF_WHY[kind];
}

// The risk score's band, in words and a tone. 0 means nothing is open.
export function riskRatingInfo(score: number): StatusInfo {
  if (score === 0) return { label: "Nothing open", tone: "good", hint: "No open findings count towards the score." };
  if (score >= 60) return { label: "High", tone: "bad", hint: "Serious findings are still open." };
  if (score >= 25) return { label: "Medium", tone: "warn", hint: "Some important findings are still open." };
  return { label: "Low", tone: "good", hint: "Only minor findings are still open." };
}

// How the risk score moved since the first test shown, in words.
export function riskChangeText(first: number, now: number, tests: number): string {
  if (tests < 2) return "Run another test to see the trend.";
  if (now < first) return `Down from ${first} after the first test.`;
  if (now > first) return `Up from ${first} after the first test.`;
  return `Unchanged since the first test.`;
}

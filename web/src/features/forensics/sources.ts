import type { JsonObject } from "@bufbuild/protobuf";
import {
  baseName,
  fromFiles,
  head,
  isZip,
  looksLikeText,
  packStored,
  readZip,
  sha256Hex,
  toBase64,
  type LeftOut,
  type Picked,
} from "./files.ts";
import { indicatorsFor, type Feed } from "./indicators.ts";

// The places evidence can come from, and for each one what Ares reads and
// which checks it runs. Every source is read offline: Ares never talks to the
// phone, server or network the evidence came from.

export type SourceId = "files" | "android" | "iphone" | "network" | "windows";

export interface OptionDef {
  id: string;
  label: string;
  description: string;
  on: boolean;
  // Shown only for these files (for example, app checks only for an APK).
  when?: (names: string[]) => boolean;
}

export interface SourceDef {
  id: SourceId;
  title: string;
  blurb: string;
  heading: string;
  intro: string;
  fileLabel: string;
  fileHelp: string;
  // A folder can be chosen as well as files (a phone collection or a backup).
  folder: boolean;
  button: string;
  placeholder: string;
  options: OptionDef[];
}

const THREATS: OptionDef = {
  id: "threats",
  label: "Compare with known threats",
  description:
    "Uses the workspace's threat indicators below: file fingerprints, domains, addresses and apps that are known to be bad.",
  on: true,
};

export const SOURCES: SourceDef[] = [
  {
    id: "files",
    title: "Files & bundles",
    blurb: "Logs, docs, images, email, ZIP/TAR/7z, WordPress, APK",
    heading: "Add files",
    intro:
      "Choose files or whole bundles. Each one is fingerprinted the moment it arrives, bundles are opened safely, and every file inside is checked for what it really is.",
    fileLabel: "Files",
    fileHelp:
      "Any file, or a bundle: ZIP, TAR, TAR.GZ or 7-Zip. A website backup such as WordPress and Android apps (APK) get their own checks. Up to 20 MB each.",
    folder: false,
    button: "Add evidence",
    placeholder: "Web server 2, collected by Dana Reyes",
    options: [
      {
        id: "wpcore",
        label: "Compare WordPress files with the official ones",
        description:
          "Spots changed or added core files in a WordPress backup. Asks wordpress.org for the official list, so it needs internet access.",
        on: false,
      },
      {
        id: "appservers",
        label: "Find and test the servers this app talks to",
        description:
          "Works out the app's servers from its contents. Only servers inside the case's scope are tested.",
        on: true,
        when: (names) => names.some((n) => n.toLowerCase().endsWith(".apk")),
      },
      {
        id: "logs",
        label: "Read them as logs",
        description: "Finds signs of attack in log files and puts them in order as a timeline.",
        on: false,
      },
      {
        id: "email",
        label: "Read them as email",
        description:
          "Checks a saved message (.eml) or mailbox (mbox) for a faked sender, failed sender checks and dangerous attachments. No link is opened.",
        on: false,
      },
      {
        id: "browser",
        label: "Read them as browser history",
        description:
          "Checks bookmarks or an exported history for look-alike addresses, script links and direct program downloads. No page is visited.",
        on: false,
      },
      { ...THREATS, description: "Looks for file fingerprints, addresses and domains that are known to be bad, using the workspace's threat indicators below." },
    ],
  },
  {
    id: "android",
    title: "Android phone",
    blurb: "An AndroidQF collection from the phone",
    heading: "Add an Android collection",
    intro:
      "Choose an AndroidQF collection, as a folder or a ZIP. It holds what the phone copied over USB: the app list with each app's fingerprint and signing certificate, running apps, settings and logs. Ares reads only that folder and never touches the phone.",
    fileLabel: "Collection",
    fileHelp: "An AndroidQF folder or its ZIP.",
    folder: true,
    button: "Add collection",
    placeholder: "Journalist handset, collected by Dana Reyes",
    options: [
      {
        id: "apps",
        label: "Check installed apps and certificates",
        description:
          "Matches every app id, APK fingerprint and signing certificate against known spyware and stalkerware, and flags sideloaded apps that ask for stalkerware permissions.",
        on: true,
      },
      {
        id: "intrusion",
        label: "Read intrusion and connection logs",
        description:
          "Reads the phone's own security, DNS and connection records offline. A logged connection is an attempt, not proof of contact.",
        on: true,
      },
      THREATS,
    ],
  },
  {
    id: "iphone",
    title: "iPhone",
    blurb: "A local backup, profiles or launch items",
    heading: "Add an iPhone backup",
    intro:
      "Choose a local Finder or iTunes backup folder, its ZIP, or the backup's Info, Manifest and Status files. Configuration profiles (.mobileconfig) and Mac or iPhone launch items (.plist) can be added too. Ares reads only those files and never contacts the device.",
    fileLabel: "Backup",
    fileHelp: "A backup folder, its ZIP, or individual .plist and .mobileconfig files.",
    folder: true,
    button: "Add backup",
    placeholder: "Executive's iPhone, backed up by Dana Reyes",
    options: [
      {
        id: "backup",
        label: "Read the device and app records",
        description:
          "Reads which device it is, whether the backup is encrypted, and every installed app, and matches app ids and addresses against known threats.",
        on: true,
      },
      {
        id: "profiles",
        label: "Check profiles and launch items",
        description:
          "Flags a profile that installs a root certificate or enrolls the device in management, and a launch item that runs a downloader when it starts.",
        on: true,
      },
      THREATS,
    ],
  },
  {
    id: "network",
    title: "Network DNS log",
    blurb: "Pi-hole, router or dnsmasq export, or a connection table",
    heading: "Add a network log",
    intro:
      "Choose a DNS query log from a Pi-hole, dnsmasq, AdGuard Home, BIND or router. One log covers every phone, laptop and TV behind it. Connection tables (netstat, ss, conntrack or a Zeek conn.log) are read too. Nothing is looked up or contacted.",
    fileLabel: "Logs",
    fileHelp: "Text logs or exports, or a ZIP of them. Up to 64 MB each.",
    folder: false,
    button: "Add logs",
    placeholder: "Home router, exported by Dana Reyes",
    options: [
      {
        ...THREATS,
        description:
          "Matches every looked-up name, answer and connection against the workspace's threat indicators. A lookup is an attempt, not proof of a reply.",
      },
    ],
  },
  {
    id: "windows",
    title: "Windows records",
    blurb: "Event logs, autostart exports, hosts and download marks",
    heading: "Add Windows records",
    intro:
      "Choose records copied off a Windows computer: event logs exported as XML or CSV, autostart exports (registry Run keys, scheduled tasks, services or an Autoruns CSV), the hosts file, and a downloaded file's Zone.Identifier. Ares reads only the copies.",
    fileLabel: "Records",
    fileHelp: "Text exports, or a ZIP or folder of them. Up to 64 MB each.",
    folder: true,
    button: "Add records",
    placeholder: "Finance laptop, collected by Dana Reyes",
    options: [
      {
        id: "events",
        label: "Read event logs",
        description:
          "Raises suspicious program launches, PowerShell downloaders, new services and tasks, new accounts, a cleared log and bursts of failed sign-ins.",
        on: true,
      },
      {
        id: "autostart",
        label: "Check what starts automatically",
        description:
          "Flags start-up entries that run a downloader or encoded script, or that start from a temporary folder.",
        on: true,
      },
      {
        id: "downloads",
        label: "Check download origins and the hosts file",
        description:
          "Reads where a downloaded file came from (it survives a cleared history) and whether the hosts file sends a name somewhere unexpected.",
        on: true,
      },
      THREATS,
    ],
  },
];

export function sourceDef(id: SourceId): SourceDef {
  return SOURCES.find((s) => s.id === id) ?? SOURCES[0]!;
}

// --- planning ----------------------------------------------------------------

export interface PlannedCheck {
  module: string;
  label: string;
  running: string;
  params: JsonObject;
}

export interface Plan {
  checks: PlannedCheck[];
  leftOut: LeftOut[];
  // What the run card calls the evidence ("journalist-androidqf.zip").
  title: string;
}

export interface PlanInput {
  source: SourceId;
  files: File[];
  origin: string;
  options: Record<string, boolean>;
  feeds: Feed[];
}

const MB = 1024 * 1024;
// Files travel inside the request, so each one is bounded here with a clear
// message instead of failing on the way.
export const MAX_FILE_BYTES = 20 * MB;
const MAX_CUSTODY_BYTES = 200 * MB;
const MAX_READ_BYTES = 64 * MB;
const MAX_MATCH_TEXT = 16 * MB;

const CHECK_LABEL: Record<string, { label: string; running: string }> = {
  triage: { label: "Fingerprinting evidence", running: "reading bytes…" },
  androidqf: { label: "Checking the phone's apps and logs", running: "reading the collection…" },
  iosbackup: { label: "Reading the device and app records", running: "reading the backup…" },
  persistplist: { label: "Checking profiles and launch items", running: "reading items…" },
  dnslogscan: { label: "Reading DNS lookups", running: "reading lookups…" },
  connrecord: { label: "Reading connection tables", running: "reading connections…" },
  eventlog: { label: "Reading event logs", running: "reading events…" },
  winpersist: { label: "Checking what starts automatically", running: "reading entries…" },
  winartifacts: { label: "Checking download origins and the hosts file", running: "reading records…" },
  logscan: { label: "Reading logs for signs of attack", running: "reading lines…" },
  mailheader: { label: "Reading email headers and links", running: "reading messages…" },
  browserhist: { label: "Reading browser history", running: "reading addresses…" },
  iocmatch: { label: "Comparing with known threats", running: "comparing…" },
  apkbackend: { label: "Finding the servers the app talks to", running: "reading the app…" },
};

export function checkLabel(module: string): { label: string; running: string } {
  return CHECK_LABEL[module] ?? { label: module, running: "working…" };
}

const check = (module: string, params: object): PlannedCheck => ({
  module,
  ...checkLabel(module),
  params: params as JsonObject,
});

interface Loaded {
  name: string;
  data: Uint8Array;
  text: boolean;
}

// The common folder name of a chosen folder, for naming its custody bundle.
function folderName(entries: Picked[]): string | null {
  const first = entries[0]?.name ?? "";
  const top = first.includes("/") ? first.split("/")[0]! : "";
  return top && entries.every((e) => e.name.startsWith(top + "/")) ? top : null;
}

// expand opens chosen ZIPs and keeps the chosen files, with what was given for
// custody: each chosen file (a ZIP is recorded as it is), or for a folder one
// bundle of the files Ares read from it.
async function expand(files: File[], open: boolean) {
  const entries: Picked[] = [];
  const leftOut: LeftOut[] = [];
  const zips: File[] = [];
  const loose: File[] = [];
  for (const f of files) {
    if (open && isZip(f.name)) {
      const z = await readZip(f);
      entries.push(...z.entries);
      leftOut.push(...z.leftOut);
      zips.push(f);
    } else {
      loose.push(f);
    }
  }
  entries.push(...fromFiles(loose));
  return { entries, leftOut, zips, loose };
}

async function load(p: Picked): Promise<Loaded> {
  const data = await p.bytes();
  return { name: p.name, data, text: looksLikeText(data) };
}

async function custody(
  zips: File[],
  loose: File[],
  read: Loaded[],
  origin: string,
): Promise<{ items: JsonObject[]; leftOut: LeftOut[] }> {
  const src: JsonObject = origin ? { source: origin } : {};
  const items: JsonObject[] = [];
  const leftOut: LeftOut[] = [];
  for (const z of zips) {
    if (z.size > MAX_CUSTODY_BYTES) {
      leftOut.push({ name: z.name, reason: "it is larger than 200 MB, so it was read but not kept as evidence" });
      continue;
    }
    items.push({ name: z.name, base64: toBase64(new Uint8Array(await z.arrayBuffer())), ...src });
  }
  const looseNames = new Set(loose.map((f) => f.webkitRelativePath || f.name));
  const fromLoose = read.filter((r) => looseNames.has(r.name));
  const folder = folderName(fromLoose.map((r) => ({ name: r.name, size: r.data.length, bytes: async () => r.data })));
  if (folder && fromLoose.length > 1) {
    const packed = packStored(fromLoose.map((r) => ({ name: r.name, data: r.data })));
    if (packed.length > MAX_CUSTODY_BYTES) {
      leftOut.push({ name: folder, reason: "the files read from it add up to more than 200 MB, so they were read but not kept as evidence" });
    } else {
      items.push({ name: `${folder}.zip`, base64: toBase64(packed), ...src });
    }
  } else {
    for (const r of fromLoose) items.push({ name: r.name, base64: toBase64(r.data), ...src });
  }
  return { items, leftOut };
}

const ext = (n: string) => n.toLowerCase().split(".").pop() ?? "";
const BINARY_EXT = new Set(["apk", "so", "dex", "odex", "oat", "jar", "jpg", "jpeg", "png", "gif", "webp", "mp4", "mp3", "db", "sqlite"]);

// planChecks reads the chosen evidence and decides which checks run, with the
// exact parameters each engine module is given.
export async function planChecks(input: PlanInput): Promise<Plan> {
  const { source, files, origin, options, feeds } = input;
  const on = (id: string) => options[id] === true;
  const threats = on("threats");
  const withIndicators = (module: string) => (threats ? { indicators: indicatorsFor(module, feeds) } : {});
  const src = origin ? { source: origin } : {};
  const first = files[0];
  const title =
    files.length === 0
      ? "Evidence"
      : (first!.webkitRelativePath ? first!.webkitRelativePath.split("/")[0]! : first!.name) +
        (files.length > 1 && !first!.webkitRelativePath ? ` and ${files.length - 1} more` : "");

  if (source === "files") {
    const loaded = await Promise.all(fromFiles(files).map(load));
    const items = loaded.map((l) => ({ name: l.name, base64: toBase64(l.data), ...src }));
    const checks: PlannedCheck[] = [check("triage", { items, verifyWordPressCore: on("wpcore") })];
    if (on("appservers")) {
      for (const it of items.filter((i) => i.name.toLowerCase().endsWith(".apk"))) {
        checks.push(check("apkbackend", { apkBase64: it.base64, name: it.name }));
      }
    }
    if (on("logs")) checks.push(check("logscan", { items }));
    if (on("email")) checks.push(check("mailheader", { items, ...withIndicators("mailheader") }));
    if (on("browser")) checks.push(check("browserhist", { items, ...withIndicators("browserhist") }));
    if (threats) {
      const observations = await Promise.all(
        loaded.map(async (l) => ({
          name: l.name,
          hash: await sha256Hex(l.data),
          ...(l.text ? { text: new TextDecoder().decode(l.data.subarray(0, MAX_MATCH_TEXT)) } : {}),
          ...src,
        })),
      );
      checks.push(check("iocmatch", { observations, indicators: indicatorsFor("iocmatch", feeds) }));
    }
    return { checks, leftOut: [], title };
  }

  const { entries, leftOut, zips, loose } = await expand(files, true);
  const read: Loaded[] = [];
  const binaries: string[] = [];
  const keep = async (p: Picked) => {
    if (p.size > MAX_READ_BYTES) {
      leftOut.push({ name: p.name, reason: "it is larger than 64 MB" });
      return;
    }
    const l = await load(p);
    read.push(l);
    return l;
  };
  const textItems = (ls: Loaded[]) =>
    ls.map((l) => ({ name: l.name, text: new TextDecoder().decode(l.data), ...src }));
  const checks: PlannedCheck[] = [];

  if (source === "android") {
    const wanted = entries.filter((e) => {
      if (BINARY_EXT.has(ext(e.name))) {
        binaries.push(e.name);
        return false;
      }
      return true;
    });
    for (const e of wanted) await keep(e);
    const text = read.filter((l) => {
      if (!l.text) leftOut.push({ name: l.name, reason: "it is not a text record" });
      return l.text;
    });
    const intrusion = (n: string) => n.toLowerCase().includes("intrusion");
    const pick = text.filter((l) => (intrusion(l.name) ? on("intrusion") : on("apps")));
    const hasApps = text.some((l) => /package|apps|application/.test(baseName(l.name).toLowerCase()));
    if (on("apps") && !hasApps) {
      leftOut.push({
        name: "App list",
        reason: "the collection has no app list (packages.json), so installed apps were not fingerprinted",
      });
    }
    if (on("intrusion") && !text.some((l) => intrusion(l.name))) {
      leftOut.push({
        name: "Intrusion logs",
        reason:
          "the collection has no intrusion logs (Android Intrusion Logging was off or not exported), so connection attempts were not checked",
      });
    }
    if (binaries.length > 0) {
      leftOut.push({
        name: `${binaries.length} app ${binaries.length === 1 ? "package" : "packages"} and binary files`,
        reason: "they were not opened; apps are checked by the fingerprints in the app list instead",
      });
    }
    const c = await custody(zips, loose, read, origin);
    leftOut.push(...c.leftOut);
    if (c.items.length > 0) checks.push(check("triage", { items: c.items }));
    if (pick.length > 0) checks.push(check("androidqf", { items: textItems(pick), ...withIndicators("androidqf") }));
    return { checks, leftOut, title };
  }

  if (source === "iphone") {
    const MANIFESTS = new Set(["info.plist", "manifest.plist", "status.plist"]);
    const isManifest = (n: string) => MANIFESTS.has(baseName(n).toLowerCase());
    const isItem = (n: string) => !isManifest(n) && ["plist", "mobileconfig"].includes(ext(n));
    const manifests: Loaded[] = [];
    const items: Loaded[] = [];
    let other = 0;
    for (const e of entries) {
      if (isManifest(e.name) && on("backup")) {
        const l = await keep(e);
        if (l) manifests.push(l);
      } else if (isItem(e.name) && on("profiles")) {
        const l = await keep(e);
        if (l) items.push(l);
      } else {
        other++;
      }
    }
    if (on("backup") && manifests.length === 0) {
      leftOut.push({
        name: "Backup records",
        reason: "no Info.plist, Manifest.plist or Status.plist was found, so the device and its apps were not read",
      });
    }
    if (other > 0) {
      leftOut.push({
        name: `${other} other ${other === 1 ? "file" : "files"} in the backup`,
        reason: "messages, Safari history and the other databases inside a backup are not read yet",
      });
    }
    const b64 = (ls: Loaded[]) => ls.map((l) => ({ name: l.name, base64: toBase64(l.data), ...src }));
    const c = await custody(zips, loose, read, origin);
    leftOut.push(...c.leftOut);
    if (c.items.length > 0) checks.push(check("triage", { items: c.items }));
    if (manifests.length > 0) checks.push(check("iosbackup", { items: b64(manifests), ...withIndicators("iosbackup") }));
    if (items.length > 0) checks.push(check("persistplist", { items: b64(items), ...withIndicators("persistplist") }));
    return { checks, leftOut, title };
  }

  // Network and Windows records are text: route each file to the check that
  // reads its format, and say plainly which files none of them reads.
  for (const e of entries) await keep(e);
  const text: Loaded[] = [];
  for (const l of read) {
    if (l.text) {
      text.push(l);
    } else if (ext(l.name) === "evtx") {
      leftOut.push({
        name: l.name,
        reason: "a raw .evtx file is not read; export it as XML with wevtutil qe <log> /f:xml and add that",
      });
    } else if (["db", "sqlite"].includes(ext(l.name))) {
      leftOut.push({ name: l.name, reason: "a database file is not read; export the query log as text and add that" });
    } else {
      leftOut.push({ name: l.name, reason: "it is not a text log" });
    }
  }
  const c = await custody(zips, loose, read, origin);
  leftOut.push(...c.leftOut);
  if (c.items.length > 0) checks.push(check("triage", { items: c.items }));

  if (source === "network") {
    const conn = (s: string) =>
      (s.includes("src=") && s.includes("dst=")) ||
      s.includes("users:((") ||
      s.includes("#separator") ||
      s.includes("id.orig_h") ||
      (s.includes("Proto") && s.includes("Local Address"));
    const tables = text.filter((l) => conn(head(l.data)));
    const logs = text.filter((l) => !tables.includes(l));
    if (logs.length > 0) checks.push(check("dnslogscan", { items: textItems(logs), ...withIndicators("dnslogscan") }));
    if (tables.length > 0) checks.push(check("connrecord", { items: textItems(tables), ...withIndicators("connrecord") }));
    return { checks, leftOut, title };
  }

  // Windows.
  const events: Loaded[] = [];
  const autostart: Loaded[] = [];
  const artifacts: Loaded[] = [];
  for (const l of text) {
    const s = head(l.data);
    const b = baseName(l.name).toLowerCase();
    if ((s.includes("<Event") && s.includes("<System")) || (s.includes("Event ID") && s.includes(","))) {
      if (on("events")) events.push(l);
    } else if (
      s.includes("Windows Registry Editor") ||
      s.includes("REGEDIT4") ||
      (s.includes("Launch String") && s.includes("Entry Location")) ||
      s.includes("Task To Run") ||
      s.includes("TaskName:") ||
      s.includes("BINARY_PATH_NAME")
    ) {
      if (on("autostart")) autostart.push(l);
    } else if (s.includes("[ZoneTransfer]") || b.includes("zone.identifier") || b === "hosts" || b === "hosts.txt") {
      if (on("downloads")) artifacts.push(l);
    } else {
      leftOut.push({ name: l.name, reason: "it is not a Windows record Ares recognises" });
    }
  }
  if (events.length > 0) checks.push(check("eventlog", { items: textItems(events), ...withIndicators("eventlog") }));
  if (autostart.length > 0) checks.push(check("winpersist", { items: textItems(autostart), ...withIndicators("winpersist") }));
  if (artifacts.length > 0) checks.push(check("winartifacts", { items: textItems(artifacts), ...withIndicators("winartifacts") }));
  return { checks, leftOut, title };
}

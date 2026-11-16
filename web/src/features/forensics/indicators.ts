import { useSyncExternalStore } from "react";

// Threat indicators: the known-bad fingerprints, domains, addresses and app ids
// every forensic check compares against. An operator loads a published feed
// (an Amnesty MVT STIX file, a STIX 2.1 bundle, a MISP event) or their own list
// once for the workspace, and every check after that uses it. Nothing is ever
// fetched: Ares ships no feed, and a value here is never contacted.

export type IndicatorType = "domain" | "url" | "ip" | "sha256" | "sha1" | "md5" | "appid";

export interface Indicator {
  type: IndicatorType;
  value: string;
  // The threat or campaign it belongs to, as the publisher names it.
  label?: string;
  // Provenance only: it never changes how serious a match is.
  tier?: string;
  confidence?: "primary" | "secondary";
  // The publisher has retracted it: a match is a note, never an alert.
  withdrawn?: boolean;
}

export type FeedFormat = "stix" | "misp" | "list";

export interface Feed {
  id: string;
  name: string;
  format: FeedFormat;
  loadedAt: string; // RFC3339
  inUse: boolean;
  indicators: Indicator[];
}

// --- parsing -----------------------------------------------------------------

const HEX = /^[0-9a-f]+$/;
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6 = /^[0-9a-f:]+$/i;

// refang undoes the defanging feeds use so a value is not clickable:
// example[.]com, hxxp://, 1.2.3[.]4.
export function refang(v: string): string {
  return v
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
    .replace(/\[:\]/g, ":")
    .replace(/^hxxp/i, "http")
    .replace(/^fxp/i, "ftp");
}

export function inferType(v: string): IndicatorType | null {
  const s = v.trim();
  const low = s.toLowerCase();
  if (s === "") return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return "url";
  if (HEX.test(low)) {
    if (low.length === 64) return "sha256";
    if (low.length === 40) return "sha1";
    if (low.length === 32) return "md5";
  }
  if (IPV4.test(s) || (s.includes(":") && s.split(":").length > 2 && IPV6.test(s))) return "ip";
  if (low.includes(".") && !/[\s/]/.test(low)) return "domain";
  return null;
}

function clean(ind: Indicator): Indicator | null {
  const value = refang(ind.value);
  if (value === "") return null;
  const type = ind.type;
  if (type === "sha256" || type === "sha1" || type === "md5") {
    const low = value.toLowerCase();
    const want = { sha256: 64, sha1: 40, md5: 32 }[type];
    if (!HEX.test(low) || low.length !== want) return null;
    return { ...ind, value: low };
  }
  if (type === "domain") {
    const d = value.toLowerCase().replace(/\.$/, "");
    return d.includes(".") ? { ...ind, value: d } : null;
  }
  return { ...ind, value };
}

// STIX patterns compare an object path to a quoted value:
// [domain-name:value = 'x'] OR [file:hashes.'SHA-256' = 'y'].
const COMPARISON = /([A-Za-z0-9:_.'-]+)\s*=\s*'((?:[^'\\]|\\.)+)'/g;

function stixPathType(path: string): IndicatorType | null {
  const p = path.toLowerCase();
  if (p.includes("sha-256") || p.includes("sha256")) return "sha256";
  if (p.includes("sha-1") || p.includes("sha1")) return "sha1";
  if (p.includes("md5")) return "md5";
  if (p.includes("domain-name:value")) return "domain";
  if (p.includes("ipv4-addr:value") || p.includes("ipv6-addr:value")) return "ip";
  if (p.includes("url:value")) return "url";
  // Amnesty MVT names Android and iOS apps by their package / bundle id.
  if (p.includes("app:id")) return "appid";
  return null;
}

function confidenceTier(c: unknown): Indicator["confidence"] {
  if (typeof c !== "number") return undefined;
  if (c >= 80) return "primary";
  if (c > 0) return "secondary";
  return undefined;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const firstText = (...lists: unknown[]): string | undefined => {
  for (const l of lists) {
    if (Array.isArray(l)) {
      const s = l.find((x): x is string => typeof x === "string" && x.trim() !== "");
      if (s) return s;
    }
  }
  return undefined;
};

// parseSTIX mirrors the engine's own STIX reader (iocmatch), and adds what
// MVT bundles carry: the malware an indicator points to, through its
// "indicates" relationship, names the threat.
function parseSTIX(objects: unknown[]): Indicator[] {
  const names = new Map<string, string>();
  for (const o of objects) {
    if (isObj(o) && (o["type"] === "malware" || o["type"] === "threat-actor" || o["type"] === "campaign")) {
      if (typeof o["id"] === "string" && typeof o["name"] === "string") names.set(o["id"], o["name"]);
    }
  }
  const indicates = new Map<string, string>();
  for (const o of objects) {
    if (isObj(o) && o["type"] === "relationship" && o["relationship_type"] === "indicates") {
      const target = names.get(String(o["target_ref"]));
      if (target) indicates.set(String(o["source_ref"]), target);
    }
  }
  const out: Indicator[] = [];
  for (const o of objects) {
    if (!isObj(o) || o["type"] !== "indicator" || typeof o["pattern"] !== "string") continue;
    const pt = o["pattern_type"];
    if (typeof pt === "string" && pt !== "" && pt.toLowerCase() !== "stix") continue;
    const label =
      indicates.get(String(o["id"])) ??
      (typeof o["name"] === "string" && o["name"] ? o["name"] : undefined) ??
      firstText(o["labels"], o["indicator_types"]);
    const tier = firstText(o["indicator_types"], o["labels"]);
    const confidence = confidenceTier(o["confidence"]);
    const withdrawn = o["revoked"] === true;
    for (const m of o["pattern"].matchAll(COMPARISON)) {
      const type = stixPathType(m[1]!);
      if (!type) continue;
      out.push({
        type,
        value: m[2]!.replace(/\\'/g, "'"),
        ...(label ? { label } : {}),
        ...(tier ? { tier } : {}),
        ...(confidence ? { confidence } : {}),
        ...(withdrawn ? { withdrawn } : {}),
      });
    }
  }
  return out;
}

const MISP_TYPES: Record<string, IndicatorType> = {
  domain: "domain",
  hostname: "domain",
  url: "url",
  link: "url",
  uri: "url",
  "ip-dst": "ip",
  "ip-src": "ip",
  sha256: "sha256",
  sha1: "sha1",
  md5: "md5",
};

function parseMISP(event: Obj): Indicator[] {
  const label = typeof event["info"] === "string" ? event["info"] : undefined;
  const attrs: unknown[] = Array.isArray(event["Attribute"]) ? [...event["Attribute"]] : [];
  if (Array.isArray(event["Object"])) {
    for (const o of event["Object"]) if (isObj(o) && Array.isArray(o["Attribute"])) attrs.push(...o["Attribute"]);
  }
  const out: Indicator[] = [];
  for (const a of attrs) {
    if (!isObj(a) || typeof a["type"] !== "string" || typeof a["value"] !== "string") continue;
    let t = a["type"];
    let v = a["value"];
    // Composite attributes ("domain|ip", "filename|sha256") carry two values.
    if (t.includes("|")) {
      const [t1, t2] = t.split("|");
      const [v1, v2] = v.split("|");
      if (t1 && MISP_TYPES[t1] && v1) {
        t = t1;
        v = v1;
      } else if (t2 && v2) {
        t = t2;
        v = v2;
      }
    }
    const type = MISP_TYPES[t];
    if (!type) continue;
    // An attribute the publisher marks as not for detection is context, not
    // an indicator; a deleted one is kept as withdrawn.
    if (a["to_ids"] === false) continue;
    const withdrawn = a["deleted"] === true;
    out.push({ type, value: v, ...(label ? { label } : {}), ...(withdrawn ? { withdrawn } : {}) });
  }
  return out;
}

function parseList(text: string, label?: string): Indicator[] {
  const out: Indicator[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (line === "" || line.startsWith("#") || line.startsWith("//")) continue;
    // A CSV row: the first cell is the value.
    const value = refang(line.split(/[,;\t]/)[0]!.replace(/^"|"$/g, ""));
    const type = inferType(value);
    if (type) out.push({ type, value, ...(label ? { label } : {}) });
  }
  return out;
}

export interface Parsed {
  format: FeedFormat;
  indicators: Indicator[];
  // Entries the feed held that are not something a check can compare with.
  skipped: number;
}

// parseFeed reads whatever the operator loaded: a STIX 2.1 bundle (Amnesty MVT
// publishes its indicators this way), a MISP event, or a plain list with one
// value per line.
export function parseFeed(text: string, name: string): Parsed {
  const t = text.trim();
  let format: FeedFormat = "list";
  let found: Indicator[] = [];
  if (t.startsWith("{") || t.startsWith("[")) {
    let doc: unknown;
    try {
      doc = JSON.parse(t);
    } catch {
      throw new Error("This file looks like JSON but could not be read. Check that it is complete.");
    }
    const objects = isObj(doc) && Array.isArray(doc["objects"]) ? doc["objects"] : Array.isArray(doc) ? doc : null;
    const misp = isObj(doc)
      ? isObj(doc["Event"])
        ? [doc["Event"]]
        : Array.isArray(doc["response"])
          ? doc["response"].map((r) => (isObj(r) && isObj(r["Event"]) ? r["Event"] : null)).filter(isObj)
          : []
      : [];
    if (misp.length > 0) {
      format = "misp";
      found = misp.flatMap(parseMISP);
    } else if (objects && objects.some((o) => isObj(o) && typeof o["type"] === "string")) {
      format = "stix";
      found = parseSTIX(objects);
    } else if (isObj(doc) && doc["type"] === "indicator") {
      format = "stix";
      found = parseSTIX([doc]);
    } else {
      throw new Error("This JSON is neither a STIX 2.1 bundle nor a MISP event.");
    }
  } else {
    found = parseList(t, name);
  }
  const seen = new Set<string>();
  const indicators: Indicator[] = [];
  let skipped = 0;
  for (const ind of found) {
    const c = clean(ind);
    if (!c) {
      skipped++;
      continue;
    }
    const key = `${c.type}:${c.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    indicators.push(c);
  }
  return { format, indicators, skipped };
}

// --- what each check can compare with ----------------------------------------

// The indicator types each engine module accepts. Some refuse a whole job over
// one type they do not know, so every list is narrowed before it is sent.
const SUPPORTS: Record<string, IndicatorType[]> = {
  iocmatch: ["sha256", "sha1", "md5", "domain", "url", "ip"],
  iocexport: ["sha256", "sha1", "md5", "domain", "url", "ip"],
  androidqf: ["sha256", "sha1", "appid", "domain", "ip"],
  dnslogscan: ["domain", "ip"],
  connrecord: ["ip", "domain"],
  browserhist: ["domain", "ip", "url"],
  eventlog: ["domain", "ip", "url"],
  iosbackup: ["appid", "domain", "ip", "url"],
  mailheader: ["domain", "ip", "url"],
  persistplist: ["domain", "ip", "url"],
  winartifacts: ["domain", "url", "ip", "sha256", "sha1"],
  winpersist: ["domain", "ip", "url"],
};

export function activeIndicators(feeds: Feed[]): (Indicator & { feed: string })[] {
  return feeds.filter((f) => f.inUse).flatMap((f) => f.indicators.map((i) => ({ ...i, feed: f.name })));
}

// indicatorsFor is the list one module is given. Only the known-threat match
// understands withdrawal, so it alone receives withdrawn indicators (and
// reports a match as a note); every other check never sees them, so a
// retracted value can never raise an alert.
export function indicatorsFor(module: string, feeds: Feed[]): Indicator[] {
  const ok = SUPPORTS[module];
  if (!ok) return [];
  const keepWithdrawn = module === "iocmatch";
  return activeIndicators(feeds)
    .filter((i) => ok.includes(i.type) && (keepWithdrawn || !i.withdrawn))
    .map(({ type, value, label, tier, confidence, withdrawn, feed }) => ({
      type,
      value,
      label: label ? `${label}, ${feed}` : feed,
      ...(tier ? { tier } : {}),
      ...(confidence ? { confidence } : {}),
      ...(withdrawn ? { withdrawn } : {}),
    }));
}

export function supportsType(module: string, type: string): boolean {
  return (SUPPORTS[module] ?? []).includes(type as IndicatorType);
}

export interface Provenance {
  feed: string;
  confidence?: Indicator["confidence"];
  withdrawn?: boolean;
}

// provenanceIndex finds which loaded feed an indicator value came from, so a
// finding can say "Primary confidence · Amnesty MVT" even when the check that
// raised it does not carry provenance itself.
export function provenanceIndex(feeds: Feed[]): Map<string, Provenance> {
  const m = new Map<string, Provenance>();
  for (const f of feeds) {
    if (!f.inUse) continue;
    for (const i of f.indicators) {
      const key = i.value.toLowerCase();
      if (!m.has(key)) m.set(key, { feed: f.name, confidence: i.confidence, withdrawn: i.withdrawn });
    }
  }
  return m;
}

// --- where feeds are kept ----------------------------------------------------

// Feeds are kept in this browser, per workspace. A feed can hold thousands of
// values, and keeping it here means it is never sent anywhere until a check
// that uses it runs.

const KEY = (tenantId: string) => `ares.forensics.feeds.${tenantId}`;
const cache = new Map<string, Feed[]>();
const listeners = new Set<() => void>();
const EMPTY: Feed[] = [];

function read(tenantId: string): Feed[] {
  const hit = cache.get(tenantId);
  if (hit) return hit;
  let feeds: Feed[] = EMPTY;
  try {
    const raw = localStorage.getItem(KEY(tenantId));
    if (raw) {
      const v = JSON.parse(raw) as unknown;
      if (Array.isArray(v)) feeds = v as Feed[];
    }
  } catch {
    // Storage is a convenience; without it the feed lasts for this visit.
  }
  cache.set(tenantId, feeds);
  return feeds;
}

function write(tenantId: string, feeds: Feed[]): string | null {
  cache.set(tenantId, feeds);
  listeners.forEach((l) => l());
  try {
    localStorage.setItem(KEY(tenantId), JSON.stringify(feeds));
    return null;
  } catch {
    return "This browser could not keep the feed, so it will be used until the page is closed.";
  }
}

export function useFeeds(tenantId: string): Feed[] {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    () => read(tenantId),
    () => EMPTY,
  );
}

export function addFeed(tenantId: string, feed: Omit<Feed, "id" | "loadedAt" | "inUse">): string | null {
  const next: Feed = {
    ...feed,
    id: crypto.randomUUID(),
    loadedAt: new Date().toISOString(),
    inUse: true,
  };
  // Loading a feed with the same name replaces the older copy.
  return write(tenantId, [...read(tenantId).filter((f) => f.name !== feed.name), next]);
}

export function setFeedInUse(tenantId: string, id: string, inUse: boolean) {
  write(
    tenantId,
    read(tenantId).map((f) => (f.id === id ? { ...f, inUse } : f)),
  );
}

export function removeFeed(tenantId: string, id: string) {
  write(
    tenantId,
    read(tenantId).filter((f) => f.id !== id),
  );
}

/// <reference lib="webworker" />
//
// Independently re-verifies an engagement's tamper-evident audit chain, off the
// main thread. It does not trust the server's "valid" flag: it recomputes every
// entry's SHA-256 exactly as the Go backend does (audit.Entry.computeHash) and
// checks each link, so a tampered entry is caught in the browser.
//
// The hash preimage must match the Go side byte-for-byte:
//   "<seq>\n<timeUTCRFC3339Nano>\n<actor>\n<action>\n<target>\n<detail>\n<prevHash>"
// The backend sends `time` already as UTC RFC3339Nano, i.e. the exact string the
// hash was computed over, so we use it verbatim.

export interface WireEntry {
  seq: number;
  time: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
  prevHash: string;
  hash: string;
}

export interface VerifyRequest {
  entries: WireEntry[];
}

export interface VerifyResult {
  valid: boolean;
  checked: number;
  brokenAt: number | null;
  reason: string;
}

const enc = new TextEncoder();

async function sha256hex(s: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(s));
  const bytes = new Uint8Array(digest);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

async function verify(entries: WireEntry[]): Promise<VerifyResult> {
  let prev = "";
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i) {
      return { valid: false, checked: i, brokenAt: i, reason: `out-of-order seq ${e.seq}` };
    }
    if (e.prevHash !== prev) {
      return { valid: false, checked: i, brokenAt: i, reason: "broken link to previous entry" };
    }
    const preimage = `${e.seq}\n${e.time}\n${e.actor}\n${e.action}\n${e.target}\n${e.detail}\n${e.prevHash}`;
    const computed = await sha256hex(preimage);
    if (computed !== e.hash) {
      return { valid: false, checked: i, brokenAt: i, reason: "entry has been altered" };
    }
    prev = e.hash;
  }
  return { valid: true, checked: entries.length, brokenAt: null, reason: "" };
}

self.onmessage = (ev: MessageEvent<VerifyRequest>) => {
  verify(ev.data.entries)
    .then((result) => (self as DedicatedWorkerGlobalScope).postMessage(result))
    .catch((err) =>
      (self as DedicatedWorkerGlobalScope).postMessage({
        valid: false,
        checked: 0,
        brokenAt: null,
        reason: String(err),
      } satisfies VerifyResult),
    );
};

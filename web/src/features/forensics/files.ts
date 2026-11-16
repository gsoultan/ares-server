// Reading what an operator chose: plain files, a whole folder (a phone
// collection, an iPhone backup) or a ZIP of one. Everything happens in this
// browser; nothing is unpacked on disk and nothing is changed.

export interface Picked {
  // The path inside the folder or ZIP, or the file name.
  name: string;
  size: number;
  bytes: () => Promise<Uint8Array>;
}

// A file left out, and why, so it can be listed under "What could not be checked".
export interface LeftOut {
  name: string;
  reason: string;
}

const MAX_ENTRIES = 20_000;
const MAX_TOTAL = 1024 * 1024 * 1024;

const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;

async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function isZip(name: string): boolean {
  return name.toLowerCase().endsWith(".zip");
}

// readZip lists a ZIP's files from its central directory and reads each one
// on demand. Encrypted entries, ZIP64 archives and unknown compression are
// reported as left out rather than guessed at.
export async function readZip(file: File): Promise<{ entries: Picked[]; leftOut: LeftOut[] }> {
  const buf = new Uint8Array(await file.arrayBuffer());
  const leftOut: LeftOut[] = [];
  // The end-of-central-directory record sits in the last 64 KiB + 22 bytes.
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (u32(buf, i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error(`${file.name} is not a ZIP file Ares can open.`);
  const count = u16(buf, eocd + 10);
  let p = u32(buf, eocd + 16);
  if (count === 0xffff || p === 0xffffffff) {
    throw new Error(`${file.name} is a very large (ZIP64) archive. Choose the folder itself instead.`);
  }
  const entries: Picked[] = [];
  let total = 0;
  for (let n = 0; n < count && n < MAX_ENTRIES; n++) {
    if (u32(buf, p) !== 0x02014b50) break;
    const flags = u16(buf, p + 8);
    const method = u16(buf, p + 10);
    const csize = u32(buf, p + 20);
    const usize = u32(buf, p + 24);
    const nlen = u16(buf, p + 28);
    const xlen = u16(buf, p + 30);
    const clen = u16(buf, p + 32);
    const local = u32(buf, p + 42);
    const name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nlen));
    p += 46 + nlen + xlen + clen;
    if (name.endsWith("/")) continue;
    if (flags & 1) {
      leftOut.push({ name, reason: "it is password-protected" });
      continue;
    }
    if (method !== 0 && method !== 8) {
      leftOut.push({ name, reason: "it uses a compression Ares does not read" });
      continue;
    }
    total += usize;
    if (total > MAX_TOTAL) {
      leftOut.push({ name, reason: "the ZIP is larger than Ares reads in the browser" });
      continue;
    }
    entries.push({
      name,
      size: usize,
      bytes: async () => {
        const start = local + 30 + u16(buf, local + 26) + u16(buf, local + 28);
        const raw = buf.subarray(start, start + csize);
        return method === 0 ? raw.slice() : inflateRaw(raw);
      },
    });
  }
  if (count > MAX_ENTRIES) leftOut.push({ name: file.name, reason: `only the first ${MAX_ENTRIES} files were read` });
  return { entries, leftOut };
}

// fromFiles turns chosen files (or a chosen folder) into entries, named by
// their path inside the folder when there is one.
export function fromFiles(files: File[]): Picked[] {
  return files.map((f) => ({
    name: f.webkitRelativePath || f.name,
    size: f.size,
    bytes: async () => new Uint8Array(await f.arrayBuffer()),
  }));
}

// --- packing a folder for custody --------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// packStored writes the files into one uncompressed ZIP, so a folder is
// recorded as a single piece of evidence whose every member is fingerprinted
// on intake. The bytes of each file are kept exactly as they are.
export function packStored(files: { name: string; data: Uint8Array }[]): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const f of files) {
    const name = enc.encode(f.name);
    const crc = crc32(f.data);
    const head = new Uint8Array(30 + name.length);
    const hv = new DataView(head.buffer);
    hv.setUint32(0, 0x04034b50, true);
    hv.setUint16(4, 20, true);
    hv.setUint16(6, 0x0800, true); // names are UTF-8
    hv.setUint32(14, crc, true);
    hv.setUint32(18, f.data.length, true);
    hv.setUint32(22, f.data.length, true);
    hv.setUint16(26, name.length, true);
    head.set(name, 30);
    const cd = new Uint8Array(46 + name.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, f.data.length, true);
    cv.setUint32(24, f.data.length, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(42, offset, true);
    cd.set(name, 46);
    parts.push(head, f.data);
    central.push(cd);
    offset += head.length + f.data.length;
  }
  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);
  const out = new Uint8Array(offset + cdSize + 22);
  let at = 0;
  for (const part of [...parts, ...central, end]) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

// --- encodings ---------------------------------------------------------------

export function toBase64(data: Uint8Array): string {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < data.length; i += CHUNK) s += String.fromCharCode(...data.subarray(i, i + CHUNK));
  return btoa(s);
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// looksLikeText is true for a file a reader can treat as text: no NUL bytes
// in its first few kilobytes.
export function looksLikeText(data: Uint8Array): boolean {
  const n = Math.min(data.length, 8192);
  for (let i = 0; i < n; i++) if (data[i] === 0) return false;
  return true;
}

export function baseName(path: string): string {
  return path.split("/").pop() ?? path;
}

// sniff reads the start of a text file, for routing it to the check that
// understands it.
export function head(data: Uint8Array, n = 8192): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(data.subarray(0, n));
}

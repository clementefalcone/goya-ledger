const SLH_DSA_OIDS = Array.from({ length: 12 }, (_, index) => `2.16.840.1.101.3.4.3.${20 + index}`);

const ALGORITHM_FAMILIES = [
  { name: "RSA", isQuantumSafe: false, oids: ["1.2.840.113549.1.1.1", "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.10", "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13"] },
  { name: "ECDSA", isQuantumSafe: false, oids: ["1.2.840.10045.2.1", "1.2.840.10045.4.1", "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4"] },
  { name: "Ed25519", isQuantumSafe: false, oids: ["1.3.101.112"] },
  { name: "Ed448", isQuantumSafe: false, oids: ["1.3.101.113"] },
  { name: "DSA", isQuantumSafe: false, oids: ["1.2.840.10040.4.1", "1.2.840.10040.4.3"] },
  { name: "ML-DSA-44", isQuantumSafe: true, oids: ["2.16.840.1.101.3.4.3.17"] },
  { name: "ML-DSA-65", isQuantumSafe: true, oids: ["2.16.840.1.101.3.4.3.18"] },
  { name: "ML-DSA-87", isQuantumSafe: true, oids: ["2.16.840.1.101.3.4.3.19"] },
  { name: "SLH-DSA", isQuantumSafe: true, oids: SLH_DSA_OIDS },
];

const FAMILY_BY_OID = new Map(ALGORITHM_FAMILIES.flatMap((family) => family.oids.map((oid) => [oid, family])));

const SIGNING_TIME_OID = "1.2.840.113549.1.9.5";
const TAG_OID = 0x06;
const TAG_UTC_TIME = 0x17;
const TAG_GENERALIZED_TIME = 0x18;

const VERDICTS = [
  { key: "none", matches: (families) => families.length === 0 },
  { key: "hybrid", matches: (families) => families.some((f) => f.isQuantumSafe) && families.some((f) => !f.isQuantumSafe) },
  { key: "safe", matches: (families) => families.every((f) => f.isQuantumSafe) },
  { key: "vulnerable", matches: () => true },
];

function readLength(bytes, offset) {
  const first = bytes[offset];
  if (first < 0x80) return { length: first, contentStart: offset + 1 };
  if (first === 0x80) return { length: null, contentStart: offset + 1 };
  const byteCount = first & 0x7f;
  let length = 0;
  for (let index = 1; index <= byteCount; index += 1) length = length * 256 + bytes[offset + index];
  return { length, contentStart: offset + 1 + byteCount };
}

function collectPrimitives(bytes, start, end, primitives) {
  let offset = start;
  while (offset < end) {
    const tag = bytes[offset];
    if (tag === 0 && bytes[offset + 1] === 0) return offset + 2;
    const { length, contentStart } = readLength(bytes, offset + 1);
    if (length === null) {
      offset = collectPrimitives(bytes, contentStart, end, primitives);
      continue;
    }
    const contentEnd = contentStart + length;
    if (contentEnd > end) throw new Error(`ASN.1 length ${length} at offset ${offset} exceeds the available ${end - contentStart} bytes`);
    if (tag & 0x20) collectPrimitives(bytes, contentStart, contentEnd, primitives);
    else primitives.push({ tag, content: bytes.subarray(contentStart, contentEnd) });
    offset = contentEnd;
  }
  return offset;
}

function decodeOid(content) {
  const arcs = [];
  let value = 0;
  for (const byte of content) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(value);
      value = 0;
    }
  }
  const head = arcs.shift();
  const root = Math.min(Math.floor(head / 40), 2);
  return [root, head - 40 * root, ...arcs].join(".");
}

function decodeTime(primitive) {
  const text = String.fromCharCode(...primitive.content);
  const fullYear = primitive.tag === TAG_UTC_TIME ? `${Number(text.slice(0, 2)) < 50 ? "20" : "19"}${text}` : text;
  const [, year, month, day, hour, minute, second] = fullYear.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
}

function hexToBytes(hex) {
  const digits = hex.replace(/\s/g, "");
  return Uint8Array.from(digits.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64.replace(/\s/g, "")), (char) => char.charCodeAt(0));
}

export function extractDerBlobs(bytes) {
  const text = new TextDecoder("latin1").decode(bytes);
  if (text.startsWith("%PDF")) {
    return [...text.matchAll(/\/Contents\s*<([0-9A-Fa-f\s]+)>/g)].map((match) => hexToBytes(match[1]));
  }
  const pemBlocks = [...text.matchAll(/-----BEGIN [^-]+-----([\s\S]*?)-----END/g)];
  if (pemBlocks.length > 0) return pemBlocks.map((match) => base64ToBytes(match[1]));
  return [bytes];
}

export function assessFile(bytes) {
  const blobs = extractDerBlobs(bytes);
  const primitives = [];
  for (const blob of blobs) collectPrimitives(blob, 0, blob.length, primitives);

  const families = new Set();
  const signingTimes = [];
  primitives.forEach((primitive, index) => {
    if (primitive.tag !== TAG_OID) return;
    const oid = decodeOid(primitive.content);
    const family = FAMILY_BY_OID.get(oid);
    if (family) families.add(family);
    const next = primitives[index + 1];
    const isTime = next && (next.tag === TAG_UTC_TIME || next.tag === TAG_GENERALIZED_TIME);
    if (oid === SIGNING_TIME_OID && isTime) signingTimes.push(decodeTime(next));
  });

  const found = [...families];
  return {
    verdict: VERDICTS.find((verdict) => verdict.matches(found)).key,
    algorithms: found.map((family) => family.name),
    signingTimes,
    signatureCount: blobs.length,
  };
}

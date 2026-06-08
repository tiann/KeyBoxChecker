import test from "node:test";
import assert from "node:assert/strict";
import { analyzeKeybox, decodeKeyboxBytes, parseKeyboxXml } from "../src/analyzer.js";

function concatBytes(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function derLen(len) {
  if (len < 128) return Uint8Array.of(len);
  const bytes = [];
  while (len) {
    bytes.unshift(len & 0xff);
    len >>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function derWrap(tag, value) {
  return concatBytes(Uint8Array.of(tag), derLen(value.length), value);
}

function derSeq(...parts) { return derWrap(0x30, concatBytes(...parts)); }
function derSet(...parts) { return derWrap(0x31, concatBytes(...parts)); }
function derNull() { return Uint8Array.of(0x05, 0x00); }
function derUtf8(value) { return derWrap(0x0c, new TextEncoder().encode(value)); }
function derBitString(value) { return derWrap(0x03, concatBytes(Uint8Array.of(0), value)); }
function derContext(tag, value) { return derWrap(0xa0 + tag, value); }
function derUtc(value) { return derWrap(0x17, new TextEncoder().encode(value)); }

function derInt(bytes) {
  let value = bytes instanceof Uint8Array ? bytes : Uint8Array.of(bytes);
  while (value.length > 1 && value[0] === 0) value = value.subarray(1);
  if (value[0] & 0x80) value = concatBytes(Uint8Array.of(0), value);
  return derWrap(0x02, value);
}

function derOid(dotted) {
  const nums = dotted.split(".").map(BigInt);
  const out = [Number(nums[0] * 40n + nums[1])];
  for (let n of nums.slice(2)) {
    const stack = [Number(n & 0x7fn)];
    n >>= 7n;
    while (n) {
      stack.unshift(Number((n & 0x7fn) | 0x80n));
      n >>= 7n;
    }
    out.push(...stack);
  }
  return derWrap(0x06, Uint8Array.from(out));
}

function pem(label, bytes) {
  const b64 = Buffer.from(bytes).toString("base64").replace(/(.{64})/g, "$1\n").trim();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
}

function toUtf16LeWithBom(text) {
  return concatBytes(Uint8Array.of(0xff, 0xfe), new Uint8Array(Buffer.from(text, "utf16le")));
}

async function makeSyntheticKeyboxXml() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: Uint8Array.of(1, 0, 1),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  const sigAlg = derSeq(derOid("1.2.840.113549.1.1.11"), derNull());
  const name = derSeq(derSet(derSeq(derOid("2.5.4.3"), derUtf8("KeyBox Checker Test Root"))));
  const validity = derSeq(derUtc("250101000000Z"), derUtc("350101000000Z"));
  const tbs = derSeq(
    derContext(0, derInt(2)),
    derInt(Uint8Array.of(0x42)),
    sigAlg,
    name,
    validity,
    name,
    spki,
  );
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, keyPair.privateKey, tbs));
  const cert = derSeq(tbs, sigAlg, derBitString(signature));
  const privateKeyPem = pem("PRIVATE KEY", pkcs8);
  const certPem = pem("CERTIFICATE", cert);
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<AndroidAttestation>
  <NumberOfKeyboxes>1</NumberOfKeyboxes>
  <Keybox DeviceID="unit-test-device">
    <Key algorithm="rsa">
      <PrivateKey format="pem">
${privateKeyPem}
      </PrivateKey>
      <CertificateChain>
        <NumberOfCertificates>1</NumberOfCertificates>
        <Certificate format="pem">
${certPem}
        </Certificate>
      </CertificateChain>
    </Key>
  </Keybox>
</AndroidAttestation>`;
  return { xml, certPem };
}

test("parses UTF-16 keybox XML", async () => {
  const { xml } = await makeSyntheticKeyboxXml();
  const decoded = decodeKeyboxBytes(toUtf16LeWithBom(xml));
  const parsed = parseKeyboxXml(decoded);
  assert.equal(parsed.keyboxes.length, 1);
  assert.equal(parsed.keyboxes[0].deviceId, "unit-test-device");
  assert.deepEqual(parsed.keyboxes[0].keys.map(k => k.algorithm), ["rsa"]);
  assert.equal(parsed.keyboxes[0].keys[0].certificatesPem.length, 1);
});

test("analyzes a generated keybox locally without external fixtures", async () => {
  const { xml, certPem } = await makeSyntheticKeyboxXml();
  const trustData = {
    version: "test",
    fetchedAt: "2026-06-08T00:00:00Z",
    status: { entries: {} },
    roots: [{ id: "test-root", label: "Test root", kind: "test", level: "trusted", pem: certPem }],
  };
  const result = await analyzeKeybox(xml, trustData, new Date("2026-06-08T10:00:00Z"));
  const key = result.keyboxes[0].keys[0];
  assert.equal(result.overall, "pass");
  assert.equal(key.privateKey.matchesLeafCertificate, true);
  assert.equal(key.chain.valid, true);
  assert.equal(key.root.recognized, true);
  assert.equal(key.revocation.hits.length, 0);
});

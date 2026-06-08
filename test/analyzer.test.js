import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { TRUST_DATA } from "../src/trust-data.js";
import { analyzeKeybox, decodeKeyboxBytes, parseKeyboxXml } from "../src/analyzer.js";

test("parses UTF-16 sample into both ECDSA and RSA keys", async () => {
  const bytes = await readFile("/tmp/keybox_0a9ffdf3c6.xml");
  const xml = decodeKeyboxBytes(bytes);
  const parsed = parseKeyboxXml(xml);
  assert.equal(parsed.keyboxes.length, 1);
  assert.equal(parsed.keyboxes[0].deviceId, "tryigit.dev/keybox");
  assert.deepEqual(parsed.keyboxes[0].keys.map(k => k.algorithm), ["ecdsa", "rsa"]);
  assert.equal(parsed.keyboxes[0].keys[0].certificatesPem.length, 3);
  assert.equal(parsed.keyboxes[0].keys[1].certificatesPem.length, 3);
});

test("analyzes sample keybox locally", async () => {
  const bytes = await readFile("/tmp/keybox_0a9ffdf3c6.xml");
  const xml = decodeKeyboxBytes(bytes);
  const result = await analyzeKeybox(xml, TRUST_DATA, new Date("2026-06-08T10:00:00Z"));
  assert.equal(result.keyboxes.length, 1);
  const keys = result.keyboxes[0].keys;
  assert.equal(keys.length, 2);
  assert.equal(keys[0].privateKey.matchesLeafCertificate, true);
  assert.equal(keys[1].privateKey.matchesLeafCertificate, true);
  assert.equal(keys[0].chain.valid, true);
  assert.equal(keys[1].chain.valid, true);
  assert.equal(keys[0].root.recognized, true);
  assert.equal(keys[1].root.recognized, true);
  assert.equal(keys[0].revocation.hits.length, 0);
  assert.equal(keys[1].revocation.hits.length, 0);
  assert.equal(keys[0].certificates.at(-1).serialHex, "e8fa196314d2fa18");
  assert.match(keys[0].chain.checks.map(c => c.message).join("\n"), /Certificate #3 \(root\) expired/);
  assert.equal(result.overall, "fail");
});

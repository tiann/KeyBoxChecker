#!/usr/bin/env bun
import { writeFile } from "node:fs/promises";
import { TRUST_DATA } from "../src/trust-data.js";

const STATUS_URL = "https://android.googleapis.com/attestation/status";
const ROOT_URL = "https://android.googleapis.com/attestation/root";

async function getJson(url) {
  const res = await fetch(`${url}?ts=${Date.now()}`, {
    headers: {
      "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0",
    },
  });
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`);
  return res.json();
}

async function getRootPems() {
  const res = await fetch(`${ROOT_URL}?ts=${Date.now()}`);
  if (!res.ok) throw new Error(`${ROOT_URL} returned HTTP ${res.status}`);
  const text = await res.text();
  try {
    const json = JSON.parse(text);
    const values = json.certificates || json.roots || json.entries || [];
    if (Array.isArray(values)) return values.map(v => typeof v === "string" ? v : v.pem || v.certificate).filter(Boolean);
  } catch {
    // fall through to PEM block parsing
  }
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
}

const status = await getJson(STATUS_URL);
const fetchedAt = new Date().toISOString();
let roots = TRUST_DATA.roots.filter(root => !root.id.startsWith("google_fetched_"));
const fetchedRoots = await getRootPems();
fetchedRoots.forEach((pem, index) => {
  roots.push({
    id: `google_fetched_${index + 1}`,
    label: `Google hardware attestation root certificate (fetched #${index + 1})`,
    kind: "google_hardware",
    level: "trusted",
    pem,
  });
});

const next = {
  ...TRUST_DATA,
  version: `fetched-${fetchedAt.slice(0, 10)}`,
  fetchedAt,
  status,
  roots,
};
await writeFile("src/trust-data.js", `export const TRUST_DATA = ${JSON.stringify(next, null, 2)};\n`);
console.log(`Updated trust data: ${Object.keys(status.entries || {}).length} status entries, ${roots.length} roots`);

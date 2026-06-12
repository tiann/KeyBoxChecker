const TEXT_OIDS = {
  "2.5.4.3": "commonName",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "countryName",
  "2.5.4.10": "organizationName",
  "2.5.4.11": "organizationalUnitName",
  "2.5.4.12": "title",
};

const SIG_ALGS = {
  "1.2.840.113549.1.1.5": { family: "rsa", hash: "SHA-1", label: "sha1WithRSAEncryption" },
  "1.2.840.113549.1.1.11": { family: "rsa", hash: "SHA-256", label: "sha256WithRSAEncryption" },
  "1.2.840.113549.1.1.12": { family: "rsa", hash: "SHA-384", label: "sha384WithRSAEncryption" },
  "1.2.840.113549.1.1.13": { family: "rsa", hash: "SHA-512", label: "sha512WithRSAEncryption" },
  "1.2.840.10045.4.1": { family: "ecdsa", hash: "SHA-1", label: "ecdsa-with-SHA1" },
  "1.2.840.10045.4.3.2": { family: "ecdsa", hash: "SHA-256", label: "ecdsa-with-SHA256" },
  "1.2.840.10045.4.3.3": { family: "ecdsa", hash: "SHA-384", label: "ecdsa-with-SHA384" },
  "1.2.840.10045.4.3.4": { family: "ecdsa", hash: "SHA-512", label: "ecdsa-with-SHA512" },
};

const PUBKEY_ALGS = {
  "1.2.840.113549.1.1.1": "rsa",
  "1.2.840.10045.2.1": "ec",
};

const CURVES = {
  "1.2.840.10045.3.1.7": { name: "P-256", size: 32, label: "secp256r1" },
  "1.3.132.0.34": { name: "P-384", size: 48, label: "secp384r1" },
  "1.3.132.0.35": { name: "P-521", size: 66, label: "secp521r1" },
};

const te = new TextEncoder();

function bytesToArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

export function decodeKeyboxBytes(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (data[0] === 0xff && data[1] === 0xfe) return new TextDecoder("utf-16le").decode(data.subarray(2));
  if (data[0] === 0xfe && data[1] === 0xff) return new TextDecoder("utf-16be").decode(data.subarray(2));
  if (data[0] === 0xef && data[1] === 0xbb && data[2] === 0xbf) return new TextDecoder("utf-8").decode(data.subarray(3));
  let nulEven = 0, nulOdd = 0;
  for (let i = 0; i < Math.min(data.length, 512); i++) {
    if (data[i] === 0) (i % 2 === 0 ? nulEven++ : nulOdd++);
  }
  if (nulOdd > 10 && nulOdd > nulEven * 3) return new TextDecoder("utf-16le").decode(data);
  if (nulEven > 10 && nulEven > nulOdd * 3) return new TextDecoder("utf-16be").decode(data);
  return new TextDecoder("utf-8").decode(data);
}

function decodeEntities(s) {
  const named = { quot: '"', apos: "'", lt: "<", gt: ">", amp: "&" };
  return (s || "").replace(/&(?:#(\d+)|#x([0-9a-fA-F]+)|(quot|apos|lt|gt|amp));/g, (m, dec, hexValue, name) => {
    if (name) return named[name];
    const value = Number.parseInt(dec || hexValue, dec ? 10 : 16);
    try { return String.fromCodePoint(value); } catch { return m; }
  });
}

function attr(attrs, name) {
  const m = attrs.match(new RegExp(`${name}\\s*=\\s*(["'])(.*?)\\1`, "i"));
  return m ? decodeEntities(m[2]) : undefined;
}

function firstText(xml, tag) {
  const m = xml.match(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "i"));
  return m ? decodeEntities(m[1].trim()) : undefined;
}

export function parseKeyboxXml(xmlText) {
  const xml = xmlText.replace(/^\ufeff/, "");
  const keyboxes = [];
  const keyboxRe = /<Keybox\b([^>]*)>([\s\S]*?)<\/Keybox>/gi;
  let kbMatch;
  while ((kbMatch = keyboxRe.exec(xml))) {
    const [, attrs, body] = kbMatch;
    const keys = [];
    const keyRe = /<Key\b([^>]*)>([\s\S]*?)<\/Key>/gi;
    let keyMatch;
    while ((keyMatch = keyRe.exec(body))) {
      const [, keyAttrs, keyBody] = keyMatch;
      const chain = firstText(keyBody, "CertificateChain") || keyBody;
      const certs = [];
      const certRe = /<Certificate\b[^>]*format\s*=\s*(["'])pem\1[^>]*>([\s\S]*?)<\/Certificate>/gi;
      let certMatch;
      while ((certMatch = certRe.exec(chain))) certs.push(decodeEntities(certMatch[2].trim()));
      keys.push({
        algorithm: attr(keyAttrs, "algorithm") || "Unknown",
        privateKeyPem: firstText(keyBody, "PrivateKey") || "",
        declaredCertificateCount: Number.parseInt(firstText(chain, "NumberOfCertificates") || `${certs.length}`, 10),
        certificatesPem: certs,
      });
    }
    keyboxes.push({ deviceId: attr(attrs, "DeviceID") || "Unknown", keys });
  }
  return { declaredKeyboxCount: Number.parseInt(firstText(xml, "NumberOfKeyboxes") || `${keyboxes.length}`, 10), keyboxes };
}

function base64ToBytes(value, context = "base64") {
  let b64 = decodeEntities(value).replace(/[\s\ufeff]+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (b64.length % 4 === 1) throw new Error(`Invalid ${context}: base64 length is not valid`);
  const invalid = b64.match(/[^A-Za-z0-9+/=]/);
  if (invalid) throw new Error(`Invalid ${context}: unexpected character ${JSON.stringify(invalid[0])}`);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new Error(`Invalid ${context}: padding is not valid`);
  b64 = b64.replace(/=+$/, "");
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  try {
    if (typeof atob === "function") return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return Uint8Array.from(Buffer.from(b64, "base64"));
  } catch (error) {
    throw new Error(`Invalid ${context}: ${(error instanceof Error && error.message) || String(error)}`);
  }
}

function pemToDer(pem, label) {
  const escaped = label ? label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") : "[A-Z0-9 ]+";
  const re = new RegExp(`-----BEGIN ${escaped}-----([\\s\\S]*?)-----END ${escaped}-----`, "i");
  const m = pem.match(re) || pem.match(/-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/i);
  if (!m) throw new Error(`Invalid PEM${label ? ` (${label})` : ""}`);
  return base64ToBytes(m[1], `PEM${label ? ` ${label}` : ""}`);
}

function concatBytes(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function derLen(len) {
  if (len < 128) return Uint8Array.of(len);
  const bytes = [];
  while (len) { bytes.unshift(len & 0xff); len >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function derWrap(tag, value) { return concatBytes(Uint8Array.of(tag), derLen(value.length), value); }
function derSeq(...parts) { return derWrap(0x30, concatBytes(...parts)); }
function derNull() { return Uint8Array.of(0x05, 0x00); }
function derInt(value) {
  let v = trimPositive(value);
  if (v.length === 0) v = Uint8Array.of(0);
  if (v[0] & 0x80) v = concatBytes(Uint8Array.of(0), v);
  return derWrap(0x02, v);
}
function derBitString(value) { return derWrap(0x03, concatBytes(Uint8Array.of(0), value)); }

function derOid(dotted) {
  const nums = dotted.split(".").map(BigInt);
  const out = [Number(nums[0] * 40n + nums[1])];
  for (const n0 of nums.slice(2)) {
    let n = n0;
    const stack = [Number(n & 0x7fn)];
    n >>= 7n;
    while (n) { stack.unshift(Number((n & 0x7fn) | 0x80n)); n >>= 7n; }
    out.push(...stack);
  }
  return derWrap(0x06, Uint8Array.from(out));
}

function trimPositive(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.subarray(i);
}

function parseDer(bytes, offset = 0, limit = bytes.length) {
  if (offset >= limit) throw new Error("DER offset out of range");
  const start = offset;
  const tag = bytes[offset++];
  let len = bytes[offset++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (!n || n > 4) throw new Error("Unsupported DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[offset++];
  }
  const valueStart = offset;
  const end = valueStart + len;
  if (end > limit) throw new Error("DER length exceeds buffer");
  const node = { tag, start, valueStart, end, value: bytes.subarray(valueStart, end), children: [] };
  if ((tag & 0x20) || tag === 0x30 || tag === 0x31) {
    let p = valueStart;
    while (p < end) { const child = parseDer(bytes, p, end); node.children.push(child); p = child.end; }
  }
  return node;
}

function oidFromNode(node) {
  const b = node.value;
  if (node.tag !== 0x06 || b.length === 0) throw new Error("Expected OID");
  const first = b[0];
  const parts = [Math.floor(first / 40), first % 40];
  let n = 0n;
  for (let i = 1; i < b.length; i++) {
    n = (n << 7n) | BigInt(b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(n.toString()); n = 0n; }
  }
  return parts.join(".");
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, "0")).join(""); }
function decimalFromBytes(bytes) {
  let n = 0n;
  for (const b of trimPositive(bytes)) n = (n << 8n) | BigInt(b);
  return n.toString(10);
}

function decodeText(node) {
  if ([0x0c, 0x13, 0x16, 0x14, 0x12].includes(node.tag)) return new TextDecoder("utf-8").decode(node.value);
  if (node.tag === 0x1e) {
    let s = "";
    for (let i = 0; i + 1 < node.value.length; i += 2) s += String.fromCharCode((node.value[i] << 8) | node.value[i + 1]);
    return s;
  }
  return hex(node.value);
}

function parseName(node) {
  const parts = [];
  for (const set of node.children) {
    for (const atv of set.children) {
      const oid = oidFromNode(atv.children[0]);
      const name = TEXT_OIDS[oid] || oid;
      parts.push(`${name}=${decodeText(atv.children[1])}`);
    }
  }
  return { text: parts.join(", "), der: nodeBytes(node) };
}

function parseTime(node) {
  const s = new TextDecoder("ascii").decode(node.value);
  if (node.tag === 0x17) {
    const yy = Number(s.slice(0, 2));
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, Number(s.slice(2, 4)) - 1, Number(s.slice(4, 6)), Number(s.slice(6, 8)), Number(s.slice(8, 10)), Number(s.slice(10, 12))));
  }
  return new Date(Date.UTC(Number(s.slice(0, 4)), Number(s.slice(4, 6)) - 1, Number(s.slice(6, 8)), Number(s.slice(8, 10)), Number(s.slice(10, 12)), Number(s.slice(12, 14))));
}

function nodeBytes(node) { return node._source.subarray(node.start, node.end); }
function attachSource(node, bytes) { node._source = bytes; for (const c of node.children) attachSource(c, bytes); return node; }

export function parseCertificatePem(pem) {
  const der = pem.includes("BEGIN CERTIFICATE") ? pemToDer(pem, "CERTIFICATE") : pemToDer(pem);
  return parseCertificateDer(der);
}

function parseCertificateDer(der) {
  const root = attachSource(parseDer(der), der);
  if (root.tag !== 0x30 || root.children.length < 3) throw new Error("Invalid X.509 certificate");
  const tbs = root.children[0];
  let i = 0;
  let version = 1;
  if (tbs.children[i]?.tag === 0xa0) { version = Number(tbs.children[i].children[0].value.at(-1) || 0) + 1; i++; }
  const serialNode = tbs.children[i++];
  const tbsSigAlg = oidFromNode(tbs.children[i++].children[0]);
  const issuer = parseName(tbs.children[i++]);
  const validity = tbs.children[i++];
  const notBefore = parseTime(validity.children[0]);
  const notAfter = parseTime(validity.children[1]);
  const subject = parseName(tbs.children[i++]);
  const spkiNode = tbs.children[i++];
  const algId = spkiNode.children[0];
  const publicKeyOid = oidFromNode(algId.children[0]);
  const publicKeyType = PUBKEY_ALGS[publicKeyOid] || publicKeyOid;
  const curveOid = publicKeyType === "ec" && algId.children[1] ? oidFromNode(algId.children[1]) : undefined;
  const signatureAlgorithmOid = oidFromNode(root.children[1].children[0]);
  const signatureAlgorithm = SIG_ALGS[signatureAlgorithmOid]?.label || signatureAlgorithmOid;
  const serialBytes = trimPositive(serialNode.value);
  const sigBit = root.children[2].value;
  if (sigBit[0] !== 0) throw new Error("Unsupported signature bit string padding");
  return {
    der,
    version,
    serialHex: hex(serialBytes).toLowerCase() || "0",
    serialDecimal: decimalFromBytes(serialBytes),
    subject: subject.text,
    subjectDer: subject.der,
    issuer: issuer.text,
    issuerDer: issuer.der,
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    publicKeyType,
    curve: curveOid ? CURVES[curveOid]?.label || curveOid : undefined,
    curveOid,
    signatureAlgorithm,
    signatureAlgorithmOid,
    tbsSignatureAlgorithmOid: tbsSigAlg,
    spkiDer: nodeBytes(spkiNode),
    tbsDer: nodeBytes(tbs),
    signatureDer: sigBit.subarray(1),
  };
}

function rsaSpkiFromPrivateKeyDer(der) {
  const seq = attachSource(parseDer(der), der);
  const n = seq.children[1].value;
  const e = seq.children[2].value;
  const rsaPub = derSeq(derInt(n), derInt(e));
  return derSeq(derSeq(derOid("1.2.840.113549.1.1.1"), derNull()), derBitString(rsaPub));
}

function ecSpkiFromSec1Der(der, outerCurveOid) {
  const seq = attachSource(parseDer(der), der);
  let curveOid = outerCurveOid;
  let publicPoint;
  for (const child of seq.children) {
    if (child.tag === 0xa0 && child.children[0]?.tag === 0x06) curveOid = oidFromNode(child.children[0]);
    if (child.tag === 0xa1 && child.children[0]?.tag === 0x03) {
      const bit = child.children[0].value;
      if (bit[0] !== 0) throw new Error("Unsupported EC public key bit string padding");
      publicPoint = bit.subarray(1);
    }
  }
  if (!curveOid) throw new Error("EC private key missing curve parameters");
  if (!publicPoint) throw new Error("EC private key missing public key point");
  return derSeq(derSeq(derOid("1.2.840.10045.2.1"), derOid(curveOid)), derBitString(publicPoint));
}

function spkiFromPrivateKeyPem(pem) {
  if (/BEGIN RSA PRIVATE KEY/.test(pem)) return rsaSpkiFromPrivateKeyDer(pemToDer(pem, "RSA PRIVATE KEY"));
  if (/BEGIN EC PRIVATE KEY/.test(pem)) return ecSpkiFromSec1Der(pemToDer(pem, "EC PRIVATE KEY"));
  if (/BEGIN PRIVATE KEY/.test(pem)) {
    const der = pemToDer(pem, "PRIVATE KEY");
    const seq = attachSource(parseDer(der), der);
    const alg = seq.children[1];
    const algOid = oidFromNode(alg.children[0]);
    const inner = seq.children[2].value;
    if (algOid === "1.2.840.113549.1.1.1") return rsaSpkiFromPrivateKeyDer(inner);
    if (algOid === "1.2.840.10045.2.1") return ecSpkiFromSec1Der(inner, oidFromNode(alg.children[1]));
  }
  throw new Error("Unsupported private key PEM format");
}

function signatureToWebCrypto(sigDer, family, issuerCert) {
  if (family !== "ecdsa") return sigDer;
  const size = CURVES[issuerCert.curveOid]?.size;
  if (!size) throw new Error(`Unsupported ECDSA curve ${issuerCert.curve || issuerCert.curveOid}`);
  const seq = parseDer(sigDer);
  const r = trimPositive(seq.children[0].value);
  const s = trimPositive(seq.children[1].value);
  const out = new Uint8Array(size * 2);
  out.set(r.slice(-size), size - Math.min(size, r.length));
  out.set(s.slice(-size), size * 2 - Math.min(size, s.length));
  return out;
}

async function importVerifyKey(cert, sigAlg) {
  if (sigAlg.family === "rsa") {
    return crypto.subtle.importKey("spki", bytesToArrayBuffer(cert.spkiDer), { name: "RSASSA-PKCS1-v1_5", hash: sigAlg.hash }, false, ["verify"]);
  }
  if (sigAlg.family === "ecdsa") {
    const curve = CURVES[cert.curveOid]?.name;
    if (!curve) throw new Error(`Unsupported EC curve ${cert.curve || cert.curveOid}`);
    return crypto.subtle.importKey("spki", bytesToArrayBuffer(cert.spkiDer), { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
  }
  throw new Error(`Unsupported signature family ${sigAlg.family}`);
}

async function verifyCertificateSignature(child, issuer) {
  const sigAlg = SIG_ALGS[child.signatureAlgorithmOid];
  if (!sigAlg) throw new Error(`Unsupported signature algorithm ${child.signatureAlgorithmOid}`);
  const key = await importVerifyKey(issuer, sigAlg);
  const signature = signatureToWebCrypto(child.signatureDer, sigAlg.family, issuer);
  const algorithm = sigAlg.family === "rsa" ? { name: "RSASSA-PKCS1-v1_5" } : { name: "ECDSA", hash: sigAlg.hash };
  return crypto.subtle.verify(algorithm, key, bytesToArrayBuffer(signature), bytesToArrayBuffer(child.tbsDer));
}

function normalizePrivateKeyText(text) {
  return (text || "").replace(/^\s+/gm, "").trim();
}

function makeTrustRoots(trustData) {
  return trustData.roots.map(root => {
    const der = pemToDer(root.pem);
    let spkiDer;
    if (/BEGIN CERTIFICATE/.test(root.pem)) spkiDer = parseCertificateDer(der).spkiDer;
    else spkiDer = der;
    return { ...root, spkiDer, spkiSha256: "" };
  });
}

function certPublicView(cert) {
  return {
    serialHex: cert.serialHex,
    serialDecimal: cert.serialDecimal,
    subject: cert.subject,
    issuer: cert.issuer,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
    publicKeyType: cert.publicKeyType,
    curve: cert.curve,
    signatureAlgorithm: cert.signatureAlgorithm,
  };
}

function classifyRoot(rootCert, trustRoots) {
  const exactProductionGoogle = trustRoots.find(
    r => r.kind === "google_hardware" && r.level === "trusted" && bytesEqual(r.spkiDer, rootCert.spkiDer),
  );
  if (exactProductionGoogle) {
    return {
      recognized: true,
      id: exactProductionGoogle.id,
      label: exactProductionGoogle.label,
      kind: exactProductionGoogle.kind,
      level: exactProductionGoogle.level,
    };
  }

  return {
    recognized: false,
    id: "unknown_signer",
    label: "Unknown Signer",
    kind: "unknown",
    level: "unknown",
  };
}

function worse(a, b) {
  const order = { pass: 0, warn: 1, fail: 2, error: 3 };
  return order[b] > order[a] ? b : a;
}

export async function analyzeKeybox(xmlText, trustData, now = new Date()) {
  const parsed = parseKeyboxXml(xmlText);
  const trustRoots = makeTrustRoots(trustData);
  const statusEntries = trustData.status?.entries || {};
  const result = {
    overall: "pass",
    checkedAtUtc: now.toISOString(),
    trustData: { version: trustData.version, fetchedAt: trustData.fetchedAt, revocationEntryCount: Object.keys(statusEntries).length },
    declaredKeyboxCount: parsed.declaredKeyboxCount,
    keyboxes: [],
    warnings: [],
    errors: [],
  };
  if (parsed.keyboxes.length !== parsed.declaredKeyboxCount) {
    result.warnings.push(`NumberOfKeyboxes=${parsed.declaredKeyboxCount}, actual=${parsed.keyboxes.length}`);
    result.overall = worse(result.overall, "warn");
  }
  if (!parsed.keyboxes.length) {
    result.errors.push("No Keybox elements found");
    result.overall = "error";
    return result;
  }

  for (const kb of parsed.keyboxes) {
    const kbOut = { deviceId: kb.deviceId, keys: [] };
    for (const key of kb.keys) {
      const keyOut = {
        algorithm: key.algorithm,
        declaredCertificateCount: key.declaredCertificateCount,
        actualCertificateCount: key.certificatesPem.length,
        status: "pass",
        privateKey: { matchesLeafCertificate: false, status: "fail" },
        chain: { valid: false, checks: [] },
        root: { recognized: false, label: "Unknown root certificate", level: "unknown" },
        revocation: { status: "pass", hits: [] },
        certificates: [],
        errors: [],
        warnings: [],
      };
      try {
        if (key.declaredCertificateCount !== key.certificatesPem.length) {
          keyOut.warnings.push(`NumberOfCertificates=${key.declaredCertificateCount}, actual=${key.certificatesPem.length}`);
          keyOut.status = worse(keyOut.status, "warn");
        }
        const certs = key.certificatesPem.map(parseCertificatePem);
        keyOut.certificates = certs.map(certPublicView);
        const leafSpki = certs[0]?.spkiDer;
        const privateSpki = spkiFromPrivateKeyPem(normalizePrivateKeyText(key.privateKeyPem));
        keyOut.privateKey.matchesLeafCertificate = bytesEqual(privateSpki, leafSpki);
        keyOut.privateKey.status = keyOut.privateKey.matchesLeafCertificate ? "pass" : "fail";
        if (!keyOut.privateKey.matchesLeafCertificate) keyOut.status = worse(keyOut.status, "fail");

        const timeChecks = certs.map((cert, idx) => {
          const role = idx === 0 ? "leaf" : idx === certs.length - 1 ? "root" : "intermediate";
          const nb = new Date(cert.notBefore);
          const na = new Date(cert.notAfter);
          let status = "pass";
          let message = `Certificate #${idx + 1} (${role}) within validity period`;
          if (now < nb) { status = "fail"; message = `Certificate #${idx + 1} (${role}) not yet valid`; }
          if (now > na) { status = "fail"; message = `Certificate #${idx + 1} (${role}) expired`; }
          return { status, message, serialHex: cert.serialHex };
        });
        keyOut.chain.checks.push(...timeChecks);
        if (timeChecks.some(c => c.status === "fail")) keyOut.status = worse(keyOut.status, "fail");

        let chainValid = true;
        for (let i = 0; i < certs.length - 1; i++) {
          const issuerMatch = bytesEqual(certs[i].issuerDer, certs[i + 1].subjectDer);
          let signatureValid = false;
          if (issuerMatch) signatureValid = await verifyCertificateSignature(certs[i], certs[i + 1]);
          keyOut.chain.checks.push({
            status: issuerMatch && signatureValid ? "pass" : "fail",
            message: `Certificate #${i + 1} signed by #${i + 2}`,
            issuerMatch,
            signatureValid,
          });
          chainValid &&= issuerMatch && signatureValid;
        }
        keyOut.chain.valid = chainValid;
        if (!chainValid) keyOut.status = worse(keyOut.status, "fail");

        const rootCert = certs.at(-1);
        keyOut.root = classifyRoot(rootCert, trustRoots);
        if (!keyOut.root.recognized) {
          keyOut.status = worse(keyOut.status, "warn");
          keyOut.warnings.push("Signer is not a production Google hardware attestation root.");
        }

        for (const cert of certs) {
          const hit = statusEntries[cert.serialHex.toLowerCase()];
          if (hit) keyOut.revocation.hits.push({ serialHex: cert.serialHex, ...hit });
        }
        if (keyOut.revocation.hits.length) {
          keyOut.revocation.status = "fail";
          keyOut.status = worse(keyOut.status, "fail");
        }
      } catch (error) {
        keyOut.status = "error";
        keyOut.errors.push(error instanceof Error ? error.message : String(error));
      }
      result.overall = worse(result.overall, keyOut.status);
      kbOut.keys.push(keyOut);
    }
    result.keyboxes.push(kbOut);
  }
  return result;
}

export function resultToText(result) {
  const lines = [];
  lines.push(`Overall: ${result.overall}`);
  lines.push(`Trust data: ${result.trustData.version} (${result.trustData.fetchedAt})`);
  lines.push(`Check Time (UTC): ${result.checkedAtUtc}`);
  for (const kb of result.keyboxes) {
    lines.push(`\nDevice ID: ${kb.deviceId}`);
    for (const key of kb.keys) {
      lines.push(`  Key algorithm: ${key.algorithm} [${key.status}]`);
      lines.push(`  Certificates: ${key.actualCertificateCount}/${key.declaredCertificateCount}`);
      for (const cert of key.certificates) {
        lines.push(`    Serial: ${cert.serialHex}`);
        lines.push(`    Subject: ${cert.subject}`);
        lines.push(`    Valid: ${cert.notBefore} -> ${cert.notAfter}`);
      }
      lines.push(`  Private key match: ${key.privateKey.matchesLeafCertificate ? "yes" : "no"}`);
      lines.push(`  Chain valid: ${key.chain.valid ? "yes" : "no"}`);
      for (const check of key.chain.checks) lines.push(`    ${check.status}: ${check.message}`);
      lines.push(`  Root: ${key.root.label}`);
      lines.push(`  Revocation: ${key.revocation.hits.length ? key.revocation.hits.map(h => `${h.serialHex}:${h.reason || h.status}`).join(", ") : "not found"}`);
      for (const e of key.errors) lines.push(`  Error: ${e}`);
    }
  }
  return lines.join("\n");
}

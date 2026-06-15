// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import init, {
  split_aci_certificate_bundle,
  verify_attestation_with_cert_chain_async,
  verify_c_aci_attestation,
  verify_uvm_endorsement_async,
} from "./aci_pkg/tee_attestation_verification_aci.js";

const statusEl = document.getElementById("status");
const outputEl = document.getElementById("output");
let wasmInitPromise;

function setStatus(msg, kind = "") {
  statusEl.textContent = msg;
  statusEl.className = kind;
}

function ensureWasmLoaded() {
  if (!wasmInitPromise) {
    wasmInitPromise = init();
  }
  return wasmInitPromise;
}

const u8hex = n => n.toString(16).padStart(2, "0");
const bytesToHex = bytes => Array.from(bytes, u8hex).join("");

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length === 0) return null;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  if (!/^[0-9a-fA-F]+$/.test(clean)) throw new Error("hex string contains non-hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function requiredHexToBytes(textId, name) {
  const bytes = hexToBytes(document.getElementById(textId).value);
  if (!bytes) throw new Error(`No ${name} provided`);
  return bytes;
}

function requiredHexLinesToBytes(textId, name) {
  const lines = document.getElementById(textId).value
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line.length > 0);
  if (lines.length === 0) throw new Error(`No ${name} provided`);
  return lines.map(line => hexToBytes(line));
}

function base64ToBytes(value) {
  const clean = value.replace(/\s+/g, "");
  if (!clean) return null;
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function requiredBase64ToBytes(textId, name) {
  const bytes = base64ToBytes(document.getElementById(textId).value);
  if (!bytes) throw new Error(`No ${name} provided`);
  return bytes;
}

function getText(name, textId) {
  const text = document.getElementById(textId).value;
  if (!text.trim()) throw new Error(`No ${name} provided`);
  return text;
}

function wireFileToText(fileId, textId, transform) {
  const fileEl = document.getElementById(fileId);
  const textEl = document.getElementById(textId);
  fileEl.addEventListener("change", async () => {
    const f = fileEl.files[0];
    if (!f) return;
    textEl.value = await transform(f);
  });
}

wireFileToText("report-file", "report-hex",
  async f => bytesToHex(new Uint8Array(await f.arrayBuffer())));
wireFileToText("amd-bundle-file", "amd-bundle-text", f => f.text());
wireFileToText("uvm-file", "uvm-text", f => f.text());

async function fetchText(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Failed to load ${path}: HTTP ${response.status}`);
  }
  return response.text();
}

async function loadExample() {
  outputEl.textContent = "";
  setStatus("Loading example manifest...");
  try {
    const manifest = JSON.parse(await fetchText("test-data/manifest.json"));
    const [
      attestationReportHex,
      hostAmdCertBase64,
      uvmEndorsementBase64,
    ] = await Promise.all([
      fetchText(manifest.attestation_report_hex),
      fetchText(manifest.host_amd_cert_base64),
      fetchText(manifest.uvm_endorsement_base64),
    ]);

    document.getElementById("report-hex").value = attestationReportHex.trim();
    document.getElementById("amd-bundle-text").value = hostAmdCertBase64.trim();
    document.getElementById("uvm-text").value = uvmEndorsementBase64.trim();
    document.getElementById("policy-hex").value = manifest.trusted_c_aci_policies.join("\n");
    document.getElementById("minimum-tcb-json").value =
      JSON.stringify(manifest.minimum_tcb, null, 2);
    document.getElementById("feed").value = manifest.uvm_feed;
    document.getElementById("minimum-svn").value = String(manifest.minimum_svn);
    setStatus("Loaded good example from manifest.", "ok");
  } catch (err) {
    console.error(err);
    const msg = err && err.message ? err.message : String(err);
    setStatus(`Example load failed: ${msg}`, "err");
  }
}

function hostAmdCertToEndorsements(hostAmdCertBase64) {
  const decoded = new TextDecoder().decode(base64ToBytes(hostAmdCertBase64));
  const hostAmdCert = JSON.parse(decoded);
  if (typeof hostAmdCert.vcekCert !== "string") {
    throw new Error("host AMD cert JSON missing string field vcekCert");
  }
  if (typeof hostAmdCert.certificateChain !== "string") {
    throw new Error("host AMD cert JSON missing string field certificateChain");
  }
  const chain = Array.from(split_aci_certificate_bundle(hostAmdCert.certificateChain));
  if (chain.length !== 2) {
    throw new Error(`expected certificateChain to contain ASK and ARK, got ${chain.length}`);
  }
  const encoder = new TextEncoder();
  return [hostAmdCert.vcekCert, chain[0], chain[1]].map(cert => encoder.encode(cert));
}

function formatBytes(bytes) {
  const groups = [];
  for (let i = 0; i < bytes.length; i += 16) {
    groups.push(bytesToHex(bytes.slice(i, i + 16)));
  }
  return groups.join("\n  ");
}

function requiredNonNegativeBigInt(textId, name) {
  const value = document.getElementById(textId).value.trim();
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return BigInt(value);
}

async function onSubmit(ev) {
  ev.preventDefault();
  outputEl.textContent = "";
  setStatus("Loading ACI WASM module...");
  try {
    await ensureWasmLoaded();
    setStatus("Reading ACI inputs...");

    const reportBytes = requiredHexToBytes("report-hex", "attestation report");
    const hostAmdCertBase64 = getText("host AMD certificate bundle", "amd-bundle-text");
    const endorsements = hostAmdCertToEndorsements(hostAmdCertBase64);
    const uvmEndorsementBase64 = requiredBase64ToBytes("uvm-text", "UVM endorsement");
    const policyDigests = requiredHexLinesToBytes("policy-hex", "security policy digest");
    const minimumTcbJson = document.getElementById("minimum-tcb-json").value;
    const feed = getText("UVM feed", "feed");
    const minimumSvn = requiredNonNegativeBigInt("minimum-svn", "Minimum UVM SVN");

    setStatus("Verifying SEV-SNP attestation...");
    const attestation = await verify_attestation_with_cert_chain_async(reportBytes, endorsements);
    setStatus("Verifying UVM endorsement...");
    const uvm = await verify_uvm_endorsement_async(
      uvmEndorsementBase64,
      "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2",
    );
    setStatus("Verifying Confidential ACI policy...");
    const reportData = await verify_c_aci_attestation(
      attestation,
      minimumTcbJson,
      policyDigests,
      uvm,
      feed,
      minimumSvn,
    );

    setStatus("Confidential ACI policy verified.", "ok");
    outputEl.textContent = `verified_report_data:\n  ${formatBytes(reportData)}`;
  } catch (err) {
    console.error(err);
    const msg = err && err.message ? err.message : String(err);
    setStatus(`ACI verification failed: ${msg}`, "err");
  }
}

document.getElementById("aci-form").addEventListener("submit", onSubmit);
document.getElementById("load-example").addEventListener("click", loadExample);

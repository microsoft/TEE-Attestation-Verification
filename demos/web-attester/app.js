import CONFIG from "./config.js";

// --- UI helpers ---

function showVerifying() {
  document.getElementById("verifying").style.display = "flex";
  document.getElementById("blocked").style.display = "none";
  document.getElementById("app").style.display = "none";
}

function showBlocked(reason) {
  document.getElementById("verifying").style.display = "none";
  document.getElementById("blocked").style.display = "flex";
  document.getElementById("app").style.display = "none";
  document.getElementById("error-detail").textContent = reason;
}

function showApp(attestationReport) {
  document.getElementById("verifying").style.display = "none";
  document.getElementById("blocked").style.display = "none";
  document.getElementById("app").style.display = "block";
  renderAttestationInfo(attestationReport);
}

function renderAttestationInfo(reportBytes) {
  const info = document.getElementById("attestation-info");
  const hex = Array.from(new Uint8Array(reportBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // Parse selected fields from the raw report (little-endian).
  // See AMD SEV-SNP ABI Specification, Table 23.
  const view = new DataView(reportBytes.buffer ?? reportBytes);
  const version = view.getUint32(0x000, true);
  const guestSvn = view.getUint32(0x004, true);
  const policy = view.getBigUint64(0x008, true);
  const measurement = hex.slice(0x090 * 2, (0x090 + 48) * 2);
  const reportData = hex.slice(0x050 * 2, (0x050 + 64) * 2);
  const hostData = hex.slice(0x0c0 * 2, (0x0c0 + 32) * 2);

  const fields = [
    ["Version", version],
    ["Guest SVN", guestSvn],
    ["Policy", `0x${policy.toString(16)}`],
    ["Measurement", measurement],
    ["Report Data", reportData],
    ["Host Data", hostData],
  ];

  info.innerHTML = fields
    .map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`)
    .join("");
}

// --- Measurement validation stubs ---

function validateMeasurements(reportBytes) {
  const hex = Array.from(new Uint8Array(reportBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const view = new DataView(reportBytes.buffer ?? reportBytes);
  const expected = CONFIG.expectedMeasurements;

  if (expected.measurement) {
    const actual = hex.slice(0x090 * 2, (0x090 + 48) * 2);
    if (actual !== expected.measurement.toLowerCase()) {
      throw new Error(
        `Measurement mismatch: expected ${expected.measurement}, got ${actual}`
      );
    }
  }

  if (expected.policy) {
    const actual = view.getBigUint64(0x008, true);
    if (actual !== BigInt(expected.policy)) {
      throw new Error(
        `Policy mismatch: expected ${expected.policy}, got ${actual}`
      );
    }
  }

  if (expected.reportDataPrefix) {
    const actual = hex.slice(0x050 * 2, (0x050 + 64) * 2);
    const prefix = expected.reportDataPrefix.toLowerCase();
    if (!actual.startsWith(prefix)) {
      throw new Error(
        `Report data prefix mismatch: expected ${prefix}..., got ${actual.slice(0, prefix.length)}...`
      );
    }
  }

  if (expected.hostData) {
    const actual = hex.slice(0x0c0 * 2, (0x0c0 + 32) * 2);
    if (actual !== expected.hostData.toLowerCase()) {
      throw new Error(
        `Host data mismatch: expected ${expected.hostData}, got ${actual}`
      );
    }
  }
}

// --- Attestation fetch ---

async function fetchAttestationReport() {
  const url = `${CONFIG.backendUrl}${CONFIG.attestationEndpoint}`;
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Backend returned HTTP ${resp.status} from ${url}`);
  }
  const buf = await resp.arrayBuffer();
  if (buf.byteLength !== 1184) {
    throw new Error(
      `Expected 1184-byte attestation report, got ${buf.byteLength} bytes`
    );
  }
  return new Uint8Array(buf);
}

// --- WASM verification ---

async function verifyWithWasm(reportBytes) {
  // Import the WASM module built from the verification library.
  // Build with: wasm-pack build --target web --no-default-features --features "crypto_webcrypto,kds"
  // Then copy/symlink the pkg/ directory next to this file.
  const wasm = await import("./pkg/tee_attestation_verification_lib.js");
  await wasm.default();
  await wasm.verify_attestation_report(reportBytes);
}

// --- Main flow ---

async function main() {
  showVerifying();

  try {
    // Step 1: Fetch the raw attestation report from the backend.
    const reportBytes = await fetchAttestationReport();

    // Step 2: Cryptographically verify the attestation report.
    // This checks the signature (via VCEK from AMD KDS) and TCB values.
    await verifyWithWasm(reportBytes);

    // Step 3: Validate application-level measurements.
    validateMeasurements(reportBytes);

    // Step 4: Attestation passed — show the trusted app.
    showApp(reportBytes);

    // Step 5: Now safe to fetch data from the trusted backend.
    await loadServiceData();
  } catch (err) {
    showBlocked(err.message || String(err));
  }
}

async function loadServiceData() {
  try {
    const url = `${CONFIG.backendUrl}${CONFIG.dataEndpoint}`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    document.getElementById("service-data").textContent = JSON.stringify(
      data,
      null,
      2
    );
  } catch (err) {
    document.getElementById("service-data").textContent =
      `Failed to load service data: ${err.message}`;
  }
}

main();

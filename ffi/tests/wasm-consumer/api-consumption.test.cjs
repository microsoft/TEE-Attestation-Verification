// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer-facing API-compatibility tests for the generated wasm bundle.
//
// One test per public API surface area. Each test drives the exported
// functions/classes exactly as an external JS consumer would, covering both
// the success path and, where the surface can fail, its failure mode. The goal
// is to catch any accidental break in the shipped wasm API (shapes, return
// types, and error types) from here onwards.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repoRoot = path.resolve(__dirname, '../../..');
const pkg = require(path.join(repoRoot, 'target/wasm-consumer-tests/pkg/tee_attestation_verification_ffi.js'));

const TRUSTED_DIDX509 = 'did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.2';

function read(rel, encoding = undefined) {
  return fs.readFileSync(path.join(repoRoot, rel), encoding);
}

function readText(rel) {
  return read(rel, 'utf8');
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  assert.equal(clean.length % 2, 0);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64ToBytes(value) {
  return new Uint8Array(Buffer.from(value.replace(/\s+/g, ''), 'base64'));
}

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function loadMilanInputs() {
  return {
    report: new Uint8Array(read('demos/web-verify-kernel/test-data/milan_attestation_report.bin')),
    ark: readText('demos/web-verify-kernel/test-data/milan_ark.pem'),
    ask: readText('demos/web-verify-kernel/test-data/milan_ask.pem'),
    vcek: readText('demos/web-verify-kernel/test-data/milan_vcek.pem'),
  };
}

function loadCaciInputs() {
  const manifest = JSON.parse(readText('demos/caci-attestation-verify/test-data/manifest.json'));
  const hostAmdCert = JSON.parse(new TextDecoder().decode(base64ToBytes(readText('demos/caci-attestation-verify/test-data/host-amd-cert.base64'))));
  // split_pem_bundle turns the ASK+ARK chain PEM into individual certificates.
  const chain = Array.from(pkg.split_pem_bundle(hostAmdCert.certificateChain));
  assert.equal(chain.length, 2);
  return {
    manifest,
    hostAmdCert,
    chain,
    report: hexToBytes(readText('demos/caci-attestation-verify/test-data/aci-report.hex')),
    endorsements: [hostAmdCert.vcekCert, chain[0], chain[1]].map(textBytes),
    uvmEndorsement: base64ToBytes(readText('demos/caci-attestation-verify/test-data/reference-info.base64')),
    policies: manifest.trusted_caci_execution_policies.map(hexToBytes),
  };
}

// A verified SNP report is the only way to obtain a SnpAttestationReport, so
// the accessor test reuses the real verification path to produce one.
async function verifiedMilanReport() {
  const { report, ark, ask, vcek } = loadMilanInputs();
  return pkg.verify_attestation_async(report, ark, ask, vcek);
}

function assertStringError(fn, messageSubstring) {
  assert.throws(fn, (err) => {
    assert.equal(typeof err, 'string', `expected string error, got ${err}`);
    if (messageSubstring) assert.match(err, messageSubstring);
    return true;
  });
}

async function assertRejectsStringError(promise, messageSubstring) {
  await assert.rejects(promise, (err) => {
    assert.equal(typeof err, 'string', `expected string error, got ${err}`);
    if (messageSubstring) assert.match(err, messageSubstring);
    return true;
  });
}

async function assertRejectsVerifyError(promise, code, messageSubstring) {
  await assert.rejects(promise, (err) => {
    assert.ok(err instanceof pkg.VerifyError, `expected VerifyError, got ${err}`);
    assert.equal(err.code, code);
    if (messageSubstring) assert.match(err.message, messageSubstring);
    return true;
  });
}

// Attestation accessors: every getter exported on SnpAttestationReport.
test('attestation accessors expose every SnpAttestationReport getter', async () => {
  const attestation = await verifiedMilanReport();
  assert.ok(attestation instanceof pkg.SnpAttestationReport);

  assert.equal(attestation.version, 3);
  assert.equal(typeof attestation.guest_svn, 'number');
  assert.equal(typeof attestation.policy, 'bigint');
  assert.equal(typeof attestation.policy_abi_minor, 'number');
  assert.equal(typeof attestation.policy_abi_major, 'number');
  assert.equal(typeof attestation.policy_smt, 'boolean');
  assert.equal(typeof attestation.policy_migrate_ma, 'boolean');
  assert.equal(typeof attestation.policy_debug, 'boolean');
  assert.equal(typeof attestation.policy_single_socket, 'boolean');
  assert.equal(typeof attestation.policy_cxl_allow, 'boolean');
  assert.equal(typeof attestation.policy_mem_aes_256_xts, 'boolean');
  assert.equal(typeof attestation.policy_rapl_dis, 'boolean');
  assert.equal(typeof attestation.policy_ciphertext_hiding_dram, 'boolean');
  assert.equal(typeof attestation.policy_page_swap_disable, 'boolean');
  assert.equal(typeof attestation.vmpl, 'number');
  assert.equal(typeof attestation.signature_algo, 'number');
  assert.equal(typeof attestation.platform_info, 'bigint');
  assert.equal(typeof attestation.flags, 'number');
  assert.equal(typeof attestation.flags_author_key_en, 'boolean');
  assert.equal(typeof attestation.flags_mask_chip_key, 'boolean');
  assert.equal(typeof attestation.flags_signing_key, 'number');
  assert.equal(typeof attestation.cpuid_fam_id, 'number');
  assert.equal(typeof attestation.cpuid_mod_id, 'number');
  assert.equal(typeof attestation.cpuid_step, 'number');
  assert.equal(typeof attestation.current_build, 'number');
  assert.equal(typeof attestation.current_minor, 'number');
  assert.equal(typeof attestation.current_major, 'number');
  assert.equal(typeof attestation.committed_build, 'number');
  assert.equal(typeof attestation.committed_minor, 'number');
  assert.equal(typeof attestation.committed_major, 'number');

  const byteFields = {
    family_id: 16,
    image_id: 16,
    platform_version: 8,
    report_data: 64,
    measurement: 48,
    host_data: 32,
    id_key_digest: 48,
    author_key_digest: 48,
    report_id: 32,
    report_id_ma: 32,
    reported_tcb: 8,
    chip_id: 64,
    committed_tcb: 8,
    launch_tcb: 8,
    signature_r: 72,
    signature_s: 72,
  };
  for (const [name, length] of Object.entries(byteFields)) {
    assert.ok(attestation[name] instanceof Uint8Array, `${name} should be Uint8Array`);
    assert.equal(attestation[name].length, length, `${name} length`);
  }

  // Assert concrete decoded values from the known-good Milan fixture so the
  // accessors are checked for correctness, not just shape.
  const toHex = (bytes) => Buffer.from(bytes).toString('hex');
  assert.equal(attestation.guest_svn, 2);
  assert.equal(attestation.vmpl, 0);
  assert.equal(attestation.policy, 196639n);
  assert.equal(attestation.signature_algo, 1);
  assert.equal(toHex(attestation.report_data), '00'.repeat(64));
  assert.equal(toHex(attestation.host_data), '4f4448c67f3c8dfc8de8a5e37125d807dadcc41f06cf23f615dbd52eec777d10');
  assert.equal(toHex(attestation.family_id), '01000000000000000000000000000000');
  assert.equal(toHex(attestation.image_id), '02000000000000000000000000000000');
  assert.equal(
    toHex(attestation.measurement),
    '5feee30d6d7e1a29f403d70a4198237ddfb13051a2d6976439487c609388ed7f98189887920ab2fa0096903a0c23fca1',
  );
  assert.equal(
    toHex(attestation.chip_id),
    '4ffb5cb4fd594f3fee6528fc3fb10370bb38abe89dcd5ba2cf0ab6a11df2ca282add516bef45a890a8c9f9732bdca68f9f3f16c42e846030a800295dbeb19ba5',
  );
  assert.equal(
    toHex(attestation.report_id),
    '5e01036273418d910bdca3f5cb9c7d849e88e2141483eb6cc9afd794ffbbbcbc',
  );
});

// CBOR accessors: CborValue decoding plus the CoseSign1 wrapper.
test('cbor accessors decode scalars, containers, tags, and COSE_Sign1', () => {
  const intValue = pkg.CborValue.from_bytes(Uint8Array.of(0x01));
  assert.equal(intValue.kind(), 'int');
  assert.equal(intValue.int(), 1n);
  assert.deepEqual(Array.from(intValue.to_bytes()), [0x01]);

  const simpleValue = pkg.CborValue.from_bytes(Uint8Array.of(0xf6));
  assert.equal(simpleValue.kind(), 'simple');
  assert.equal(simpleValue.simple(), 22);

  const bytesValue = pkg.CborValue.from_bytes(Uint8Array.of(0x43, 1, 2, 3));
  assert.equal(bytesValue.kind(), 'bytes');
  assert.deepEqual(Array.from(bytesValue.bytes()), [1, 2, 3]);

  const textValue = pkg.CborValue.from_bytes(Uint8Array.of(0x62, 0x68, 0x69));
  assert.equal(textValue.kind(), 'text');
  assert.equal(textValue.text(), 'hi');

  const arrayValue = pkg.CborValue.from_bytes(Uint8Array.of(0x82, 0x01, 0x61, 0x61));
  assert.equal(arrayValue.kind(), 'array');
  assert.equal(arrayValue.len(), 2);
  assert.equal(arrayValue.array_at(0).int(), 1n);
  assert.equal(arrayValue.array_at(1).text(), 'a');

  const mapValue = pkg.CborValue.from_bytes(Uint8Array.of(
    0xa2,
    0x01, 0x63, 0x6f, 0x6e, 0x65,
    0x61, 0x6b, 0x81, 0xf6,
  ));
  assert.equal(mapValue.kind(), 'map');
  assert.equal(mapValue.len(), 2);
  assert.equal(mapValue.map_at_int(1n).text(), 'one');
  assert.equal(mapValue.map_at_text('k').array_at(0).simple(), 22);
  assert.equal(mapValue.map_at(pkg.CborValue.from_bytes(Uint8Array.of(0x01))).text(), 'one');
  const entry = mapValue.map_entry_at(0);
  assert.equal(entry.length, 2);
  assert.equal(entry[0].int(), 1n);
  assert.equal(entry[1].text(), 'one');
  assert.equal(mapValue.map_key_at(1).text(), 'k');
  assert.equal(mapValue.map_value_at(1).array_at(0).simple(), 22);
  assert.equal(mapValue.map_has_int(1n), true);
  assert.equal(mapValue.map_has_int(2n), false);
  assert.equal(mapValue.map_has_text('k'), true);
  assert.equal(mapValue.map_has_text('x'), false);
  assert.equal(mapValue.map_has(pkg.CborValue.from_bytes(Uint8Array.of(0x01))), true);

  const taggedValue = pkg.CborValue.from_bytes(Uint8Array.of(0xc1, 0x18, 0x2a));
  assert.equal(taggedValue.kind(), 'tagged');
  assert.equal(taggedValue.tag(), 1n);
  assert.equal(taggedValue.tagged_payload().int(), 42n);

  const sign1Bytes = Uint8Array.of(
    0xd2, 0x84,
    0x43, 0xa1, 0x01, 0x26,
    0xa0,
    0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x43, 0x01, 0x02, 0x03,
  );
  const sign1 = pkg.CborValue.from_bytes(sign1Bytes).as_cose_sign1();
  assert.ok(sign1 instanceof pkg.CoseSign1);
  assert.deepEqual(Array.from(sign1.protected()), [0xa1, 0x01, 0x26]);
  assert.equal(sign1.protected_header().map_at_int(1n).int(), -7n);
  assert.equal(sign1.unprotected().kind(), 'map');
  assert.equal(sign1.payload().toString(), Uint8Array.of(0x68, 0x65, 0x6c, 0x6c, 0x6f).toString());
  assert.deepEqual(Array.from(sign1.signature()), [1, 2, 3]);

  // Failure mode: CborValue accessor type mismatches raise string errors.
  assertStringError(() => intValue.text(), /Expected TextString/);
  // Failure mode: a CoseSign1 accessor over a malformed structure (null payload
  // where a byte string is required) raises the shipped string error.
  const malformedSign1 = pkg.CborValue.from_bytes(Uint8Array.of(
    0xd2, 0x84,
    0x43, 0xa1, 0x01, 0x26,
    0xa0,
    0xf6,
    0x43, 0x01, 0x02, 0x03,
  )).as_cose_sign1();
  assertStringError(() => malformedSign1.payload(), /payload must be a byte string/);
});

// SNP verify attestation: verify_attestation_async (typed VerifyError).
test('snp verify attestation returns a report and rejects an invalid root', async () => {
  const { report, ark, ask, vcek } = loadMilanInputs();

  const attestation = await pkg.verify_attestation_async(report, ark, ask, vcek);
  assert.ok(attestation instanceof pkg.SnpAttestationReport);
  assert.equal(attestation.version, 3);

  // Failure mode: swapping ASK in as the ARK breaks the root of trust.
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, ask, ask, vcek),
    pkg.ErrorCode.InvalidRootCertificate,
    /Invalid root certificate/,
  );

  // Malformed inputs are rejected as InvalidArgument before verification runs.
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(new Uint8Array(), ark, ask, vcek),
    pkg.ErrorCode.InvalidArgument,
    /expected 1184 bytes, got 0/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report.slice(0, 100), ark, ask, vcek),
    pkg.ErrorCode.InvalidArgument,
    /Invalid attestation report/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, 'not a pem', ask, vcek),
    pkg.ErrorCode.InvalidArgument,
    /ARK PEM/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, ark, 'not a pem', vcek),
    pkg.ErrorCode.InvalidArgument,
    /ASK PEM/,
  );
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(report, ark, ask, 'not a pem'),
    pkg.ErrorCode.InvalidArgument,
    /VCEK PEM/,
  );

  // A tampered report body fails AMD signature verification.
  const corrupted = Uint8Array.from(report);
  corrupted[100] ^= 0xff;
  await assertRejectsVerifyError(
    pkg.verify_attestation_async(corrupted, ark, ask, vcek),
    pkg.ErrorCode.SignatureVerificationError,
  );
});

// SNP verify with cert chain: verify_snp_attestation_with_cert_chain_async,
// including the split_certificate_bundle / split_pem_bundle helpers used to
// assemble the endorsement chain.
test('snp verify with cert chain accepts endorsements and rejects a bad chain', async () => {
  const { ask, ark } = loadMilanInputs();

  const splitSnp = Array.from(pkg.split_certificate_bundle(`${ask}\n${ark}`));
  assert.equal(splitSnp.length, 2);
  assert.match(splitSnp[0], /BEGIN CERTIFICATE/);
  assert.match(splitSnp[1], /BEGIN CERTIFICATE/);
  // Failure mode: splitting an empty bundle raises the shipped string error.
  assertStringError(() => pkg.split_certificate_bundle(''), /empty/);
  // A non-PEM bundle raises the parse string error rather than a VerifyError.
  assertStringError(() => pkg.split_certificate_bundle('not a pem'), /certificate bundle PEM/);
  // split_pem_bundle is a separate exported symbol with its own string error.
  assertStringError(() => pkg.split_pem_bundle(''), /empty/);

  const { report, endorsements } = loadCaciInputs();
  const attestation = await pkg.verify_snp_attestation_with_cert_chain_async(report, endorsements);
  assert.ok(attestation instanceof pkg.SnpAttestationReport);

  // Failure mode: the endorsement array must be exactly [vcek, ask, ark].
  await assertRejectsStringError(
    pkg.verify_snp_attestation_with_cert_chain_async(report, endorsements.slice(0, 2)),
    /expected AMD endorsements/,
  );
});

// verify_uvm_endorsement: verify_uvm_endorsement_async.
test('verify_uvm_endorsement returns a CBOR payload and rejects an untrusted root', async () => {
  const { uvmEndorsement } = loadCaciInputs();

  const uvm = await pkg.verify_uvm_endorsement_async(uvmEndorsement, TRUSTED_DIDX509);
  assert.ok(uvm instanceof pkg.CborValue);
  const sign1 = uvm.as_cose_sign1();
  assert.ok(sign1 instanceof pkg.CoseSign1);
  assert.ok(sign1.payload().length > 0);

  // Failure mode: a did:x509 root that doesn't match the chain is rejected.
  await assertRejectsStringError(
    pkg.verify_uvm_endorsement_async(
      uvmEndorsement,
      'did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::eku:1.3.6.1.4.1.311.76.59.1.2',
    ),
    /DID x509 policy error: issuer DID prefix .* does not match trusted DID prefix/,
  );
});

// verify_caci_attestation: the full relying-party policy check.
test('verify_caci_attestation returns report data and rejects an empty policy set', async () => {
  const { manifest, report, endorsements, uvmEndorsement, policies } = loadCaciInputs();

  const attestation = await pkg.verify_snp_attestation_with_cert_chain_async(report, endorsements);
  const uvm = await pkg.verify_uvm_endorsement_async(uvmEndorsement, TRUSTED_DIDX509);

  const reportData = await pkg.verify_caci_attestation(
    attestation,
    JSON.stringify(manifest.minimum_tcb),
    policies,
    uvm,
    manifest.uvm_feed,
    BigInt(manifest.minimum_svn),
  );
  assert.ok(reportData instanceof Uint8Array);
  assert.equal(reportData.length, 64);

  // Failure mode: at least one trusted execution policy digest is required.
  await assertRejectsStringError(
    pkg.verify_caci_attestation(
      attestation,
      JSON.stringify(manifest.minimum_tcb),
      [],
      uvm,
      manifest.uvm_feed,
      BigInt(manifest.minimum_svn),
    ),
    /at least one trusted CACI execution policy/,
  );
});

// Standalone COSE_Sign1 signature verification: the wasm equivalent of the C
// ABI tav_verify_cose_sign1_embedded / tav_verify_cose_sign1_detached. Uses the
// same P-256 verification-only vector as the C consumer and in-crate tests.
const COSE_ALG_ES256 = -7;
const COSE_PHDR = [0xa1, 0x01, 0x26];
const COSE_PAYLOAD = textBytes('verification-only COSE vector');
const COSE_SPKI = new Uint8Array([
  48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
  3, 1, 7, 3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119,
  177, 246, 18, 133, 248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11,
  85, 3, 249, 180, 113, 248, 87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72,
  167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11, 126, 11, 242, 186, 211,
  205,
]);
const COSE_SIG = [
  90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47,
  248, 221, 245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92,
  210, 184, 112, 104, 224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93,
  103, 128, 147, 144, 252, 13, 252, 91, 233, 88, 189, 169, 103, 151,
];

// Append a CBOR byte string (major type 2) for buffers up to 255 bytes.
function putBstr(out, bytes) {
  if (bytes.length < 24) out.push(0x40 | bytes.length);
  else out.push(0x58, bytes.length);
  for (const b of bytes) out.push(b);
}

// Build a tagged (18) COSE_Sign1 envelope [protected, {}, payload, signature].
// With embeddedPayload false the payload slot is CBOR null (detached).
function buildSign1(embeddedPayload) {
  const env = [0xd2, 0x84];
  putBstr(env, COSE_PHDR);
  env.push(0xa0); // empty unprotected header map
  if (embeddedPayload) putBstr(env, COSE_PAYLOAD);
  else env.push(0xf6); // CBOR null
  putBstr(env, COSE_SIG);
  return new Uint8Array(env);
}

function coseSign1(bytes) {
  return pkg.CborValue.from_bytes(bytes).as_cose_sign1();
}

test('CoseSign1.verify_embedded accepts a valid signature and rejects tampering', async () => {
  // Valid embedded signature resolves.
  await coseSign1(buildSign1(true)).verify_embedded(COSE_SPKI, COSE_ALG_ES256);

  // Corrupting the trailing signature byte makes verification fail; a verifier
  // that skipped the signature check would wrongly resolve.
  const tampered = buildSign1(true);
  tampered[tampered.length - 1] ^= 0xff;
  await assertRejectsStringError(
    coseSign1(tampered).verify_embedded(COSE_SPKI, COSE_ALG_ES256),
  );
});

test('CoseSign1.verify_detached accepts a nil payload and rejects an embedded one', async () => {
  // A detached envelope (nil payload) verifies against the caller-supplied payload.
  await coseSign1(buildSign1(false)).verify_detached(COSE_PAYLOAD, COSE_SPKI, COSE_ALG_ES256);

  // The wrong detached payload fails the signature check.
  await assertRejectsStringError(
    coseSign1(buildSign1(false)).verify_detached(
      textBytes('a different payload'),
      COSE_SPKI,
      COSE_ALG_ES256,
    ),
  );

  // An embedded (byte-string) payload is rejected by detached verification.
  await assertRejectsStringError(
    coseSign1(buildSign1(true)).verify_detached(COSE_PAYLOAD, COSE_SPKI, COSE_ALG_ES256),
    /nil COSE payload/,
  );
});

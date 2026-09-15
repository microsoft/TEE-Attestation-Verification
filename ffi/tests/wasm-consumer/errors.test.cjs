// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { pkg } = require('./support.cjs');

test('shared error codes match the public C header exactly', () => {
  const mapping = {
    TAV_ERROR_OK: 'Ok',
    TAV_ERROR_INVALID_ARGUMENT: 'InvalidArgument',
    TAV_ERROR_IS_NULL: 'ErrorIsNull',
    TAV_ERROR_PANIC: 'Panic',
    TAV_ERROR_SNP_UNSUPPORTED_PROCESSOR: 'UnsupportedProcessor',
    TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE: 'InvalidRootCertificate',
    TAV_ERROR_SNP_CERTIFICATE_CHAIN_ERROR: 'CertificateChainError',
    TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR: 'SignatureVerificationError',
    TAV_ERROR_SNP_TCB_VERIFICATION_ERROR: 'TcbVerificationError',
    TAV_ERROR_COSE_CBOR: 'CoseCbor',
    TAV_ERROR_COSE_UNEXPECTED_TYPE: 'CoseUnexpectedType',
    TAV_ERROR_COSE_UNSUPPORTED_ALGORITHM: 'CoseUnsupportedAlgorithm',
    TAV_ERROR_COSE_KEY_IMPORT: 'CoseKeyImport',
    TAV_ERROR_COSE_VERIFICATION: 'CoseVerification',
    TAV_ERROR_CACI_COSE: 'CaciCose',
    TAV_ERROR_CACI_CERTIFICATE: 'CaciCertificate',
    TAV_ERROR_CACI_DID_X509: 'CaciDidX509',
    TAV_ERROR_CACI_SIGNATURE: 'CaciSignature',
    TAV_ERROR_CACI_MEASUREMENT: 'CaciMeasurement',
    TAV_ERROR_CACI_POLICY: 'CaciPolicy',
    TAV_ERROR_CBOR_DECODE_FAILED: 'CborDecodeFailed',
    TAV_ERROR_CBOR_KEY_NOT_FOUND: 'CborKeyNotFound',
    TAV_ERROR_CBOR_OUT_OF_BOUND: 'CborOutOfBound',
    TAV_ERROR_CBOR_TYPE_MISMATCH: 'CborTypeMismatch',
    TAV_ERROR_CBOR_ENCODE_FAILED: 'CborEncodeFailed',
  };
  const header = fs.readFileSync(path.join(__dirname, '../../include/tav/errors.h'), 'utf8');
  const entries = [...header.matchAll(/\b(TAV_ERROR_\w+)\s*=\s*(\d+)\s*,/g)];
  const names = entries.map(([, name]) => name);
  assert.equal(new Set(names).size, names.length, 'duplicate C enum member');
  assert.deepEqual(names.sort(), Object.keys(mapping).sort());
  const managedNames = Object.keys(pkg.ErrorCode).filter((name) => !/^\d+$/.test(name));
  assert.deepEqual(managedNames.sort(), Object.values(mapping).sort());
  for (const [, name, value] of entries) {
    assert.equal(pkg.ErrorCode[mapping[name]], Number(value), name);
  }
});

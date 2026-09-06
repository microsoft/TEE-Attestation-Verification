// Configuration for the attester demo.
// These values are stubs — fill in with real values for your deployment.

const CONFIG = {
  // URL of the backend attester service that provides attestation reports.
  backendUrl: "http://localhost:8080",

  // Endpoint that returns the raw attestation report (1184 bytes).
  attestationEndpoint: "/api/attestation",

  // Endpoint for fetching application data once attested.
  dataEndpoint: "/api/data",

  // Expected attestation report field values.
  // These should match your known-good deployment.
  expectedMeasurements: {
    // SHA-384 measurement of the guest launch image (hex, 96 chars).
    // Set to null to skip measurement check.
    measurement: null,

    // Expected guest policy (as a decimal u64 string).
    // Set to null to skip policy check.
    policy: null,

    // Expected report_data prefix (hex).
    // Useful if the guest puts a nonce or public key hash in report_data.
    // Set to null to skip.
    reportDataPrefix: null,

    // Expected host_data (hex, 64 chars).
    // Set to null to skip.
    hostData: null,
  },
};

export default CONFIG;

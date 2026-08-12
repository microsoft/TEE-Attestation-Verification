# TeeAttestationVerification for .NET

Linux x64 .NET 8 bindings for verifying SNP and CACI attestations through the
repository's native C ABI.

## Install

Add the package from your configured NuGet feed:

```bash
dotnet add package TeeAttestationVerification --version 1.0.7
```

The runtime environment must provide:

- a Linux x64 process;
- glibc 2.35 or newer;
- OpenSSL 3 (`libssl.so.3` and `libcrypto.so.3`).

## Inspect an unverified SNP report

```csharp
using SnpAttestationReport report =
    SnpAttestationReport.FromUnverifiedBytes(reportBytes);
byte[] chipId = report.ChipId();
```

`FromUnverifiedBytes` checks only that the input has the fixed SNP report size.
Field values, reserved bytes, signatures, certificates, and TCBs remain
untrusted. Use `VerifySnpAttestation` before making trust decisions, and do not
pass an unverified report to `VerifyCaciAttestation`.

## Verify a CACI attestation

Confidential ACI publishes `host-amd-cert-base64` and
`reference-info-base64` under its `UVM_SECURITY_CONTEXT_DIR`. Send those files
and a hex-encoded SNP attestation report to the relying party.

```csharp
using System.Text.Json;
using TeeAttestationVerification;

const string TrustedDidX509 =
    "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s" +
    "::eku:1.3.6.1.4.1.311.76.59.1.2";
const string TrustedUvmFeed = "ContainerPlat-AMD-UVM";

// Evidence supplied by the C-ACI workload is untrusted until verified.
byte[] reportBytes = ReadHexFile("attestation-report.hex");
AmdEndorsements amd = ReadAmdEndorsements("host-amd-cert-base64");
byte[] uvmEndorsement = ReadBase64File("reference-info-base64");

// Relying-party policy must be configured independently of that evidence.
ReadOnlyMemory<byte>[] trustedPolicyDigests =
[
    ReadHexFile("trusted-policy-digest.hex"),
];
ulong minimumUvmSvn = ulong.Parse(File.ReadAllText("minimum-uvm-svn").Trim());

using SnpAttestationReport report = AttestationVerifier.VerifySnpAttestation(
    reportBytes,
    amd.ArkPem,
    amd.AskPem,
    amd.VcekPem);
using CborValue uvm = AttestationVerifier.VerifyUvmEndorsement(
    uvmEndorsement,
    TrustedDidX509);

byte[] reportData = AttestationVerifier.VerifyCaciAttestation(
    report,
    [],
    trustedPolicyDigests,
    uvm,
    TrustedUvmFeed,
    minimumUvmSvn);

Console.WriteLine(Convert.ToHexString(reportData));

static AmdEndorsements ReadAmdEndorsements(string path)
{
    using JsonDocument document = JsonDocument.Parse(ReadBase64File(path));
    JsonElement root = document.RootElement;
    string vcekPem = root.GetProperty("vcekCert").GetString()
        ?? throw new FormatException("host AMD certificate JSON has no VCEK");
    string chainPem = root.GetProperty("certificateChain").GetString()
        ?? throw new FormatException("host AMD certificate JSON has no certificate chain");

    // C-ACI publishes the certificate chain in ASK, ARK order.
    IReadOnlyList<string> chain = AttestationVerifier.SplitPemBundle(chainPem);
    if (chain.Count != 2)
    {
        throw new FormatException(
            $"expected an ASK and ARK certificate, got {chain.Count}");
    }

    return new AmdEndorsements(chain[1], chain[0], vcekPem);
}

static byte[] ReadBase64File(string path) =>
    Convert.FromBase64String(RemoveWhitespace(File.ReadAllText(path)));

static byte[] ReadHexFile(string path) =>
    Convert.FromHexString(RemoveWhitespace(File.ReadAllText(path)));

static string RemoveWhitespace(string value) =>
    string.Concat(value.Where(character => !char.IsWhiteSpace(character)));

sealed record AmdEndorsements(string ArkPem, string AskPem, string VcekPem);
```

`VerifySnpAttestation` authenticates the AMD certificate chain and SNP report,
`VerifyUvmEndorsement` authenticates `reference-info-base64`, and
`VerifyCaciAttestation` applies the relying-party policy before returning the
verified 64-byte report data. The trusted DID, UVM feed, and minimum SVN are
specified by the
[Confidential ACI scheme](https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md#reference-info-base64).
Load trusted policy digests and the minimum SVN from relying-party
configuration.

Native calls fail with `DllNotFoundException` when the package does not carry a
native asset for the running platform, or when the OpenSSL 3 runtime libraries
are missing.

## Ownership and errors

All passed values are snapshotted before a synchronous native call, and all
returned values are managed copies or managed wrappers. Native resources held by
managed wrappers are reclaimed by garbage collection; `SnpAttestationReport`,
`CborValue`, and `CoseSign1` also implement `IDisposable` for faster release.
Native failures become `VerifyException` with a stable `ErrorCode`; managed input
errors use standard .NET exceptions.

## Build and test from source

Run from `ffi/csharp`:

```bash
python3 run_tests.py --configuration Release
```

The runner packs a uniquely versioned NuGet into a temporary feed, restores the
public xUnit consumer suite against that exact package, and tests the complete
NuGet → C# → C ABI → Rust path. It also checks the package layout and OpenSSL
dependencies.

Source builds require Rust, the OpenSSL development headers, and `pkg-config`.
The MSBuild project invokes Cargo with `crypto_openssl` for every build.

To create a release package:

```bash
dotnet pack \
  TeeAttestationVerification/TeeAttestationVerification.csproj \
  --configuration Release
```

The native asset is packaged at
`runtimes/linux-x64/native/libtee_attestation_verification_ffi.so`.

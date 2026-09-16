# TeeAttestationVerification for .NET

Cross-platform x64 .NET 8 bindings for CBOR parsing and COSE, SNP, and CACI
verification through the native C ABI.

## Install

Add the package from your configured NuGet feed:

```bash
dotnet add package TeeAttestationVerification --version 1.0.8
```

Supported runtime identifiers:

- `linux-x64` with glibc 2.35 or newer and OpenSSL 3.
- `osx-x64` with OpenSSL 3.
- `win-x64` on Windows 10 or Windows Server 2016 and newer.

ARM platforms are not currently supported. OpenSSL must be installed separately
on Linux and macOS; on macOS, it is available from Homebrew as `openssl@3`.

Missing native assets or required OpenSSL runtime libraries can cause
`DllNotFoundException`.

## Inspect an unverified SNP report

```csharp
using TeeAttestationVerification;

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

## Ownership and errors

Use `using` or `Dispose` to release `SnpAttestationReport`, `CborValue`, and
`CoseSign1` handles when finished. Their safe handles also release native
resources during finalization. Returned byte arrays are managed copies.

`CborValue.FromBytes` snapshots and pins the input, then copies the parsed tree
into native-owned storage before unpinning. Returned values and their projections
do not depend on managed input buffers.

Native failures throw `VerifyException`; its `Code` property identifies the
error. Invalid managed arguments throw standard .NET exceptions.

## Build and test from source

Local builds require Linux x64, the .NET 8 SDK, Rust, OpenSSL development
headers, and `pkg-config`. Run from `ffi/csharp`:

```bash
python3 run_tests.py --configuration Release
```

The runner builds a Linux development package and runs the consumer suite
against that package.

To create a local Linux development package:

```bash
dotnet pack \
  TeeAttestationVerification/TeeAttestationVerification.csproj \
  --configuration Release
```

The local native asset is packaged at
`runtimes/linux-x64/native/libtee_attestation_verification_ffi.so`.
Release packages are built in CI from native assets produced on all three host
operating systems.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TeeAttestationVerification.Tests;

public sealed class PublicApiTests
{
    [Fact]
    public void ErrorCodeValuesMatchNativeAbi()
    {
        AssertManagedEnumMatchesHeader(typeof(ErrorCode),
            "ffi/include/tav/errors.h",
            "TavErrorCode",
            [
                ("TAV_ERROR_OK", nameof(ErrorCode.Ok)),
                ("TAV_ERROR_INVALID_ARGUMENT", nameof(ErrorCode.InvalidArgument)),
                ("TAV_ERROR_IS_NULL", nameof(ErrorCode.ErrorIsNull)),
                ("TAV_ERROR_PANIC", nameof(ErrorCode.Panic)),
                ("TAV_ERROR_SNP_UNSUPPORTED_PROCESSOR", nameof(ErrorCode.UnsupportedProcessor)),
                ("TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE", nameof(ErrorCode.InvalidRootCertificate)),
                ("TAV_ERROR_SNP_CERTIFICATE_CHAIN_ERROR", nameof(ErrorCode.CertificateChainError)),
                ("TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR", nameof(ErrorCode.SignatureVerificationError)),
                ("TAV_ERROR_SNP_TCB_VERIFICATION_ERROR", nameof(ErrorCode.TcbVerificationError)),
                ("TAV_ERROR_COSE_CBOR", nameof(ErrorCode.CoseCbor)),
                ("TAV_ERROR_COSE_UNEXPECTED_TYPE", nameof(ErrorCode.CoseUnexpectedType)),
                ("TAV_ERROR_COSE_UNSUPPORTED_ALGORITHM", nameof(ErrorCode.CoseUnsupportedAlgorithm)),
                ("TAV_ERROR_COSE_KEY_IMPORT", nameof(ErrorCode.CoseKeyImport)),
                ("TAV_ERROR_COSE_VERIFICATION", nameof(ErrorCode.CoseVerification)),
                ("TAV_ERROR_CACI_COSE", nameof(ErrorCode.CaciCose)),
                ("TAV_ERROR_CACI_CERTIFICATE", nameof(ErrorCode.CaciCertificate)),
                ("TAV_ERROR_CACI_DID_X509", nameof(ErrorCode.CaciDidX509)),
                ("TAV_ERROR_CACI_SIGNATURE", nameof(ErrorCode.CaciSignature)),
                ("TAV_ERROR_CACI_MEASUREMENT", nameof(ErrorCode.CaciMeasurement)),
                ("TAV_ERROR_CACI_POLICY", nameof(ErrorCode.CaciPolicy)),
                ("TAV_ERROR_CBOR_DECODE_FAILED", nameof(ErrorCode.CborDecodeFailed)),
                ("TAV_ERROR_CBOR_KEY_NOT_FOUND", nameof(ErrorCode.CborKeyNotFound)),
                ("TAV_ERROR_CBOR_OUT_OF_BOUND", nameof(ErrorCode.CborOutOfBound)),
                ("TAV_ERROR_CBOR_TYPE_MISMATCH", nameof(ErrorCode.CborTypeMismatch)),
                ("TAV_ERROR_CBOR_ENCODE_FAILED", nameof(ErrorCode.CborEncodeFailed)),
            ]);
    }

    [Fact]
    public void CborKindValuesMatchNativeAbi()
    {
        AssertManagedEnumMatchesHeader(typeof(CborKind),
            "ffi/include/tav/cbor.h",
            "TavCborHandleKind",
            [
                ("TAV_CBOR_HANDLE_KIND_INVALID", "Invalid"),
                ("TAV_CBOR_HANDLE_KIND_SIGNED", "Int"),
                ("TAV_CBOR_HANDLE_KIND_BYTES", "Bytes"),
                ("TAV_CBOR_HANDLE_KIND_STRING", "Text"),
                ("TAV_CBOR_HANDLE_KIND_ARRAY", "Array"),
                ("TAV_CBOR_HANDLE_KIND_MAP", "Map"),
                ("TAV_CBOR_HANDLE_KIND_TAGGED", "Tagged"),
                ("TAV_CBOR_HANDLE_KIND_SIMPLE", "Simple"),
            ]);
    }

    [Fact]
    public void CoseAlgorithmValuesMatchNativeAbi()
    {
        AssertManagedEnumMatchesHeader(typeof(CoseAlgorithm),
            "ffi/include/tav/cose.h",
            "TavCoseAlgorithm",
            [
                ("TAV_COSE_ALG_ES256", nameof(CoseAlgorithm.Es256)),
                ("TAV_COSE_ALG_ES384", nameof(CoseAlgorithm.Es384)),
                ("TAV_COSE_ALG_ES512", nameof(CoseAlgorithm.Es512)),
                ("TAV_COSE_ALG_PS256", nameof(CoseAlgorithm.Ps256)),
                ("TAV_COSE_ALG_PS384", nameof(CoseAlgorithm.Ps384)),
                ("TAV_COSE_ALG_PS512", nameof(CoseAlgorithm.Ps512)),
            ]);
    }

    private static void AssertManagedEnumMatchesHeader(
        Type enumType,
        string headerPath,
        string cType,
        IReadOnlyList<(string CName, string ManagedName)> mappings)
    {
        Assert.Equal(typeof(int), Enum.GetUnderlyingType(enumType));

        IReadOnlyDictionary<string, long> cValues = ParseCEnum(headerPath, cType);
        Dictionary<string, long> managedValues = Enum.GetNames(enumType)
            .ToDictionary(
                name => name,
                name => Convert.ToInt64(Enum.Parse(enumType, name)),
                StringComparer.Ordinal);

        Assert.Equal(
            mappings.Select(mapping => mapping.CName).Order(StringComparer.Ordinal),
            cValues.Keys.Order(StringComparer.Ordinal));
        Assert.Equal(
            mappings.Select(mapping => mapping.ManagedName).Order(StringComparer.Ordinal),
            managedValues.Keys.Order(StringComparer.Ordinal));

        foreach ((string cName, string managedName) in mappings)
        {
            Assert.Equal(cValues[cName], managedValues[managedName]);
        }
    }

    private static IReadOnlyDictionary<string, long> ParseCEnum(
        string relativePath,
        string cType)
    {
        string header = FixtureData.ReadText(relativePath);
        var declaration = System.Text.RegularExpressions.Regex.Match(
            header, $@"\btypedef\s+enum\s+{System.Text.RegularExpressions.Regex.Escape(cType)}\s*\{{");
        Assert.True(declaration.Success, $"{relativePath} does not declare {cType}");
        int bodyStart = declaration.Index + declaration.Length;
        int bodyEnd = header.IndexOf('}', bodyStart);
        Assert.True(bodyEnd >= 0, $"{relativePath} does not terminate {cType}");

        return header[bodyStart..bodyEnd]
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => line.Contains('=', StringComparison.Ordinal))
            .Select(line => line.TrimEnd(',').Split('=', 2))
            .ToDictionary(
                parts => parts[0].Trim(),
                parts => long.Parse(parts[1].Trim(), System.Globalization.CultureInfo.InvariantCulture),
                StringComparer.Ordinal);
    }

}

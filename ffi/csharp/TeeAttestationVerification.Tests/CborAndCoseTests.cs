// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Buffers.Binary;
using System.Text;

namespace TeeAttestationVerification.Tests;

public sealed class CborAndCoseTests
{
    [Fact]
    public void CompoundKeysAreLookedUpByValue()
    {
        // {[1, 18(2)]: 7}, looked up with a separately parsed copy of the key.
        using CborValue map = CborValue.FromBytes(new byte[] { 0xa1, 0x82, 1, 0xd2, 2, 7 });
        using CborValue key = CborValue.FromBytes(new byte[] { 0x82, 1, 0xd2, 2 });
        Assert.True(map.TryGetValue(key, out CborValue? result));
        using CborValue found = Assert.IsType<CborValue>(result);
        using CborValue direct = map.MapAt(key);
        map.Dispose();
        Assert.Equal(7, found.GetInt64());
        Assert.Equal(7, direct.GetInt64());
    }

    [Fact]
    public void MapsInsideKeysAndOversizedMapsAreRejected()
    {
        // {{1: 2, 3: 4}: 7}
        Assert.Equal(ErrorCode.CborDecodeFailed,
            Assert.Throws<VerifyException>(
                () => CborValue.FromBytes(new byte[] { 0xa1, 0xa2, 1, 2, 3, 4, 7 })).Code);

        // {0: 0, 1: 0, ...} in preferred encoding: 256 entries parse, 257 do not.
        static byte[] FlatMap(int entries)
        {
            List<byte> document = [0xb9, (byte)(entries >> 8), (byte)entries];
            for (int key = 0; key < entries; key++)
            {
                if (key >= 256)
                {
                    document.Add(0x19);
                    document.Add((byte)(key >> 8));
                }
                else if (key >= 24)
                {
                    document.Add(0x18);
                }

                document.Add((byte)key);
                document.Add(0x00);
            }

            return [.. document];
        }

        using CborValue atLimit = CborValue.FromBytes(FlatMap(256));
        Assert.Equal(256, atLimit.GetLength());
        Assert.Equal(ErrorCode.CborDecodeFailed,
            Assert.Throws<VerifyException>(() => CborValue.FromBytes(FlatMap(257))).Code);
    }

    private static readonly byte[] ProtectedHeader = [0xa1, 0x01, 0x26];
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("verification-only COSE vector");
    private static readonly byte[] Spki =
    [
        48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
        3, 1, 7, 3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119,
        177, 246, 18, 133, 248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11,
        85, 3, 249, 180, 113, 248, 87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72,
        167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11, 126, 11, 242, 186, 211,
        205,
    ];
    private static readonly byte[] Signature =
    [
        90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47,
        248, 221, 245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92,
        210, 184, 112, 104, 224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93,
        103, 128, 147, 144, 252, 13, 252, 91, 233, 88, 189, 169, 103, 151,
    ];

    [Fact]
    public void CborOperationsReturnExpectedValues()
    {
        using CborValue integer = CborValue.FromBytes(new byte[] { 0x01 });
        Assert.Equal(CborKind.Int, integer.Kind);
        Assert.Equal(1, integer.GetInt64());
        Assert.Equal(new byte[] { 0x01 }, integer.ToBytes());
        VerifyException typeError = Assert.Throws<VerifyException>(() => integer.GetTextString());
        Assert.Equal(ErrorCode.CborTypeMismatch, typeError.Code);

        using CborValue simple = CborValue.FromBytes(new byte[] { 0xf6 });
        Assert.Equal(CborKind.Simple, simple.Kind);
        Assert.Equal(22, simple.GetSimpleValue());

        using CborValue bytes = CborValue.FromBytes(new byte[] { 0x43, 1, 2, 3 });
        Assert.Equal(CborKind.Bytes, bytes.Kind);
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes.GetByteString());

        using CborValue text = CborValue.FromBytes(new byte[] { 0x62, 0x68, 0x69 });
        Assert.Equal(CborKind.Text, text.Kind);
        Assert.Equal("hi", text.GetTextString());

        using CborValue array = CborValue.FromBytes(new byte[] { 0x82, 0x01, 0x61, 0x61 });
        Assert.Equal(CborKind.Array, array.Kind);
        Assert.Equal(2, array.GetLength());
        using CborValue first = array.ArrayAt(0);
        using CborValue second = array.ArrayAt(1);
        Assert.Equal(1, first.GetInt64());
        Assert.Equal("a", second.GetTextString());

        using CborValue map = CborValue.FromBytes(
            new byte[] { 0xa3, 0x01, 0x63, (byte)'o', (byte)'n', (byte)'e',
                0x61, (byte)'k', 0x18, 0x2a, 0x41, 0xaa, 0xf5 });
        Assert.Equal(CborKind.Map, map.Kind);
        Assert.Equal(3, map.GetLength());
        using CborValue one = map.MapAt(1L);
        using CborValue fortyTwo = map.MapAt("k");
        using CborValue key = CborValue.FromBytes(new byte[] { 0x41, 0xaa });
        using CborValue trueValue = map.MapAt(key);
        Assert.Equal("one", one.GetTextString());
        Assert.Equal(42, fortyTwo.GetInt64());
        Assert.Equal(21, trueValue.GetSimpleValue());
        Assert.True(map.TryGetValue(1L, out CborValue? oneByTry));
        using CborValue oneTryValue = Assert.IsType<CborValue>(oneByTry);
        Assert.Equal("one", oneTryValue.GetTextString());
        Assert.False(map.TryGetValue(2L, out CborValue? missingInt));
        Assert.Null(missingInt);

        Assert.True(map.TryGetValue("k", out CborValue? fortyTwoByTry));
        using CborValue fortyTwoTryValue = Assert.IsType<CborValue>(fortyTwoByTry);
        Assert.Equal(42, fortyTwoTryValue.GetInt64());
        Assert.False(map.TryGetValue("missing", out CborValue? missingText));
        Assert.Null(missingText);

        Assert.True(map.TryGetValue(key, out CborValue? trueByTry));
        using CborValue trueTryValue = Assert.IsType<CborValue>(trueByTry);
        Assert.Equal(21, trueTryValue.GetSimpleValue());

        KeyValuePair<CborValue, CborValue> entry = map.MapEntryAt(0);
        using (entry.Key)
        using (entry.Value)
        {
            Assert.Equal(1, entry.Key.GetInt64());
            Assert.Equal("one", entry.Value.GetTextString());
        }
        using CborValue mapKey = map.MapKeyAt(1);
        using CborValue mapValue = map.MapValueAt(1);
        Assert.Equal("k", mapKey.GetTextString());
        Assert.Equal(42, mapValue.GetInt64());

        using CborValue tagged = CborValue.FromBytes(new byte[] { 0xc1, 0x18, 0x2a });
        Assert.Equal(CborKind.Tagged, tagged.Kind);
        Assert.Equal(1ul, tagged.GetTag());
        using CborValue taggedPayload = tagged.TaggedPayload();
        Assert.Equal(42, taggedPayload.GetInt64());
    }

    [Fact]
    public void OwnedChildOutlivesDisposedParent()
    {
        using CborValue parent = CborValue.FromBytes(
            new byte[] { 0x81, 0x82, 0x43, 1, 2, 3, 0x01 });
        using CborValue child = parent.ArrayAt(0);

        parent.Dispose();
        Assert.Throws<ObjectDisposedException>(() => parent.ArrayAt(0));
        using CborValue grandchild = child.ArrayAt(0);
        Assert.Equal(new byte[] { 1, 2, 3 }, grandchild.GetByteString());

        child.Dispose();
        Assert.Throws<ObjectDisposedException>(() => child.ArrayAt(0));
    }

    [Fact]
    public void OwnedCoseSign1OutlivesDisposedParent()
    {
        using CborValue parent = CborValue.FromBytes(BuildSign1(embeddedPayload: true));
        using CoseSign1 sign1 = parent.AsCoseSign1();

        parent.Dispose();
        CompactAndReuseManagedHeap();
        Assert.Throws<ObjectDisposedException>(() => parent.AsCoseSign1());
        Assert.Equal(Payload, sign1.GetPayload());
        sign1.VerifyEmbedded(Spki, CoseAlgorithm.Es256);

        sign1.Dispose();
        Assert.Throws<ObjectDisposedException>(() => sign1.GetPayload());
    }

    [Fact]
    public void CoseSign1AccessorsAndVerificationModesReturnExpectedResults()
    {
        using CborValue embeddedRoot = CborValue.FromBytes(
            BuildSign1(embeddedPayload: true));
        using CoseSign1 embedded = embeddedRoot.AsCoseSign1();
        embeddedRoot.Dispose();

        Assert.Equal(ProtectedHeader, embedded.GetProtectedBytes());
        using CborValue protectedHeader = embedded.GetProtectedHeader();
        using CborValue algorithm = protectedHeader.MapAt(1L);
        Assert.Equal(-7, algorithm.GetInt64());
        using CborValue unprotected = embedded.GetUnprotectedHeader();
        Assert.Equal(CborKind.Map, unprotected.Kind);
        Assert.Equal(Payload, embedded.GetPayload());
        Assert.Equal(Signature, embedded.GetSignature());
        embedded.VerifyEmbedded(Spki, CoseAlgorithm.Es256);

        byte[] tampered = BuildSign1(embeddedPayload: true);
        tampered[^1] ^= 0xff;
        using CborValue tamperedRoot = CborValue.FromBytes(tampered);
        using CoseSign1 tamperedSign1 = tamperedRoot.AsCoseSign1();
        VerifyException verificationError = Assert.Throws<VerifyException>(
            () => tamperedSign1.VerifyEmbedded(Spki, CoseAlgorithm.Es256));
        Assert.Equal(ErrorCode.CoseVerification, verificationError.Code);

        using CborValue detachedRoot = CborValue.FromBytes(BuildSign1(embeddedPayload: false));
        using CoseSign1 detached = detachedRoot.AsCoseSign1();
        detached.VerifyDetached(Payload, Spki, CoseAlgorithm.Es256);

        embedded.Dispose();
        Assert.Throws<ObjectDisposedException>(() => embedded.GetSignature());
    }

    [Fact]
    public void ProtectedHeaderOverTheLengthLimitIsRejected()
    {
        int limit = FixtureData.ReadCHeaderLimit(
            "ffi/include/tav/cose.h", "TAV_COSE_MAX_PROTECTED_HEADER_LEN");

        // At the limit the header is decoded, so verification reaches the
        // signature, which was made over a different header.
        using (CborValue root = CborValue.FromBytes(
            BuildSign1(embeddedPayload: true, PaddedProtectedHeader(limit))))
        using (CoseSign1 sign1 = root.AsCoseSign1())
        {
            using CborValue protectedHeader = sign1.GetProtectedHeader();
            using CborValue algorithm = protectedHeader.MapAt(1L);
            Assert.Equal(-7, algorithm.GetInt64());
            VerifyException signatureError = Assert.Throws<VerifyException>(
                () => sign1.VerifyEmbedded(Spki, CoseAlgorithm.Es256));
            Assert.Equal(ErrorCode.CoseVerification, signatureError.Code);
            Assert.Contains("signature verification failed", signatureError.Message);
        }

        // A byte longer, the header is rejected by its length alone. The
        // envelope still parses.
        string overLimit = $"protected header is {limit + 1} bytes, over the {limit}-byte limit";
        using CborValue embeddedRoot = CborValue.FromBytes(
            BuildSign1(embeddedPayload: true, PaddedProtectedHeader(limit + 1)));
        using CoseSign1 embedded = embeddedRoot.AsCoseSign1();
        Assert.Equal(limit + 1, embedded.GetProtectedBytes().Length);
        VerifyException headerError = Assert.Throws<VerifyException>(
            () => embedded.GetProtectedHeader());
        Assert.Equal(ErrorCode.CborDecodeFailed, headerError.Code);
        Assert.Equal(overLimit, headerError.Message);
        VerifyException embeddedError = Assert.Throws<VerifyException>(
            () => embedded.VerifyEmbedded(Spki, CoseAlgorithm.Es256));
        Assert.Equal(ErrorCode.CoseVerification, embeddedError.Code);
        Assert.Equal(overLimit, embeddedError.Message);

        using CborValue detachedRoot = CborValue.FromBytes(
            BuildSign1(embeddedPayload: false, PaddedProtectedHeader(limit + 1)));
        using CoseSign1 detached = detachedRoot.AsCoseSign1();
        VerifyException detachedError = Assert.Throws<VerifyException>(
            () => detached.VerifyDetached(Payload, Spki, CoseAlgorithm.Es256));
        Assert.Equal(ErrorCode.CoseVerification, detachedError.Code);
        Assert.Equal(overLimit, detachedError.Message);
    }

    [Fact]
    public void ParsedPayloadsOwnTheirBytesAfterUnpinningAndParentDisposal()
    {
        byte[] input = [0x82, 0x43, 1, 2, 3, 0x62, 0x68, 0x69];
        using CborValue parent = CborValue.FromBytes(input);
        Array.Fill(input, (byte)0xff);
        using CborValue bytes = parent.ArrayAt(0);
        using CborValue text = parent.ArrayAt(1);
        parent.Dispose();
        CompactAndReuseManagedHeap();
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes.GetByteString());
        Assert.Equal("hi", text.GetTextString());
        Assert.Equal(new byte[] { 0x43, 1, 2, 3 }, bytes.ToBytes());
        Assert.Equal(new byte[] { 0x62, 0x68, 0x69 }, text.ToBytes());
        byte[] copy = bytes.GetByteString();
        copy[0] = 0xff;
        Assert.Equal(new byte[] { 1, 2, 3 }, bytes.GetByteString());
        Assert.Throws<ObjectDisposedException>(() => parent.Kind);
    }

    [Fact]
    public void EmptyPayloadsRemainLiveOwnedValues()
    {
        Assert.Equal(ErrorCode.CborDecodeFailed,
            Assert.Throws<VerifyException>(() => CborValue.FromBytes(ReadOnlyMemory<byte>.Empty)).Code);
        using CborValue bytes = CborValue.FromBytes(new byte[] { 0x40 });
        using CborValue text = CborValue.FromBytes(new byte[] { 0x60 });
        CompactAndReuseManagedHeap();
        Assert.Equal(CborKind.Bytes, bytes.Kind);
        Assert.Equal(CborKind.Text, text.Kind);
        Assert.Empty(bytes.GetByteString());
        Assert.Empty(text.GetTextString());
        Assert.Equal(new byte[] { 0x40 }, bytes.ToBytes());
        Assert.Equal(new byte[] { 0x60 }, text.ToBytes());
    }

    [Fact]
    public void MapHelpersHandleEmptyUnicodeAndNegativeKeys()
    {
        using CborValue map = CborValue.FromBytes(
            new byte[] { 0xa3, 0x60, 0x01, 0x62, 0xcf, 0x80, 0x02, 0x20, 0x03 });
        using CborValue emptyText = map.MapAt("");
        using CborValue unicode = map.MapAt("π");
        using CborValue negative = map.MapAt(-1L);
        Assert.True(map.TryGetValue("π", out CborValue? found));
        using CborValue foundValue = Assert.IsType<CborValue>(found);
        KeyValuePair<CborValue, CborValue> entry = map.MapEntryAt(1);
        using CborValue key = entry.Key;
        using CborValue value = entry.Value;
        map.Dispose();
        CompactAndReuseManagedHeap();
        Assert.Equal(1, emptyText.GetInt64());
        Assert.Equal(2, unicode.GetInt64());
        Assert.Equal(3, negative.GetInt64());
        Assert.Equal(2, foundValue.GetInt64());
        Assert.Equal("π", key.GetTextString());
        Assert.Equal(2, value.GetInt64());
    }

    [Fact]
    public void TryGetValueSuppressesOnlyMissingKeys()
    {
        using CborValue scalar = CborValue.FromBytes(new byte[] { 1 });
        using CborValue key = CborValue.FromBytes(new byte[] { 2 });
        Assert.Equal(ErrorCode.CborTypeMismatch,
            Assert.Throws<VerifyException>(() => scalar.TryGetValue(1L, out _)).Code);
        Assert.Equal(ErrorCode.CborTypeMismatch,
            Assert.Throws<VerifyException>(() => scalar.TryGetValue("key", out _)).Code);
        Assert.Equal(ErrorCode.CborTypeMismatch,
            Assert.Throws<VerifyException>(() => scalar.TryGetValue(key, out _)).Code);
        using CborValue map = CborValue.FromBytes(new byte[] { 0xa0 });
        Assert.False(map.TryGetValue(key, out CborValue? missing));
        Assert.Null(missing);
        Assert.Equal(ErrorCode.CborKeyNotFound,
            Assert.Throws<VerifyException>(() => map.MapAt(key)).Code);
        Assert.Throws<ArgumentNullException>(() => map.TryGetValue((CborValue)null!, out _));
        Assert.Throws<ArgumentNullException>(() => map.TryGetValue((string)null!, out _));
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => map.TryGetValue(key, out _));
        map.Dispose();
        Assert.Throws<ObjectDisposedException>(() => map.TryGetValue(1L, out _));
    }

    [Fact]
    public void GenericParseSerializationAndNavigationReportExactErrors()
    {
        Assert.Equal(ErrorCode.CborDecodeFailed,
            Assert.Throws<VerifyException>(() => CborValue.FromBytes(new byte[] { 0x18 })).Code);
        using CborValue nonCanonical = CborValue.FromBytes(new byte[] { 0x18, 1 });
        Assert.Equal(new byte[] { 1 }, nonCanonical.ToBytes());
        Assert.Equal(ErrorCode.CborDecodeFailed,
            Assert.Throws<VerifyException>(
                () => CborValue.FromBytes(new byte[] { 0xa2, 1, 2, 1, 3 })).Code);
        byte[] tooDeep = [.. Enumerable.Repeat((byte)0x81, 65), 0x01];
        Assert.Equal(ErrorCode.CborDecodeFailed,
            Assert.Throws<VerifyException>(() => CborValue.FromBytes(tooDeep)).Code);
        using CborValue array = CborValue.FromBytes(new byte[] { 0x80 });
        Assert.Equal(ErrorCode.CborOutOfBound,
            Assert.Throws<VerifyException>(() => array.ArrayAt(0)).Code);
        Assert.Equal(ErrorCode.CborTypeMismatch,
            Assert.Throws<VerifyException>(() => array.TaggedPayload()).Code);
        Assert.Throws<ArgumentOutOfRangeException>(() => array.ArrayAt(-1));
        using CborValue map = CborValue.FromBytes(new byte[] { 0xa0 });
        Assert.Equal(ErrorCode.CborOutOfBound,
            Assert.Throws<VerifyException>(() => map.MapEntryAt(0)).Code);
        Assert.Throws<ArgumentOutOfRangeException>(() => map.MapEntryAt(-1));
        using CborValue tagged = CborValue.FromBytes(new byte[] { 0xc1, 0x41, 0xaa });
        using CborValue payload = tagged.TaggedPayload();
        tagged.Dispose();
        CompactAndReuseManagedHeap();
        Assert.Equal(new byte[] { 0xaa }, payload.GetByteString());
    }

    private static void CompactAndReuseManagedHeap()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        byte[][] pressure = new byte[256][];
        for (int i = 0; i < pressure.Length; ++i)
        {
            pressure[i] = new byte[4096];
            Array.Fill(pressure[i], (byte)0xcc);
        }
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.KeepAlive(pressure);
    }

    private static byte[] BuildSign1(bool embeddedPayload, byte[]? protectedHeader = null)
    {
        List<byte> bytes = [0xd2, 0x84];
        PutByteString(bytes, protectedHeader ?? ProtectedHeader);
        bytes.Add(0xa0);
        if (embeddedPayload)
        {
            PutByteString(bytes, Payload);
        }
        else
        {
            bytes.Add(0xf6);
        }

        PutByteString(bytes, Signature);
        return bytes.ToArray();
    }

    // The protected header {1: -7, "pad": h'00...'} in exactly length bytes.
    private static byte[] PaddedProtectedHeader(int length)
    {
        byte[] header = new byte[length];
        new byte[] { 0xa2, 0x01, 0x26, 0x63, (byte)'p', (byte)'a', (byte)'d', 0x5a }
            .CopyTo(header, 0);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), (uint)(length - 12));
        return header;
    }

    private static void PutByteString(List<byte> destination, byte[] value)
    {
        int length = value.Length;
        if (length < 24)
        {
            destination.Add((byte)(0x40 | length));
        }
        else if (length < 0x100)
        {
            destination.Add(0x58);
            destination.Add((byte)length);
        }
        else if (length < 0x10000)
        {
            destination.Add(0x59);
            destination.Add((byte)(length >> 8));
            destination.Add((byte)length);
        }
        else
        {
            destination.Add(0x5a);
            destination.Add((byte)(length >> 24));
            destination.Add((byte)(length >> 16));
            destination.Add((byte)(length >> 8));
            destination.Add((byte)length);
        }

        destination.AddRange(value);
    }
}

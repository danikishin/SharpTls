using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls.Tests.Records;

public sealed class Tls12AeadRecordCipherTests
{
    public static TheoryData<TlsCipherSuite> SupportedSuites
    {
        get
        {
            var data = new TheoryData<TlsCipherSuite>
            {
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                TlsCipherSuite.TlsEcdheEcdsaWithAes256GcmSha384,
            };
            if (ChaCha20Poly1305.IsSupported)
            {
                data.Add(TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256);
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(SupportedSuites))]
    public void RoundTripsAllProtectedContentTypes(TlsCipherSuite cipherSuite)
    {
        var suite = Tls12CipherSuiteInfo.Get(cipherSuite);
        var key = Range(0, suite.KeyLength);
        var iv = Range(0x80, suite.FixedIvLength);

        foreach (var contentType in new[]
                 {
                     TlsContentType.Handshake,
                     TlsContentType.Alert,
                     TlsContentType.ApplicationData,
                 })
        {
            using var sender = new Tls12AeadRecordCipher(suite, key, iv);
            using var receiver = new Tls12AeadRecordCipher(suite, key, iv);
            var fragment = sender.Encrypt(contentType, [1, 2, 3, 4]);

            Assert.Equal([1, 2, 3, 4], receiver.Decrypt(contentType, fragment));
        }
    }

    [Fact]
    public void AesGcmUsesSequenceNumberAsEightByteExplicitNonceAndTls12Aad()
    {
        const ulong sequence = 0x0102030405060708;
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        var key = Range(0, 16);
        var fixedIv = new byte[] { 0xA0, 0xA1, 0xA2, 0xA3 };
        var plaintext = new byte[] { 1, 2, 3 };
        using var cipher = new Tls12AeadRecordCipher(
            suite,
            key,
            fixedIv,
            initialSequenceNumber: sequence);

        var actual = cipher.Encrypt(TlsContentType.Handshake, plaintext);
        var expected = new byte[8 + plaintext.Length + 16];
        var explicitNonce = expected.AsSpan(0, 8);
        WriteUInt64(explicitNonce, sequence);
        byte[] nonce = [.. fixedIv, .. explicitNonce];
        var aad = BuildAad(sequence, TlsContentType.Handshake, plaintext.Length);
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(
                nonce,
                plaintext,
                expected.AsSpan(8, plaintext.Length),
                expected.AsSpan(8 + plaintext.Length, 16),
                aad);
        }

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ChaChaNonceXorsPaddedSequenceWithFixedIvAndTransmitsNoExplicitNonce()
    {
        if (!ChaCha20Poly1305.IsSupported)
        {
            return;
        }

        const ulong sequence = 0x0102030405060708;
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithChaCha20Poly1305Sha256);
        var key = Range(0, 32);
        var fixedIv = Range(0x90, 12);
        var plaintext = new byte[] { 1, 2, 3 };
        using var cipher = new Tls12AeadRecordCipher(
            suite,
            key,
            fixedIv,
            initialSequenceNumber: sequence);

        var actual = cipher.Encrypt(TlsContentType.Handshake, plaintext);
        var expected = new byte[plaintext.Length + 16];
        var nonce = fixedIv.ToArray();
        Span<byte> paddedSequence = stackalloc byte[12];
        WriteUInt64(paddedSequence[4..], sequence);
        for (var index = 0; index < nonce.Length; index++)
        {
            nonce[index] ^= paddedSequence[index];
        }
        using (var chaCha = new ChaCha20Poly1305(key))
        {
            chaCha.Encrypt(
                nonce,
                plaintext,
                expected.AsSpan(0, plaintext.Length),
                expected.AsSpan(plaintext.Length, 16),
                BuildAad(sequence, TlsContentType.Handshake, plaintext.Length));
        }

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void TamperingTypeOrSequenceNumberFailsAuthentication()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var sender = new Tls12AeadRecordCipher(suite, new byte[16], new byte[4]);
        var fragment = sender.Encrypt(TlsContentType.Handshake, [1, 2, 3]);

        using var wrongType = new Tls12AeadRecordCipher(suite, new byte[16], new byte[4]);
        var typeException = Assert.Throws<TlsProtocolException>(() =>
            wrongType.Decrypt(TlsContentType.ApplicationData, fragment));
        Assert.Equal(TlsAlertDescription.BadRecordMac, typeException.Alert);

        using var wrongSequence = new Tls12AeadRecordCipher(
            suite,
            new byte[16],
            new byte[4],
            initialSequenceNumber: 1);
        var sequenceException = Assert.Throws<TlsProtocolException>(() =>
            wrongSequence.Decrypt(TlsContentType.Handshake, fragment));
        Assert.Equal(TlsAlertDescription.BadRecordMac, sequenceException.Alert);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(23)]
    public void TruncatedAesGcmFragmentsFailClosed(int length)
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var receiver = new Tls12AeadRecordCipher(suite, new byte[16], new byte[4]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            receiver.Decrypt(TlsContentType.Handshake, new byte[length]));

        Assert.Equal(TlsAlertDescription.BadRecordMac, exception.Alert);
    }

    [Fact]
    public void KeyUsageAndSequenceLimitsFailClosed()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var limited = new Tls12AeadRecordCipher(
            suite,
            new byte[16],
            new byte[4],
            maximumRecords: 1);
        _ = limited.Encrypt(TlsContentType.ApplicationData, [1]);
        Assert.Equal(
            TlsAlertDescription.GeneralError,
            Assert.Throws<TlsProtocolException>(() =>
                limited.Encrypt(TlsContentType.ApplicationData, [2])).Alert);

        using var exhausted = new Tls12AeadRecordCipher(
            suite,
            new byte[16],
            new byte[4],
            initialSequenceNumber: ulong.MaxValue,
            maximumRecords: 2);
        _ = exhausted.Encrypt(TlsContentType.ApplicationData, [1]);
        Assert.Equal(
            TlsAlertDescription.GeneralError,
            Assert.Throws<TlsProtocolException>(() =>
                exhausted.Encrypt(TlsContentType.ApplicationData, [2])).Alert);
    }

    [Fact]
    public void WrongRecordVersionAndOversizedPlaintextAreRejected()
    {
        var suite = Tls12CipherSuiteInfo.Get(
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256);
        using var cipher = new Tls12AeadRecordCipher(suite, new byte[16], new byte[4]);

        Assert.Equal(
            TlsAlertDescription.ProtocolVersion,
            Assert.Throws<TlsProtocolException>(() =>
                cipher.Encrypt(TlsContentType.Handshake, [], recordVersion: 0x0302)).Alert);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            cipher.Encrypt(
                TlsContentType.ApplicationData,
                new byte[TlsConstants.MaxPlaintextLength + 1]));
    }

    private static byte[] BuildAad(ulong sequence, TlsContentType contentType, int length)
    {
        var aad = new byte[13];
        WriteUInt64(aad.AsSpan(0, 8), sequence);
        aad[8] = (byte)contentType;
        aad[9] = 3;
        aad[10] = 3;
        aad[11] = (byte)(length >> 8);
        aad[12] = (byte)length;
        return aad;
    }

    private static void WriteUInt64(Span<byte> destination, ulong value)
    {
        destination[0] = (byte)(value >> 56);
        destination[1] = (byte)(value >> 48);
        destination[2] = (byte)(value >> 40);
        destination[3] = (byte)(value >> 32);
        destination[4] = (byte)(value >> 24);
        destination[5] = (byte)(value >> 16);
        destination[6] = (byte)(value >> 8);
        destination[7] = (byte)value;
    }

    private static byte[] Range(int start, int count) =>
        Enumerable.Range(start, count).Select(value => (byte)value).ToArray();
}

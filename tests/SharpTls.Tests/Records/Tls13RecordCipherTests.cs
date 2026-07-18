using System.Security.Cryptography;
using SharpTls.Cryptography;
using SharpTls.Protocol;
using SharpTls.Records;

namespace SharpTls.Tests.Records;

public sealed class Tls13RecordCipherTests
{
    public static TheoryData<TlsCipherSuite> SupportedSuites
    {
        get
        {
            var data = new TheoryData<TlsCipherSuite>
            {
                TlsCipherSuite.TlsAes128GcmSha256,
                TlsCipherSuite.TlsAes256GcmSha384,
            };
            if (System.Security.Cryptography.ChaCha20Poly1305.IsSupported)
            {
                data.Add(TlsCipherSuite.TlsChaCha20Poly1305Sha256);
            }
            return data;
        }
    }

    [Theory]
    [MemberData(nameof(SupportedSuites))]
    public void RoundTripsContentAndAllPaddingLengths(TlsCipherSuite cipherSuite)
    {
        var suite = CipherSuiteInfo.Get(cipherSuite);
        var key = Enumerable.Range(0, suite.KeyLength).Select(value => (byte)value).ToArray();
        var iv = Enumerable.Range(0, suite.IvLength).Select(value => (byte)(0xA0 + value)).ToArray();

        foreach (var padding in new[] { 0, 1, 31, 255 })
        {
            using var sender = new Tls13RecordCipher(suite, key, iv);
            using var receiver = new Tls13RecordCipher(suite, key, iv);
            var encrypted = sender.Encrypt(TlsContentType.Handshake, [1, 2, 3], padding);
            var decrypted = receiver.Decrypt(encrypted);

            Assert.Equal(TlsContentType.Handshake, decrypted.ContentType);
            Assert.Equal([1, 2, 3], decrypted.Content);
        }
    }

    [Fact]
    public void SequenceNumberChangesCiphertextAndStaysInSync()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var sender = new Tls13RecordCipher(suite, new byte[16], new byte[12]);
        using var receiver = new Tls13RecordCipher(suite, new byte[16], new byte[12]);

        var first = sender.Encrypt(TlsContentType.ApplicationData, [9]);
        var second = sender.Encrypt(TlsContentType.ApplicationData, [9]);
        Assert.NotEqual(first, second);
        Assert.Equal([9], receiver.Decrypt(first).Content);
        Assert.Equal([9], receiver.Decrypt(second).Content);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(16)]
    public void TruncatedCiphertextIsRejected(int length)
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var receiver = new Tls13RecordCipher(suite, new byte[16], new byte[12]);

        var exception = Assert.Throws<TlsProtocolException>(() => receiver.Decrypt(new byte[length]));
        Assert.Equal(TlsAlertDescription.RecordOverflow, exception.Alert);
    }

    [Fact]
    public void TamperedCiphertextNeverReleasesPlaintext()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var sender = new Tls13RecordCipher(suite, new byte[16], new byte[12]);
        using var receiver = new Tls13RecordCipher(suite, new byte[16], new byte[12]);
        var encrypted = sender.Encrypt(TlsContentType.Handshake, [1, 2, 3]);
        encrypted[0] ^= 1;

        var exception = Assert.Throws<TlsProtocolException>(() => receiver.Decrypt(encrypted));
        Assert.Equal(TlsAlertDescription.BadRecordMac, exception.Alert);
    }

    [Fact]
    public void WrongSequenceNumberFailsAuthentication()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var sender = new Tls13RecordCipher(suite, new byte[16], new byte[12], initialSequenceNumber: 1);
        using var receiver = new Tls13RecordCipher(suite, new byte[16], new byte[12], initialSequenceNumber: 0);
        var encrypted = sender.Encrypt(TlsContentType.Handshake, [1]);

        var exception = Assert.Throws<TlsProtocolException>(() => receiver.Decrypt(encrypted));
        Assert.Equal(TlsAlertDescription.BadRecordMac, exception.Alert);
    }

    [Fact]
    public void MaximumPaddingAndContentLimitsAreEnforced()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var cipher = new Tls13RecordCipher(suite, new byte[16], new byte[12]);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            cipher.Encrypt(TlsContentType.ApplicationData, new byte[TlsConstants.MaxPlaintextLength + 1]));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            cipher.Encrypt(TlsContentType.ApplicationData, [], TlsConstants.MaxCiphertextLength));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            cipher.Encrypt(
                TlsContentType.ApplicationData,
                new byte[TlsConstants.MaxPlaintextLength],
                paddingLength: 1));
    }

    [Fact]
    public void DecryptionReportsCompleteInnerPlaintextLengthIncludingTypeAndPadding()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var sender = new Tls13RecordCipher(suite, new byte[16], new byte[12]);
        using var receiver = new Tls13RecordCipher(suite, new byte[16], new byte[12]);

        var decrypted = receiver.Decrypt(sender.Encrypt(
            TlsContentType.ApplicationData,
            new byte[17],
            paddingLength: 9));

        Assert.Equal(27, decrypted.EncodedLength);
    }

    [Fact]
    public void KeyUsageLimitFailsClosed()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var cipher = new Tls13RecordCipher(
            suite,
            new byte[16],
            new byte[12],
            maximumRecords: 1);
        Assert.Equal(1UL, cipher.RecordsRemaining);
        _ = cipher.Encrypt(TlsContentType.ApplicationData, [1]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            cipher.Encrypt(TlsContentType.ApplicationData, [2]));
        Assert.Equal(TlsAlertDescription.GeneralError, exception.Alert);
    }

    [Fact]
    public void SequenceNumberCannotWrap()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var cipher = new Tls13RecordCipher(
            suite,
            new byte[16],
            new byte[12],
            initialSequenceNumber: ulong.MaxValue,
            maximumRecords: 2);
        _ = cipher.Encrypt(TlsContentType.ApplicationData, [1]);

        var exception = Assert.Throws<TlsProtocolException>(() =>
            cipher.Encrypt(TlsContentType.ApplicationData, [2]));
        Assert.Equal(TlsAlertDescription.GeneralError, exception.Alert);
    }

    [Fact]
    public void AllZeroInnerPlaintextIsRejectedAfterValidAuthentication()
    {
        var suite = CipherSuiteInfo.Get(TlsCipherSuite.TlsAes128GcmSha256);
        using var receiver = new Tls13RecordCipher(suite, new byte[16], new byte[12]);
        var encrypted = new byte[17];
        using (var aes = new AesGcm(new byte[16], 16))
        {
            aes.Encrypt(
                new byte[12],
                new byte[] { 0 },
                encrypted.AsSpan(0, 1),
                encrypted.AsSpan(1, 16),
                new byte[] { 23, 3, 3, 0, 17 });
        }

        var exception = Assert.Throws<TlsProtocolException>(() => receiver.Decrypt(encrypted));
        Assert.Equal(TlsAlertDescription.UnexpectedMessage, exception.Alert);
    }
}

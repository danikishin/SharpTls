using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.Sessions;

public sealed class Tls13ServerSessionTicketProtectorTests
{
    [Fact]
    public void StateDecoderMapsHostileSuiteAndIssueTimeToDecodeError()
    {
        using var source = new Tls13ServerSessionTicketState(
            1_700_000_000_000,
            3_600,
            0x10203040,
            TlsCipherSuite.TlsAes128GcmSha256,
            "fuzz.invalid",
            "h2",
            new byte[32]);
        var unknownSuite = source.Encode();
        unknownSuite[21] = 0x33;
        unknownSuite[22] = 0x01;
        var suiteError = Assert.Throws<TlsProtocolException>(() =>
            Tls13ServerSessionTicketState.Decode(unknownSuite));
        Assert.Equal(TlsAlertDescription.DecodeError, suiteError.Alert);

        var issueTimeOverflow = source.Encode();
        issueTimeOverflow.AsSpan(5, 8).Fill(0xFF);
        var timeError = Assert.Throws<TlsProtocolException>(() =>
            Tls13ServerSessionTicketState.Decode(issueTimeOverflow));
        Assert.Equal(TlsAlertDescription.DecodeError, timeError.Alert);
    }

    [Fact]
    public void ProtectRoundTripsAndRejectsEveryAuthenticatedMutation()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var psk = RandomNumberGenerator.GetBytes(32);
        try
        {
            using var protector = new Tls13ServerSessionTicketProtector("k1", key);
            using var source = new Tls13ServerSessionTicketState(
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                3600,
                0x12345678,
                TlsCipherSuite.TlsAes128GcmSha256,
                "example.com",
                "http/1.1",
                psk);
            var ticket = protector.Protect(source);

            Assert.True(protector.TryUnprotect(ticket, out var decoded));
            using (decoded)
            {
                Assert.Equal(source.IssuedAtUnixMilliseconds, decoded!.IssuedAtUnixMilliseconds);
                Assert.Equal(source.AgeAdd, decoded.AgeAdd);
                Assert.Equal(source.CipherSuite, decoded.CipherSuite);
                Assert.Equal(source.ServerName, decoded.ServerName);
                Assert.Equal(source.Alpn, decoded.Alpn);
                Assert.Equal(psk, decoded.Psk);
            }

            for (var index = 0; index < ticket.Length; index++)
            {
                var tampered = (byte[])ticket.Clone();
                tampered[index] ^= 0x01;
                Assert.False(protector.TryUnprotect(tampered, out var rejected));
                Assert.Null(rejected);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(psk);
        }
    }

    [Fact]
    public void RotationKeyDecryptsOldTicketsAndRemovalRejectsThem()
    {
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);
        var psk = RandomNumberGenerator.GetBytes(48);
        try
        {
            byte[] ticket;
            using (var oldProtector = new Tls13ServerSessionTicketProtector("old", oldKey))
            using (var state = new Tls13ServerSessionTicketState(
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                60,
                7,
                TlsCipherSuite.TlsAes256GcmSha384,
                null,
                null,
                psk))
            {
                ticket = oldProtector.Protect(state);
            }

            using var current = new Tls13ServerSessionTicketProtector("new", newKey);
            current.AddDecryptionKey("old", oldKey);
            Assert.True(current.TryUnprotect(ticket, out var decoded));
            decoded!.Dispose();
            Assert.True(current.RemoveDecryptionKey("old"));
            Assert.False(current.TryUnprotect(ticket, out decoded));
            Assert.Null(decoded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldKey);
            CryptographicOperations.ZeroMemory(newKey);
            CryptographicOperations.ZeroMemory(psk);
        }
    }
}

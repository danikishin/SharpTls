using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Tests.Sessions;

public sealed class Tls12ServerSessionTicketProtectorTests
{
    [Fact]
    public void StateDecoderMapsHostileSuiteGroupAndIssueTimeToDecodeError()
    {
        using var source = new Tls12ServerTicketState(
            1_700_000_000_000,
            3_600,
            TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
            "fuzz.invalid",
            "http/1.1",
            NamedGroup.X25519,
            new byte[TlsConstants.Tls12MasterSecretLength]);

        var unknownSuite = source.Encode();
        unknownSuite[17] = 0x33;
        unknownSuite[18] = 0x01;
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerTicketState.Decode(unknownSuite)).Alert);

        var unknownGroup = source.Encode();
        unknownGroup[19] = 0x33;
        unknownGroup[20] = 0x01;
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerTicketState.Decode(unknownGroup)).Alert);

        var issueTimeOverflow = source.Encode();
        issueTimeOverflow.AsSpan(5, 8).Fill(0xFF);
        Assert.Equal(
            TlsAlertDescription.DecodeError,
            Assert.Throws<TlsProtocolException>(() =>
                Tls12ServerTicketState.Decode(issueTimeOverflow)).Alert);
    }

    [Fact]
    public void ProtectRoundTripsAndRejectsEveryAuthenticatedMutation()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var masterSecret = RandomNumberGenerator.GetBytes(TlsConstants.Tls12MasterSecretLength);
        try
        {
            using var protector = new Tls12ServerSessionTicketProtector("current", key);
            using var source = new Tls12ServerTicketState(
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                3600,
                TlsCipherSuite.TlsEcdheRsaWithAes128GcmSha256,
                "example.com",
                "http/1.1",
                NamedGroup.Secp256r1,
                masterSecret);
            var ticket = protector.Protect(source);
            Assert.True(protector.TryUnprotect(ticket, out var decoded));
            using (decoded)
            {
                Assert.Equal(source.CipherSuite, decoded!.CipherSuite);
                Assert.Equal(source.ServerName, decoded.ServerName);
                Assert.Equal(source.Alpn, decoded.Alpn);
                Assert.Equal(source.Group, decoded.Group);
                var copy = decoded.CopyMasterSecret();
                Assert.Equal(masterSecret, copy);
                CryptographicOperations.ZeroMemory(copy);
            }

            for (var index = 0; index < ticket.Length; index++)
            {
                var tampered = (byte[])ticket.Clone();
                tampered[index] ^= 1;
                Assert.False(protector.TryUnprotect(tampered, out var rejected));
                Assert.Null(rejected);
            }
            CryptographicOperations.ZeroMemory(ticket);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(masterSecret);
        }
    }

    [Fact]
    public void RotationAcceptsOldKeyUntilItIsRemoved()
    {
        var oldKey = RandomNumberGenerator.GetBytes(32);
        var newKey = RandomNumberGenerator.GetBytes(32);
        var secret = RandomNumberGenerator.GetBytes(TlsConstants.Tls12MasterSecretLength);
        try
        {
            byte[] ticket;
            using (var old = new Tls12ServerSessionTicketProtector("old", oldKey))
            using (var state = new Tls12ServerTicketState(
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                60,
                TlsCipherSuite.TlsEcdheRsaWithAes256GcmSha384,
                null,
                null,
                NamedGroup.Secp384r1,
                secret))
            {
                ticket = old.Protect(state);
            }
            using var current = new Tls12ServerSessionTicketProtector("new", newKey);
            current.AddDecryptionKey("old", oldKey);
            Assert.True(current.TryUnprotect(ticket, out var decoded));
            decoded!.Dispose();
            Assert.True(current.RemoveDecryptionKey("old"));
            Assert.False(current.TryUnprotect(ticket, out decoded));
            Assert.Null(decoded);
            CryptographicOperations.ZeroMemory(ticket);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldKey);
            CryptographicOperations.ZeroMemory(newKey);
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}

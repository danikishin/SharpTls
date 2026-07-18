using SharpTls.Quic;
using SharpTls.Protocol;

namespace SharpTls.Tests.Quic;

public sealed class TlsQuicPrimitiveTests
{
    [Theory]
    [InlineData(0UL, "00")]
    [InlineData(63UL, "3F")]
    [InlineData(64UL, "4040")]
    [InlineData(16383UL, "7FFF")]
    [InlineData(16384UL, "80004000")]
    [InlineData(1073741823UL, "BFFFFFFF")]
    [InlineData(1073741824UL, "C000000040000000")]
    [InlineData(4611686018427387903UL, "FFFFFFFFFFFFFFFF")]
    public void VariableLengthIntegerBoundariesAreCanonical(ulong value, string expectedHex)
    {
        var encoded = QuicVariableLengthInteger.Encode(value);
        var offset = 0;

        Assert.Equal(expectedHex, Convert.ToHexString(encoded));
        Assert.Equal(value, QuicVariableLengthInteger.Read(encoded, ref offset));
        Assert.Equal(encoded.Length, offset);
    }

    [Fact]
    public void OrderedTransportParametersRoundTripAndPreserveUnknownIds()
    {
        var parameters = new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxUdpPayloadSize,
                65_527),
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.InitialMaxData,
                1_000_000),
            new TlsQuicTransportParameter(0x173E, [1, 2, 3]),
            TlsQuicTransportParameter.Empty(
                TlsQuicTransportParameterId.DisableActiveMigration),
        ]);

        var encoded = parameters.Encode();
        var parsed = TlsQuicTransportParameters.Parse(encoded);
        parsed.ValidatePeer(TlsQuicEndpointRole.Client);

        Assert.Equal(encoded, parsed.Encode());
        Assert.Equal([1, 2, 3], parsed.Get(0x173E)!.Value);
        Assert.Equal(
            1_000_000UL,
            parsed.Get((ulong)TlsQuicTransportParameterId.InitialMaxData)!
                .GetVariableInteger());
        var defensive = parsed.Get(0x173E)!.Value;
        defensive[0] = 9;
        Assert.Equal([1, 2, 3], parsed.Get(0x173E)!.Value);
    }

    [Fact]
    public void DuplicateTruncatedAndInvalidPeerParametersFailClosed()
    {
        Assert.Equal(
            TlsQuicTransportError.TransportParameterError,
            Assert.Throws<TlsQuicTransportException>(() =>
                TlsQuicTransportParameters.Parse([0x01, 0x01, 0x00, 0x01, 0x00]))
                .Error);
        Assert.Equal(
            TlsQuicTransportError.TransportParameterError,
            Assert.Throws<TlsQuicTransportException>(() =>
                TlsQuicTransportParameters.Parse([0x40])).Error);

        var clientWithServerOnlyParameter = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.StatelessResetToken,
                new byte[16]),
        ]);
        Assert.Equal(
            TlsQuicTransportError.TransportParameterError,
            Assert.Throws<TlsQuicTransportException>(() =>
                clientWithServerOnlyParameter.ValidatePeer(TlsQuicEndpointRole.Client)).Error);

        var invalidUdp = new TlsQuicTransportParameters(
        [
            TlsQuicTransportParameter.VariableInteger(
                TlsQuicTransportParameterId.MaxUdpPayloadSize,
                1199),
        ]);
        Assert.Throws<TlsQuicTransportException>(() =>
            invalidUdp.ValidatePeer(TlsQuicEndpointRole.Server));

        var invalidVersionInfo = new TlsQuicTransportParameters(
        [
            new TlsQuicTransportParameter(
                (ulong)TlsQuicTransportParameterId.VersionInformation,
                [0, 0, 0, 2, 0, 0, 0, 1]),
        ]);
        Assert.Throws<TlsQuicTransportException>(() =>
            invalidVersionInfo.ValidatePeer(TlsQuicEndpointRole.Server));
    }

    [Fact]
    public void CryptoStreamReassemblesGapsRetransmissionsAndRejectsConflicts()
    {
        var stream = new TlsQuicCryptoStreamReassembler(4096);

        Assert.Empty(stream.Add(5, "world"u8));
        Assert.Equal("helloworld"u8.ToArray(), stream.Add(0, "hello"u8));
        Assert.Empty(stream.Add(0, "helloworld"u8));
        Assert.Equal(10, stream.DeliveredLength);
        Assert.Equal(
            TlsQuicTransportError.ProtocolViolation,
            Assert.Throws<TlsQuicTransportException>(() =>
                stream.Add(3, "X"u8)).Error);

        stream.Discard();
        Assert.Empty(stream.Add(0, "hello"u8));
        Assert.Equal(
            TlsQuicTransportError.ProtocolViolation,
            Assert.Throws<TlsQuicTransportException>(() =>
                stream.Add(10, "!"u8)).Error);
    }

    [Fact]
    public void CryptoStreamEnforcesBufferLimitAndCannotDiscardAGap()
    {
        var stream = new TlsQuicCryptoStreamReassembler(1024);
        Assert.Empty(stream.Add(100, [1]));
        Assert.Equal(
            TlsQuicTransportError.ProtocolViolation,
            Assert.Throws<TlsQuicTransportException>(stream.Discard).Error);
        Assert.Equal(
            TlsQuicTransportError.CryptoBufferExceeded,
            Assert.Throws<TlsQuicTransportException>(() =>
                stream.Add(1024, [1])).Error);
    }

    [Fact]
    public void Rfc9001InitialSecretsAndKeysMatchAppendixA()
    {
        var connectionId = Convert.FromHexString("8394C8F03E515708");
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version1,
            connectionId);
        using var clientKeys = secrets.DeriveClientPacketProtectionKeys(
            TlsQuicVersion.Version1);
        using var serverKeys = secrets.DeriveServerPacketProtectionKeys(
            TlsQuicVersion.Version1);

        Assert.Equal(
            "C00CF151CA5BE075ED0EBFB5C80323C42D6B7DB67881289AF4008F1F6C357AEA",
            Convert.ToHexString(secrets.CopyClientSecret()));
        Assert.Equal(
            "3C199828FD139EFD216C155AD844CC81FB82FA8D7446FA7D78BE803ACDDA951B",
            Convert.ToHexString(secrets.CopyServerSecret()));
        AssertKeys(
            clientKeys,
            "1F369613DD76D5467730EFCBE3B1A22D",
            "FA044B2F42A3FD3B46FB255C",
            "9F50449E04A0E810283A1E9933ADEDD2");
        AssertKeys(
            serverKeys,
            "CF3A5331653C364C88F0F379B6067E37",
            "0AC1493CA1905853B0BBA03E",
            "C206B8D9B9F0F37644430B490EEAA314");
    }

    [Fact]
    public void Rfc9369InitialSecretsAndKeysMatchAppendixA()
    {
        var connectionId = Convert.FromHexString("8394C8F03E515708");
        using var secrets = TlsQuicInitialSecrets.Derive(
            TlsQuicVersion.Version2,
            connectionId);
        using var clientKeys = secrets.DeriveClientPacketProtectionKeys(
            TlsQuicVersion.Version2);
        using var serverKeys = secrets.DeriveServerPacketProtectionKeys(
            TlsQuicVersion.Version2);

        Assert.Equal(
            "14EC9D6EB9FD7AF83BF5A668BC17A7E283766AADE7ECD0891F70F9FF7F4BF47B",
            Convert.ToHexString(secrets.CopyClientSecret()));
        Assert.Equal(
            "0263DB1782731BF4588E7E4D93B7463907CB8CD8200B5DA55A8BD488EAFC37C1",
            Convert.ToHexString(secrets.CopyServerSecret()));
        AssertKeys(
            clientKeys,
            "8B1A0BC121284290A29E0971B5CD045D",
            "91F73E2351D8FA91660E909F",
            "45B95E15235D6F45A6B19CB CB0294BA9".Replace(" ", string.Empty));
        AssertKeys(
            serverKeys,
            "82DB637861D55E1D011F19EA71D5D2A7",
            "DD13C276499C0249D3310652",
            "EDF6D05C83121201B436E16877593C3A");
    }

    [Fact]
    public void TlsTrafficSecretUsesVersionSpecificKeySeparationLabels()
    {
        using var secret = new TlsQuicTrafficSecret(
            TlsQuicEncryptionLevel.Handshake,
            TlsQuicSecretDirection.Write,
            TlsCipherSuite.TlsAes128GcmSha256,
            Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
        using var v1 = secret.DerivePacketProtectionKeys(TlsQuicVersion.Version1);
        using var v2 = secret.DerivePacketProtectionKeys(TlsQuicVersion.Version2);

        Assert.False(v1.CopyKey().AsSpan().SequenceEqual(v2.CopyKey()));
        Assert.False(v1.CopyIv().AsSpan().SequenceEqual(v2.CopyIv()));
        Assert.False(v1.CopyHeaderProtectionKey().AsSpan().SequenceEqual(
            v2.CopyHeaderProtectionKey()));
        Assert.Equal(TlsQuicEncryptionLevel.Handshake, secret.Level);
        Assert.Equal(TlsQuicSecretDirection.Write, secret.Direction);

        secret.Dispose();
        Assert.Throws<ObjectDisposedException>(secret.CopySecret);
    }

    private static void AssertKeys(
        TlsQuicPacketProtectionKeys keys,
        string key,
        string iv,
        string headerProtectionKey)
    {
        Assert.Equal(key, Convert.ToHexString(keys.CopyKey()));
        Assert.Equal(iv, Convert.ToHexString(keys.CopyIv()));
        Assert.Equal(
            headerProtectionKey,
            Convert.ToHexString(keys.CopyHeaderProtectionKey()));
    }
}

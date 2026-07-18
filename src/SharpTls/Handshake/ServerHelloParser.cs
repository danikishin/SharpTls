using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Handshake;

internal sealed record ServerHelloResult(
    bool IsHelloRetryRequest,
    TlsCipherSuite CipherSuite,
    NamedGroup SelectedGroup,
    byte[]? PeerKeyExchange,
    byte[]? Cookie,
    byte[]? EchConfirmation,
    byte[] Random,
    ushort? SelectedPskIdentity);

internal static class ServerHelloParser
{
    private static ReadOnlySpan<byte> HelloRetryRequestRandom =>
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];

    internal static ServerHelloResult Parse(
        ReadOnlySpan<byte> body,
        ClientHelloBuildResult offer,
        TlsCipherSuite? helloRetryRequestSuite = null,
        NamedGroup? helloRetryRequestGroup = null)
    {
        var reader = new TlsBinaryReader(body);
        if (reader.ReadUInt16() != TlsConstants.LegacyRecordVersion)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.ProtocolVersion,
                "ServerHello legacy_version is not 0x0303.");
        }

        var random = reader.ReadBytes(TlsConstants.RandomLength).ToArray();
        var isRetry = random.AsSpan().SequenceEqual(HelloRetryRequestRandom);
        var sessionId = reader.ReadVector8(TlsConstants.MaxSessionIdLength);
        if (!sessionId.SequenceEqual(offer.SessionId))
        {
            throw TlsProtocolException.Illegal("ServerHello did not echo the legacy session ID.");
        }

        var suiteValue = reader.ReadUInt16();
        if (!Enum.IsDefined(typeof(TlsCipherSuite), suiteValue) ||
            !offer.Configuration.CipherSuites.Any(suite => (ushort)suite == suiteValue))
        {
            throw TlsProtocolException.Illegal("ServerHello selected an unoffered cipher suite.");
        }
        var suite = (TlsCipherSuite)suiteValue;
        if (helloRetryRequestSuite.HasValue && suite != helloRetryRequestSuite.Value)
        {
            throw TlsProtocolException.Illegal("ServerHello changed the cipher suite selected by HRR.");
        }

        if (reader.ReadUInt8() != 0)
        {
            throw TlsProtocolException.Illegal("ServerHello selected legacy compression.");
        }

        var extensions = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ServerHello");

        var seen = new HashSet<ushort>();
        NamedGroup? selectedGroup = null;
        byte[]? peerKey = null;
        byte[]? cookie = null;
        byte[]? echConfirmation = null;
        ushort? selectedPskIdentity = null;
        var hasSupportedVersion = false;

        while (!extensions.End)
        {
            var type = extensions.ReadUInt16();
            var data = extensions.ReadVector16();
            if (!seen.Add(type))
            {
                throw TlsProtocolException.Illegal($"ServerHello contains duplicate extension 0x{type:X4}.");
            }

            switch ((TlsExtensionType)type)
            {
                case TlsExtensionType.SupportedVersions:
                    var versionReader = new TlsBinaryReader(data);
                    if (versionReader.ReadUInt16() != TlsConstants.Tls13Version)
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.ProtocolVersion,
                            "ServerHello did not negotiate TLS 1.3.");
                    }
                    versionReader.EnsureEnd("supported_versions");
                    hasSupportedVersion = true;
                    break;

                case TlsExtensionType.KeyShare:
                    if (isRetry)
                    {
                        var retryShare = new TlsBinaryReader(data);
                        selectedGroup = ParseGroup(retryShare.ReadUInt16());
                        retryShare.EnsureEnd("HRR key_share");
                    }
                    else
                    {
                        var serverShare = new TlsBinaryReader(data);
                        selectedGroup = ParseGroup(serverShare.ReadUInt16());
                        peerKey = serverShare.ReadVector16().ToArray();
                        if (peerKey.Length == 0)
                        {
                            throw TlsProtocolException.Illegal("Server key_share is empty.");
                        }
                        serverShare.EnsureEnd("ServerHello key_share");
                    }
                    break;

                case TlsExtensionType.Cookie when isRetry:
                    var cookieReader = new TlsBinaryReader(data);
                    cookie = cookieReader.ReadVector16().ToArray();
                    if (cookie.Length == 0)
                    {
                        throw TlsProtocolException.Illegal("HRR cookie is empty.");
                    }
                    cookieReader.EnsureEnd("HRR cookie");
                    break;

                case TlsExtensionType.EncryptedClientHello when isRetry:
                    if (!offer.Configuration.ExtensionLayout.Any(extension =>
                        extension.RawExtensionType ==
                        (ushort)TlsExtensionType.EncryptedClientHello))
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.UnsupportedExtension,
                            "HelloRetryRequest sent encrypted_client_hello without an offer.");
                    }
                    if (data.Length != 8)
                    {
                        throw TlsProtocolException.Decode(
                            "HelloRetryRequest ECH confirmation must contain exactly 8 bytes.");
                    }
                    echConfirmation = data.ToArray();
                    break;

                case TlsExtensionType.PreSharedKey when !isRetry:
                    if (offer.OfferedPskCount == 0)
                    {
                        throw new TlsProtocolException(
                            TlsAlertDescription.UnsupportedExtension,
                            "ServerHello selected a PSK that the client did not offer.");
                    }
                    var selectedPsk = new TlsBinaryReader(data);
                    selectedPskIdentity = selectedPsk.ReadUInt16();
                    selectedPsk.EnsureEnd("ServerHello pre_shared_key");
                    if (selectedPskIdentity.Value >= offer.OfferedPskCount)
                    {
                        throw TlsProtocolException.Illegal(
                            "ServerHello selected an out-of-range PSK identity.");
                    }
                    break;

                default:
                    throw new TlsProtocolException(
                        TlsAlertDescription.UnsupportedExtension,
                        $"ServerHello extension 0x{type:X4} is unsupported or illegal in context.");
            }
        }

        if (!hasSupportedVersion)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "ServerHello omitted supported_versions.");
        }
        if (suite is not (TlsCipherSuite.TlsAes128GcmSha256 or
            TlsCipherSuite.TlsAes256GcmSha384 or
            TlsCipherSuite.TlsChaCha20Poly1305Sha256))
        {
            throw TlsProtocolException.Illegal(
                "TLS 1.3 ServerHello selected a non-TLS-1.3 cipher suite.");
        }
        if (!selectedGroup.HasValue)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.MissingExtension,
                "ServerHello omitted key_share.");
        }

        if (isRetry)
        {
            if (helloRetryRequestSuite.HasValue)
            {
                throw TlsProtocolException.Unexpected("A second HelloRetryRequest is forbidden.");
            }
            if (!offer.Configuration.SupportedGroups.Contains(selectedGroup.Value) ||
                offer.Configuration.KeyShareGroups.Contains(selectedGroup.Value))
            {
                throw TlsProtocolException.Illegal("HRR selected an unoffered or already-shared group.");
            }
        }
        else
        {
            if (!offer.Configuration.KeyShareGroups.Contains(selectedGroup.Value))
            {
                throw TlsProtocolException.Illegal("ServerHello selected an unoffered key share.");
            }
            if (helloRetryRequestGroup.HasValue && selectedGroup.Value != helloRetryRequestGroup.Value)
            {
                throw TlsProtocolException.Illegal("ServerHello did not use the HRR-selected group.");
            }
        }

        return new ServerHelloResult(
            isRetry,
            suite,
            selectedGroup.Value,
            peerKey,
            cookie,
            echConfirmation,
            random,
            selectedPskIdentity);
    }

    private static NamedGroup ParseGroup(ushort value) => value switch
    {
        (ushort)NamedGroup.Secp256r1 => NamedGroup.Secp256r1,
        (ushort)NamedGroup.Secp384r1 => NamedGroup.Secp384r1,
        (ushort)NamedGroup.Secp521r1 => NamedGroup.Secp521r1,
        (ushort)NamedGroup.X25519 => NamedGroup.X25519,
        (ushort)NamedGroup.X25519MlKem768 => NamedGroup.X25519MlKem768,
        (ushort)NamedGroup.X25519Kyber768Draft00 => NamedGroup.X25519Kyber768Draft00,
        _ => throw TlsProtocolException.Illegal($"Server selected unsupported group 0x{value:X4}."),
    };
}

using SharpTls.Protocol;
using SharpTls.Quic;

namespace SharpTls;

/// <summary>Builds an immutable, byte-order-preserving TLS 1.3 ClientHello profile.</summary>
public sealed class ClientHelloBuilder
{
    private const int MaxAggregateRawExtensionData = 48 * 1024;

    private readonly List<ClientHelloExtensionKind> _extensionOrder =
    [
        ClientHelloExtensionKind.ServerName,
        ClientHelloExtensionKind.SupportedVersions,
        ClientHelloExtensionKind.SupportedGroups,
        ClientHelloExtensionKind.SignatureAlgorithms,
        ClientHelloExtensionKind.KeyShare,
    ];

    private TlsCipherSuite[] _cipherSuites =
    [
        TlsCipherSuite.TlsAes128GcmSha256,
        TlsCipherSuite.TlsAes256GcmSha384,
        TlsCipherSuite.TlsChaCha20Poly1305Sha256,
    ];

    private TlsProtocolVersion[] _supportedVersions = [TlsProtocolVersion.Tls13];
    private bool _includeSupportedVersionsExtension = true;
    private bool _includeKeyShareExtension = true;

    private NamedGroup[] _supportedGroups = [NamedGroup.Secp256r1, NamedGroup.Secp384r1];
    private NamedGroup[]? _keyShareGroups;
    private bool _keySharesExplicit;
    private SignatureScheme[] _signatureAlgorithms =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.EcdsaSecp521r1Sha512,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPssRsaeSha512,
        SignatureScheme.RsaPssPssSha256,
        SignatureScheme.RsaPssPssSha384,
        SignatureScheme.RsaPssPssSha512,
    ];
    private bool _allowDuplicateSignatureAlgorithms;
    private SignatureScheme[]? _certificateSignatureAlgorithms;
    private int? _recordSizeLimit;
    private SignatureScheme[]? _delegatedCredentialSignatureAlgorithms;
    private bool _allowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity;
    private byte[]? _quicTransportParameters;

    private string[] _alpn = [];
    private TlsApplicationSettingsCodePoint? _applicationSettingsCodePoint;
    private string[] _applicationSettingsProtocols = [];
    private byte[]? _sessionId;
    private int? _paddingLength;
    private bool _useBoringPadding;
    private bool _shuffleExtensions;
    private TlsHpkeSymmetricCipherSuite[]? _greaseEchCipherSuites;
    private int[]? _greaseEchPayloadLengths;
    private ClientHelloGreasePolicy? _greasePolicy;
    private byte[]? _fixedGreaseKeyShareBody;
    private byte[]? _secondaryGreaseExtensionBody;
    private bool _includeSni = true;
    private ClientHelloExtensionSpec[]? _extensionLayout;

    /// <summary>Ensures that TLS 1.3 is the only offered protocol version.</summary>
    public ClientHelloBuilder WithTls13()
    {
        _supportedVersions = [TlsProtocolVersion.Tls13];
        _includeSupportedVersionsExtension = true;
        _includeKeyShareExtension = true;
        SetExtensionEnabled(ClientHelloExtensionKind.SupportedVersions, enabled: true);
        SetExtensionEnabled(ClientHelloExtensionKind.KeyShare, enabled: true);
        return this;
    }

    /// <summary>
    /// Sets supported_versions in exact wire order. TLS 1.3 and secure TLS 1.2 fallback are executable;
    /// older values remain available only for faithful ClientHello wire profiles.
    /// </summary>
    public ClientHelloBuilder WithSupportedVersions(params TlsProtocolVersion[] versions)
    {
        ArgumentNullException.ThrowIfNull(versions);
        _supportedVersions = (TlsProtocolVersion[])versions.Clone();
        _includeSupportedVersionsExtension = true;
        SetExtensionEnabled(ClientHelloExtensionKind.SupportedVersions, enabled: true);
        if (versions.Contains(TlsProtocolVersion.Tls13))
        {
            _includeKeyShareExtension = true;
            SetExtensionEnabled(ClientHelloExtensionKind.KeyShare, enabled: true);
        }
        return this;
    }

    /// <summary>
    /// Encodes a legacy TLS 1.2 ClientHello without supported_versions or key_share.
    /// A connectable TLS 1.2 profile must also offer EMS, secure renegotiation, and an implemented AEAD suite.
    /// </summary>
    public ClientHelloBuilder WithLegacyTls12ClientHello()
    {
        _supportedVersions = [TlsProtocolVersion.Tls12];
        _includeSupportedVersionsExtension = false;
        _includeKeyShareExtension = false;
        _keyShareGroups = [];
        _keySharesExplicit = true;
        SetExtensionEnabled(ClientHelloExtensionKind.SupportedVersions, enabled: false);
        SetExtensionEnabled(ClientHelloExtensionKind.KeyShare, enabled: false);
        return this;
    }

    /// <summary>Sets the supported TLS 1.3 cipher suites in exact wire order.</summary>
    public ClientHelloBuilder WithCipherSuites(params TlsCipherSuite[] cipherSuites)
    {
        ArgumentNullException.ThrowIfNull(cipherSuites);
        _cipherSuites = (TlsCipherSuite[])cipherSuites.Clone();
        return this;
    }

    /// <summary>Enables a consistent RFC 8701 GREASE value in relevant vectors and an empty extension.</summary>
    public ClientHelloBuilder WithGrease(bool enabled = true)
    {
        _greasePolicy = enabled ? ClientHelloGreasePolicy.Consistent : null;
        SetExtensionEnabled(ClientHelloExtensionKind.Grease, enabled, insertAtStart: true);
        if (!enabled)
        {
            _fixedGreaseKeyShareBody = null;
            _secondaryGreaseExtensionBody = null;
            SetExtensionEnabled(ClientHelloExtensionKind.SecondaryGrease, enabled: false);
        }
        return this;
    }

    /// <summary>Enables semantic RFC 8701 GREASE with a caller-defined value-sharing policy.</summary>
    public ClientHelloBuilder WithGrease(ClientHelloGreasePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (_secondaryGreaseExtensionBody is not null &&
            policy.GetValueClass(ClientHelloGreaseSlot.Extension) ==
                policy.GetValueClass(ClientHelloGreaseSlot.SecondaryExtension))
        {
            throw new ArgumentException(
                "Primary and secondary GREASE extension types must use distinct value classes.",
                nameof(policy));
        }
        _greasePolicy = policy.Snapshot();
        SetExtensionEnabled(ClientHelloExtensionKind.Grease, enabled: true, insertAtStart: true);
        return this;
    }

    /// <summary>
    /// Adds a second independently typed GREASE extension with an exact body. Passing null removes it.
    /// </summary>
    public ClientHelloBuilder WithSecondaryGreaseExtension(byte[]? body)
    {
        if (body is { Length: > ushort.MaxValue })
        {
            throw new ArgumentOutOfRangeException(nameof(body));
        }
        if (body is not null && _greasePolicy is null)
        {
            throw new InvalidOperationException("Enable GREASE before adding a secondary GREASE extension.");
        }
        if (body is not null &&
            _greasePolicy!.GetValueClass(ClientHelloGreaseSlot.Extension) ==
                _greasePolicy.GetValueClass(ClientHelloGreaseSlot.SecondaryExtension))
        {
            throw new InvalidOperationException(
                "The GREASE policy must assign distinct classes to both extension slots.");
        }

        _secondaryGreaseExtensionBody = body is null ? null : (byte[])body.Clone();
        SetExtensionEnabled(ClientHelloExtensionKind.SecondaryGrease, body is not null);
        return this;
    }

    /// <summary>
    /// Sets an exact non-empty GREASE key_share body. Null restores one fresh random byte per connection.
    /// </summary>
    public ClientHelloBuilder WithGreaseKeyShareBody(byte[]? body)
    {
        if (body is { Length: 0 or > ushort.MaxValue })
        {
            throw new ArgumentOutOfRangeException(nameof(body));
        }

        _fixedGreaseKeyShareBody = body is null ? null : (byte[])body.Clone();
        return this;
    }

    /// <summary>Sets supported ECDHE groups in preference order.</summary>
    public ClientHelloBuilder WithSupportedGroups(params NamedGroup[] groups)
    {
        ArgumentNullException.ThrowIfNull(groups);
        _supportedGroups = (NamedGroup[])groups.Clone();
        if (!_keySharesExplicit)
        {
            _keyShareGroups = (NamedGroup[])groups.Clone();
        }

        return this;
    }

    /// <summary>Sets the non-GREASE key-share groups. An empty list intentionally requests HRR.</summary>
    public ClientHelloBuilder WithKeyShares(params NamedGroup[] groups)
    {
        ArgumentNullException.ThrowIfNull(groups);
        _keyShareGroups = (NamedGroup[])groups.Clone();
        _keySharesExplicit = true;
        return this;
    }

    /// <summary>Sets TLS CertificateVerify signature schemes in preference order.</summary>
    public ClientHelloBuilder WithSignatureAlgorithms(params SignatureScheme[] algorithms)
    {
        ArgumentNullException.ThrowIfNull(algorithms);
        _signatureAlgorithms = (SignatureScheme[])algorithms.Clone();
        return this;
    }

    /// <summary>
    /// Sets signature schemes accepted on X.509 certificate chains. Null removes the
    /// extension and makes the CertificateVerify signature list apply to certificates.
    /// </summary>
    public ClientHelloBuilder WithCertificateSignatureAlgorithms(
        params SignatureScheme[]? algorithms)
    {
        _certificateSignatureAlgorithms = algorithms is null
            ? null
            : (SignatureScheme[])algorithms.Clone();
        SetExtensionEnabled(
            ClientHelloExtensionKind.SignatureAlgorithmsCert,
            algorithms is not null);
        return this;
    }

    /// <summary>
    /// Permits duplicate signature_algorithms entries for byte-faithful imported/browser profiles.
    /// Duplicates remain rejected by default.
    /// </summary>
    public ClientHelloBuilder AllowDuplicateSignatureAlgorithms(bool enabled = true)
    {
        _allowDuplicateSignatureAlgorithms = enabled;
        return this;
    }

    /// <summary>Sets ALPN protocol names in wire order, or removes ALPN when empty.</summary>
    public ClientHelloBuilder WithAlpn(params string[] protocols)
    {
        ArgumentNullException.ThrowIfNull(protocols);
        _alpn = (string[])protocols.Clone();
        SetExtensionEnabled(ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation, protocols.Length != 0);
        return this;
    }

    /// <summary>
    /// Enables the experimental ALPS/application_settings ClientHello extension using the
    /// selected uTLS-compatible code point. Protocols must be a non-empty subset of ALPN.
    /// Passing an empty list removes the extension.
    /// </summary>
    public ClientHelloBuilder WithApplicationSettings(
        TlsApplicationSettingsCodePoint codePoint,
        params string[] protocols)
    {
        ArgumentNullException.ThrowIfNull(protocols);
        if (!Enum.IsDefined(codePoint))
        {
            throw new ArgumentOutOfRangeException(nameof(codePoint));
        }

        _applicationSettingsCodePoint = protocols.Length == 0 ? null : codePoint;
        _applicationSettingsProtocols = (string[])protocols.Clone();
        SetExtensionEnabled(
            ClientHelloExtensionKind.ApplicationSettings,
            protocols.Length != 0);
        return this;
    }

    /// <summary>
    /// Enables TLS 1.3 ticket resumption using only forward-secret psk_dhe_ke.
    /// The pre_shared_key slot is emitted only when a usable cached ticket exists.
    /// </summary>
    public ClientHelloBuilder WithSessionResumption(bool enabled = true)
    {
        SetExtensionEnabled(ClientHelloExtensionKind.PskKeyExchangeModes, enabled);
        SetExtensionEnabled(ClientHelloExtensionKind.EarlyData, enabled);
        SetExtensionEnabled(ClientHelloExtensionKind.PreSharedKey, enabled);
        return this;
    }

    /// <summary>
    /// Advertises willingness to answer TLS 1.3 post-handshake CertificateRequest messages.
    /// A configured client certificate is used when compatible; otherwise an empty response is sent.
    /// </summary>
    public ClientHelloBuilder WithPostHandshakeAuthentication(bool enabled = true)
    {
        SetExtensionEnabled(ClientHelloExtensionKind.PostHandshakeAuthentication, enabled);
        return this;
    }

    /// <summary>
    /// Advertises the maximum protected-record plaintext this client accepts. TLS 1.3
    /// permits 64 through 16385 bytes; TLS 1.2 negotiation further caps it at 16384.
    /// Passing null removes the extension.
    /// </summary>
    public ClientHelloBuilder WithRecordSizeLimit(int? maximumProtectedPlaintextLength)
    {
        if (maximumProtectedPlaintextLength is < 64 or > TlsConstants.MaxPlaintextLength + 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumProtectedPlaintextLength));
        }

        _recordSizeLimit = maximumProtectedPlaintextLength;
        SetExtensionEnabled(
            ClientHelloExtensionKind.RecordSizeLimit,
            maximumProtectedPlaintextLength.HasValue);
        return this;
    }

    /// <summary>
    /// Advertises TLS 1.3 RFC 9345 delegated-credential CertificateVerify algorithms.
    /// Passing null removes the extension.
    /// </summary>
    public ClientHelloBuilder WithDelegatedCredentials(params SignatureScheme[]? algorithms)
    {
        _delegatedCredentialSignatureAlgorithms = algorithms is null
            ? null
            : (SignatureScheme[])algorithms.Clone();
        SetExtensionEnabled(
            ClientHelloExtensionKind.DelegatedCredential,
            algorithms is not null);
        return this;
    }

    /// <summary>
    /// Adds ordered RFC 9001 QUIC transport parameters. Passing null removes extension 57.
    /// Client-role constraints are validated before the immutable profile is created.
    /// </summary>
    public ClientHelloBuilder WithQuicTransportParameters(
        TlsQuicTransportParameters? transportParameters)
    {
        transportParameters?.ValidatePeer(TlsQuicEndpointRole.Client);
        _quicTransportParameters = transportParameters?.Encode();
        SetExtensionEnabled(
            ClientHelloExtensionKind.QuicTransportParameters,
            transportParameters is not null);
        return this;
    }

    /// <summary>
    /// Retains legacy delegated-credential schemes in imported historical wire profiles.
    /// Such schemes are never accepted from a server and are rejected by default.
    /// </summary>
    public ClientHelloBuilder AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity(
        bool enabled = true)
    {
        _allowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity = enabled;
        return this;
    }

    /// <summary>Enables or disables SNI. The name comes from the client options.</summary>
    public ClientHelloBuilder WithSni(bool enabled = true)
    {
        _includeSni = enabled;
        SetExtensionEnabled(ClientHelloExtensionKind.ServerName, enabled);
        return this;
    }

    /// <summary>Sets the exact legacy session ID. Null restores a fresh 32-byte compatibility ID.</summary>
    public ClientHelloBuilder WithSessionId(byte[]? sessionId)
    {
        _sessionId = sessionId is null ? null : (byte[])sessionId.Clone();
        return this;
    }

    /// <summary>Adds an exact number of zero padding bytes, or removes the padding extension when null.</summary>
    public ClientHelloBuilder WithPadding(int? paddingLength)
    {
        _paddingLength = paddingLength;
        _useBoringPadding = false;
        SetExtensionEnabled(ClientHelloExtensionKind.Padding, paddingLength.HasValue);
        return this;
    }

    /// <summary>
    /// Uses the BoringSSL 256–511 byte ClientHello padding rule employed by uTLS browser profiles.
    /// </summary>
    public ClientHelloBuilder WithBoringPadding()
    {
        _paddingLength = null;
        _useBoringPadding = true;
        SetExtensionEnabled(ClientHelloExtensionKind.Padding, enabled: true);
        return this;
    }

    /// <summary>
    /// Enables Chrome-style per-connection extension shuffling. Semantic GREASE,
    /// padding, and pre_shared_key slots retain their configured positions.
    /// </summary>
    public ClientHelloBuilder WithExtensionShuffling(bool enabled = true)
    {
        _shuffleExtensions = enabled;
        return this;
    }

    /// <summary>
    /// Enables a semantic GREASE encrypted_client_hello extension. Optional values are
    /// pre-encryption payload lengths; an empty list derives a plausible padded length.
    /// </summary>
    public ClientHelloBuilder WithGreaseEncryptedClientHello(params int[] payloadLengths)
    {
        ArgumentNullException.ThrowIfNull(payloadLengths);
        _greaseEchCipherSuites = TlsEchGreaseOptions.DefaultCipherSuites.ToArray();
        _greaseEchPayloadLengths = (int[])payloadLengths.Clone();
        SetExtensionEnabled(ClientHelloExtensionKind.EncryptedClientHello, enabled: true);
        return this;
    }

    /// <summary>
    /// Enables semantic GREASE encrypted_client_hello with an exact ordered HPKE-suite
    /// candidate set. This is primarily useful for reproducing browser fingerprints whose
    /// GREASE policy intentionally differs from the SharpTls default.
    /// </summary>
    public ClientHelloBuilder WithGreaseEncryptedClientHello(
        IReadOnlyList<TlsHpkeSymmetricCipherSuite> cipherSuites,
        params int[] payloadLengths)
    {
        ArgumentNullException.ThrowIfNull(cipherSuites);
        ArgumentNullException.ThrowIfNull(payloadLengths);
        _greaseEchCipherSuites = cipherSuites.ToArray();
        _greaseEchPayloadLengths = (int[])payloadLengths.Clone();
        SetExtensionEnabled(ClientHelloExtensionKind.EncryptedClientHello, enabled: true);
        return this;
    }

    /// <summary>Sets the exact order of every enabled built-in extension.</summary>
    public ClientHelloBuilder WithExtensionOrder(params ClientHelloExtensionKind[] order)
    {
        ArgumentNullException.ThrowIfNull(order);
        _extensionLayout = null;
        _extensionOrder.Clear();
        _extensionOrder.AddRange(order);
        return this;
    }

    /// <summary>
    /// Sets an exact mixed layout of semantic built-ins and opaque raw extensions.
    /// Every enabled built-in must occur exactly once. Raw data is snapshotted.
    /// </summary>
    public ClientHelloBuilder WithExtensionLayout(params ClientHelloExtensionSpec[] extensions)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        _extensionLayout = extensions.Select(extension =>
        {
            ArgumentNullException.ThrowIfNull(extension);
            return extension.Snapshot();
        }).ToArray();
        return this;
    }

    /// <summary>Validates and creates an immutable reusable ClientHello specification.</summary>
    public ClientHelloSpec BuildSpec() => new(BuildConfiguration());

    internal ClientHelloConfiguration BuildConfiguration()
    {
        ValidateUniqueAndNonEmpty(_cipherSuites, nameof(_cipherSuites));
        ValidateUniqueAndNonEmpty(_supportedVersions, nameof(_supportedVersions));
        ValidateUniqueAndNonEmpty(_supportedGroups, nameof(_supportedGroups));
        if (_signatureAlgorithms.Length == 0)
        {
            throw new ArgumentException("At least one value is required.", nameof(_signatureAlgorithms));
        }
        if (!_allowDuplicateSignatureAlgorithms)
        {
            ValidateUnique(_signatureAlgorithms, nameof(_signatureAlgorithms));
        }

        foreach (var suite in _cipherSuites)
        {
            if (!Enum.IsDefined(suite))
            {
                throw new NotSupportedException($"Cipher suite 0x{(ushort)suite:X4} is unknown.");
            }
        }

        foreach (var version in _supportedVersions)
        {
            if (!Enum.IsDefined(version))
            {
                throw new NotSupportedException($"TLS version 0x{(ushort)version:X4} is unknown.");
            }
        }

        foreach (var group in _supportedGroups)
        {
            EnsureAdvertisableGroup(group);
        }

        var keyShareGroups = _includeKeyShareExtension
            ? _keyShareGroups ?? _supportedGroups
            : [];
        ValidateUnique(keyShareGroups, nameof(_keyShareGroups));
        var lastSupportedIndex = -1;
        foreach (var group in keyShareGroups)
        {
            EnsureKeyShareGroup(group);
            var supportedIndex = Array.IndexOf(_supportedGroups, group);
            if (supportedIndex < 0 || supportedIndex <= lastSupportedIndex)
            {
                throw new ArgumentException(
                    "Key shares must be a same-order subset of supported groups.",
                    nameof(_keyShareGroups));
            }

            lastSupportedIndex = supportedIndex;
        }

        foreach (var scheme in _signatureAlgorithms)
        {
            if (!Enum.IsDefined(scheme))
            {
                throw new NotSupportedException($"Signature scheme 0x{(ushort)scheme:X4} is not implemented.");
            }
        }
        if (_certificateSignatureAlgorithms is not null)
        {
            ValidateUniqueAndNonEmpty(
                _certificateSignatureAlgorithms,
                nameof(_certificateSignatureAlgorithms));
            foreach (var scheme in _certificateSignatureAlgorithms)
            {
                if (!Enum.IsDefined(scheme))
                {
                    throw new NotSupportedException(
                        $"Certificate signature scheme 0x{(ushort)scheme:X4} is not implemented.");
                }
            }

            var firstLegacyIndex = Array.FindIndex(
                _certificateSignatureAlgorithms,
                IsLegacySignatureScheme);
            if (firstLegacyIndex >= 0 && _certificateSignatureAlgorithms
                .Skip(firstLegacyIndex)
                .Any(scheme => !IsLegacySignatureScheme(scheme)))
            {
                throw new ArgumentException(
                    "Legacy SHA-1 certificate schemes must have the lowest preference.",
                    nameof(_certificateSignatureAlgorithms));
            }
        }
        if (_delegatedCredentialSignatureAlgorithms is not null)
        {
            ValidateUniqueAndNonEmpty(
                _delegatedCredentialSignatureAlgorithms,
                nameof(_delegatedCredentialSignatureAlgorithms));
            foreach (var scheme in _delegatedCredentialSignatureAlgorithms)
            {
                if (!Enum.IsDefined(scheme) || !_signatureAlgorithms.Contains(scheme))
                {
                    throw new NotSupportedException(
                        $"Delegated credential scheme 0x{(ushort)scheme:X4} must also be offered in signature_algorithms.");
                }
                if (!IsExecutableDelegatedCredentialAlgorithm(scheme) &&
                    !_allowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity)
                {
                    throw new NotSupportedException(
                        $"Delegated credential scheme {scheme} is retained only by an explicit historical wire-fidelity profile.");
                }
            }
            if (!_supportedVersions.Contains(TlsProtocolVersion.Tls13))
            {
                throw new InvalidOperationException(
                    "Delegated credentials require a TLS 1.3-capable ClientHello.");
            }
        }

        ValidateAlpn();
        ValidateApplicationSettings();
        if (_quicTransportParameters is not null &&
            (!_supportedVersions.SequenceEqual([TlsProtocolVersion.Tls13]) ||
             _alpn.Length == 0))
        {
            throw new InvalidOperationException(
                "QUIC requires a TLS 1.3-only ClientHello with at least one ALPN protocol.");
        }
        if (_sessionId is { Length: > TlsConstants.MaxSessionIdLength })
        {
            throw new ArgumentOutOfRangeException(nameof(_sessionId));
        }

        if (_paddingLength is < 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(_paddingLength));
        }
        if (_recordSizeLimit > TlsConstants.MaxPlaintextLength &&
            !_supportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            throw new ArgumentOutOfRangeException(
                nameof(_recordSizeLimit),
                "A TLS 1.2-only ClientHello cannot advertise a record limit above 16384.");
        }
        if (_greaseEchPayloadLengths is not null)
        {
            if (!_supportedVersions.Contains(TlsProtocolVersion.Tls13))
            {
                throw new InvalidOperationException(
                    "GREASE ECH requires a TLS 1.3-capable ClientHello.");
            }
            if (_greaseEchPayloadLengths.Distinct().Count() !=
                _greaseEchPayloadLengths.Length ||
                _greaseEchPayloadLengths.Length > byte.MaxValue ||
                _greaseEchPayloadLengths.Any(length => length is < 1 or > ushort.MaxValue - 16))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(_greaseEchPayloadLengths),
                    "GREASE ECH accepts at most 255 distinct payload lengths that leave room for the AEAD tag.");
            }
            if ((_extensionLayout ?? []).Any(extension =>
                extension.RawExtensionType == (ushort)TlsExtensionType.EncryptedClientHello))
            {
                throw new ArgumentException(
                    "Semantic GREASE ECH cannot be combined with a raw encrypted_client_hello extension.",
                    nameof(_extensionLayout));
            }

            if (_greaseEchCipherSuites is not { Length: > 0 and <= byte.MaxValue } ||
                _greaseEchCipherSuites.Distinct().Count() != _greaseEchCipherSuites.Length)
            {
                throw new ArgumentException(
                    "GREASE ECH requires between 1 and 255 distinct HPKE suites.",
                    nameof(_greaseEchCipherSuites));
            }
            foreach (var suite in _greaseEchCipherSuites)
            {
                if (suite.KdfId is not (TlsHpkeKdfId.HkdfSha256 or
                    TlsHpkeKdfId.HkdfSha384 or TlsHpkeKdfId.HkdfSha512) ||
                    suite.AeadId is not (TlsHpkeAeadId.Aes128Gcm or
                        TlsHpkeAeadId.Aes256Gcm or TlsHpkeAeadId.ChaCha20Poly1305))
                {
                    throw new NotSupportedException(
                        "GREASE ECH was configured with an unsupported HPKE suite.");
                }
            }
        }
        if (_fixedGreaseKeyShareBody is not null && _greasePolicy is null)
        {
            throw new InvalidOperationException("A fixed GREASE key_share body requires GREASE.");
        }

        var required = new HashSet<ClientHelloExtensionKind>
        {
            ClientHelloExtensionKind.SupportedGroups,
            ClientHelloExtensionKind.SignatureAlgorithms,
        };
        if (_includeSupportedVersionsExtension)
        {
            required.Add(ClientHelloExtensionKind.SupportedVersions);
        }
        if (_includeKeyShareExtension)
        {
            required.Add(ClientHelloExtensionKind.KeyShare);
        }

        if (_includeSni)
        {
            required.Add(ClientHelloExtensionKind.ServerName);
        }
        if (_greasePolicy is not null)
        {
            required.Add(ClientHelloExtensionKind.Grease);
        }
        if (_secondaryGreaseExtensionBody is not null)
        {
            required.Add(ClientHelloExtensionKind.SecondaryGrease);
        }
        if (_alpn.Length != 0)
        {
            required.Add(ClientHelloExtensionKind.ApplicationLayerProtocolNegotiation);
        }
        if (_applicationSettingsCodePoint.HasValue)
        {
            required.Add(ClientHelloExtensionKind.ApplicationSettings);
        }
        if (_paddingLength.HasValue || _useBoringPadding)
        {
            required.Add(ClientHelloExtensionKind.Padding);
        }
        if (_certificateSignatureAlgorithms is not null)
        {
            required.Add(ClientHelloExtensionKind.SignatureAlgorithmsCert);
        }
        if (_recordSizeLimit.HasValue)
        {
            required.Add(ClientHelloExtensionKind.RecordSizeLimit);
        }
        if (_delegatedCredentialSignatureAlgorithms is not null)
        {
            required.Add(ClientHelloExtensionKind.DelegatedCredential);
        }
        if (_quicTransportParameters is not null)
        {
            required.Add(ClientHelloExtensionKind.QuicTransportParameters);
        }
        if (_greaseEchPayloadLengths is not null)
        {
            required.Add(ClientHelloExtensionKind.EncryptedClientHello);
        }

        var configuredLayout = _extensionLayout ??
            _extensionOrder.Select(ClientHelloExtensionSpec.BuiltIn).ToArray();
        if (configuredLayout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.PskKeyExchangeModes))
        {
            required.Add(ClientHelloExtensionKind.PskKeyExchangeModes);
        }
        if (configuredLayout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey))
        {
            required.Add(ClientHelloExtensionKind.PreSharedKey);
        }
        if (configuredLayout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.EarlyData))
        {
            required.Add(ClientHelloExtensionKind.EarlyData);
        }
        if (configuredLayout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.PostHandshakeAuthentication))
        {
            required.Add(ClientHelloExtensionKind.PostHandshakeAuthentication);
        }
        if (_greaseEchPayloadLengths is null && configuredLayout.Any(extension =>
            extension.BuiltInKind == ClientHelloExtensionKind.EncryptedClientHello))
        {
            required.Add(ClientHelloExtensionKind.EncryptedClientHello);
        }

        var extensionLayout = configuredLayout.Select(extension => extension.Snapshot()).ToArray();
        ValidateExtensionLayout(extensionLayout, required);
        ValidateResumptionLayout(extensionLayout, _supportedVersions);

        return new ClientHelloConfiguration(
            (TlsCipherSuite[])_cipherSuites.Clone(),
            (TlsProtocolVersion[])_supportedVersions.Clone(),
            (NamedGroup[])_supportedGroups.Clone(),
            (NamedGroup[])keyShareGroups.Clone(),
            (SignatureScheme[])_signatureAlgorithms.Clone(),
            _allowDuplicateSignatureAlgorithms,
            _certificateSignatureAlgorithms is null
                ? null
                : (SignatureScheme[])_certificateSignatureAlgorithms.Clone(),
            _recordSizeLimit,
            _delegatedCredentialSignatureAlgorithms is null
                ? null
                : (SignatureScheme[])_delegatedCredentialSignatureAlgorithms.Clone(),
            _allowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity,
            _quicTransportParameters is null ? null : (byte[])_quicTransportParameters.Clone(),
            (string[])_alpn.Clone(),
            _applicationSettingsCodePoint,
            (string[])_applicationSettingsProtocols.Clone(),
            _sessionId is null ? null : (byte[])_sessionId.Clone(),
            _paddingLength,
            _useBoringPadding,
            _shuffleExtensions,
            _greaseEchCipherSuites is null
                ? null
                : (TlsHpkeSymmetricCipherSuite[])_greaseEchCipherSuites.Clone(),
            _greaseEchPayloadLengths is null
                ? null
                : (int[])_greaseEchPayloadLengths.Clone(),
            _greasePolicy?.Snapshot(),
            _fixedGreaseKeyShareBody is null ? null : (byte[])_fixedGreaseKeyShareBody.Clone(),
            _secondaryGreaseExtensionBody is null ? null : (byte[])_secondaryGreaseExtensionBody.Clone(),
            _includeSni,
            extensionLayout);
    }

    private static void ValidateExtensionLayout(
        IReadOnlyList<ClientHelloExtensionSpec> layout,
        HashSet<ClientHelloExtensionKind> required)
    {
        var builtIns = new List<ClientHelloExtensionKind>();
        var rawTypes = new HashSet<ushort>();
        var aggregateRawData = 0;

        foreach (var extension in layout)
        {
            if (extension.BuiltInKind is { } kind)
            {
                if (kind == ClientHelloExtensionKind.Cookie)
                {
                    throw new ArgumentException(
                        "Cookie is inserted only in response to a HelloRetryRequest.",
                        nameof(layout));
                }

                builtIns.Add(kind);
                continue;
            }

            var type = extension.RawExtensionType ??
                throw new ArgumentException("Extension slot has no kind or wire type.", nameof(layout));
            if (IsSemanticBuiltInWireType(type))
            {
                throw new ArgumentException(
                    $"Raw extension 0x{type:X4} collides with a semantic SharpTls extension.",
                    nameof(layout));
            }
            if (!rawTypes.Add(type))
            {
                throw new ArgumentException(
                    $"Raw extension type 0x{type:X4} occurs more than once.",
                    nameof(layout));
            }

            aggregateRawData = checked(aggregateRawData + extension.RawData.Length);
        }

        if (builtIns.Count != required.Count ||
            builtIns.Distinct().Count() != builtIns.Count ||
            !builtIns.ToHashSet().SetEquals(required))
        {
            throw new ArgumentException(
                "Extension layout must contain every enabled built-in exactly once.",
                nameof(layout));
        }
        if (aggregateRawData > MaxAggregateRawExtensionData)
        {
            throw new ArgumentOutOfRangeException(
                nameof(layout),
                $"Aggregate raw extension data exceeds {MaxAggregateRawExtensionData} bytes.");
        }
        if (required.Contains(ClientHelloExtensionKind.Grease) &&
            rawTypes.Any(IsGreaseValue))
        {
            throw new ArgumentException(
                "A raw GREASE extension cannot be combined with semantic GREASE generation.",
                nameof(layout));
        }
    }

    private static bool IsSemanticBuiltInWireType(ushort type) => type is
        (ushort)TlsExtensionType.ServerName or
        (ushort)TlsExtensionType.SupportedVersions or
        (ushort)TlsExtensionType.Cookie or
        (ushort)TlsExtensionType.SupportedGroups or
        (ushort)TlsExtensionType.SignatureAlgorithms or
        (ushort)TlsExtensionType.SignatureAlgorithmsCert or
        (ushort)TlsExtensionType.KeyShare or
        (ushort)TlsExtensionType.PostHandshakeAuthentication or
        (ushort)TlsExtensionType.RecordSizeLimit or
        (ushort)TlsExtensionType.DelegatedCredential or
        (ushort)TlsExtensionType.QuicTransportParameters or
        (ushort)TlsExtensionType.EarlyData or
        (ushort)TlsExtensionType.PreSharedKey or
        (ushort)TlsExtensionType.ApplicationLayerProtocolNegotiation or
        (ushort)TlsExtensionType.Padding or
        (ushort)TlsApplicationSettingsCodePoint.LegacyDraft or
        (ushort)TlsApplicationSettingsCodePoint.ChromeExperiment;

    private static void ValidateResumptionLayout(
        IReadOnlyList<ClientHelloExtensionSpec> layout,
        IReadOnlyList<TlsProtocolVersion> supportedVersions)
    {
        var pskIndex = -1;
        var hasPskDheMode = false;
        var hasSemanticModes = false;
        var earlyDataIndex = -1;
        for (var index = 0; index < layout.Count; index++)
        {
            var extension = layout[index];
            if (extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey)
            {
                pskIndex = index;
            }
            if (extension.BuiltInKind == ClientHelloExtensionKind.PskKeyExchangeModes)
            {
                hasSemanticModes = true;
                hasPskDheMode = true;
            }
            if (extension.BuiltInKind == ClientHelloExtensionKind.EarlyData)
            {
                earlyDataIndex = index;
            }
            if (extension.RawExtensionType == (ushort)TlsExtensionType.PskKeyExchangeModes)
            {
                var data = extension.RawData;
                hasPskDheMode = data.Length >= 2 && data[0] == data.Length - 1 &&
                    data[1..].Contains((byte)1);
            }
        }

        if (hasSemanticModes && layout.Any(extension =>
            extension.RawExtensionType == (ushort)TlsExtensionType.PskKeyExchangeModes))
        {
            throw new ArgumentException(
                "Semantic and raw psk_key_exchange_modes extensions cannot be combined.",
                nameof(layout));
        }
        if (pskIndex < 0)
        {
            if (earlyDataIndex >= 0)
            {
                throw new ArgumentException(
                    "An early_data slot requires a pre_shared_key slot.",
                    nameof(layout));
            }
            return;
        }
        if (pskIndex != layout.Count - 1)
        {
            throw new ArgumentException(
                "pre_shared_key must be the final ClientHello extension slot.",
                nameof(layout));
        }
        if (!supportedVersions.Contains(TlsProtocolVersion.Tls13) || !hasPskDheMode)
        {
            throw new ArgumentException(
                "TLS 1.3 resumption requires TLS 1.3 and the psk_dhe_ke mode.",
                nameof(layout));
        }
        if (earlyDataIndex > pskIndex)
        {
            throw new ArgumentException(
                "early_data must precede the final pre_shared_key extension.",
                nameof(layout));
        }
    }

    private static bool IsGreaseValue(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (byte)(value >> 8) == (byte)value;

    private void ValidateAlpn()
    {
        if (_alpn.Distinct(StringComparer.Ordinal).Count() != _alpn.Length)
        {
            throw new ArgumentException("ALPN protocol names must be unique.", nameof(_alpn));
        }

        foreach (var protocol in _alpn)
        {
            if (string.IsNullOrEmpty(protocol) || protocol.Length > TlsConstants.MaxAlpnProtocolLength ||
                protocol.Any(character => character > 0x7F))
            {
                throw new ArgumentException(
                    "ALPN protocol names must contain 1-255 ASCII bytes.",
                    nameof(_alpn));
            }
        }
    }

    private void ValidateApplicationSettings()
    {
        if (!_applicationSettingsCodePoint.HasValue)
        {
            if (_applicationSettingsProtocols.Length != 0)
            {
                throw new InvalidOperationException(
                    "Application-settings protocols exist without an extension code point.");
            }
            return;
        }
        if (!_supportedVersions.Contains(TlsProtocolVersion.Tls13))
        {
            throw new InvalidOperationException(
                "Experimental application_settings requires a TLS 1.3-capable ClientHello.");
        }
        if (_alpn.Length == 0)
        {
            throw new InvalidOperationException(
                "Experimental application_settings requires ALPN.");
        }
        if (_applicationSettingsProtocols.Distinct(StringComparer.Ordinal).Count() !=
            _applicationSettingsProtocols.Length)
        {
            throw new ArgumentException(
                "Application-settings protocol names must be unique.",
                nameof(_applicationSettingsProtocols));
        }
        foreach (var protocol in _applicationSettingsProtocols)
        {
            if (!_alpn.Contains(protocol, StringComparer.Ordinal))
            {
                throw new ArgumentException(
                    "Every application-settings protocol must also be offered in ALPN.",
                    nameof(_applicationSettingsProtocols));
            }
        }
    }

    private void SetExtensionEnabled(ClientHelloExtensionKind kind, bool enabled, bool insertAtStart = false)
    {
        _extensionOrder.Remove(kind);
        if (enabled)
        {
            var preSharedKeyIndex = kind == ClientHelloExtensionKind.PreSharedKey
                ? -1
                : _extensionOrder.IndexOf(ClientHelloExtensionKind.PreSharedKey);
            var insertionIndex = insertAtStart
                ? 0
                : preSharedKeyIndex >= 0
                    ? preSharedKeyIndex
                    : _extensionOrder.Count;
            _extensionOrder.Insert(insertionIndex, kind);
        }
    }

    private static void EnsureAdvertisableGroup(NamedGroup group)
    {
        if (group is not (NamedGroup.Secp256r1 or NamedGroup.Secp384r1 or
            NamedGroup.Secp521r1 or NamedGroup.X25519 or NamedGroup.X25519MlKem768 or
            NamedGroup.X25519Kyber768Draft00 or
            NamedGroup.Ffdhe2048 or NamedGroup.Ffdhe3072))
        {
            throw new NotSupportedException($"Named group {group} is unknown.");
        }
    }

    private static bool IsLegacySignatureScheme(SignatureScheme scheme) => scheme is
        SignatureScheme.RsaPkcs1Sha1 or SignatureScheme.EcdsaSha1;

    private static bool IsExecutableDelegatedCredentialAlgorithm(SignatureScheme scheme) =>
        scheme is SignatureScheme.EcdsaSecp256r1Sha256 or
            SignatureScheme.EcdsaSecp384r1Sha384 or
            SignatureScheme.EcdsaSecp521r1Sha512 or
            SignatureScheme.RsaPssPssSha256 or
            SignatureScheme.RsaPssPssSha384 or
            SignatureScheme.RsaPssPssSha512;

    private static void EnsureKeyShareGroup(NamedGroup group)
    {
        if (group is not (NamedGroup.Secp256r1 or NamedGroup.Secp384r1 or
            NamedGroup.Secp521r1 or NamedGroup.X25519 or NamedGroup.X25519MlKem768 or
            NamedGroup.X25519Kyber768Draft00))
        {
            throw new NotSupportedException($"Named group {group} has no implemented key-share provider.");
        }
    }

    private static void ValidateUniqueAndNonEmpty<T>(T[] values, string parameterName)
        where T : struct, Enum
    {
        if (values.Length == 0)
        {
            throw new ArgumentException("At least one value is required.", parameterName);
        }

        ValidateUnique(values, parameterName);
    }

    private static void ValidateUnique<T>(T[] values, string parameterName)
        where T : struct, Enum
    {
        if (values.Distinct().Count() != values.Length)
        {
            throw new ArgumentException("Duplicate values are not allowed.", parameterName);
        }
    }
}

internal sealed record ClientHelloConfiguration(
    TlsCipherSuite[] CipherSuites,
    TlsProtocolVersion[] SupportedVersions,
    NamedGroup[] SupportedGroups,
    NamedGroup[] KeyShareGroups,
    SignatureScheme[] SignatureAlgorithms,
    bool AllowDuplicateSignatureAlgorithms,
    SignatureScheme[]? CertificateSignatureAlgorithms,
    int? RecordSizeLimit,
    SignatureScheme[]? DelegatedCredentialSignatureAlgorithms,
    bool AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity,
    byte[]? QuicTransportParameters,
    string[] AlpnProtocols,
    TlsApplicationSettingsCodePoint? ApplicationSettingsCodePoint,
    string[] ApplicationSettingsProtocols,
    byte[]? SessionId,
    int? PaddingLength,
    bool UseBoringPadding,
    bool ShuffleExtensions,
    TlsHpkeSymmetricCipherSuite[]? GreaseEchCipherSuites,
    int[]? GreaseEchPayloadLengths,
    ClientHelloGreasePolicy? GreasePolicy,
    byte[]? FixedGreaseKeyShareBody,
    byte[]? SecondaryGreaseExtensionBody,
    bool IncludeSni,
    ClientHelloExtensionSpec[] ExtensionLayout)
{
    internal bool SupportsSessionResumption => ExtensionLayout.Any(extension =>
        extension.BuiltInKind == ClientHelloExtensionKind.PreSharedKey);

    internal bool SupportsEarlyData => ExtensionLayout.Any(extension =>
        extension.BuiltInKind == ClientHelloExtensionKind.EarlyData);

    internal bool SupportsPostHandshakeAuthentication => ExtensionLayout.Any(extension =>
        extension.BuiltInKind == ClientHelloExtensionKind.PostHandshakeAuthentication);

    internal ClientHelloConfiguration Snapshot() => new(
        (TlsCipherSuite[])CipherSuites.Clone(),
        (TlsProtocolVersion[])SupportedVersions.Clone(),
        (NamedGroup[])SupportedGroups.Clone(),
        (NamedGroup[])KeyShareGroups.Clone(),
        (SignatureScheme[])SignatureAlgorithms.Clone(),
        AllowDuplicateSignatureAlgorithms,
        CertificateSignatureAlgorithms is null
            ? null
            : (SignatureScheme[])CertificateSignatureAlgorithms.Clone(),
        RecordSizeLimit,
        DelegatedCredentialSignatureAlgorithms is null
            ? null
            : (SignatureScheme[])DelegatedCredentialSignatureAlgorithms.Clone(),
        AllowUnsupportedDelegatedCredentialAlgorithmsForWireFidelity,
        QuicTransportParameters is null ? null : (byte[])QuicTransportParameters.Clone(),
        (string[])AlpnProtocols.Clone(),
        ApplicationSettingsCodePoint,
        (string[])ApplicationSettingsProtocols.Clone(),
        SessionId is null ? null : (byte[])SessionId.Clone(),
        PaddingLength,
        UseBoringPadding,
        ShuffleExtensions,
        GreaseEchCipherSuites is null
            ? null
            : (TlsHpkeSymmetricCipherSuite[])GreaseEchCipherSuites.Clone(),
        GreaseEchPayloadLengths is null ? null : (int[])GreaseEchPayloadLengths.Clone(),
        GreasePolicy?.Snapshot(),
        FixedGreaseKeyShareBody is null ? null : (byte[])FixedGreaseKeyShareBody.Clone(),
        SecondaryGreaseExtensionBody is null ? null : (byte[])SecondaryGreaseExtensionBody.Clone(),
        IncludeSni,
        ExtensionLayout.Select(extension => extension.Snapshot()).ToArray());
}

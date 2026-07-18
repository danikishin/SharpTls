using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

/// <summary>
/// Holds a caller-owned client certificate chain and its non-exported private signing key.
/// Keep this object alive until every client configured with it has been disposed.
/// </summary>
public sealed class TlsClientCertificate : IDisposable
{
    private const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";
    private readonly object _sync = new();
    private readonly byte[][] _certificateChain;
    private readonly string? _rsaPublicKeyOid;
    private readonly bool _rsaPssSha256;
    private readonly bool _rsaPssSha384;
    private readonly bool _rsaPssSha512;
    private readonly bool _ownsPrivateKeyHandle;
    private readonly int? _ecdsaKeySize;
    private readonly ITlsClientCertificateSigner? _externalSigner;
    private readonly HashSet<SignatureScheme>? _externalSignerSchemes;
    private readonly SemaphoreSlim _externalSigningGate = new(1, 1);
    private RSA? _rsa;
    private ECDsa? _ecdsa;
    private TlsClientDelegatedCredential? _delegatedCredential;
    private bool _disposed;

    /// <summary>
    /// Creates a credential from a leaf certificate containing a private key and optional
    /// issuer certificates in leaf-to-root wire order. Private key bytes are never exported.
    /// </summary>
    public TlsClientCertificate(
        X509Certificate2 leafWithPrivateKey,
        IEnumerable<X509Certificate2>? issuerCertificates = null)
        : this(
            leafWithPrivateKey,
            GetPrivateKeys(leafWithPrivateKey),
            issuerCertificates,
            ownsPrivateKeyHandle: true)
    {
    }

    /// <summary>
    /// Creates a credential backed by a caller-owned asynchronous signer. SharpTls
    /// verifies that the signer's exported public SPKI exactly matches the leaf and
    /// never requests or exports private key material.
    /// </summary>
    public TlsClientCertificate(
        X509Certificate2 leafCertificate,
        ITlsClientCertificateSigner signer,
        IEnumerable<X509Certificate2>? issuerCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);
        ArgumentNullException.ThrowIfNull(signer);
        ValidateLeafUsage(leafCertificate);

        var signerSpki = signer.ExportSubjectPublicKeyInfo();
        ArgumentNullException.ThrowIfNull(signerSpki);
        var certificateSpki = leafCertificate.PublicKey.ExportSubjectPublicKeyInfo();
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(signerSpki, certificateSpki))
            {
                throw new ArgumentException(
                    "The asynchronous signer's public key does not match the leaf certificate.",
                    nameof(signer));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signerSpki);
            CryptographicOperations.ZeroMemory(certificateSpki);
        }

        _externalSigner = signer;
        _ownsPrivateKeyHandle = false;
        _rsaPublicKeyOid = leafCertificate.PublicKey.Oid?.Value;
        if (_rsaPublicKeyOid is RsaSignatureScheme.RsaEncryptionOid or
            RsaSignatureScheme.RsaPssOid)
        {
            _rsaPssSha256 = RsaSignatureScheme.ParametersPermit(
                leafCertificate,
                HashAlgorithmName.SHA256);
            _rsaPssSha384 = RsaSignatureScheme.ParametersPermit(
                leafCertificate,
                HashAlgorithmName.SHA384);
            _rsaPssSha512 = RsaSignatureScheme.ParametersPermit(
                leafCertificate,
                HashAlgorithmName.SHA512);
        }
        else
        {
            using var ecdsa = leafCertificate.GetECDsaPublicKey() ??
                throw new ArgumentException(
                    "The asynchronous signer leaf must contain an RSA or ECDSA public key.",
                    nameof(leafCertificate));
            _ecdsaKeySize = ecdsa.KeySize;
        }

        ArgumentNullException.ThrowIfNull(signer.SupportedSignatureSchemes);
        var signerSchemes = signer.SupportedSignatureSchemes.ToArray();
        _externalSignerSchemes = signerSchemes.ToHashSet();
        if (_externalSignerSchemes.Count == 0 ||
            _externalSignerSchemes.Count != signerSchemes.Length ||
            _externalSignerSchemes.Any(scheme => !IsCompatibleKeyScheme(scheme)))
        {
            throw new ArgumentException(
                "The asynchronous signer advertises an empty or leaf-incompatible signature-scheme set.",
                nameof(signer));
        }
        _certificateChain = BuildCertificateChain(leafCertificate, issuerCertificates);
    }

    /// <summary>
    /// Creates an RSA credential when the platform cannot associate an RSASSA-PSS SubjectPublicKeyInfo
    /// certificate with its private key. The caller retains ownership of <paramref name="privateKey"/>
    /// and must keep it alive until this credential is disposed.
    /// </summary>
    public TlsClientCertificate(
        X509Certificate2 leafCertificate,
        RSA privateKey,
        IEnumerable<X509Certificate2>? issuerCertificates = null)
        : this(
            leafCertificate,
            (privateKey ?? throw new ArgumentNullException(nameof(privateKey)), null),
            issuerCertificates,
            ownsPrivateKeyHandle: false)
    {
    }

    private TlsClientCertificate(
        X509Certificate2 leafWithPrivateKey,
        (RSA? Rsa, ECDsa? Ecdsa) keys,
        IEnumerable<X509Certificate2>? issuerCertificates,
        bool ownsPrivateKeyHandle)
    {
        ArgumentNullException.ThrowIfNull(leafWithPrivateKey);

        _rsa = keys.Rsa;
        _ecdsa = keys.Ecdsa;
        _ownsPrivateKeyHandle = ownsPrivateKeyHandle;
        if ((_rsa is null) == (_ecdsa is null))
        {
            DisposeOwnedKeys();
            throw new ArgumentException(
                "The leaf must contain exactly one supported RSA or ECDSA private key.",
                nameof(leafWithPrivateKey));
        }

        try
        {
            ValidateLeafUsage(leafWithPrivateKey);
            ValidatePrivateKeyMatchesCertificate(leafWithPrivateKey);
            if (_rsa is not null)
            {
                _rsaPublicKeyOid = leafWithPrivateKey.PublicKey.Oid?.Value;
                _rsaPssSha256 = RsaSignatureScheme.ParametersPermit(
                    leafWithPrivateKey,
                    HashAlgorithmName.SHA256);
                _rsaPssSha384 = RsaSignatureScheme.ParametersPermit(
                    leafWithPrivateKey,
                    HashAlgorithmName.SHA384);
                _rsaPssSha512 = RsaSignatureScheme.ParametersPermit(
                    leafWithPrivateKey,
                    HashAlgorithmName.SHA512);
            }
            else
            {
                _ecdsaKeySize = _ecdsa!.KeySize;
            }
            _certificateChain = BuildCertificateChain(leafWithPrivateKey, issuerCertificates);
        }
        catch
        {
            if (_ownsPrivateKeyHandle)
            {
                _rsa?.Dispose();
                _ecdsa?.Dispose();
            }
            _rsa = null;
            _ecdsa = null;
            throw;
        }
    }

    /// <summary>Gets the number of certificates that will be sent, including the leaf.</summary>
    public int CertificateCount => _certificateChain.Length;

    /// <summary>
    /// Attaches one caller-owned, pre-issued RFC 9345 client delegated credential.
    /// Its signature, lifetime, DelegationUsage, and certificate binding are validated
    /// immediately. Keep the delegated credential alive while this credential is in use.
    /// </summary>
    public void AttachDelegatedCredential(
        TlsClientDelegatedCredential delegatedCredential)
    {
        ArgumentNullException.ThrowIfNull(delegatedCredential);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_delegatedCredential is not null)
            {
                throw new InvalidOperationException(
                    "A client delegated credential is already attached.");
            }
            using var leaf = X509CertificateLoader.LoadCertificate(_certificateChain[0]);
            delegatedCredential.ValidateAndBind(leaf);
            _delegatedCredential = delegatedCredential;
        }
    }

    internal IReadOnlyList<byte[]> SnapshotCertificateChain()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _certificateChain.Select(value => (byte[])value.Clone()).ToArray();
        }
    }

    internal SignatureScheme? SelectTls13SignatureScheme(
        IReadOnlyList<SignatureScheme> peerSchemes)
    {
        ArgumentNullException.ThrowIfNull(peerSchemes);
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateCurrentTime();
            foreach (var scheme in peerSchemes)
            {
                if (IsCompatibleTls13Scheme(scheme))
                {
                    return scheme;
                }
            }

            return null;
        }
    }

    internal Tls13ClientAuthenticationSelection? SelectTls13Authentication(
        IReadOnlyList<SignatureScheme> peerSchemes,
        IReadOnlyList<SignatureScheme>? delegatedCredentialSchemes)
    {
        ArgumentNullException.ThrowIfNull(peerSchemes);
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateCurrentTime();
            if (_delegatedCredential is { } delegated &&
                delegated.CanUse(peerSchemes, delegatedCredentialSchemes))
            {
                return new Tls13ClientAuthenticationSelection(
                    delegated.CertificateVerifyAlgorithm,
                    delegated);
            }
            foreach (var scheme in peerSchemes)
            {
                if (IsCompatibleTls13Scheme(scheme))
                {
                    return new Tls13ClientAuthenticationSelection(scheme, null);
                }
            }
            return null;
        }
    }

    internal SignatureScheme? SelectTls12SignatureScheme(
        IReadOnlyList<SignatureScheme> peerSchemes,
        ReadOnlySpan<byte> certificateTypes)
    {
        ArgumentNullException.ThrowIfNull(peerSchemes);
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateCurrentTime();
            if ((_rsa is not null && !certificateTypes.Contains((byte)1)) ||
                (_ecdsa is not null && !certificateTypes.Contains((byte)64)))
            {
                return null;
            }

            foreach (var scheme in peerSchemes)
            {
                if (IsCompatibleTls12Scheme(scheme))
                {
                    return scheme;
                }
            }

            return null;
        }
    }

    internal byte[] SignHash(SignatureScheme scheme, ReadOnlySpan<byte> hash)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_externalSigner is not null)
            {
                throw new InvalidOperationException(
                    "An asynchronous client signer must be invoked through SignHashAsync.");
            }
            var algorithm = GetHashAlgorithm(scheme);
            return scheme switch
            {
                SignatureScheme.RsaPssRsaeSha256 or
                SignatureScheme.RsaPssRsaeSha384 or
                SignatureScheme.RsaPssRsaeSha512 or
                SignatureScheme.RsaPssPssSha256 or
                SignatureScheme.RsaPssPssSha384 or
                SignatureScheme.RsaPssPssSha512 =>
                    GetRsa().SignHash(hash, algorithm, RSASignaturePadding.Pss),
                SignatureScheme.RsaPkcs1Sha256 or
                SignatureScheme.RsaPkcs1Sha384 or
                SignatureScheme.RsaPkcs1Sha512 =>
                    GetRsa().SignHash(hash, algorithm, RSASignaturePadding.Pkcs1),
                SignatureScheme.EcdsaSecp256r1Sha256 or
                SignatureScheme.EcdsaSecp384r1Sha384 or
                SignatureScheme.EcdsaSecp521r1Sha512 =>
                    GetEcdsa().SignHash(hash, DSASignatureFormat.Rfc3279DerSequence),
                _ => throw new NotSupportedException(
                    $"Client CertificateVerify scheme {scheme} is not supported."),
            };
        }
    }

    internal async ValueTask<byte[]> SignHashAsync(
        SignatureScheme scheme,
        ReadOnlyMemory<byte> hash,
        CancellationToken cancellationToken)
    {
        var expectedHashLength = GetHashAlgorithm(scheme).Name switch
        {
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new NotSupportedException(),
        };
        if (hash.Length != expectedHashLength)
        {
            throw new ArgumentException(
                "The CertificateVerify hash length does not match the signature scheme.",
                nameof(hash));
        }
        if (_externalSigner is null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SignHash(scheme, hash.Span);
        }

        await _externalSigningGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var hashCopy = hash.ToArray();
        try
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                if (!IsCompatibleScheme(scheme))
                {
                    throw new NotSupportedException(
                        $"Client CertificateVerify scheme {scheme} is not supported by this signer.");
                }
            }
            var signature = await _externalSigner.SignHashAsync(
                scheme,
                hashCopy,
                cancellationToken).ConfigureAwait(false);
            lock (_sync)
            {
                if (_disposed)
                {
                    if (signature is not null)
                    {
                        CryptographicOperations.ZeroMemory(signature);
                    }
                    ThrowIfDisposed();
                }
            }
            if (signature is null || signature.Length is 0 or > ushort.MaxValue)
            {
                if (signature is not null)
                {
                    CryptographicOperations.ZeroMemory(signature);
                }
                throw new CryptographicException(
                    "The asynchronous client signer returned an invalid signature length.");
            }
            return signature;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hashCopy);
            _externalSigningGate.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_ownsPrivateKeyHandle)
            {
                _rsa?.Dispose();
                _ecdsa?.Dispose();
            }
            _rsa = null;
            _ecdsa = null;
        }
    }

    internal static HashAlgorithmName GetHashAlgorithm(SignatureScheme scheme) => scheme switch
    {
        SignatureScheme.RsaPssRsaeSha256 or
        SignatureScheme.RsaPssPssSha256 or
        SignatureScheme.RsaPkcs1Sha256 or
        SignatureScheme.EcdsaSecp256r1Sha256 => HashAlgorithmName.SHA256,
        SignatureScheme.RsaPssRsaeSha384 or
        SignatureScheme.RsaPssPssSha384 or
        SignatureScheme.RsaPkcs1Sha384 or
        SignatureScheme.EcdsaSecp384r1Sha384 => HashAlgorithmName.SHA384,
        SignatureScheme.RsaPssRsaeSha512 or
        SignatureScheme.RsaPssPssSha512 or
        SignatureScheme.RsaPkcs1Sha512 or
        SignatureScheme.EcdsaSecp521r1Sha512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException(
            $"Client CertificateVerify scheme {scheme} is not supported."),
    };

    private bool IsCompatibleTls13Scheme(SignatureScheme scheme) =>
        IsCompatibleScheme(scheme) && scheme is not (
            SignatureScheme.RsaPkcs1Sha256 or
            SignatureScheme.RsaPkcs1Sha384 or
            SignatureScheme.RsaPkcs1Sha512);

    private bool IsCompatibleScheme(SignatureScheme scheme) =>
        (_externalSignerSchemes is null || _externalSignerSchemes.Contains(scheme)) &&
        IsCompatibleKeyScheme(scheme);

    private bool IsCompatibleKeyScheme(SignatureScheme scheme) => scheme switch
    {
        SignatureScheme.RsaPssRsaeSha256 or
        SignatureScheme.RsaPssRsaeSha384 or
        SignatureScheme.RsaPssRsaeSha512 =>
            _rsaPublicKeyOid == RsaSignatureScheme.RsaEncryptionOid,
        SignatureScheme.RsaPssPssSha256 =>
            _rsaPublicKeyOid == RsaSignatureScheme.RsaPssOid && _rsaPssSha256,
        SignatureScheme.RsaPssPssSha384 =>
            _rsaPublicKeyOid == RsaSignatureScheme.RsaPssOid && _rsaPssSha384,
        SignatureScheme.RsaPssPssSha512 =>
            _rsaPublicKeyOid == RsaSignatureScheme.RsaPssOid && _rsaPssSha512,
        SignatureScheme.RsaPkcs1Sha256 or
        SignatureScheme.RsaPkcs1Sha384 or
        SignatureScheme.RsaPkcs1Sha512 =>
            _rsaPublicKeyOid == RsaSignatureScheme.RsaEncryptionOid,
        SignatureScheme.EcdsaSecp256r1Sha256 => _ecdsaKeySize == 256,
        SignatureScheme.EcdsaSecp384r1Sha384 => _ecdsaKeySize == 384,
        SignatureScheme.EcdsaSecp521r1Sha512 => _ecdsaKeySize == 521,
        _ => false,
    };

    private bool IsCompatibleTls12Scheme(SignatureScheme scheme) =>
        IsCompatibleScheme(scheme);

    private static byte[][] BuildCertificateChain(
        X509Certificate2 leaf,
        IEnumerable<X509Certificate2>? issuerCertificates)
    {
        var chain = new List<byte[]> { leaf.RawData };
        if (issuerCertificates is null)
        {
            return [.. chain];
        }
        foreach (var issuer in issuerCertificates)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            if (chain.Any(existing => existing.AsSpan().SequenceEqual(issuer.RawData)))
            {
                throw new ArgumentException(
                    "The client certificate chain contains a duplicate certificate.",
                    nameof(issuerCertificates));
            }
            chain.Add(issuer.RawData);
        }
        return [.. chain];
    }

    private void ValidatePrivateKeyMatchesCertificate(X509Certificate2 leaf)
    {
        byte[] privateSpki;
        byte[] publicSpki;
        if (_rsa is not null)
        {
            if (leaf.PublicKey.Oid?.Value is not (
                RsaSignatureScheme.RsaEncryptionOid or RsaSignatureScheme.RsaPssOid))
            {
                throw new ArgumentException(
                    "The client RSA certificate must use rsaEncryption or RSASSA-PSS.",
                    nameof(leaf));
            }

            using var publicKey = RsaSignatureScheme.CreatePublicKey(leaf) ??
                throw new ArgumentException("The leaf RSA public key is unavailable.", nameof(leaf));
            var privateParameters = _rsa.ExportParameters(includePrivateParameters: false);
            var publicParameters = publicKey.ExportParameters(includePrivateParameters: false);
            privateSpki = EncodeRsaPublicValues(privateParameters);
            publicSpki = EncodeRsaPublicValues(publicParameters);
        }
        else
        {
            using var publicKey = leaf.GetECDsaPublicKey() ??
                throw new ArgumentException("The leaf ECDSA public key is unavailable.", nameof(leaf));
            privateSpki = _ecdsa!.ExportSubjectPublicKeyInfo();
            publicSpki = publicKey.ExportSubjectPublicKeyInfo();
        }

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(privateSpki, publicSpki))
            {
                throw new ArgumentException(
                    "The private key does not match the leaf certificate.",
                    nameof(leaf));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateSpki);
            CryptographicOperations.ZeroMemory(publicSpki);
        }
    }

    private static byte[] EncodeRsaPublicValues(RSAParameters parameters)
    {
        if (parameters.Modulus is null || parameters.Exponent is null)
        {
            throw new CryptographicException("RSA public parameters are incomplete.");
        }
        var encoded = new byte[4 + parameters.Modulus.Length + parameters.Exponent.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
            encoded,
            checked((ushort)parameters.Modulus.Length));
        parameters.Modulus.CopyTo(encoded.AsSpan(2));
        var exponentOffset = 2 + parameters.Modulus.Length;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
            encoded.AsSpan(exponentOffset),
            checked((ushort)parameters.Exponent.Length));
        parameters.Exponent.CopyTo(encoded.AsSpan(exponentOffset + 2));
        return encoded;
    }

    private static (RSA? Rsa, ECDsa? Ecdsa) GetPrivateKeys(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return (certificate.GetRSAPrivateKey(), certificate.GetECDsaPrivateKey());
    }

    private void DisposeOwnedKeys()
    {
        if (_ownsPrivateKeyHandle)
        {
            _rsa?.Dispose();
            _ecdsa?.Dispose();
        }
    }

    private static void ValidateLeafUsage(X509Certificate2 leaf)
    {
        var keyUsage = leaf.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (keyUsage is not null &&
            (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
        {
            throw new ArgumentException(
                "The client certificate key usage does not permit digital signatures.",
                nameof(leaf));
        }

        var enhancedKeyUsage = leaf.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();
        if (enhancedKeyUsage is not null &&
            !enhancedKeyUsage.EnhancedKeyUsages.Cast<Oid>().Any(oid =>
                oid.Value is ClientAuthenticationOid or AnyExtendedKeyUsageOid))
        {
            throw new ArgumentException(
                "The client certificate extended key usage does not permit client authentication.",
                nameof(leaf));
        }
    }

    private void ValidateCurrentTime()
    {
        using var leaf = X509CertificateLoader.LoadCertificate(_certificateChain[0]);
        var now = DateTime.UtcNow;
        if (now < leaf.NotBefore.ToUniversalTime() || now > leaf.NotAfter.ToUniversalTime())
        {
            throw new TlsProtocolException(
                TlsAlertDescription.CertificateExpired,
                "The configured client certificate is outside its validity interval.");
        }
    }

    private RSA GetRsa() => _rsa ?? throw new InvalidOperationException(
        "The client credential does not contain an RSA key.");

    private ECDsa GetEcdsa() => _ecdsa ?? throw new InvalidOperationException(
        "The client credential does not contain an ECDSA key.");

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

internal readonly record struct Tls13ClientAuthenticationSelection(
    SignatureScheme SignatureScheme,
    TlsClientDelegatedCredential? DelegatedCredential);

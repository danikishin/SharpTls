using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

/// <summary>Optional authenticated certificate evidence emitted when the client requests it.</summary>
public sealed class TlsServerCertificatePresentation
{
    private readonly byte[]? _ocspResponse;
    private readonly byte[][] _signedCertificateTimestamps;

    /// <summary>Creates a snapshotted OCSP/SCT presentation.</summary>
    public TlsServerCertificatePresentation(
        ReadOnlyMemory<byte>? stapledOcspResponse = null,
        IEnumerable<byte[]>? signedCertificateTimestamps = null)
    {
        _ocspResponse = stapledOcspResponse?.ToArray();
        _signedCertificateTimestamps = signedCertificateTimestamps?
            .Select(value => value is null
                ? throw new ArgumentException("An SCT cannot be null.", nameof(signedCertificateTimestamps))
                : (byte[])value.Clone())
            .ToArray() ?? [];
        if (_ocspResponse is { Length: 0 } || _ocspResponse is { Length: > 0xFFFFFF } ||
            _signedCertificateTimestamps.Length > ushort.MaxValue ||
            _signedCertificateTimestamps.Any(value => value.Length is 0 or > ushort.MaxValue) ||
            _signedCertificateTimestamps.Sum(value => 2L + value.Length) > ushort.MaxValue)
        {
            throw new ArgumentException("The stapled OCSP response or SCT list is invalid.");
        }
    }

    internal byte[]? CopyOcspResponse() => _ocspResponse is null
        ? null
        : (byte[])_ocspResponse.Clone();

    internal byte[][] CopySignedCertificateTimestamps() =>
        _signedCertificateTimestamps.Select(value => (byte[])value.Clone()).ToArray();

    internal bool HasOcspResponse => _ocspResponse is not null;

    internal bool HasSignedCertificateTimestamps => _signedCertificateTimestamps.Length != 0;
}

/// <summary>
/// Holds a server certificate chain and a runtime RSA or ECDSA signing handle.
/// Caller-supplied key handles remain caller-owned; keys acquired from a certificate are owned.
/// </summary>
public sealed class TlsServerCertificate : IDisposable
{
    private const string AnyExtendedKeyUsageOid = "2.5.29.37.0";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private readonly object _sync = new();
    private readonly byte[][] _chain;
    private readonly bool _ownsKey;
    private readonly string? _rsaOid;
    private readonly bool _rsaPssSha256;
    private readonly bool _rsaPssSha384;
    private readonly bool _rsaPssSha512;
    private RSA? _rsa;
    private ECDsa? _ecdsa;
    private readonly TlsServerCertificatePresentation? _presentation;
    private bool _disposed;

    /// <summary>Creates a credential from a leaf that contains exactly one supported private key.</summary>
    public TlsServerCertificate(
        X509Certificate2 leafWithPrivateKey,
        IEnumerable<X509Certificate2>? issuerCertificates = null,
        TlsServerCertificatePresentation? presentation = null)
    {
        ArgumentNullException.ThrowIfNull(leafWithPrivateKey);
        _rsa = leafWithPrivateKey.GetRSAPrivateKey();
        _ecdsa = leafWithPrivateKey.GetECDsaPrivateKey();
        _ownsKey = true;
        _presentation = presentation;
        try
        {
            Initialize(leafWithPrivateKey, issuerCertificates);
            _chain = BuildChain(leafWithPrivateKey, issuerCertificates);
            _rsaOid = leafWithPrivateKey.PublicKey.Oid?.Value;
            (_rsaPssSha256, _rsaPssSha384, _rsaPssSha512) =
                GetRsaCapabilities(leafWithPrivateKey, _rsa);
        }
        catch
        {
            _rsa?.Dispose();
            _ecdsa?.Dispose();
            _rsa = null;
            _ecdsa = null;
            throw;
        }
    }

    /// <summary>Creates a credential backed by a caller-owned RSA key handle.</summary>
    public TlsServerCertificate(
        X509Certificate2 leafCertificate,
        RSA privateKey,
        IEnumerable<X509Certificate2>? issuerCertificates = null,
        TlsServerCertificatePresentation? presentation = null)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);
        _rsa = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        _ownsKey = false;
        _presentation = presentation;
        Initialize(leafCertificate, issuerCertificates);
        ValidateKeyBinding(leafCertificate, privateKey);
        _chain = BuildChain(leafCertificate, issuerCertificates);
        _rsaOid = leafCertificate.PublicKey.Oid?.Value;
        (_rsaPssSha256, _rsaPssSha384, _rsaPssSha512) =
            GetRsaCapabilities(leafCertificate, privateKey);
    }

    /// <summary>Creates a credential backed by a caller-owned ECDSA key handle.</summary>
    public TlsServerCertificate(
        X509Certificate2 leafCertificate,
        ECDsa privateKey,
        IEnumerable<X509Certificate2>? issuerCertificates = null,
        TlsServerCertificatePresentation? presentation = null)
    {
        ArgumentNullException.ThrowIfNull(leafCertificate);
        _ecdsa = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        _ownsKey = false;
        _presentation = presentation;
        Initialize(leafCertificate, issuerCertificates);
        ValidateKeyBinding(leafCertificate, privateKey);
        _chain = BuildChain(leafCertificate, issuerCertificates);
    }

    /// <summary>Gets the number of leaf-to-root certificates emitted on the wire.</summary>
    public int CertificateCount => _chain.Length;

    internal IReadOnlyList<byte[]> SnapshotCertificateChain()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _chain.Select(value => (byte[])value.Clone()).ToArray();
        }
    }

    internal byte[]? CopyStapledOcspResponse()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _presentation?.CopyOcspResponse();
        }
    }

    internal bool HasStapledOcspResponse
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _presentation?.HasOcspResponse == true;
            }
        }
    }

    internal bool HasSignedCertificateTimestamps
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _presentation?.HasSignedCertificateTimestamps == true;
            }
        }
    }

    internal byte[][] CopySignedCertificateTimestamps()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _presentation?.CopySignedCertificateTimestamps() ?? [];
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
                if (IsCompatible(scheme))
                {
                    return scheme;
                }
            }
            return null;
        }
    }

    internal byte[] SignTls13CertificateVerify(
        SignatureScheme scheme,
        ReadOnlySpan<byte> transcriptHash)
    {
        var content = BuildServerCertificateVerifyContent(transcriptHash);
        try
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                if (!IsCompatible(scheme))
                {
                    throw new InvalidOperationException(
                        $"Server credential cannot use {scheme}.");
                }
                var hash = TlsClientCertificate.GetHashAlgorithm(scheme);
                return _rsa is not null
                    ? _rsa.SignData(content, hash, RSASignaturePadding.Pss)
                    : _ecdsa!.SignData(
                        content,
                        hash,
                        DSASignatureFormat.Rfc3279DerSequence);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(content);
        }
    }

    internal SignatureScheme? SelectTls12SignatureScheme(
        IReadOnlyList<SignatureScheme> peerSchemes,
        Tls12CertificateKeyType requiredKeyType)
    {
        ArgumentNullException.ThrowIfNull(peerSchemes);
        lock (_sync)
        {
            ThrowIfDisposed();
            ValidateCurrentTime();
            foreach (var scheme in peerSchemes)
            {
                if (IsTls12Compatible(scheme, requiredKeyType))
                {
                    return scheme;
                }
            }
            return null;
        }
    }

    internal byte[] SignTls12ServerKeyExchange(
        SignatureScheme scheme,
        Tls12CertificateKeyType requiredKeyType,
        ReadOnlySpan<byte> signedContent)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!IsTls12Compatible(scheme, requiredKeyType))
            {
                throw new InvalidOperationException(
                    $"Server credential cannot use TLS 1.2 signature scheme {scheme}.");
            }
            var hash = TlsClientCertificate.GetHashAlgorithm(scheme);
            if (_rsa is not null)
            {
                var padding = scheme is
                    SignatureScheme.RsaPssRsaeSha256 or
                    SignatureScheme.RsaPssRsaeSha384 or
                    SignatureScheme.RsaPssRsaeSha512 or
                    SignatureScheme.RsaPssPssSha256 or
                    SignatureScheme.RsaPssPssSha384 or
                    SignatureScheme.RsaPssPssSha512
                        ? RSASignaturePadding.Pss
                        : RSASignaturePadding.Pkcs1;
                return _rsa.SignData(signedContent, hash, padding);
            }
            return _ecdsa!.SignData(
                signedContent,
                hash,
                DSASignatureFormat.Rfc3279DerSequence);
        }
    }

    internal static byte[] BuildServerCertificateVerifyContent(
        ReadOnlySpan<byte> transcriptHash)
    {
        var context = "TLS 1.3, server CertificateVerify"u8;
        var result = new byte[64 + context.Length + 1 + transcriptHash.Length];
        result.AsSpan(0, 64).Fill(0x20);
        context.CopyTo(result.AsSpan(64));
        transcriptHash.CopyTo(result.AsSpan(64 + context.Length + 1));
        return result;
    }

    private bool IsCompatible(SignatureScheme scheme) => scheme switch
    {
        SignatureScheme.RsaPssRsaeSha256 =>
            _rsa is not null && _rsaOid == RsaSignatureScheme.RsaEncryptionOid,
        SignatureScheme.RsaPssRsaeSha384 =>
            _rsa is not null && _rsaOid == RsaSignatureScheme.RsaEncryptionOid,
        SignatureScheme.RsaPssRsaeSha512 =>
            _rsa is not null && _rsaOid == RsaSignatureScheme.RsaEncryptionOid,
        SignatureScheme.RsaPssPssSha256 => _rsa is not null && _rsaPssSha256,
        SignatureScheme.RsaPssPssSha384 => _rsa is not null && _rsaPssSha384,
        SignatureScheme.RsaPssPssSha512 => _rsa is not null && _rsaPssSha512,
        SignatureScheme.EcdsaSecp256r1Sha256 => _ecdsa?.KeySize == 256,
        SignatureScheme.EcdsaSecp384r1Sha384 => _ecdsa?.KeySize == 384,
        SignatureScheme.EcdsaSecp521r1Sha512 => _ecdsa?.KeySize == 521,
        _ => false,
    };

    private bool IsTls12Compatible(
        SignatureScheme scheme,
        Tls12CertificateKeyType requiredKeyType)
    {
        if (requiredKeyType == Tls12CertificateKeyType.Ecdsa)
        {
            return _ecdsa is not null && scheme switch
            {
                SignatureScheme.EcdsaSecp256r1Sha256 => _ecdsa.KeySize == 256,
                SignatureScheme.EcdsaSecp384r1Sha384 => _ecdsa.KeySize == 384,
                SignatureScheme.EcdsaSecp521r1Sha512 => _ecdsa.KeySize == 521,
                _ => false,
            };
        }
        if (_rsa is null)
        {
            return false;
        }
        return scheme switch
        {
            SignatureScheme.RsaPssRsaeSha256 or
            SignatureScheme.RsaPssRsaeSha384 or
            SignatureScheme.RsaPssRsaeSha512 =>
                _rsaOid == RsaSignatureScheme.RsaEncryptionOid,
            SignatureScheme.RsaPssPssSha256 => _rsaPssSha256,
            SignatureScheme.RsaPssPssSha384 => _rsaPssSha384,
            SignatureScheme.RsaPssPssSha512 => _rsaPssSha512,
            SignatureScheme.RsaPkcs1Sha256 or
            SignatureScheme.RsaPkcs1Sha384 or
            SignatureScheme.RsaPkcs1Sha512 =>
                _rsaOid == RsaSignatureScheme.RsaEncryptionOid,
            _ => false,
        };
    }

    private static void ValidateLeaf(
        X509Certificate2 leaf,
        IEnumerable<X509Certificate2>? issuers)
    {
        _ = issuers;
        if (!leaf.HasPrivateKey && leaf.PublicKey.Oid?.Value is null)
        {
            throw new ArgumentException("Server leaf public key is unavailable.", nameof(leaf));
        }
        var now = DateTime.UtcNow;
        if (now < leaf.NotBefore.ToUniversalTime() || now > leaf.NotAfter.ToUniversalTime())
        {
            throw new ArgumentException("Server certificate is not currently valid.", nameof(leaf));
        }
        var basicConstraints = leaf.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        if (basicConstraints?.CertificateAuthority == true)
        {
            throw new ArgumentException("Server leaf cannot be a CA certificate.", nameof(leaf));
        }
        var keyUsage = leaf.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (keyUsage is not null &&
            (keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
        {
            throw new ArgumentException(
                "Server leaf lacks digitalSignature key usage.",
                nameof(leaf));
        }
        var eku = leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        if (eku is not null && !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid =>
            oid.Value is ServerAuthenticationOid or AnyExtendedKeyUsageOid))
        {
            throw new ArgumentException(
                "Server leaf lacks the serverAuth extended key usage.",
                nameof(leaf));
        }
    }

    private void Initialize(
        X509Certificate2 leaf,
        IEnumerable<X509Certificate2>? issuers)
    {
        ValidateLeaf(leaf, issuers);
        if ((_rsa is null) == (_ecdsa is null))
        {
            throw new ArgumentException(
                "Server leaf must use exactly one RSA or ECDSA private key.",
                nameof(leaf));
        }
        ValidateKeyBinding(leaf, _rsa as AsymmetricAlgorithm ?? _ecdsa!);
    }

    private static void ValidateKeyBinding(
        X509Certificate2 leaf,
        AsymmetricAlgorithm privateKey)
    {
        var privateSpki = privateKey.ExportSubjectPublicKeyInfo();
        var certificateSpki = leaf.PublicKey.ExportSubjectPublicKeyInfo();
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(privateSpki, certificateSpki))
            {
                throw new ArgumentException(
                    "Server private key does not match the leaf certificate.",
                    nameof(privateKey));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateSpki);
            CryptographicOperations.ZeroMemory(certificateSpki);
        }
    }

    private static (bool Sha256, bool Sha384, bool Sha512) GetRsaCapabilities(
        X509Certificate2 leaf,
        RSA? rsa)
    {
        if (rsa is null)
        {
            return default;
        }
        return (
            RsaSignatureScheme.ParametersPermit(leaf, HashAlgorithmName.SHA256),
            RsaSignatureScheme.ParametersPermit(leaf, HashAlgorithmName.SHA384),
            RsaSignatureScheme.ParametersPermit(leaf, HashAlgorithmName.SHA512));
    }

    private static byte[][] BuildChain(
        X509Certificate2 leaf,
        IEnumerable<X509Certificate2>? issuers)
    {
        var result = new List<byte[]> { leaf.RawData };
        if (issuers is not null)
        {
            foreach (var issuer in issuers)
            {
                ArgumentNullException.ThrowIfNull(issuer);
                if (result.Any(value => value.AsSpan().SequenceEqual(issuer.RawData)))
                {
                    throw new ArgumentException(
                        "Server certificate chain contains a duplicate.",
                        nameof(issuers));
                }
                result.Add(issuer.RawData);
            }
        }
        return [.. result];
    }

    private void ValidateCurrentTime()
    {
        using var leaf = X509CertificateLoader.LoadCertificate(_chain[0]);
        var now = DateTime.UtcNow;
        if (now < leaf.NotBefore.ToUniversalTime() || now > leaf.NotAfter.ToUniversalTime())
        {
            throw new InvalidOperationException("Server certificate is no longer valid.");
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

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
            if (_ownsKey)
            {
                _rsa?.Dispose();
                _ecdsa?.Dispose();
            }
            _rsa = null;
            _ecdsa = null;
        }
    }
}

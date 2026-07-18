using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls.Certificates;

/// <summary>
/// Holds a pre-issued RFC 9345 client delegated credential and its caller-owned
/// private-key signer. The credential is cryptographically validated when attached
/// to its delegation certificate.
/// </summary>
public sealed class TlsClientDelegatedCredential : IDisposable
{
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromDays(7);
    private readonly object _sync = new();
    private readonly SemaphoreSlim _signingGate = new(1, 1);
    private readonly ITlsClientCertificateSigner _signer;
    private readonly byte[] _encoded;
    private readonly byte[] _signedFields;
    private readonly byte[] _signature;
    private byte[]? _boundCertificateHash;
    private DateTimeOffset? _expiresAt;
    private bool _disposed;

    /// <summary>
    /// Creates a delegated credential from its complete RFC 9345 extension body.
    /// The signer must expose the exact public key encoded in the credential and
    /// support its fixed CertificateVerify algorithm. The caller retains signer ownership.
    /// </summary>
    public TlsClientDelegatedCredential(
        ReadOnlySpan<byte> encodedCredential,
        ITlsClientCertificateSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        if (encodedCredential.IsEmpty || encodedCredential.Length > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(encodedCredential));
        }

        try
        {
            var reader = new TlsBinaryReader(encodedCredential);
            ValidTimeSeconds = reader.ReadUInt32();
            var certificateVerifyValue = reader.ReadUInt16();
            var subjectPublicKeyInfo = reader.ReadVector24().ToArray();
            if (subjectPublicKeyInfo.Length == 0)
            {
                throw new ArgumentException(
                    "The delegated credential SubjectPublicKeyInfo is empty.",
                    nameof(encodedCredential));
            }
            var delegationValue = reader.ReadUInt16();
            var signedFieldsLength = encodedCredential.Length - reader.Remaining;
            var signature = reader.ReadVector16().ToArray();
            reader.EnsureEnd("client delegated credential");
            if (signature.Length == 0 ||
                !Enum.IsDefined(typeof(SignatureScheme), certificateVerifyValue) ||
                !Enum.IsDefined(typeof(SignatureScheme), delegationValue))
            {
                throw new ArgumentException(
                    "The delegated credential has an empty signature or unknown algorithm.",
                    nameof(encodedCredential));
            }

            CertificateVerifyAlgorithm = (SignatureScheme)certificateVerifyValue;
            DelegationSignatureAlgorithm = (SignatureScheme)delegationValue;
            if (!Tls13DelegatedCredentialParser.IsAllowedCredentialAlgorithm(
                    CertificateVerifyAlgorithm) ||
                !Tls13DelegatedCredentialParser.IsAllowedDelegationSignatureAlgorithm(
                    DelegationSignatureAlgorithm))
            {
                throw new NotSupportedException(
                    "The client delegated credential uses an unsupported signature algorithm.");
            }

            using var validatedPublicKey =
                Tls13DelegatedCredentialParser.ImportCredentialPublicKey(
                    CertificateVerifyAlgorithm,
                    subjectPublicKeyInfo);

            ArgumentNullException.ThrowIfNull(signer.SupportedSignatureSchemes);
            if (!signer.SupportedSignatureSchemes.Contains(CertificateVerifyAlgorithm))
            {
                throw new ArgumentException(
                    "The delegated signer does not support the credential's CertificateVerify algorithm.",
                    nameof(signer));
            }
            var signerSpki = signer.ExportSubjectPublicKeyInfo();
            ArgumentNullException.ThrowIfNull(signerSpki);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(
                    signerSpki,
                    subjectPublicKeyInfo))
                {
                    throw new ArgumentException(
                        "The delegated signer's public key does not match the encoded credential.",
                        nameof(signer));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signerSpki);
                CryptographicOperations.ZeroMemory(subjectPublicKeyInfo);
            }

            _signer = signer;
            _encoded = encodedCredential.ToArray();
            _signedFields = encodedCredential[..signedFieldsLength].ToArray();
            _signature = signature;
        }
        catch (TlsProtocolException exception)
        {
            throw new ArgumentException(
                "The encoded client delegated credential is malformed.",
                nameof(encodedCredential),
                exception);
        }
    }

    /// <summary>Gets the delegated key's fixed TLS CertificateVerify algorithm.</summary>
    public SignatureScheme CertificateVerifyAlgorithm { get; }

    /// <summary>Gets the delegation certificate signature algorithm embedded in the credential.</summary>
    public SignatureScheme DelegationSignatureAlgorithm { get; }

    /// <summary>Gets the encoded validity offset from the delegation certificate's notBefore.</summary>
    public uint ValidTimeSeconds { get; }

    /// <summary>Gets the validated expiry after attachment, or null before attachment.</summary>
    public DateTimeOffset? ExpiresAt
    {
        get
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                return _expiresAt;
            }
        }
    }

    internal void ValidateAndBind(X509Certificate2 delegationCertificate)
    {
        ArgumentNullException.ThrowIfNull(delegationCertificate);
        lock (_sync)
        {
            ThrowIfDisposed();
            Tls13DelegatedCredentialParser.ValidateDelegationCertificate(
                delegationCertificate);
            var certificateHash = SHA256.HashData(delegationCertificate.RawData);
            try
            {
                if (_boundCertificateHash is not null &&
                    !CryptographicOperations.FixedTimeEquals(
                        _boundCertificateHash,
                        certificateHash))
                {
                    throw new ArgumentException(
                        "The delegated credential is already bound to another certificate.",
                        nameof(delegationCertificate));
                }

                var notBefore = new DateTimeOffset(
                    delegationCertificate.NotBefore.ToUniversalTime());
                var notAfter = new DateTimeOffset(
                    delegationCertificate.NotAfter.ToUniversalTime());
                DateTimeOffset expiresAt;
                try
                {
                    expiresAt = notBefore.AddSeconds(ValidTimeSeconds);
                }
                catch (ArgumentOutOfRangeException exception)
                {
                    throw new ArgumentException(
                        "The delegated credential validity overflows the supported time range.",
                        nameof(delegationCertificate),
                        exception);
                }
                var now = DateTimeOffset.UtcNow;
                if (now > expiresAt || expiresAt > now.Add(MaximumLifetime) ||
                    expiresAt >= notAfter)
                {
                    throw new ArgumentException(
                        "The delegated credential is expired, exceeds seven days, or outlives its certificate.",
                        nameof(delegationCertificate));
                }

                var signedContent = Tls13DelegatedCredentialParser.BuildClientSignedContent(
                    delegationCertificate.RawData,
                    _signedFields);
                try
                {
                    if (!Tls13DelegatedCredentialParser.VerifyDelegationSignature(
                        delegationCertificate,
                        DelegationSignatureAlgorithm,
                        signedContent,
                        _signature))
                    {
                        throw new CryptographicException(
                            "The client delegated credential signature is invalid.");
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(signedContent);
                }

                _boundCertificateHash ??= certificateHash.ToArray();
                _expiresAt = expiresAt;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(certificateHash);
            }
        }
    }

    internal bool CanUse(
        IReadOnlyList<SignatureScheme> certificateRequestAlgorithms,
        IReadOnlyList<SignatureScheme>? delegatedCredentialAlgorithms)
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            return _boundCertificateHash is not null &&
                _expiresAt >= DateTimeOffset.UtcNow &&
                delegatedCredentialAlgorithms?.Contains(CertificateVerifyAlgorithm) == true &&
                certificateRequestAlgorithms.Contains(DelegationSignatureAlgorithm);
        }
    }

    internal byte[] CopyEncoded()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_boundCertificateHash is null)
            {
                throw new InvalidOperationException(
                    "The client delegated credential has not been attached to its certificate.");
            }
            return (byte[])_encoded.Clone();
        }
    }

    internal async ValueTask<byte[]> SignHashAsync(
        ReadOnlyMemory<byte> hash,
        CancellationToken cancellationToken)
    {
        var expectedLength = TlsClientCertificate.GetHashAlgorithm(
            CertificateVerifyAlgorithm).Name switch
        {
            "SHA256" => 32,
            "SHA384" => 48,
            "SHA512" => 64,
            _ => throw new NotSupportedException(),
        };
        if (hash.Length != expectedLength)
        {
            throw new ArgumentException(
                "The delegated CertificateVerify hash has the wrong length.",
                nameof(hash));
        }

        await _signingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var hashCopy = hash.ToArray();
        try
        {
            lock (_sync)
            {
                ThrowIfDisposed();
                if (_expiresAt < DateTimeOffset.UtcNow)
                {
                    throw new TlsProtocolException(
                        TlsAlertDescription.CertificateExpired,
                        "The client delegated credential expired before signing.");
                }
            }
            var signature = await _signer.SignHashAsync(
                CertificateVerifyAlgorithm,
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
                    "The delegated signer returned an invalid signature length.");
            }
            return signature;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hashCopy);
            _signingGate.Release();
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
            CryptographicOperations.ZeroMemory(_encoded);
            CryptographicOperations.ZeroMemory(_signedFields);
            CryptographicOperations.ZeroMemory(_signature);
            if (_boundCertificateHash is not null)
            {
                CryptographicOperations.ZeroMemory(_boundCertificateHash);
            }
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

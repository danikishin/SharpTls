using System.Security.Cryptography;
using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal sealed class EcdheKeyShare : IKeyShare
{
    private readonly ECDiffieHellman _key;
    private readonly ECCurve _curve;
    private readonly int _coordinateLength;
    private readonly byte[] _publicKey;
    private bool _disposed;
    private bool _agreementPerformed;

    private EcdheKeyShare(NamedGroup group, ECDiffieHellman key, ECCurve curve, int coordinateLength)
    {
        Group = group;
        _key = key;
        _curve = curve;
        _coordinateLength = coordinateLength;

        var parameters = key.ExportParameters(includePrivateParameters: false);
        if (parameters.Q.X is null || parameters.Q.Y is null ||
            parameters.Q.X.Length > coordinateLength || parameters.Q.Y.Length > coordinateLength)
        {
            key.Dispose();
            throw new CryptographicException("The ECDH provider returned an invalid public point.");
        }

        _publicKey = new byte[1 + (2 * coordinateLength)];
        _publicKey[0] = 4;
        parameters.Q.X.CopyTo(_publicKey.AsSpan(1 + coordinateLength - parameters.Q.X.Length));
        parameters.Q.Y.CopyTo(_publicKey.AsSpan(1 + (2 * coordinateLength) - parameters.Q.Y.Length));
    }

    public NamedGroup Group { get; }

    public ReadOnlyMemory<byte> PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    internal static EcdheKeyShare Create(NamedGroup group)
    {
        var (curve, coordinateLength) = group switch
        {
            NamedGroup.Secp256r1 => (ECCurve.NamedCurves.nistP256, 32),
            NamedGroup.Secp384r1 => (ECCurve.NamedCurves.nistP384, 48),
            NamedGroup.Secp521r1 => (ECCurve.NamedCurves.nistP521, 66),
            NamedGroup.X25519 => throw new NotSupportedException(
                "X25519 is not advertised because .NET 9 has no portable raw X25519 TLS primitive."),
            _ => throw new NotSupportedException($"Named group 0x{(ushort)group:X4} is not supported."),
        };

        return new EcdheKeyShare(group, ECDiffieHellman.Create(curve), curve, coordinateLength);
    }

    internal static EcdheKeyShare CreateDeterministicForTesting(NamedGroup group)
    {
        var (curve, coordinateLength, xHex, yHex) = group switch
        {
            NamedGroup.Secp256r1 => (
                ECCurve.NamedCurves.nistP256,
                32,
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            NamedGroup.Secp384r1 => (
                ECCurve.NamedCurves.nistP384,
                48,
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),
            NamedGroup.Secp521r1 => (
                ECCurve.NamedCurves.nistP521,
                66,
                "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
                "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
            _ => throw new NotSupportedException($"Named group {group} is not supported."),
        };

        var d = new byte[coordinateLength];
        d[^1] = 1;
        var key = ECDiffieHellman.Create(new ECParameters
        {
            Curve = curve,
            D = d,
            Q = new ECPoint
            {
                X = Convert.FromHexString(xHex),
                Y = Convert.FromHexString(yHex),
            },
        });
        CryptographicOperations.ZeroMemory(d);
        return new EcdheKeyShare(group, key, curve, coordinateLength);
    }

    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerKeyExchange)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_agreementPerformed)
        {
            throw new InvalidOperationException("A key share can perform agreement only once.");
        }

        if (peerKeyExchange.Length != 1 + (2 * _coordinateLength) || peerKeyExchange[0] != 4)
        {
            throw TlsProtocolException.Illegal(
                $"Invalid {Group} uncompressed point encoding length or format.");
        }

        var x = peerKeyExchange.Slice(1, _coordinateLength).ToArray();
        var y = peerKeyExchange.Slice(1 + _coordinateLength, _coordinateLength).ToArray();
        try
        {
            using var peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = _curve,
                Q = new ECPoint { X = x, Y = y },
            });

            var secret = _key.DeriveRawSecretAgreement(peer.PublicKey);
            if (secret.Length != _coordinateLength)
            {
                CryptographicOperations.ZeroMemory(secret);
                throw new CryptographicException("The ECDH provider returned a non-canonical secret length.");
            }

            _agreementPerformed = true;
            return secret;
        }
        catch (TlsProtocolException)
        {
            throw;
        }
        catch (Exception exception) when (exception is
            CryptographicException or
            PlatformNotSupportedException or
            ArgumentException)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                $"The peer {Group} public point is invalid.",
                exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(x);
            CryptographicOperations.ZeroMemory(y);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _key.Dispose();
        CryptographicOperations.ZeroMemory(_publicKey);
    }
}

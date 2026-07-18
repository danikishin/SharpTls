// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license documented in
// THIRD-PARTY-NOTICES.md. Ported to C# and adapted to .NET SHA-3/SHAKE primitives.

using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SharpTls.Cryptography;

/// <summary>
/// Managed FIPS 203 ML-KEM-768. All secret-dependent polynomial operations and
/// implicit-rejection selection are branch-free with respect to secret values.
/// </summary>
internal static partial class MlKem768
{
    private const int K = 3;

    internal const int SharedSecretSize = 32;
    internal const int SeedSize = 64;
    internal const int EncapsulationKeySize = K * EncodingSize12 + 32;
    internal const int CiphertextSize = K * EncodingSize10 + EncodingSize4;

    internal static bool IsSupported =>
        true;

    internal readonly record struct Encapsulation(byte[] SharedSecret, byte[] Ciphertext);

    internal sealed class KeyPair : IDisposable
    {
        private readonly byte[] _d;
        private readonly byte[] _z;
        private readonly byte[] _rho;
        private readonly byte[] _publicKeyHash;
        private readonly ushort[][] _t;
        private readonly ushort[][] _a;
        private readonly ushort[][] _s;
        private bool _disposed;

        internal KeyPair(
            byte[] d,
            byte[] z,
            byte[] rho,
            byte[] publicKeyHash,
            ushort[][] t,
            ushort[][] a,
            ushort[][] s)
        {
            _d = d;
            _z = z;
            _rho = rho;
            _publicKeyHash = publicKeyHash;
            _t = t;
            _a = a;
            _s = s;
        }

        internal byte[] ExportEncapsulationKey()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return EncodeEncapsulationKey(_t, _rho);
        }

        internal byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (ciphertext.Length != CiphertextSize)
            {
                throw new CryptographicException("ML-KEM-768 ciphertext has an invalid length.");
            }

            var message = PkeDecrypt(_s, ciphertext);
            byte[]? gInput = null;
            byte[]? g = null;
            byte[]? rejectionInput = null;
            byte[]? rejectedSecret = null;
            byte[]? reencryption = null;
            try
            {
                gInput = new byte[64];
                message.CopyTo(gInput, 0);
                _publicKeyHash.CopyTo(gInput, 32);
                g = Fips202.Sha3_512(gInput);

                rejectionInput = new byte[checked(_z.Length + ciphertext.Length)];
                _z.CopyTo(rejectionInput, 0);
                ciphertext.CopyTo(rejectionInput.AsSpan(_z.Length));
                rejectedSecret = Fips202.Shake256(rejectionInput, SharedSecretSize);

                reencryption = PkeEncrypt(_t, _a, message, g.AsSpan(SharedSecretSize));
                ConstantTimeSelect(
                    rejectedSecret,
                    g.AsSpan(0, SharedSecretSize),
                    ciphertext,
                    reencryption);
                return rejectedSecret;
            }
            catch
            {
                if (rejectedSecret is not null)
                {
                    CryptographicOperations.ZeroMemory(rejectedSecret);
                }
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(message);
                Zero(gInput);
                Zero(g);
                Zero(rejectionInput);
                Zero(reencryption);
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            CryptographicOperations.ZeroMemory(_d);
            CryptographicOperations.ZeroMemory(_z);
            CryptographicOperations.ZeroMemory(_rho);
            CryptographicOperations.ZeroMemory(_publicKeyHash);
            ZeroPolynomials(_t);
            ZeroPolynomials(_a);
            ZeroPolynomials(_s);
        }
    }

    private sealed class ParsedEncapsulationKey : IDisposable
    {
        internal ParsedEncapsulationKey(
            byte[] rho,
            byte[] hash,
            ushort[][] t,
            ushort[][] a)
        {
            Rho = rho;
            Hash = hash;
            T = t;
            A = a;
        }

        internal byte[] Rho { get; }
        internal byte[] Hash { get; }
        internal ushort[][] T { get; }
        internal ushort[][] A { get; }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Rho);
            CryptographicOperations.ZeroMemory(Hash);
            ZeroPolynomials(T);
            ZeroPolynomials(A);
        }
    }

    internal static KeyPair GenerateKey()
    {
        var seed = RandomNumberGenerator.GetBytes(SeedSize);
        try
        {
            var result = GenerateKeyCore(seed);
            PairwiseConsistencyTest(result);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    internal static KeyPair GenerateKeyDeterministicForTesting(ReadOnlySpan<byte> seed)
    {
        return GenerateKeyCore(seed);
    }

    internal static Encapsulation Encapsulate(ReadOnlySpan<byte> encapsulationKey)
    {
        var message = RandomNumberGenerator.GetBytes(SharedSecretSize);
        try
        {
            return EncapsulateDeterministicForTesting(encapsulationKey, message);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(message);
        }
    }

    internal static Encapsulation EncapsulateDeterministicForTesting(
        ReadOnlySpan<byte> encapsulationKey,
        ReadOnlySpan<byte> message)
    {
        if (message.Length != SharedSecretSize)
        {
            throw new ArgumentOutOfRangeException(nameof(message));
        }

        using var parsed = ParseEncapsulationKey(encapsulationKey);
        byte[]? gInput = null;
        byte[]? g = null;
        byte[]? ciphertext = null;
        try
        {
            gInput = new byte[64];
            message.CopyTo(gInput);
            parsed.Hash.CopyTo(gInput, 32);
            g = Fips202.Sha3_512(gInput);
            ciphertext = PkeEncrypt(
                parsed.T,
                parsed.A,
                message,
                g.AsSpan(SharedSecretSize));
            var sharedSecret = g.AsSpan(0, SharedSecretSize).ToArray();
            return new Encapsulation(sharedSecret, ciphertext);
        }
        catch
        {
            Zero(ciphertext);
            throw;
        }
        finally
        {
            Zero(gInput);
            Zero(g);
        }
    }

    private static KeyPair GenerateKeyCore(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedSize)
        {
            throw new ArgumentOutOfRangeException(nameof(seed));
        }

        var d = seed[..32].ToArray();
        var z = seed[32..].ToArray();
        byte[]? gInput = null;
        byte[]? expanded = null;
        byte[]? rho = null;
        byte[]? sigma = null;
        ushort[][]? a = null;
        ushort[][]? s = null;
        ushort[][]? t = null;
        ushort[][]? errors = null;
        byte[]? publicKeyHash = null;
        try
        {
            gInput = new byte[33];
            d.CopyTo(gInput, 0);
            gInput[^1] = K;
            expanded = Fips202.Sha3_512(gInput);
            rho = expanded[..32].ToArray();
            sigma = expanded[32..].ToArray();

            a = CreatePolynomialMatrix(K * K);
            for (byte row = 0; row < K; row++)
            {
                for (byte column = 0; column < K; column++)
                {
                    a[row * K + column] = SampleNtt(rho, column, row);
                }
            }

            byte nonce = 0;
            s = CreatePolynomialMatrix(K);
            for (var index = 0; index < K; index++)
            {
                var sampled = SamplePolyCbd(sigma, nonce++);
                s[index] = Ntt(sampled);
                ZeroPolynomial(sampled);
            }

            errors = CreatePolynomialMatrix(K);
            for (var index = 0; index < K; index++)
            {
                var sampled = SamplePolyCbd(sigma, nonce++);
                errors[index] = Ntt(sampled);
                ZeroPolynomial(sampled);
            }

            t = CreatePolynomialMatrix(K);
            for (var row = 0; row < K; row++)
            {
                t[row] = (ushort[])errors[row].Clone();
                for (var column = 0; column < K; column++)
                {
                    var product = NttMultiply(a[row * K + column], s[column]);
                    var sum = PolyAdd(t[row], product);
                    ZeroPolynomial(t[row]);
                    ZeroPolynomial(product);
                    t[row] = sum;
                }
            }

            var publicKey = EncodeEncapsulationKey(t, rho);
            try
            {
                publicKeyHash = Fips202.Sha3_256(publicKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }

            var result = new KeyPair(d, z, rho, publicKeyHash, t, a, s);
            d = null!;
            z = null!;
            rho = null;
            publicKeyHash = null;
            t = null;
            a = null;
            s = null;
            return result;
        }
        finally
        {
            Zero(d);
            Zero(z);
            Zero(gInput);
            Zero(expanded);
            Zero(rho);
            Zero(sigma);
            Zero(publicKeyHash);
            if (a is not null)
            {
                ZeroPolynomials(a);
            }
            if (s is not null)
            {
                ZeroPolynomials(s);
            }
            if (t is not null)
            {
                ZeroPolynomials(t);
            }
            if (errors is not null)
            {
                ZeroPolynomials(errors);
            }
        }
    }

    private static ParsedEncapsulationKey ParseEncapsulationKey(
        ReadOnlySpan<byte> encapsulationKey)
    {
        if (encapsulationKey.Length != EncapsulationKeySize)
        {
            throw new CryptographicException("ML-KEM-768 encapsulation key has an invalid length.");
        }
        var hash = Fips202.Sha3_256(encapsulationKey);
        var rho = encapsulationKey[^32..].ToArray();
        var t = CreatePolynomialMatrix(K);
        var a = CreatePolynomialMatrix(K * K);
        try
        {
            for (var index = 0; index < K; index++)
            {
                t[index] = DecodePolynomial12(
                    encapsulationKey.Slice(index * EncodingSize12, EncodingSize12));
            }
            for (byte row = 0; row < K; row++)
            {
                for (byte column = 0; column < K; column++)
                {
                    a[row * K + column] = SampleNtt(rho, column, row);
                }
            }
            return new ParsedEncapsulationKey(rho, hash, t, a);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(rho);
            ZeroPolynomials(t);
            ZeroPolynomials(a);
            throw;
        }
    }

    private static byte[] PkeEncrypt(
        IReadOnlyList<ushort[]> t,
        IReadOnlyList<ushort[]> a,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> randomness)
    {
        if (message.Length != SharedSecretSize || randomness.Length != SharedSecretSize)
        {
            throw new ArgumentOutOfRangeException(nameof(message));
        }

        var r = CreatePolynomialMatrix(K);
        var e1 = CreatePolynomialMatrix(K);
        ushort[]? e2 = null;
        ushort[][]? u = null;
        ushort[]? mu = null;
        ushort[]? vNtt = null;
        ushort[]? v = null;
        try
        {
            byte nonce = 0;
            for (var index = 0; index < K; index++)
            {
                var sampled = SamplePolyCbd(randomness, nonce++);
                r[index] = Ntt(sampled);
                ZeroPolynomial(sampled);
            }
            for (var index = 0; index < K; index++)
            {
                e1[index] = SamplePolyCbd(randomness, nonce++);
            }
            e2 = SamplePolyCbd(randomness, nonce);

            u = CreatePolynomialMatrix(K);
            for (var row = 0; row < K; row++)
            {
                u[row] = (ushort[])e1[row].Clone();
                for (var column = 0; column < K; column++)
                {
                    var productNtt = NttMultiply(a[column * K + row], r[column]);
                    var product = InverseNtt(productNtt);
                    var sum = PolyAdd(u[row], product);
                    ZeroPolynomial(productNtt);
                    ZeroPolynomial(product);
                    ZeroPolynomial(u[row]);
                    u[row] = sum;
                }
            }

            mu = DecodeAndDecompress1(message);
            vNtt = new ushort[N];
            for (var index = 0; index < K; index++)
            {
                var product = NttMultiply(t[index], r[index]);
                var sum = PolyAdd(vNtt, product);
                ZeroPolynomial(product);
                ZeroPolynomial(vNtt);
                vNtt = sum;
            }
            var inverse = InverseNtt(vNtt);
            var noisy = PolyAdd(inverse, e2);
            v = PolyAdd(noisy, mu);
            ZeroPolynomial(inverse);
            ZeroPolynomial(noisy);

            var ciphertext = new byte[CiphertextSize];
            for (var index = 0; index < K; index++)
            {
                CompressAndEncode10(
                    u[index],
                    ciphertext.AsSpan(index * EncodingSize10, EncodingSize10));
            }
            CompressAndEncode4(v, ciphertext.AsSpan(K * EncodingSize10, EncodingSize4));
            return ciphertext;
        }
        finally
        {
            ZeroPolynomials(r);
            ZeroPolynomials(e1);
            Zero(e2);
            if (u is not null)
            {
                ZeroPolynomials(u);
            }
            Zero(mu);
            Zero(vNtt);
            Zero(v);
        }
    }

    private static byte[] PkeDecrypt(
        IReadOnlyList<ushort[]> s,
        ReadOnlySpan<byte> ciphertext)
    {
        var u = CreatePolynomialMatrix(K);
        ushort[]? v = null;
        ushort[]? mask = null;
        ushort[]? w = null;
        try
        {
            for (var index = 0; index < K; index++)
            {
                u[index] = DecodeAndDecompress10(
                    ciphertext.Slice(index * EncodingSize10, EncodingSize10));
            }
            v = DecodeAndDecompress4(ciphertext.Slice(K * EncodingSize10, EncodingSize4));
            mask = new ushort[N];
            for (var index = 0; index < K; index++)
            {
                var transformed = Ntt(u[index]);
                var product = NttMultiply(s[index], transformed);
                var sum = PolyAdd(mask, product);
                ZeroPolynomial(transformed);
                ZeroPolynomial(product);
                ZeroPolynomial(mask);
                mask = sum;
            }
            var inverse = InverseNtt(mask);
            w = PolySubtract(v, inverse);
            ZeroPolynomial(inverse);
            return CompressAndEncode1(w);
        }
        finally
        {
            ZeroPolynomials(u);
            Zero(v);
            Zero(mask);
            Zero(w);
        }
    }

    private static byte[] EncodeEncapsulationKey(
        IReadOnlyList<ushort[]> t,
        ReadOnlySpan<byte> rho)
    {
        var result = new byte[EncapsulationKeySize];
        for (var index = 0; index < K; index++)
        {
            EncodePolynomial12(
                t[index],
                result.AsSpan(index * EncodingSize12, EncodingSize12));
        }
        rho.CopyTo(result.AsSpan(K * EncodingSize12));
        return result;
    }

    private static ushort[][] CreatePolynomialMatrix(int count)
    {
        var result = new ushort[count][];
        for (var index = 0; index < count; index++)
        {
            result[index] = new ushort[N];
        }
        return result;
    }

    private static void PairwiseConsistencyTest(KeyPair keyPair)
    {
        var publicKey = keyPair.ExportEncapsulationKey();
        var message = Fips202.Sha3_256(publicKey);
        Encapsulation encapsulation = default;
        byte[]? decapsulated = null;
        try
        {
            encapsulation = EncapsulateDeterministicForTesting(publicKey, message);
            decapsulated = keyPair.Decapsulate(encapsulation.Ciphertext);
            if (!CryptographicOperations.FixedTimeEquals(
                encapsulation.SharedSecret,
                decapsulated))
            {
                throw new CryptographicException("ML-KEM-768 pairwise consistency test failed.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(message);
            Zero(encapsulation.SharedSecret);
            Zero(encapsulation.Ciphertext);
            Zero(decapsulated);
        }
    }

    private static void ConstantTimeSelect(
        Span<byte> destination,
        ReadOnlySpan<byte> validValue,
        ReadOnlySpan<byte> receivedCiphertext,
        ReadOnlySpan<byte> expectedCiphertext)
    {
        uint difference = 0;
        for (var index = 0; index < receivedCiphertext.Length; index++)
        {
            difference |= (uint)(receivedCiphertext[index] ^ expectedCiphertext[index]);
        }
        var equal = (difference - 1) >> 31;
        var mask = unchecked((byte)(0u - equal));
        for (var index = 0; index < destination.Length; index++)
        {
            destination[index] = (byte)((destination[index] & ~mask) |
                (validValue[index] & mask));
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(value);
        }
    }

    private static void Zero(ushort[]? value)
    {
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(value.AsSpan()));
        }
    }

    private static void ZeroPolynomial(ushort[] value) => Zero(value);
}

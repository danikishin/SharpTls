// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license documented in
// THIRD-PARTY-NOTICES.md. Ported to C# and adapted to .NET SHA-3/SHAKE primitives.

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SharpTls.Cryptography;

/// <summary>FIPS 203 ML-KEM-768 field, encoding, sampling and NTT primitives.</summary>
internal static partial class MlKem768
{
    private const int N = 256;
    private const int Q = 3329;
    private const int EncodingSize12 = N * 12 / 8;
    private const int EncodingSize10 = N * 10 / 8;
    private const int EncodingSize4 = N * 4 / 8;
    private const int EncodingSize1 = N / 8;

    private const uint BarrettMultiplier = 5039;
    private const int BarrettShift = 24;

    private static readonly ushort[] Gammas =
    [
        17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606,
        2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096,
        756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678,
        2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
        939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992,
        268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109,
        375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010,
        2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735,
        2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179,
        2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300,
        2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
    ];

    private static readonly ushort[] Zetas =
    [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797,
        2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
        1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756,
        1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
        2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100,
        1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789,
        1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757,
        2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
        1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
    ];

    private static ushort CheckReduced(ushort value)
    {
        if (value >= Q)
        {
            throw new CryptographicException("ML-KEM polynomial encoding is not reduced.");
        }
        return value;
    }

    private static ushort ReduceOnce(ushort value)
    {
        var reduced = unchecked((ushort)(value - Q));
        reduced = unchecked((ushort)(reduced + (reduced >> 15) * Q));
        return reduced;
    }

    private static ushort Add(ushort left, ushort right) =>
        ReduceOnce(unchecked((ushort)(left + right)));

    private static ushort Subtract(ushort left, ushort right) =>
        ReduceOnce(unchecked((ushort)(left - right + Q)));

    private static ushort Reduce(uint value)
    {
        var quotient = (uint)(((ulong)value * BarrettMultiplier) >> BarrettShift);
        return ReduceOnce(unchecked((ushort)(value - quotient * Q)));
    }

    private static ushort Multiply(ushort left, ushort right) =>
        Reduce((uint)left * right);

    private static ushort MultiplySubtract(ushort a, ushort b, ushort c) =>
        Reduce((uint)a * unchecked((ushort)(b - c + Q)));

    private static ushort AddProducts(ushort a, ushort b, ushort c, ushort d) =>
        Reduce((uint)a * b + (uint)c * d);

    private static ushort Compress(ushort value, int bits)
    {
        var dividend = (uint)value << bits;
        var quotient = (uint)(((ulong)dividend * BarrettMultiplier) >> BarrettShift);
        var remainder = dividend - quotient * Q;
        quotient += unchecked((uint)(Q / 2) - remainder) >> 31 & 1;
        quotient += unchecked((uint)(Q + Q / 2) - remainder) >> 31 & 1;
        return (ushort)(quotient & ((1u << bits) - 1));
    }

    private static ushort Decompress(ushort value, int bits)
    {
        var dividend = (uint)value * Q;
        var quotient = dividend >> bits;
        quotient += dividend >> (bits - 1) & 1;
        return (ushort)quotient;
    }

    private static ushort[] PolyAdd(ReadOnlySpan<ushort> left, ReadOnlySpan<ushort> right)
    {
        var result = new ushort[N];
        for (var index = 0; index < N; index++)
        {
            result[index] = Add(left[index], right[index]);
        }
        return result;
    }

    private static ushort[] PolySubtract(ReadOnlySpan<ushort> left, ReadOnlySpan<ushort> right)
    {
        var result = new ushort[N];
        for (var index = 0; index < N; index++)
        {
            result[index] = Subtract(left[index], right[index]);
        }
        return result;
    }

    private static void EncodePolynomial12(ReadOnlySpan<ushort> polynomial, Span<byte> destination)
    {
        if (destination.Length != EncodingSize12)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }
        for (var index = 0; index < N; index += 2)
        {
            var value = (uint)polynomial[index] | (uint)polynomial[index + 1] << 12;
            var offset = index / 2 * 3;
            destination[offset] = (byte)value;
            destination[offset + 1] = (byte)(value >> 8);
            destination[offset + 2] = (byte)(value >> 16);
        }
    }

    private static ushort[] DecodePolynomial12(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodingSize12)
        {
            throw new ArgumentOutOfRangeException(nameof(encoded));
        }
        var result = new ushort[N];
        for (var index = 0; index < N; index += 2)
        {
            var offset = index / 2 * 3;
            var value = (uint)encoded[offset] |
                (uint)encoded[offset + 1] << 8 |
                (uint)encoded[offset + 2] << 16;
            result[index] = CheckReduced((ushort)(value & 0x0FFF));
            result[index + 1] = CheckReduced((ushort)(value >> 12));
        }
        return result;
    }

    private static byte[] CompressAndEncode1(ReadOnlySpan<ushort> polynomial)
    {
        var result = new byte[EncodingSize1];
        for (var index = 0; index < N; index++)
        {
            result[index / 8] |= (byte)(Compress(polynomial[index], 1) << (index % 8));
        }
        return result;
    }

    private static ushort[] DecodeAndDecompress1(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodingSize1)
        {
            throw new ArgumentOutOfRangeException(nameof(encoded));
        }
        var result = new ushort[N];
        for (var index = 0; index < N; index++)
        {
            var bit = (encoded[index / 8] >> (index % 8)) & 1;
            result[index] = (ushort)(bit * ((Q + 1) / 2));
        }
        return result;
    }

    private static void CompressAndEncode4(ReadOnlySpan<ushort> polynomial, Span<byte> destination)
    {
        if (destination.Length != EncodingSize4)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }
        for (var index = 0; index < N; index += 2)
        {
            destination[index / 2] = (byte)(Compress(polynomial[index], 4) |
                Compress(polynomial[index + 1], 4) << 4);
        }
    }

    private static ushort[] DecodeAndDecompress4(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodingSize4)
        {
            throw new ArgumentOutOfRangeException(nameof(encoded));
        }
        var result = new ushort[N];
        for (var index = 0; index < N; index += 2)
        {
            result[index] = Decompress((ushort)(encoded[index / 2] & 0x0F), 4);
            result[index + 1] = Decompress((ushort)(encoded[index / 2] >> 4), 4);
        }
        return result;
    }

    private static void CompressAndEncode10(ReadOnlySpan<ushort> polynomial, Span<byte> destination)
    {
        if (destination.Length != EncodingSize10)
        {
            throw new ArgumentOutOfRangeException(nameof(destination));
        }
        for (var index = 0; index < N; index += 4)
        {
            ulong value = Compress(polynomial[index], 10);
            value |= (ulong)Compress(polynomial[index + 1], 10) << 10;
            value |= (ulong)Compress(polynomial[index + 2], 10) << 20;
            value |= (ulong)Compress(polynomial[index + 3], 10) << 30;
            var offset = index / 4 * 5;
            destination[offset] = (byte)value;
            destination[offset + 1] = (byte)(value >> 8);
            destination[offset + 2] = (byte)(value >> 16);
            destination[offset + 3] = (byte)(value >> 24);
            destination[offset + 4] = (byte)(value >> 32);
        }
    }

    private static ushort[] DecodeAndDecompress10(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodingSize10)
        {
            throw new ArgumentOutOfRangeException(nameof(encoded));
        }
        var result = new ushort[N];
        for (var index = 0; index < N; index += 4)
        {
            var offset = index / 4 * 5;
            var value = (ulong)encoded[offset] |
                (ulong)encoded[offset + 1] << 8 |
                (ulong)encoded[offset + 2] << 16 |
                (ulong)encoded[offset + 3] << 24 |
                (ulong)encoded[offset + 4] << 32;
            result[index] = Decompress((ushort)(value & 0x03FF), 10);
            result[index + 1] = Decompress((ushort)(value >> 10 & 0x03FF), 10);
            result[index + 2] = Decompress((ushort)(value >> 20 & 0x03FF), 10);
            result[index + 3] = Decompress((ushort)(value >> 30 & 0x03FF), 10);
        }
        return result;
    }

    private static ushort[] SamplePolyCbd(ReadOnlySpan<byte> seed, byte nonce)
    {
        Span<byte> input = stackalloc byte[seed.Length + 1];
        seed.CopyTo(input);
        input[^1] = nonce;
        Span<byte> random = stackalloc byte[128];
        Fips202.Shake256(input, random);
        var result = new ushort[N];
        for (var index = 0; index < N; index += 2)
        {
            var value = random[index / 2];
            var b7 = value >> 7;
            var b6 = value >> 6 & 1;
            var b5 = value >> 5 & 1;
            var b4 = value >> 4 & 1;
            var b3 = value >> 3 & 1;
            var b2 = value >> 2 & 1;
            var b1 = value >> 1 & 1;
            var b0 = value & 1;
            result[index] = Subtract((ushort)(b0 + b1), (ushort)(b2 + b3));
            result[index + 1] = Subtract((ushort)(b4 + b5), (ushort)(b6 + b7));
        }
        CryptographicOperations.ZeroMemory(random);
        return result;
    }

    private static ushort[] NttMultiply(ReadOnlySpan<ushort> left, ReadOnlySpan<ushort> right)
    {
        var result = new ushort[N];
        for (var index = 0; index < N; index += 2)
        {
            var a0 = left[index];
            var a1 = left[index + 1];
            var b0 = right[index];
            var b1 = right[index + 1];
            result[index] = AddProducts(a0, b0, Multiply(a1, b1), Gammas[index / 2]);
            result[index + 1] = AddProducts(a0, b1, a1, b0);
        }
        return result;
    }

    private static ushort[] Ntt(ReadOnlySpan<ushort> polynomial)
    {
        var result = polynomial.ToArray();
        var k = 1;
        for (var length = 128; length >= 2; length /= 2)
        {
            for (var start = 0; start < N; start += 2 * length)
            {
                var zeta = Zetas[k++];
                for (var offset = 0; offset < length; offset++)
                {
                    var first = start + offset;
                    var second = first + length;
                    var value = Multiply(zeta, result[second]);
                    result[second] = Subtract(result[first], value);
                    result[first] = Add(result[first], value);
                }
            }
        }
        return result;
    }

    private static ushort[] InverseNtt(ReadOnlySpan<ushort> polynomial)
    {
        var result = polynomial.ToArray();
        var k = 127;
        for (var length = 2; length <= 128; length *= 2)
        {
            for (var start = 0; start < N; start += 2 * length)
            {
                var zeta = Zetas[k--];
                for (var offset = 0; offset < length; offset++)
                {
                    var first = start + offset;
                    var second = first + length;
                    var value = result[first];
                    result[first] = Add(value, result[second]);
                    result[second] = MultiplySubtract(zeta, result[second], value);
                }
            }
        }
        for (var index = 0; index < N; index++)
        {
            result[index] = Multiply(result[index], 3303);
        }
        return result;
    }

    private static ushort[] SampleNtt(ReadOnlySpan<byte> rho, byte first, byte second)
    {
        using var shake = Fips202.CreateShake128();
        shake.AppendData(rho);
        Span<byte> domain = stackalloc byte[] { first, second };
        shake.AppendData(domain);
        var result = new ushort[N];
        Span<byte> buffer = stackalloc byte[24];
        var index = 0;
        while (index < result.Length)
        {
            shake.Read(buffer);
            for (var offset = 0; offset < buffer.Length && index < result.Length; offset += 3)
            {
                var d1 = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(buffer[offset..]) & 0x0FFF);
                var d2 = (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(buffer[(offset + 1)..]) >> 4);
                if (d1 < Q)
                {
                    result[index++] = d1;
                }
                if (index < result.Length && d2 < Q)
                {
                    result[index++] = d2;
                }
            }
        }
        return result;
    }

    private static void ZeroPolynomials(IEnumerable<ushort[]> polynomials)
    {
        foreach (var polynomial in polynomials)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(polynomial.AsSpan()));
        }
    }
}

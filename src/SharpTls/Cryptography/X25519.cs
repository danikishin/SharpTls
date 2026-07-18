using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SharpTls.Cryptography;

/// <summary>
/// Managed RFC 7748 X25519 implementation for runtimes without a portable raw-X25519 API.
/// Field arithmetic uses five 51-bit limbs and UInt128 intermediates. The Montgomery ladder
/// always executes 255 iterations and its swaps do not branch on scalar bits.
/// </summary>
internal static class X25519
{
    internal const int KeyLength = 32;

    private const ulong LimbMask = (1UL << 51) - 1;
    private const ulong LimbBase = 1UL << 51;
    private const ulong PrimeLimb0 = LimbMask - 18;
    private const ulong MontgomeryA24 = 121665;

    internal static void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
    {
        Span<byte> basePoint = stackalloc byte[KeyLength];
        basePoint[0] = 9;
        ScalarMultiply(privateKey, basePoint, publicKey);
        CryptographicOperations.ZeroMemory(basePoint);
    }

    internal static void ScalarMultiply(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerUCoordinate,
        Span<byte> result)
    {
        if (privateKey.Length != KeyLength)
        {
            throw new ArgumentException("An X25519 private key must contain exactly 32 bytes.", nameof(privateKey));
        }
        if (peerUCoordinate.Length != KeyLength)
        {
            throw new ArgumentException("An X25519 u-coordinate must contain exactly 32 bytes.", nameof(peerUCoordinate));
        }
        if (result.Length < KeyLength)
        {
            throw new ArgumentException("The X25519 result buffer must contain at least 32 bytes.", nameof(result));
        }

        Span<byte> scalar = stackalloc byte[KeyLength];
        privateKey.CopyTo(scalar);
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;

        var x1 = FieldElement.Decode(peerUCoordinate);
        var x2 = FieldElement.One;
        var z2 = FieldElement.Zero;
        var x3 = x1;
        var z3 = FieldElement.One;
        ulong swap = 0;

        for (var position = 254; position >= 0; position--)
        {
            var scalarBit = (ulong)((scalar[position >> 3] >> (position & 7)) & 1);
            swap ^= scalarBit;
            FieldElement.ConditionalSwap(ref x2, ref x3, swap);
            FieldElement.ConditionalSwap(ref z2, ref z3, swap);
            swap = scalarBit;

            var a = FieldElement.Add(x2, z2);
            var aa = FieldElement.Square(a);
            var b = FieldElement.Subtract(x2, z2);
            var bb = FieldElement.Square(b);
            var e = FieldElement.Subtract(aa, bb);
            var c = FieldElement.Add(x3, z3);
            var d = FieldElement.Subtract(x3, z3);
            var da = FieldElement.Multiply(d, a);
            var cb = FieldElement.Multiply(c, b);
            x3 = FieldElement.Square(FieldElement.Add(da, cb));
            z3 = FieldElement.Multiply(x1, FieldElement.Square(FieldElement.Subtract(da, cb)));
            x2 = FieldElement.Multiply(aa, bb);
            z2 = FieldElement.Multiply(
                e,
                FieldElement.Add(aa, FieldElement.Multiply(e, FieldElement.FromUInt64(MontgomeryA24))));
        }

        FieldElement.ConditionalSwap(ref x2, ref x3, swap);
        FieldElement.ConditionalSwap(ref z2, ref z3, swap);
        FieldElement.Encode(FieldElement.Multiply(x2, FieldElement.Invert(z2)), result);
        CryptographicOperations.ZeroMemory(scalar);
    }

    private struct FieldElement
    {
        internal ulong L0;
        internal ulong L1;
        internal ulong L2;
        internal ulong L3;
        internal ulong L4;

        internal FieldElement(ulong l0, ulong l1, ulong l2, ulong l3, ulong l4)
        {
            L0 = l0;
            L1 = l1;
            L2 = l2;
            L3 = l3;
            L4 = l4;
        }

        internal static FieldElement Zero => default;

        internal static FieldElement One => new(1, 0, 0, 0, 0);

        internal static FieldElement FromUInt64(ulong value) => new(value, 0, 0, 0, 0);

        internal static FieldElement Decode(ReadOnlySpan<byte> encoded) => new(
            BinaryPrimitives.ReadUInt64LittleEndian(encoded) & LimbMask,
            (BinaryPrimitives.ReadUInt64LittleEndian(encoded[6..]) >> 3) & LimbMask,
            (BinaryPrimitives.ReadUInt64LittleEndian(encoded[12..]) >> 6) & LimbMask,
            (BinaryPrimitives.ReadUInt64LittleEndian(encoded[19..]) >> 1) & LimbMask,
            (BinaryPrimitives.ReadUInt64LittleEndian(encoded[24..]) >> 12) & LimbMask);

        internal static void Encode(FieldElement value, Span<byte> destination)
        {
            value = Canonicalize(value);
            destination[..KeyLength].Clear();

            WriteLimbBits(value.L0, 0, destination);
            WriteLimbBits(value.L1, 51, destination);
            WriteLimbBits(value.L2, 102, destination);
            WriteLimbBits(value.L3, 153, destination);
            WriteLimbBits(value.L4, 204, destination);
        }

        internal static FieldElement Add(FieldElement left, FieldElement right) => Normalize(new FieldElement(
            left.L0 + right.L0,
            left.L1 + right.L1,
            left.L2 + right.L2,
            left.L3 + right.L3,
            left.L4 + right.L4));

        internal static FieldElement Subtract(FieldElement left, FieldElement right)
        {
            left = Normalize(left);
            right = Normalize(right);
            return Normalize(new FieldElement(
                left.L0 + (2 * PrimeLimb0) - right.L0,
                left.L1 + (2 * LimbMask) - right.L1,
                left.L2 + (2 * LimbMask) - right.L2,
                left.L3 + (2 * LimbMask) - right.L3,
                left.L4 + (2 * LimbMask) - right.L4));
        }

        internal static FieldElement Square(FieldElement value) => Multiply(value, value);

        internal static FieldElement Multiply(FieldElement left, FieldElement right)
        {
            left = Normalize(left);
            right = Normalize(right);

            UInt128 c0 = ((UInt128)left.L0 * right.L0) +
                (19 * (((UInt128)left.L1 * right.L4) + ((UInt128)left.L2 * right.L3) +
                    ((UInt128)left.L3 * right.L2) + ((UInt128)left.L4 * right.L1)));
            UInt128 c1 = ((UInt128)left.L0 * right.L1) + ((UInt128)left.L1 * right.L0) +
                (19 * (((UInt128)left.L2 * right.L4) + ((UInt128)left.L3 * right.L3) +
                    ((UInt128)left.L4 * right.L2)));
            UInt128 c2 = ((UInt128)left.L0 * right.L2) + ((UInt128)left.L1 * right.L1) +
                ((UInt128)left.L2 * right.L0) +
                (19 * (((UInt128)left.L3 * right.L4) + ((UInt128)left.L4 * right.L3)));
            UInt128 c3 = ((UInt128)left.L0 * right.L3) + ((UInt128)left.L1 * right.L2) +
                ((UInt128)left.L2 * right.L1) + ((UInt128)left.L3 * right.L0) +
                (19 * ((UInt128)left.L4 * right.L4));
            UInt128 c4 = ((UInt128)left.L0 * right.L4) + ((UInt128)left.L1 * right.L3) +
                ((UInt128)left.L2 * right.L2) + ((UInt128)left.L3 * right.L1) +
                ((UInt128)left.L4 * right.L0);

            c1 += c0 >> 51;
            var l0 = (ulong)c0 & LimbMask;
            c2 += c1 >> 51;
            var l1 = (ulong)c1 & LimbMask;
            c3 += c2 >> 51;
            var l2 = (ulong)c2 & LimbMask;
            c4 += c3 >> 51;
            var l3 = (ulong)c3 & LimbMask;
            var l4 = (ulong)c4 & LimbMask;
            l0 += 19 * (ulong)(c4 >> 51);

            return Normalize(new FieldElement(l0, l1, l2, l3, l4));
        }

        internal static FieldElement Invert(FieldElement value)
        {
            // p - 2 = 2^255 - 21. The exponent is public and fixed.
            var result = One;
            for (var bit = 254; bit >= 0; bit--)
            {
                result = Square(result);
                if (bit >= 5 || bit is 3 or 1 or 0)
                {
                    result = Multiply(result, value);
                }
            }

            return result;
        }

        internal static void ConditionalSwap(ref FieldElement left, ref FieldElement right, ulong swap)
        {
            var mask = 0UL - swap;
            SwapLimb(ref left.L0, ref right.L0, mask);
            SwapLimb(ref left.L1, ref right.L1, mask);
            SwapLimb(ref left.L2, ref right.L2, mask);
            SwapLimb(ref left.L3, ref right.L3, mask);
            SwapLimb(ref left.L4, ref right.L4, mask);
        }

        private static FieldElement Normalize(FieldElement value)
        {
            // Three fixed carry passes cover the deliberately loose bounds used by Add/Subtract.
            Carry(ref value);
            Carry(ref value);
            Carry(ref value);
            return value;
        }

        private static void Carry(ref FieldElement value)
        {
            var carry = value.L0 >> 51;
            value.L0 &= LimbMask;
            value.L1 += carry;
            carry = value.L1 >> 51;
            value.L1 &= LimbMask;
            value.L2 += carry;
            carry = value.L2 >> 51;
            value.L2 &= LimbMask;
            value.L3 += carry;
            carry = value.L3 >> 51;
            value.L3 &= LimbMask;
            value.L4 += carry;
            carry = value.L4 >> 51;
            value.L4 &= LimbMask;
            value.L0 += carry * 19;
        }

        private static FieldElement Canonicalize(FieldElement value)
        {
            value = Normalize(value);
            ulong borrow = 0;
            var d0 = SubtractLimb(value.L0, PrimeLimb0, ref borrow);
            var d1 = SubtractLimb(value.L1, LimbMask, ref borrow);
            var d2 = SubtractLimb(value.L2, LimbMask, ref borrow);
            var d3 = SubtractLimb(value.L3, LimbMask, ref borrow);
            var d4 = SubtractLimb(value.L4, LimbMask, ref borrow);
            var selectReduced = 0UL - (1UL - borrow);

            return new FieldElement(
                Select(value.L0, d0, selectReduced),
                Select(value.L1, d1, selectReduced),
                Select(value.L2, d2, selectReduced),
                Select(value.L3, d3, selectReduced),
                Select(value.L4, d4, selectReduced));
        }

        private static ulong SubtractLimb(ulong value, ulong modulusLimb, ref ulong borrow)
        {
            var difference = value + LimbBase - modulusLimb - borrow;
            borrow = 1UL - (difference >> 51);
            return difference & LimbMask;
        }

        private static ulong Select(ulong original, ulong reduced, ulong selectReduced) =>
            (original & ~selectReduced) | (reduced & selectReduced);

        private static void SwapLimb(ref ulong left, ref ulong right, ulong mask)
        {
            var difference = mask & (left ^ right);
            left ^= difference;
            right ^= difference;
        }

        private static void WriteLimbBits(ulong limb, int firstBit, Span<byte> destination)
        {
            for (var bit = 0; bit < 51; bit++)
            {
                var outputBit = firstBit + bit;
                destination[outputBit >> 3] |= (byte)(((limb >> bit) & 1) << (outputBit & 7));
            }
        }
    }
}

// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license documented in
// THIRD-PARTY-NOTICES.md. The Keccak-f[1600] layout follows FIPS 202 and the
// Go standard library's crypto/internal/fips140/sha3 implementation.

using System.Numerics;
using System.Security.Cryptography;

namespace SharpTls.Cryptography;

/// <summary>
/// FIPS 202 SHA-3/SHAKE helpers used only when the corresponding .NET primitive is
/// unavailable. The managed sponge is also used where incremental XOF reads are required.
/// </summary>
internal static class Fips202
{
    internal static byte[] Sha3_256(ReadOnlySpan<byte> input)
    {
        if (SHA3_256.IsSupported)
        {
            return SHA3_256.HashData(input);
        }
        using var sponge = new Xof(rate: 136, domainSeparator: 0x06);
        sponge.AppendData(input);
        return sponge.Read(32);
    }

    internal static byte[] Sha3_512(ReadOnlySpan<byte> input)
    {
        if (SHA3_512.IsSupported)
        {
            return SHA3_512.HashData(input);
        }
        using var sponge = new Xof(rate: 72, domainSeparator: 0x06);
        sponge.AppendData(input);
        return sponge.Read(64);
    }

    internal static byte[] Shake256(ReadOnlySpan<byte> input, int outputLength)
    {
        if (outputLength < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputLength));
        }
        if (System.Security.Cryptography.Shake256.IsSupported)
        {
            return System.Security.Cryptography.Shake256.HashData(input, outputLength);
        }
        using var sponge = CreateShake256();
        sponge.AppendData(input);
        return sponge.Read(outputLength);
    }

    internal static void Shake256(ReadOnlySpan<byte> input, Span<byte> destination)
    {
        if (System.Security.Cryptography.Shake256.IsSupported)
        {
            System.Security.Cryptography.Shake256.HashData(input, destination);
            return;
        }
        using var sponge = CreateShake256();
        sponge.AppendData(input);
        sponge.Read(destination);
    }

    internal static Xof CreateShake128() => new(rate: 168, domainSeparator: 0x1F);

    internal static Xof CreateShake256() => new(rate: 136, domainSeparator: 0x1F);

    internal sealed class Xof : IDisposable
    {
        private readonly ulong[] _state;
        private readonly int _rate;
        private readonly byte _domainSeparator;
        private int _position;
        private bool _squeezing;
        private bool _disposed;

        internal Xof(int rate, byte domainSeparator)
        {
            if (rate is <= 0 or >= 200 || rate % sizeof(ulong) != 0)
            {
                throw new ArgumentOutOfRangeException(nameof(rate));
            }
            _state = new ulong[25];
            _rate = rate;
            _domainSeparator = domainSeparator;
        }

        private Xof(Xof source)
        {
            _state = (ulong[])source._state.Clone();
            _rate = source._rate;
            _domainSeparator = source._domainSeparator;
            _position = source._position;
            _squeezing = source._squeezing;
        }

        internal void AppendData(ReadOnlySpan<byte> data)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_squeezing)
            {
                throw new InvalidOperationException("FIPS 202 input cannot be appended after squeezing begins.");
            }
            foreach (var value in data)
            {
                XorByte(_position++, value);
                if (_position == _rate)
                {
                    Permute(_state);
                    _position = 0;
                }
            }
        }

        internal byte[] Read(int outputLength)
        {
            if (outputLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength));
            }
            var result = new byte[outputLength];
            Read(result);
            return result;
        }

        internal void Read(Span<byte> destination)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            EnsureSqueezing();
            for (var index = 0; index < destination.Length; index++)
            {
                if (_position == _rate)
                {
                    Permute(_state);
                    _position = 0;
                }
                destination[index] = GetByte(_position++);
            }
        }

        internal byte[] GetCurrentHash(int outputLength)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var clone = new Xof(this);
            return clone.Read(outputLength);
        }

        private void EnsureSqueezing()
        {
            if (_squeezing)
            {
                return;
            }
            XorByte(_position, _domainSeparator);
            XorByte(_rate - 1, 0x80);
            Permute(_state);
            _position = 0;
            _squeezing = true;
        }

        private void XorByte(int offset, byte value) =>
            _state[offset / sizeof(ulong)] ^=
                (ulong)value << ((offset % sizeof(ulong)) * 8);

        private byte GetByte(int offset) =>
            (byte)(_state[offset / sizeof(ulong)] >>
                ((offset % sizeof(ulong)) * 8));

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            Array.Clear(_state);
            _position = 0;
        }
    }

    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008,
    ];

    private static readonly int[] RotationOffsets =
    [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ];

    private static void Permute(ulong[] state)
    {
        Span<ulong> columns = stackalloc ulong[5];
        Span<ulong> transformed = stackalloc ulong[25];
        foreach (var roundConstant in RoundConstants)
        {
            for (var x = 0; x < 5; x++)
            {
                columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^
                    state[x + 15] ^ state[x + 20];
            }
            for (var x = 0; x < 5; x++)
            {
                var adjustment = columns[(x + 4) % 5] ^
                    BitOperations.RotateLeft(columns[(x + 1) % 5], 1);
                for (var y = 0; y < 5; y++)
                {
                    state[x + 5 * y] ^= adjustment;
                }
            }

            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                {
                    transformed[y + 5 * ((2 * x + 3 * y) % 5)] =
                        BitOperations.RotateLeft(
                            state[x + 5 * y],
                            RotationOffsets[x + 5 * y]);
                }
            }

            for (var x = 0; x < 5; x++)
            {
                for (var y = 0; y < 5; y++)
                {
                    state[x + 5 * y] = transformed[x + 5 * y] ^
                        (~transformed[(x + 1) % 5 + 5 * y] &
                         transformed[(x + 2) % 5 + 5 * y]);
                }
            }
            state[0] ^= roundConstant;
        }
        CryptographicOperations.ZeroMemory(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(columns));
        CryptographicOperations.ZeroMemory(
            System.Runtime.InteropServices.MemoryMarshal.AsBytes(transformed));
    }
}

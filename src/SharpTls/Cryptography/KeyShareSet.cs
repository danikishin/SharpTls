using SharpTls.Protocol;

namespace SharpTls.Cryptography;

internal sealed class KeyShareSet : IDisposable
{
    private readonly Dictionary<NamedGroup, IKeyShare> _shares = [];
    private readonly Func<NamedGroup, IKeyShare> _factory;
    private readonly bool _reuseHybridClassicalShare;
    private readonly bool _deterministicForTesting;
    private bool _disposed;

    internal KeyShareSet(Func<NamedGroup, IKeyShare>? factory = null)
    {
        _factory = factory ?? KeyShareFactory.Create;
        _reuseHybridClassicalShare = factory is null;
    }

    internal KeyShareSet(bool deterministicForTesting)
    {
        _deterministicForTesting = deterministicForTesting;
        _reuseHybridClassicalShare = true;
        _factory = deterministicForTesting
            ? KeyShareFactory.CreateDeterministicForTesting
            : KeyShareFactory.Create;
    }

    internal IReadOnlyList<IKeyShare> Generate(IReadOnlyList<NamedGroup> groups)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_shares.Count != 0)
        {
            throw new InvalidOperationException("Key shares have already been generated for this ClientHello.");
        }

        X25519KeyShare? reusedX25519 = null;
        if (_reuseHybridClassicalShare &&
            groups.Any(group => group is NamedGroup.X25519MlKem768 or
                NamedGroup.X25519Kyber768Draft00) &&
            groups.Contains(NamedGroup.X25519))
        {
            reusedX25519 = _deterministicForTesting
                ? X25519KeyShare.CreateDeterministicForTesting()
                : X25519KeyShare.Create();
        }
        try
        {
            foreach (var group in groups)
            {
                IKeyShare share = group switch
                {
                    NamedGroup.X25519MlKem768 when reusedX25519 is not null =>
                        _deterministicForTesting
                            ? X25519MlKem768KeyShare.CreateDeterministicForTesting(reusedX25519)
                            : X25519MlKem768KeyShare.Create(reusedX25519),
                    NamedGroup.X25519Kyber768Draft00 when reusedX25519 is not null =>
                        _deterministicForTesting
                            ? X25519Kyber768Draft00KeyShare.CreateDeterministicForTesting(
                                reusedX25519)
                            : X25519Kyber768Draft00KeyShare.Create(reusedX25519),
                    NamedGroup.X25519 when reusedX25519 is not null => reusedX25519,
                    _ => _factory(group),
                };
                if (!_shares.TryAdd(group, share))
                {
                    share.Dispose();
                    throw new ArgumentException($"Duplicate key-share group {group}.", nameof(groups));
                }
            }
        }
        catch
        {
            foreach (var share in _shares.Values)
            {
                share.Dispose();
            }
            reusedX25519?.Dispose();
            _shares.Clear();
            throw;
        }

        return groups.Select(group => _shares[group]).ToArray();
    }

    internal IKeyShare Get(NamedGroup group)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _shares.TryGetValue(group, out var share)
            ? share
            : throw TlsProtocolException.Illegal($"The server selected an unoffered key-share group {group}.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var share in _shares.Values)
        {
            share.Dispose();
        }

        _shares.Clear();
    }
}

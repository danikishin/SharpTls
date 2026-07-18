using System.Security.Cryptography;

namespace SharpTls;

/// <summary>Controls what happens when a server rejects explicitly enabled TLS 1.3 early data.</summary>
public enum Tls13EarlyDataRejectionPolicy
{
    /// <summary>Do not resend. The caller inspects EarlyDataStatus and decides what is safe.</summary>
    ReturnToCaller,
    /// <summary>Explicitly resend the same bytes once under authenticated 1-RTT application keys.</summary>
    RetransmitAfterHandshake,
}

/// <summary>Reports the outcome of an explicitly configured TLS 1.3 early-data attempt.</summary>
public enum Tls13EarlyDataStatus
{
    /// <summary>No early data was configured.</summary>
    NotConfigured,
    /// <summary>No suitable early-data ticket was available, so no bytes were sent.</summary>
    Unavailable,
    /// <summary>The server accepted the transmitted early data.</summary>
    Accepted,
    /// <summary>The server rejected the transmitted early data and it was not resent.</summary>
    Rejected,
    /// <summary>The server rejected early data and the explicitly requested 1-RTT retransmission completed.</summary>
    RejectedAndRetransmitted,
}

/// <summary>
/// Immutable, snapshotted TLS 1.3 early-data request. Early data can be replayed by an attacker;
/// construction therefore requires an explicit risk acknowledgement.
/// </summary>
public sealed class Tls13EarlyDataOptions
{
    private readonly byte[] _data;

    /// <summary>Creates an early-data request and snapshots <paramref name="data"/>.</summary>
    public Tls13EarlyDataOptions(
        ReadOnlySpan<byte> data,
        bool acknowledgeReplayRisk,
        Tls13EarlyDataRejectionPolicy rejectionPolicy =
            Tls13EarlyDataRejectionPolicy.ReturnToCaller)
    {
        if (data.IsEmpty)
        {
            throw new ArgumentException("TLS early data cannot be empty.", nameof(data));
        }
        if (!acknowledgeReplayRisk)
        {
            throw new ArgumentException(
                "The application must explicitly acknowledge that TLS early data is replayable.",
                nameof(acknowledgeReplayRisk));
        }
        if (!Enum.IsDefined(rejectionPolicy))
        {
            throw new ArgumentOutOfRangeException(nameof(rejectionPolicy));
        }

        _data = data.ToArray();
        RejectionPolicy = rejectionPolicy;
    }

    /// <summary>Gets a copy of the early application bytes.</summary>
    public byte[] Data => (byte[])_data.Clone();

    /// <summary>Gets the explicit server-rejection behavior.</summary>
    public Tls13EarlyDataRejectionPolicy RejectionPolicy { get; }

    internal int Length => _data.Length;

    internal Tls13EarlyDataConfiguration Snapshot() => new(
        (byte[])_data.Clone(),
        RejectionPolicy);
}

internal sealed class Tls13EarlyDataConfiguration : IDisposable
{
    private byte[]? _data;

    internal Tls13EarlyDataConfiguration(
        byte[] data,
        Tls13EarlyDataRejectionPolicy rejectionPolicy)
    {
        _data = data;
        RejectionPolicy = rejectionPolicy;
    }

    internal ReadOnlyMemory<byte> Data => _data ??
        throw new ObjectDisposedException(nameof(Tls13EarlyDataConfiguration));

    internal Tls13EarlyDataRejectionPolicy RejectionPolicy { get; }

    public void Dispose()
    {
        var data = Interlocked.Exchange(ref _data, null);
        if (data is not null)
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }
}

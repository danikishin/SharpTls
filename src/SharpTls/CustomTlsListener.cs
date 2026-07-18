using System.Net;
using System.Net.Sockets;

namespace SharpTls;

/// <summary>
/// Accepts TCP connections and authenticates each with an independent
/// <see cref="CustomTlsServer"/> instance. Application protocol dispatch remains caller-owned.
/// </summary>
public sealed class CustomTlsListener : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly Func<CustomTlsServerOptions> _optionsFactory;
    private readonly bool _ownsListener;
    private bool _started;
    private bool _disposed;

    /// <summary>Creates an owned TCP listener that is started explicitly with <see cref="Start"/>.</summary>
    public CustomTlsListener(
        IPEndPoint localEndpoint,
        Func<CustomTlsServerOptions> optionsFactory)
    {
        ArgumentNullException.ThrowIfNull(localEndpoint);
        _optionsFactory = optionsFactory ?? throw new ArgumentNullException(nameof(optionsFactory));
        _listener = new TcpListener(localEndpoint);
        _ownsListener = true;
    }

    /// <summary>
    /// Wraps a caller-owned listener. Set <paramref name="leaveOpen"/> to false to stop it on dispose.
    /// </summary>
    public CustomTlsListener(
        TcpListener listener,
        Func<CustomTlsServerOptions> optionsFactory,
        bool leaveOpen = true)
    {
        _listener = listener ?? throw new ArgumentNullException(nameof(listener));
        _optionsFactory = optionsFactory ?? throw new ArgumentNullException(nameof(optionsFactory));
        _ownsListener = !leaveOpen;
    }

    /// <summary>Gets the bound endpoint after the listener is started.</summary>
    public EndPoint LocalEndpoint
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_started)
            {
                throw new InvalidOperationException("The TLS listener has not been started.");
            }
            return _listener.LocalEndpoint;
        }
    }

    /// <summary>Starts the underlying TCP listener exactly once.</summary>
    public void Start(int backlog = 512)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (backlog < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(backlog));
        }
        if (_started)
        {
            throw new InvalidOperationException("The TLS listener has already been started.");
        }
        _listener.Start(backlog);
        _started = true;
    }

    /// <summary>
    /// Accepts and fully authenticates one connection. The caller owns and must dispose the result.
    /// </summary>
    public async ValueTask<CustomTlsServer> AcceptConnectionAsync(
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_started)
        {
            throw new InvalidOperationException("The TLS listener has not been started.");
        }
        var socket = await _listener.AcceptSocketAsync(cancellationToken).ConfigureAwait(false);
        CustomTlsServer? server = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var options = _optionsFactory() ?? throw new InvalidOperationException(
                "The TLS listener options factory returned null.");
            server = new CustomTlsServer(options);
            await server.AuthenticateAsync(
                socket,
                ownsSocket: true,
                cancellationToken).ConfigureAwait(false);
            return server;
        }
        catch
        {
            if (server is not null)
            {
                await server.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                socket.Dispose();
            }
            throw;
        }
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }
        _disposed = true;
        if (_ownsListener)
        {
            _listener.Stop();
        }
        return ValueTask.CompletedTask;
    }
}

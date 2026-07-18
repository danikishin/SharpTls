namespace SharpTls.Protocol;

/// <summary>Represents a fatal local TLS protocol failure and its corresponding alert.</summary>
public sealed class TlsProtocolException : IOException
{
    /// <summary>Creates a protocol failure.</summary>
    public TlsProtocolException(TlsAlertDescription alert, string message)
        : this(alert, message, innerException: null, isPeerAlert: false)
    {
    }

    /// <summary>Creates a protocol failure with an underlying runtime error.</summary>
    public TlsProtocolException(TlsAlertDescription alert, string message, Exception innerException)
        : this(alert, message, innerException, isPeerAlert: false)
    {
    }

    internal TlsProtocolException(
        TlsAlertDescription alert,
        string message,
        Exception? innerException,
        bool isPeerAlert)
        : base(message, innerException)
    {
        Alert = alert;
        IsPeerAlert = isPeerAlert;
    }

    /// <summary>Gets the fatal alert classification.</summary>
    public TlsAlertDescription Alert { get; }

    internal bool IsPeerAlert { get; }

    internal static TlsProtocolException Decode(string message) =>
        new(TlsAlertDescription.DecodeError, message);

    internal static TlsProtocolException Illegal(string message) =>
        new(TlsAlertDescription.IllegalParameter, message);

    internal static TlsProtocolException Unexpected(string message) =>
        new(TlsAlertDescription.UnexpectedMessage, message);
}

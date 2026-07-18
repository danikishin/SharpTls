namespace SharpTls;

public static partial class ClientHelloProfiles
{
    /// <summary>
    /// Gets the newest capture-backed Chrome profile shipped by this SharpTls version.
    /// This alias currently resolves to <see cref="UTlsChrome133"/>.
    /// </summary>
    public static ClientHelloProfile UTlsChromeAuto => UTlsChrome133;

    /// <summary>
    /// Gets the newest capture-backed Firefox profile shipped by this SharpTls version.
    /// This alias currently resolves to <see cref="UTlsFirefox148"/>.
    /// </summary>
    public static ClientHelloProfile UTlsFirefoxAuto => UTlsFirefox148;

    /// <summary>
    /// Gets the newest capture-backed Edge profile shipped by this SharpTls version.
    /// This alias currently resolves to <see cref="UTlsEdge106"/>.
    /// </summary>
    public static ClientHelloProfile UTlsEdgeAuto => UTlsEdge106;

    /// <summary>
    /// Gets the newest capture-backed iOS profile shipped by this SharpTls version.
    /// This alias currently resolves to <see cref="UTlsIOS14"/>.
    /// </summary>
    public static ClientHelloProfile UTlsIOSAuto => UTlsIOS14;

    /// <summary>
    /// Gets the newest capture-backed Safari profile shipped by this SharpTls version.
    /// This alias currently resolves to <see cref="UTlsSafari263"/>.
    /// </summary>
    public static ClientHelloProfile UTlsSafariAuto => UTlsSafari263;

    /// <summary>
    /// Gets the newest capture-backed Android/OkHttp profile shipped by this SharpTls version.
    /// This alias currently resolves to <see cref="UTlsAndroid11OkHttp"/>.
    /// </summary>
    public static ClientHelloProfile UTlsAndroidAuto => UTlsAndroid11OkHttp;
}

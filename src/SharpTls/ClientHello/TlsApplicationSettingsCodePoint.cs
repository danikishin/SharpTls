namespace SharpTls;

/// <summary>
/// Experimental ALPS/application_settings extension code points used by uTLS-compatible peers.
/// Neither value is assigned by the IANA TLS ExtensionType registry.
/// </summary>
public enum TlsApplicationSettingsCodePoint : ushort
{
    /// <summary>Code point used by draft-vvv-tls-alps-01 and older Chromium/uTLS profiles.</summary>
    LegacyDraft = 17513,

    /// <summary>Later Chromium experiment code point exposed by current uTLS releases.</summary>
    ChromeExperiment = 17613,
}

namespace SharpTls.Protocol;

internal static class TlsConstants
{
    internal const ushort LegacyRecordVersion = 0x0303;
    internal const ushort Tls12Version = 0x0303;
    internal const ushort Tls13Version = 0x0304;
    internal const int RecordHeaderLength = 5;
    internal const int HandshakeHeaderLength = 4;
    internal const int MaxPlaintextLength = 1 << 14;
    internal const int MaxCiphertextLength = MaxPlaintextLength + 256;
    internal const int AeadTagLength = 16;
    internal const int Tls12FinishedLength = 12;
    internal const int Tls12MasterSecretLength = 48;
    internal const int Tls12AeadAdditionalDataLength = 13;
    internal const int RandomLength = 32;
    internal const int MaxSessionIdLength = 32;
    internal const int MaxAlpnProtocolLength = 255;
}

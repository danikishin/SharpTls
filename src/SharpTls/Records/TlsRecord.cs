using SharpTls.Protocol;

namespace SharpTls.Records;

internal sealed record TlsRecord(
    TlsContentType ContentType,
    byte[] Fragment,
    ushort LegacyRecordVersion);

using System.Security.Cryptography;
using System.Text;
using SharpTls.IO;
using SharpTls.Protocol;

namespace SharpTls;

/// <summary>HPKE KEM identifiers relevant to RFC 9849 ECH.</summary>
public enum TlsHpkeKemId : ushort
{
    /// <summary>DHKEM(P-256, HKDF-SHA256).</summary>
    DhkemP256HkdfSha256 = 0x0010,
    /// <summary>DHKEM(P-384, HKDF-SHA384).</summary>
    DhkemP384HkdfSha384 = 0x0011,
    /// <summary>DHKEM(P-521, HKDF-SHA512).</summary>
    DhkemP521HkdfSha512 = 0x0012,
    /// <summary>DHKEM(X25519, HKDF-SHA256).</summary>
    DhkemX25519HkdfSha256 = 0x0020,
}

/// <summary>HPKE KDF identifiers relevant to RFC 9849 ECH.</summary>
public enum TlsHpkeKdfId : ushort
{
    /// <summary>HKDF-SHA256.</summary>
    HkdfSha256 = 0x0001,
    /// <summary>HKDF-SHA384.</summary>
    HkdfSha384 = 0x0002,
    /// <summary>HKDF-SHA512.</summary>
    HkdfSha512 = 0x0003,
}

/// <summary>HPKE AEAD identifiers relevant to RFC 9849 ECH.</summary>
public enum TlsHpkeAeadId : ushort
{
    /// <summary>AES-128-GCM.</summary>
    Aes128Gcm = 0x0001,
    /// <summary>AES-256-GCM.</summary>
    Aes256Gcm = 0x0002,
    /// <summary>ChaCha20-Poly1305.</summary>
    ChaCha20Poly1305 = 0x0003,
}

/// <summary>An HPKE KDF/AEAD pair advertised by an RFC 9849 ECH configuration.</summary>
public readonly record struct TlsHpkeSymmetricCipherSuite(
    TlsHpkeKdfId KdfId,
    TlsHpkeAeadId AeadId);

/// <summary>An opaque RFC 9849 ECH configuration extension.</summary>
public sealed class TlsEchConfigExtension
{
    private readonly byte[] _data;

    internal TlsEchConfigExtension(ushort type, ReadOnlySpan<byte> data)
    {
        Type = type;
        _data = data.ToArray();
    }

    /// <summary>Gets the extension type.</summary>
    public ushort Type { get; }

    /// <summary>Gets whether the high mandatory bit is set.</summary>
    public bool IsMandatory => (Type & 0x8000) != 0;

    /// <summary>Gets a defensive copy of the extension body.</summary>
    public byte[] GetData() => (byte[])_data.Clone();
}

/// <summary>A parsed current-version RFC 9849 ECHConfig.</summary>
public sealed class TlsEchConfig
{
    private readonly byte[] _publicKey;
    private readonly byte[] _encoded;
    private readonly TlsHpkeSymmetricCipherSuite[] _cipherSuites;
    private readonly TlsEchConfigExtension[] _extensions;

    internal TlsEchConfig(
        byte configId,
        TlsHpkeKemId kemId,
        ReadOnlySpan<byte> publicKey,
        TlsHpkeSymmetricCipherSuite[] cipherSuites,
        byte maximumNameLength,
        string publicName,
        TlsEchConfigExtension[] extensions,
        ReadOnlySpan<byte> encoded)
    {
        ConfigId = configId;
        KemId = kemId;
        _publicKey = publicKey.ToArray();
        _cipherSuites = (TlsHpkeSymmetricCipherSuite[])cipherSuites.Clone();
        MaximumNameLength = maximumNameLength;
        PublicName = publicName;
        _extensions = (TlsEchConfigExtension[])extensions.Clone();
        _encoded = encoded.ToArray();
    }

    /// <summary>Gets the RFC 9849 ECH version and TLS extension code point.</summary>
    public ushort Version => (ushort)TlsExtensionType.EncryptedClientHello;

    /// <summary>Gets the server-selected configuration identifier.</summary>
    public byte ConfigId { get; }

    /// <summary>Gets the HPKE KEM identifier.</summary>
    public TlsHpkeKemId KemId { get; }

    /// <summary>Gets a defensive copy of the serialized HPKE public key.</summary>
    public byte[] GetPublicKey() => (byte[])_publicKey.Clone();

    /// <summary>Gets HPKE cipher suites in server preference order.</summary>
    public IReadOnlyList<TlsHpkeSymmetricCipherSuite> CipherSuites =>
        Array.AsReadOnly((TlsHpkeSymmetricCipherSuite[])_cipherSuites.Clone());

    /// <summary>Gets the server's inner-name padding hint.</summary>
    public byte MaximumNameLength { get; }

    /// <summary>Gets the validated ASCII public DNS name.</summary>
    public string PublicName { get; }

    /// <summary>Gets snapshotted ECH configuration extensions.</summary>
    public IReadOnlyList<TlsEchConfigExtension> Extensions =>
        Array.AsReadOnly((TlsEchConfigExtension[])_extensions.Clone());

    /// <summary>Gets whether an unknown mandatory ECH configuration extension is present.</summary>
    public bool HasUnsupportedMandatoryExtensions => _extensions.Any(extension =>
        extension.IsMandatory);

    /// <summary>Gets the exact serialized ECHConfig, including version and length.</summary>
    public byte[] GetEncodedConfig() => (byte[])_encoded.Clone();
}

/// <summary>A strict, bounded RFC 9849 ECHConfigList parser and immutable model.</summary>
public sealed class TlsEchConfigList
{
    private readonly TlsEchConfig[] _configurations;
    private readonly byte[] _encoded;

    private TlsEchConfigList(
        TlsEchConfig[] configurations,
        int unknownVersionCount,
        ReadOnlySpan<byte> encoded)
    {
        _configurations = configurations;
        UnknownVersionCount = unknownVersionCount;
        _encoded = encoded.ToArray();
    }

    /// <summary>Gets parsed current-version configurations in wire preference order.</summary>
    public IReadOnlyList<TlsEchConfig> Configurations =>
        Array.AsReadOnly((TlsEchConfig[])_configurations.Clone());

    /// <summary>Gets the number of well-framed configurations with an unsupported version.</summary>
    public int UnknownVersionCount { get; }

    /// <summary>Gets a defensive copy of the complete encoded ECHConfigList.</summary>
    public byte[] GetEncodedList() => (byte[])_encoded.Clone();

    internal EchConfigSelection? SelectSupportedConfiguration()
    {
        foreach (var configuration in _configurations)
        {
            if (configuration.HasUnsupportedMandatoryExtensions ||
                !IsKemExecutable(configuration.KemId))
            {
                continue;
            }
            foreach (var suite in configuration.CipherSuites)
            {
                if (IsCipherSuiteExecutable(suite))
                {
                    return new EchConfigSelection(configuration, suite);
                }
            }
        }
        return null;
    }

    internal static bool IsCipherSuiteExecutable(
        TlsHpkeSymmetricCipherSuite suite) =>
        (suite.KdfId is TlsHpkeKdfId.HkdfSha256 or
            TlsHpkeKdfId.HkdfSha384 or TlsHpkeKdfId.HkdfSha512) &&
        (suite.AeadId is TlsHpkeAeadId.Aes128Gcm or
            TlsHpkeAeadId.Aes256Gcm or TlsHpkeAeadId.ChaCha20Poly1305) &&
        (suite.AeadId != TlsHpkeAeadId.ChaCha20Poly1305 ||
            ChaCha20Poly1305.IsSupported);

    private static bool IsKemExecutable(TlsHpkeKemId kemId) => kemId switch
    {
        TlsHpkeKemId.DhkemX25519HkdfSha256 => true,
        TlsHpkeKemId.DhkemP256HkdfSha256 or
        TlsHpkeKemId.DhkemP384HkdfSha384 or
        TlsHpkeKemId.DhkemP521HkdfSha512 => Ech.HpkeNistKem.IsSupported(kemId),
        _ => false,
    };

    /// <summary>Parses exactly one network-encoded ECHConfigList.</summary>
    public static TlsEchConfigList Parse(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length > ushort.MaxValue + 2)
        {
            throw TlsProtocolException.Decode("ECHConfigList exceeds its 16-bit vector bound.");
        }

        var outer = new TlsBinaryReader(encoded);
        var listBytes = outer.ReadVector16();
        outer.EnsureEnd("ECHConfigList");
        if (listBytes.Length < 4)
        {
            throw TlsProtocolException.Decode("ECHConfigList must contain at least one configuration.");
        }

        var list = new TlsBinaryReader(listBytes);
        var configurations = new List<TlsEchConfig>();
        var unknownVersionCount = 0;
        while (!list.End)
        {
            var version = list.ReadUInt16();
            var contents = list.ReadVector16();
            var encodedConfig = new TlsBinaryWriter(contents.Length + 4);
            encodedConfig.WriteUInt16(version);
            encodedConfig.WriteVector16(contents);
            if (version != (ushort)TlsExtensionType.EncryptedClientHello)
            {
                unknownVersionCount++;
                continue;
            }

            var configuration = ParseCurrent(contents, encodedConfig.WrittenSpan);
            if (configuration is not null)
            {
                configurations.Add(configuration);
            }
        }

        return new TlsEchConfigList(
            configurations.ToArray(),
            unknownVersionCount,
            encoded);
    }

    private static TlsEchConfig? ParseCurrent(
        ReadOnlySpan<byte> contents,
        ReadOnlySpan<byte> encodedConfig)
    {
        var reader = new TlsBinaryReader(contents);
        var configId = reader.ReadUInt8();
        var kemCode = reader.ReadUInt16();
        var publicKey = reader.ReadVector16();
        if (publicKey.IsEmpty)
        {
            throw TlsProtocolException.Decode("ECHConfig HPKE public_key cannot be empty.");
        }
        var hasKnownKem = Enum.IsDefined(typeof(TlsHpkeKemId), kemCode);
        var kemId = (TlsHpkeKemId)kemCode;
        if (hasKnownKem)
        {
            ValidatePublicKey(kemId, publicKey);
        }

        var encodedSuites = reader.ReadVector16();
        if (encodedSuites.Length < 4 || (encodedSuites.Length & 3) != 0)
        {
            throw TlsProtocolException.Decode("ECHConfig HPKE cipher_suites has an invalid length.");
        }
        var suitesReader = new TlsBinaryReader(encodedSuites);
        var suites = new List<TlsHpkeSymmetricCipherSuite>();
        var seenSuites = new HashSet<(ushort Kdf, ushort Aead)>();
        while (!suitesReader.End)
        {
            var kdfCode = suitesReader.ReadUInt16();
            var aeadCode = suitesReader.ReadUInt16();
            if (!seenSuites.Add((kdfCode, aeadCode)))
            {
                throw TlsProtocolException.Illegal("ECHConfig contains a duplicate HPKE cipher suite.");
            }
            if (!Enum.IsDefined(typeof(TlsHpkeKdfId), kdfCode) ||
                !Enum.IsDefined(typeof(TlsHpkeAeadId), aeadCode))
            {
                continue;
            }
            suites.Add(new TlsHpkeSymmetricCipherSuite(
                (TlsHpkeKdfId)kdfCode,
                (TlsHpkeAeadId)aeadCode));
        }

        var maximumNameLength = reader.ReadUInt8();
        var publicNameBytes = reader.ReadVector8(TlsConstants.MaxAlpnProtocolLength);
        var publicName = ParsePublicName(publicNameBytes);
        var extensionsReader = new TlsBinaryReader(reader.ReadVector16());
        reader.EnsureEnd("ECHConfigContents");
        var extensions = new List<TlsEchConfigExtension>();
        var extensionTypes = new HashSet<ushort>();
        while (!extensionsReader.End)
        {
            var type = extensionsReader.ReadUInt16();
            var data = extensionsReader.ReadVector16();
            if (!extensionTypes.Add(type))
            {
                throw TlsProtocolException.Illegal(
                    $"ECHConfig contains duplicate extension 0x{type:X4}.");
            }
            extensions.Add(new TlsEchConfigExtension(type, data));
        }

        return hasKnownKem
            ? new TlsEchConfig(
            configId,
            kemId,
            publicKey,
            suites.ToArray(),
            maximumNameLength,
            publicName,
            extensions.ToArray(),
            encodedConfig)
            : null;
    }

    private static void ValidatePublicKey(TlsHpkeKemId kemId, ReadOnlySpan<byte> key)
    {
        var expectedLength = kemId switch
        {
            TlsHpkeKemId.DhkemP256HkdfSha256 => 65,
            TlsHpkeKemId.DhkemP384HkdfSha384 => 97,
            TlsHpkeKemId.DhkemP521HkdfSha512 => 133,
            TlsHpkeKemId.DhkemX25519HkdfSha256 => 32,
            _ => throw new NotSupportedException(),
        };
        if (key.Length != expectedLength ||
            (kemId != TlsHpkeKemId.DhkemX25519HkdfSha256 && key[0] != 4))
        {
            throw TlsProtocolException.Illegal("ECHConfig HPKE public key has invalid encoding.");
        }
        if (kemId == TlsHpkeKemId.DhkemX25519HkdfSha256)
        {
            return;
        }
        try
        {
            Ech.HpkeNistKem.ValidatePublicKey(kemId, key);
        }
        catch (Exception exception) when (exception is
            CryptographicException or PlatformNotSupportedException)
        {
            throw new TlsProtocolException(
                TlsAlertDescription.IllegalParameter,
                "ECHConfig HPKE public key is not a valid point on the selected curve.",
                exception);
        }
    }

    private static string ParsePublicName(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded.Length > 253 ||
            encoded.IndexOfAnyInRange((byte)0x80, byte.MaxValue) >= 0)
        {
            throw TlsProtocolException.Illegal("ECHConfig public_name is not an ASCII DNS name.");
        }
        var name = Encoding.ASCII.GetString(encoded);
        if (name[0] == '.' || name[^1] == '.')
        {
            throw TlsProtocolException.Illegal("ECHConfig public_name cannot begin or end with a dot.");
        }
        var labels = name.Split('.');
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63 ||
                !IsAsciiAlphaNumeric(label[0]) ||
                !IsAsciiAlphaNumeric(label[^1]) ||
                label.Any(character => !IsAsciiAlphaNumeric(character) && character != '-'))
            {
                throw TlsProtocolException.Illegal("ECHConfig public_name contains an invalid LDH label.");
            }
        }

        var finalLabel = labels[^1];
        if (finalLabel.All(character => character is >= '0' and <= '9') ||
            IsHexLikeIpv4Label(finalLabel))
        {
            throw TlsProtocolException.Illegal(
                "ECHConfig public_name has an IPv4-ambiguous final label.");
        }
        return name;
    }

    private static bool IsAsciiAlphaNumeric(char value) =>
        value is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';

    private static bool IsHexLikeIpv4Label(string label)
    {
        if (label.Length < 2 || label[0] != '0' || label[1] is not ('x' or 'X'))
        {
            return false;
        }
        return label.AsSpan(2).IsEmpty || label[2..].All(character => character is
            >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    }
}

internal sealed record EchConfigSelection(
    TlsEchConfig Configuration,
    TlsHpkeSymmetricCipherSuite CipherSuite);

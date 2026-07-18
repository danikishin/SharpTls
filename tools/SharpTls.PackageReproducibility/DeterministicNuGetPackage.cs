using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SharpTls.Packaging;

internal static class DeterministicNuGetPackage
{
    private const int MaximumEntryCount = 4096;
    private const long MaximumEntryLength = 256L * 1024 * 1024;
    private const long MaximumPackageLength = 512L * 1024 * 1024;
    private const string RelationshipsPath = "_rels/.rels";
    private const string CorePropertiesPrefix = "package/services/metadata/core-properties/";
    private const string StableCorePropertiesPath = CorePropertiesPrefix + "metadata.psmdcp";
    private static readonly DateTimeOffset StableTimestamp = new(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);

    internal static void Normalize(string inputPath, string outputPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        var inputFullPath = Path.GetFullPath(inputPath);
        var outputFullPath = Path.GetFullPath(outputPath);
        if (string.Equals(inputFullPath, outputFullPath, StringComparison.Ordinal))
        {
            throw new ArgumentException("Input and output package paths must differ.");
        }
        var inputInfo = new FileInfo(inputFullPath);
        if (!inputInfo.Exists || inputInfo.Length is 0 or > MaximumPackageLength)
        {
            throw new InvalidDataException("NuGet input package is missing, empty, or oversized.");
        }

        var entries = ReadEntries(inputFullPath);
        if (!entries.TryGetValue(RelationshipsPath, out var relationships))
        {
            throw new InvalidDataException("NuGet package omitted _rels/.rels.");
        }
        var corePaths = entries.Keys.Where(path =>
            path.StartsWith(CorePropertiesPrefix, StringComparison.Ordinal) &&
            path.EndsWith(".psmdcp", StringComparison.Ordinal)).ToArray();
        if (corePaths.Length != 1)
        {
            throw new InvalidDataException("NuGet package must contain exactly one core-properties part.");
        }

        var coreProperties = entries[corePaths[0]];
        entries.Remove(corePaths[0]);
        if (!entries.TryAdd(StableCorePropertiesPath, coreProperties))
        {
            throw new InvalidDataException("NuGet package contains a colliding core-properties path.");
        }
        entries[RelationshipsPath] = NormalizeRelationships(relationships);

        var outputDirectory = Path.GetDirectoryName(outputFullPath);
        if (!string.IsNullOrEmpty(outputDirectory)) Directory.CreateDirectory(outputDirectory);
        try
        {
            using var output = new FileStream(
                outputFullPath,
                FileMode.Create,
                FileAccess.ReadWrite,
                FileShare.None);
            using var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: false, Encoding.UTF8);
            foreach (var pair in entries.OrderBy(pair => pair.Key, StringComparer.Ordinal))
            {
                var entry = archive.CreateEntry(pair.Key, CompressionLevel.Optimal);
                entry.LastWriteTime = StableTimestamp;
                entry.ExternalAttributes = 0;
                using var destination = entry.Open();
                destination.Write(pair.Value);
            }
        }
        catch
        {
            File.Delete(outputFullPath);
            throw;
        }
    }

    private static Dictionary<string, byte[]> ReadEntries(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: false, Encoding.UTF8);
        if (archive.Entries.Count is 0 or > MaximumEntryCount)
        {
            throw new InvalidDataException("NuGet package has an invalid entry count.");
        }
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        long totalLength = 0;
        foreach (var entry in archive.Entries)
        {
            ValidateEntryPath(entry.FullName);
            if (entry.FullName.EndsWith("/", StringComparison.Ordinal))
            {
                continue;
            }
            if (entry.Length < 0 || entry.Length > MaximumEntryLength ||
                totalLength > MaximumPackageLength - entry.Length)
            {
                throw new InvalidDataException("NuGet package expands beyond its configured bound.");
            }
            totalLength += entry.Length;
            var length = checked((int)entry.Length);
            var data = new byte[length];
            using var source = entry.Open();
            source.ReadExactly(data);
            if (source.ReadByte() != -1)
            {
                throw new InvalidDataException("NuGet entry length changed while being read.");
            }
            if (!entries.TryAdd(entry.FullName, data))
            {
                throw new InvalidDataException($"NuGet package contains duplicate entry '{entry.FullName}'.");
            }
        }
        return entries;
    }

    private static byte[] NormalizeRelationships(byte[] encoded)
    {
        XDocument document;
        try
        {
            using var input = new MemoryStream(encoded, writable: false);
            using var reader = XmlReader.Create(input, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                MaxCharactersInDocument = 1024 * 1024,
                XmlResolver = null,
            });
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException exception)
        {
            throw new InvalidDataException("NuGet package relationships XML is malformed.", exception);
        }

        var relationships = document.Root?.Elements().Where(element =>
            element.Name.LocalName == "Relationship").ToArray() ?? [];
        if (relationships.Length == 0)
        {
            throw new InvalidDataException("NuGet package has no package relationships.");
        }
        var core = relationships.Where(element =>
            ((string?)element.Attribute("Type"))?.EndsWith(
                "/metadata/core-properties",
                StringComparison.Ordinal) == true).ToArray();
        if (core.Length != 1)
        {
            throw new InvalidDataException("NuGet package must have one core-properties relationship.");
        }
        core[0].SetAttributeValue("Target", "/" + StableCorePropertiesPath);
        foreach (var relationship in relationships)
        {
            var type = (string?)relationship.Attribute("Type") ??
                throw new InvalidDataException("NuGet relationship omitted Type.");
            var target = (string?)relationship.Attribute("Target") ??
                throw new InvalidDataException("NuGet relationship omitted Target.");
            var stableId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(type + "\0" + target)))[..16];
            relationship.SetAttributeValue("Id", "R" + stableId);
        }

        using var output = new MemoryStream();
        using (var writer = XmlWriter.Create(output, new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            Indent = true,
            NewLineChars = "\n",
            NewLineHandling = NewLineHandling.Replace,
            OmitXmlDeclaration = false,
        }))
        {
            document.Save(writer);
        }
        return output.ToArray();
    }

    private static void ValidateEntryPath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.StartsWith("/", StringComparison.Ordinal) ||
            path.Contains('\\') ||
            path.Split('/').Any(segment => segment is "" or "." or ".."))
        {
            throw new InvalidDataException($"NuGet package entry path '{path}' is unsafe or non-canonical.");
        }
    }
}

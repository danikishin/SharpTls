using System.IO.Compression;
using System.Text;
using SharpTls.Packaging;

namespace SharpTls.Tests.Packaging;

public sealed class DeterministicNuGetPackageTests
{
    [Fact]
    public void RandomOpcIdentifiersAndTimestampsNormalizeByteForByte()
    {
        using var directory = new TemporaryDirectory();
        var firstInput = Path.Combine(directory.Path, "first.nupkg");
        var secondInput = Path.Combine(directory.Path, "second.nupkg");
        var firstOutput = Path.Combine(directory.Path, "first.normalized.nupkg");
        var secondOutput = Path.Combine(directory.Path, "second.normalized.nupkg");
        CreatePackage(firstInput, "aaaaaaaa", "RANDOM-A", new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero));
        CreatePackage(secondInput, "bbbbbbbb", "RANDOM-B", new DateTimeOffset(2026, 7, 18, 0, 0, 0, TimeSpan.Zero));

        DeterministicNuGetPackage.Normalize(firstInput, firstOutput);
        DeterministicNuGetPackage.Normalize(secondInput, secondOutput);

        Assert.Equal(File.ReadAllBytes(firstOutput), File.ReadAllBytes(secondOutput));
        using var archive = ZipFile.OpenRead(firstOutput);
        Assert.Contains(archive.Entries, entry =>
            entry.FullName == "package/services/metadata/core-properties/metadata.psmdcp");
        Assert.All(archive.Entries, entry =>
            Assert.Equal(new DateTime(2000, 1, 1, 0, 0, 0), entry.LastWriteTime.DateTime));
    }

    [Fact]
    public void UnsafeEntryPathIsRejected()
    {
        using var directory = new TemporaryDirectory();
        var input = Path.Combine(directory.Path, "hostile.nupkg");
        using (var archive = ZipFile.Open(input, ZipArchiveMode.Create))
        {
            Write(archive, "../escape", [1]);
        }

        Assert.Throws<InvalidDataException>(() => DeterministicNuGetPackage.Normalize(
            input,
            Path.Combine(directory.Path, "output.nupkg")));
    }

    private static void CreatePackage(
        string path,
        string coreName,
        string relationshipId,
        DateTimeOffset timestamp)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        var corePath = $"package/services/metadata/core-properties/{coreName}.psmdcp";
        var relationships = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
              <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/SharpTls.nuspec" Id="MANIFEST" />
              <Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="/{corePath}" Id="{relationshipId}" />
            </Relationships>
            """;
        Write(archive, "_rels/.rels", Encoding.UTF8.GetBytes(relationships), timestamp);
        Write(archive, corePath, "same-core-properties"u8.ToArray(), timestamp);
        Write(archive, "SharpTls.nuspec", "same-manifest"u8.ToArray(), timestamp);
    }

    private static void Write(
        ZipArchive archive,
        string name,
        byte[] content,
        DateTimeOffset? timestamp = null)
    {
        var entry = archive.CreateEntry(name);
        if (timestamp.HasValue) entry.LastWriteTime = timestamp.Value;
        using var stream = entry.Open();
        stream.Write(content);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        internal TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "SharpTls.PackageTests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        internal string Path { get; }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}

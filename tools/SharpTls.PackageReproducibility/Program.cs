using SharpTls.Packaging;

if (args.Length != 2)
{
    throw new ArgumentException(
        "Usage: SharpTls.PackageReproducibility <input.nupkg|input.snupkg> <output-path>");
}

DeterministicNuGetPackage.Normalize(args[0], args[1]);
Console.WriteLine($"Normalized deterministic NuGet package: {Path.GetFullPath(args[1])}");

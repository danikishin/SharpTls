using SharpTls;
using SharpTls.ApiCompatibility;

if (args.Length != 0)
{
    throw new ArgumentException("SharpTls.ApiCompat does not accept arguments.");
}

Console.Write(PublicApiContract.Generate(typeof(CustomTlsClient).Assembly));

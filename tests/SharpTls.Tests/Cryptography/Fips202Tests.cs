using SharpTls.Cryptography;

namespace SharpTls.Tests.Cryptography;

public sealed class Fips202Tests
{
    [Theory]
    [InlineData(136, 32,
        "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A")]
    [InlineData(72, 64,
        "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6" +
        "15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26")]
    public void ManagedSha3EmptyMessageMatchesFips202(
        int rate,
        int outputLength,
        string expectedHex)
    {
        using var hash = new Fips202.Xof(rate, domainSeparator: 0x06);
        Assert.Equal(expectedHex, Convert.ToHexString(hash.Read(outputLength)));
    }

    [Theory]
    [InlineData(168, 32,
        "7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF26")]
    [InlineData(136, 64,
        "46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F" +
        "D75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE")]
    public void ManagedShakeEmptyMessageMatchesFips202(
        int rate,
        int outputLength,
        string expectedHex)
    {
        using var hash = new Fips202.Xof(rate, domainSeparator: 0x1F);
        Assert.Equal(expectedHex, Convert.ToHexString(hash.Read(outputLength)));
    }

    [Fact]
    public void XofSupportsIncrementalReadsCloningAndStrictStateTransitions()
    {
        using var hash = Fips202.CreateShake256();
        hash.AppendData("abc"u8);
        var beforeSqueeze = hash.GetCurrentHash(64);
        var first = hash.Read(17);
        var second = hash.Read(47);

        Assert.Equal(beforeSqueeze, first.Concat(second).ToArray());
        Assert.Throws<InvalidOperationException>(() => hash.AppendData([1]));
    }
}

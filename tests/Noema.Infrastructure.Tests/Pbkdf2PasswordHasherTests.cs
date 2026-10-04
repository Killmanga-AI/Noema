using Noema.Infrastructure.Security;

namespace Noema.Infrastructure.Tests;

public sealed class Pbkdf2PasswordHasherTests
{
    // Low cost keeps the tests fast. Production uses the configured cost, which is never below 100,000.
    private readonly Pbkdf2PasswordHasher hasher = new(1_000);

    [Fact]
    public void A_hash_verifies_the_password_it_was_made_from()
    {
        var hash = hasher.Hash("correct horse battery staple");

        Assert.Equal(PasswordVerification.Success, hasher.Verify(hash, "correct horse battery staple"));
    }

    [Theory]
    [InlineData("correct horse battery stapl")]
    [InlineData("Correct horse battery staple")]
    [InlineData("")]
    [InlineData(" correct horse battery staple")]
    public void A_different_password_fails(string attempt)
    {
        var hash = hasher.Hash("correct horse battery staple");

        Assert.Equal(PasswordVerification.Failed, hasher.Verify(hash, attempt));
    }

    [Fact]
    public void The_same_password_gets_a_different_hash_each_time()
    {
        Assert.NotEqual(hasher.Hash("same password here"), hasher.Hash("same password here"));
    }

    [Fact]
    public void The_hash_does_not_contain_the_password_and_uses_the_documented_format()
    {
        var hash = hasher.Hash("super secret passphrase");

        Assert.DoesNotContain("super secret passphrase", hash);
        var parts = hash.Split('$');
        Assert.Equal(4, parts.Length);
        Assert.Equal("pbkdf2-sha256", parts[0]);
        Assert.Equal("1000", parts[1]);
    }

    [Fact]
    public void Unicode_passwords_round_trip()
    {
        var hash = hasher.Hash("pässwörd-密码-🔐-long-enough");

        Assert.Equal(PasswordVerification.Success, hasher.Verify(hash, "pässwörd-密码-🔐-long-enough"));
        Assert.Equal(PasswordVerification.Failed, hasher.Verify(hash, "passwoerd-密码-🔐-long-enough"));
    }

    [Fact]
    public void A_hash_made_with_a_lower_cost_asks_to_be_replaced()
    {
        var weak = new Pbkdf2PasswordHasher(1_000).Hash("another long password");
        var strong = new Pbkdf2PasswordHasher(2_000);

        Assert.Equal(PasswordVerification.SuccessRehashNeeded, strong.Verify(weak, "another long password"));
        Assert.Equal(PasswordVerification.Success, strong.Verify(strong.Hash("another long password"), "another long password"));
        Assert.Equal(PasswordVerification.Failed, strong.Verify(weak, "wrong password here"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a hash")]
    [InlineData("pbkdf2-sha256$1000$AAAA")]
    [InlineData("pbkdf2-sha256$abc$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("pbkdf2-sha256$-5$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("pbkdf2-sha256$999$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("pbkdf2-sha256$99999999999$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("pbkdf2-sha256$1000$!!!notbase64!!!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    [InlineData("md5$1000$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    public void Malformed_or_unsupported_hashes_fail_instead_of_throwing(string stored)
    {
        Assert.Equal(PasswordVerification.Failed, hasher.Verify(stored, "any password at all"));
    }

    [Fact]
    public void A_null_password_fails_verification()
    {
        Assert.Equal(PasswordVerification.Failed, hasher.Verify(hasher.Hash("a real password"), null!));
    }

    [Fact]
    public void Hashing_requires_a_password_and_a_sensible_cost()
    {
        Assert.Throws<ArgumentNullException>(() => hasher.Hash(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(10));
    }

    [Fact]
    public void SimulateVerify_runs_without_throwing_for_any_input()
    {
        hasher.SimulateVerify("anything");
        hasher.SimulateVerify(string.Empty);
        hasher.SimulateVerify(null!);
    }
}

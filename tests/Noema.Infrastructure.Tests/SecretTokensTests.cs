using Noema.Infrastructure.Security;

namespace Noema.Infrastructure.Tests;

public sealed class SecretTokensTests
{
    [Fact]
    public void Enrollment_tokens_and_agent_secrets_have_recognisable_prefixes_and_enough_length()
    {
        var enrollment = SecretTokens.NewEnrollmentToken();
        var secret = SecretTokens.NewAgentSecret();

        Assert.StartsWith("nmt_", enrollment);
        Assert.StartsWith("nma_", secret);
        Assert.True(enrollment.Length >= 4 + 43);
        Assert.True(secret.Length >= 4 + 43);
    }

    [Fact]
    public void Secrets_are_unique_and_url_safe()
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < 200; i++)
        {
            var token = SecretTokens.NewEnrollmentToken();
            Assert.True(seen.Add(token));
            Assert.True(token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
        }
    }

    [Fact]
    public void Hashing_is_stable_and_does_not_reveal_the_secret()
    {
        var secret = SecretTokens.NewAgentSecret();

        var hash = SecretTokens.Hash(secret);

        Assert.Equal(hash, SecretTokens.Hash(secret));
        Assert.NotEqual(hash, SecretTokens.Hash(secret + "x"));
        Assert.DoesNotContain(secret, hash);
        Assert.Equal(44, hash.Length);
    }

    [Fact]
    public void Matches_accepts_the_right_secret_and_nothing_else()
    {
        var secret = SecretTokens.NewAgentSecret();
        var hash = SecretTokens.Hash(secret);

        Assert.True(SecretTokens.Matches(secret, hash));
        Assert.False(SecretTokens.Matches(secret + "x", hash));
        Assert.False(SecretTokens.Matches(SecretTokens.NewAgentSecret(), hash));
        Assert.False(SecretTokens.Matches(secret.ToUpperInvariant(), hash));
    }

    [Theory]
    [InlineData(null, "hash")]
    [InlineData("", "hash")]
    [InlineData("secret", null)]
    [InlineData("secret", "")]
    [InlineData(null, null)]
    public void Matches_refuses_missing_values(string? presented, string? stored)
    {
        Assert.False(SecretTokens.Matches(presented, stored));
    }

    [Fact]
    public void Hashing_requires_a_value()
    {
        Assert.Throws<ArgumentNullException>(() => SecretTokens.Hash(null!));
    }
}

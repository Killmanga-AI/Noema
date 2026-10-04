using Noema.Api.Security;

namespace Noema.Api.Tests;

public sealed class JwtOptionsValidatorTests
{
    private readonly JwtOptionsValidator validator = new();

    private static JwtOptions Valid() => new() { SigningKey = TestSecrets.SigningKey };

    [Fact]
    public void Accepts_a_good_configuration()
    {
        Assert.True(validator.Validate(null, Valid()).Succeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base64 at all!")]
    [InlineData("c2hvcnQ=")]
    [InlineData("replace-with-the-output-of-openssl-rand-base64-48")]
    public void Rejects_missing_malformed_or_short_signing_keys(string key)
    {
        var options = Valid();
        options.SigningKey = key;

        var result = validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("SigningKey", result.FailureMessage);
    }

    [Fact]
    public void Accepts_a_key_of_exactly_32_bytes()
    {
        var options = Valid();
        options.SigningKey = Convert.ToBase64String(new byte[32]);

        Assert.True(validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Rejects_a_key_of_31_bytes()
    {
        var options = Valid();
        options.SigningKey = Convert.ToBase64String(new byte[31]);

        Assert.True(validator.Validate(null, options).Failed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(61)]
    public void Rejects_access_token_lifetimes_outside_the_range(int minutes)
    {
        var options = Valid();
        options.AccessTokenMinutes = minutes;

        Assert.Contains("AccessTokenMinutes", validator.Validate(null, options).FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(91)]
    public void Rejects_refresh_token_lifetimes_outside_the_range(int days)
    {
        var options = Valid();
        options.RefreshTokenDays = days;

        Assert.Contains("RefreshTokenDays", validator.Validate(null, options).FailureMessage);
    }

    [Fact]
    public void Rejects_blank_issuer_and_audience()
    {
        var options = Valid();
        options.Issuer = " ";
        options.Audience = "";

        var result = validator.Validate(null, options);

        Assert.Contains("Issuer", result.FailureMessage);
        Assert.Contains("Audience", result.FailureMessage);
    }
}

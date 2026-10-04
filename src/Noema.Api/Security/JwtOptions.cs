using Microsoft.Extensions.Options;

namespace Noema.Api.Security;

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";

    public string Issuer { get; set; } = "noema";

    public string Audience { get; set; } = "noema-api";

    /// <summary>Base64 text of at least 32 random bytes. Generate one with: openssl rand -base64 48</summary>
    public string SigningKey { get; set; } = string.Empty;

    public int AccessTokenMinutes { get; set; } = 15;

    public int RefreshTokenDays { get; set; } = 7;
}

public sealed class JwtOptionsValidator : IValidateOptions<JwtOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            failures.Add("Jwt:Issuer is required.");
        }

        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            failures.Add("Jwt:Audience is required.");
        }

        var buffer = new byte[options.SigningKey.Length];
        if (!Convert.TryFromBase64String(options.SigningKey, buffer, out var written) || written < 32)
        {
            failures.Add("Jwt:SigningKey must be base64 text of at least 32 bytes, for example the output of: openssl rand -base64 48");
        }

        if (options.AccessTokenMinutes is < 1 or > 60)
        {
            failures.Add("Jwt:AccessTokenMinutes must be between 1 and 60.");
        }

        if (options.RefreshTokenDays is < 1 or > 90)
        {
            failures.Add("Jwt:RefreshTokenDays must be between 1 and 90.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}

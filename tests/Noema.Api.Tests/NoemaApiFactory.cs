using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Noema.Api.Tests;

public static class TestSecrets
{
    /// <summary>A throwaway signing key used only by tests. It is not used anywhere else.</summary>
    public const string SigningKey = "dGVzdC1vbmx5LXNpZ25pbmcta2V5LTAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ei1BQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWi0wMTIzNDU2Nzg5";

    public const string OtherSigningKey = "b3RoZXItdGVzdC1vbmx5LXNpZ25pbmcta2V5LTAxMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ei1BQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWi0wMTIzNDU2Nzg5";
}

public class NoemaApiFactory(string connectionString) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // "Testing" keeps appsettings.Development.json out of the picture.
        builder.UseEnvironment("Testing");
        builder.UseSetting("Database:ConnectionString", connectionString);
        builder.UseSetting("Jwt:SigningKey", TestSecrets.SigningKey);

        // Tests sign in a lot from one address, and hashing at full cost would make them slow.
        builder.UseSetting("Security:AuthRateLimitPerMinute", "1000");
        builder.UseSetting("Security:PasswordHashIterations", "100000");
    }
}

/// <summary>
/// Points at a port nothing listens on, so no Docker is needed to test the unhealthy paths.
/// </summary>
public sealed class UnreachableDatabaseFactory : NoemaApiFactory
{
    public UnreachableDatabaseFactory()
        : base("Host=127.0.0.1;Port=1;Database=noema;Username=test;Password=test;Timeout=1;Command Timeout=1")
    {
    }
}

/// <summary>Same as the unreachable database factory but with a very low sign in limit.</summary>
public sealed class TightRateLimitFactory : NoemaApiFactory
{
    public TightRateLimitFactory()
        : base("Host=127.0.0.1;Port=1;Database=noema;Username=test;Password=test;Timeout=1;Command Timeout=1")
    {
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Security:AuthRateLimitPerMinute", "3");
    }
}

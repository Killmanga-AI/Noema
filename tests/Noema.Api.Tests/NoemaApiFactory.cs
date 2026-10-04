using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Noema.Api.Tests;

public class NoemaApiFactory(string connectionString) : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // "Testing" keeps appsettings.Development.json out of the picture.
        builder.UseEnvironment("Testing");
        builder.UseSetting("Database:ConnectionString", connectionString);
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

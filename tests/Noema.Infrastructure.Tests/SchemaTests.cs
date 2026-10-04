using Microsoft.EntityFrameworkCore;

namespace Noema.Infrastructure.Tests;

[Collection(PostgresCollection.Name)]
[Trait("Category", "Docker")]
public sealed class SchemaTests(PostgresFixture postgres)
{
    private async Task<List<string>> QueryAsync(string sql)
    {
        await using var context = postgres.CreateContext();
        return await context.Database.SqlQueryRaw<string>(sql).ToListAsync();
    }

    [Fact]
    public async Task All_expected_tables_exist()
    {
        var tables = await QueryAsync(
            "SELECT table_name AS \"Value\" FROM information_schema.tables WHERE table_schema = 'public'");

        foreach (var expected in new[] { "assets", "asset_interfaces", "interface_addresses", "scan_runs", "observations" })
        {
            Assert.Contains(expected, tables);
        }
    }

    [Fact]
    public async Task Column_names_are_snake_case()
    {
        var columns = await QueryAsync(
            "SELECT column_name AS \"Value\" FROM information_schema.columns " +
            "WHERE table_schema = 'public' AND table_name <> '__EFMigrationsHistory'");

        Assert.NotEmpty(columns);
        Assert.All(columns, c => Assert.Equal(c.ToLowerInvariant(), c));
        Assert.Contains("first_seen_at", columns);
        Assert.Contains("hostname_observed_at", columns);
        Assert.Contains("asset_interface_id", columns);
    }

    [Theory]
    [InlineData("asset_interfaces", "mac_address", "macaddr")]
    [InlineData("observations", "mac_address", "macaddr")]
    [InlineData("interface_addresses", "address", "inet")]
    [InlineData("observations", "address", "inet")]
    [InlineData("observations", "detail_json", "jsonb")]
    [InlineData("assets", "first_seen_at", "timestamptz")]
    public async Task Columns_use_the_native_postgres_types(string table, string column, string expectedType)
    {
        var types = await QueryAsync(
            $"SELECT udt_name AS \"Value\" FROM information_schema.columns " +
            $"WHERE table_schema = 'public' AND table_name = '{table}' AND column_name = '{column}'");

        Assert.Equal(expectedType, Assert.Single(types));
    }
}

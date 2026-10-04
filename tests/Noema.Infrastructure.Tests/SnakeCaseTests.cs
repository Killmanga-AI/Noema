using Noema.Infrastructure.Persistence;

namespace Noema.Infrastructure.Tests;

public sealed class SnakeCaseTests
{
    [Theory]
    [InlineData("Id", "id")]
    [InlineData("Name", "name")]
    [InlineData("MacAddress", "mac_address")]
    [InlineData("FirstSeenAt", "first_seen_at")]
    [InlineData("AssetInterfaceId", "asset_interface_id")]
    [InlineData("DetailJson", "detail_json")]
    [InlineData("IPAddress", "ip_address")]
    [InlineData("xmin", "xmin")]
    [InlineData("already_snake", "already_snake")]
    public void Converts_property_names(string input, string expected)
    {
        Assert.Equal(expected, SnakeCase.From(input));
    }
}

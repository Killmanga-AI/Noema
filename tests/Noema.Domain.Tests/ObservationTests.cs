using System.Net;

namespace Noema.Domain.Tests;

public sealed class ObservationTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid RunId = Guid.NewGuid();
    private static readonly IPAddress Host = IPAddress.Parse("192.168.1.20");
    private static readonly MacAddress Mac = MacAddress.Parse("aa:bb:cc:00:00:01");

    [Fact]
    public void Creates_an_observation_with_all_fields()
    {
        var observation = Observation.Create(
            RunId, ObservationKind.TcpPortOpen, Host, T0, null, "{\"port\":443}");

        Assert.NotEqual(Guid.Empty, observation.Id);
        Assert.Equal(RunId, observation.ScanRunId);
        Assert.Equal(ObservationKind.TcpPortOpen, observation.Kind);
        Assert.Equal(Host, observation.Address);
        Assert.Equal(T0, observation.ObservedAt);
        Assert.Equal("{\"port\":443}", observation.DetailJson);
    }

    [Fact]
    public void An_arp_observation_needs_a_mac()
    {
        Assert.Throws<ArgumentException>(() => Observation.Create(RunId, ObservationKind.ArpEntry, Host, T0));

        var observation = Observation.Create(RunId, ObservationKind.ArpEntry, Host, T0, Mac);
        Assert.Equal(Mac, observation.MacAddress);
    }

    [Fact]
    public void Other_kinds_do_not_need_a_mac()
    {
        var observation = Observation.Create(RunId, ObservationKind.IcmpEchoReply, Host, T0);

        Assert.Null(observation.MacAddress);
        Assert.Null(observation.DetailJson);
    }

    [Fact]
    public void Addresses_are_normalized()
    {
        var observation = Observation.Create(RunId, ObservationKind.IcmpEchoReply, IPAddress.Parse("::ffff:192.168.1.20"), T0);

        Assert.Equal(Host, observation.Address);
    }

    [Fact]
    public void Rejects_an_empty_scan_run_id_unknown_kinds_unusable_addresses_and_non_utc_times()
    {
        Assert.Throws<ArgumentException>(() => Observation.Create(Guid.Empty, ObservationKind.IcmpEchoReply, Host, T0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Observation.Create(RunId, (ObservationKind)99, Host, T0));
        Assert.Throws<ArgumentException>(() => Observation.Create(RunId, ObservationKind.IcmpEchoReply, IPAddress.Loopback, T0));
        Assert.Throws<ArgumentException>(() =>
            Observation.Create(RunId, ObservationKind.IcmpEchoReply, Host, new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2))));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"port\":")]
    [InlineData("{'port': 443}")]
    public void Rejects_detail_that_is_not_valid_json(string detail)
    {
        Assert.Throws<ArgumentException>(() => Observation.Create(RunId, ObservationKind.TcpPortOpen, Host, T0, null, detail));
    }

    [Fact]
    public void Blank_detail_becomes_null()
    {
        Assert.Null(Observation.Create(RunId, ObservationKind.TcpPortOpen, Host, T0, null, "   ").DetailJson);
    }

    [Fact]
    public void Rejects_oversized_detail()
    {
        var big = "\"" + new string('a', Observation.MaxDetailLength) + "\"";

        Assert.Throws<ArgumentException>(() => Observation.Create(RunId, ObservationKind.TcpPortOpen, Host, T0, null, big));
    }
}

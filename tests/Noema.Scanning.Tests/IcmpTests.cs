using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Noema.Domain;
using Noema.Scanning.Icmp;

namespace Noema.Scanning.Tests;

public sealed class IcmpProbeTests
{
    private sealed class FakePinger(Func<IPAddress, IcmpReply> reply) : IIcmpPinger
    {
        public Task<IcmpReply> PingAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(reply(target));
    }

    private static readonly IPAddress Host = IPAddress.Parse("192.168.1.20");

    private static IcmpProbe Probe(IcmpReply reply, TimeProvider? time = null) =>
        new(new FakePinger(_ => reply), time ?? new FakeTimeProvider());

    [Fact]
    public void Identifies_itself_as_the_icmp_discovery_probe()
    {
        var probe = Probe(new IcmpReply(IcmpStatus.Success));

        Assert.Equal(ScanProbes.Icmp, probe.Kind);
        Assert.Equal(ProbePhase.Discovery, probe.Phase);
    }

    [Fact]
    public async Task A_reply_becomes_an_echo_observation_with_timing_detail()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 4, 12, 0, 0, TimeSpan.Zero));
        var probe = Probe(new IcmpReply(IcmpStatus.Success, TimeSpan.FromMilliseconds(1.236), 64), time);

        var result = await probe.ProbeAsync(Host, TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.Equal(ProbeStatus.Responded, result.Status);
        var observation = Assert.Single(result.Observations);
        Assert.Equal(ObservationKind.IcmpEchoReply, observation.Kind);
        Assert.Equal(Host, observation.Address);
        Assert.Equal(new DateTimeOffset(2026, 10, 4, 12, 0, 0, TimeSpan.Zero), observation.ObservedAt);

        using var detail = JsonDocument.Parse(observation.DetailJson!);
        Assert.Equal(1.24, detail.RootElement.GetProperty("rttMs").GetDouble());
        Assert.Equal(64, detail.RootElement.GetProperty("ttl").GetInt32());
    }

    [Fact]
    public async Task A_reply_without_a_ttl_leaves_it_out()
    {
        var result = await Probe(new IcmpReply(IcmpStatus.Success, TimeSpan.FromMilliseconds(2))).ProbeAsync(Host, TimeSpan.FromSeconds(1), CancellationToken.None);

        using var detail = JsonDocument.Parse(result.Observations[0].DetailJson!);
        Assert.False(detail.RootElement.TryGetProperty("ttl", out _));
    }

    [Fact]
    public async Task The_observation_converts_to_a_valid_stored_observation()
    {
        var result = await Probe(new IcmpReply(IcmpStatus.Success, TimeSpan.FromMilliseconds(2), 128)).ProbeAsync(Host, TimeSpan.FromSeconds(1), CancellationToken.None);

        var stored = result.Observations[0].ToDomain(Guid.NewGuid());

        Assert.Equal(ObservationKind.IcmpEchoReply, stored.Kind);
        Assert.Equal(Host, stored.Address);
    }

    [Theory]
    [InlineData(IcmpStatus.TimedOut)]
    [InlineData(IcmpStatus.Unreachable)]
    public async Task Silence_and_unreachable_answers_mean_no_response_not_an_error(IcmpStatus status)
    {
        var result = await Probe(new IcmpReply(status)).ProbeAsync(Host, TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.Equal(ProbeStatus.NoResponse, result.Status);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task A_failed_ping_is_an_error_that_names_the_target_and_cause()
    {
        var result = await Probe(new IcmpReply(IcmpStatus.Error, Error: "Permission denied")).ProbeAsync(Host, TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.Equal(ProbeStatus.Error, result.Status);
        Assert.Contains("192.168.1.20", result.Error);
        Assert.Contains("Permission denied", result.Error);
    }

    [Fact]
    public async Task The_target_and_timeout_are_passed_to_the_pinger()
    {
        IPAddress? seen = null;
        TimeSpan seenTimeout = default;
        var pinger = new RecordingPinger((target, timeout) => { seen = target; seenTimeout = timeout; });
        var probe = new IcmpProbe(pinger, new FakeTimeProvider());

        await probe.ProbeAsync(Host, TimeSpan.FromMilliseconds(750), CancellationToken.None);

        Assert.Equal(Host, seen);
        Assert.Equal(TimeSpan.FromMilliseconds(750), seenTimeout);
    }

    private sealed class RecordingPinger(Action<IPAddress, TimeSpan> record) : IIcmpPinger
    {
        public Task<IcmpReply> PingAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken)
        {
            record(target, timeout);
            return Task.FromResult(new IcmpReply(IcmpStatus.TimedOut));
        }
    }
}

public sealed class SystemIcmpPingerTests
{
    [Theory]
    [InlineData(IPStatus.Success, IcmpStatus.Success)]
    [InlineData(IPStatus.TimedOut, IcmpStatus.TimedOut)]
    [InlineData(IPStatus.DestinationHostUnreachable, IcmpStatus.Unreachable)]
    [InlineData(IPStatus.DestinationNetworkUnreachable, IcmpStatus.Unreachable)]
    [InlineData(IPStatus.DestinationProhibited, IcmpStatus.Unreachable)]
    [InlineData(IPStatus.TtlExpired, IcmpStatus.Unreachable)]
    [InlineData(IPStatus.BadOption, IcmpStatus.Error)]
    [InlineData(IPStatus.HardwareError, IcmpStatus.Error)]
    [InlineData(IPStatus.PacketTooBig, IcmpStatus.Error)]
    [InlineData(IPStatus.Unknown, IcmpStatus.Error)]
    public void Operating_system_statuses_map_to_the_probe_statuses(IPStatus status, IcmpStatus expected)
    {
        Assert.Equal(expected, SystemIcmpPinger.Map(status));
    }

    [Fact]
    [Trait("Category", "Network")]
    public async Task Pinging_loopback_either_succeeds_or_reports_a_clean_error()
    {
        // Some CI runners (Linux without cap_net_raw) cannot send ICMP at all.
        // The pinger is a thin OS wrapper: it either returns a reply or throws
        // PlatformNotSupportedException. The engine's per-probe catch handles the
        // latter and turns it into a probe error, so the scan still fails cleanly.
        IcmpReply reply;
        try
        {
            reply = await new SystemIcmpPinger().PingAsync(IPAddress.Loopback, TimeSpan.FromSeconds(2), CancellationToken.None);
        }
        catch (PlatformNotSupportedException)
        {
            // No ICMP capability on this host — that is the expected "clean failure" path.
            return;
        }

        Assert.True(reply.Status is IcmpStatus.Success or IcmpStatus.Error or IcmpStatus.TimedOut);
        if (reply.Status == IcmpStatus.Success)
        {
            Assert.True(reply.RoundTrip >= TimeSpan.Zero);
        }
    }

    [Fact]
    public async Task A_cancelled_ping_throws_instead_of_reporting_an_error()
    {
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SystemIcmpPinger().PingAsync(IPAddress.Loopback, TimeSpan.FromSeconds(2), new CancellationToken(true)));
    }

    [Fact]
    public async Task A_null_target_is_rejected()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => new SystemIcmpPinger().PingAsync(null!, TimeSpan.FromSeconds(1), CancellationToken.None));
    }
}

using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent.Tests;

public sealed class ScanCommandParsingTests
{
    [Theory]
    [InlineData("scan")]
    [InlineData("SCAN")]
    [InlineData("Scan")]
    public void Recognises_the_scan_command_in_any_case(string word)
    {
        Assert.True(ScanCommand.IsScanCommand([word, "192.168.1.0/24"]));
    }

    [Fact]
    public void Other_arguments_are_not_the_scan_command()
    {
        Assert.False(ScanCommand.IsScanCommand([]));
        Assert.False(ScanCommand.IsScanCommand(["--urls", "http://localhost"]));
        Assert.False(ScanCommand.IsScanCommand(["scanner"]));
    }

    [Fact]
    public void Parses_a_target_and_defaults_to_icmp()
    {
        var result = ScanCommand.Parse(["scan", "192.168.1.0/24"]);

        Assert.Null(result.Error);
        Assert.Equal(CidrRange.Parse("192.168.1.0/24"), result.Arguments!.Target);
        Assert.Equal(ScanProbes.Icmp, result.Arguments.Probes);
    }

    [Theory]
    [InlineData("Icmp", ScanProbes.Icmp)]
    [InlineData("icmp,arp", ScanProbes.Icmp | ScanProbes.Arp)]
    [InlineData("Icmp, Dns ,Tcp", ScanProbes.Icmp | ScanProbes.Dns | ScanProbes.Tcp)]
    [InlineData("ICMP,icmp", ScanProbes.Icmp)]
    public void Parses_probe_lists(string list, ScanProbes expected)
    {
        var result = ScanCommand.Parse(["scan", "10.0.0.0/24", "--probes", list]);

        Assert.Equal(expected, result.Arguments!.Probes);
    }

    [Fact]
    public void The_probes_option_can_come_before_the_target()
    {
        var result = ScanCommand.Parse(["scan", "--probes", "Arp", "10.0.0.0/24"]);

        Assert.Equal(ScanProbes.Arp, result.Arguments!.Probes);
        Assert.Equal(CidrRange.Parse("10.0.0.0/24"), result.Arguments.Target);
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("scan|--probes")]
    [InlineData("scan|10.0.0.0/24|--probes")]
    [InlineData("scan|10.0.0.0/24|--probes|")]
    [InlineData("scan|10.0.0.0/24|--probes|Teleport")]
    [InlineData("scan|10.0.0.0/24|--probes|3")]
    [InlineData("scan|10.0.0.0/24|--probes|None")]
    [InlineData("scan|10.0.0.0/24|--probes|Icmp,Arp,")]
    [InlineData("scan|10.0.0.0/24|--verbose")]
    [InlineData("scan|10.0.0.0/24|10.0.1.0/24")]
    [InlineData("scan|192.168.1.5/24")]
    [InlineData("scan|10.1/16")]
    [InlineData("scan|not-a-range")]
    public void Bad_input_gives_an_error_and_no_arguments(string joined)
    {
        var result = ScanCommand.Parse(joined.Split('|'));

        Assert.Null(result.Arguments);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }
}

public sealed class ScanCommandRunTests
{
    private sealed class LiveHostsProbe(TimeProvider time, params string[] live) : IProbe
    {
        private readonly HashSet<IPAddress> hosts = live.Select(IPAddress.Parse).ToHashSet();

        public ScanProbes Kind => ScanProbes.Icmp;

        public ProbePhase Phase => ProbePhase.Discovery;

        public ValueTask<ProbeResult> ProbeAsync(IPAddress target, TimeSpan timeout, CancellationToken cancellationToken) =>
            ValueTask.FromResult(hosts.Contains(target)
                ? ProbeResult.Responded(new ProbeObservation(
                    ObservationKind.IcmpEchoReply, target, time.GetUtcNow(), DetailJson: "{\"rttMs\":1.5,\"ttl\":64}"))
                : ProbeResult.NoResponse);
    }

    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(v => v.Key, v => (string?)v.Value)).Build();

    private static Func<ScanningOptions, TimeProvider, ScanEngine> FakeEngine(params string[] live) =>
        (options, time) => new ScanEngine([new LiveHostsProbe(time, live)], options.BuildScope(), options.BuildEngineOptions(), NoRateLimiter.Instance, time);

    private static async Task<(int Code, string Out, string Err)> RunAsync(
        string[] args, IConfiguration configuration, Func<ScanningOptions, TimeProvider, ScanEngine>? factory = null, CancellationToken token = default)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var code = await ScanCommand.RunAsync(args, output, error, configuration, new FakeTimeProvider(), token, factory);
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public async Task A_scan_inside_the_configured_scope_prints_the_hosts_and_a_summary()
    {
        var (code, output, error) = await RunAsync(
            ["scan", "192.168.1.0/28"],
            Config(("Scanning:AllowedRanges:0", "192.168.1.0/24")),
            FakeEngine("192.168.1.3", "192.168.1.9"));

        Assert.Equal(0, code);
        Assert.Contains("192.168.1.3", output);
        Assert.Contains("192.168.1.9", output);
        Assert.Contains("1.5 ms", output);
        Assert.Contains("ttl=64", output);
        Assert.Contains("2 hosts answered out of 14 of 14", output);
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public async Task A_scan_outside_the_configured_scope_is_refused_with_exit_code_1()
    {
        var (code, output, _) = await RunAsync(
            ["scan", "10.0.0.0/24"],
            Config(("Scanning:AllowedRanges:0", "192.168.1.0/24")),
            FakeEngine("10.0.0.5"));

        Assert.Equal(1, code);
        Assert.Contains("Refused", output);
        Assert.DoesNotContain("10.0.0.5  ", output);
    }

    [Fact]
    public async Task With_no_allowed_ranges_every_scan_is_refused()
    {
        var (code, output, _) = await RunAsync(["scan", "192.168.1.0/28"], Config(), FakeEngine("192.168.1.3"));

        Assert.Equal(1, code);
        Assert.Contains("Refused", output);
    }

    [Fact]
    public async Task Bad_arguments_exit_with_code_2_and_a_usage_message()
    {
        var (code, output, error) = await RunAsync(["scan"], Config());

        Assert.Equal(2, code);
        Assert.Contains("Usage", error);
        Assert.Equal(string.Empty, output);
    }

    [Fact]
    public async Task Invalid_scanning_settings_exit_with_code_2_and_name_the_problem()
    {
        var (code, _, error) = await RunAsync(
            ["scan", "192.168.1.0/28"],
            Config(("Scanning:AllowedRanges:0", "8.8.8.0/24")),
            FakeEngine());

        Assert.Equal(2, code);
        Assert.Contains("Scanning:AllowedRanges", error);
    }

    [Fact]
    public async Task A_cancelled_scan_exits_with_code_130()
    {
        var (code, output, _) = await RunAsync(
            ["scan", "192.168.1.0/24"],
            Config(("Scanning:AllowedRanges:0", "192.168.1.0/24")),
            FakeEngine(),
            new CancellationToken(true));

        Assert.Equal(130, code);
        Assert.Contains("Cancelled", output);
    }

    [Fact]
    public async Task Settings_come_from_configuration_including_the_size_limit()
    {
        var (code, output, _) = await RunAsync(
            ["scan", "192.168.1.0/24"],
            Config(("Scanning:AllowedRanges:0", "192.168.1.0/24"), ("Scanning:MaxAddressesPerScan", "100")),
            FakeEngine());

        Assert.Equal(1, code);
        Assert.Contains("Refused", output);
    }
}

public sealed class ConsoleObservationSinkTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Formats_an_icmp_reply_with_round_trip_time_and_ttl()
    {
        var line = ConsoleObservationSink.FormatLine(new ProbeObservation(
            ObservationKind.IcmpEchoReply, IPAddress.Parse("192.168.1.1"), T0, DetailJson: "{\"rttMs\":0.84,\"ttl\":64}"));

        Assert.Equal("192.168.1.1     icmp  0.8 ms ttl=64", line);
    }

    [Fact]
    public void Includes_the_mac_address_when_there_is_one()
    {
        var line = ConsoleObservationSink.FormatLine(new ProbeObservation(
            ObservationKind.ArpEntry, IPAddress.Parse("192.168.1.7"), T0, MacAddress.Parse("aa:bb:cc:00:00:01")));

        Assert.Equal("192.168.1.7     arp   aa:bb:cc:00:00:01", line);
    }

    [Fact]
    public void Shows_unknown_detail_fields_as_name_equals_value()
    {
        var line = ConsoleObservationSink.FormatLine(new ProbeObservation(
            ObservationKind.TcpPortOpen, IPAddress.Parse("10.0.0.2"), T0, DetailJson: "{\"port\":443}"));

        Assert.Equal("10.0.0.2        tcp   port=443", line);
    }

    [Fact]
    public void Survives_detail_that_is_not_the_expected_shape()
    {
        var odd = ConsoleObservationSink.FormatLine(new ProbeObservation(
            ObservationKind.SnmpSystemInfo, IPAddress.Parse("10.0.0.2"), T0, DetailJson: "[1,2]"));
        var broken = ConsoleObservationSink.FormatLine(new ProbeObservation(
            ObservationKind.SnmpSystemInfo, IPAddress.Parse("10.0.0.2"), T0, DetailJson: "{oops"));

        Assert.StartsWith("10.0.0.2", odd);
        Assert.Contains("{oops", broken);
    }

    [Fact]
    public async Task Writes_one_line_per_observation()
    {
        var writer = new StringWriter();
        var sink = new ConsoleObservationSink(writer);

        await sink.WriteAsync(new ProbeObservation(ObservationKind.IcmpEchoReply, IPAddress.Parse("192.168.1.1"), T0), CancellationToken.None);
        await sink.WriteAsync(new ProbeObservation(ObservationKind.IcmpEchoReply, IPAddress.Parse("192.168.1.2"), T0), CancellationToken.None);

        Assert.Equal(2, writer.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
    }
}

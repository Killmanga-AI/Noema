using System.Net;

namespace Noema.Domain.Tests;

public sealed class AgentTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly CidrRange Lan = CidrRange.Parse("192.168.1.0/24");

    private static Agent NewAgent(
        string name = "office-agent",
        ScanProbes capabilities = ScanProbes.Icmp,
        params string[] ranges) =>
        Agent.Enroll(name, "hash", T0, "1.0.0", "Linux 6.1", capabilities, (ranges.Length == 0 ? ["192.168.1.0/24"] : ranges).Select(CidrRange.Parse));

    [Fact]
    public void Enrolling_creates_an_active_agent_that_has_just_been_seen()
    {
        var agent = Agent.Enroll("  Office Agent  ", "hash-1", T0, "1.2.3", "Ubuntu 24.04", ScanProbes.Icmp | ScanProbes.Arp, [Lan], IPAddress.Parse("192.168.1.9"));

        Assert.NotEqual(Guid.Empty, agent.Id);
        Assert.Equal("Office Agent", agent.Name);
        Assert.Equal("hash-1", agent.CredentialHash);
        Assert.Equal(AgentStatus.Active, agent.Status);
        Assert.Equal(T0, agent.CreatedAt);
        Assert.Equal(T0, agent.LastSeenAt);
        Assert.Equal(IPAddress.Parse("192.168.1.9"), agent.LastSeenAddress);
        Assert.Equal("1.2.3", agent.Version);
        Assert.Equal("Ubuntu 24.04", agent.OperatingSystem);
        Assert.Equal(ScanProbes.Icmp | ScanProbes.Arp, agent.Capabilities);
        Assert.Equal([Lan], agent.ReportedRanges);
        Assert.False(agent.IsRevoked);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("-leading")]
    [InlineData(".leading")]
    [InlineData("bad!name")]
    [InlineData("tab\tname")]
    public void Names_must_follow_the_pattern(string name)
    {
        Assert.Throws<ArgumentException>(() => NewAgent(name));
        Assert.False(Agent.IsValidName(name));
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("Warehouse 2 - north")]
    [InlineData("host.example.com")]
    public void Reasonable_names_are_accepted(string name)
    {
        Assert.True(Agent.IsValidName(name));
        Assert.Equal(name, NewAgent(name).Name);
    }

    [Fact]
    public void Names_over_64_characters_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => NewAgent(new string('a', 65)));
        Assert.NotNull(NewAgent(new string('a', 64)));
    }

    [Fact]
    public void Enrolling_rejects_a_missing_hash_non_utc_time_and_bad_capabilities()
    {
        Assert.Throws<ArgumentException>(() => Agent.Enroll("agent-1", " ", T0, null, null, ScanProbes.Icmp, [Lan]));
        Assert.Throws<ArgumentException>(() =>
            Agent.Enroll("agent-1", "hash", new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2)), null, null, ScanProbes.Icmp, [Lan]));
        Assert.Throws<ArgumentException>(() => Agent.Enroll("agent-1", "hash", T0, null, null, ScanProbes.None, [Lan]));
        Assert.Throws<ArgumentException>(() => Agent.Enroll("agent-1", "hash", T0, null, null, (ScanProbes)1024, [Lan]));
    }

    [Fact]
    public void Reported_ranges_are_deduplicated_and_limited_and_may_not_include_reserved_space()
    {
        var agent = Agent.Enroll("agent-1", "hash", T0, null, null, ScanProbes.Icmp, [Lan, Lan, CidrRange.Parse("10.0.0.0/8")]);
        Assert.Equal(2, agent.ReportedRanges.Count);

        var tooMany = Enumerable.Range(0, Agent.MaxReportedRanges + 1).Select(i => CidrRange.Parse($"10.{i}.0.0/16"));
        Assert.Throws<ArgumentException>(() => Agent.Enroll("agent-1", "hash", T0, null, null, ScanProbes.Icmp, tooMany));

        Assert.Throws<ArgumentException>(() => Agent.Enroll("agent-1", "hash", T0, null, null, ScanProbes.Icmp, [CidrRange.Parse("127.0.0.0/8")]));
        Assert.Throws<ArgumentException>(() => Agent.Enroll("agent-1", "hash", T0, null, null, ScanProbes.Icmp, [CidrRange.Parse("0.0.0.0/0")]));
    }

    [Fact]
    public void Contact_refreshes_what_the_agent_reports()
    {
        var agent = NewAgent();

        agent.RecordContact(T0.AddMinutes(5), IPAddress.Parse("::ffff:10.0.0.7"), "2.0.0", "Windows 11", ScanProbes.Icmp | ScanProbes.Tcp, [CidrRange.Parse("10.0.0.0/24")]);

        Assert.Equal(T0.AddMinutes(5), agent.LastSeenAt);
        Assert.Equal(IPAddress.Parse("10.0.0.7"), agent.LastSeenAddress);
        Assert.Equal("2.0.0", agent.Version);
        Assert.Equal("Windows 11", agent.OperatingSystem);
        Assert.Equal(ScanProbes.Icmp | ScanProbes.Tcp, agent.Capabilities);
        Assert.Equal([CidrRange.Parse("10.0.0.0/24")], agent.ReportedRanges);
    }

    [Fact]
    public void Long_version_and_os_text_is_truncated_and_blank_becomes_null()
    {
        var agent = NewAgent();

        agent.RecordContact(T0, null, new string('v', 200), new string('o', 500), ScanProbes.Icmp, [Lan]);
        Assert.Equal(Agent.MaxVersionLength, agent.Version!.Length);
        Assert.Equal(Agent.MaxOperatingSystemLength, agent.OperatingSystem!.Length);

        agent.RecordContact(T0, null, "   ", null, ScanProbes.Icmp, [Lan]);
        Assert.Null(agent.Version);
        Assert.Null(agent.OperatingSystem);
        Assert.Null(agent.LastSeenAddress);
    }

    [Fact]
    public void Revoking_is_permanent_idempotent_and_keeps_the_first_time()
    {
        var agent = NewAgent();

        agent.Revoke(T0.AddHours(1));
        agent.Revoke(T0.AddHours(2));

        Assert.True(agent.IsRevoked);
        Assert.Equal(AgentStatus.Revoked, agent.Status);
        Assert.Equal(T0.AddHours(1), agent.RevokedAt);
        Assert.Throws<ArgumentException>(() => agent.Revoke(new DateTimeOffset(2026, 10, 4, 14, 0, 0, TimeSpan.FromHours(2))));
    }

    [Theory]
    [InlineData("192.168.1.0/24", ScanProbes.Icmp, true)]
    [InlineData("192.168.1.128/25", ScanProbes.Icmp, true)]
    [InlineData("192.168.1.7/32", ScanProbes.Icmp, true)]
    [InlineData("192.168.2.0/24", ScanProbes.Icmp, false)]
    [InlineData("192.168.0.0/16", ScanProbes.Icmp, false)]
    [InlineData("192.168.1.0/24", ScanProbes.Icmp | ScanProbes.Arp, false)]
    [InlineData("192.168.1.0/24", ScanProbes.Snmp, false)]
    [InlineData("192.168.1.0/24", ScanProbes.None, false)]
    public void An_agent_can_serve_a_scan_only_inside_its_ranges_and_capabilities(string target, ScanProbes probes, bool expected)
    {
        Assert.Equal(expected, NewAgent().CanServe(CidrRange.Parse(target), probes));
    }

    [Fact]
    public void A_revoked_agent_can_serve_nothing()
    {
        var agent = NewAgent();
        agent.Revoke(T0);

        Assert.False(agent.CanServe(Lan, ScanProbes.Icmp));
    }

    [Fact]
    public void Online_means_active_and_seen_within_the_window()
    {
        var agent = NewAgent();

        Assert.True(agent.IsOnline(T0.AddSeconds(30), TimeSpan.FromSeconds(90)));
        Assert.True(agent.IsOnline(T0.AddSeconds(90), TimeSpan.FromSeconds(90)));
        Assert.False(agent.IsOnline(T0.AddSeconds(91), TimeSpan.FromSeconds(90)));

        agent.Revoke(T0);
        Assert.False(agent.IsOnline(T0, TimeSpan.FromSeconds(90)));
    }
}

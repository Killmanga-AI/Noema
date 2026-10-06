using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Noema.Agent.ControlPlane;
using Noema.Agent.Credentials;
using Noema.Scanning;

namespace Noema.Agent.Tests;

public sealed class AgentWorkerTests
{
    private static readonly Uri Server = new("https://noema.example.com/");

    private sealed class FakeStore(AgentCredentials? credentials, Exception? loadFault = null) : ICredentialStore
    {
        public string Location => "/var/lib/noema-agent/agent-credentials.json";

        public AgentCredentials? Load() => loadFault is null ? credentials : throw loadFault;

        public void Save(AgentCredentials value) => throw new NotSupportedException();
    }

    private sealed class FakeFactory(IControlPlaneClient client) : IControlPlaneClientFactory
    {
        public int Created;
        public AgentCredentials? Used;

        public IControlPlaneClient Create(AgentCredentials credentials)
        {
            Created++;
            Used = credentials;
            return client;
        }
    }

    private sealed class Harness
    {
        public FakeControlPlaneClient Client { get; } = new();

        public FakeLifetime Lifetime { get; } = new();

        public FakeTimeProvider Time { get; } = new();

        public int ExitCode { get; private set; }

        public FakeFactory Factory { get; }

        public AgentWorker Worker { get; }

        public Harness(AgentCredentials? credentials, Uri? configuredServer = null, Exception? loadFault = null, TimeSpan? poll = null, string allowed = "192.168.1.0/24")
        {
            Factory = new FakeFactory(Client);
            var engine = TestEngine.Create(FuncProbe.IcmpUp(Time, "192.168.1.5"), Time, allowed);

            Worker = new AgentWorker(
                Options.Create(new AgentOptions
                {
                    ControlPlaneUrl = configuredServer ?? Server,
                    PollInterval = poll ?? TimeSpan.FromSeconds(30),
                    ReportInterval = TimeSpan.FromSeconds(5),
                    MaxBackoff = TimeSpan.FromMinutes(5)
                }),
                Options.Create(new ScanningOptions { AllowedRanges = ["192.168.1.0/24"] }),
                new FakeStore(credentials, loadFault),
                Factory,
                engine,
                Time,
                Lifetime,
                NullLogger<AgentWorker>.Instance,
                () => 0.0,
                code => ExitCode = code);
        }
    }

    private static AgentCredentials Credentials(Uri? server = null) => new(server ?? Server, Guid.NewGuid(), "nma_secret");

    [Fact]
    public async Task An_agent_that_is_not_enrolled_stops_with_an_error_and_never_contacts_the_server()
    {
        var harness = new Harness(null);

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Lifetime.StopCalls == 1, "the agent to stop");

        Assert.Equal(1, harness.ExitCode);
        Assert.Equal(0, harness.Factory.Created);
        Assert.Equal(0, harness.Client.ClaimCalls);
        await harness.Worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_damaged_credential_file_stops_the_agent()
    {
        var harness = new Harness(null, loadFault: new InvalidDataException("damaged"));

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Lifetime.StopCalls == 1, "the agent to stop");

        Assert.Equal(1, harness.ExitCode);
        Assert.Equal(0, harness.Factory.Created);
        await harness.Worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task The_credential_is_never_sent_to_a_server_other_than_the_one_it_was_issued_by()
    {
        var harness = new Harness(Credentials(new Uri("https://noema.example.com/")), configuredServer: new Uri("https://evil.example.net/"));

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Lifetime.StopCalls == 1, "the agent to stop");

        Assert.Equal(1, harness.ExitCode);
        Assert.Equal(0, harness.Factory.Created);
        Assert.Equal(0, harness.Client.ClaimCalls);
        await harness.Worker.StopAsync(CancellationToken.None);
    }

    [Theory]
    [InlineData("https://noema.example.com", "https://noema.example.com/", true)]
    [InlineData("https://NOEMA.example.com/", "https://noema.example.com/api", true)]
    [InlineData("https://noema.example.com:8443/", "https://noema.example.com/", false)]
    [InlineData("http://localhost:8080/", "https://localhost:8080/", false)]
    [InlineData("https://a.example.com/", "https://b.example.com/", false)]
    public void Servers_are_compared_by_scheme_host_and_port(string first, string second, bool expected)
    {
        Assert.Equal(expected, AgentWorker.SameServer(new Uri(first), new Uri(second)));
    }

    [Fact]
    public async Task An_enrolled_agent_checks_in_with_its_probes_and_ranges_and_then_waits_for_the_poll_interval()
    {
        var harness = new Harness(Credentials());

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 1, "the first check in");

        var claim = Assert.Single(harness.Client.Claims);
        Assert.Equal(["Icmp"], claim.Capabilities);
        Assert.Equal(["192.168.1.0/24"], claim.ReportedRanges);
        Assert.False(string.IsNullOrEmpty(claim.Version));

        await Task.Delay(50);
        Assert.Equal(1, harness.Client.ClaimCalls);

        harness.Time.Advance(TimeSpan.FromSeconds(29));
        await Task.Delay(50);
        Assert.Equal(1, harness.Client.ClaimCalls);

        harness.Time.Advance(TimeSpan.FromSeconds(1));
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 2, "the second check in");
        await harness.Worker.StopAsync(CancellationToken.None);
        Assert.Equal(0, harness.Lifetime.StopCalls);
    }

    [Fact]
    public async Task A_refused_credential_stops_the_agent_instead_of_retrying()
    {
        var harness = new Harness(Credentials());
        harness.Client.ClaimBehavior = _ => throw Jobs.Fault(ControlPlaneErrorKind.Unauthorized, "revoked");

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Lifetime.StopCalls == 1, "the agent to stop");

        Assert.Equal(1, harness.ExitCode);
        harness.Time.Advance(TimeSpan.FromMinutes(10));
        await Task.Delay(50);
        Assert.Equal(1, harness.Client.ClaimCalls);
        await harness.Worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task While_the_control_plane_is_unreachable_the_agent_backs_off_further_each_time()
    {
        var harness = new Harness(Credentials(), poll: TimeSpan.FromSeconds(10));
        harness.Client.ClaimBehavior = _ => throw Jobs.Fault(ControlPlaneErrorKind.Transient, "no route");

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 1, "the first attempt");

        // With no jitter the waits are 10 seconds, then 20, then 40.
        harness.Time.Advance(TimeSpan.FromSeconds(9));
        await Task.Delay(50);
        Assert.Equal(1, harness.Client.ClaimCalls);

        harness.Time.Advance(TimeSpan.FromSeconds(1));
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 2, "the second attempt");

        harness.Time.Advance(TimeSpan.FromSeconds(19));
        await Task.Delay(50);
        Assert.Equal(2, harness.Client.ClaimCalls);

        harness.Time.Advance(TimeSpan.FromSeconds(1));
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 3, "the third attempt");
        await harness.Worker.StopAsync(CancellationToken.None);
        Assert.Equal(0, harness.Lifetime.StopCalls);
    }

    [Fact]
    public async Task A_successful_round_resets_the_backoff()
    {
        var harness = new Harness(Credentials(), poll: TimeSpan.FromSeconds(10));
        harness.Client.ClaimBehavior = call => call <= 2 ? throw Jobs.Fault(ControlPlaneErrorKind.Transient, "blip") : null;

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 1, "attempt one");
        harness.Time.Advance(TimeSpan.FromSeconds(10));
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 2, "attempt two");
        harness.Time.Advance(TimeSpan.FromSeconds(20));
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 3, "attempt three, which succeeds");

        // The next wait is the normal poll interval again, not a longer backoff.
        harness.Time.Advance(TimeSpan.FromSeconds(10));
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 4, "the poll after recovery");
        await harness.Worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_claimed_scan_is_run_and_reported_and_the_agent_asks_for_more_straight_away()
    {
        var harness = new Harness(Credentials());
        var job = Jobs.Job("192.168.1.0/28");
        harness.Client.Jobs.Enqueue(job);

        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Client.CompleteCalls == 1, "the scan to be reported");
        await Wait.UntilAsync(() => harness.Client.ClaimCalls >= 2, "the next claim");

        var (scanId, completion) = Assert.Single(harness.Client.Completes);
        Assert.Equal(job.ScanId, scanId);
        Assert.Equal("Completed", completion.Outcome);
        Assert.Equal(1, completion.HostsResponded);
        Assert.Single(harness.Client.Uploads.SelectMany(u => u.Observations));
        await harness.Worker.StopAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Stopping_the_worker_ends_the_loop_quietly()
    {
        var harness = new Harness(Credentials());
        await harness.Worker.StartAsync(CancellationToken.None);
        await Wait.UntilAsync(() => harness.Client.ClaimCalls == 1, "the first check in");

        await harness.Worker.StopAsync(CancellationToken.None);

        Assert.Equal(0, harness.Lifetime.StopCalls);
        Assert.Equal(0, harness.ExitCode);
    }
}

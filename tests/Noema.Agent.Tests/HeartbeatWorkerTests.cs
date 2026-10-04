using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Noema.Agent.Tests;

public sealed class HeartbeatWorkerTests
{
    [Fact]
    public async Task Counts_one_heartbeat_per_interval_and_stops_cleanly()
    {
        var time = new FakeTimeProvider();
        var options = Options.Create(new AgentOptions
        {
            ControlPlaneUrl = new Uri("https://noema.example.com"),
            PollInterval = TimeSpan.FromSeconds(30)
        });
        using var worker = new HeartbeatWorker(options, time, NullLogger<HeartbeatWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);
        await worker.ExecutionStarted.WaitAsync(TimeSpan.FromSeconds(5));

        time.Advance(TimeSpan.FromSeconds(30));
        await WaitForHeartbeatCountAsync(worker, 1);

        time.Advance(TimeSpan.FromSeconds(30));
        await WaitForHeartbeatCountAsync(worker, 2);

        await worker.StopAsync(CancellationToken.None);
    }

    private static async Task WaitForHeartbeatCountAsync(HeartbeatWorker worker, int expected)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        while (worker.HeartbeatCount != expected)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(10), cts.Token);
        }
    }
}

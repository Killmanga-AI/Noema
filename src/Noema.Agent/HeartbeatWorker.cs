using Microsoft.Extensions.Options;

namespace Noema.Agent;

public sealed class HeartbeatWorker(
    IOptions<AgentOptions> options,
    TimeProvider timeProvider,
    ILogger<HeartbeatWorker> logger) : BackgroundService
{
    private int heartbeatCount;
    private readonly TaskCompletionSource executionStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public int HeartbeatCount => Volatile.Read(ref heartbeatCount);

    internal Task ExecutionStarted => executionStarted.Task;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        logger.LogInformation(
            "Agent started. Control plane {ControlPlaneUrl}, interval {PollInterval}",
            settings.ControlPlaneUrl,
            settings.PollInterval);

        using var timer = new PeriodicTimer(settings.PollInterval, timeProvider);
        executionStarted.TrySetResult();

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                Interlocked.Increment(ref heartbeatCount);
                logger.LogDebug("Agent heartbeat {Count}", HeartbeatCount);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }

        logger.LogInformation("Agent stopping");
    }
}

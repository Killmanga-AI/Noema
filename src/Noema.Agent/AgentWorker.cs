using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Noema.Agent.ControlPlane;
using Noema.Agent.Credentials;
using Noema.Agent.Jobs;
using Noema.Scanning;

namespace Noema.Agent;

/// <summary>
/// The agent's main loop: ask the control plane for work, run what it is given, and ask again. Only ever makes
/// outbound requests. Network trouble is waited out with growing, jittered pauses. A refused credential means the
/// agent was revoked, so it stops instead of hammering the server.
/// </summary>
public sealed class AgentWorker(
    IOptions<AgentOptions> agentOptions,
    IOptions<ScanningOptions> scanningOptions,
    ICredentialStore credentialStore,
    IControlPlaneClientFactory clientFactory,
    ScanEngine engine,
    TimeProvider time,
    IHostApplicationLifetime lifetime,
    ILogger<AgentWorker> logger,
    Func<double>? random = null,
    Action<int>? setExitCode = null) : BackgroundService
{
    private readonly Func<double> nextRandom = random ?? (() => Random.Shared.NextDouble());
    private readonly Action<int> exitCodeSetter = setExitCode ?? (code => Environment.ExitCode = code);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = agentOptions.Value;

        var credentials = LoadCredentials(settings);
        if (credentials is null)
        {
            return;
        }

        var client = clientFactory.Create(credentials);
        var runner = new JobRunner(
            engine,
            client,
            new JobRunnerOptions { ReportInterval = settings.ReportInterval },
            time,
            nextRandom,
            logger);
        var claim = AgentProfile.BuildClaim(scanningOptions.Value);

        logger.LogInformation("Agent {AgentId} started. Control plane {ControlPlaneUrl}, polling every {PollInterval}", credentials.AgentId, credentials.ControlPlaneUrl, settings.PollInterval);

        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var job = await client.ClaimAsync(claim, stoppingToken).ConfigureAwait(false);
                failures = 0;

                if (job is null)
                {
                    await Task.Delay(settings.PollInterval, time, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                logger.LogInformation("Claimed scan {ScanId} of {Target}", job.ScanId, job.Target);
                await runner.RunAsync(job, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (ControlPlaneException ex) when (ex.Kind == ControlPlaneErrorKind.Unauthorized)
            {
                logger.LogCritical(
                    "The control plane refused this agent's credential ({Message}). The agent was probably revoked. Stopping. Enroll it again with a new token to continue.",
                    ex.Message);
                Stop(1);
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failures++;
                var delay = Backoff.Delay(failures, settings.PollInterval, settings.MaxBackoff, nextRandom());
                logger.LogWarning("Could not complete a round with the control plane (attempt {Attempt}): {Message}. Trying again in {Delay}", failures, ex.Message, delay);

                try
                {
                    await Task.Delay(delay, time, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        logger.LogInformation("Agent stopping");
    }

    private AgentCredentials? LoadCredentials(AgentOptions settings)
    {
        AgentCredentials? credentials;

        try
        {
            credentials = credentialStore.Load();
        }
        catch (InvalidDataException ex)
        {
            logger.LogCritical("{Message}", ex.Message);
            Stop(1);
            return null;
        }

        if (credentials is null)
        {
            logger.LogCritical(
                "This agent is not enrolled: there is no credential at {Location}. Run: noema-agent enroll --server <url> --token <token>",
                credentialStore.Location);
            Stop(1);
            return null;
        }

        // The credential is a secret. Never send it to a server other than the one it was issued by.
        if (settings.ControlPlaneUrl is null || !SameServer(credentials.ControlPlaneUrl, settings.ControlPlaneUrl))
        {
            logger.LogCritical(
                "This agent was enrolled with {Enrolled} but Agent:ControlPlaneUrl is {Configured}. Refusing to send its credential to a different server. Fix the setting or enroll again.",
                credentials.ControlPlaneUrl,
                settings.ControlPlaneUrl);
            Stop(1);
            return null;
        }

        return credentials;
    }

    public static bool SameServer(Uri first, Uri second) =>
        Uri.Compare(first, second, UriComponents.SchemeAndServer, UriFormat.UriEscaped, StringComparison.OrdinalIgnoreCase) == 0;

    private void Stop(int exitCode)
    {
        exitCodeSetter(exitCode);
        lifetime.StopApplication();
    }
}

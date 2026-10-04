using Microsoft.Extensions.Options;

namespace Noema.Agent;

public sealed class AgentOptionsValidator : IValidateOptions<AgentOptions>
{
    public static readonly TimeSpan MinPollInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan MaxPollInterval = TimeSpan.FromMinutes(5);

    public ValidateOptionsResult Validate(string? name, AgentOptions options)
    {
        var failures = new List<string>();
        var url = options.ControlPlaneUrl;

        if (url is null || !url.IsAbsoluteUri)
        {
            failures.Add("Agent:ControlPlaneUrl must be set to an absolute URL.");
        }
        else
        {
            var isHttps = url.Scheme == Uri.UriSchemeHttps;
            var isLoopbackHttp = url.Scheme == Uri.UriSchemeHttp && url.IsLoopback;

            if (!isHttps && !isLoopbackHttp)
            {
                failures.Add("Agent:ControlPlaneUrl must use https. Plain http is only allowed for loopback addresses.");
            }
        }

        if (options.PollInterval < MinPollInterval || options.PollInterval > MaxPollInterval)
        {
            failures.Add($"Agent:PollInterval must be between {MinPollInterval} and {MaxPollInterval}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}

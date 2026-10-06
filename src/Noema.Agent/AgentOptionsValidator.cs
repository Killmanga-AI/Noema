using Microsoft.Extensions.Options;

namespace Noema.Agent;

public static class ControlPlaneUrlRules
{
    /// <summary>Why a control plane address is not acceptable, or null when it is. Credentials only ever travel over https, or to this machine.</summary>
    public static string? Check(Uri? url, string settingName = "Agent:ControlPlaneUrl")
    {
        if (url is null || !url.IsAbsoluteUri)
        {
            return $"{settingName} must be set to an absolute URL.";
        }

        var isHttps = url.Scheme == Uri.UriSchemeHttps;
        var isLoopbackHttp = url.Scheme == Uri.UriSchemeHttp && url.IsLoopback;

        return isHttps || isLoopbackHttp
            ? null
            : $"{settingName} must use https. Plain http is only allowed for loopback addresses.";
    }
}

public sealed class AgentOptionsValidator : IValidateOptions<AgentOptions>
{
    public static readonly TimeSpan MinPollInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan MaxPollInterval = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MinReportInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan MaxReportInterval = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan MaxBackoffLimit = TimeSpan.FromHours(1);

    public ValidateOptionsResult Validate(string? name, AgentOptions options)
    {
        var failures = new List<string>();

        var urlProblem = ControlPlaneUrlRules.Check(options.ControlPlaneUrl);
        if (urlProblem is not null)
        {
            failures.Add(urlProblem);
        }

        if (options.PollInterval < MinPollInterval || options.PollInterval > MaxPollInterval)
        {
            failures.Add($"Agent:PollInterval must be between {MinPollInterval} and {MaxPollInterval}.");
        }

        if (options.ReportInterval < MinReportInterval || options.ReportInterval > MaxReportInterval)
        {
            failures.Add($"Agent:ReportInterval must be between {MinReportInterval} and {MaxReportInterval}. It has to stay well under the control plane's lease.");
        }

        if (options.MaxBackoff < options.PollInterval || options.MaxBackoff > MaxBackoffLimit)
        {
            failures.Add($"Agent:MaxBackoff must be at least the poll interval and at most {MaxBackoffLimit}.");
        }

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}

using Microsoft.Extensions.Configuration;
using Noema.Agent.ControlPlane;
using Noema.Agent.Credentials;
using Noema.Contracts;
using Noema.Domain;
using DomainAgent = Noema.Domain.Agent;

namespace Noema.Agent;

public sealed record EnrollCommandArguments(
    Uri Server,
    string Token,
    string? Name,
    IReadOnlyList<string> Allow,
    string? DataDirectory,
    bool Force);

public sealed record EnrollCommandParseResult(EnrollCommandArguments? Arguments, string? Error);

/// <summary>
/// noema-agent enroll --server https://noema.example --token nmt_... [--name office] [--allow 192.168.1.0/24]
/// Trades the single use token for this agent's own credential and saves it where only the service can read it.
/// </summary>
public static class EnrollCommand
{
    public const string Usage =
        "Usage: enroll --server <https url> --token <enrollment token> [--name <agent name>] [--allow <cidr>]... [--data-dir <folder>] [--force]";

    public static bool IsEnrollCommand(string[] args) =>
        args.Length > 0 && string.Equals(args[0], "enroll", StringComparison.OrdinalIgnoreCase);

    public static EnrollCommandParseResult Parse(string[] args)
    {
        if (!IsEnrollCommand(args))
        {
            return new(null, Usage);
        }

        string? server = null;
        string? token = null;
        string? name = null;
        string? dataDirectory = null;
        var allow = new List<string>();
        var force = false;

        for (var i = 1; i < args.Length; i++)
        {
            var option = args[i].ToLowerInvariant();

            switch (option)
            {
                case "--force":
                    force = true;
                    break;
                case "--server" or "--token" or "--name" or "--allow" or "--data-dir":
                    if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        return new(null, $"{args[i]} needs a value. {Usage}");
                    }

                    var value = args[++i];
                    switch (option)
                    {
                        case "--server": server = value; break;
                        case "--token": token = value; break;
                        case "--name": name = value; break;
                        case "--data-dir": dataDirectory = value; break;
                        default: allow.Add(value); break;
                    }

                    break;
                default:
                    return new(null, $"Unknown option '{args[i]}'. {Usage}");
            }
        }

        if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(token))
        {
            return new(null, "--server and --token are required. " + Usage);
        }

        if (!Uri.TryCreate(server, UriKind.Absolute, out var serverUrl))
        {
            return new(null, $"'{server}' is not a valid address.");
        }

        var urlProblem = ControlPlaneUrlRules.Check(serverUrl, "--server");
        if (urlProblem is not null)
        {
            return new(null, urlProblem);
        }

        if (name is not null && !DomainAgent.IsValidName(name))
        {
            return new(null, "An agent name is 2 to 64 characters: letters, digits, dot, dash, underscore or space.");
        }

        var ranges = new List<string>();
        foreach (var text in allow)
        {
            if (!CidrRange.TryParse(text, out var range))
            {
                return new(null, $"'{text}' is not a valid range. Use network notation such as 192.168.1.0/24 with no host bits set.");
            }

            ranges.Add(range.ToString());
        }

        return new(new EnrollCommandArguments(serverUrl, token.Trim(), name?.Trim(), ranges.Distinct().ToList(), dataDirectory, force), null);
    }

    /// <summary>Returns 0 when enrolled, 1 when enrollment fails, 2 for bad input or settings.</summary>
    public static async Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        IConfiguration configuration,
        CancellationToken cancellationToken,
        HttpMessageHandler? handler = null)
    {
        var parsed = Parse(args);
        if (parsed.Arguments is null)
        {
            await error.WriteLineAsync(parsed.Error);
            return 2;
        }

        var arguments = parsed.Arguments;
        var dataDirectory = AgentPaths.CurrentDataDirectory(arguments.DataDirectory ?? configuration[$"{AgentOptions.SectionName}:DataDirectory"]);

        var scanning = configuration.GetSection(ScanningOptions.SectionName).Get<ScanningOptions>() ?? new ScanningOptions();
        if (arguments.Allow.Count > 0)
        {
            scanning.AllowedRanges = arguments.Allow.ToArray();
        }

        var problems = scanning.Validate();
        if (problems.Count > 0)
        {
            foreach (var problem in problems)
            {
                await error.WriteLineAsync(problem);
            }

            return 2;
        }

        var store = new FileCredentialStore(AgentPaths.CredentialsPath(dataDirectory));
        AgentCredentials? existing;
        try
        {
            existing = store.Load();
        }
        catch (InvalidDataException)
        {
            existing = null;
        }

        if (existing is not null && !arguments.Force)
        {
            await error.WriteLineAsync($"This agent is already enrolled as {existing.AgentId} (credential at {store.Location}). Use --force to enroll again.");
            return 2;
        }

        var name = arguments.Name ?? SafeMachineName();
        if (!DomainAgent.IsValidName(name))
        {
            await error.WriteLineAsync($"The machine name '{name}' cannot be used as an agent name. Pass one with --name.");
            return 2;
        }

        using var http = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        http.BaseAddress = arguments.Server;
        http.Timeout = HttpControlPlaneClient.DefaultTimeout;

        EnrollResponse enrolled;
        try
        {
            enrolled = await ControlPlaneEnrollment.EnrollAsync(
                http, AgentProfile.BuildEnrollment(arguments.Token, name, scanning), cancellationToken);
        }
        catch (ControlPlaneException ex)
        {
            await error.WriteLineAsync(Describe(ex));
            return 1;
        }

        store.Save(new AgentCredentials(arguments.Server, enrolled.AgentId, enrolled.AgentSecret));
        SettingsFile.Update(AgentPaths.SettingsPath(dataDirectory), arguments.Server, scanning.AllowedRanges);

        await output.WriteLineAsync($"Enrolled as '{enrolled.Name}' ({enrolled.AgentId}).");
        await output.WriteLineAsync($"Credential saved to {store.Location}");
        await output.WriteLineAsync($"Settings saved to {AgentPaths.SettingsPath(dataDirectory)}");

        if (scanning.AllowedRanges.Length == 0)
        {
            await output.WriteLineAsync("Warning: no ranges are allowed yet, so this agent will refuse every scan. Re-run with --allow <cidr> --force, or set Scanning:AllowedRanges.");
        }

        await output.WriteLineAsync("Start the agent service to begin taking scans.");
        return 0;
    }

    public static string Describe(ControlPlaneException exception) => exception.Kind switch
    {
        ControlPlaneErrorKind.Unauthorized => "The enrollment token was refused. It may have been used already, expired, or been mistyped. Ask an administrator for a new one.",
        ControlPlaneErrorKind.Rejected => "The control plane did not accept the enrollment: " + exception.Message,
        ControlPlaneErrorKind.Transient => "Could not reach the control plane. Check the address and the network, then try again. " + exception.Message,
        _ => "Enrollment failed: " + exception.Message
    };

    private static string SafeMachineName()
    {
        var name = new string(Environment.MachineName.Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_').ToArray()).ToLowerInvariant();
        return name.Length > 64 ? name[..64] : name;
    }
}

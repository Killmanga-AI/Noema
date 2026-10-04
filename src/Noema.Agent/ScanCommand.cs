using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Noema.Domain;
using Noema.Scanning;

namespace Noema.Agent;

public sealed record ScanCommandArguments(CidrRange Target, ScanProbes Probes);

public sealed record ScanCommandParseResult(ScanCommandArguments? Arguments, string? Error);

/// <summary>
/// A one-off local scan, for trying the agent on a real network without a control plane:
/// noema-agent scan 192.168.1.0/24. It follows the same scope and rate limits as a scan from the control plane.
/// </summary>
public static class ScanCommand
{
    public const string Usage = "Usage: scan <cidr> [--probes Icmp[,Arp,...]]   for example: scan 192.168.1.0/24";

    public static bool IsScanCommand(string[] args) =>
        args.Length > 0 && string.Equals(args[0], "scan", StringComparison.OrdinalIgnoreCase);

    public static ScanCommandParseResult Parse(string[] args)
    {
        if (!IsScanCommand(args))
        {
            return new(null, Usage);
        }

        string? target = null;
        var probes = ScanProbes.Icmp;

        for (var i = 1; i < args.Length; i++)
        {
            var arg = args[i];

            if (string.Equals(arg, "--probes", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length)
                {
                    return new(null, "--probes needs a value. " + Usage);
                }

                var parsed = ParseProbes(args[++i]);
                if (parsed is null)
                {
                    return new(null, $"'{args[i]}' is not a valid probe list. Use names like Icmp or Icmp,Arp.");
                }

                probes = parsed.Value;
            }
            else if (arg.StartsWith('-'))
            {
                return new(null, $"Unknown option '{arg}'. " + Usage);
            }
            else if (target is null)
            {
                target = arg;
            }
            else
            {
                return new(null, "Only one target can be scanned at a time. " + Usage);
            }
        }

        if (target is null)
        {
            return new(null, "A target range is required. " + Usage);
        }

        if (!CidrRange.TryParse(target, out var range))
        {
            return new(null, $"'{target}' is not a valid range. Use network notation such as 192.168.1.0/24 with no host bits set.");
        }

        return new(new ScanCommandArguments(range, probes), null);
    }

    private static ScanProbes? ParseProbes(string text)
    {
        var combined = ScanProbes.None;

        foreach (var part in text.Split(',', StringSplitOptions.TrimEntries))
        {
            if (!part.All(char.IsAsciiLetter)
                || !Enum.TryParse<ScanProbes>(part, ignoreCase: true, out var probe)
                || probe == ScanProbes.None
                || !Enum.IsDefined(probe))
            {
                return null;
            }

            combined |= probe;
        }

        return combined == ScanProbes.None ? null : combined;
    }

    public static IConfiguration BuildConfiguration()
    {
        var environment = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production";

        return new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile($"appsettings.{environment}.json", optional: true)
            .AddEnvironmentVariables()
            .Build();
    }

    /// <summary>Returns 0 when the scan completes, 1 when it fails or is refused, 2 for bad input or settings, 130 when cancelled.</summary>
    public static async Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        IConfiguration configuration,
        TimeProvider time,
        CancellationToken cancellationToken,
        Func<ScanningOptions, TimeProvider, ScanEngine>? engineFactory = null)
    {
        var parsed = Parse(args);
        if (parsed.Arguments is null)
        {
            await error.WriteLineAsync(parsed.Error);
            return 2;
        }

        var options = configuration.GetSection(ScanningOptions.SectionName).Get<ScanningOptions>() ?? new ScanningOptions();
        var problems = options.Validate();
        if (problems.Count > 0)
        {
            foreach (var problem in problems)
            {
                await error.WriteLineAsync(problem);
            }

            return 2;
        }

        var engine = (engineFactory ?? ((o, t) => ScanEngineFactory.Create(o, t)))(options, time);
        var job = new ScanJob(Guid.NewGuid(), parsed.Arguments.Target, parsed.Arguments.Probes);
        var sink = new ConsoleObservationSink(output);

        await output.WriteLineAsync($"Scanning {job.Target} with {job.Probes}...");
        var summary = await engine.RunAsync(job, sink, null, cancellationToken);
        await output.WriteLineAsync(FormatSummary(summary));

        foreach (var sample in summary.ErrorSamples)
        {
            await error.WriteLineAsync("  " + sample);
        }

        return summary.Outcome switch
        {
            SweepOutcome.Completed => 0,
            SweepOutcome.Cancelled => 130,
            _ => 1
        };
    }

    public static string FormatSummary(ScanSummary summary)
    {
        var headline = summary.Outcome switch
        {
            SweepOutcome.Completed => "Done.",
            SweepOutcome.Cancelled => "Cancelled.",
            SweepOutcome.Failed => "Failed: " + summary.Reason,
            _ => "Refused: " + summary.Reason
        };

        if (summary.Outcome == SweepOutcome.Refused)
        {
            return headline;
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{headline} {summary.HostsResponded} hosts answered out of {summary.TargetsScanned} of {summary.TargetsPlanned} addresses in {summary.Duration.TotalSeconds:F1}s ({summary.ProbeErrors} errors).");
    }
}

/// <summary>Prints each finding as it arrives, one line per observation.</summary>
public sealed class ConsoleObservationSink(TextWriter output) : IObservationSink
{
    public async ValueTask WriteAsync(ProbeObservation observation, CancellationToken cancellationToken) =>
        await output.WriteLineAsync(FormatLine(observation));

    public static string FormatLine(ProbeObservation observation)
    {
        var kind = observation.Kind switch
        {
            ObservationKind.IcmpEchoReply => "icmp",
            ObservationKind.ArpEntry => "arp",
            ObservationKind.ReverseDnsName => "dns",
            ObservationKind.TcpPortOpen => "tcp",
            ObservationKind.SnmpSystemInfo => "snmp",
            _ => observation.Kind.ToString()
        };

        var parts = new List<string> { observation.Address.ToString().PadRight(15), kind.PadRight(5) };

        if (observation.MacAddress is not null)
        {
            parts.Add(observation.MacAddress.ToString());
        }

        var detail = Describe(observation.DetailJson);
        if (detail.Length > 0)
        {
            parts.Add(detail);
        }

        return string.Join(' ', parts).TrimEnd();
    }

    private static string Describe(string? detailJson)
    {
        if (string.IsNullOrWhiteSpace(detailJson))
        {
            return string.Empty;
        }

        try
        {
            using var document = JsonDocument.Parse(detailJson);
            var pieces = new List<string>();

            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in document.RootElement.EnumerateObject())
                {
                    pieces.Add(property.Name switch
                    {
                        "rttMs" => string.Create(CultureInfo.InvariantCulture, $"{property.Value.GetDouble():F1} ms"),
                        "ttl" => $"ttl={property.Value}",
                        _ => $"{property.Name}={property.Value}"
                    });
                }
            }

            return string.Join(' ', pieces);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            return detailJson;
        }
    }
}

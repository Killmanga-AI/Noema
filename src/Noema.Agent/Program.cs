using Microsoft.Extensions.Options;
using Noema.Agent;
using Noema.Agent.Credentials;

// "noema-agent scan ..." and "noema-agent enroll ..." run once and exit, without starting the service.
if (ScanCommand.IsScanCommand(args) || EnrollCommand.IsEnrollCommand(args))
{
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cancellation.Cancel();
    };

    var configuration = ScanCommand.BuildConfiguration();

    return ScanCommand.IsScanCommand(args)
        ? await ScanCommand.RunAsync(args, Console.Out, Console.Error, configuration, TimeProvider.System, cancellation.Token)
        : await EnrollCommand.RunAsync(args, Console.Out, Console.Error, configuration, cancellation.Token);
}

var builder = Host.CreateApplicationBuilder(args);

// Local settings written by "enroll" live next to the credential, outside the install folder.
var dataDirectory = AgentPaths.CurrentDataDirectory(builder.Configuration[$"{AgentOptions.SectionName}:DataDirectory"]);
builder.Configuration.AddJsonFile(AgentPaths.SettingsPath(dataDirectory), optional: true, reloadOnChange: false);

builder.Services.AddWindowsService(options => options.ServiceName = "NoemaAgent");
builder.Services.AddSystemd();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IValidateOptions<AgentOptions>, AgentOptionsValidator>();
builder.Services.AddOptions<AgentOptions>()
    .BindConfiguration(AgentOptions.SectionName)
    .ValidateOnStart();

builder.Services.AddNoemaAgent(dataDirectory);

await builder.Build().RunAsync();
return Environment.ExitCode;

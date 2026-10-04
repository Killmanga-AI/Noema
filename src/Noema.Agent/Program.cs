using Microsoft.Extensions.Options;
using Noema.Agent;

// "noema-agent scan 192.168.1.0/24" runs one local scan and exits, without starting the service.
if (ScanCommand.IsScanCommand(args))
{
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cancellation.Cancel();
    };

    return await ScanCommand.RunAsync(
        args, Console.Out, Console.Error, ScanCommand.BuildConfiguration(), TimeProvider.System, cancellation.Token);
}

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "NoemaAgent");
builder.Services.AddSystemd();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IValidateOptions<AgentOptions>, AgentOptionsValidator>();
builder.Services.AddOptions<AgentOptions>()
    .BindConfiguration(AgentOptions.SectionName)
    .ValidateOnStart();

builder.Services.AddNoemaScanning();

builder.Services.AddHostedService<HeartbeatWorker>();

await builder.Build().RunAsync();
return 0;

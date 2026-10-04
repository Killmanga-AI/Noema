using Microsoft.Extensions.Options;
using Noema.Agent;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options => options.ServiceName = "NoemaAgent");
builder.Services.AddSystemd();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IValidateOptions<AgentOptions>, AgentOptionsValidator>();
builder.Services.AddOptions<AgentOptions>()
    .BindConfiguration(AgentOptions.SectionName)
    .ValidateOnStart();

builder.Services.AddHostedService<HeartbeatWorker>();

await builder.Build().RunAsync();

using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Noema.Api.Middleware;
using Noema.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddNoemaInfrastructure();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseExceptionHandler();
app.UseStatusCodePages();

// Liveness answers as long as the process is up. Readiness also checks the database.
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains(DependencyInjection.ReadyTag)
});

app.Run();

public partial class Program;

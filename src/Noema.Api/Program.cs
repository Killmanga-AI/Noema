using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Noema.Api.Features.Agents;
using Noema.Api.Features.Audit;
using Noema.Api.Features.Auth;
using Noema.Api.Features.Ranges;
using Noema.Api.Features.Scans;
using Noema.Api.Features.Users;
using Noema.Api.Middleware;
using Noema.Api.Security;
using Noema.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// Every request body here is small JSON, so cap it well below the default.
builder.WebHost.ConfigureKestrel(kestrel => kestrel.Limits.MaxRequestBodySize = 64 * 1024);

builder.Services.AddNoemaInfrastructure();
builder.Services.AddNoemaSecurity();
builder.Services.AddProblemDetails();

var app = builder.Build();

app.UseMiddleware<CorrelationIdMiddleware>();
app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Liveness answers as long as the process is up. Readiness also checks the database. Both are open to probes.
app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = check => check.Tags.Contains(DependencyInjection.ReadyTag)
}).AllowAnonymous();

app.MapAuthEndpoints();
app.MapUserEndpoints();
app.MapRangeEndpoints();
app.MapScanEndpoints();
app.MapAuditEndpoints();
app.MapAgentAdminEndpoints();
app.MapAgentProtocolEndpoints();
app.MapFallback(() => Results.NotFound()).AllowAnonymous();

app.Run();

public partial class Program;

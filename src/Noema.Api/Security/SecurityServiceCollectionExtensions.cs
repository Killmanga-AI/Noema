using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication;
using Noema.Api.Features.Agents;
using Noema.Api.Features.Audit;
using Noema.Contracts;
using Noema.Api.Features.Auth;
using Noema.Api.Features.Ranges;
using Noema.Api.Features.Scans;
using Noema.Api.Features.Users;
using Noema.Infrastructure.Security;

namespace Noema.Api.Security;

internal static class SecurityServiceCollectionExtensions
{
    public static IServiceCollection AddNoemaSecurity(this IServiceCollection services)
    {
        services.AddOptions<JwtOptions>()
            .BindConfiguration(JwtOptions.SectionName)
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<JwtOptions>, JwtOptionsValidator>();

        services.AddHttpContextAccessor();
        services.AddScoped<IRequestContext, HttpRequestContext>();
        services.AddScoped<IAuditWriter, AuditWriter>();
        services.AddSingleton<ITokenService, JwtTokenService>();

        services.AddScoped<AuthService>();
        services.AddScoped<UserAdminService>();
        services.AddScoped<RangeService>();
        services.AddScoped<ScanRequestService>();
        services.AddScoped<AuditQueryService>();

        services.AddSingleton<IValidateOptions<AgentFleetOptions>, AgentFleetOptionsValidator>();
        services.AddOptions<AgentFleetOptions>()
            .BindConfiguration(AgentFleetOptions.SectionName)
            .ValidateOnStart();
        services.AddScoped<AgentAdminService>();
        services.AddScoped<AgentProtocolService>();
        services.AddSingleton<LeaseReaper>();
        services.AddHostedService(provider => provider.GetRequiredService<LeaseReaper>());

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer()
            .AddScheme<AuthenticationSchemeOptions, AgentAuthenticationHandler>(AgentProtocol.AuthenticationScheme, null);
        services.ConfigureOptions<ConfigureJwtBearer>();

        // Secure by default: anything without its own rule needs a signed in user.
        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy(Policies.Admin, policy => policy.RequireRole("Admin"))
            .AddPolicy(Policies.Operator, policy => policy.RequireRole("Admin", "Operator"))
            .AddPolicy(Policies.Agent, policy => policy
                .AddAuthenticationSchemes(AgentProtocol.AuthenticationScheme)
                .RequireAuthenticatedUser()
                .RequireClaim("role", "Agent"));

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(RateLimitPolicies.Auth, httpContext =>
            {
                var permits = httpContext.RequestServices.GetRequiredService<IOptions<SecurityOptions>>().Value.AuthRateLimitPerMinute;

                return RateLimitPartition.GetFixedWindowLimiter(
                    httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permits,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });
        });

        return services;
    }
}

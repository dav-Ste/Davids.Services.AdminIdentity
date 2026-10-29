using Davids.Services.AdminIdentity.Application.Services;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Repositories;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Davids.Services.AdminIdentity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using StackExchange.Redis;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.AdminIdentity.Infrastructure;

public static class AdminIdentityInfrastructureExtensions
{
    public static IServiceCollection AddAdminIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var oidc = configuration.GetSection("Oidc").Get<AdminOidcSettings>() ?? new AdminOidcSettings();
        oidc.InitializeKeys(requireExplicitEncryptionKey: environment.IsProduction());
        services.AddSingleton(oidc);
        var lockout = configuration.GetSection("Lockout").Get<AdminLockoutSettings>() ?? new AdminLockoutSettings();
        services.AddSingleton(lockout);
        services.AddDataProtection();
        services.AddSingleton<AdminOidcLoginStateProtector>();
        services.AddSingleton<AdminOidcApplicationSeeder>();

        var connectionString = configuration.GetConnectionString("adminidentitydb")
            ?? throw new InvalidOperationException("Missing adminidentitydb connection string.");
        services.AddDbContext<AdminIdentityDbContext>(options =>
        {
            options.UseSqlServer(connectionString);
            options.UseOpenIddict();
        });

        services.AddScoped<IAdminUserRepository, AdminUserRepository>();
        services.AddScoped<IAdminLoginAuditRepository, AdminLoginAuditRepository>();
        services.AddScoped<IAdminIdentityService, AdminIdentityService>();
        services.AddSingleton<IAdminPasswordService, AdminPasswordService>();
        services.AddScoped<AdminRevocationStore>();

        if (configuration.GetValue<bool>("Redis:Enabled"))
        {
            var cacheConnection = configuration.GetConnectionString("cache")
                ?? throw new InvalidOperationException("Missing cache connection string.");
            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(cacheConnection);
                options.AbortOnConnectFail = false;
                options.ConnectTimeout = 5000;
                options.AsyncTimeout = 5000;
                return ConnectionMultiplexer.Connect(options);
            });
            services.AddSingleton<IAdminRevocationCache, RedisAdminRevocationCache>();
        }
        else
        {
            services.AddSingleton<IAdminRevocationCache, NoAdminRevocationCache>();
        }

        var allowInsecureTransport =
            !environment.IsProduction() &&
            (environment.IsDevelopment() ||
             environment.IsEnvironment("Testing") ||
             configuration.GetValue<bool>("Http:AllowInsecureDevelopment"));

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<AdminIdentityDbContext>();
            })
            .AddServer(options =>
            {
                if (oidc.NormalizedIssuerUri is not null)
                {
                    options.SetIssuer(oidc.NormalizedIssuerUri);
                }

                options.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetEndSessionEndpointUris("connect/logout")
                    .SetRevocationEndpointUris("connect/revocation");

                options.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange();
                options.AllowRefreshTokenFlow();

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(oidc.AccessTokenLifetimeMinutes));
                options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(oidc.AccessTokenLifetimeMinutes));
                options.SetRefreshTokenLifetime(TimeSpan.FromHours(oidc.RefreshTokenLifetimeHours));
                options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

                // Downstream resource servers (APIGateway, Customers, Istio) verify RS256 signatures via public JWKS.
                options.DisableAccessTokenEncryption();

                options.AddSigningKey(oidc.PrivateSigningKey);
                options.AddEncryptionKey(oidc.EncryptionSecurityKey);

                options.RegisterScopes(
                    Scopes.OpenId,
                    Scopes.Email,
                    Scopes.Profile,
                    Scopes.Roles,
                    Scopes.OfflineAccess,
                    oidc.Audience);

                options.AddEventHandler(AdminOidcRevocationSyncHandler.Descriptor);
                options.AddEventHandler(AdminOidcTokenErrorAuditHandler.Descriptor);

                var aspNetCore = options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();

                if (allowInsecureTransport)
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            });

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.MapInboundClaims = false;
                options.TokenValidationParameters = oidc.CreateValidationParameters();
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var role = context.Principal?.FindFirst(Claims.Role)?.Value;
                        if (!string.Equals(role, AdminUser.AdminRole, StringComparison.Ordinal))
                        {
                            context.Fail("Admin Identity accepts 'admin' role tokens only.");
                            return;
                        }

                        var tokenId = context.Principal?.FindFirst(Claims.JwtId)?.Value;
                        var oiTokenId = context.Principal?.FindFirst(Claims.Private.TokenId)?.Value;
                        DateTime? expUtc = long.TryParse(
                            context.Principal?.FindFirst(Claims.ExpiresAt)?.Value,
                            out var expSeconds)
                            ? DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime
                            : null;
                        var store = context.HttpContext.RequestServices.GetRequiredService<AdminRevocationStore>();
                        if (await store.IsRevokedAsync(tokenId, context.HttpContext.RequestAborted, oiTokenId, expUtc))
                        {
                            context.Fail("Admin access token has been revoked.");
                        }
                    }
                };
            });

        services.AddAuthorizationBuilder()
            .AddPolicy("AdminOnly", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.Role, AdminUser.AdminRole);
            });

        services.AddHealthChecks()
            .AddCheck<AdminDatabaseHealthCheck>("admin-identity-database");

        return services;
    }
}

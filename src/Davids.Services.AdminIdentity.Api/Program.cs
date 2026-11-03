using System.Security.Claims;
using System.Threading.RateLimiting;
using Davids.ServiceDefaults;
using Davids.Services.AdminIdentity.Api;
using Davids.Services.AdminIdentity.Application.Commands;
using Davids.Services.AdminIdentity.Application.DTO;
using Davids.Services.AdminIdentity.Application.Services;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Repositories;
using Davids.Services.AdminIdentity.Infrastructure;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Davids.Services.AdminIdentity.Infrastructure.Persistence;
using Davids.Services.AdminIdentity.Infrastructure.Secrets;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
await builder.Configuration.LoadVaultAsync();
builder.AddServiceDefaults();
builder.Services.AddTrustedForwardedHeaders(builder.Configuration, builder.Environment);
builder.Services.AddAdminIdentityInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddDataProtection()
    .ConfigureDavidsDataProtection(
        builder.Configuration,
        builder.Environment,
        applicationName: "davids-admin-identity",
        externalRepositoryFactory: sp => new AdminDataProtectionXmlRepository(sp.GetRequiredService<IServiceScopeFactory>()));
builder.Services.AddExceptionHandler<AdminApiExceptionHandler>();
builder.Services.AddProblemDetails();
builder.Services.AddAdminIdentityOpenApi();

var authPermitLimit = Math.Max(1, builder.Configuration.GetValue("RateLimiting:AuthPermitLimit", 5));
var authWindowSeconds = Math.Max(1, builder.Configuration.GetValue("RateLimiting:WindowSeconds", 60));
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (rejectedContext, cancellationToken) =>
    {
        var ip = rejectedContext.HttpContext.Connection.RemoteIpAddress;
        var clientIp = ip is null
            ? "unknown"
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        var correlationId = rejectedContext.HttpContext.Request.Headers["X-Correlation-ID"].FirstOrDefault()
            ?? rejectedContext.HttpContext.TraceIdentifier;
        DavidsSecurityMetrics.RecordRateLimitRejection("davids-admin-identity", "admin-authentication");
        rejectedContext.HttpContext.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("Davids.Security.Audit")
            .LogWarning(
                "Audit: rate-limit rejected administrator authentication request from {ClientIp} on {Path} (SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
                clientIp,
                rejectedContext.HttpContext.Request.Path.Value,
                "RateLimitRejected",
                correlationId);

        rejectedContext.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (rejectedContext.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
            rejectedContext.HttpContext.Response.Headers.RetryAfter =
                seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        await rejectedContext.HttpContext.Response.WriteAsJsonAsync(new
        {
            code = "rate_limit_exceeded",
            reason = "Too many administrator authentication attempts. Please try again later."
        }, cancellationToken);
    };
    options.AddPolicy("admin-authentication", context =>
    {
        var ip = context.Connection.RemoteIpAddress;
        var partitionKey = ip is null
            ? "unknown"
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = authPermitLimit,
                Window = TimeSpan.FromSeconds(authWindowSeconds),
                QueueLimit = 0
            });
    });
});

var app = builder.Build();

if (builder.Configuration.GetValue<bool>("Database:ApplyMigrations"))
{
    if (!app.Environment.IsDevelopment())
    {
        throw new InvalidOperationException("Automatic database migration is restricted to Development.");
    }

    await using var scope = app.Services.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>().Database.MigrateAsync();
    await app.Services.GetRequiredService<AdminOidcApplicationSeeder>().EnsureSeededAsync();
}

if (builder.Configuration.GetValue<bool>("SeedAdmin:Enabled"))
{
    if (!app.Environment.IsDevelopment())
    {
        throw new InvalidOperationException("Initial administrator seeding via configuration is restricted to Development.");
    }

    var seedEmail = builder.Configuration["SeedAdmin:Email"];
    var seedPassword = builder.Configuration["SeedAdmin:Password"];
    var seedFullName = builder.Configuration["SeedAdmin:FullName"] ?? "Local Administrator";
    if (!string.IsNullOrWhiteSpace(seedEmail) && !string.IsNullOrWhiteSpace(seedPassword))
    {
        await using var scope = app.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<IAdminUserRepository>();
        var passwords = scope.ServiceProvider.GetRequiredService<IAdminPasswordService>();
        var normalized = AdminUser.NormalizeAndValidateEmail(seedEmail);
        if (await users.GetByEmailAsync(normalized) is null)
        {
            await users.AddAsync(new AdminUser(
                Guid.NewGuid(),
                normalized,
                passwords.Hash(seedPassword),
                seedFullName,
                isActive: true,
                DateTime.UtcNow));
        }
    }
}

app.UseTrustedForwardedHeaders();
app.UseExceptionHandler();
if (!(app.Environment.IsDevelopment() && builder.Configuration.GetValue<bool>("Http:AllowInsecureDevelopment")))
{
    app.UseHttpsRedirection();
}

app.Use(async (context, next) =>
{
    try
    {
        if (context.Request.Path.StartsWithSegments("/connect") ||
            context.Request.Path.StartsWithSegments("/.well-known"))
        {
            await context.RequestServices.GetRequiredService<AdminOidcApplicationSeeder>()
                .EnsureSeededAsync(CancellationToken.None);
        }

        await next();
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status499ClientClosedRequest;
        }
    }
});

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
    {
        options.RoutePrefix = "docs";
        options.SwaggerEndpoint("../openapi/v1.json", "Davids Admin Identity OIDC v1");
    });
}

// NOTE: By security design, Davids.Services.AdminIdentity exposes NO public /sign-up endpoint.
// Employee authentication uses OAuth 2.1 Authorization Code + PKCE via OpenIddict (/connect/*).
app.MapGet("/", () => Results.Text("Davids Admin Identity OIDC Service"))
    .ExcludeFromDescription()
    .AllowAnonymous();
app.MapAdminOidcEndpoints();

static AdminActorMetadata? TryResolveActor(ClaimsPrincipal principal, HttpContext httpContext)
{
    if (!Guid.TryParse(principal.FindFirstValue("sub"), out var actorId))
    {
        return null;
    }

    var email = principal.FindFirstValue("email");
    var role = principal.FindFirstValue("role") ?? AdminUser.AdminRole;
    var jti = principal.FindFirstValue("jti");
    DateTime? expUtc = long.TryParse(principal.FindFirstValue("exp"), out var expSeconds)
        ? DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime
        : null;
    var correlationId = DavidsActorContext.ResolveCorrelationId(httpContext);
    return new AdminActorMetadata(actorId, email, role, correlationId, jti, expUtc);
}

app.MapGet("/me", async (HttpContext httpContext, ClaimsPrincipal principal, IAdminIdentityService service, CancellationToken ct) =>
{
    if (!Guid.TryParse(principal.FindFirstValue("sub"), out var adminId))
    {
        return Results.Unauthorized();
    }

    try
    {
        var admin = await service.GetAsync(adminId, ct);
        return admin is null ? Results.NotFound() : Results.Ok(admin);
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<AdminUserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status404NotFound)
.RequireAuthorization("WorkforceAny");

app.MapPut("/me/password", async (
    HttpContext httpContext,
    ChangeAdminPassword command,
    ClaimsPrincipal principal,
    IAdminIdentityService service,
    CancellationToken ct) =>
{
    if (command is null)
    {
        return Results.BadRequest(new { code = "invalid_request", reason = "Request body is required." });
    }

    var actor = TryResolveActor(principal, httpContext);
    if (actor is null)
    {
        return Results.Unauthorized();
    }

    try
    {
        await service.ChangeMyPasswordAsync(actor.ActorAdminUserId, command, actor, ct);
        return Results.NoContent();
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces(StatusCodes.Status204NoContent)
.Produces(StatusCodes.Status400BadRequest)
.RequireAuthorization("WorkforceAny");

app.MapGet("/users", async (HttpContext httpContext, IAdminIdentityService service, CancellationToken ct) =>
{
    try
    {
        return Results.Ok(await service.BrowseAsync(ct));
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<IReadOnlyList<AdminUserDto>>(StatusCodes.Status200OK)
.RequireAuthorization("WorkforceAuditRead");

app.MapGet("/login-audits", async (
    HttpContext httpContext,
    int? limit,
    bool? succeeded,
    IAdminIdentityService service,
    CancellationToken ct,
    string? email = null) =>
{
    if (limit is < 1 or > 500)
    {
        return Results.BadRequest(new { code = "invalid_limit", reason = "Limit must be between 1 and 500." });
    }

    try
    {
        var entries = await service.BrowseLoginAuditsAsync(limit ?? 100, succeeded, email, ct);
        return Results.Ok(entries);
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<IReadOnlyList<AdminLoginAuditDto>>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.RequireAuthorization("WorkforceAuditRead");

app.MapGet("/change-audits", async (
    HttpContext httpContext,
    int? limit,
    Guid? targetUserId,
    Guid? actorUserId,
    IAdminIdentityService service,
    CancellationToken ct) =>
{
    if (limit is < 1 or > 500)
    {
        return Results.BadRequest(new { code = "invalid_limit", reason = "Limit must be between 1 and 500." });
    }

    try
    {
        var entries = await service.BrowseChangeAuditsAsync(limit ?? 100, targetUserId, actorUserId, ct);
        return Results.Ok(entries);
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<IReadOnlyList<AdminChangeAuditDto>>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.RequireAuthorization("WorkforceAuditRead");

app.MapPost("/users", async (
    HttpContext httpContext,
    CreateAdminUser command,
    ClaimsPrincipal principal,
    IAdminIdentityService service,
    CancellationToken ct) =>
{
    if (command is null)
    {
        return Results.BadRequest(new { code = "invalid_request", reason = "Request body is required." });
    }

    var actor = TryResolveActor(principal, httpContext);
    if (actor is null)
    {
        return Results.Unauthorized();
    }

    try
    {
        var created = await service.CreateAdminAsync(command, actor.ActorAdminUserId, ct, actor);
        return Results.Created($"/users/{created.Id}", created);
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<AdminUserDto>(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status409Conflict)
.RequireAuthorization("AdminOnly");

app.MapPut("/users/{userId:guid}", async (
    Guid userId,
    HttpContext httpContext,
    UpdateAdminUser command,
    ClaimsPrincipal principal,
    IAdminIdentityService service,
    CancellationToken ct) =>
{
    if (command is null)
    {
        return Results.BadRequest(new { code = "invalid_request", reason = "Request body is required." });
    }

    var actor = TryResolveActor(principal, httpContext);
    if (actor is null)
    {
        return Results.Unauthorized();
    }

    try
    {
        var updated = await service.UpdateEmployeeAsync(userId, command, actor, ct);
        return Results.Ok(updated);
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<AdminUserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status404NotFound)
.Produces(StatusCodes.Status409Conflict)
.RequireAuthorization("AdminOnly");

app.MapPost("/users/{userId:guid}/unlock", async (
    Guid userId,
    HttpContext httpContext,
    ClaimsPrincipal principal,
    IAdminIdentityService service,
    CancellationToken ct) =>
{
    var actor = TryResolveActor(principal, httpContext);
    if (actor is null)
    {
        return Results.Unauthorized();
    }

    try
    {
        var unlocked = await service.UnlockEmployeeAsync(userId, actor, ct);
        return Results.Ok(unlocked);
    }
    catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
    {
        return Results.Empty;
    }
})
.Produces<AdminUserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status404NotFound)
.RequireAuthorization("AdminOnly");

app.Run();
public partial class Program;

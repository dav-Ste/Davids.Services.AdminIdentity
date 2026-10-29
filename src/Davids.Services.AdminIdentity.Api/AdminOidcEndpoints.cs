using System.Net;
using System.Security.Claims;
using System.Text;
using Davids.Services.AdminIdentity.Application.DTO;
using Davids.Services.AdminIdentity.Application.Services;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Exceptions;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.AdminIdentity.Api;

public static class AdminOidcEndpoints
{
    private const string AuthorizeStylesheet = """
        :root { color-scheme: dark; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: radial-gradient(circle at top, #172554 0%, #090d16 70%); color: #f8fafc; }
        .card { width: min(430px, 92vw); background: #0f172a; border: 1px solid #334155; border-radius: 16px; padding: 2rem; box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55); }
        .badge { display: inline-block; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase; color: #93c5fd; background: rgba(37, 99, 235, 0.22); border: 1px solid rgba(96, 165, 250, 0.35); padding: 0.25rem 0.65rem; border-radius: 999px; margin-bottom: 0.8rem; }
        h1 { margin: 0 0 0.45rem; font-size: 1.4rem; color: #f8fafc; }
        p.sub { margin: 0 0 1.4rem; color: #94a3b8; font-size: 0.9rem; line-height: 1.45; }
        label { display: block; font-size: 0.84rem; font-weight: 600; margin-bottom: 0.35rem; color: #cbd5e1; }
        input[type="email"], input[type="password"] { box-sizing: border-box; width: 100%; padding: 0.7rem 0.85rem; background: #020617; color: #f8fafc; border: 1px solid #475569; border-radius: 10px; font-size: 0.95rem; margin-bottom: 1rem; }
        input:focus { outline: 2px solid #3b82f6; border-color: #3b82f6; }
        .error { background: rgba(127, 29, 29, 0.45); border: 1px solid #ef4444; color: #fecaca; padding: 0.7rem 0.85rem; border-radius: 10px; font-size: 0.88rem; margin-bottom: 1rem; }
        button { width: 100%; padding: 0.78rem 1rem; border: 0; border-radius: 10px; background: #2563eb; color: #fff; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .meta { margin-top: 1.15rem; font-size: 0.77rem; color: #64748b; text-align: center; }
        """;

    public static void MapAdminOidcEndpoints(this WebApplication app)
    {
        app.MapGet("/connect/authorize.css", () =>
            Results.Content(AuthorizeStylesheet, "text/css; charset=utf-8"))
            .ExcludeFromDescription()
            .AllowAnonymous();

        app.MapGet("/connect/authorize", (HttpContext context, AdminOidcLoginStateProtector stateProtector) =>
        {
            var request = context.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect authorization request cannot be retrieved.");

            var requestToken = stateProtector.Protect(
                request.ClientId,
                request.RedirectUri,
                request.CodeChallenge,
                request.State);

            return RenderAuthorizeForm(context, request, requestToken, emailValue: string.Empty, errorMessage: null);
        })
        .ExcludeFromDescription()
        .AllowAnonymous();

        app.MapPost("/connect/authorize", async (
            HttpContext context,
            IAdminIdentityService adminIdentityService,
            AdminOidcSettings oidcSettings,
            AdminOidcLoginStateProtector stateProtector,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var request = context.GetOpenIddictServerRequest()
                    ?? throw new InvalidOperationException("The OpenID Connect authorization request cannot be retrieved.");

                if (!context.Request.HasFormContentType)
                {
                    return Results.BadRequest(new { error = "invalid_request", error_description = "Form-encoded body is required." });
                }

                var form = await context.Request.ReadFormAsync(cancellationToken);
                var submittedToken = form["request_token"].ToString();
                var email = form["email"].ToString().Trim();
                var password = form["password"].ToString();
                var metadata = ExtractAuditMetadata(context, request.ClientId);

                if (!stateProtector.TryValidate(
                        submittedToken,
                        request.ClientId,
                        request.RedirectUri,
                        request.CodeChallenge,
                        request.State))
                {
                    await adminIdentityService.RecordProtocolFailureAuditAsync(
                        email,
                        adminUserId: null,
                        outcome: "invalid_request_token",
                        failureReason: "Authorize form request_token expired or failed verification.",
                        metadata: metadata,
                        cancellationToken: cancellationToken);
                    var freshToken = stateProtector.Protect(
                        request.ClientId,
                        request.RedirectUri,
                        request.CodeChallenge,
                        request.State);
                    return RenderAuthorizeForm(
                        context,
                        request,
                        freshToken,
                        email,
                        "Your administrator sign-in request expired or failed verification. Please try again.",
                        StatusCodes.Status400BadRequest);
                }

                AdminUserDto admin;
                try
                {
                    admin = await adminIdentityService.AuthenticateAsync(email, password, cancellationToken, metadata);
                }
                catch (AdminAccountDisabledException)
                {
                    var retryToken = stateProtector.Protect(
                        request.ClientId,
                        request.RedirectUri,
                        request.CodeChallenge,
                        request.State);
                    return RenderAuthorizeForm(
                        context,
                        request,
                        retryToken,
                        email,
                        "This administrator account has been disabled.",
                        StatusCodes.Status403Forbidden);
                }
                catch (AdminAccountLockedException)
                {
                    var retryToken = stateProtector.Protect(
                        request.ClientId,
                        request.RedirectUri,
                        request.CodeChallenge,
                        request.State);
                    return RenderAuthorizeForm(
                        context,
                        request,
                        retryToken,
                        email,
                        "This administrator account is temporarily locked due to repeated failed sign-in attempts. Please try again later.",
                        StatusCodes.Status429TooManyRequests);
                }
                catch (AdminDomainException)
                {
                    var retryToken = stateProtector.Protect(
                        request.ClientId,
                        request.RedirectUri,
                        request.CodeChallenge,
                        request.State);
                    return RenderAuthorizeForm(
                        context,
                        request,
                        retryToken,
                        email,
                        "Invalid administrator email or password.",
                        StatusCodes.Status400BadRequest);
                }

                var requestedScopes = request.GetScopes();
                if (!requestedScopes.Contains(oidcSettings.Audience))
                {
                    requestedScopes = requestedScopes.Add(oidcSettings.Audience);
                }

                var principal = BuildAdminPrincipal(admin, oidcSettings, requestedScopes);
                return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                return Results.Empty;
            }
        })
        .ExcludeFromDescription()
        .AllowAnonymous()
        .RequireRateLimiting("admin-authentication");

        app.MapPost("/connect/token", async (
            HttpContext context,
            IAdminIdentityService adminIdentityService,
            AdminOidcSettings oidcSettings,
            CancellationToken cancellationToken) =>
        {
            try
            {
                var request = context.GetOpenIddictServerRequest()
                    ?? throw new InvalidOperationException("The OpenID Connect token request cannot be retrieved.");
                var metadata = ExtractAuditMetadata(context, request.ClientId);

                if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                {
                    context.Items[AdminOidcTokenErrorAuditHandler.AuditRecordedItemKey] = true;
                    await adminIdentityService.RecordProtocolFailureAuditAsync(
                        email: "[token-endpoint]",
                        adminUserId: null,
                        outcome: "unsupported_grant_type",
                        failureReason: $"Rejected unsupported token grant type '{request.GrantType ?? "unknown"}'.",
                        metadata: metadata,
                        cancellationToken: cancellationToken);
                    return Results.Forbid(
                        authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "Only authorization_code (with PKCE) and refresh_token grants are supported."
                        }));
                }

                var authResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                var subject = authResult.Principal?.GetClaim(Claims.Subject);
                if (!authResult.Succeeded || !Guid.TryParse(subject, out var adminId))
                {
                    context.Items[AdminOidcTokenErrorAuditHandler.AuditRecordedItemKey] = true;
                    await adminIdentityService.RecordProtocolFailureAuditAsync(
                        email: authResult.Principal?.GetClaim(Claims.Email) ?? "[token-endpoint]",
                        adminUserId: Guid.TryParse(subject, out var parsedSubject) ? parsedSubject : null,
                        outcome: "token_grant_rejected",
                        failureReason: "Invalid, expired, or revoked authorization code or refresh token.",
                        metadata: metadata,
                        cancellationToken: cancellationToken);
                    return Results.Forbid(
                        authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "The administrator authorization code or refresh token is invalid or revoked."
                        }));
                }

                var admin = await adminIdentityService.GetAsync(adminId, cancellationToken);
                if (admin is null || !admin.IsActive || !string.Equals(admin.Role, AdminUser.AdminRole, StringComparison.Ordinal))
                {
                    context.Items[AdminOidcTokenErrorAuditHandler.AuditRecordedItemKey] = true;
                    await adminIdentityService.RecordProtocolFailureAuditAsync(
                        email: admin?.Email ?? "[token-endpoint]",
                        adminUserId: adminId,
                        outcome: "account_disabled",
                        failureReason: "Administrator account is disabled or missing during token grant.",
                        metadata: metadata,
                        cancellationToken: cancellationToken);
                    return Results.Forbid(
                        authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                        properties: new AuthenticationProperties(new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                                "The administrator account is disabled or no longer exists."
                        }));
                }

                var scopes = authResult.Principal!.GetScopes();
                if (!scopes.Contains(oidcSettings.Audience))
                {
                    scopes = scopes.Add(oidcSettings.Audience);
                }

                var principal = BuildAdminPrincipal(admin, oidcSettings, scopes);
                return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                return Results.Empty;
            }
        })
        .Produces<Dictionary<string, object>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .AllowAnonymous()
        .RequireRateLimiting("admin-authentication");

        app.MapMethods("/connect/userinfo", ["GET", "POST"], async (
            HttpContext httpContext,
            ClaimsPrincipal user,
            IAdminIdentityService adminIdentityService,
            CancellationToken cancellationToken) =>
        {
            if (!Guid.TryParse(user.FindFirstValue(Claims.Subject), out var adminId))
            {
                return Results.Challenge();
            }

            try
            {
                var dto = await adminIdentityService.GetAsync(adminId, cancellationToken);
                if (dto is null || !dto.IsActive)
                {
                    return Results.Challenge();
                }

                var claims = new Dictionary<string, object>
                {
                    [Claims.Subject] = dto.Id.ToString("N"),
                    [Claims.Email] = dto.Email,
                    [Claims.Role] = dto.Role
                };
                if (!string.IsNullOrWhiteSpace(dto.FullName))
                {
                    claims[Claims.Name] = dto.FullName;
                }

                return Results.Ok(claims);
            }
            catch (OperationCanceledException) when (httpContext.RequestAborted.IsCancellationRequested)
            {
                return Results.Empty;
            }
        })
        .Produces<Dictionary<string, object>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .RequireAuthorization("AdminOnly");

        app.MapMethods("/connect/logout", ["GET", "POST"], () =>
            Results.SignOut(
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                properties: new AuthenticationProperties { RedirectUri = "/login" }))
            .ExcludeFromDescription()
            .AllowAnonymous();
    }

    private static ClaimsPrincipal BuildAdminPrincipal(
        AdminUserDto admin,
        AdminOidcSettings oidcSettings,
        System.Collections.Immutable.ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Subject,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, admin.Id.ToString("N"))
            .SetClaim(Claims.Email, admin.Email)
            .SetClaim(Claims.Role, AdminUser.AdminRole)
            .SetClaim(Claims.JwtId, Guid.NewGuid().ToString("N"));

        if (!string.IsNullOrWhiteSpace(admin.FullName))
        {
            identity.SetClaim(Claims.Name, admin.FullName);
        }

        identity.SetScopes(scopes);
        identity.SetResources(oidcSettings.Audience);
        identity.SetDestinations(claim => claim.Type switch
        {
            Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Email => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Name => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Role => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.JwtId => [Destinations.AccessToken],
            _ => [Destinations.AccessToken]
        });

        return new ClaimsPrincipal(identity);
    }

    private static IResult RenderAuthorizeForm(
        HttpContext context,
        OpenIddictRequest request,
        string requestToken,
        string? emailValue,
        string? errorMessage,
        int statusCode = StatusCodes.Status200OK)
    {
        context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        var sb = new StringBuilder(2048);
        sb.Append("""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Davids Admin Identity · OpenID Connect</title>
              <link rel="stylesheet" href="authorize.css">
            </head>
            <body>
              <main class="card">
                <span class="badge">Isolated Admin OIDC Provider</span>
                <h1>Administrator Sign In</h1>
                <p class="sub">Authenticate against the dedicated <code>adminidentitydb</code> OpenID Connect authority.</p>
            """);

        if (!string.IsNullOrWhiteSpace(errorMessage))
        {
            sb.Append($"<div class=\"error\" role=\"alert\">{WebUtility.HtmlEncode(errorMessage)}</div>");
        }

        sb.Append("<form method=\"post\" action=\"authorize\">");
        AppendHidden(sb, "request_token", requestToken);

        foreach (var parameter in request.GetParameters())
        {
            if (string.Equals(parameter.Key, "email", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parameter.Key, "password", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parameter.Key, "request_token", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = (string?)parameter.Value;
            if (value is not null)
            {
                AppendHidden(sb, parameter.Key, value);
            }
        }

        sb.Append($"""
                <label for="email">Administrator email</label>
                <input id="email" name="email" type="email" autocomplete="username" value="{WebUtility.HtmlEncode(emailValue ?? string.Empty)}" required>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
                <button type="submit">Sign In with OIDC</button>
              </form>
              <p class="meta">Confidential BFF Client: <code>{WebUtility.HtmlEncode(request.ClientId ?? string.Empty)}</code> · PKCE S256 · RS256</p>
            </main>
            </body>
            </html>
            """);

        return Results.Content(sb.ToString(), "text/html; charset=utf-8", Encoding.UTF8, statusCode);
    }

    private static void AppendHidden(StringBuilder sb, string name, string value)
        => sb.Append($"<input type=\"hidden\" name=\"{WebUtility.HtmlEncode(name)}\" value=\"{WebUtility.HtmlEncode(value)}\">");

    private static AdminLoginRequestMetadata ExtractAuditMetadata(HttpContext context, string? clientId)
    {
        var ip = context.Connection.RemoteIpAddress;
        var normalizedIp = ip is null
            ? null
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        var correlationId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = context.TraceIdentifier;
        }

        return new AdminLoginRequestMetadata(
            ClientId: clientId,
            ClientIpAddress: normalizedIp,
            UserAgent: context.Request.Headers.UserAgent.ToString(),
            CorrelationId: correlationId);
    }
}

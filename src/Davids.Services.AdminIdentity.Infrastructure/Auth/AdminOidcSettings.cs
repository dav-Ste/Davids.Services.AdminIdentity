using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using Davids.Services.AdminIdentity.Application.Services;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.AdminIdentity.Infrastructure.Auth;

public sealed class AdminOidcSettings
{
    public string? Issuer { get; set; }
    public string Audience { get; set; } = "davids-admin";
    public string BffClientId { get; set; } = "davids-admin-bff";
    public string BffClientSecret { get; set; } = string.Empty;
    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    public int RefreshTokenLifetimeHours { get; set; } = 8;
    public string? SigningKeyPem { get; set; }
    public string? EncryptionKeyPem { get; set; }
    public string? GatewayRedirectUri { get; set; }
    public string? GatewayPostLogoutRedirectUri { get; set; }
    public string[] AllowedRedirectUris { get; set; } =
    [
        "https://localhost/signin-oidc",
        "http://localhost:17320/signin-oidc",
        "https://localhost:17320/signin-oidc",
        "http://localhost:5000/signin-oidc",
        "https://localhost:5001/signin-oidc"
    ];
    public string[] AllowedPostLogoutRedirectUris { get; set; } =
    [
        "https://localhost/admin/login",
        "http://localhost:17320/admin/login",
        "https://localhost:17320/admin/login",
        "http://localhost:5000/admin/login",
        "https://localhost:5001/admin/login"
    ];

    public RsaSecurityKey PrivateSigningKey { get; private set; } = null!;
    public RsaSecurityKey PublicSigningSecurityKey { get; private set; } = null!;
    public RsaSecurityKey EncryptionSecurityKey { get; private set; } = null!;

    public Uri? NormalizedIssuerUri
        => string.IsNullOrWhiteSpace(Issuer)
            ? null
            : new Uri(Issuer.TrimEnd('/') + "/", UriKind.Absolute);

    public void InitializeKeys(bool requireExplicitEncryptionKey)
    {
        if (string.IsNullOrWhiteSpace(Audience) ||
            string.IsNullOrWhiteSpace(BffClientId) ||
            AccessTokenLifetimeMinutes <= 0 ||
            RefreshTokenLifetimeHours <= 0)
        {
            throw new InvalidOperationException("Invalid Admin Identity OIDC configuration.");
        }

        if (string.IsNullOrWhiteSpace(BffClientSecret) || BffClientSecret.Length < 24)
        {
            throw new InvalidOperationException(
                "Oidc:BffClientSecret must be configured with at least 24 characters via user-secrets or Vault.");
        }

        if (!string.IsNullOrWhiteSpace(Issuer) &&
            (!Uri.TryCreate(Issuer, UriKind.Absolute, out var issuerUri) ||
             (issuerUri.Scheme != Uri.UriSchemeHttp && issuerUri.Scheme != Uri.UriSchemeHttps)))
        {
            throw new InvalidOperationException("Oidc:Issuer must be a valid absolute HTTP(S) URI when configured.");
        }

        if (string.IsNullOrWhiteSpace(SigningKeyPem))
        {
            throw new InvalidOperationException(
                "Oidc:SigningKeyPem (2048-bit+ RSA private key) is required. Configure it via user-secrets or Vault.");
        }

        var signingParams = LoadRsaParameters(SigningKeyPem, "Oidc:SigningKeyPem");
        var signingKeyId = ComputeKeyId(signingParams);
        PrivateSigningKey = new RsaSecurityKey(signingParams) { KeyId = signingKeyId };
        PublicSigningSecurityKey = new RsaSecurityKey(new RSAParameters
        {
            Modulus = signingParams.Modulus,
            Exponent = signingParams.Exponent
        })
        {
            KeyId = signingKeyId
        };

        RSAParameters encParams;
        if (!string.IsNullOrWhiteSpace(EncryptionKeyPem))
        {
            encParams = LoadRsaParameters(EncryptionKeyPem, "Oidc:EncryptionKeyPem");
        }
        else if (!requireExplicitEncryptionKey)
        {
            using var generated = RSA.Create(2048);
            encParams = generated.ExportParameters(includePrivateParameters: true);
        }
        else
        {
            throw new InvalidOperationException(
                "Oidc:EncryptionKeyPem (2048-bit+ RSA private key) is required in Production.");
        }

        EncryptionSecurityKey = new RsaSecurityKey(encParams)
        {
            KeyId = "enc-" + ComputeKeyId(encParams)
        };
    }

    public TokenValidationParameters CreateValidationParameters(bool validateLifetime = true)
    {
        var issuerUri = NormalizedIssuerUri;
        return new TokenValidationParameters
        {
            ValidateIssuer = issuerUri is not null,
            ValidIssuer = issuerUri?.AbsoluteUri,
            ValidateAudience = true,
            ValidAudience = Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = PublicSigningSecurityKey,
            ValidateLifetime = validateLifetime,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = Claims.Subject,
            RoleClaimType = Claims.Role
        };
    }

    public static string GenerateRsaPrivateKeyPem(int keySizeInBits = 2048)
    {
        using var rsa = RSA.Create(keySizeInBits);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    private static RSAParameters LoadRsaParameters(string value, string settingName)
    {
        using var rsa = RSA.Create();
        var trimmed = value.Trim();
        try
        {
            if (trimmed.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(trimmed);
            }
            else
            {
                var raw = Convert.FromBase64String(trimmed);
                rsa.ImportPkcs8PrivateKey(raw, out _);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new InvalidOperationException($"{settingName} is not a valid RSA private key.", ex);
        }

        if (rsa.KeySize < 2048)
        {
            throw new InvalidOperationException($"{settingName} must be at least 2048 bits.");
        }

        return rsa.ExportParameters(includePrivateParameters: true);
    }

    private static string ComputeKeyId(RSAParameters parameters)
    {
        using var pub = RSA.Create();
        pub.ImportParameters(new RSAParameters
        {
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent
        });
        var spki = pub.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        return Base64UrlEncoder.Encode(hash)[..16];
    }
}

public sealed class AdminPasswordService : IAdminPasswordService
{
    private readonly PasswordHasher<AdminPasswordService> hasher = new();
    public string Hash(string password) => hasher.HashPassword(this, password);
    public bool IsValid(string hash, string password)
        => hasher.VerifyHashedPassword(this, hash, password) != PasswordVerificationResult.Failed;
}

public sealed class AdminOidcLoginStateProtector(IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector protector =
        dataProtectionProvider.CreateProtector("Davids.Services.AdminIdentity.OidcAuthorizeForm.v1");

    private sealed record Payload(
        string ClientId,
        string RedirectUri,
        string CodeChallenge,
        string State,
        long ExpiresUnixSeconds);

    public string Protect(string? clientId, string? redirectUri, string? codeChallenge, string? state)
    {
        var json = JsonSerializer.Serialize(new Payload(
            clientId ?? string.Empty,
            redirectUri ?? string.Empty,
            codeChallenge ?? string.Empty,
            state ?? string.Empty,
            DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds()));
        return protector.Protect(json);
    }

    public bool TryValidate(
        string? token,
        string? clientId,
        string? redirectUri,
        string? codeChallenge,
        string? state)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        try
        {
            var json = protector.Unprotect(token);
            var payload = JsonSerializer.Deserialize<Payload>(json);
            if (payload is null || payload.ExpiresUnixSeconds < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                return false;
            }

            return string.Equals(payload.ClientId, clientId ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(payload.RedirectUri, redirectUri ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(payload.CodeChallenge, codeChallenge ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(payload.State, state ?? string.Empty, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

public sealed class AdminOidcRevocationSyncHandler(
    IServiceProvider serviceProvider,
    AdminOidcSettings oidcSettings,
    IAdminRevocationCache revocationCache)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyRevocationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ApplyRevocationResponseContext>()
            .UseSingletonHandler<AdminOidcRevocationSyncHandler>()
            .SetOrder(int.MinValue + 100)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.ApplyRevocationResponseContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Request?.Token))
        {
            return;
        }

        if (!string.IsNullOrEmpty(context.Error) &&
            !string.Equals(context.Error, Errors.InvalidToken, StringComparison.Ordinal))
        {
            return;
        }

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        if (!handler.CanReadToken(context.Request.Token))
        {
            return;
        }

        try
        {
            handler.ValidateToken(
                context.Request.Token,
                oidcSettings.CreateValidationParameters(validateLifetime: false),
                out var validated);

            if (validated is not JwtSecurityToken jwt || string.IsNullOrWhiteSpace(jwt.Id))
            {
                return;
            }

            var expiresAt = jwt.ValidTo > DateTime.UtcNow ? jwt.ValidTo : DateTime.UtcNow.AddMinutes(5);
            await using var scope = serviceProvider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
            if (!await db.RevokedAdminAccessTokens.AnyAsync(x => x.TokenId == jwt.Id, context.CancellationToken))
            {
                db.RevokedAdminAccessTokens.Add(new RevokedAdminAccessToken
                {
                    TokenId = jwt.Id,
                    ExpiresAt = expiresAt
                });
                await db.SaveChangesAsync(context.CancellationToken);
            }

            await revocationCache.AddAsync(jwt.Id, expiresAt);
            AdminIdentitySecurityMetrics.RecordTokenRevocation("rfc7009_revocation");
        }
        catch (SecurityTokenException)
        {
            // Token was an encrypted JWE refresh token rather than an RS256 access token; OpenIddict already revoked it in DB.
        }
    }
}

public sealed class AdminOidcTokenErrorAuditHandler(IServiceProvider serviceProvider)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyTokenResponseContext>
{
    public const string AuditRecordedItemKey = "Davids.AdminTokenAuditRecorded";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ApplyTokenResponseContext>()
            .UseSingletonHandler<AdminOidcTokenErrorAuditHandler>()
            .SetOrder(int.MinValue + 100)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.ApplyTokenResponseContext context)
    {
        if (string.IsNullOrEmpty(context.Error))
        {
            return;
        }

        var httpContext = Microsoft.AspNetCore.OpenIddictServerAspNetCoreHelpers.GetHttpRequest(context.Transaction)?.HttpContext;
        if (httpContext?.Items.ContainsKey(AuditRecordedItemKey) == true)
        {
            return;
        }

        var ip = httpContext?.Connection.RemoteIpAddress;
        var clientIp = ip is null
            ? null
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        var correlationId = httpContext?.Request.Headers["X-Correlation-ID"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = httpContext?.TraceIdentifier;
        }

        var errorDescription = context.Response?.ErrorDescription;
        var entry = new Davids.Services.AdminIdentity.Core.Entities.AdminLoginAuditEntry(
            Guid.NewGuid(),
            DateTime.UtcNow,
            adminUserId: null,
            email: "[token-endpoint]",
            succeeded: false,
            outcome: "token_grant_rejected",
            failureReason: string.IsNullOrWhiteSpace(errorDescription)
                ? $"Token grant failed ({context.Error})."
                : $"{context.Error}: {errorDescription}",
            clientId: context.Request?.ClientId,
            clientIpAddress: clientIp,
            userAgent: httpContext?.Request.Headers.UserAgent.ToString(),
            correlationId: correlationId);

        await using var scope = serviceProvider.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<Davids.Services.AdminIdentity.Core.Repositories.IAdminLoginAuditRepository>();
        await repo.AddAsync(entry, context.CancellationToken);
    }
}

public sealed class AdminOidcApplicationSeeder(IServiceProvider serviceProvider, AdminOidcSettings settings)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private volatile bool seeded;

    public async Task EnsureSeededAsync(CancellationToken cancellationToken = default)
    {
        if (seeded)
        {
            return;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            if (seeded)
            {
                return;
            }

            await using var scope = serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = settings.BffClientId,
                ClientSecret = settings.BffClientSecret,
                ClientType = ClientTypes.Confidential,
                DisplayName = "Davids Admin Gateway OIDC BFF Client",
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Permissions.Prefixes.Scope + settings.Audience
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            };

            var redirectUris = settings.AllowedRedirectUris
                .Concat([settings.GatewayRedirectUri])
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => u!)
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var redirect in redirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(redirect, UriKind.Absolute));
            }

            var postLogoutUris = settings.AllowedPostLogoutRedirectUris
                .Concat([settings.GatewayPostLogoutRedirectUri])
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Select(u => u!)
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var logoutRedirect in postLogoutUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(logoutRedirect, UriKind.Absolute));
            }

            var existing = await manager.FindByClientIdAsync(settings.BffClientId, cancellationToken);
            if (existing is null)
            {
                await manager.CreateAsync(descriptor, cancellationToken);
            }
            else
            {
                await manager.UpdateAsync(existing, descriptor, cancellationToken);
            }

            seeded = true;
        }
        finally
        {
            gate.Release();
        }
    }
}

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Davids.Services.AdminIdentity.Application.DTO;
using Davids.Services.AdminIdentity.Application.Services;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Repositories;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Davids.Services.AdminIdentity.Infrastructure.Persistence;
using Davids.Services.AdminIdentity.Infrastructure.Secrets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Davids.Services.AdminIdentity.Tests;

public sealed class AdminIdentityFactory(int authPermitLimit = 50, IAdminRevocationCache? revocationCache = null)
    : WebApplicationFactory<Program>
{
    public static readonly string TestSigningKeyPem = AdminOidcSettings.GenerateRsaPrivateKeyPem();
    public static readonly string TestEncryptionKeyPem = AdminOidcSettings.GenerateRsaPrivateKeyPem();
    public const string BffClientId = "davids-admin-bff";
    public const string BffClientSecret = "test-admin-bff-client-secret-minimum-24-chars!";

    private readonly SqliteConnection connection = new("Data Source=:memory:");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        connection.Open();
        builder.UseEnvironment("Testing");
        builder.UseSetting("Oidc:Issuer", "https://localhost/");
        builder.UseSetting("Oidc:Audience", "davids-admin");
        builder.UseSetting("Oidc:BffClientId", BffClientId);
        builder.UseSetting("Oidc:BffClientSecret", BffClientSecret);
        builder.UseSetting("Oidc:SigningKeyPem", TestSigningKeyPem);
        builder.UseSetting("Oidc:EncryptionKeyPem", TestEncryptionKeyPem);
        builder.UseSetting("RateLimiting:AuthPermitLimit", authPermitLimit.ToString());
        builder.UseSetting("ConnectionStrings:adminidentitydb", "unused");
        builder.UseSetting("Vault:Enabled", "false");
        builder.UseSetting("Redis:Enabled", "false");

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<AdminIdentityDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<AdminIdentityDbContext>>();
            services.RemoveAll<AdminIdentityDbContext>();
            services.AddDbContext<AdminIdentityDbContext>(options =>
            {
                options.UseSqlite(connection);
                options.UseOpenIddict();
            });

            if (revocationCache is not null)
            {
                services.RemoveAll<IAdminRevocationCache>();
                services.AddSingleton(revocationCache);
            }
        });
    }

    public HttpClient CreateAdminClient()
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var scope = Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>().Database.EnsureCreated();
        return client;
    }

    public async Task<AdminUser> SeedAdminAsync(
        string email = "admin@davids.local",
        string password = "Admin-Correct-Horse-123!",
        string fullName = "Root Admin",
        bool isActive = true)
    {
        using var scope = Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<IAdminUserRepository>();
        var passwords = scope.ServiceProvider.GetRequiredService<IAdminPasswordService>();
        var admin = new AdminUser(
            Guid.NewGuid(),
            email,
            passwords.Hash(password),
            fullName,
            isActive,
            DateTime.UtcNow);
        await users.AddAsync(admin);
        return admin;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            connection.Dispose();
        }
    }
}

public sealed record AdminOidcTokens(string AccessToken, string IdToken, string RefreshToken);

[Trait("Category", "Integration")]
public sealed class AdminIdentityTests
{
    private const string AdminPassword = "Admin-Correct-Horse-123!";
    private const string RedirectUri = "https://localhost/signin-oidc";

    private sealed class RecordingRevocationCache : IAdminRevocationCache
    {
        public HashSet<string> RevokedTokenIds { get; } = new(StringComparer.Ordinal);
        public Task<bool> ContainsAsync(string tokenId) => Task.FromResult(RevokedTokenIds.Contains(tokenId));
        public Task AddAsync(string tokenId, DateTime expiresAt)
        {
            RevokedTokenIds.Add(tokenId);
            return Task.CompletedTask;
        }
    }

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static string ExtractHiddenField(string html, string fieldName)
    {
        var match = Regex.Match(
            html,
            $"name=\"{Regex.Escape(fieldName)}\"\\s+value=\"([^\"]*)\"",
            RegexOptions.IgnoreCase);
        Assert.True(match.Success, $"Missing hidden input '{fieldName}' in admin authorize HTML.");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    internal static async Task<AdminOidcTokens> SignInAdminOidcAsync(
        HttpClient client,
        string email = "ADMIN@davids.local",
        string password = AdminPassword)
    {
        var (verifier, challenge) = CreatePkcePair();
        var state = "adm-" + Guid.NewGuid().ToString("N");
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["response_mode"] = "query",
            ["scope"] = "openid email profile roles offline_access davids-admin",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state
        });

        var getAuthorize = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.OK, getAuthorize.StatusCode);
        var html = await getAuthorize.Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");
        Assert.Equal("query", ExtractHiddenField(html, "response_mode"));

        using var postAuthorize = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["response_mode"] = "query",
            ["scope"] = "openid email profile roles offline_access davids-admin",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state,
            ["request_token"] = requestToken,
            ["email"] = email,
            ["password"] = password
        }));

        Assert.Equal(HttpStatusCode.Redirect, postAuthorize.StatusCode);
        var query = QueryHelpers.ParseQuery(postAuthorize.Headers.Location!.Query);
        Assert.Equal(state, query["state"].ToString());
        var code = query["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));

        using var tokenResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        using var doc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        return new AdminOidcTokens(
            root.GetProperty("access_token").GetString()!,
            root.GetProperty("id_token").GetString()!,
            root.GetProperty("refresh_token").GetString()!);
    }

    [Fact]
    public async Task PublicSignUpEndpointDoesNotExistOnAdminIdentity()
    {
        using var factory = new AdminIdentityFactory();
        using var client = factory.CreateAdminClient();

        using var response = await client.PostAsJsonAsync("/sign-up", new
        {
            email = "attacker@example.com",
            password = AdminPassword,
            role = "admin"
        });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DiscoveryJwksAndConfidentialPkceSignInIssueDedicatedRs256AdminJwtAndRejectCustomerKeys()
    {
        using var factory = new AdminIdentityFactory();
        using var client = factory.CreateAdminClient();
        var rootAdmin = await factory.SeedAdminAsync();

        using var discoveryDoc = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        Assert.Equal("https://localhost/", discoveryDoc.RootElement.GetProperty("issuer").GetString());
        using var jwksDoc = JsonDocument.Parse(await client.GetStringAsync("/.well-known/jwks"));
        Assert.Contains(
            jwksDoc.RootElement.GetProperty("keys").EnumerateArray(),
            k => k.GetProperty("kty").GetString() == "RSA" && k.GetProperty("alg").GetString() == "RS256");

        var tokens = await SignInAdminOidcAsync(client);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken);
        Assert.Equal(SecurityAlgorithms.RsaSha256, jwt.Header.Alg);
        Assert.Equal("https://localhost/", jwt.Issuer);
        Assert.Contains("davids-admin", jwt.Audiences);
        Assert.Equal("admin", jwt.Claims.Single(c => c.Type == "role").Value);
        Assert.Equal(rootAdmin.Id.ToString("N"), jwt.Subject);

        // A JWT signed with a separate customer RSA key must be rejected on Admin Identity endpoints.
        using var customerRsa = RSA.Create(2048);
        var forgedCustomerJwt = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            issuer: "https://localhost/",
            audience: "davids-admin",
            claims:
            [
                new Claim("sub", Guid.NewGuid().ToString("N")),
                new Claim("role", "admin"),
                new Claim("jti", Guid.NewGuid().ToString("N"))
            ],
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: new SigningCredentials(new RsaSecurityKey(customerRsa), SecurityAlgorithms.RsaSha256)));

        using var customerAttempt = new HttpRequestMessage(HttpMethod.Get, "/me");
        customerAttempt.Headers.Authorization = new AuthenticationHeaderValue("Bearer", forgedCustomerJwt);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(customerAttempt)).StatusCode);

        // Authenticated admin can read /me, /connect/userinfo, provision a fellow admin via POST /users, and list /users.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var me = await client.GetFromJsonAsync<AdminUserDto>("/me");
        Assert.Equal(rootAdmin.Id, me!.Id);
        Assert.Equal("Root Admin", me.FullName);

        using var userInfo = JsonDocument.Parse(await client.GetStringAsync("/connect/userinfo"));
        Assert.Equal("admin@davids.local", userInfo.RootElement.GetProperty("email").GetString());
        Assert.Equal("Root Admin", userInfo.RootElement.GetProperty("name").GetString());

        var createResponse = await client.PostAsJsonAsync("/users", new
        {
            adminId = Guid.Empty,
            email = "ops.admin@davids.local",
            password = "Ops-Admin-Strong-Pass-987!",
            fullName = "Operations Admin"
        });
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);

        var duplicateResponse = await client.PostAsJsonAsync("/users", new
        {
            adminId = Guid.Empty,
            email = "OPS.ADMIN@davids.local",
            password = "Ops-Admin-Strong-Pass-987!",
            fullName = "Duplicate"
        });
        Assert.Equal(HttpStatusCode.Conflict, duplicateResponse.StatusCode);

        var allAdmins = await client.GetFromJsonAsync<AdminUserDto[]>("/users");
        Assert.Equal(2, allAdmins!.Length);
    }

    [Fact]
    public async Task ConfidentialClientRequiresClientSecretAndRefreshTokenReplayRevokesActiveSessions()
    {
        using var factory = new AdminIdentityFactory();
        using var client = factory.CreateAdminClient();
        await factory.SeedAdminAsync();

        var initial = await SignInAdminOidcAsync(client);

        // Missing client_secret must be rejected because davids-admin-bff is a confidential client.
        var unauthenticatedRefresh = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["refresh_token"] = initial.RefreshToken
        }));
        Assert.True(unauthenticatedRefresh.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized);

        var rotatedResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["refresh_token"] = initial.RefreshToken
        }));
        Assert.Equal(HttpStatusCode.OK, rotatedResponse.StatusCode);
        using var rotatedDoc = JsonDocument.Parse(await rotatedResponse.Content.ReadAsStringAsync());
        var rotatedRefreshToken = rotatedDoc.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(initial.RefreshToken, rotatedRefreshToken);

        // Replaying the already-rotated token fails AND revokes the descendant session token chain!
        var replayResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["refresh_token"] = initial.RefreshToken
        }));
        Assert.Equal(HttpStatusCode.BadRequest, replayResponse.StatusCode);

        var compromisedDescendant = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["refresh_token"] = rotatedRefreshToken
        }));
        Assert.Equal(HttpStatusCode.BadRequest, compromisedDescendant.StatusCode);
    }

    [Fact]
    public async Task AccessTokenRevocationPopulatesCacheAndBlocksSubsequentRequests()
    {
        var cache = new RecordingRevocationCache();
        using var factory = new AdminIdentityFactory(revocationCache: cache);
        using var client = factory.CreateAdminClient();
        await factory.SeedAdminAsync();

        var tokens = await SignInAdminOidcAsync(client);
        var jti = new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken).Id;

        var revoke = await client.PostAsync("/connect/revocation", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["token"] = tokens.AccessToken,
            ["token_type_hint"] = "access_token"
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Contains(jti, cache.RevokedTokenIds);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/connect/userinfo")).StatusCode);
    }

    [Fact]
    public async Task DisabledAdminIsForbiddenAndStricterRateLimitBlocksRepeatedAuthorizePosts()
    {
        using var factory = new AdminIdentityFactory(authPermitLimit: 2);
        using var client = factory.CreateAdminClient();
        await factory.SeedAdminAsync(email: "disabled@davids.local", isActive: false);

        var (_, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-rate"
        });
        var html = await (await client.GetAsync(authorizeUrl)).Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");

        FormUrlEncodedContent BuildForm(string email, string pw) => new(new Dictionary<string, string>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-rate",
            ["request_token"] = requestToken,
            ["email"] = email,
            ["password"] = pw
        });

        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync("/connect/authorize", BuildForm("disabled@davids.local", AdminPassword))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/connect/authorize", BuildForm("disabled@davids.local", "wrong"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsync("/connect/authorize", BuildForm("disabled@davids.local", "wrong"))).StatusCode);
    }

    [Fact]
    public async Task ForwardedHeadersBucketRateLimitsPerClientIpAndPerAccountLockoutStopsDistributedBruteForce()
    {
        using var baseFactory = new AdminIdentityFactory(authPermitLimit: 2);
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Lockout:MaxFailedAccessAttempts", "3");
            b.UseSetting("Lockout:DurationMinutes", "15");
            b.ConfigureServices(services =>
            {
                // Simulate requests arriving over loopback from the local YARP API Gateway on TestServer.
                services.AddSingleton<IStartupFilter>(new DefaultLoopbackRemoteIpStartupFilter());
            });
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var initScope = factory.Services.CreateScope())
        {
            initScope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>().Database.EnsureCreated();
            var users = initScope.ServiceProvider.GetRequiredService<IAdminUserRepository>();
            var passwords = initScope.ServiceProvider.GetRequiredService<IAdminPasswordService>();
            await users.AddAsync(new AdminUser(
                Guid.NewGuid(),
                "lockout-admin@davids.local",
                passwords.Hash(AdminPassword),
                "Lockout Admin",
                isActive: true,
                DateTime.UtcNow));
        }

        var (_, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-ip"
        });
        var getForm = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.OK, getForm.StatusCode);
        var requestToken = ExtractHiddenField(await getForm.Content.ReadAsStringAsync(), "request_token");

        HttpRequestMessage BuildPost(string email, string pw, string forwardedForIp)
        {
            var msg = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = AdminIdentityFactory.BffClientId,
                    ["redirect_uri"] = RedirectUri,
                    ["response_type"] = "code",
                    ["scope"] = "openid email",
                    ["code_challenge"] = challenge,
                    ["code_challenge_method"] = "S256",
                    ["state"] = "st-ip",
                    ["request_token"] = requestToken,
                    ["email"] = email,
                    ["password"] = pw
                })
            };
            msg.Headers.TryAddWithoutValidation("X-Forwarded-For", forwardedForIp);
            return msg;
        }

        // 1. Exhaust IP 198.51.100.10's per-IP limit (2 req/min) against a nonexistent email so account lockout isn't triggered yet.
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildPost("nobody@davids.local", "wrong", "198.51.100.10"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildPost("nobody@davids.local", "wrong", "198.51.100.10"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.SendAsync(BuildPost("nobody@davids.local", "wrong", "198.51.100.10"))).StatusCode);

        // 2. Another client IP (198.51.100.20) behind the same YARP gateway is NOT blocked by 198.51.100.10!
        //    Now simulate a distributed brute-force attack rotating across 3 distinct client IPs against lockout-admin@davids.local.
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildPost("lockout-admin@davids.local", "wrong-1", "198.51.100.20"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildPost("lockout-admin@davids.local", "wrong-2", "198.51.100.21"))).StatusCode);

        // 3rd failed attempt from a 3rd IP triggers per-account lockout (429).
        var lockResp = await client.SendAsync(BuildPost("lockout-admin@davids.local", "wrong-3", "198.51.100.22"));
        Assert.Equal(HttpStatusCode.TooManyRequests, lockResp.StatusCode);
        Assert.Contains("temporarily locked", await lockResp.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);

        // Even the valid password from a brand-new IP (198.51.100.99) is rejected while locked out.
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.SendAsync(BuildPost("lockout-admin@davids.local", AdminPassword, "198.51.100.99"))).StatusCode);
    }

    [Fact]
    public async Task CanceledHealthCheckAndRequestAbortedDoNotThrowUnhandledTaskCanceledException()
    {
        using var factory = new AdminIdentityFactory();
        using var client = factory.CreateAdminClient();

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
        var healthCheck = new AdminDatabaseHealthCheck(db);
        using var canceledCts = new CancellationTokenSource();
        canceledCts.Cancel();

        var healthResult = await healthCheck.CheckHealthAsync(new HealthCheckContext(), canceledCts.Token);
        Assert.Equal(HealthStatus.Unhealthy, healthResult.Status);

        var exceptionHandler = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Diagnostics.IExceptionHandler>();
        var abortedHttpContext = new DefaultHttpContext
        {
            RequestAborted = canceledCts.Token
        };
        var handled = await exceptionHandler.TryHandleAsync(
            abortedHttpContext,
            new TaskCanceledException("A task was canceled."),
            CancellationToken.None);
        Assert.True(handled);
        Assert.Equal(StatusCodes.Status499ClientClosedRequest, abortedHttpContext.Response.StatusCode);
    }

    [Fact]
    public async Task DataProtectionKeysArePersistedAndEncryptedAtRestInAdminIdentityDb()
    {
        using var baseFactory = new AdminIdentityFactory();
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("DataProtection:MasterKey", "admin-identity-dp-master-key-at-least-32-bytes!");
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var initScope = factory.Services.CreateScope())
        {
            initScope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>().Database.EnsureCreated();
        }

        var (_, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "dp-admin-state"
        });

        var getResp = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.OK, getResp.StatusCode);
        var requestToken = ExtractHiddenField(await getResp.Content.ReadAsStringAsync(), "request_token");
        Assert.False(string.IsNullOrWhiteSpace(requestToken));

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
        var storedKeys = await db.DataProtectionKeys.AsNoTracking().ToListAsync();
        Assert.NotEmpty(storedKeys);
        foreach (var row in storedKeys)
        {
            Assert.Contains("encryptedKey", row.Xml, StringComparison.Ordinal);
            Assert.DoesNotContain("<masterKey", row.Xml, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task VaultAndDevelopmentSeedContractsEnforceAdminBoundaries()
    {
        var vaultConfig = new ConfigurationManager();
        vaultConfig["Vault:Enabled"] = "true";
        vaultConfig["Vault:Address"] = "http://127.0.0.1:1";
        await Assert.ThrowsAsync<InvalidOperationException>(() => vaultConfig.LoadVaultAsync());

        Assert.Throws<InvalidOperationException>(() =>
        {
            using var prodFactory = new AdminIdentityFactory().WithWebHostBuilder(b =>
            {
                b.UseEnvironment("Production");
                b.UseSetting("SeedAdmin:Enabled", "true");
                b.UseSetting("SeedAdmin:Email", "admin@davids.local");
                b.UseSetting("SeedAdmin:Password", AdminPassword);
            });
            using var _ = prodFactory.CreateClient();
        });
    }

    [Fact]
    public async Task LoginAttemptsAreAuditedInAdminIdentityDbWithoutSecretsAndExposedOnlyToAdmins()
    {
        using var baseFactory = new AdminIdentityFactory(authPermitLimit: 50);
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Lockout:MaxFailedAccessAttempts", "2");
            b.UseSetting("ForwardedHeaders:TrustLoopbackProxies", "true");
            b.ConfigureServices(services =>
                services.AddSingleton<IStartupFilter, DefaultLoopbackRemoteIpStartupFilter>());
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        AdminUser activeAdmin;
        AdminUser disabledAdmin;
        AdminUser lockTargetAdmin;
        await using (var seedScope = factory.Services.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
            await db.Database.EnsureCreatedAsync();
            var users = seedScope.ServiceProvider.GetRequiredService<IAdminUserRepository>();
            var passwords = seedScope.ServiceProvider.GetRequiredService<IAdminPasswordService>();

            activeAdmin = new AdminUser(Guid.NewGuid(), "audit-root@davids.local", passwords.Hash(AdminPassword), "Audit Root", true, DateTime.UtcNow);
            disabledAdmin = new AdminUser(Guid.NewGuid(), "audit-disabled@davids.local", passwords.Hash(AdminPassword), "Disabled Admin", false, DateTime.UtcNow);
            lockTargetAdmin = new AdminUser(Guid.NewGuid(), "audit-lock@davids.local", passwords.Hash(AdminPassword), "Lock Admin", true, DateTime.UtcNow);
            await users.AddAsync(activeAdmin);
            await users.AddAsync(disabledAdmin);
            await users.AddAsync(lockTargetAdmin);
        }

        // Anonymous callers cannot inspect administrator login audit records.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/login-audits")).StatusCode);

        var (verifier, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles offline_access davids-admin",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-audit"
        });
        var html = await (await client.GetAsync(authorizeUrl)).Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");

        HttpRequestMessage CreateAuthorizePost(string email, string password, string token, string ip, string correlationId)
        {
            var msg = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = AdminIdentityFactory.BffClientId,
                    ["redirect_uri"] = RedirectUri,
                    ["response_type"] = "code",
                    ["scope"] = "openid email profile roles offline_access davids-admin",
                    ["code_challenge"] = challenge,
                    ["code_challenge_method"] = "S256",
                    ["state"] = "st-audit",
                    ["request_token"] = token,
                    ["email"] = email,
                    ["password"] = password
                })
            };
            msg.Headers.TryAddWithoutValidation("X-Forwarded-For", ip);
            msg.Headers.TryAddWithoutValidation("X-Correlation-ID", correlationId);
            msg.Headers.TryAddWithoutValidation("User-Agent", "DavidsAuditTest/1.0");
            return msg;
        }

        const string wrongSecretAttempt = "Wrong-Super-Secret-Attempt-999!";

        // 1. Tampered request_token -> invalid_request_token
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(CreateAuthorizePost("audit-root@davids.local", AdminPassword, "tampered-token", "203.0.113.41", "corr-admin-1"))).StatusCode);

        // 2. Unknown administrator email -> invalid_credentials
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(CreateAuthorizePost("ghost@davids.local", wrongSecretAttempt, requestToken, "203.0.113.42", "corr-admin-2"))).StatusCode);

        // 3. Disabled administrator -> account_disabled
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(CreateAuthorizePost("audit-disabled@davids.local", AdminPassword, requestToken, "203.0.113.43", "corr-admin-3"))).StatusCode);

        // 4. Wrong password + threshold lockout -> invalid_credentials then account_locked
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(CreateAuthorizePost("audit-lock@davids.local", wrongSecretAttempt, requestToken, "203.0.113.44", "corr-admin-4"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.SendAsync(CreateAuthorizePost("audit-lock@davids.local", wrongSecretAttempt, requestToken, "203.0.113.45", "corr-admin-5"))).StatusCode);

        // 5. Invalid refresh_token grant -> token_grant_rejected
        var badGrantReq = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = AdminIdentityFactory.BffClientId,
                ["client_secret"] = AdminIdentityFactory.BffClientSecret,
                ["refresh_token"] = "non-existent-refresh-token"
            })
        };
        badGrantReq.Headers.TryAddWithoutValidation("X-Forwarded-For", "203.0.113.46");
        badGrantReq.Headers.TryAddWithoutValidation("X-Correlation-ID", "corr-admin-6");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(badGrantReq)).StatusCode);

        // 6. Successful administrator OIDC login -> succeeded
        var okPost = await client.SendAsync(CreateAuthorizePost("audit-root@davids.local", AdminPassword, requestToken, "203.0.113.47", "corr-admin-7"));
        Assert.Equal(HttpStatusCode.Redirect, okPost.StatusCode);
        var code = QueryHelpers.ParseQuery(okPost.Headers.Location!.Query)["code"].ToString();
        var tokenResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        using var tokenDoc = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var accessToken = tokenDoc.RootElement.GetProperty("access_token").GetString()!;

        // Inspect persisted rows in adminidentitydb and ensure NO secrets or passwords are stored.
        await using (var verifyScope = factory.Services.CreateAsyncScope())
        {
            var db = verifyScope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
            var rows = await db.AdminLoginAuditLogs.AsNoTracking().ToListAsync();
            Assert.Equal(7, rows.Count);
            foreach (var row in rows)
            {
                var combined = $"{row.Email}|{row.Outcome}|{row.FailureReason}|{row.ClientId}|{row.ClientIpAddress}|{row.UserAgent}|{row.CorrelationId}";
                Assert.DoesNotContain(AdminPassword, combined, StringComparison.Ordinal);
                Assert.DoesNotContain(wrongSecretAttempt, combined, StringComparison.Ordinal);
                Assert.DoesNotContain("non-existent-refresh-token", combined, StringComparison.Ordinal);
            }
        }

        // Verify AdminOnly GET /login-audits endpoint + query filters.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var allAudits = await client.GetFromJsonAsync<AdminLoginAuditDto[]>("/login-audits?limit=50");
        Assert.NotNull(allAudits);
        Assert.Equal(7, allAudits.Length);
        Assert.Contains(allAudits, a => a.Succeeded && a.Outcome == "succeeded" && a.AdminUserId == activeAdmin.Id && a.ClientIpAddress == "203.0.113.47" && a.CorrelationId == "corr-admin-7");
        Assert.Contains(allAudits, a => !a.Succeeded && a.Outcome == "invalid_request_token" && a.CorrelationId == "corr-admin-1");
        Assert.Contains(allAudits, a => !a.Succeeded && a.Outcome == "account_disabled" && a.AdminUserId == disabledAdmin.Id);
        Assert.Contains(allAudits, a => !a.Succeeded && a.Outcome == "account_locked" && a.AdminUserId == lockTargetAdmin.Id);
        Assert.Contains(allAudits, a => !a.Succeeded && a.Outcome == "token_grant_rejected" && a.CorrelationId == "corr-admin-6");

        var failedForLockUser = await client.GetFromJsonAsync<AdminLoginAuditDto[]>("/login-audits?succeeded=false&email=AUDIT-LOCK@davids.local");
        Assert.NotNull(failedForLockUser);
        Assert.Equal(2, failedForLockUser.Length);
        Assert.All(failedForLockUser, a => Assert.False(a.Succeeded));
    }

    [Fact]
    public async Task OpenApiContractAndFuzzingBoundariesEnforceStagingDastInvariants()
    {
        await using var baseFactory = new AdminIdentityFactory();
        using var nonDevClient = baseFactory.CreateClient();

        // /openapi/v1.json and /sign-up are never exposed in non-Development environments.
        Assert.Equal(HttpStatusCode.NotFound, (await nonDevClient.GetAsync("/openapi/v1.json")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await nonDevClient.PostAsync("/sign-up", null)).StatusCode);

        // Percent-encoded null bytes (%00) in form-urlencoded /connect/token return 400 Bad Request, never 500.
        var nullByteForm = new StringContent(
            "grant_type=authorization_code&client_id=davids-admin-cli&code=%00&code_verifier=abc",
            Encoding.UTF8,
            "application/x-www-form-urlencoded");
        Assert.Equal(HttpStatusCode.BadRequest, (await nonDevClient.PostAsync("/connect/token", nullByteForm)).StatusCode);

        await using var devFactory = baseFactory.WithWebHostBuilder(wb => wb.UseEnvironment("Development"));
        using var devClient = devFactory.CreateClient();
        var openApiResp = await devClient.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, openApiResp.StatusCode);

        using var doc = JsonDocument.Parse(await openApiResp.Content.ReadAsStringAsync());
        Assert.Equal("3.1.1", doc.RootElement.GetProperty("openapi").GetString());
        Assert.True(doc.RootElement.GetProperty("components").GetProperty("securitySchemes").TryGetProperty("BearerAuth", out _));
        Assert.False(doc.RootElement.GetProperty("paths").TryGetProperty("/sign-up", out _));
    }

    [Fact]
    public async Task AdminAuthCodeReplayCascadeRevokesIssuedAdminAccessToken()
    {
        var cache = new RecordingRevocationCache();
        using var factory = new AdminIdentityFactory(revocationCache: cache);
        using var client = factory.CreateAdminClient();
        await factory.SeedAdminAsync(email: "release-admin@davids.local");

        var (verifier, challenge) = CreatePkcePair();
        var state = "adm-release-" + Guid.NewGuid().ToString("N");
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["response_mode"] = "query",
            ["scope"] = "openid email profile roles offline_access davids-admin",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state
        });

        var getAuthorize = await client.GetAsync(authorizeUrl);
        var requestToken = ExtractHiddenField(await getAuthorize.Content.ReadAsStringAsync(), "request_token");

        using var postAuthorize = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["response_mode"] = "query",
            ["scope"] = "openid email profile roles offline_access davids-admin",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state,
            ["request_token"] = requestToken,
            ["email"] = "release-admin@davids.local",
            ["password"] = AdminPassword
        }));
        var code = QueryHelpers.ParseQuery(postAuthorize.Headers.Location!.Query)["code"].ToString();

        using var tokenResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        using var tokenDoc = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var accessToken = tokenDoc.RootElement.GetProperty("access_token").GetString()!;
        var jti = new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Id;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/me")).StatusCode);

        // Replaying the redeemed authorization code fails (400) AND immediately cascade-revokes the issued admin RS256 access_token.
        using var replayResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["client_secret"] = AdminIdentityFactory.BffClientSecret,
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.BadRequest, replayResp.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
        Assert.Contains(jti, cache.RevokedTokenIds);
    }

    private sealed class DefaultLoopbackRemoteIpStartupFilter : IStartupFilter
    {
        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(
            Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) =>
            app =>
            {
                app.Use((ctx, innerNext) =>
                {
                    ctx.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    return innerNext();
                });
                next(app);
            };
    }
}

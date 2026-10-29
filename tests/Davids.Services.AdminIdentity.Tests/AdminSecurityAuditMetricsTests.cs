using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Repositories;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Davids.Services.AdminIdentity.Tests;

[Trait("Category", "Integration")]
public sealed class AdminSecurityAuditMetricsTests
{
    [Fact]
    public async Task AdminLockoutTamperedLoginAndRfc7009RevocationEmitSecurityMetrics()
    {
        var events = new ConcurrentBag<(string Name, string Domain, string Outcome, string Source)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == AdminIdentitySecurityMetrics.MeterName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
        {
            string domain = string.Empty, outcome = string.Empty, source = string.Empty;
            foreach (var tag in tags)
            {
                if (tag.Key == "domain") domain = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "outcome") outcome = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "source") source = tag.Value?.ToString() ?? string.Empty;
            }
            events.Add((instrument.Name, domain, outcome, source));
        });
        listener.Start();

        using var factory = new AdminIdentityFactory();
        using var client = factory.CreateAdminClient();

        using (var scope = factory.Services.CreateScope())
        {
            var auditRepo = scope.ServiceProvider.GetRequiredService<IAdminLoginAuditRepository>();
            await auditRepo.AddAsync(new AdminLoginAuditEntry(
                Guid.NewGuid(),
                DateTime.UtcNow,
                adminUserId: null,
                email: "secops-admin@davids.test",
                succeeded: false,
                outcome: "account_locked",
                clientIpAddress: "198.51.100.88",
                userAgent: "RuntimeAuditTest/1.0"));
        }

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = AdminIdentityFactory.BffClientId,
            ["redirect_uri"] = "https://localhost/signin-oidc",
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles davids-admin",
            ["code_challenge"] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ["code_challenge_method"] = "S256",
            ["state"] = "audit-admin-state",
            ["request_token"] = "tampered-admin-request-token",
            ["email"] = "secops-admin@davids.test",
            ["password"] = "WrongPassword123!"
        });
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/connect/authorize", form)).StatusCode);

        await factory.SeedAdminAsync("audit-admin@davids.local", "Admin-Correct-Horse-123!", "Audit Admin");
        var adminTokens = await AdminIdentityTests.SignInAdminOidcAsync(client, "audit-admin@davids.local", "Admin-Correct-Horse-123!");

        using var revokeReq = new HttpRequestMessage(HttpMethod.Post, "/connect/revocation")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = adminTokens.AccessToken,
                ["token_type_hint"] = "access_token"
            })
        };
        var basicCreds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{AdminIdentityFactory.BffClientId}:{AdminIdentityFactory.BffClientSecret}"));
        revokeReq.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicCreds);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(revokeReq)).StatusCode);

        Assert.Contains(events, e =>
            e.Name == "davids.security.login_audit" &&
            e.Domain == "admin" &&
            e.Outcome == "account_locked");
        Assert.Contains(events, e =>
            e.Name == "davids.security.login_audit" &&
            e.Domain == "admin" &&
            e.Outcome == "invalid_request_token");
        Assert.Contains(events, e =>
            e.Name == "davids.security.token_revoked" &&
            e.Domain == "admin" &&
            e.Source == "rfc7009_revocation");
    }
}

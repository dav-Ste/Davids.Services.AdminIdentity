using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Davids.Services.AdminIdentity.Application.Commands;
using Davids.Services.AdminIdentity.Application.DTO;
using Davids.Services.AdminIdentity.Core.Entities;
using Xunit;

namespace Davids.Services.AdminIdentity.Tests;

[Trait("Category", "Integration")]
public sealed class WorkforceRbacAndChangeAuditTests
{
    private const string RootPassword = "Admin-Correct-Horse-123!";
    private const string SupportPassword = "Support-Correct-Horse-123!";
    private const string AuditorPassword = "Auditor-Correct-Horse-123!";

    [Fact]
    public async Task WorkforceRolesEnforceRbacAndRecordTransactionalChangeAudits()
    {
        await using var factory = new AdminIdentityFactory(authPermitLimit: 100);
        using var client = factory.CreateAdminClient();
        var rootAdmin = await factory.SeedAdminAsync("root@davids.local", RootPassword);

        var rootTokens = await AdminIdentityTests.SignInAdminOidcAsync(client, rootAdmin.Email, RootPassword);

        // 1. Root admin provisions 'support' and 'auditor' employees.
        using var createSupportReq = new HttpRequestMessage(HttpMethod.Post, "/users")
        {
            Content = JsonContent.Create(new CreateAdminUser(
                Guid.Empty,
                "support@davids.local",
                SupportPassword,
                "Support Agent",
                AdminUser.SupportRole))
        };
        createSupportReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rootTokens.AccessToken);
        createSupportReq.Headers.Add("X-Correlation-Id", "corr-support-create");
        using var createSupportResp = await client.SendAsync(createSupportReq);
        Assert.Equal(HttpStatusCode.Created, createSupportResp.StatusCode);
        var supportDto = await createSupportResp.Content.ReadFromJsonAsync<AdminUserDto>();
        Assert.NotNull(supportDto);
        Assert.Equal(AdminUser.SupportRole, supportDto!.Role);

        using var createAuditorReq = new HttpRequestMessage(HttpMethod.Post, "/users")
        {
            Content = JsonContent.Create(new CreateAdminUser(
                Guid.Empty,
                "auditor@davids.local",
                AuditorPassword,
                "Security Auditor",
                AdminUser.AuditorRole))
        };
        createAuditorReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rootTokens.AccessToken);
        using var createAuditorResp = await client.SendAsync(createAuditorReq);
        Assert.Equal(HttpStatusCode.Created, createAuditorResp.StatusCode);
        var auditorDto = await createAuditorResp.Content.ReadFromJsonAsync<AdminUserDto>();
        Assert.NotNull(auditorDto);
        Assert.Equal(AdminUser.AuditorRole, auditorDto!.Role);

        // 2. Non-workforce role ('user') is rejected with 400.
        using var badRoleReq = new HttpRequestMessage(HttpMethod.Post, "/users")
        {
            Content = JsonContent.Create(new CreateAdminUser(
                Guid.Empty,
                "badrole@davids.local",
                SupportPassword,
                "Invalid Role",
                "user"))
        };
        badRoleReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rootTokens.AccessToken);
        using var badRoleResp = await client.SendAsync(badRoleReq);
        Assert.Equal(HttpStatusCode.BadRequest, badRoleResp.StatusCode);

        // 3. Support employee signs in via OIDC PKCE: gets 'support' role claim, can access /me & /connect/userinfo,
        //    and receives 403 on employee IAM & audit endpoints.
        var supportTokens = await AdminIdentityTests.SignInAdminOidcAsync(client, "support@davids.local", SupportPassword);
        using var supportMeReq = new HttpRequestMessage(HttpMethod.Get, "/me");
        supportMeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportTokens.AccessToken);
        using var supportMeResp = await client.SendAsync(supportMeReq);
        Assert.Equal(HttpStatusCode.OK, supportMeResp.StatusCode);
        var supportMe = await supportMeResp.Content.ReadFromJsonAsync<AdminUserDto>();
        Assert.Equal(AdminUser.SupportRole, supportMe!.Role);

        using var supportUsersReq = new HttpRequestMessage(HttpMethod.Get, "/users");
        supportUsersReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(supportUsersReq)).StatusCode);

        using var supportAuditsReq = new HttpRequestMessage(HttpMethod.Get, "/change-audits");
        supportAuditsReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(supportAuditsReq)).StatusCode);

        // 4. Auditor employee signs in via OIDC PKCE: can read /users, /login-audits, and /change-audits,
        //    but receives 403 on POST/PUT mutations.
        var auditorTokens = await AdminIdentityTests.SignInAdminOidcAsync(client, "auditor@davids.local", AuditorPassword);
        using var auditorUsersReq = new HttpRequestMessage(HttpMethod.Get, "/users");
        auditorUsersReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auditorTokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(auditorUsersReq)).StatusCode);

        using var auditorMutateReq = new HttpRequestMessage(HttpMethod.Put, $"/users/{supportDto.Id}")
        {
            Content = JsonContent.Create(new UpdateAdminUser(FullName: "Blocked Edit"))
        };
        auditorMutateReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auditorTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(auditorMutateReq)).StatusCode);

        // 5. Last-active-admin safeguard prevents deactivating or demoting the sole active admin.
        using var demoteRootReq = new HttpRequestMessage(HttpMethod.Put, $"/users/{rootAdmin.Id}")
        {
            Content = JsonContent.Create(new UpdateAdminUser(Role: AdminUser.SupportRole))
        };
        demoteRootReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rootTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Conflict, (await client.SendAsync(demoteRootReq)).StatusCode);

        // 6. Support employee rotates their own password via PUT /me/password -> existing access token is revoked!
        const string newSupportPassword = "Support-Rotated-Horse-456!";
        using var wrongPwReq = new HttpRequestMessage(HttpMethod.Put, "/me/password")
        {
            Content = JsonContent.Create(new ChangeAdminPassword("Wrong-Current-123!", newSupportPassword))
        };
        wrongPwReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportTokens.AccessToken);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(wrongPwReq)).StatusCode);

        using var rotatePwReq = new HttpRequestMessage(HttpMethod.Put, "/me/password")
        {
            Content = JsonContent.Create(new ChangeAdminPassword(SupportPassword, newSupportPassword))
        };
        rotatePwReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportTokens.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(rotatePwReq)).StatusCode);

        using var revokedMeReq = new HttpRequestMessage(HttpMethod.Get, "/me");
        revokedMeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(revokedMeReq)).StatusCode);

        var freshSupportTokens = await AdminIdentityTests.SignInAdminOidcAsync(client, "support@davids.local", newSupportPassword);
        Assert.False(string.IsNullOrWhiteSpace(freshSupportTokens.AccessToken));

        // 7. Root admin updates support agent full name and unlocks account; auditor inspects /change-audits.
        using var updateSupportReq = new HttpRequestMessage(HttpMethod.Put, $"/users/{supportDto.Id}")
        {
            Content = JsonContent.Create(new UpdateAdminUser(FullName: "Senior Support Agent"))
        };
        updateSupportReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rootTokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(updateSupportReq)).StatusCode);

        using var unlockSupportReq = new HttpRequestMessage(HttpMethod.Post, $"/users/{supportDto.Id}/unlock");
        unlockSupportReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", rootTokens.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(unlockSupportReq)).StatusCode);

        using var getAuditsReq = new HttpRequestMessage(HttpMethod.Get, $"/change-audits?targetUserId={supportDto.Id}");
        getAuditsReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auditorTokens.AccessToken);
        using var getAuditsResp = await client.SendAsync(getAuditsReq);
        Assert.Equal(HttpStatusCode.OK, getAuditsResp.StatusCode);
        var audits = await getAuditsResp.Content.ReadFromJsonAsync<List<AdminChangeAuditDto>>();
        Assert.NotNull(audits);
        Assert.Contains(audits!, a => a.Action == "employee_provisioned" && a.CorrelationId == "corr-support-create");
        Assert.Contains(audits!, a =>
            a.Action == "password_changed" &&
            a.ActorSub == supportDto.Id.ToString("D") &&
            a.Changes.All(c => c.NewValue == "[REDACTED]"));
        Assert.Contains(audits!, a =>
            a.Action == "employee_updated" &&
            a.ActorSub == rootAdmin.Id.ToString("D") &&
            a.Changes.Any(c => c.Field == "fullName" && c.OldValue == "Support Agent" && c.NewValue == "Senior Support Agent"));
        Assert.Contains(audits!, a => a.Action == "employee_unlocked");
    }
}

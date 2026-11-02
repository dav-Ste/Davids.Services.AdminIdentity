using Davids.Services.AdminIdentity.Application.Commands;
using Davids.Services.AdminIdentity.Application.DTO;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Exceptions;
using Davids.Services.AdminIdentity.Core.Repositories;
using Microsoft.Extensions.Logging;

namespace Davids.Services.AdminIdentity.Application.Services;

public sealed class AdminLockoutSettings
{
    public int MaxFailedAccessAttempts { get; set; } = 5;
    public int DurationMinutes { get; set; } = 15;
}

public interface IAdminPasswordService
{
    string Hash(string password);
    bool IsValid(string hash, string password);
}

public interface IAdminIdentityService
{
    Task<AdminUserDto?> GetAsync(Guid id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AdminUserDto>> BrowseAsync(CancellationToken cancellationToken = default);
    Task<AdminUserDto> AuthenticateAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default,
        AdminLoginRequestMetadata? metadata = null);
    Task<AdminUserDto> CreateAdminAsync(CreateAdminUser command, Guid createdByAdminId, CancellationToken cancellationToken = default);
    Task RecordProtocolFailureAuditAsync(
        string? email,
        Guid? adminUserId,
        string outcome,
        string? failureReason,
        AdminLoginRequestMetadata? metadata = null,
        CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AdminLoginAuditDto>> BrowseLoginAuditsAsync(
        int limit = 100,
        bool? succeeded = null,
        string? email = null,
        CancellationToken cancellationToken = default);
}

public sealed class AdminIdentityService(
    IAdminUserRepository users,
    IAdminPasswordService passwords,
    ILogger<AdminIdentityService> logger,
    AdminLockoutSettings? lockoutSettings = null,
    IAdminLoginAuditRepository? loginAudits = null) : IAdminIdentityService
{
    private readonly AdminLockoutSettings _lockout = lockoutSettings ?? new AdminLockoutSettings();

    public async Task<AdminUserDto?> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var admin = await users.GetAsync(id, cancellationToken);
        return admin is null ? null : AdminUserDto.FromEntity(admin);
    }

    public async Task<IReadOnlyList<AdminUserDto>> BrowseAsync(CancellationToken cancellationToken = default)
    {
        var admins = await users.BrowseAsync(cancellationToken);
        return admins.Select(AdminUserDto.FromEntity).ToArray();
    }

    public async Task<AdminUserDto> AuthenticateAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default,
        AdminLoginRequestMetadata? metadata = null)
    {
        var now = DateTime.UtcNow;
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrEmpty(password))
        {
            await WriteAuditAsync(now, null, email, false, "invalid_credentials", "Missing administrator email or password.", metadata, cancellationToken);
            throw new InvalidAdminCredentialsException();
        }

        string normalizedEmail;
        try
        {
            normalizedEmail = AdminUser.NormalizeAndValidateEmail(email.Trim());
        }
        catch (InvalidAdminEmailException)
        {
            await WriteAuditAsync(now, null, email, false, "invalid_credentials", "Malformed administrator email.", metadata, cancellationToken);
            throw new InvalidAdminCredentialsException();
        }

        var admin = await users.GetByEmailAsync(normalizedEmail, cancellationToken);
        if (admin is null)
        {
            await WriteAuditAsync(now, null, normalizedEmail, false, "invalid_credentials", "Unknown administrator email.", metadata, cancellationToken);
            logger.LogWarning(
                "Audit: rejected administrator OIDC sign-in for unknown email from {ClientIp}.",
                metadata?.ClientIpAddress ?? "unknown");
            throw new InvalidAdminCredentialsException();
        }

        if (admin.IsLockedOut(now))
        {
            await WriteAuditAsync(now, admin.Id, normalizedEmail, false, "account_locked", "Administrator account is currently locked out.", metadata, cancellationToken);
            logger.LogWarning(
                "Audit: rejected OIDC sign-in for locked administrator {AdminId} until {LockoutEndUtc} from {ClientIp}.",
                admin.Id,
                admin.LockoutEndUtc,
                metadata?.ClientIpAddress ?? "unknown");
            throw new AdminAccountLockedException(admin.LockoutEndUtc!.Value);
        }

        if (!passwords.IsValid(admin.PasswordHash, password))
        {
            var maxAttempts = Math.Max(1, _lockout.MaxFailedAccessAttempts);
            var lockoutDuration = TimeSpan.FromMinutes(Math.Max(1, _lockout.DurationMinutes));
            var lockedNow = admin.RecordFailedLogin(now, maxAttempts, lockoutDuration);
            await users.UpdateAsync(admin, cancellationToken);

            if (lockedNow)
            {
                await WriteAuditAsync(
                    now,
                    admin.Id,
                    normalizedEmail,
                    false,
                    "account_locked",
                    $"Administrator account locked after {maxAttempts} failed attempts.",
                    metadata,
                    cancellationToken);
                logger.LogWarning(
                    "Audit: locked administrator {AdminId} until {LockoutEndUtc} after {MaxAttempts} failed attempts from {ClientIp}.",
                    admin.Id,
                    admin.LockoutEndUtc,
                    maxAttempts,
                    metadata?.ClientIpAddress ?? "unknown");
                throw new AdminAccountLockedException(admin.LockoutEndUtc!.Value);
            }

            await WriteAuditAsync(now, admin.Id, normalizedEmail, false, "invalid_credentials", "Invalid administrator password.", metadata, cancellationToken);
            logger.LogWarning(
                "Audit: rejected administrator OIDC sign-in attempt for {AdminId} from {ClientIp}.",
                admin.Id,
                metadata?.ClientIpAddress ?? "unknown");
            throw new InvalidAdminCredentialsException();
        }

        if (!admin.IsActive)
        {
            await WriteAuditAsync(now, admin.Id, normalizedEmail, false, "account_disabled", "Administrator account is disabled.", metadata, cancellationToken);
            logger.LogWarning(
                "Audit: rejected OIDC sign-in for disabled administrator {AdminId} from {ClientIp}.",
                admin.Id,
                metadata?.ClientIpAddress ?? "unknown");
            throw new AdminAccountDisabledException();
        }

        if (admin.FailedLoginCount > 0 || admin.LockoutEndUtc is not null)
        {
            admin.ResetFailedLogins();
            await users.UpdateAsync(admin, cancellationToken);
        }

        await WriteAuditAsync(now, admin.Id, normalizedEmail, true, "succeeded", null, metadata, cancellationToken);
        logger.LogInformation(
            "Audit: administrator {AdminId} authenticated via OIDC from {ClientIp} (ClientId={ClientId}).",
            admin.Id,
            metadata?.ClientIpAddress ?? "unknown",
            metadata?.ClientId ?? "unknown");
        return AdminUserDto.FromEntity(admin);
    }

    public Task RecordProtocolFailureAuditAsync(
        string? email,
        Guid? adminUserId,
        string outcome,
        string? failureReason,
        AdminLoginRequestMetadata? metadata = null,
        CancellationToken cancellationToken = default)
        => WriteAuditAsync(DateTime.UtcNow, adminUserId, email, false, outcome, failureReason, metadata, cancellationToken);

    public async Task<IReadOnlyList<AdminLoginAuditDto>> BrowseLoginAuditsAsync(
        int limit = 100,
        bool? succeeded = null,
        string? email = null,
        CancellationToken cancellationToken = default)
    {
        if (loginAudits is null)
        {
            return [];
        }

        var entries = await loginAudits.BrowseRecentAsync(limit, succeeded, email, cancellationToken);
        return entries.Select(AdminLoginAuditDto.FromEntity).ToArray();
    }

    private async Task WriteAuditAsync(
        DateTime occurredAtUtc,
        Guid? adminUserId,
        string? email,
        bool succeeded,
        string outcome,
        string? failureReason,
        AdminLoginRequestMetadata? metadata,
        CancellationToken cancellationToken)
    {
        if (loginAudits is null)
        {
            return;
        }

        var entry = new AdminLoginAuditEntry(
            Guid.NewGuid(),
            occurredAtUtc,
            adminUserId,
            email,
            succeeded,
            outcome,
            failureReason,
            metadata?.ClientId,
            metadata?.ClientIpAddress,
            metadata?.UserAgent,
            metadata?.CorrelationId);
        await loginAudits.AddAsync(entry, cancellationToken);
    }

    public async Task<AdminUserDto> CreateAdminAsync(
        CreateAdminUser command,
        Guid createdByAdminId,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var normalizedEmail = AdminUser.NormalizeAndValidateEmail(command.Email);
        var passwordRuneCount = command.Password?.EnumerateRunes().Count() ?? 0;
        if (string.IsNullOrWhiteSpace(command.Password) ||
            passwordRuneCount < 12 ||
            passwordRuneCount > 128 ||
            command.Password.Contains('\0'))
        {
            throw new InvalidAdminPasswordException();
        }

        var adminId = command.AdminId == Guid.Empty ? Guid.NewGuid() : command.AdminId;
        var existing = await users.GetByEmailAsync(normalizedEmail, cancellationToken);
        if (existing is not null || await users.GetAsync(adminId, cancellationToken) is not null)
        {
            throw new AdminEmailInUseException(normalizedEmail);
        }

        var admin = new AdminUser(
            adminId,
            normalizedEmail,
            passwords.Hash(command.Password),
            command.FullName,
            isActive: true,
            DateTime.UtcNow);

        await users.AddAsync(admin, cancellationToken);
        logger.LogInformation("Administrator {NewAdminId} provisioned by {ActorAdminId}.", admin.Id, createdByAdminId);
        return AdminUserDto.FromEntity(admin);
    }
}

using System.Text.Json;
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

public interface IAdminTokenRevocationService
{
    Task RevokeAllForSubjectAsync(
        Guid adminUserId,
        string? currentAccessTokenJti = null,
        DateTime? currentAccessTokenExpiresAtUtc = null,
        CancellationToken cancellationToken = default);
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
    Task<AdminUserDto> CreateAdminAsync(
        CreateAdminUser command,
        Guid createdByAdminId,
        CancellationToken cancellationToken = default,
        AdminActorMetadata? actor = null);
    Task ChangeMyPasswordAsync(
        Guid adminUserId,
        ChangeAdminPassword command,
        AdminActorMetadata actor,
        CancellationToken cancellationToken = default);
    Task<AdminUserDto> UpdateEmployeeAsync(
        Guid targetAdminUserId,
        UpdateAdminUser command,
        AdminActorMetadata actor,
        CancellationToken cancellationToken = default);
    Task<AdminUserDto> UnlockEmployeeAsync(
        Guid targetAdminUserId,
        AdminActorMetadata actor,
        CancellationToken cancellationToken = default);
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
    Task<IReadOnlyList<AdminChangeAuditDto>> BrowseChangeAuditsAsync(
        int limit = 100,
        Guid? targetAdminUserId = null,
        Guid? actorAdminUserId = null,
        CancellationToken cancellationToken = default);
}

public sealed class AdminIdentityService(
    IAdminUserRepository users,
    IAdminPasswordService passwords,
    ILogger<AdminIdentityService> logger,
    AdminLockoutSettings? lockoutSettings = null,
    IAdminLoginAuditRepository? loginAudits = null,
    IAdminChangeAuditRepository? changeAudits = null,
    IAdminTokenRevocationService? tokenRevocation = null) : IAdminIdentityService
{
    private static readonly JsonSerializerOptions AuditJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

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
            "Audit: employee {AdminId} (Role={Role}) authenticated via OIDC from {ClientIp} (ClientId={ClientId}).",
            admin.Id,
            admin.Role,
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

    public async Task<IReadOnlyList<AdminChangeAuditDto>> BrowseChangeAuditsAsync(
        int limit = 100,
        Guid? targetAdminUserId = null,
        Guid? actorAdminUserId = null,
        CancellationToken cancellationToken = default)
    {
        if (changeAudits is null)
        {
            return [];
        }

        var entries = await changeAudits.BrowseRecentAsync(limit, targetAdminUserId, actorAdminUserId, cancellationToken);
        return entries.Select(AdminChangeAuditDto.FromEntity).ToArray();
    }

    public async Task<AdminUserDto> CreateAdminAsync(
        CreateAdminUser command,
        Guid createdByAdminId,
        CancellationToken cancellationToken = default,
        AdminActorMetadata? actor = null)
    {
        ArgumentNullException.ThrowIfNull(command);

        var normalizedEmail = AdminUser.NormalizeAndValidateEmail(command.Email);
        ValidatePasswordStrength(command.Password);

        var normalizedRole = string.IsNullOrWhiteSpace(command.Role)
            ? AdminUser.AdminRole
            : AdminUser.NormalizeAndValidateRole(command.Role);

        var adminId = command.AdminId == Guid.Empty ? Guid.NewGuid() : command.AdminId;
        var existing = await users.GetByEmailAsync(normalizedEmail, cancellationToken);
        if (existing is not null || await users.GetAsync(adminId, cancellationToken) is not null)
        {
            throw new AdminEmailInUseException(normalizedEmail);
        }

        var now = DateTime.UtcNow;
        var admin = new AdminUser(
            adminId,
            normalizedEmail,
            passwords.Hash(command.Password),
            command.FullName,
            isActive: true,
            now,
            role: normalizedRole);

        var effectiveActorId = actor?.ActorAdminUserId is { } aid && aid != Guid.Empty ? aid : createdByAdminId;
        var changes = new List<AdminFieldChangeDto>
        {
            new("email", null, admin.Email),
            new("fullName", null, admin.FullName),
            new("role", null, admin.Role),
            new("isActive", null, "true"),
            new("password", "[REDACTED]", "[REDACTED]")
        };

        var audit = effectiveActorId == Guid.Empty
            ? null
            : new AdminChangeAuditEntry(
                Guid.NewGuid(),
                now,
                admin.Id,
                admin.Email,
                "employee_provisioned",
                effectiveActorId,
                actor?.ActorEmail,
                actor?.ActorRole ?? AdminUser.AdminRole,
                JsonSerializer.Serialize(changes, AuditJsonOptions),
                actor?.CorrelationId);

        await users.AddAsync(admin, cancellationToken, audit);
        logger.LogInformation(
            "Employee {NewAdminId} (Role={Role}) provisioned by {ActorAdminId}.",
            admin.Id,
            admin.Role,
            effectiveActorId);
        return AdminUserDto.FromEntity(admin);
    }

    public async Task ChangeMyPasswordAsync(
        Guid adminUserId,
        ChangeAdminPassword command,
        AdminActorMetadata actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(actor);

        var admin = await users.GetAsync(adminUserId, cancellationToken)
            ?? throw new AdminNotFoundException(adminUserId);
        if (!admin.IsActive)
        {
            throw new AdminAccountDisabledException();
        }

        if (string.IsNullOrEmpty(command.CurrentPassword) || !passwords.IsValid(admin.PasswordHash, command.CurrentPassword))
        {
            throw new InvalidCurrentPasswordException();
        }

        ValidatePasswordStrength(command.NewPassword);
        if (string.Equals(command.CurrentPassword, command.NewPassword, StringComparison.Ordinal))
        {
            throw new InvalidAdminPasswordException();
        }

        admin.ChangePasswordHash(passwords.Hash(command.NewPassword));
        var changes = new List<AdminFieldChangeDto>
        {
            new("password", "[REDACTED]", "[REDACTED]")
        };

        var audit = new AdminChangeAuditEntry(
            Guid.NewGuid(),
            DateTime.UtcNow,
            admin.Id,
            admin.Email,
            "password_changed",
            actor.ActorAdminUserId,
            actor.ActorEmail ?? admin.Email,
            actor.ActorRole,
            JsonSerializer.Serialize(changes, AuditJsonOptions),
            actor.CorrelationId);

        await users.UpdateAsync(admin, cancellationToken, audit);
        if (tokenRevocation is not null)
        {
            await tokenRevocation.RevokeAllForSubjectAsync(
                admin.Id,
                actor.CurrentAccessTokenJti,
                actor.CurrentAccessTokenExpiresAtUtc,
                cancellationToken);
        }

        logger.LogInformation("Audit: employee {AdminId} rotated their password.", admin.Id);
    }

    public async Task<AdminUserDto> UpdateEmployeeAsync(
        Guid targetAdminUserId,
        UpdateAdminUser command,
        AdminActorMetadata actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentNullException.ThrowIfNull(actor);

        var target = await users.GetAsync(targetAdminUserId, cancellationToken)
            ?? throw new AdminNotFoundException(targetAdminUserId);

        var requestedRole = command.Role is null ? target.Role : AdminUser.NormalizeAndValidateRole(command.Role);
        var requestedActive = command.IsActive ?? target.IsActive;

        if (string.Equals(target.Role, AdminUser.AdminRole, StringComparison.Ordinal) &&
            target.IsActive &&
            (!requestedActive || !string.Equals(requestedRole, AdminUser.AdminRole, StringComparison.Ordinal)))
        {
            var remainingAdmins = await users.CountActiveAdminsExcludingAsync(target.Id, cancellationToken);
            if (remainingAdmins < 1)
            {
                throw new LastActiveAdminException();
            }
        }

        var oldRole = target.Role;
        var oldActive = target.IsActive;
        var oldName = target.FullName;

        target.UpdateProfileAndAccess(command.Role, command.IsActive, command.FullName);

        var changes = new List<AdminFieldChangeDto>();
        if (!string.Equals(oldRole, target.Role, StringComparison.Ordinal))
        {
            changes.Add(new AdminFieldChangeDto("role", oldRole, target.Role));
        }

        if (oldActive != target.IsActive)
        {
            changes.Add(new AdminFieldChangeDto("isActive", oldActive ? "true" : "false", target.IsActive ? "true" : "false"));
        }

        if (!string.Equals(oldName, target.FullName, StringComparison.Ordinal))
        {
            changes.Add(new AdminFieldChangeDto("fullName", oldName, target.FullName));
        }

        var audit = changes.Count == 0
            ? null
            : new AdminChangeAuditEntry(
                Guid.NewGuid(),
                DateTime.UtcNow,
                target.Id,
                target.Email,
                "employee_updated",
                actor.ActorAdminUserId,
                actor.ActorEmail,
                actor.ActorRole,
                JsonSerializer.Serialize(changes, AuditJsonOptions),
                actor.CorrelationId);

        await users.UpdateAsync(target, cancellationToken, audit);

        if ((!target.IsActive && oldActive) || !string.Equals(oldRole, target.Role, StringComparison.Ordinal))
        {
            if (tokenRevocation is not null)
            {
                await tokenRevocation.RevokeAllForSubjectAsync(target.Id, cancellationToken: cancellationToken);
            }
        }

        return AdminUserDto.FromEntity(target);
    }

    public async Task<AdminUserDto> UnlockEmployeeAsync(
        Guid targetAdminUserId,
        AdminActorMetadata actor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(actor);

        var target = await users.GetAsync(targetAdminUserId, cancellationToken)
            ?? throw new AdminNotFoundException(targetAdminUserId);

        var wasLocked = target.LockoutEndUtc?.ToString("O") ?? "unlocked";
        target.ResetFailedLogins();

        var changes = new List<AdminFieldChangeDto>
        {
            new("lockoutEndUtc", wasLocked, "unlocked")
        };

        var audit = new AdminChangeAuditEntry(
            Guid.NewGuid(),
            DateTime.UtcNow,
            target.Id,
            target.Email,
            "employee_unlocked",
            actor.ActorAdminUserId,
            actor.ActorEmail,
            actor.ActorRole,
            JsonSerializer.Serialize(changes, AuditJsonOptions),
            actor.CorrelationId);

        await users.UpdateAsync(target, cancellationToken, audit);
        return AdminUserDto.FromEntity(target);
    }

    private static void ValidatePasswordStrength(string? password)
    {
        var passwordRuneCount = password?.EnumerateRunes().Count() ?? 0;
        if (string.IsNullOrWhiteSpace(password) ||
            passwordRuneCount < 12 ||
            passwordRuneCount > 128 ||
            password.Contains('\0'))
        {
            throw new InvalidAdminPasswordException();
        }
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
}

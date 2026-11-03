using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Core.Repositories;
using Davids.Services.AdminIdentity.Infrastructure.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Davids.Services.AdminIdentity.Infrastructure.Persistence;

public sealed class AdminUserRepository(
    AdminIdentityDbContext db,
    ILoggerFactory? loggerFactory = null) : IAdminUserRepository
{
    public async Task<AdminUser?> GetAsync(Guid id, CancellationToken cancellationToken = default)
        => Map(await db.AdminUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, cancellationToken));

    public async Task<AdminUser?> GetByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var normalized = email.Trim().ToLowerInvariant();
        return Map(await db.AdminUsers.AsNoTracking().SingleOrDefaultAsync(x => x.Email == normalized, cancellationToken));
    }

    public async Task<IReadOnlyList<AdminUser>> BrowseAsync(CancellationToken cancellationToken = default)
    {
        var rows = await db.AdminUsers.AsNoTracking()
            .OrderByDescending(x => x.CreatedAt)
            .ToListAsync(cancellationToken);
        return rows.Select(r => Map(r)!).ToArray();
    }

    public Task<int> CountActiveAdminsExcludingAsync(Guid excludedAdminId, CancellationToken cancellationToken = default)
        => db.AdminUsers.AsNoTracking()
            .CountAsync(
                x => x.Id != excludedAdminId && x.IsActive && x.Role == AdminUser.AdminRole,
                cancellationToken);

    public async Task AddAsync(
        AdminUser adminUser,
        CancellationToken cancellationToken = default,
        AdminChangeAuditEntry? changeAudit = null)
    {
        db.AdminUsers.Add(new AdminUserRow
        {
            Id = adminUser.Id,
            Email = adminUser.Email,
            PasswordHash = adminUser.PasswordHash,
            FullName = adminUser.FullName,
            Role = adminUser.Role,
            IsActive = adminUser.IsActive,
            CreatedAt = adminUser.CreatedAt,
            FailedLoginCount = adminUser.FailedLoginCount,
            LockoutEndUtc = adminUser.LockoutEndUtc
        });
        if (changeAudit is not null)
        {
            db.AdminChangeAuditLogs.Add(ToRow(changeAudit));
        }

        await db.SaveChangesAsync(cancellationToken);
        EmitChangeAuditTelemetry(changeAudit);
    }

    public async Task UpdateAsync(
        AdminUser adminUser,
        CancellationToken cancellationToken = default,
        AdminChangeAuditEntry? changeAudit = null)
    {
        var row = await db.AdminUsers.SingleOrDefaultAsync(x => x.Id == adminUser.Id, cancellationToken)
            ?? throw new InvalidOperationException($"Administrator '{adminUser.Id}' was not found.");
        row.PasswordHash = adminUser.PasswordHash;
        row.FullName = adminUser.FullName;
        row.Role = adminUser.Role;
        row.IsActive = adminUser.IsActive;
        row.FailedLoginCount = adminUser.FailedLoginCount;
        row.LockoutEndUtc = adminUser.LockoutEndUtc;
        if (changeAudit is not null)
        {
            db.AdminChangeAuditLogs.Add(ToRow(changeAudit));
        }

        await db.SaveChangesAsync(cancellationToken);
        EmitChangeAuditTelemetry(changeAudit);
    }

    private void EmitChangeAuditTelemetry(AdminChangeAuditEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        AdminIdentitySecurityMetrics.RecordChangeAudit(entry.Action);
        loggerFactory?.CreateLogger("Davids.Security.Audit").LogInformation(
            "Audit: recorded admin-identity change {Action} on {TargetAdminUserId} by {ActorAdminUserId} (ActorRole={ActorRole}, SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
            entry.Action,
            entry.TargetAdminUserId,
            entry.ActorAdminUserId,
            entry.ActorRole,
            "ChangeAudit",
            entry.CorrelationId ?? "none");
    }

    private static AdminChangeAuditLogRow ToRow(AdminChangeAuditEntry entry)
        => new()
        {
            Id = entry.Id,
            OccurredAtUtc = entry.OccurredAtUtc,
            TargetAdminUserId = entry.TargetAdminUserId,
            TargetEmail = entry.TargetEmail,
            Action = entry.Action,
            ActorAdminUserId = entry.ActorAdminUserId,
            ActorEmail = entry.ActorEmail,
            ActorRole = entry.ActorRole,
            ChangedFieldsJson = entry.ChangedFieldsJson,
            CorrelationId = entry.CorrelationId
        };

    private static AdminUser? Map(AdminUserRow? row)
        => row is null
            ? null
            : new AdminUser(
                row.Id,
                row.Email,
                row.PasswordHash,
                row.FullName,
                row.IsActive,
                DateTime.SpecifyKind(row.CreatedAt, DateTimeKind.Utc),
                row.FailedLoginCount,
                row.LockoutEndUtc.HasValue ? DateTime.SpecifyKind(row.LockoutEndUtc.Value, DateTimeKind.Utc) : null,
                string.IsNullOrWhiteSpace(row.Role) ? AdminUser.AdminRole : row.Role);
}

public sealed class AdminChangeAuditRepository(AdminIdentityDbContext db) : IAdminChangeAuditRepository
{
    public async Task<IReadOnlyList<AdminChangeAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        Guid? targetAdminUserId = null,
        Guid? actorAdminUserId = null,
        CancellationToken cancellationToken = default)
    {
        var clamped = Math.Clamp(limit, 1, 500);
        IQueryable<AdminChangeAuditLogRow> query = db.AdminChangeAuditLogs.AsNoTracking();

        if (targetAdminUserId.HasValue)
        {
            query = query.Where(x => x.TargetAdminUserId == targetAdminUserId.Value);
        }

        if (actorAdminUserId.HasValue)
        {
            query = query.Where(x => x.ActorAdminUserId == actorAdminUserId.Value);
        }

        var rows = await query
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(clamped)
            .ToListAsync(cancellationToken);

        return rows.Select(row => new AdminChangeAuditEntry(
            row.Id,
            DateTime.SpecifyKind(row.OccurredAtUtc, DateTimeKind.Utc),
            row.TargetAdminUserId,
            row.TargetEmail,
            row.Action,
            row.ActorAdminUserId,
            row.ActorEmail,
            row.ActorRole,
            row.ChangedFieldsJson,
            row.CorrelationId)).ToArray();
    }
}

public sealed class AdminLoginAuditRepository(
    AdminIdentityDbContext db,
    ILoggerFactory? loggerFactory = null) : IAdminLoginAuditRepository
{
    public async Task AddAsync(AdminLoginAuditEntry entry, CancellationToken cancellationToken = default)
    {
        db.AdminLoginAuditLogs.Add(new AdminLoginAuditLogRow
        {
            Id = entry.Id,
            OccurredAtUtc = entry.OccurredAtUtc,
            AdminUserId = entry.AdminUserId,
            Email = entry.Email,
            Succeeded = entry.Succeeded,
            Outcome = entry.Outcome,
            FailureReason = entry.FailureReason,
            ClientId = entry.ClientId,
            ClientIpAddress = entry.ClientIpAddress,
            UserAgent = entry.UserAgent,
            CorrelationId = entry.CorrelationId
        });
        await db.SaveChangesAsync(cancellationToken);

        AdminIdentitySecurityMetrics.RecordLoginAudit(entry.Outcome, entry.Succeeded);
        var auditLogger = loggerFactory?.CreateLogger("Davids.Security.Audit");
        if (entry.Succeeded)
        {
            auditLogger?.LogInformation(
                "Audit: recorded {AuthDomain} login outcome {Outcome} (Succeeded={Succeeded}, SecurityAuditEvent={SecurityAuditEvent}, ClientId={ClientId}, ClientIp={ClientIp}, CorrelationId={CorrelationId}).",
                "admin",
                entry.Outcome,
                true,
                "LoginAudit",
                entry.ClientId ?? "unknown",
                entry.ClientIpAddress ?? "unknown",
                entry.CorrelationId ?? "none");
        }
        else
        {
            auditLogger?.LogWarning(
                "Audit: recorded {AuthDomain} login failure {Outcome} (Succeeded={Succeeded}, SecurityAuditEvent={SecurityAuditEvent}, ClientId={ClientId}, ClientIp={ClientIp}, CorrelationId={CorrelationId}).",
                "admin",
                entry.Outcome,
                false,
                "LoginAudit",
                entry.ClientId ?? "unknown",
                entry.ClientIpAddress ?? "unknown",
                entry.CorrelationId ?? "none");
        }
    }

    public async Task<IReadOnlyList<AdminLoginAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        bool? succeeded = null,
        string? email = null,
        CancellationToken cancellationToken = default)
    {
        var clamped = Math.Clamp(limit, 1, 500);
        IQueryable<AdminLoginAuditLogRow> query = db.AdminLoginAuditLogs.AsNoTracking();

        if (succeeded.HasValue)
        {
            query = query.Where(x => x.Succeeded == succeeded.Value);
        }

        if (!string.IsNullOrWhiteSpace(email))
        {
            var normalized = email.Trim().ToLowerInvariant();
            query = query.Where(x => x.Email == normalized);
        }

        var rows = await query
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(clamped)
            .ToListAsync(cancellationToken);

        return rows.Select(Map).ToArray();
    }

    private static AdminLoginAuditEntry Map(AdminLoginAuditLogRow row)
        => new(
            row.Id,
            DateTime.SpecifyKind(row.OccurredAtUtc, DateTimeKind.Utc),
            row.AdminUserId,
            row.Email,
            row.Succeeded,
            row.Outcome,
            row.FailureReason,
            row.ClientId,
            row.ClientIpAddress,
            row.UserAgent,
            row.CorrelationId);
}

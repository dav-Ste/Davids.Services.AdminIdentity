using Davids.Services.AdminIdentity.Core.Entities;

namespace Davids.Services.AdminIdentity.Core.Repositories;

public interface IAdminUserRepository
{
    Task<AdminUser?> GetAsync(Guid id, CancellationToken cancellationToken = default);
    Task<AdminUser?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AdminUser>> BrowseAsync(CancellationToken cancellationToken = default);
    Task<int> CountActiveAdminsExcludingAsync(Guid excludedAdminId, CancellationToken cancellationToken = default);
    Task AddAsync(
        AdminUser adminUser,
        CancellationToken cancellationToken = default,
        AdminChangeAuditEntry? changeAudit = null);
    Task UpdateAsync(
        AdminUser adminUser,
        CancellationToken cancellationToken = default,
        AdminChangeAuditEntry? changeAudit = null);
}

public interface IAdminLoginAuditRepository
{
    Task AddAsync(AdminLoginAuditEntry entry, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AdminLoginAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        bool? succeeded = null,
        string? email = null,
        CancellationToken cancellationToken = default);
}

public interface IAdminChangeAuditRepository
{
    Task<IReadOnlyList<AdminChangeAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        Guid? targetAdminUserId = null,
        Guid? actorAdminUserId = null,
        CancellationToken cancellationToken = default);
}

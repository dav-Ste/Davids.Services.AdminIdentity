using Davids.Services.AdminIdentity.Core.Entities;

namespace Davids.Services.AdminIdentity.Core.Repositories;

public interface IAdminUserRepository
{
    Task<AdminUser?> GetAsync(Guid id, CancellationToken cancellationToken = default);
    Task<AdminUser?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<AdminUser>> BrowseAsync(CancellationToken cancellationToken = default);
    Task AddAsync(AdminUser adminUser, CancellationToken cancellationToken = default);
    Task UpdateAsync(AdminUser adminUser, CancellationToken cancellationToken = default);
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

using Microsoft.EntityFrameworkCore;

namespace Davids.Services.AdminIdentity.Infrastructure.Persistence;

public sealed class AdminIdentityDbContext(DbContextOptions<AdminIdentityDbContext> options) : DbContext(options)
{
    public DbSet<AdminUserRow> AdminUsers => Set<AdminUserRow>();
    public DbSet<RevokedAdminAccessToken> RevokedAdminAccessTokens => Set<RevokedAdminAccessToken>();
    public DbSet<AdminDataProtectionKeyRow> DataProtectionKeys => Set<AdminDataProtectionKeyRow>();
    public DbSet<AdminLoginAuditLogRow> AdminLoginAuditLogs => Set<AdminLoginAuditLogRow>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.UseOpenIddict();

        modelBuilder.Entity<AdminUserRow>(entity =>
        {
            entity.ToTable("AdminUsers");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Email).IsRequired().HasMaxLength(320);
            entity.HasIndex(x => x.Email).IsUnique();
            entity.Property(x => x.PasswordHash).IsRequired().HasMaxLength(512);
            entity.Property(x => x.FullName).HasMaxLength(200);
            entity.Property(x => x.FailedLoginCount).HasDefaultValue(0);
        });

        modelBuilder.Entity<RevokedAdminAccessToken>(entity =>
        {
            entity.ToTable("RevokedAdminAccessTokens");
            entity.HasKey(x => x.TokenId);
            entity.Property(x => x.TokenId).HasMaxLength(64);
            entity.HasIndex(x => x.ExpiresAt);
        });

        modelBuilder.Entity<AdminDataProtectionKeyRow>(entity =>
        {
            entity.ToTable("AdminDataProtectionKeys");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.FriendlyName).HasMaxLength(256);
            entity.Property(x => x.Xml).IsRequired();
            entity.HasIndex(x => x.FriendlyName);
        });

        modelBuilder.Entity<AdminLoginAuditLogRow>(entity =>
        {
            entity.ToTable("AdminLoginAuditLogs");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Email).IsRequired().HasMaxLength(320);
            entity.Property(x => x.Outcome).IsRequired().HasMaxLength(64);
            entity.Property(x => x.FailureReason).HasMaxLength(256);
            entity.Property(x => x.ClientId).HasMaxLength(128);
            entity.Property(x => x.ClientIpAddress).HasMaxLength(64);
            entity.Property(x => x.UserAgent).HasMaxLength(512);
            entity.Property(x => x.CorrelationId).HasMaxLength(128);
            entity.HasIndex(x => x.OccurredAtUtc);
            entity.HasIndex(x => new { x.Email, x.OccurredAtUtc });
            entity.HasIndex(x => new { x.AdminUserId, x.OccurredAtUtc });
        });
    }
}

public sealed class AdminUserRow
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? FullName { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEndUtc { get; set; }
}

public sealed class RevokedAdminAccessToken
{
    public string TokenId { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
}

public sealed class AdminDataProtectionKeyRow
{
    public int Id { get; set; }
    public string? FriendlyName { get; set; }
    public string Xml { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
}

public sealed class AdminLoginAuditLogRow
{
    public Guid Id { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public Guid? AdminUserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public bool Succeeded { get; set; }
    public string Outcome { get; set; } = string.Empty;
    public string? FailureReason { get; set; }
    public string? ClientId { get; set; }
    public string? ClientIpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? CorrelationId { get; set; }
}

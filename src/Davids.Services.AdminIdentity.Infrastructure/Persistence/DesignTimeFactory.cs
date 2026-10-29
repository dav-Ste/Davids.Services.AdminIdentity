using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Davids.Services.AdminIdentity.Infrastructure.Persistence;

public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<AdminIdentityDbContext>
{
    public AdminIdentityDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("ConnectionStrings__adminidentitydb")
            ?? "Server=localhost;Database=davids_admin_identity;Integrated Security=true;TrustServerCertificate=true";
        return new AdminIdentityDbContext(
            new DbContextOptionsBuilder<AdminIdentityDbContext>()
                .UseSqlServer(connection)
                .UseOpenIddict()
                .Options);
    }
}

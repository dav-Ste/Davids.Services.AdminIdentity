using System.Security.Cryptography;
using Davids.Services.AdminIdentity.Application.Services;
using Davids.Services.AdminIdentity.Core.Entities;
using Davids.Services.AdminIdentity.Infrastructure;
using Davids.Services.AdminIdentity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting.Internal;
using Xunit;

namespace Davids.Services.AdminIdentity.Tests;

[Trait("Category", "Unit")]
public sealed class ArchitectureTests
{
    [Fact]
    public void CoreLayerHasZeroOuterLayerOrInfrastructureFrameworkDependencies()
    {
        var coreRefs = typeof(AdminUser).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(coreRefs, n => n.StartsWith("Davids.", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("OpenIddict", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ApplicationLayerDependsOnlyOnCoreAndNeverOnInfrastructureOrApi()
    {
        var appRefs = typeof(AdminIdentityService).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.Contains("Davids.Services.AdminIdentity.Core", appRefs, StringComparer.Ordinal);
        Assert.DoesNotContain("Davids.Services.AdminIdentity.Infrastructure", appRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Davids.Services.AdminIdentity.Api", appRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Davids.ServiceDefaults", appRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(appRefs, n => n.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(appRefs, n => n.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(appRefs, n => n.StartsWith("OpenIddict", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void InfrastructureAndApiLayersFollowInwardDependenciesAndMaintainCustomerIdentityIsolation()
    {
        var infraRefs = typeof(AdminIdentityDbContext).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain("Davids.Services.AdminIdentity.Api", infraRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.Services.Identity", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.Services.Customers", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.APIGateway", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.Frontend", StringComparison.OrdinalIgnoreCase));

        var apiRefs = typeof(Program).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.Services.Identity", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.Services.Customers", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.APIGateway", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.Frontend", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EfCoreRuntimeModelMatchesMigrationsSnapshotWithoutPendingChanges()
    {
        using var designTimeDb = new DesignTimeFactory().CreateDbContext([]);
        Assert.False(
            designTimeDb.Database.HasPendingModelChanges(),
            "Design-time AdminIdentityDbContext has pending EF Core model changes relative to AdminIdentityDbContextModelSnapshot.");

        using var rsa = RSA.Create(2048);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:adminidentitydb"] = "Server=localhost;Database=davids_admin_identity;Integrated Security=true;TrustServerCertificate=true",
                ["Oidc:SigningKeyPem"] = rsa.ExportRSAPrivateKeyPem(),
                ["Oidc:BffClientSecret"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            })
            .Build();
        var services = new ServiceCollection();
        services.AddAdminIdentityInfrastructure(
            configuration,
            new HostingEnvironment { EnvironmentName = "Development", ApplicationName = "Davids.Services.AdminIdentity.Tests" });

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var runtimeDb = scope.ServiceProvider.GetRequiredService<AdminIdentityDbContext>();
        Assert.False(
            runtimeDb.Database.HasPendingModelChanges(),
            "Runtime DI AdminIdentityDbContext has pending EF Core model changes relative to AdminIdentityDbContextModelSnapshot.");
    }
}

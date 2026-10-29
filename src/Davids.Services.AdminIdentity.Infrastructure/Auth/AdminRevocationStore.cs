using Davids.Services.AdminIdentity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using StackExchange.Redis;

namespace Davids.Services.AdminIdentity.Infrastructure.Auth;

public interface IAdminRevocationCache
{
    Task<bool> ContainsAsync(string tokenId);
    Task AddAsync(string tokenId, DateTime expiresAt);
}

public sealed class NoAdminRevocationCache : IAdminRevocationCache
{
    public Task<bool> ContainsAsync(string tokenId) => Task.FromResult(false);
    public Task AddAsync(string tokenId, DateTime expiresAt) => Task.CompletedTask;
}

public sealed class RedisAdminRevocationCache(
    IConnectionMultiplexer redis,
    ILogger<RedisAdminRevocationCache> logger) : IAdminRevocationCache
{
    public const string KeyPrefix = "davids:admin-identity:revoked:";

    public async Task<bool> ContainsAsync(string tokenId)
    {
        try
        {
            return await redis.GetDatabase().KeyExistsAsync(KeyPrefix + tokenId);
        }
        catch (RedisException ex)
        {
            logger.LogWarning(ex, "Redis unavailable; checking SQL admin revocation store.");
            return false;
        }
    }

    public async Task AddAsync(string tokenId, DateTime expiresAt)
    {
        var ttl = expiresAt.ToUniversalTime().AddMinutes(1) - DateTime.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            return;
        }

        try
        {
            await redis.GetDatabase().StringSetAsync(KeyPrefix + tokenId, "1", ttl);
        }
        catch (RedisException ex)
        {
            logger.LogWarning(ex, "Could not cache revoked admin token; SQL remains authoritative.");
        }
    }
}

public sealed class AdminRevocationStore(
    AdminIdentityDbContext db,
    IAdminRevocationCache cache,
    IOpenIddictTokenManager? tokenManager = null)
{
    public async Task<bool> IsRevokedAsync(
        string? tokenId,
        CancellationToken cancellationToken = default,
        string? openIddictTokenId = null,
        DateTime? tokenExpiresAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(tokenId))
        {
            return true;
        }

        if (await cache.ContainsAsync(tokenId))
        {
            return true;
        }

        var revoked = await db.RevokedAdminAccessTokens.AsNoTracking()
            .SingleOrDefaultAsync(x => x.TokenId == tokenId, cancellationToken);
        if (revoked is not null)
        {
            await cache.AddAsync(tokenId, revoked.ExpiresAt);
            return true;
        }

        if (!string.IsNullOrWhiteSpace(openIddictTokenId) && tokenManager is not null)
        {
            var oidcToken = await tokenManager.FindByIdAsync(openIddictTokenId, cancellationToken);
            if (oidcToken is not null)
            {
                var status = await tokenManager.GetStatusAsync(oidcToken, cancellationToken);
                if (!string.Equals(status, OpenIddictConstants.Statuses.Valid, StringComparison.OrdinalIgnoreCase))
                {
                    var expiresAt = tokenExpiresAtUtc is { } exp && exp > DateTime.UtcNow
                        ? exp
                        : DateTime.UtcNow.AddMinutes(60);
                    if (!await db.RevokedAdminAccessTokens.AnyAsync(x => x.TokenId == tokenId, cancellationToken))
                    {
                        db.RevokedAdminAccessTokens.Add(new RevokedAdminAccessToken
                        {
                            TokenId = tokenId,
                            ExpiresAt = expiresAt
                        });
                        await db.SaveChangesAsync(cancellationToken);
                    }

                    await cache.AddAsync(tokenId, expiresAt);
                    AdminIdentitySecurityMetrics.RecordTokenRevocation("replay_cascade");
                    return true;
                }
            }
        }

        return false;
    }
}

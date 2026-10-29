namespace Davids.Services.AdminIdentity.Core.Exceptions;

public abstract class AdminDomainException(string message) : Exception(message)
{
    public abstract string Code { get; }
}

public sealed class InvalidAdminEmailException(string? email)
    : AdminDomainException($"Invalid administrator email: '{email}'.")
{
    public override string Code => "invalid_admin_email";
}

public sealed class InvalidAdminPasswordException()
    : AdminDomainException("Administrator password must contain at least 12 characters.")
{
    public override string Code => "invalid_admin_password";
}

public sealed class InvalidAdminFullNameException()
    : AdminDomainException("Administrator full name must be 200 characters or fewer.")
{
    public override string Code => "invalid_admin_full_name";
}

public sealed class InvalidAdminCredentialsException()
    : AdminDomainException("Invalid administrator email or password.")
{
    public override string Code => "invalid_credentials";
}

public sealed class AdminAccountDisabledException()
    : AdminDomainException("This administrator account is disabled.")
{
    public override string Code => "admin_account_disabled";
}

public sealed class AdminAccountLockedException(DateTime lockoutEndUtc)
    : AdminDomainException("This administrator account is temporarily locked due to repeated failed sign-in attempts.")
{
    public DateTime LockoutEndUtc { get; } = lockoutEndUtc;
    public override string Code => "admin_account_locked";
}

public sealed class AdminEmailInUseException(string email)
    : AdminDomainException($"Administrator email '{email}' is already registered.")
{
    public override string Code => "admin_email_in_use";
}

public sealed class InvalidAdminRefreshTokenException()
    : AdminDomainException("Invalid or expired administrator refresh token.")
{
    public override string Code => "invalid_refresh_token";
}

public sealed class RevokedAdminRefreshTokenException()
    : AdminDomainException("Administrator refresh token has already been used or revoked.")
{
    public override string Code => "revoked_refresh_token";
}

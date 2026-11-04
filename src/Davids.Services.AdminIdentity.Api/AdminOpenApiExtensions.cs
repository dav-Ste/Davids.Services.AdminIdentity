using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Davids.Services.AdminIdentity.Api;

public static class AdminOpenApiExtensions
{
    public static IServiceCollection AddAdminIdentityOpenApi(this IServiceCollection services)
    {
        services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer((document, _, _) =>
            {
                document.Info.Title = "Davids Administrator Identity OIDC API";
                document.Info.Version = "1.0.0";
                document.Info.Description =
                    "Dedicated OAuth 2.1 / OpenID Connect administrator authority (adminidentitydb, RS256 + PKCE S256). No public sign-up endpoint exists.";

                document.Components ??= new OpenApiComponents();
                document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
                document.Components.SecuritySchemes["BearerAuth"] = new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    Description = "RS256 OIDC administrator access token (aud: davids-admin, role: admin)."
                };

                const string NonWhitespaceNoNullPattern = @"^[^\u0000]*\S[^\u0000]*$";
                JsonNode?[] WorkforceRoleEnum() =>
                [
                    null,
                    JsonValue.Create("admin"),
                    JsonValue.Create("support"),
                    JsonValue.Create("auditor")
                ];

                if (document.Components.Schemas is not null)
                {
                    if (document.Components.Schemas.TryGetValue("CreateAdminUser", out var createRef) &&
                        createRef is OpenApiSchema createSchema &&
                        createSchema.Properties is not null)
                    {
                        createSchema.Required = new HashSet<string>(StringComparer.Ordinal) { "email", "password" };

                        if (createSchema.Properties.TryGetValue("email", out var emailProp) && emailProp is OpenApiSchema emailSchema)
                        {
                            emailSchema.Type = JsonSchemaType.String;
                            emailSchema.MinLength = 6;
                            emailSchema.MaxLength = 254;
                            emailSchema.Pattern = @"^[A-Za-z0-9_%+\-]{1,20}(?:\.[A-Za-z0-9_%+\-]{1,20}){0,2}@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,30}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$";
                        }

                        if (createSchema.Properties.TryGetValue("password", out var pwdProp) && pwdProp is OpenApiSchema pwdSchema)
                        {
                            pwdSchema.Type = JsonSchemaType.String;
                            pwdSchema.MinLength = 12;
                            pwdSchema.MaxLength = 128;
                            pwdSchema.Pattern = NonWhitespaceNoNullPattern;
                        }

                        if (createSchema.Properties.TryGetValue("fullName", out var nameProp) && nameProp is OpenApiSchema nameSchema)
                        {
                            nameSchema.Type = JsonSchemaType.String | JsonSchemaType.Null;
                            nameSchema.MaxLength = 100;
                            nameSchema.Pattern = @"^[^\u0000]*$";
                        }

                        if (createSchema.Properties.TryGetValue("role", out var roleProp) && roleProp is OpenApiSchema roleSchema)
                        {
                            roleSchema.Type = JsonSchemaType.String | JsonSchemaType.Null;
                            roleSchema.Enum = WorkforceRoleEnum()!;
                        }
                    }

                    if (document.Components.Schemas.TryGetValue("UpdateAdminUser", out var updateRef) &&
                        updateRef is OpenApiSchema updateSchema &&
                        updateSchema.Properties is not null)
                    {
                        if (updateSchema.Properties.TryGetValue("role", out var roleProp) && roleProp is OpenApiSchema roleSchema)
                        {
                            roleSchema.Type = JsonSchemaType.String | JsonSchemaType.Null;
                            roleSchema.Enum = WorkforceRoleEnum()!;
                        }

                        if (updateSchema.Properties.TryGetValue("fullName", out var nameProp) && nameProp is OpenApiSchema nameSchema)
                        {
                            nameSchema.Type = JsonSchemaType.String | JsonSchemaType.Null;
                            nameSchema.MaxLength = 100;
                            nameSchema.Pattern = @"^[^\u0000]*$";
                        }
                    }

                    if (document.Components.Schemas.TryGetValue("ChangeAdminPassword", out var changePwdRef) &&
                        changePwdRef is OpenApiSchema changePwdSchema &&
                        changePwdSchema.Properties is not null)
                    {
                        changePwdSchema.Required = new HashSet<string>(StringComparer.Ordinal) { "currentPassword", "newPassword" };

                        if (changePwdSchema.Properties.TryGetValue("currentPassword", out var curProp) && curProp is OpenApiSchema curSchema)
                        {
                            curSchema.Type = JsonSchemaType.String;
                            curSchema.MinLength = 1;
                            curSchema.MaxLength = 128;
                            curSchema.Pattern = NonWhitespaceNoNullPattern;
                        }

                        if (changePwdSchema.Properties.TryGetValue("newPassword", out var newProp) && newProp is OpenApiSchema newSchema)
                        {
                            newSchema.Type = JsonSchemaType.String;
                            newSchema.MinLength = 12;
                            newSchema.MaxLength = 128;
                            newSchema.Pattern = NonWhitespaceNoNullPattern;
                        }
                    }
                }

                if (document.Paths is not null &&
                    document.Paths.TryGetValue("/connect/token", out var tokenPathItem) &&
                    tokenPathItem.Operations is not null &&
                    tokenPathItem.Operations.TryGetValue(HttpMethod.Post, out var tokenOp))
                {
                    tokenOp.Summary = "Exchange a confidential BFF OAuth 2.1 authorization code (+ PKCE verifier) or refresh token.";
                    tokenOp.RequestBody = new OpenApiRequestBody
                    {
                        Required = true,
                        Content = new Dictionary<string, OpenApiMediaType>
                        {
                            ["application/x-www-form-urlencoded"] = new()
                            {
                                Schema = new OpenApiSchema
                                {
                                    Type = JsonSchemaType.Object,
                                    Required = new HashSet<string>(StringComparer.Ordinal) { "grant_type", "client_id" },
                                    Properties = new Dictionary<string, IOpenApiSchema>
                                    {
                                        ["grant_type"] = new OpenApiSchema
                                        {
                                            Type = JsonSchemaType.String,
                                            Enum = [JsonValue.Create("authorization_code"), JsonValue.Create("refresh_token")]
                                        },
                                        ["client_id"] = new OpenApiSchema { Type = JsonSchemaType.String, MinLength = 1, MaxLength = 100 },
                                        ["client_secret"] = new OpenApiSchema { Type = JsonSchemaType.String, MinLength = 1, MaxLength = 256 },
                                        ["code"] = new OpenApiSchema { Type = JsonSchemaType.String, MaxLength = 2048 },
                                        ["redirect_uri"] = new OpenApiSchema { Type = JsonSchemaType.String, Format = "uri", MaxLength = 512 },
                                        ["code_verifier"] = new OpenApiSchema { Type = JsonSchemaType.String, MinLength = 43, MaxLength = 128 },
                                        ["refresh_token"] = new OpenApiSchema { Type = JsonSchemaType.String, MaxLength = 2048 }
                                    }
                                }
                            }
                        }
                    };
                }

                foreach (var (_, pathItem) in document.Paths ?? [])
                {
                    foreach (var (_, operation) in pathItem.Operations ?? [])
                    {
                        if (operation.RequestBody is OpenApiRequestBody reqBody)
                        {
                            reqBody.Required = true;
                        }

                        foreach (var parameter in operation.Parameters ?? [])
                        {
                            if (string.Equals(parameter.Name, "limit", StringComparison.Ordinal) &&
                                parameter.Schema is OpenApiSchema limitSchema)
                            {
                                limitSchema.Type = JsonSchemaType.Integer;
                                limitSchema.Minimum = "1";
                                limitSchema.Maximum = "500";
                            }
                            else if (string.Equals(parameter.Name, "email", StringComparison.Ordinal) &&
                                     parameter.Schema is OpenApiSchema emailFilterSchema)
                            {
                                emailFilterSchema.MaxLength = 254;
                                emailFilterSchema.Pattern = @"^[^\u0000]*$";
                            }
                        }

                        if (operation.Security is { Count: > 0 })
                        {
                            operation.Security =
                            [
                                new OpenApiSecurityRequirement
                                {
                                    [new OpenApiSecuritySchemeReference("BearerAuth", document)] = []
                                }
                            ];
                        }
                    }
                }

                return Task.CompletedTask;
            });

            options.AddOperationTransformer((operation, context, _) =>
            {
                var metadata = context.Description.ActionDescriptor.EndpointMetadata;
                var requiresAuth = metadata.OfType<IAuthorizeData>().Any() && !metadata.OfType<IAllowAnonymous>().Any();

                operation.Responses ??= new OpenApiResponses();
                operation.Responses.TryAdd("429", new OpenApiResponse { Description = "Rate limit exceeded." });

                if (requiresAuth)
                {
                    operation.Security = [new OpenApiSecurityRequirement()];
                    operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Missing, invalid, or revoked administrator Bearer token." });
                    operation.Responses.TryAdd("403", new OpenApiResponse { Description = "Caller does not hold the admin role." });
                }

                return Task.CompletedTask;
            });
        });

        return services;
    }
}

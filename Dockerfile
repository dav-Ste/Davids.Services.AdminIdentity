# Build from workspace parent directory so sibling ../Davids.Shared is in build context:
#   docker build -f Davids.Services.AdminIdentity/Dockerfile -t ghcr.io/davids/davids-services-admin-identity:1.0.0 .
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble AS build
WORKDIR /workspace

COPY Davids.Shared/Directory.Build.props Davids.Shared/Directory.Packages.props Davids.Shared/global.json ./Davids.Shared/
COPY Davids.Shared/eng/ ./Davids.Shared/eng/
COPY Davids.Shared/src/Davids.ServiceDefaults/Davids.ServiceDefaults.csproj Davids.Shared/src/Davids.ServiceDefaults/packages.lock.json ./Davids.Shared/src/Davids.ServiceDefaults/
COPY Davids.Services.AdminIdentity/Directory.Build.props Davids.Services.AdminIdentity/Directory.Packages.props Davids.Services.AdminIdentity/global.json ./Davids.Services.AdminIdentity/
COPY Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Core/Davids.Services.AdminIdentity.Core.csproj Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Core/packages.lock.json ./Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Core/
COPY Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Application/Davids.Services.AdminIdentity.Application.csproj Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Application/packages.lock.json ./Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Application/
COPY Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Infrastructure/Davids.Services.AdminIdentity.Infrastructure.csproj Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Infrastructure/packages.lock.json ./Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Infrastructure/
COPY Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Api/Davids.Services.AdminIdentity.Api.csproj Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Api/packages.lock.json ./Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Api/

RUN dotnet restore ./Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Api/Davids.Services.AdminIdentity.Api.csproj --locked-mode

COPY Davids.Shared/src/Davids.ServiceDefaults/ ./Davids.Shared/src/Davids.ServiceDefaults/
COPY Davids.Services.AdminIdentity/src/ ./Davids.Services.AdminIdentity/src/

RUN dotnet publish ./Davids.Services.AdminIdentity/src/Davids.Services.AdminIdentity.Api/Davids.Services.AdminIdentity.Api.csproj \
      --no-restore -c Release /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble AS runtime
WORKDIR /app
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_EnableDiagnostics=0

COPY --from=build --chown=10001:10001 /workspace/Davids.Services.AdminIdentity/artifacts/publish/Davids.Services.AdminIdentity.Api/release .
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["dotnet", "--info"]

ENTRYPOINT ["dotnet", "Davids.Services.AdminIdentity.Api.dll"]

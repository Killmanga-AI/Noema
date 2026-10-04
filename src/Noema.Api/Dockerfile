FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props ./
COPY src/Noema.Api/Noema.Api.csproj src/Noema.Api/
COPY src/Noema.Infrastructure/Noema.Infrastructure.csproj src/Noema.Infrastructure/
RUN dotnet restore src/Noema.Api/Noema.Api.csproj
COPY src/Noema.Api/ src/Noema.Api/
COPY src/Noema.Infrastructure/ src/Noema.Infrastructure/
RUN dotnet publish src/Noema.Api/Noema.Api.csproj -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "Noema.Api.dll"]

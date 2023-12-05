FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["Esia.SignProvider.Api/Esia.SignProvider.Api.csproj", "Esia.SignProvider.Api/"]
RUN dotnet restore "Esia.SignProvider.Api/Esia.SignProvider.Api.csproj"
COPY . .
WORKDIR "/src/Esia.SignProvider.Api"
RUN dotnet build "Esia.SignProvider.Api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Esia.SignProvider.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Esia.SignProvider.Api.dll"]

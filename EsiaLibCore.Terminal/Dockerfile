FROM mcr.microsoft.com/dotnet/runtime:6.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["EsiaLibCore.Terminal/EsiaLibCore.Terminal.csproj", "EsiaLibCore.Terminal/"]
RUN dotnet restore "EsiaLibCore.Terminal/EsiaLibCore.Terminal.csproj"
COPY . .
WORKDIR "/src/EsiaLibCore.Terminal"
RUN dotnet build "EsiaLibCore.Terminal.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "EsiaLibCore.Terminal.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "EsiaLibCore.Terminal.dll"]

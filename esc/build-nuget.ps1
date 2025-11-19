# Script to build ESC as a DLL and create NuGet package

Write-Host "Building Evil SQL Client as Library for NuGet..." -ForegroundColor Green

# Clean previous builds
Write-Host "`nCleaning previous builds..." -ForegroundColor Yellow
dotnet clean esc/esc.csproj

# Build as library
Write-Host "`nBuilding DLL..." -ForegroundColor Yellow
dotnet build esc/esc.csproj /p:BuildAsLibrary=true -c Release

# Create NuGet package
Write-Host "`nCreating NuGet package..." -ForegroundColor Yellow
dotnet pack esc/esc.csproj /p:BuildAsLibrary=true -c Release

Write-Host "`nBuild complete!" -ForegroundColor Green
Write-Host "DLL location: esc\bin\Release\net461\esc.dll" -ForegroundColor Cyan
Write-Host "NuGet package location: esc\bin\Release\*.nupkg" -ForegroundColor Cyan


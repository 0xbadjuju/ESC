# Script to build ESC as an executable (default behavior)

Write-Host "Building Evil SQL Client as Executable..." -ForegroundColor Green

# Clean previous builds
Write-Host "`nCleaning previous builds..." -ForegroundColor Yellow
dotnet clean esc/esc.csproj

# Build as exe
Write-Host "`nBuilding EXE..." -ForegroundColor Yellow
dotnet build esc/esc.csproj -c Release

Write-Host "`nBuild complete!" -ForegroundColor Green
Write-Host "EXE location: esc\bin\Release\net461\esc.exe" -ForegroundColor Cyan


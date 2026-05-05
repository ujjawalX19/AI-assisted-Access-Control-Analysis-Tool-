# BAC Scanner - Unified Startup Script
# This script now uses Docker Compose to manage all services.

Write-Host " Starting BAC Scanner Platform via Docker Compose..." -ForegroundColor Cyan

# Check if Docker is running
docker info >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ ERROR: Docker Desktop is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again." -ForegroundColor Red
    exit 1
}

docker-compose up --build
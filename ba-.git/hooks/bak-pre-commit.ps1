#!/usr/bin/env pwsh
# PowerShell pre-commit hook for Windows

Write-Host "Running flake8..."
flake8 --ignore=E501,W503,W203,E203,E722 --exclude=tests .
if ($LASTEXITCODE -ne 0) {
   Write-Host "flake8 failed. Commit aborted."
   exit 1
}

Write-Host "Running isort..."
isort .
if ($LASTEXITCODE -ne 0) {
    Write-Host "isort failed. Commit aborted."
    exit 1
}

Write-Host "Running black..."
black .
if ($LASTEXITCODE -ne 0) {
    Write-Host "black formatting failed. Commit aborted."
    exit 1
}

Write-Host "All checks passed. Proceeding with commit."
exit 0
<#
    .SYNOPSIS
    Simple On-Premise Deployment Script for AL-Go
    
    .DESCRIPTION
    This script is called by AL-Go for GitHub when EnvironmentType is set to "OnPrem".
    Based on the approach from https://github.com/microsoft/AL-Go/issues/519
    
    It copies artifacts to a deployment folder and executes BC Management commands
    to install the apps on your on-premise Business Central server.
    
    .NOTES
    Author: Based on AL-Go community approach
    Version: 1.0.0
    
    Prerequisites:
    - Self-hosted runner on the BC server (or with network access)
    - BC Management module available (NavAdminTool.ps1)
    - Deployment folder exists: C:\Deploy\DeployOnPrem\CustomApps
#>

Param(
    [Parameter(HelpMessage = "Parameters from AL-Go", Mandatory = $true)]
    [hashtable] $parameters
)

#region Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Deployment folder - change this to match your environment
$deployAppsPath = 'C:\Deploy\DeployOnPrem\CustomApps'

# BC Server Configuration - can be overridden via AuthContext
$defaultServerInstance = 'BC'
$defaultTenant = 'default'
$defaultSyncMode = 'Add'  # Add, ForceSync, Development
#endregion

#region Helper Functions
function Write-DeployLog {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Error"   { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default   { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Import-BCModule {
    Write-DeployLog "Loading BC Management module..."
    
    $modulePaths = @(
        "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\NavAdminTool.ps1",
        "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\Microsoft.Dynamics.Nav.Management.psm1"
    )
    
    foreach ($pattern in $modulePaths) {
        $resolved = Resolve-Path $pattern -ErrorAction SilentlyContinue | Sort-Object -Descending | Select-Object -First 1
        if ($resolved) {
            try {
                if ($resolved.Path -like "*.ps1") {
                    . $resolved.Path
                } else {
                    Import-Module $resolved.Path -Force -DisableNameChecking
                }
                Write-DeployLog "Loaded: $($resolved.Path)" -Level Success
                return $true
            }
            catch {
                Write-DeployLog "Failed to load $($resolved.Path): $_" -Level Warning
            }
        }
    }
    return $false
}

function Install-BCApp {
    param(
        [string]$AppPath,
        [string]$ServerInstance,
        [string]$Tenant,
        [string]$SyncMode,
        [switch]$SkipVerification
    )
    
    # Get app info
    $appInfo = Get-NAVAppInfo -Path $AppPath -ErrorAction SilentlyContinue
    $appName = if ($appInfo) { $appInfo.Name } else { [System.IO.Path]::GetFileNameWithoutExtension($AppPath) }
    $appVersion = if ($appInfo) { $appInfo.Version } else { "1.0.0.0" }
    $appPublisher = if ($appInfo) { $appInfo.Publisher } else { "Unknown" }
    
    Write-DeployLog "Installing: $appName v$appVersion by $appPublisher"
    
    # Step 1: Publish
    Write-DeployLog "  Publishing..." -Level Info
    try {
        Publish-NAVApp -ServerInstance $ServerInstance -Path $AppPath -SkipVerification:$SkipVerification -Scope Tenant -Tenant $Tenant
        Write-DeployLog "  Published" -Level Success
    }
    catch {
        if ($_.Exception.Message -like "*already published*") {
            Write-DeployLog "  Already published, continuing..." -Level Warning
        }
        else {
            throw $_
        }
    }
    
    # Step 2: Sync
    Write-DeployLog "  Syncing (Mode: $SyncMode)..." -Level Info
    try {
        Sync-NAVApp -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant -Mode $SyncMode
        Write-DeployLog "  Synced" -Level Success
    }
    catch {
        Write-DeployLog "  Sync warning: $_" -Level Warning
    }
    
    # Step 3: Install or Upgrade
    Write-DeployLog "  Installing..." -Level Info
    try {
        $installedApp = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Tenant $Tenant -ErrorAction SilentlyContinue | 
                        Where-Object { $_.IsInstalled }
        
        if ($installedApp) {
            if ($installedApp.Version -lt $appVersion) {
                Write-DeployLog "  Upgrading from v$($installedApp.Version)..." -Level Info
                Start-NAVAppDataUpgrade -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant
            }
            elseif ($installedApp.Version -eq $appVersion) {
                Write-DeployLog "  Same version - reinstalling..." -Level Warning
                Uninstall-NAVApp -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant -Force -ErrorAction SilentlyContinue
                Install-NAVApp -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant
            }
            else {
                Write-DeployLog "  Newer version already installed, skipping" -Level Warning
                return
            }
        }
        else {
            Install-NAVApp -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant
        }
        Write-DeployLog "  Installed" -Level Success
    }
    catch {
        throw "Install failed: $_"
    }
}
#endregion

#region Main Script
try {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  AL-Go On-Premise Deployment (Simple)      " -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Extract parameters from AL-Go
    $environmentName = $parameters.EnvironmentName
    $apps = $parameters.apps  # Path to apps (can be .app file or .zip)
    $authContextJson = $parameters.AuthContext
    
    Write-DeployLog "Environment: $environmentName"
    Write-DeployLog "Apps source: $apps"
    
    # Parse AuthContext for server settings (optional)
    $serverInstance = $defaultServerInstance
    $tenant = $defaultTenant
    $syncMode = $defaultSyncMode
    $skipVerification = $true
    
    if ($authContextJson) {
        try {
            $authContext = $authContextJson | ConvertFrom-Json
            if ($authContext.ServerInstance) { $serverInstance = $authContext.ServerInstance }
            if ($authContext.Tenant) { $tenant = $authContext.Tenant }
            if ($authContext.SyncMode) { $syncMode = $authContext.SyncMode }
            if ($null -ne $authContext.SkipVerification) { $skipVerification = $authContext.SkipVerification }
            Write-DeployLog "Using AuthContext settings" -Level Info
        }
        catch {
            Write-DeployLog "Could not parse AuthContext, using defaults" -Level Warning
        }
    }
    
    Write-Host ""
    Write-Host "Server Instance: $serverInstance" -ForegroundColor DarkCyan
    Write-Host "Tenant:          $tenant" -ForegroundColor DarkCyan
    Write-Host "Sync Mode:       $syncMode" -ForegroundColor DarkCyan
    Write-Host ""
    
    # Ensure deployment folder exists
    if (-not (Test-Path $deployAppsPath)) {
        New-Item -ItemType Directory -Path $deployAppsPath -Force | Out-Null
        Write-DeployLog "Created deployment folder: $deployAppsPath"
    }
    
    # Clean up deployment folder
    Write-DeployLog "Cleaning up deployment folder..."
    Get-ChildItem -Path $deployAppsPath -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    
    # Copy/Move apps to deployment folder
    Write-DeployLog "Moving artifacts to deployment folder: $apps"
    
    if (Test-Path $apps) {
        if ((Get-Item $apps).PSIsContainer) {
            # It's a directory - copy contents
            Copy-Item -Path "$apps\*" -Destination $deployAppsPath -Recurse -Force
        }
        else {
            # It's a file - copy it
            Copy-Item -Path $apps -Destination $deployAppsPath -Force
        }
    }
    else {
        throw "Apps source not found: $apps"
    }
    
    # Expand any zip artifacts
    Write-DeployLog "Expanding zip artifacts..."
    $zipFiles = Get-ChildItem -Path $deployAppsPath -Filter "*.zip" -Recurse
    foreach ($zipFile in $zipFiles) {
        Write-DeployLog "  Extracting: $($zipFile.Name)"
        Expand-Archive -LiteralPath $zipFile.FullName -DestinationPath $deployAppsPath -Force
        Remove-Item -Path $zipFile.FullName -Force
    }
    
    # Find all .app files
    $appFiles = Get-ChildItem -Path $deployAppsPath -Filter "*.app" -Recurse
    
    if ($appFiles.Count -eq 0) {
        throw "No .app files found in deployment folder"
    }
    
    Write-DeployLog "Found $($appFiles.Count) app(s) to deploy" -Level Success
    
    # Import BC Management module
    $moduleLoaded = Import-BCModule
    if (-not $moduleLoaded) {
        throw "Could not load BC Management module. Ensure NavAdminTool.ps1 is available."
    }
    
    # Install each app
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor DarkGray
    
    $successCount = 0
    $failedApps = @()
    
    foreach ($appFile in $appFiles) {
        try {
            Install-BCApp -AppPath $appFile.FullName -ServerInstance $serverInstance -Tenant $tenant -SyncMode $syncMode -SkipVerification:$skipVerification
            $successCount++
        }
        catch {
            Write-DeployLog "FAILED: $($appFile.Name) - $_" -Level Error
            $failedApps += $appFile.Name
        }
    }
    
    # Summary
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    
    if ($failedApps.Count -eq 0) {
        Write-Host "  DEPLOYMENT SUCCESSFUL" -ForegroundColor Green
        Write-Host "  Deployed: $successCount app(s)" -ForegroundColor Green
    }
    else {
        Write-Host "  DEPLOYMENT COMPLETED WITH ERRORS" -ForegroundColor Yellow
        Write-Host "  Succeeded: $successCount | Failed: $($failedApps.Count)" -ForegroundColor Yellow
        throw "Failed to deploy: $($failedApps -join ', ')"
    }
    
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host "        DEPLOYMENT FAILED                   " -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Red
    Write-DeployLog "Error: $_" -Level Error
    throw $_
}
finally {
    # Cleanup is optional - keep files for debugging if needed
    # Remove-Item -Path $deployAppsPath -Recurse -Force -ErrorAction SilentlyContinue
}
#endregion

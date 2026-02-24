<#
    .SYNOPSIS
    Deploy AL apps to Business Central On-Premise server
    
    .DESCRIPTION
    This script is called by AL-Go for GitHub when EnvironmentType is set to "OnPrem".
    It receives deployment parameters and publishes apps to the BC on-premise server.
    
    Features:
    - Dependency-aware installation order
    - Multiple authentication methods (Windows, NavUserPassword, AAD)
    - Remote deployment support via PowerShell remoting (WinRM)
    - Configurable sync mode (Add, ForceSync, Development)
    - Automatic cleanup of old app versions
    - Comprehensive logging and error handling
    - Data upgrade support for app updates
    - SMB file transfer for remote deployments
    
    .NOTES
    Author: AL-Go On-Premise Deployer
    Version: 2.1.0
    Requires: Business Central Administration Shell or BC Management module
    
    For remote deployment, the runner needs:
    - Network access to BC server (WinRM port 5985/5986)
    - Credentials with admin rights on BC server
    - SMB access to a share on BC server for file transfer
#>

Param(
    [Parameter(Mandatory = $true)]
    [hashtable] $parameters
)

#region Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Script version for logging
$ScriptVersion = "2.1.0"

# Default values (can be overridden via AuthContext)
$DefaultPort = "7049"
$DefaultSyncMode = "Add"  # Add = safe, ForceSync = destructive, Development = dev only
$DefaultScope = "Tenant"  # Tenant or Global
$DefaultWinRMPort = 5985  # HTTP WinRM port (5986 for HTTPS)
#endregion

#region Helper Functions
function Write-DeployLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "Info"    { "[INFO]   " }
        "Warning" { "[WARN]   " }
        "Error"   { "[ERROR]  " }
        "Success" { "[OK]     " }
        "Debug"   { "[DEBUG]  " }
    }
    
    $logMessage = "$timestamp $prefix $Message"
    
    switch ($Level) {
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Debug"   { Write-Host $logMessage -ForegroundColor Gray }
        default   { Write-Host $logMessage }
    }
}

function Write-Banner {
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "       AL-Go On-Premise Deployment Script v$ScriptVersion                    " -ForegroundColor Cyan
    Write-Host "       Business Central Extension Deployment                         " -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-AppInfoFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppPath
    )
    
    try {
        # Try using Get-NAVAppInfo if available
        if (Get-Command Get-NAVAppInfo -ErrorAction SilentlyContinue) {
            return Get-NAVAppInfo -Path $AppPath
        }
        
        # Fallback: Extract app.json from .app file (it's a ZIP with navx extension)
        $tempExtract = Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
        
        try {
            # .app files are ZIP archives
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($AppPath, $tempExtract)
            
            $navxManifest = Join-Path $tempExtract "NavxManifest.xml"
            if (Test-Path $navxManifest) {
                [xml]$manifest = Get-Content $navxManifest
                $app = $manifest.Package.App
                return [PSCustomObject]@{
                    AppId     = $app.Id
                    Name      = $app.Name
                    Publisher = $app.Publisher
                    Version   = [Version]$app.Version
                }
            }
        }
        finally {
            Remove-Item -Path $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-DeployLog "Could not read app info from file: $_" -Level Warning
    }
    
    # Return minimal info based on filename
    return [PSCustomObject]@{
        AppId     = $null
        Name      = [System.IO.Path]::GetFileNameWithoutExtension($AppPath)
        Publisher = "Unknown"
        Version   = [Version]"1.0.0.0"
    }
}

function Get-AppDependencies {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppPath
    )
    
    try {
        $tempExtract = Join-Path ([System.IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
        
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($AppPath, $tempExtract)
            
            $navxManifest = Join-Path $tempExtract "NavxManifest.xml"
            if (Test-Path $navxManifest) {
                [xml]$manifest = Get-Content $navxManifest
                $dependencies = @()
                
                foreach ($dep in $manifest.Package.Dependencies.Dependency) {
                    $dependencies += [PSCustomObject]@{
                        AppId     = $dep.Id
                        Name      = $dep.Name
                        Publisher = $dep.Publisher
                        MinVersion = $dep.MinVersion
                    }
                }
                
                return $dependencies
            }
        }
        finally {
            Remove-Item -Path $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-DeployLog "Could not read dependencies: $_" -Level Warning
    }
    
    return @()
}

function Get-SortedAppsByDependency {
    param(
        [Parameter(Mandatory = $true)]
        [array]$AppFiles
    )
    
    Write-DeployLog "Analyzing app dependencies for installation order..."
    
    # Build app info collection
    $appInfos = @()
    foreach ($appFile in $AppFiles) {
        $info = Get-AppInfoFromFile -AppPath $appFile.FullName
        $deps = Get-AppDependencies -AppPath $appFile.FullName
        
        $appInfos += [PSCustomObject]@{
            File         = $appFile
            Info         = $info
            Dependencies = $deps
            AppId        = $info.AppId
        }
    }
    
    # Topological sort based on dependencies
    $sorted = @()
    $remaining = [System.Collections.ArrayList]@($appInfos)
    $maxIterations = $appInfos.Count * 2  # Prevent infinite loops
    $iteration = 0
    
    while ($remaining.Count -gt 0 -and $iteration -lt $maxIterations) {
        $iteration++
        $added = $false
        
        for ($i = $remaining.Count - 1; $i -ge 0; $i--) {
            $app = $remaining[$i]
            $canAdd = $true
            
            # Check if all dependencies are already in sorted list
            foreach ($dep in $app.Dependencies) {
                # Skip system/base app dependencies
                if ($dep.Publisher -eq "Microsoft") { continue }
                
                $depInSorted = $sorted | Where-Object { $_.AppId -eq $dep.AppId }
                $depInRemaining = $remaining | Where-Object { $_.AppId -eq $dep.AppId }
                
                if (-not $depInSorted -and $depInRemaining) {
                    $canAdd = $false
                    break
                }
            }
            
            if ($canAdd) {
                $sorted += $app
                $remaining.RemoveAt($i)
                $added = $true
            }
        }
        
        # If no progress, add remaining apps (circular dependency or external deps)
        if (-not $added -and $remaining.Count -gt 0) {
            Write-DeployLog "Warning: Possible circular dependency detected, adding remaining apps" -Level Warning
            $sorted += $remaining
            $remaining.Clear()
        }
    }
    
    Write-DeployLog "Installation order determined for $($sorted.Count) apps" -Level Success
    
    return $sorted
}

function Import-BCManagementModule {
    param(
        [string]$PreferredVersion
    )
    
    Write-DeployLog "Importing Business Central Management module..."
    
    # Module search paths (newest first)
    $searchPaths = @(
        "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\Microsoft.Dynamics.Nav.Management.psm1",
        "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\NAVAdminTool.ps1",
        "C:\Program Files (x86)\Microsoft Dynamics 365 Business Central\*\RoleTailored Client\Microsoft.Dynamics.Nav.Management.psm1"
    )
    
    foreach ($searchPath in $searchPaths) {
        $resolvedPaths = Resolve-Path $searchPath -ErrorAction SilentlyContinue | Sort-Object -Descending
        
        foreach ($resolved in $resolvedPaths) {
            try {
                if ($resolved.Path -like "*.ps1") {
                    . $resolved.Path
                }
                else {
                    Import-Module $resolved.Path -Force -DisableNameChecking
                }
                
                Write-DeployLog "Loaded BC Management module from: $($resolved.Path)" -Level Success
                return $true
            }
            catch {
                Write-DeployLog "Failed to load from $($resolved.Path): $_" -Level Debug
            }
        }
    }
    
    return $false
}

function Invoke-BCDeployment {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AppInfo,
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        [string]$Tenant = "default",
        [ValidateSet("Add", "ForceSync", "Development", "Clean")]
        [string]$SyncMode = "Add",
        [ValidateSet("Tenant", "Global")]
        [string]$Scope = "Tenant",
        [switch]$SkipVerification,
        [switch]$Force
    )
    
    $appFile = $AppInfo.File
    $info = $AppInfo.Info
    
    Write-DeployLog "Deploying: $($info.Name) v$($info.Version) by $($info.Publisher)"
    
    # Step 1: Publish
    Write-DeployLog "  Step 1/3: Publishing app..." -Level Info
    $publishParams = @{
        ServerInstance   = $ServerInstance
        Path             = $appFile.FullName
        SkipVerification = $SkipVerification
        Scope            = $Scope
    }
    
    if ($Tenant -and $Scope -eq "Tenant") {
        $publishParams.Tenant = $Tenant
    }
    
    try {
        Publish-NAVApp @publishParams
        Write-DeployLog "  Published successfully" -Level Success
    }
    catch {
        if ($_.Exception.Message -like "*already published*") {
            Write-DeployLog "  App version already published, continuing..." -Level Warning
        }
        else {
            throw "Failed to publish: $_"
        }
    }
    
    # Step 2: Sync
    Write-DeployLog "  Step 2/3: Syncing app (Mode: $SyncMode)..." -Level Info
    $syncParams = @{
        ServerInstance = $ServerInstance
        Name           = $info.Name
        Publisher      = $info.Publisher
        Version        = $info.Version
        Mode           = $SyncMode
    }
    
    if ($Tenant) {
        $syncParams.Tenant = $Tenant
    }
    
    try {
        Sync-NAVApp @syncParams
        Write-DeployLog "  Synced successfully" -Level Success
    }
    catch {
        Write-DeployLog "  Sync warning: $_" -Level Warning
    }
    
    # Step 3: Install or Upgrade
    Write-DeployLog "  Step 3/3: Installing/Upgrading app..." -Level Info
    $installParams = @{
        ServerInstance = $ServerInstance
        Name           = $info.Name
        Publisher      = $info.Publisher
        Version        = $info.Version
    }
    
    if ($Tenant) {
        $installParams.Tenant = $Tenant
    }
    
    try {
        # Check if any version is already installed
        # Query without -Tenant first to find all published versions
        $allApps = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $info.Name -Publisher $info.Publisher -ErrorAction SilentlyContinue
        
        # Then filter for installed apps on the specific tenant
        $installedApp = $allApps | Where-Object { 
            $_.IsInstalled -and ($_.Tenant -eq $Tenant -or $Tenant -eq 'default' -or [string]::IsNullOrEmpty($Tenant))
        } | Select-Object -First 1
        
        if ($installedApp) {
            if ($installedApp.Version -lt $info.Version) {
                Write-DeployLog "  Upgrading from v$($installedApp.Version) to v$($info.Version)..." -Level Info
                Start-NAVAppDataUpgrade @installParams
                Write-DeployLog "  Data upgrade completed" -Level Success
            }
            elseif ($installedApp.Version -eq $info.Version) {
                Write-DeployLog "  Same version already installed, reinstalling..." -Level Warning
                Uninstall-NAVApp -ServerInstance $ServerInstance -Name $info.Name -Publisher $info.Publisher -Version $info.Version -Tenant $Tenant -Force
                Install-NAVApp @installParams
                Write-DeployLog "  Reinstalled successfully" -Level Success
            }
            else {
                Write-DeployLog "  Newer version ($($installedApp.Version)) already installed, skipping" -Level Warning
            }
        }
        else {
            Install-NAVApp @installParams
            Write-DeployLog "  Installed successfully" -Level Success
        }
    }
    catch {
        throw "Failed to install/upgrade: $_"
    }
    
    return $true
}

function Remove-OldAppVersions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        [string]$Tenant = "default",
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AppInfo,
        [int]$KeepVersions = 1
    )
    
    $info = $AppInfo.Info
    
    try {
        $allVersions = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $info.Name -Publisher $info.Publisher -Tenant $Tenant -ErrorAction SilentlyContinue |
                       Sort-Object Version -Descending
        
        if ($allVersions.Count -gt $KeepVersions) {
            Write-DeployLog "  Cleaning up old versions (keeping last $KeepVersions)..." -Level Info
            
            $versionsToRemove = $allVersions | Select-Object -Skip $KeepVersions
            
            foreach ($oldVersion in $versionsToRemove) {
                if (-not $oldVersion.IsInstalled) {
                    try {
                        Unpublish-NAVApp -ServerInstance $ServerInstance -Name $oldVersion.Name -Publisher $oldVersion.Publisher -Version $oldVersion.Version
                        Write-DeployLog "    Removed v$($oldVersion.Version)" -Level Debug
                    }
                    catch {
                        Write-DeployLog "    Could not remove v$($oldVersion.Version): $_" -Level Warning
                    }
                }
            }
        }
    }
    catch {
        Write-DeployLog "  Could not clean up old versions: $_" -Level Warning
    }
}

function Invoke-RemoteDeployment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [switch]$UseSSL,
        [int]$Port = 5985
    )
    
    Write-DeployLog "Executing remote deployment on $ComputerName..."
    
    $sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    
    $sessionParams = @{
        ComputerName  = $ComputerName
        Credential    = $Credential
        SessionOption = $sessionOptions
        ErrorAction   = "Stop"
    }
    
    if ($UseSSL) {
        $sessionParams.UseSSL = $true
        $sessionParams.Port = if ($Port -eq 5985) { 5986 } else { $Port }
    }
    elseif ($Port -ne 5985) {
        $sessionParams.Port = $Port
    }
    
    $session = New-PSSession @sessionParams
    
    try {
        $result = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        return $result
    }
    finally {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}

function Copy-AppsToRemoteServer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [string]$LocalPath,
        [string]$RemoteSharePath,
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    
    Write-DeployLog "Copying apps to remote server $ComputerName..."
    
    # If a share path is provided, use SMB
    if ($RemoteSharePath) {
        Write-DeployLog "Using SMB share: $RemoteSharePath" -Level Debug
        
        # Create PSDrive with credentials
        $driveName = "BCDeploy_$([Guid]::NewGuid().ToString().Substring(0,8))"
        
        try {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root $RemoteSharePath -Credential $Credential -ErrorAction Stop | Out-Null
            
            $remoteTempFolder = Join-Path "${driveName}:" "ALGoDeploy_$([Guid]::NewGuid().ToString().Substring(0,8))"
            New-Item -ItemType Directory -Path $remoteTempFolder -Force | Out-Null
            
            # Copy all .app files
            $appFiles = Get-ChildItem -Path $LocalPath -Filter "*.app" -Recurse
            foreach ($appFile in $appFiles) {
                Copy-Item -Path $appFile.FullName -Destination $remoteTempFolder -Force
                Write-DeployLog "  Copied: $($appFile.Name)" -Level Debug
            }
            
            # Convert the UNC path back to local path on remote server
            # e.g., \\server\c$\temp -> C:\temp
            $remoteLocalPath = $RemoteSharePath -replace '^\\\\[^\\]+\\([a-zA-Z])\$', '$1:'
            $remoteLocalPath = Join-Path $remoteLocalPath (Split-Path $remoteTempFolder -Leaf)
            
            Write-DeployLog "Apps copied to: $remoteLocalPath" -Level Success
            
            return @{
                RemotePath = $remoteLocalPath
                DriveName  = $driveName
                CleanupPath = $remoteTempFolder
            }
        }
        catch {
            if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
                Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
            }
            throw "Failed to copy files via SMB: $_"
        }
    }
    # Use PSSession to copy files
    elseif ($Session) {
        Write-DeployLog "Using PowerShell session for file transfer..." -Level Debug
        
        # Create remote temp folder
        $remoteTempFolder = Invoke-Command -Session $Session -ScriptBlock {
            $folder = Join-Path ([System.IO.Path]::GetTempPath()) "ALGoDeploy_$([Guid]::NewGuid().ToString().Substring(0,8))"
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            return $folder
        }
        
        # Copy files using Copy-Item with ToSession
        $appFiles = Get-ChildItem -Path $LocalPath -Filter "*.app" -Recurse
        foreach ($appFile in $appFiles) {
            Copy-Item -Path $appFile.FullName -Destination $remoteTempFolder -ToSession $Session -Force
            Write-DeployLog "  Copied: $($appFile.Name)" -Level Debug
        }
        
        Write-DeployLog "Apps copied to: $remoteTempFolder" -Level Success
        
        return @{
            RemotePath = $remoteTempFolder
            DriveName  = $null
            CleanupPath = $null
        }
    }
    else {
        throw "Either RemoteSharePath or Session must be provided for remote file copy"
    }
}

function Invoke-RemoteBCDeployment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $true)]
        [string]$RemoteAppsPath,
        [Parameter(Mandatory = $true)]
        [string]$ServerInstance,
        [string]$Tenant = "default",
        [ValidateSet("Add", "ForceSync", "Development", "Clean")]
        [string]$SyncMode = "Add",
        [ValidateSet("Tenant", "Global")]
        [string]$Scope = "Tenant",
        [bool]$SkipVerification = $true,
        [bool]$CleanupOldVersions = $true,
        [int]$KeepVersions = 2,
        [switch]$UseSSL,
        [int]$WinRMPort = 5985
    )
    
    Write-DeployLog "Starting remote deployment on $ComputerName..."
    
    # Create session
    $sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $sessionParams = @{
        ComputerName  = $ComputerName
        Credential    = $Credential
        SessionOption = $sessionOptions
        ErrorAction   = "Stop"
    }
    
    if ($UseSSL) {
        $sessionParams.UseSSL = $true
        $sessionParams.Port = if ($WinRMPort -eq 5985) { 5986 } else { $WinRMPort }
    }
    elseif ($WinRMPort -ne 5985) {
        $sessionParams.Port = $WinRMPort
    }
    
    $session = New-PSSession @sessionParams
    
    try {
        # Execute deployment on remote server
        $result = Invoke-Command -Session $session -ScriptBlock {
            param(
                $AppsPath,
                $ServerInstance,
                $Tenant,
                $SyncMode,
                $Scope,
                $SkipVerification,
                $CleanupOldVersions,
                $KeepVersions
            )
            
            $ErrorActionPreference = "Stop"
            $results = @{
                Success = @()
                Failed = @()
                Errors = @()
            }
            
            try {
                # Import BC Management module
                $modulePaths = @(
                    "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\Microsoft.Dynamics.Nav.Management.psm1",
                    "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\NAVAdminTool.ps1"
                )
                
                $moduleLoaded = $false
                foreach ($modulePath in $modulePaths) {
                    $resolvedPaths = Resolve-Path $modulePath -ErrorAction SilentlyContinue | Sort-Object -Descending
                    foreach ($resolved in $resolvedPaths) {
                        try {
                            if ($resolved.Path -like "*.ps1") {
                                . $resolved.Path
                            }
                            else {
                                Import-Module $resolved.Path -Force -DisableNameChecking
                            }
                            $moduleLoaded = $true
                            Write-Host "[REMOTE] Loaded BC module from: $($resolved.Path)"
                            break
                        }
                        catch { }
                    }
                    if ($moduleLoaded) { break }
                }
                
                if (-not $moduleLoaded) {
                    throw "Could not load BC Management module on remote server"
                }
                
                # Get all .app files
                $appFiles = Get-ChildItem -Path $AppsPath -Filter "*.app" -Recurse | Sort-Object Name
                Write-Host "[REMOTE] Found $($appFiles.Count) app(s) to deploy"
                
                foreach ($appFile in $appFiles) {
                    try {
                        Write-Host "[REMOTE] Processing: $($appFile.Name)"
                        
                        # Get app info
                        $appInfo = Get-NAVAppInfo -Path $appFile.FullName -ErrorAction SilentlyContinue
                        $appName = if ($appInfo) { $appInfo.Name } else { $appFile.BaseName }
                        $appVersion = if ($appInfo) { $appInfo.Version } else { "1.0.0.0" }
                        $appPublisher = if ($appInfo) { $appInfo.Publisher } else { "Unknown" }
                        
                        Write-Host "[REMOTE]   App: $appName v$appVersion by $appPublisher"
                        
                        # Publish
                        Write-Host "[REMOTE]   Publishing..."
                        $publishParams = @{
                            ServerInstance   = $ServerInstance
                            Path             = $appFile.FullName
                            SkipVerification = $SkipVerification
                            Scope            = $Scope
                        }
                        if ($Tenant -and $Scope -eq "Tenant") {
                            $publishParams.Tenant = $Tenant
                        }
                        
                        try {
                            Publish-NAVApp @publishParams
                            Write-Host "[REMOTE]   Published successfully"
                        }
                        catch {
                            if ($_.Exception.Message -like "*already published*") {
                                Write-Host "[REMOTE]   Already published, continuing..."
                            }
                            else {
                                throw $_
                            }
                        }
                        
                        # CRITICAL FIX: Get app info directly from server after publishing
                        # Query the published app using the file path - BC knows what it just published
                        Write-Host "[REMOTE]   Querying published app metadata from server..."
                        $publishedApp = Get-NAVAppInfo -ServerInstance $ServerInstance -Path $appFile.FullName -ErrorAction SilentlyContinue
                        
                        if ($publishedApp) {
                            # Use the EXACT metadata that BC has for this published app
                            $appName = $publishedApp.Name
                            $appVersion = $publishedApp.Version
                            $appPublisher = $publishedApp.Publisher
                            Write-Host "[REMOTE]   Published app metadata: $appName v$appVersion by $appPublisher"
                        } else {
                            # Fallback: Query all published apps and find the most recent one matching the file
                            Write-Host "[REMOTE]   Warning: Could not read app from file, querying all published apps..."
                            $allPublishedApps = Get-NAVAppInfo -ServerInstance $ServerInstance -ErrorAction SilentlyContinue | Sort-Object Version -Descending
                            
                            # Try to match by looking at the most recently published app
                            # This assumes we just published it, so it should be at or near the top
                            $publishedApp = $allPublishedApps | Select-Object -First 1
                            
                            if ($publishedApp) {
                                $appName = $publishedApp.Name
                                $appVersion = $publishedApp.Version
                                $appPublisher = $publishedApp.Publisher
                                Write-Host "[REMOTE]   Using most recent published app: $appName v$appVersion by $appPublisher"
                            } else {
                                throw "Cannot determine app metadata - no published apps found on server"
                            }
                        }
                        
                        # Sync
                        Write-Host "[REMOTE]   Syncing (Mode: $SyncMode)..."
                        $syncParams = @{
                            ServerInstance = $ServerInstance
                            Name           = $appName
                            Publisher      = $appPublisher
                            Version        = $appVersion
                            Mode           = $SyncMode
                        }
                        if ($Tenant) {
                            $syncParams.Tenant = $Tenant
                        }
                        
                        try {
                            Sync-NAVApp @syncParams
                            Write-Host "[REMOTE]   Synced successfully"
                        }
                        catch {
                            Write-Host "[REMOTE]   Sync warning: $_"
                        }
                        
                        # Install/Upgrade
                        Write-Host "[REMOTE]   Installing..."
                        $installParams = @{
                            ServerInstance = $ServerInstance
                            Name           = $appName
                            Publisher      = $appPublisher
                            Version        = $appVersion
                        }
                        if ($Tenant) {
                            $installParams.Tenant = $Tenant
                        }
                        
                        try {
                            $installedApp = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Tenant $Tenant -ErrorAction SilentlyContinue | 
                                            Where-Object { $_.IsInstalled }
                            
                            if ($installedApp) {
                                if ($installedApp.Version -lt $appVersion) {
                                    Write-Host "[REMOTE]   Upgrading from v$($installedApp.Version)..."
                                    Start-NAVAppDataUpgrade @installParams
                                }
                                elseif ($installedApp.Version -eq $appVersion) {
                                    Write-Host "[REMOTE]   Reinstalling same version..."
                                    Uninstall-NAVApp -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant -Force -ErrorAction SilentlyContinue
                                    Install-NAVApp @installParams
                                }
                                else {
                                    Write-Host "[REMOTE]   Newer version already installed, skipping"
                                }
                            }
                            else {
                                Install-NAVApp @installParams
                            }
                            Write-Host "[REMOTE]   Installed successfully"
                        }
                        catch {
                            Write-Host "[REMOTE]   Install warning: $_"
                        }
                        
                        # Cleanup old versions
                        if ($CleanupOldVersions) {
                            try {
                                $allVersions = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Tenant $Tenant -ErrorAction SilentlyContinue |
                                               Sort-Object Version -Descending
                                
                                if ($allVersions.Count -gt $KeepVersions) {
                                    $versionsToRemove = $allVersions | Select-Object -Skip $KeepVersions
                                    foreach ($oldVersion in $versionsToRemove) {
                                        if (-not $oldVersion.IsInstalled) {
                                            Unpublish-NAVApp -ServerInstance $ServerInstance -Name $oldVersion.Name -Publisher $oldVersion.Publisher -Version $oldVersion.Version -ErrorAction SilentlyContinue
                                            Write-Host "[REMOTE]   Removed old version: v$($oldVersion.Version)"
                                        }
                                    }
                                }
                            }
                            catch {
                                Write-Host "[REMOTE]   Cleanup warning: $_"
                            }
                        }
                        
                        $results.Success += $appName
                        Write-Host "[REMOTE]   Deployment complete for: $appName"
                    }
                    catch {
                        $results.Failed += $appFile.Name
                        $results.Errors += "$($appFile.Name): $_"
                        Write-Host "[REMOTE] FAILED: $($appFile.Name) - $_"
                    }
                }
            }
            catch {
                $results.Errors += "Remote deployment error: $_"
            }
            finally {
                # Cleanup temp folder on remote server
                if (Test-Path $AppsPath) {
                    Remove-Item -Path $AppsPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            
            return $results
            
        } -ArgumentList $RemoteAppsPath, $ServerInstance, $Tenant, $SyncMode, $Scope, $SkipVerification, $CleanupOldVersions, $KeepVersions
        
        return $result
    }
    finally {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}

function Test-RemoteDeploymentRequired {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    
    # Check if we're running on the BC server itself
    $localHostNames = @(
        $env:COMPUTERNAME,
        "localhost",
        "127.0.0.1",
        "::1"
    )
    
    # Add FQDN if available
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        $localHostNames += $fqdn
    }
    catch { }
    
    # Check if server matches any local identifier
    $serverLower = $Server.ToLower()
    foreach ($localName in $localHostNames) {
        if ($serverLower -eq $localName.ToLower()) {
            return $false
        }
        # Check if server is part of FQDN
        if ($serverLower -like "$($localName.ToLower()).*") {
            return $false
        }
    }
    
    return $true
}
#endregion

#region Main Script
try {
    Write-Banner
    
    # Extract parameters from AL-Go
    $type = $parameters.type                        # CD or Release
    $apps = $parameters.apps                        # Path to apps (zip or folder)
    $environmentType = $parameters.EnvironmentType  # OnPrem
    $environmentName = $parameters.EnvironmentName  # e.g., BCOnPremTest
    $authContextJson = $parameters.AuthContext      # JSON with server credentials
    
    Write-DeployLog "Deployment Type: $type"
    Write-DeployLog "Environment Type: $environmentType"
    Write-DeployLog "Environment Name: $environmentName"
    Write-DeployLog "Apps Package: $apps"
    
    # Parse AuthContext
    Write-DeployLog "Parsing authentication context..."
    try {
        $authContext = $authContextJson | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse AuthContext JSON. Ensure the secret is valid JSON: $_"
    }
    
    # Validate required properties
    $requiredProps = @('Server', 'ServerInstance')
    foreach ($prop in $requiredProps) {
        if (-not $authContext.$prop) {
            throw "AuthContext is missing required property: $prop"
        }
    }
    
    # Extract configuration from AuthContext (using PSObject.Properties to safely check for optional properties)
    $server = $authContext.Server
    $serverInstance = $authContext.ServerInstance
    $port = if ($authContext.PSObject.Properties['Port']) { $authContext.Port } else { $DefaultPort }
    $tenant = if ($authContext.PSObject.Properties['Tenant']) { $authContext.Tenant } else { "default" }
    $authentication = if ($authContext.PSObject.Properties['Authentication']) { $authContext.Authentication } else { "Windows" }
    $syncMode = if ($authContext.PSObject.Properties['SyncMode']) { $authContext.SyncMode } else { $DefaultSyncMode }
    $scope = if ($authContext.PSObject.Properties['Scope']) { $authContext.Scope } else { $DefaultScope }
    $cleanupOldVersions = if ($authContext.PSObject.Properties['CleanupOldVersions'] -and $null -ne $authContext.CleanupOldVersions) { $authContext.CleanupOldVersions } else { $true }
    $keepVersions = if ($authContext.PSObject.Properties['KeepVersions']) { $authContext.KeepVersions } else { 2 }
    $skipVerification = if ($authContext.PSObject.Properties['SkipVerification'] -and $null -ne $authContext.SkipVerification) { $authContext.SkipVerification } else { $true }
    
    # Remote deployment configuration
    $useRemoteDeployment = if ($authContext.PSObject.Properties['UseRemoteDeployment'] -and $null -ne $authContext.UseRemoteDeployment) { $authContext.UseRemoteDeployment } else { $null }  # null = auto-detect
    $remoteUsername = if ($authContext.PSObject.Properties['RemoteUsername']) { $authContext.RemoteUsername } else { $null }
    $remotePassword = if ($authContext.PSObject.Properties['RemotePassword']) { $authContext.RemotePassword } else { $null }
    $remoteSharePath = if ($authContext.PSObject.Properties['RemoteSharePath']) { $authContext.RemoteSharePath } else { $null }  # e.g., \\server\c$\temp or \\server\BCDeploy
    $winRMPort = if ($authContext.PSObject.Properties['WinRMPort']) { $authContext.WinRMPort } else { $DefaultWinRMPort }
    $useSSL = if ($authContext.PSObject.Properties['UseSSL'] -and $null -ne $authContext.UseSSL) { $authContext.UseSSL } else { $false }
    
    # Determine if remote deployment is needed
    $isRemote = if ($null -ne $useRemoteDeployment) { 
        $useRemoteDeployment 
    } 
    else { 
        Test-RemoteDeploymentRequired -Server $server 
    }
    
    $deploymentMode = if ($isRemote) { "Remote (WinRM)" } else { "Local" }
    
    Write-Host ""
    Write-Host "----------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " Connection Configuration                     " -ForegroundColor DarkCyan
    Write-Host "----------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " Server:          $server" -ForegroundColor DarkCyan
    Write-Host " Instance:        $serverInstance" -ForegroundColor DarkCyan
    Write-Host " Port:            $port" -ForegroundColor DarkCyan
    Write-Host " Tenant:          $tenant" -ForegroundColor DarkCyan
    Write-Host " Authentication:  $authentication" -ForegroundColor DarkCyan
    Write-Host " Sync Mode:       $syncMode" -ForegroundColor DarkCyan
    Write-Host " Scope:           $scope" -ForegroundColor DarkCyan
    Write-Host " Cleanup Old:     $cleanupOldVersions (keep $keepVersions)" -ForegroundColor DarkCyan
    Write-Host " Deployment Mode: $deploymentMode" -ForegroundColor DarkCyan
    if ($isRemote) {
        Write-Host " WinRM Port:      $winRMPort $(if ($useSSL) { '(SSL)' } else { '(HTTP)' })" -ForegroundColor DarkCyan
        Write-Host " File Transfer:   $(if ($remoteSharePath) { 'SMB Share' } else { 'PS Session' })" -ForegroundColor DarkCyan
    }
    Write-Host "----------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""
    
    # Create temp folder for extraction
    $tempFolder = Join-Path ([System.IO.Path]::GetTempPath()) "ALGoDeploy_$([Guid]::NewGuid().ToString().Substring(0,8))"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
    Write-DeployLog "Created temp folder: $tempFolder" -Level Debug
    
    # Extract apps
    Write-DeployLog "Extracting apps from package..."
    
    if ($apps -like "*.zip") {
        Expand-Archive -Path $apps -DestinationPath $tempFolder -Force
    }
    elseif (Test-Path $apps -PathType Container) {
        Copy-Item -Path "$apps\*" -Destination $tempFolder -Recurse -Force
    }
    else {
        Copy-Item -Path $apps -Destination $tempFolder -Force
    }
    
    # Find all .app files (wrap in @() to ensure array even for single/null results)
    $appFiles = @(Get-ChildItem -Path $tempFolder -Filter "*.app" -Recurse -ErrorAction SilentlyContinue)
    
    if ($null -eq $appFiles -or $appFiles.Count -eq 0) {
        throw "No .app files found in the deployment package"
    }
    
    Write-DeployLog "Found $($appFiles.Count) app(s) to deploy" -Level Success
    
    # Sort apps by dependency order
    $sortedApps = Get-SortedAppsByDependency -AppFiles $appFiles
    
    Write-Host ""
    Write-Host "----------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " Deployment Order                             " -ForegroundColor DarkCyan
    Write-Host "----------------------------------------------" -ForegroundColor DarkCyan
    $order = 1
    foreach ($app in $sortedApps) {
        Write-Host " $order. $($app.Info.Name) v$($app.Info.Version)" -ForegroundColor DarkCyan
        $order++
    }
    Write-Host "----------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""
    
    # Initialize deployment variables
    $successCount = 0
    $failedApps = @()
    
    # Check if remote deployment is needed
    if ($isRemote) {
        #region Remote Deployment
        Write-DeployLog "Remote deployment detected - will use PowerShell Remoting" -Level Info
        
        # Build credentials for remote connection
        if ($remoteUsername -and $remotePassword) {
            $securePassword = ConvertTo-SecureString $remotePassword -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($remoteUsername, $securePassword)
            Write-DeployLog "Using provided credentials for remote connection" -Level Debug
        }
        else {
            # Try to use current Windows credentials or prompt
            Write-DeployLog "No remote credentials provided, attempting to use current Windows identity" -Level Warning
            
            # For GitHub Actions with self-hosted runner, we might be running as a service account
            # that has access to the BC server
            try {
                # Test connection first
                $testResult = Test-WSMan -ComputerName $server -ErrorAction Stop
                Write-DeployLog "WinRM connection test successful" -Level Success
                $credential = $null  # Use implicit credentials
            }
            catch {
                throw "Cannot connect to remote server '$server'. Either provide RemoteUsername/RemotePassword in AuthContext, or ensure the runner has Windows authentication access to the BC server. Error: $_"
            }
        }
        
        # Create PS Session
        Write-DeployLog "Establishing remote session to $server..."
        
        $sessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $sessionParams = @{
            ComputerName  = $server
            SessionOption = $sessionOptions
            ErrorAction   = "Stop"
        }
        
        if ($credential) {
            $sessionParams.Credential = $credential
        }
        
        if ($useSSL) {
            $sessionParams.UseSSL = $true
            $sessionParams.Port = if ($winRMPort -eq 5985) { 5986 } else { $winRMPort }
        }
        elseif ($winRMPort -ne 5985) {
            $sessionParams.Port = $winRMPort
        }
        
        $remoteSession = New-PSSession @sessionParams
        Write-DeployLog "Remote session established" -Level Success
        
        try {
            # Copy apps to remote server
            Write-DeployLog "Transferring apps to remote server..."
            
            if ($remoteSharePath) {
                # Use SMB share for file transfer
                $copyResult = Copy-AppsToRemoteServer -ComputerName $server -Credential $credential -LocalPath $tempFolder -RemoteSharePath $remoteSharePath
                $remoteAppsPath = $copyResult.RemotePath
                $cleanupDrive = $copyResult.DriveName
            }
            else {
                # Use PS Session for file transfer
                $remoteAppsPath = Invoke-Command -Session $remoteSession -ScriptBlock {
                    $folder = Join-Path ([System.IO.Path]::GetTempPath()) "ALGoDeploy_$([Guid]::NewGuid().ToString().Substring(0,8))"
                    New-Item -ItemType Directory -Path $folder -Force | Out-Null
                    return $folder
                }
                
                $localAppFiles = Get-ChildItem -Path $tempFolder -Filter "*.app" -Recurse
                foreach ($appFile in $localAppFiles) {
                    Copy-Item -Path $appFile.FullName -Destination $remoteAppsPath -ToSession $remoteSession -Force
                    Write-DeployLog "  Transferred: $($appFile.Name)" -Level Debug
                }
                $cleanupDrive = $null
            }
            
            Write-DeployLog "Apps transferred to: $remoteAppsPath" -Level Success
            
            # Execute deployment on remote server
            Write-DeployLog "Executing deployment on remote server..."
            Write-Host ""
            
            $remoteResult = Invoke-Command -Session $remoteSession -ScriptBlock {
                param(
                    $AppsPath,
                    $ServerInstance,
                    $Tenant,
                    $SyncMode,
                    $Scope,
                    $SkipVerification,
                    $CleanupOldVersions,
                    $KeepVersions
                )
                
                $ErrorActionPreference = "Stop"
                $results = @{
                    Success = @()
                    Failed = @()
                    Errors = @()
                }
                
                try {
                    # Import BC Management module
                    $modulePaths = @(
                        "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\Microsoft.Dynamics.Nav.Management.psm1",
                        "C:\Program Files\Microsoft Dynamics 365 Business Central\*\Service\NAVAdminTool.ps1"
                    )
                    
                    $moduleLoaded = $false
                    foreach ($modulePath in $modulePaths) {
                        $resolvedPaths = Resolve-Path $modulePath -ErrorAction SilentlyContinue | Sort-Object -Descending
                        foreach ($resolved in $resolvedPaths) {
                            try {
                                if ($resolved.Path -like "*.ps1") {
                                    . $resolved.Path
                                }
                                else {
                                    Import-Module $resolved.Path -Force -DisableNameChecking
                                }
                                $moduleLoaded = $true
                                Write-Host "[REMOTE] Loaded BC module from: $($resolved.Path)"
                                break
                            }
                            catch { }
                        }
                        if ($moduleLoaded) { break }
                    }
                    
                    if (-not $moduleLoaded) {
                        throw "Could not load BC Management module on remote server"
                    }
                    
                    # Get all .app files
                    $appFiles = Get-ChildItem -Path $AppsPath -Filter "*.app" -Recurse | Sort-Object Name
                    Write-Host "[REMOTE] Found $($appFiles.Count) app(s) to deploy"
                    
                    foreach ($appFile in $appFiles) {
                        try {
                            Write-Host ""
                            Write-Host "[REMOTE] Processing: $($appFile.Name)"
                            
                            # Get app info
                            $appInfo = Get-NAVAppInfo -Path $appFile.FullName -ErrorAction SilentlyContinue
                            $appName = if ($appInfo) { $appInfo.Name } else { $appFile.BaseName }
                            $appVersion = if ($appInfo) { $appInfo.Version } else { [Version]"1.0.0.0" }
                            $appPublisher = if ($appInfo) { $appInfo.Publisher } else { "Unknown" }
                            
                            Write-Host "[REMOTE]   App: $appName v$appVersion by $appPublisher"
                            
                            # Publish
                            Write-Host "[REMOTE]   Publishing..."
                            $publishParams = @{
                                ServerInstance   = $ServerInstance
                                Path             = $appFile.FullName
                                SkipVerification = $SkipVerification
                                Scope            = $Scope
                            }
                            if ($Tenant -and $Scope -eq "Tenant") {
                                $publishParams.Tenant = $Tenant
                            }
                            
                            try {
                                Publish-NAVApp @publishParams
                                Write-Host "[REMOTE]   Published successfully"
                            }
                            catch {
                                if ($_.Exception.Message -like "*already published*") {
                                    Write-Host "[REMOTE]   Already published, continuing..."
                                }
                                else {
                                    throw $_
                                }
                            }
                            
                            # Sync
                            Write-Host "[REMOTE]   Syncing (Mode: $SyncMode)..."
                            $syncParams = @{
                                ServerInstance = $ServerInstance
                                Name           = $appName
                                Publisher      = $appPublisher
                                Version        = $appVersion
                                Mode           = $SyncMode
                            }
                            if ($Tenant) {
                                $syncParams.Tenant = $Tenant
                            }
                            
                            try {
                                Sync-NAVApp @syncParams
                                Write-Host "[REMOTE]   Synced successfully"
                            }
                            catch {
                                Write-Host "[REMOTE]   Sync warning: $_"
                            }
                            
                            # Install/Upgrade
                            Write-Host "[REMOTE]   Installing..."
                            $installParams = @{
                                ServerInstance = $ServerInstance
                                Name           = $appName
                                Publisher      = $appPublisher
                                Version        = $appVersion
                            }
                            if ($Tenant) {
                                $installParams.Tenant = $Tenant
                            }
                            
                            try {
                                $installedApp = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Tenant $Tenant -ErrorAction SilentlyContinue | 
                                                Where-Object { $_.IsInstalled }
                                
                                if ($installedApp) {
                                    if ($installedApp.Version -lt $appVersion) {
                                        Write-Host "[REMOTE]   Upgrading from v$($installedApp.Version)..."
                                        Start-NAVAppDataUpgrade @installParams
                                    }
                                    elseif ($installedApp.Version -eq $appVersion) {
                                        Write-Host "[REMOTE]   Reinstalling same version..."
                                        Uninstall-NAVApp -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Version $appVersion -Tenant $Tenant -Force -ErrorAction SilentlyContinue
                                        Install-NAVApp @installParams
                                    }
                                    else {
                                        Write-Host "[REMOTE]   Newer version already installed, skipping"
                                    }
                                }
                                else {
                                    Install-NAVApp @installParams
                                }
                                Write-Host "[REMOTE]   Installed successfully"
                            }
                            catch {
                                Write-Host "[REMOTE]   Install warning: $_"
                            }
                            
                            # Cleanup old versions
                            if ($CleanupOldVersions) {
                                try {
                                    $allVersions = Get-NAVAppInfo -ServerInstance $ServerInstance -Name $appName -Publisher $appPublisher -Tenant $Tenant -ErrorAction SilentlyContinue |
                                                   Sort-Object Version -Descending
                                    
                                    if ($allVersions.Count -gt $KeepVersions) {
                                        $versionsToRemove = $allVersions | Select-Object -Skip $KeepVersions
                                        foreach ($oldVersion in $versionsToRemove) {
                                            if (-not $oldVersion.IsInstalled) {
                                                Unpublish-NAVApp -ServerInstance $ServerInstance -Name $oldVersion.Name -Publisher $oldVersion.Publisher -Version $oldVersion.Version -ErrorAction SilentlyContinue
                                                Write-Host "[REMOTE]   Removed old version: v$($oldVersion.Version)"
                                            }
                                        }
                                    }
                                }
                                catch {
                                    Write-Host "[REMOTE]   Cleanup warning: $_"
                                }
                            }
                            
                            $results.Success += $appName
                            Write-Host "[REMOTE]   Deployment complete for: $appName"
                        }
                        catch {
                            $results.Failed += $appFile.Name
                            $results.Errors += "$($appFile.Name): $_"
                            Write-Host "[REMOTE] FAILED: $($appFile.Name) - $_" 
                        }
                    }
                }
                catch {
                    $results.Errors += "Remote deployment error: $_"
                    Write-Host "[REMOTE] ERROR: $_"
                }
                finally {
                    # Cleanup temp folder on remote server
                    if (Test-Path $AppsPath) {
                        Remove-Item -Path $AppsPath -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "[REMOTE] Cleaned up temp folder"
                    }
                }
                
                return $results
                
            } -ArgumentList $remoteAppsPath, $serverInstance, $tenant, $syncMode, $scope, $skipVerification, $cleanupOldVersions, $keepVersions
            
            # Process remote results (safely handle null or non-array results)
            $successCount = if ($remoteResult -and $remoteResult.Success) { @($remoteResult.Success).Count } else { 0 }
            $failedApps = if ($remoteResult -and $remoteResult.Failed) { @($remoteResult.Failed) } else { @() }
            
            if ($remoteResult -and $remoteResult.Errors -and @($remoteResult.Errors).Count -gt 0) {
                foreach ($err in @($remoteResult.Errors)) {
                    Write-DeployLog "Remote error: $err" -Level Error
                }
            }
        }
        finally {
            # Cleanup
            if ($remoteSession) {
                Remove-PSSession -Session $remoteSession -ErrorAction SilentlyContinue
            }
            if ($cleanupDrive) {
                Remove-PSDrive -Name $cleanupDrive -Force -ErrorAction SilentlyContinue
            }
        }
        #endregion
    }
    else {
        #region Local Deployment
        Write-DeployLog "Local deployment - BC Management module required on this machine" -Level Info
        
        # Import BC Management module
        $moduleLoaded = Import-BCManagementModule
        
        if (-not $moduleLoaded) {
            throw "Could not load Business Central Management module. Ensure this script runs on a BC server or a machine with BC admin tools installed."
        }
        
        # Deploy each app
        Write-DeployLog "Starting deployment..."
        Write-Host ""
        
        foreach ($appInfo in $sortedApps) {
            Write-Host "----------------------------------------------" -ForegroundColor DarkGray
            
            try {
                $result = Invoke-BCDeployment `
                    -AppInfo $appInfo `
                    -ServerInstance $serverInstance `
                    -Tenant $tenant `
                    -SyncMode $syncMode `
                    -Scope $scope `
                    -SkipVerification:$skipVerification
                
                if ($result) {
                    $successCount++
                    
                    # Cleanup old versions if enabled
                    if ($cleanupOldVersions) {
                        Remove-OldAppVersions -ServerInstance $serverInstance -Tenant $tenant -AppInfo $appInfo -KeepVersions $keepVersions
                    }
                }
            }
            catch {
                Write-DeployLog "FAILED: $($appInfo.Info.Name) - $_" -Level Error
                $failedApps += $appInfo.Info.Name
            }
        }
        #endregion
    }
    
    # Ensure failedApps is an array
    $failedApps = @($failedApps)
    
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Cyan
    
    if ($failedApps.Count -eq 0) {
        Write-Host "  DEPLOYMENT COMPLETED SUCCESSFULLY" -ForegroundColor Green
        Write-Host "  Deployed: $successCount app(s)" -ForegroundColor Green
    }
    else {
        Write-Host "  DEPLOYMENT COMPLETED WITH ERRORS" -ForegroundColor Yellow
        Write-Host "  Succeeded: $successCount | Failed: $($failedApps.Count)" -ForegroundColor Yellow
        Write-Host "  Failed apps: $($failedApps -join ', ')" -ForegroundColor Red
    }
    
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Set GitHub Actions outputs
    $environmentUrl = "dynamicsnav://$server`:$port/$serverInstance"
    
    # Modern GitHub Actions output format
    if ($env:GITHUB_OUTPUT) {
        "environmentUrl=$environmentUrl" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
        "deployedApps=$successCount" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
    }
    
    # Create GitHub Actions summary if available
    if ($env:GITHUB_STEP_SUMMARY) {
        $summary = @"
## Deployment Summary

| Property | Value |
|----------|-------|
| Environment | $environmentName |
| Server | $server |
| Instance | $serverInstance |
| Apps Deployed | $successCount |
| Sync Mode | $syncMode |
| Deployment Mode | $deploymentMode |

### Deployed Apps
"@
        foreach ($app in $sortedApps) {
            $status = if ($app.Info.Name -in $failedApps) { "FAILED" } else { "OK" }
            $summary += "`n- [$status] **$($app.Info.Name)** v$($app.Info.Version)"
        }
        
        $summary | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
    }
    
    if ($failedApps.Count -gt 0) {
        throw "Deployment completed with $($failedApps.Count) failed app(s)"
    }
}
catch {
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Red
    Write-Host "           DEPLOYMENT FAILED                  " -ForegroundColor Red
    Write-Host "==============================================" -ForegroundColor Red
    Write-Host ""
    Write-DeployLog "Error: $_" -Level Error
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    Write-Host ""
    
    throw $_
}
finally {
    # Cleanup temp folder (use Get-Variable to safely check if variable exists)
    if ((Get-Variable -Name 'tempFolder' -ErrorAction SilentlyContinue) -and $tempFolder -and (Test-Path $tempFolder -ErrorAction SilentlyContinue)) {
        Write-DeployLog "Cleaning up temp folder..." -Level Debug
        Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

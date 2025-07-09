# Wizard-Shield v2.3 - Advanced IOC Blocking Script for Microsoft Defender for Endpoint
# Developer: mahdiesta@wizardcyber
# Description: Automates blocking of malicious indicators across multiple tenants
# Enhanced with comprehensive error handling

param(
    [string]$ConfigFile = ""
)

# Global Variables
$Global:TenantConfigs = @()
$Global:BlockedCount = 0
$Global:AlreadyBlockedCount = 0
$Global:FailedCount = 0

# Enhanced error handling function
function Write-ErrorMessage {
    param(
        [string]$FunctionName,
        [string]$ErrorMessage,
        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "ERROR in function: $FunctionName" -ForegroundColor Red
    Write-Host "Error Message: $ErrorMessage" -ForegroundColor Red
    if ($ErrorRecord) {
        Write-Host "Exception Type: $($ErrorRecord.Exception.GetType().Name)" -ForegroundColor Red
        Write-Host "Line Number: $($ErrorRecord.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
        Write-Host "Position: $($ErrorRecord.InvocationInfo.PositionMessage)" -ForegroundColor Red
    }
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host ""
}

# Function to show loading spinner
function Show-LoadingSpinner {
    param(
        [string]$Message = "Loading",
        [int]$Duration = 3
    )
    
    try {
        $spinnerChars = @('|', '/', '-', '\')
        $counter = 0
        $endTime = (Get-Date).AddSeconds($Duration)
        
        while ((Get-Date) -lt $endTime) {
            try {
                $spinnerChar = $spinnerChars[$counter % 4]
                Write-Host "`r$Message $spinnerChar" -NoNewline -ForegroundColor Cyan
                Start-Sleep -Milliseconds 200
                $counter++
            }
            catch {
                Write-ErrorMessage -FunctionName "Show-LoadingSpinner" -ErrorMessage "Error in spinner animation loop: $($_.Exception.Message)" -ErrorRecord $_
                break
            }
        }
        Write-Host "`r$Message... Done!" -ForegroundColor Green
    }
    catch {
        Write-ErrorMessage -FunctionName "Show-LoadingSpinner" -ErrorMessage "Failed to show loading spinner: $($_.Exception.Message)" -ErrorRecord $_
    }
}

# Function to show dot progress animation
function Show-DotProgress {
    param(
        [string]$Message,
        [int]$DotCount = 6
    )
    
    try {
        if ([string]::IsNullOrEmpty($Message)) {
            Write-Host "Warning: Empty message provided to Show-DotProgress" -ForegroundColor Yellow
            $Message = "Processing"
        }
        
        Write-Host "$Message " -NoNewline -ForegroundColor Yellow
        for ($i = 0; $i -lt $DotCount; $i++) {
            try {
                Write-Host "." -NoNewline -ForegroundColor Yellow
                Start-Sleep -Milliseconds 300
            }
            catch {
                Write-ErrorMessage -FunctionName "Show-DotProgress" -ErrorMessage "Error in dot animation loop: $($_.Exception.Message)" -ErrorRecord $_
                break
            }
        }
    }
    catch {
        Write-ErrorMessage -FunctionName "Show-DotProgress" -ErrorMessage "Failed to show dot progress: $($_.Exception.Message)" -ErrorRecord $_
    }
}

# Function to get AAD token
function Get-AADToken {
    param(
        [string]$TenantId,
        [string]$AppId,
        [string]$AppSecret
    )
    
    try {
        # Input validation
        if ([string]::IsNullOrEmpty($TenantId)) {
            Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "TenantId parameter is null or empty"
            return $null
        }
        if ([string]::IsNullOrEmpty($AppId)) {
            Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "AppId parameter is null or empty"
            return $null
        }
        if ([string]::IsNullOrEmpty($AppSecret)) {
            Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "AppSecret parameter is null or empty"
            return $null
        }
        
        $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
        $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $authBody = @{
            client_id     = $AppId
            client_secret = $AppSecret
            scope         = "$resourceAppIdUri/.default"
            grant_type    = 'client_credentials'
        }
        
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        
        if (-not $authResponse.access_token) {
            Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "No access token received from Azure AD"
            return $null
        }
        
        return $authResponse.access_token
    }
    catch [System.Net.WebException] {
        Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "Network error while getting AAD token for tenant $TenantId. Check internet connection and tenant credentials." -ErrorRecord $_
        return $null
    }
    catch [System.Management.Automation.RuntimeException] {
        Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "Authentication failed for tenant $TenantId. Verify App ID, Secret, and Tenant ID are correct." -ErrorRecord $_
        return $null
    }
    catch {
        Write-ErrorMessage -FunctionName "Get-AADToken" -ErrorMessage "Failed to get AAD token for tenant $TenantId`: $($_.Exception.Message)" -ErrorRecord $_
        return $null
    }
}

# Function to defang IOCs
function Repair-DefangedIOC {
    param([string]$IOC)
    
    try {
        if ([string]::IsNullOrEmpty($IOC)) {
            Write-ErrorMessage -FunctionName "Repair-DefangedIOC" -ErrorMessage "IOC parameter is null or empty"
            return ""
        }
        
        # Remove common defanging patterns
        $cleanIOC = $IOC -replace '\[', '' -replace '\]', '' -replace 'hxxp', 'http' -replace 'hXXp', 'http'
        $cleanIOC = $cleanIOC -replace '\.', '.' -replace '\(\.\)', '.'
        
        return $cleanIOC.Trim()
    }
    catch {
        Write-ErrorMessage -FunctionName "Repair-DefangedIOC" -ErrorMessage "Failed to repair defanged IOC '$IOC': $($_.Exception.Message)" -ErrorRecord $_
        return $IOC
    }
}

# Function to determine IOC type
function Get-IOCType {
    param([string]$IOC)
    
    try {
        if ([string]::IsNullOrEmpty($IOC)) {
            Write-ErrorMessage -FunctionName "Get-IOCType" -ErrorMessage "IOC parameter is null or empty"
            return "DomainName"
        }
        
        # Check if it's an IP address
        if ($IOC -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            return "IpAddress"
        }
        # Check if it's a URL
        elseif ($IOC -match '^https?://') {
            return "Url"
        }
        # Otherwise treat as domain
        else {
            return "DomainName"
        }
    }
    catch {
        Write-ErrorMessage -FunctionName "Get-IOCType" -ErrorMessage "Failed to determine IOC type for '$IOC': $($_.Exception.Message)" -ErrorRecord $_
        return "DomainName"
    }
}

# Function to check if IOC already exists
function Test-IOCExists {
    param(
        [string]$Token,
        [string]$IOC,
        [string]$IOCType
    )
    
    try {
        # Input validation
        if ([string]::IsNullOrEmpty($Token)) {
            Write-ErrorMessage -FunctionName "Test-IOCExists" -ErrorMessage "Token parameter is null or empty"
            return $false
        }
        if ([string]::IsNullOrEmpty($IOC)) {
            Write-ErrorMessage -FunctionName "Test-IOCExists" -ErrorMessage "IOC parameter is null or empty"
            return $false
        }
        if ([string]::IsNullOrEmpty($IOCType)) {
            Write-ErrorMessage -FunctionName "Test-IOCExists" -ErrorMessage "IOCType parameter is null or empty"
            return $false
        }
        
        $headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        
        $filterValue = [System.Web.HttpUtility]::UrlEncode($IOC)
        $checkUrl = "https://api.securitycenter.microsoft.com/api/indicators?`$filter=indicatorValue eq '$filterValue'"
        
        $response = Invoke-RestMethod -Method Get -Uri $checkUrl -Headers $headers -ErrorAction Stop
        
        if ($response -and $response.value) {
            return $response.value.Count -gt 0
        }
        
        return $false
    }
    catch [System.Net.WebException] {
        Write-ErrorMessage -FunctionName "Test-IOCExists" -ErrorMessage "Network error checking IOC existence for '$IOC'. Check internet connection." -ErrorRecord $_
        return $false
    }
    catch [System.UnauthorizedAccessException] {
        Write-ErrorMessage -FunctionName "Test-IOCExists" -ErrorMessage "Authorization failed when checking IOC existence for '$IOC'. Token may be expired or invalid." -ErrorRecord $_
        return $false
    }
    catch {
        Write-ErrorMessage -FunctionName "Test-IOCExists" -ErrorMessage "Error checking IOC existence for '$IOC': $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

# Function to block IOC
function Block-IOC {
    param(
        [string]$Token,
        [string]$IOC,
        [string]$IOCType,
        [string]$TenantName
    )
    
    try {
        # Input validation
        if ([string]::IsNullOrEmpty($Token)) {
            Write-ErrorMessage -FunctionName "Block-IOC" -ErrorMessage "Token parameter is null or empty"
            return $false
        }
        if ([string]::IsNullOrEmpty($IOC)) {
            Write-ErrorMessage -FunctionName "Block-IOC" -ErrorMessage "IOC parameter is null or empty"
            return $false
        }
        if ([string]::IsNullOrEmpty($IOCType)) {
            Write-ErrorMessage -FunctionName "Block-IOC" -ErrorMessage "IOCType parameter is null or empty"
            return $false
        }
        if ([string]::IsNullOrEmpty($TenantName)) {
            $TenantName = "Unknown"
        }
        
        $headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        
        $expirationTime = (Get-Date).AddDays(365).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        
        $body = @{
            indicatorValue = $IOC
            indicatorType  = $IOCType
            title          = "Blocked by Wizard-Shield v2.3"
            description    = "Automatically blocked malicious indicator via Wizard-Shield"
            expirationTime = $expirationTime
            severity       = "High"
            action         = "Block"
            recommendedActions = "Block this indicator"
            rbacGroupNames = @()
        } | ConvertTo-Json -ErrorAction Stop
        
        $blockUrl = "https://api.securitycenter.microsoft.com/api/indicators"
        $response = Invoke-RestMethod -Method Post -Uri $blockUrl -Headers $headers -Body $body -ErrorAction Stop
        
        if ($response) {
            return $true
        }
        
        return $false
    }
    catch [System.Net.WebException] {
        Write-ErrorMessage -FunctionName "Block-IOC" -ErrorMessage "Network error blocking IOC '$IOC' in tenant '$TenantName'. Check internet connection." -ErrorRecord $_
        return $false
    }
    catch [System.UnauthorizedAccessException] {
        Write-ErrorMessage -FunctionName "Block-IOC" -ErrorMessage "Authorization failed when blocking IOC '$IOC' in tenant '$TenantName'. Token may be expired or insufficient permissions." -ErrorRecord $_
        return $false
    }
    catch {
        Write-ErrorMessage -FunctionName "Block-IOC" -ErrorMessage "Failed to block IOC '$IOC' in tenant '$TenantName': $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

# Function to process IOCs with enhanced progress tracking for 30 tenants
function Process-IOCs {
    param([array]$IOCs)
    
    try {
        if (-not $IOCs -or $IOCs.Count -eq 0) {
            Write-ErrorMessage -FunctionName "Process-IOCs" -ErrorMessage "No IOCs provided for processing"
            return
        }
        
        if (-not $Global:TenantConfigs -or $Global:TenantConfigs.Count -eq 0) {
            Write-ErrorMessage -FunctionName "Process-IOCs" -ErrorMessage "No tenant configurations available"
            return
        }
        
        $totalOperations = $IOCs.Count * $Global:TenantConfigs.Count
        $currentOperation = 0
        
        Write-Host "`nProcessing $($IOCs.Count) IOC(s) across $($Global:TenantConfigs.Count) tenant(s)..." -ForegroundColor Cyan
        Write-Host "Total operations to perform: $totalOperations" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
        
        foreach ($ioc in $IOCs) {
            try {
                $cleanIOC = Repair-DefangedIOC -IOC $ioc
                $iocType = Get-IOCType -IOC $cleanIOC
                $iocIndex = $IOCs.IndexOf($ioc) + 1
                
                Write-Host ""
                Write-Host "[$iocIndex/$($IOCs.Count)] Processing IOC: $cleanIOC (Type: $iocType)" -ForegroundColor White -BackgroundColor DarkBlue
                Write-Host "─────────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
                
                $tenantIndex = 0
                foreach ($tenant in $Global:TenantConfigs) {
                    try {
                        $tenantIndex++
                        $currentOperation++
                        
                        if ($totalOperations -gt 0) {
                            $progressPercent = [math]::Round(($currentOperation / $totalOperations) * 100, 1)
                        } else {
                            $progressPercent = 0
                        }
                        
                        Write-Host "  [$tenantIndex/$($Global:TenantConfigs.Count)] $($tenant.Name) - Progress: $progressPercent%" -ForegroundColor Cyan
                        
                        # Get token with error handling
                        Write-Host "    └─ Getting token..." -NoNewline -ForegroundColor Gray
                        $token = Get-AADToken -TenantId $tenant.TenantId -AppId $tenant.AppId -AppSecret $tenant.AppSecret
                        
                        if (-not $token) {
                            Write-Host " ✗ Failed!" -ForegroundColor Red
                            $Global:FailedCount++
                            continue
                        }
                        Write-Host " ✓ Success" -ForegroundColor Green
                        
                        # Check if IOC already exists
                        Write-Host "    └─ Checking existing IOC..." -NoNewline -ForegroundColor Gray
                        $exists = Test-IOCExists -Token $token -IOC $cleanIOC -IOCType $iocType
                        
                        if ($exists) {
                            Write-Host " ⚠ Already blocked!" -ForegroundColor Yellow
                            $Global:AlreadyBlockedCount++
                            continue
                        }
                        Write-Host " ✓ Not found" -ForegroundColor Green
                        
                        # Block the IOC
                        Write-Host "    └─ Blocking IOC..." -NoNewline -ForegroundColor Gray
                        $blocked = Block-IOC -Token $token -IOC $cleanIOC -IOCType $iocType -TenantName $tenant.Name
                        
                        if ($blocked) {
                            Write-Host " ✓ Blocked successfully!" -ForegroundColor Green
                            $Global:BlockedCount++
                        } else {
                            Write-Host " ✗ Failed to block!" -ForegroundColor Red
                            $Global:FailedCount++
                        }
                    }
                    catch {
                        Write-ErrorMessage -FunctionName "Process-IOCs" -ErrorMessage "Error processing tenant '$($tenant.Name)': $($_.Exception.Message)" -ErrorRecord $_
                        $Global:FailedCount++
                    }
                }
                
                # Show intermediate summary after each IOC
                $completedIOCs = $iocIndex
                $remainingIOCs = $IOCs.Count - $completedIOCs
                Write-Host ""
                Write-Host "    IOC Summary - Completed: $completedIOCs | Remaining: $remainingIOCs" -ForegroundColor Magenta
                Write-Host "    Running Totals - Blocked: $Global:BlockedCount | Already Blocked: $Global:AlreadyBlockedCount | Failed: $Global:FailedCount" -ForegroundColor Magenta
            }
            catch {
                Write-ErrorMessage -FunctionName "Process-IOCs" -ErrorMessage "Error processing IOC '$ioc': $($_.Exception.Message)" -ErrorRecord $_
                $Global:FailedCount += $Global:TenantConfigs.Count
            }
        }
    }
    catch {
        Write-ErrorMessage -FunctionName "Process-IOCs" -ErrorMessage "Critical error in IOC processing: $($_.Exception.Message)" -ErrorRecord $_
    }
}

# Function to read IOCs from file
function Read-IOCsFromFile {
    param([string]$FilePath)
    
    try {
        if ([string]::IsNullOrEmpty($FilePath)) {
            Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "FilePath parameter is null or empty"
            return @()
        }
        
        if (-not (Test-Path $FilePath)) {
            Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "File not found: $FilePath"
            return @()
        }
        
        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        
        switch ($extension) {
            ".txt" {
                try {
                    $content = Get-Content $FilePath -ErrorAction Stop
                    $filteredContent = $content | Where-Object { $_ -and $_.Trim() -ne "" }
                    
                    if (-not $filteredContent) {
                        Write-Host "Warning: No valid IOCs found in text file" -ForegroundColor Yellow
                        return @()
                    }
                    
                    return $filteredContent
                }
                catch {
                    Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "Error reading text file '$FilePath': $($_.Exception.Message)" -ErrorRecord $_
                    return @()
                }
            }
            ".json" {
                try {
                    $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    
                    if ($jsonContent -is [array]) {
                        return $jsonContent
                    } 
                    elseif ($jsonContent.IOCs) {
                        return $jsonContent.IOCs
                    } 
                    elseif ($jsonContent.indicators) {
                        return $jsonContent.indicators
                    } 
                    else {
                        Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "Invalid JSON format in '$FilePath'. Expected array or object with 'IOCs'/'indicators' property."
                        return @()
                    }
                }
                catch [System.ArgumentException] {
                    Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "Invalid JSON format in file '$FilePath'. Please check JSON syntax." -ErrorRecord $_
                    return @()
                }
                catch {
                    Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "Error reading JSON file '$FilePath': $($_.Exception.Message)" -ErrorRecord $_
                    return @()
                }
            }
            default {
                Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "Unsupported file format '$extension'. Please use .txt or .json files."
                return @()
            }
        }
    }
    catch {
        Write-ErrorMessage -FunctionName "Read-IOCsFromFile" -ErrorMessage "Error reading file '$FilePath': $($_.Exception.Message)" -ErrorRecord $_
        return @()
    }
}

# Function to load tenant configurations from external file
function Import-TenantConfig {
    param([string]$ConfigPath = "tenants.json")
    
    try {
        if ([string]::IsNullOrEmpty($ConfigPath)) {
            Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "ConfigPath parameter is null or empty"
            return $false
        }
        
        if (Test-Path $ConfigPath) {
            try {
                Write-Host "Loading tenant configurations from: $ConfigPath" -ForegroundColor Cyan
                $configContent = Get-Content $ConfigPath -Raw -ErrorAction Stop
                
                if ([string]::IsNullOrEmpty($configContent)) {
                    Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "Configuration file '$ConfigPath' is empty"
                    return $false
                }
                
                $configData = $configContent | ConvertFrom-Json -ErrorAction Stop
                
                if ($configData.tenants) {
                    # Validate tenant configurations
                    $validTenants = @()
                    foreach ($tenant in $configData.tenants) {
                        if ($tenant.Name -and $tenant.TenantId -and $tenant.AppId -and $tenant.AppSecret) {
                            $validTenants += $tenant
                        } else {
                            Write-Host "Warning: Skipping invalid tenant configuration (missing required fields)" -ForegroundColor Yellow
                        }
                    }
                    
                    if ($validTenants.Count -eq 0) {
                        Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "No valid tenant configurations found in file '$ConfigPath'"
                        return $false
                    }
                    
                    $Global:TenantConfigs = $validTenants
                    Write-Host "Successfully loaded $($Global:TenantConfigs.Count) tenant configurations from file" -ForegroundColor Green
                    return $true
                } else {
                    Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "Invalid configuration file format. Expected 'tenants' property in '$ConfigPath'"
                    return $false
                }
            }
            catch [System.ArgumentException] {
                Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "Invalid JSON format in configuration file '$ConfigPath'. Please check JSON syntax." -ErrorRecord $_
                return $false
            }
            catch {
                Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "Error loading tenant configuration from '$ConfigPath': $($_.Exception.Message)" -ErrorRecord $_
                return $false
            }
        } else {
            Write-Host "Configuration file not found: $ConfigPath" -ForegroundColor Yellow
            Write-Host "Using default tenant configurations..." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-ErrorMessage -FunctionName "Import-TenantConfig" -ErrorMessage "Critical error in Import-TenantConfig: $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

# Function to create sample tenant configuration file
function New-TenantConfigFile {
    param([string]$ConfigPath = "tenants.json")
    
    try {
        if ([string]::IsNullOrEmpty($ConfigPath)) {
            Write-ErrorMessage -FunctionName "New-TenantConfigFile" -ErrorMessage "ConfigPath parameter is null or empty"
            return $false
        }
        
        $sampleConfig = @{
            tenants = @()
        }
        
        # Create 30 sample tenant configurations
        for ($i = 1; $i -le 30; $i++) {
            try {
                $tenantNumber = $i.ToString("D2")
                $sampleConfig.tenants += @{
                    Name = "Tenant-$tenantNumber"
                    TenantId = "tenant-id-$tenantNumber-replace-with-actual"
                    AppId = "app-id-$tenantNumber-replace-with-actual"
                    AppSecret = "app-secret-$tenantNumber-replace-with-actual"
                }
            }
            catch {
                Write-ErrorMessage -FunctionName "New-TenantConfigFile" -ErrorMessage "Error creating sample tenant configuration #$i`: $($_.Exception.Message)" -ErrorRecord $_
            }
        }
        
        try {
            $jsonContent = $sampleConfig | ConvertTo-Json -Depth 3 -ErrorAction Stop
            Set-Content $ConfigPath -Value $jsonContent -Encoding UTF8 -ErrorAction Stop
            Write-Host "Sample tenant configuration file created: $ConfigPath" -ForegroundColor Green
            Write-Host "Please edit this file with your actual tenant credentials." -ForegroundColor Yellow
            return $true
        }
        catch [System.UnauthorizedAccessException] {
            Write-ErrorMessage -FunctionName "New-TenantConfigFile" -ErrorMessage "Access denied when creating configuration file '$ConfigPath'. Check file permissions." -ErrorRecord $_
            return $false
        }
        catch {
            Write-ErrorMessage -FunctionName "New-TenantConfigFile" -ErrorMessage "Error creating configuration file '$ConfigPath': $($_.Exception.Message)" -ErrorRecord $_
            return $false
        }
    }
    catch {
        Write-ErrorMessage -FunctionName "New-TenantConfigFile" -ErrorMessage "Critical error in New-TenantConfigFile: $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

# Function to initialize tenant configurations
function Initialize-TenantConfigs {
    try {
        # Try to load from external file first
        if (-not (Import-TenantConfig)) {
            Write-Host "Creating sample configuration file..." -ForegroundColor Cyan
            $fileCreated = New-TenantConfigFile
            
            if (-not $fileCreated) {
                Write-ErrorMessage -FunctionName "Initialize-TenantConfigs" -ErrorMessage "Failed to create sample configuration file"
                return $false
            }
            
            Write-Host ""
            Write-Host "Please edit 'tenants.json' with your actual tenant credentials and re-run the script." -ForegroundColor Yellow
            Write-Host "Alternatively, you can continue with the default configuration (update the script directly)." -ForegroundColor Yellow
            Write-Host ""
            
            try {
                $continue = Read-Host "Continue with default configuration? (y/n)"
                if ($continue -ne "y") {
                    Write-Host "Exiting. Please configure your tenants and re-run the script." -ForegroundColor Red
                    exit
                }
            }
            catch {
                Write-ErrorMessage -FunctionName "Initialize-TenantConfigs" -ErrorMessage "Error reading user input: $($_.Exception.Message)" -ErrorRecord $_
                return $false
            }
            
            # 30 Tenant configurations - Replace with your actual tenant details
            $Global:TenantConfigs = @(
                @{ Name = "Tenant-01"; TenantId = "tenant-id-01"; AppId = "app-id-01"; AppSecret = "app-secret-01" },
                @{ Name = "Tenant-02"; TenantId = "tenant-id-02"; AppId = "app-id-02"; AppSecret = "app-secret-02" },
                @{ Name = "Tenant-03"; TenantId = "tenant-id-03"; AppId = "app-id-03"; AppSecret = "app-secret-03" },
                @{ Name = "Tenant-04"; TenantId = "tenant-id-04"; AppId = "app-id-04"; AppSecret = "app-secret-04" },
                @{ Name = "Tenant-05"; TenantId = "tenant-id-05"; AppId = "app-id-05"; AppSecret = "app-secret-05" },
                @{ Name = "Tenant-06"; TenantId = "tenant-id-06"; AppId = "app-id-06"; AppSecret = "app-secret-06" },
                @{ Name = "Tenant-07"; TenantId = "tenant-id-07"; AppId = "app-id-07"; AppSecret = "app-secret-07" },
                @{ Name = "Tenant-08"; TenantId = "tenant-id-08"; AppId = "app-id-08"; AppSecret = "app-secret-08" },
                @{ Name = "Tenant-09"; TenantId = "tenant-id-09"; AppId = "app-id-09"; AppSecret = "app-secret-09" },
                @{ Name = "Tenant-10"; TenantId = "tenant-id-10"; AppId = "app-id-10"; AppSecret = "app-secret-10" },
                @{ Name = "Tenant-11"; TenantId = "tenant-id-11"; AppId = "app-id-11"; AppSecret = "app-secret-11" },
                @{ Name = "Tenant-12"; TenantId = "tenant-id-12"; AppId = "app-id-12"; AppSecret = "app-secret-12" },
                @{ Name = "Tenant-13"; TenantId = "tenant-id-13"; AppId = "app-id-13"; AppSecret = "app-secret-13" },
                @{ Name = "Tenant-14"; TenantId = "tenant-id-14"; AppId = "app-id-14"; AppSecret = "app-secret-14" },
                @{ Name = "Tenant-15"; TenantId = "tenant-id-15"; AppId = "app-id-15"; AppSecret = "app-secret-15" },
                @{ Name = "Tenant-16"; TenantId = "tenant-id-16"; AppId = "app-id-16"; AppSecret = "app-secret-16" },
                @{ Name = "Tenant-17"; TenantId = "tenant-id-17"; AppId = "app-id-17"; AppSecret = "app-secret-17" },
                @{ Name = "Tenant-18"; TenantId = "tenant-id-18"; AppId = "app-id-18"; AppSecret = "app-secret-18" },
                @{ Name = "Tenant-19"; TenantId = "tenant-id-19"; AppId = "app-id-19"; AppSecret = "app-secret-19" },
                @{ Name = "Tenant-20"; TenantId = "tenant-id-20"; AppId = "app-id-20"; AppSecret = "app-secret-20" },
                @{ Name = "Tenant-21"; TenantId = "tenant-id-21"; AppId = "app-id-21"; AppSecret = "app-secret-21" },
                @{ Name = "Tenant-22"; TenantId = "tenant-id-22"; AppId = "app-id-22"; AppSecret = "app-secret-22" },
                @{ Name = "Tenant-23"; TenantId = "tenant-id-23"; AppId = "app-id-23"; AppSecret = "app-secret-23" },
                @{ Name = "Tenant-24"; TenantId = "tenant-id-24"; AppId = "app-id-24"; AppSecret = "app-secret-24" },
                @{ Name = "Tenant-25"; TenantId = "tenant-id-25"; AppId = "app-id-25"; AppSecret = "app-secret-25" },
                @{ Name = "Tenant-26"; TenantId = "tenant-id-26"; AppId = "app-id-26"; AppSecret = "app-secret-26" },
                @{ Name = "Tenant-27"; TenantId = "tenant-id-27"; AppId = "app-id-27"; AppSecret = "app-secret-27" },
                @{ Name = "Tenant-28"; TenantId = "tenant-id-28"; AppId = "app-id-28"; AppSecret = "app-secret-28" },
                @{ Name = "Tenant-29"; TenantId = "tenant-id-29"; AppId = "app-id-29"; AppSecret = "app-secret-29" },
                @{ Name = "Tenant-30"; TenantId = "tenant-id-30"; AppId = "app-id-30"; AppSecret = "app-secret-30" }
            )
        }
        
        Write-Host "Initialized $($Global:TenantConfigs.Count) tenant configuration(s)" -ForegroundColor Green
        Write-Host "Ready to process IOCs across all 30 tenants!" -ForegroundColor Cyan
        return $true
    }
    catch {
        Write-ErrorMessage -FunctionName "Initialize-TenantConfigs" -ErrorMessage "Critical error in Initialize-TenantConfigs: $($_.Exception.Message)" -ErrorRecord $_
        return $false
    }
}

# Function to show final summary
function Show-Summary {
    try {
        Write-Host ""
        Show-DotProgress -Message "Finalizing results" -DotCount 5
        Write-Host ""
        
        Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Green
        Write-Host "▓▓▓                    OPERATION COMPLETE                    ▓▓▓" -ForegroundColor Green
        Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Green
        Write-Host ""
        Write-Host "Summary:" -ForegroundColor White
        Write-Host "  ✓ Successfully blocked: $Global:BlockedCount" -ForegroundColor Green
        Write-Host "  ⚠ Already blocked: $Global:AlreadyBlockedCount" -ForegroundColor Yellow
        Write-Host "  ✗ Failed to block: $Global:FailedCount" -ForegroundColor Red
        Write-Host ""
        Write-Host "Wizard-Shield v2.3 execution completed!" -ForegroundColor Cyan
    }
    catch {
        Write-ErrorMessage -FunctionName "Show-Summary" -ErrorMessage "Error displaying summary: $($_.Exception.Message)" -ErrorRecord $_
    }
}

# Main execution
function Main {
    try {
        # Show loading animation
        Show-LoadingSpinner -Message "Initializing Wizard-Shield v2.3" -Duration 2
        
        # Initialize tenant configurations
        $initSuccess = Initialize-TenantConfigs
        if (-not $initSuccess) {
            Write-ErrorMessage -FunctionName "Main" -ErrorMessage "Failed to initialize tenant configurations. Cannot proceed."
            return
        }
        
        Write-Host ""
        Write-Host "What would you like to block?" -ForegroundColor Cyan
        Write-Host "[1] Domain/IP (Single)" -ForegroundColor White
        Write-Host "[2] File Input (.txt or .json)" -ForegroundColor White
        Write-Host ""
        
        $choice = ""
        do {
            try {
                $choice = Read-Host "Please select an option (1 or 2)"
            }
            catch {
                Write-ErrorMessage -FunctionName "Main" -ErrorMessage "Error reading user input: $($_.Exception.Message)" -ErrorRecord $_
                continue
            }
        } while ($choice -notin @("1", "2"))
        
        $iocsToProcess = @()
        
        switch ($choice) {
            "1" {
                try {
                    Write-Host ""
                    $ioc = Read-Host "Enter the IOC to block (domain/IP/URL)"
                    if ([string]::IsNullOrEmpty($ioc)) {
                        Write-ErrorMessage -FunctionName "Main" -ErrorMessage "No IOC provided. Cannot proceed."
                        return
                    } else {
                        $iocsToProcess = @($ioc)
                    }
                }
                catch {
                    Write-ErrorMessage -FunctionName "Main" -ErrorMessage "Error reading IOC input: $($_.Exception.Message)" -ErrorRecord $_
                    return
                }
            }
            "2" {
                try {
                    Write-Host ""
                    $filePath = Read-Host "Enter the path to your IOC file (.txt or .json)"
                    
                    if ([string]::IsNullOrEmpty($filePath)) {
                        Write-ErrorMessage -FunctionName "Main" -ErrorMessage "No file path provided. Cannot proceed."
                        return
                    }
                    
                    $iocsToProcess = Read-IOCsFromFile -FilePath $filePath
                    
                    if ($iocsToProcess.Count -eq 0) {
                        Write-ErrorMessage -FunctionName "Main" -ErrorMessage "No IOCs found in file or file error. Cannot proceed."
                        return
                    }
                    
                    Write-Host "Found $($iocsToProcess.Count) IOC(s) in file" -ForegroundColor Green
                }
                catch {
                    Write-ErrorMessage -FunctionName "Main" -ErrorMessage "Error processing file input: $($_.Exception.Message)" -ErrorRecord $_
                    return
                }
            }
        }
        
        # Process the IOCs
        if ($iocsToProcess.Count -gt 0) {
            Process-IOCs -IOCs $iocsToProcess
        } else {
            Write-ErrorMessage -FunctionName "Main" -ErrorMessage "No IOCs available for processing"
            return
        }
        
        # Show summary
        Show-Summary
    }
    catch {
        Write-ErrorMessage -FunctionName "Main" -ErrorMessage "Critical error in main execution: $($_.Exception.Message)" -ErrorRecord $_
    }
}

# Add System.Web assembly for URL encoding with error handling
try {
    Add-Type -AssemblyName System.Web -ErrorAction Stop
}
catch {
    Write-ErrorMessage -FunctionName "Global" -ErrorMessage "Failed to load System.Web assembly. URL encoding may not work properly: $($_.Exception.Message)" -ErrorRecord $_
}

# Execute main function with global error handling
try {
    Main
}
catch {
    Write-ErrorMessage -FunctionName "Global" -ErrorMessage "Critical unhandled error in script execution: $($_.Exception.Message)" -ErrorRecord $_
    Write-Host "Script execution failed. Please check the errors above and try again." -ForegroundColor Red
    exit 1
}
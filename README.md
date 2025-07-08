# defender
MS Defender IOC's Blocker via API 


# Wizard-Shield v2.3 - Advanced IOC Blocking Script for Microsoft Defender for Endpoint
# Developer: mahdiesta@wizardcyber
# Description: Automates blocking of malicious indicators across multiple tenants

param(
    [string]$ConfigFile = ""
)

# Global Variables
$Global:TenantConfigs = @()
$Global:BlockedCount = 0
$Global:AlreadyBlockedCount = 0
$Global:FailedCount = 0

# Function to show loading spinner
function Show-LoadingSpinner {
    param(
        [string]$Message = "Loading",
        [int]$Duration = 3
    )
    
    $spinnerChars = @('|', '/', '-', '\')
    $counter = 0
    $endTime = (Get-Date).AddSeconds($Duration)
    
    while ((Get-Date) -lt $endTime) {
        $spinnerChar = $spinnerChars[$counter % 4]
        Write-Host "`r$Message $spinnerChar" -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds 200
        $counter++
    }
    Write-Host "`r$Message... Done!" -ForegroundColor Green
}

# Function to show dot progress animation
function Show-DotProgress {
    param(
        [string]$Message,
        [int]$DotCount = 6
    )
    
    Write-Host "$Message " -NoNewline -ForegroundColor Yellow
    for ($i = 0; $i -lt $DotCount; $i++) {
        Write-Host "." -NoNewline -ForegroundColor Yellow
        Start-Sleep -Milliseconds 300
    }
}

# Function to display the startup banner
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Magenta
    Write-Host "▓▓▓                  Wizard-Shield v2.3                      ▓▓▓" -ForegroundColor Magenta
    Write-Host "▓▓▓              Block IOCs Across All Tenants               ▓▓▓" -ForegroundColor Magenta
    Write-Host "▓▓▓              Developer: mahdiesta@wizardcyber             ▓▓▓" -ForegroundColor Magenta
    Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Magenta
    Write-Host ""
}

# Function to get AAD token
function Get-AADToken {
    param(
        [string]$TenantId,
        [string]$AppId,
        [string]$AppSecret
    )
    
    try {
        $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
        $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $authBody = @{
            client_id     = $AppId
            client_secret = $AppSecret
            scope         = "$resourceAppIdUri/.default"
            grant_type    = 'client_credentials'
        }
        
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        return $authResponse.access_token
    }
    catch {
        Write-Host "Failed to get AAD token for tenant $TenantId`: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to defang IOCs
function Repair-DefangedIOC {
    param([string]$IOC)
    
    # Remove common defanging patterns
    $cleanIOC = $IOC -replace '\[', '' -replace '\]', '' -replace 'hxxp', 'http' -replace 'hXXp', 'http'
    $cleanIOC = $cleanIOC -replace '\.', '.' -replace '\(\.\)', '.'
    
    return $cleanIOC.Trim()
}

# Function to determine IOC type
function Get-IOCType {
    param([string]$IOC)
    
    # Check if it's an IP address
    if ($IOC -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) {
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

# Function to check if IOC already exists
function Test-IOCExists {
    param(
        [string]$Token,
        [string]$IOC,
        [string]$IOCType
    )
    
    try {
        $headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        
        $filterValue = [System.Web.HttpUtility]::UrlEncode($IOC)
        $checkUrl = "https://api.securitycenter.microsoft.com/api/indicators?`$filter=indicatorValue eq '$filterValue'"
        
        $response = Invoke-RestMethod -Method Get -Uri $checkUrl -Headers $headers -ErrorAction Stop
        
        return $response.value.Count -gt 0
    }
    catch {
        Write-Host "Error checking IOC existence: $($_.Exception.Message)" -ForegroundColor Red
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
        $headers = @{
            'Authorization' = "Bearer $Token"
            'Content-Type'  = 'application/json'
        }
        
        $body = @{
            indicatorValue = $IOC
            indicatorType  = $IOCType
            title          = "Blocked by Wizard-Shield v2.3"
            description    = "Automatically blocked malicious indicator via Wizard-Shield"
            expirationTime = (Get-Date).AddDays(365).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            severity       = "High"
            action         = "Block"
            recommendedActions = "Block this indicator"
            rbacGroupNames = @()
        } | ConvertTo-Json
        
        $blockUrl = "https://api.securitycenter.microsoft.com/api/indicators"
        $response = Invoke-RestMethod -Method Post -Uri $blockUrl -Headers $headers -Body $body -ErrorAction Stop
        
        return $true
    }
    catch {
        Write-Host "Failed to block IOC $IOC in tenant $TenantName`: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to process IOCs with enhanced progress tracking for 30 tenants
function Process-IOCs {
    param([array]$IOCs)
    
    $totalOperations = $IOCs.Count * $Global:TenantConfigs.Count
    $currentOperation = 0
    
    Write-Host "`nProcessing $($IOCs.Count) IOC(s) across $($Global:TenantConfigs.Count) tenant(s)..." -ForegroundColor Cyan
    Write-Host "Total operations to perform: $totalOperations" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray
    
    foreach ($ioc in $IOCs) {
        $cleanIOC = Repair-DefangedIOC -IOC $ioc
        $iocType = Get-IOCType -IOC $cleanIOC
        $iocIndex = $IOCs.IndexOf($ioc) + 1
        
        Write-Host ""
        Write-Host "[$iocIndex/$($IOCs.Count)] Processing IOC: $cleanIOC (Type: $iocType)" -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host "─────────────────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
        
        $tenantIndex = 0
        foreach ($tenant in $Global:TenantConfigs) {
            $tenantIndex++
            $currentOperation++
            $progressPercent = [math]::Round(($currentOperation / $totalOperations) * 100, 1)
            
            Write-Host "  [$tenantIndex/30] $($tenant.Name) - Progress: $progressPercent%" -ForegroundColor Cyan
            
            # Get token with shorter animation for performance
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
        
        # Show intermediate summary after each IOC
        $completedIOCs = $iocIndex
        $remainingIOCs = $IOCs.Count - $completedIOCs
        Write-Host ""
        Write-Host "    IOC Summary - Completed: $completedIOCs | Remaining: $remainingIOCs" -ForegroundColor Magenta
        Write-Host "    Running Totals - Blocked: $Global:BlockedCount | Already Blocked: $Global:AlreadyBlockedCount | Failed: $Global:FailedCount" -ForegroundColor Magenta
    }
}

# Function to read IOCs from file
function Read-IOCsFromFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Host "File not found: $FilePath" -ForegroundColor Red
        return @()
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    try {
        switch ($extension) {
            ".txt" {
                $content = Get-Content $FilePath -ErrorAction Stop
                return $content | Where-Object { $_ -and $_.Trim() -ne "" }
            }
            ".json" {
                $jsonContent = Get-Content $FilePath -Raw -ErrorAction Stop | ConvertFrom-Json
                if ($jsonContent -is [array]) {
                    return $jsonContent
                } elseif ($jsonContent.IOCs) {
                    return $jsonContent.IOCs
                } elseif ($jsonContent.indicators) {
                    return $jsonContent.indicators
                } else {
                    Write-Host "Invalid JSON format. Expected array or object with 'IOCs'/'indicators' property." -ForegroundColor Red
                    return @()
                }
            }
            default {
                Write-Host "Unsupported file format. Please use .txt or .json files." -ForegroundColor Red
                return @()
            }
        }
    }
    catch {
        Write-Host "Error reading file: $($_.Exception.Message)" -ForegroundColor Red
        return @()
    }
}

# Function to load tenant configurations from external file
function Import-TenantConfig {
    param([string]$ConfigPath = "tenants.json")
    
    if (Test-Path $ConfigPath) {
        try {
            Write-Host "Loading tenant configurations from: $ConfigPath" -ForegroundColor Cyan
            $configData = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            
            if ($configData.tenants) {
                $Global:TenantConfigs = $configData.tenants
                Write-Host "Successfully loaded $($Global:TenantConfigs.Count) tenant configurations from file" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Invalid configuration file format. Expected 'tenants' property." -ForegroundColor Red
                return $false
            }
        }
        catch {
            Write-Host "Error loading tenant configuration: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "Configuration file not found: $ConfigPath" -ForegroundColor Yellow
        Write-Host "Using default tenant configurations..." -ForegroundColor Yellow
        return $false
    }
}

# Function to create sample tenant configuration file
function New-TenantConfigFile {
    param([string]$ConfigPath = "tenants.json")
    
    $sampleConfig = @{
        tenants = @()
    }
    
    # Create 30 sample tenant configurations
    for ($i = 1; $i -le 30; $i++) {
        $tenantNumber = $i.ToString("D2")
        $sampleConfig.tenants += @{
            Name = "Tenant-$tenantNumber"
            TenantId = "tenant-id-$tenantNumber-replace-with-actual"
            AppId = "app-id-$tenantNumber-replace-with-actual"
            AppSecret = "app-secret-$tenantNumber-replace-with-actual"
        }
    }
    
    try {
        $sampleConfig | ConvertTo-Json -Depth 3 | Set-Content $ConfigPath -Encoding UTF8
        Write-Host "Sample tenant configuration file created: $ConfigPath" -ForegroundColor Green
        Write-Host "Please edit this file with your actual tenant credentials." -ForegroundColor Yellow
        return $true
    }
    catch {
        Write-Host "Error creating configuration file: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to initialize tenant configurations
function Initialize-TenantConfigs {
    # Try to load from external file first
    if (-not (Import-TenantConfig)) {
        Write-Host "Creating sample configuration file..." -ForegroundColor Cyan
        New-TenantConfigFile
        Write-Host ""
        Write-Host "Please edit 'tenants.json' with your actual tenant credentials and re-run the script." -ForegroundColor Yellow
        Write-Host "Alternatively, you can continue with the default configuration (update the script directly)." -ForegroundColor Yellow
        Write-Host ""
        
        $continue = Read-Host "Continue with default configuration? (y/n)"
        if ($continue -ne "y") {
            Write-Host "Exiting. Please configure your tenants and re-run the script." -ForegroundColor Red
            exit
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
}

# Function to show final summary
function Show-Summary {
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

# Main execution
function Main {
    # Show loading animation and banner
    Show-LoadingSpinner -Message "Initializing Wizard-Shield v2.3" -Duration 2
    Show-Banner
    
    # Initialize tenant configurations
    Initialize-TenantConfigs
    
    Write-Host ""
    Write-Host "What would you like to block?" -ForegroundColor Cyan
    Write-Host "[1] Domain/IP (Single)" -ForegroundColor White
    Write-Host "[2] File Input (.txt or .json)" -ForegroundColor White
    Write-Host ""
    
    do {
        $choice = Read-Host "Please select an option (1 or 2)"
    } while ($choice -notin @("1", "2"))
    
    $iocsToProcess = @()
    
    switch ($choice) {
        "1" {
            Write-Host ""
            $ioc = Read-Host "Enter the IOC to block (domain/IP/URL)"
            if ($ioc) {
                $iocsToProcess = @($ioc)
            } else {
                Write-Host "No IOC provided. Exiting." -ForegroundColor Red
                return
            }
        }
        "2" {
            Write-Host ""
            $filePath = Read-Host "Enter the path to your IOC file (.txt or .json)"
            $iocsToProcess = Read-IOCsFromFile -FilePath $filePath
            
            if ($iocsToProcess.Count -eq 0) {
                Write-Host "No IOCs found in file or file error. Exiting." -ForegroundColor Red
                return
            }
            
            Write-Host "Found $($iocsToProcess.Count) IOC(s) in file" -ForegroundColor Green
        }
    }
    
    # Process the IOCs
    Process-IOCs -IOCs $iocsToProcess
    
    # Show summary
    Show-Summary
}

# Add System.Web assembly for URL encoding
Add-Type -AssemblyName System.Web

# Execute main function
Main

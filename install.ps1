# Installation script for MCP Web Reconnaissance tools (Windows)

Write-Host "MCP Web Reconnaissance - Tools Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Install UV if not present
function Install-UV {
    Write-Host "Checking for UV..." -ForegroundColor Yellow
    
    try {
        $uvVersion = uv --version 2>$null
        Write-Host "[OK] UV is already installed: $uvVersion" -ForegroundColor Green
    }
    catch {
        Write-Host "Installing UV..." -ForegroundColor Yellow
        
        # Download and run UV installer
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        
        # Add to PATH
        $uvPath = "$env:USERPROFILE\.local\bin"
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*$uvPath*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$uvPath", "User")
            $env:Path = "$env:Path;$uvPath"
        }
        
        Write-Host "[OK] UV installed successfully" -ForegroundColor Green
        Write-Host "[WARNING] You may need to restart your terminal for PATH changes to take effect" -ForegroundColor Yellow
    }
}

# Install Nmap
function Install-Nmap {
    Write-Host "`nChecking for Nmap..." -ForegroundColor Yellow
    
    # Function to find and configure nmap
    function Find-AndConfigureNmap {
        # Check default installation paths first
        $defaultPaths = @(
            "C:\Program Files (x86)\Nmap",
            "C:\Program Files\Nmap"
        )
        
        foreach ($nmapDir in $defaultPaths) {
            if (Test-Path "$nmapDir\nmap.exe") {
                Write-Host "Found Nmap at: $nmapDir" -ForegroundColor Green
                
                # Add to current session PATH immediately
                if ($env:Path -notlike "*$nmapDir*") {
                    $env:Path = "$env:Path;$nmapDir"
                    Write-Host "Added to current session PATH" -ForegroundColor Green
                }
                
                # Add to permanent system PATH
                try {
                    $currentMachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
                    if ($currentMachinePath -notlike "*$nmapDir*") {
                        [Environment]::SetEnvironmentVariable("Path", "$currentMachinePath;$nmapDir", "Machine")
                        Write-Host "Added to system PATH permanently" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "Warning: Could not update system PATH" -ForegroundColor Yellow
                }
                
                return $true
            }
        }
        return $false
    }
    
    # Check if nmap is already available
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        try {
            $nmapVersion = nmap --version 2>$null | Select-Object -First 1
            Write-Host "[OK] Nmap is already installed: $nmapVersion" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Host "[OK] Nmap is already installed" -ForegroundColor Green
            return $true
        }
    }
    
    # Try to find existing installation first
    if (Find-AndConfigureNmap) {
        if (Get-Command nmap -ErrorAction SilentlyContinue) {
            try {
                $nmapVersion = nmap --version 2>$null | Select-Object -First 1
                Write-Host "[OK] Found and configured existing Nmap: $nmapVersion" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "[OK] Found and configured existing Nmap" -ForegroundColor Green
                return $true
            }
        }
    }
    
    Write-Host "Installing Nmap..." -ForegroundColor Yellow
    
    try {
        # Try Chocolatey
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            Write-Host "Installing Nmap via Chocolatey..." -ForegroundColor Yellow
            $chocoOutput = choco install nmap -y 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Nmap installed via Chocolatey" -ForegroundColor Green
                
                # Refresh environment variables
                $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
                
                if (Get-Command nmap -ErrorAction SilentlyContinue) {
                    try {
                        $nmapVersion = nmap --version 2>$null | Select-Object -First 1
                        Write-Host "[OK] Nmap installed and configured: $nmapVersion" -ForegroundColor Green
                        return $true
                    }
                    catch {
                        Write-Host "[OK] Nmap installed and configured successfully" -ForegroundColor Green
                        return $true
                    }
                }
                
                if (Find-AndConfigureNmap) {
                    if (Get-Command nmap -ErrorAction SilentlyContinue) {
                        try {
                            $nmapVersion = nmap --version 2>$null | Select-Object -First 1
                            Write-Host "[OK] Nmap found and configured: $nmapVersion" -ForegroundColor Green
                            return $true
                        }
                        catch {
                            Write-Host "[OK] Nmap found and configured successfully" -ForegroundColor Green
                            return $true
                        }
                    }
                }
            }
            else {
                Write-Host "Chocolatey installation failed, trying manual installation..." -ForegroundColor Yellow
            }
        }
        
        # Manual installation with interactive installer
        Write-Host "Downloading Nmap installer..." -ForegroundColor Yellow
        $nmapUrl = "https://nmap.org/dist/nmap-7.95-setup.exe"
        $installerPath = "$env:TEMP\nmap-setup.exe"
        
        Invoke-WebRequest -Uri $nmapUrl -OutFile $installerPath -UseBasicParsing
        
        Write-Host "Starting Nmap installer..." -ForegroundColor Yellow
        Write-Host "IMPORTANT: Please ensure 'Add Nmap to PATH' is checked in the installer!" -ForegroundColor Cyan
        
        # Use interactive installer
        $process = Start-Process -FilePath $installerPath -Wait -PassThru -Verb RunAs
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Nmap installer completed successfully" -ForegroundColor Green
        }
        else {
            Write-Host "Installer may have been cancelled or failed" -ForegroundColor Yellow
        }
        
        # Wait for installation to complete
        Start-Sleep -Seconds 5
        
        # Refresh environment variables after installation
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        # Check if nmap is now available
        if (Get-Command nmap -ErrorAction SilentlyContinue) {
            try {
                $nmapVersion = nmap --version 2>$null | Select-Object -First 1
                Write-Host "[OK] Nmap installed and configured successfully: $nmapVersion" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Host "[OK] Nmap installed and configured successfully" -ForegroundColor Green
                return $true
            }
        }
        
        # If still not in PATH, try to find and configure manually
        if (Find-AndConfigureNmap) {
            if (Get-Command nmap -ErrorAction SilentlyContinue) {
                try {
                    $nmapVersion = nmap --version 2>$null | Select-Object -First 1
                    Write-Host "[OK] Nmap found and configured: $nmapVersion" -ForegroundColor Green
                    return $true
                }
                catch {
                    Write-Host "[OK] Nmap found and configured successfully" -ForegroundColor Green
                    return $true
                }
            }
        }
        
        Write-Host "[ERROR] Nmap installation may have failed or PATH not configured correctly" -ForegroundColor Red
        return $false
        
    }
    catch {
        Write-Host "[ERROR] Failed to install Nmap: $_" -ForegroundColor Red
        return $false
    }
}

# Main installation
function Start-Installation {
    Write-Host "This script will install:"
    Write-Host "- UV (Python package manager)"
    Write-Host "- Nmap (network mapping tool)"
    Write-Host "- Python dependencies for web reconnaissance"
    Write-Host ""
    Write-Host "Requirements:"
    Write-Host "- Python 3.10 or higher"
    Write-Host ""
    
    $response = Read-Host "Do you want to continue? (y/n)"
    
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "Installation cancelled."
        exit
    }
    
    # Install UV
    Install-UV | Out-Null

    # Install Nmap
    Install-Nmap | Out-Null
    
    # Install Python dependencies with UV
    Write-Host "`nInstalling Python dependencies with UV..." -ForegroundColor Yellow
    try {
        & uv sync
        Write-Host "[OK] Python dependencies installed" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to install Python dependencies" -ForegroundColor Red
        Write-Host "Try running: uv sync" -ForegroundColor Yellow
    }
    
    # Verify installations
    Write-Host "`nVerifying installations..." -ForegroundColor Yellow
    
    $tools = @("uv", "nmap")
    
    foreach ($tool in $tools) {
        if (Get-Command $tool -ErrorAction SilentlyContinue) {
            Write-Host "[OK] $tool is available" -ForegroundColor Green
        }
        else {
            Write-Host "[ERROR] $tool not found in PATH" -ForegroundColor Red
        }
    }
    
    Write-Host "`nInstallation complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Python dependencies installed include:" -ForegroundColor Cyan
    Write-Host "- httpx (HTTP client)"
    Write-Host "- beautifulsoup4 (HTML parsing)"
    Write-Host "- dnspython (DNS resolution)"
    Write-Host "- python-nmap (Nmap interface)"
    Write-Host "- python-whois (WHOIS lookup)"
    Write-Host ""
}

# Run main function
Start-Installation

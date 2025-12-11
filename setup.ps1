# setup.ps1 - Windows PowerShell setup script
Write-Host "Setting up Cybersecurity Insider Threat Detection Environment on Windows" -ForegroundColor Green

# Check if Python is installed
$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCheck) {
    Write-Host "Python is not installed. Please install Python from https://python.org" -ForegroundColor Red
    exit 1
}

# Create virtual environment
python -m venv cyber-env

# Activate virtual environment
.\cyber-env\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Install Windows-compatible security tools
Write-Host "Please install the following Windows security tools manually:" -ForegroundColor Yellow
Write-Host "1. Nmap: https://nmap.org/download.html" -ForegroundColor Yellow
Write-Host "2. Wireshark: https://www.wireshark.org/download.html" -ForegroundColor Yellow
Write-Host "3. Tor Browser: https://www.torproject.org/download/" -ForegroundColor Yellow

Write-Host "Environment setup complete!" -ForegroundColor Green
Write-Host "Activate the virtual environment with: .\cyber-env\Scripts\Activate.ps1" -ForegroundColor Green
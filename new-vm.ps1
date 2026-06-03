Function DisableServerMgrNetworkPopup
{
    # Fix #22: Create the registry KEY 'NewNetworkWindowOff' under Network (the key's presence is what suppresses the popup).
    $networkKey = 'HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff'
    if (-not (Test-Path $networkKey)) {
        New-Item -Path $networkKey -Force | Out-Null
    }

    Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
}
DisableServerMgrNetworkPopup


Function InstallChocolatey
{
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

Function InstallVsCode
{
choco install vscode.install -y
}

DisableServerMgrNetworkPopup
InstallChocolatey
InstallVsCode

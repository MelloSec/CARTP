#Azure AD
Write-Host "Installing AzureAD and Azure Graph modules..."
Install-Module -Name AzureADPreview -Force

#Az
Write-Host "Installing Az..."
Install-Module -Name Az -Force

# Az CLI
$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\AzureCLI.msi

# pwsh
Install-Module -Name Microsoft.Graph -Force

#MSOnline
Write-Host "Installing MSonline..."
Install-Module -Name MSOnline -Force

#Exchange
Write-Host "Installing Exchange Online modules..."
Install-Module -Name ExchangeOnlineManagement -Force
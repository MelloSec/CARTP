## CARTP - Azure Red Team Resources

<p align="center">
    <img src="https://sec.straylightsecurity.com/images/vault.webp" alt="cartp" height="300"/>
</p>

#### Made some adjustments to PowerZure and Microburst, collected some scripts and tools in one spot to make setup easier for the exam. 

### Cheatsheets and Notes

#### Our Specific Cheatsheet and Notes are here
- ***https://sec.straylightsecurity.com/blog/CARTP***

#### General and Comprehensive Cheatsheet
- ***https://github.com/0xJs/CARTP-cheatsheet?tab=readme-ov-file***

### Install Tools
```powershell
# Install Choco
iex (iwr https://raw.githubusercontent.com/MelloSec/RepeatOffender/main/Choco.ps1 -UseBasicParsing)

# Clone repos and Install Azure Tools (cli, storage explorer included)
iex (iwr https://raw.githubusercontent.com/MelloSec/RepeatOffender/main/Azure.ps1 -UseBasicParsing)

# Import Modules
iex (iwr https://raw.githubusercontent.com/MelloSec/CARTP/main/Scripts/Import-Modules.ps1 -UseBasicParsing)

# # Install Azure Storage Explorer
# iwr https://github.com/microsoft/AzureStorageExplorer/releases/download/v1.34.0/StorageExplorer-windows-arm64.exe -Outfile storageexplorer.exe
# .\storageexplorer.exe

# az cli one-liners for Windows
# winget install -e --id Microsoft.AzureCLI
# $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\AzureCLI.msi

# for Linux
# curl -L https://aka.ms/InstallAzureCli | bash
```

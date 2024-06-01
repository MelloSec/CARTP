# Function to check path and import module if exists
function Import-ModuleIfExists {
    param (
        [string]$modulePath,
        [string]$moduleName
    )

    if (Test-Path $modulePath) {
        Write-Output "Importing module: $moduleName"
        Import-Module $modulePath -Force
    } else {
        Write-Output "Module not found: $moduleName at path: $modulePath"
    }
}

# Define paths to modules
$modulesToCheck = @{
    "TokenTactics" = "C:\Git\TokenTactics\TokenTactics.psm1"
    "GraphRunner" = "C:\Git\GraphRunner\GraphRunner.ps1"
    "PowerZure" = "C:\Git\CARTP\Tools\PowerZure\PowerZure.psm1"
    "MicroBurst-Misc" = "C:\Git\CARTP\Tools\MicroBurst\Misc\MicroBurst-Misc.psm1"
   # "MicroBurst" = "C:\Git\CARTP\Tools\MicroBurst\MicroBurst.psm1"
}

# Check and import the modules
foreach ($module in $modulesToCheck.GetEnumerator()) {
    Import-ModuleIfExists -modulePath $module.Value -moduleName $module.Key
}

# Import other required modules
$requiredModules = @("AADInternals", "Az", "AzureADPreview", "MSOnline", "Microsoft.Graph", "ExchangeOnlineManagement")

foreach ($module in $requiredModules) {
    Write-Output "Importing module: $module"
    Import-Module $module -Force
}

﻿# Test to see if each module is installed, load scripts as applicable

$prefBackup = $WarningPreference
$global:WarningPreference = 'SilentlyContinue'

# Az
if(!(Get-Module Az)){
    try{
        Import-Module Az -ErrorAction Stop
        Import-Module $PSScriptRoot\Az\MicroBurst-Az.psm1
        $azStatus = "1"
    }
    catch{Write-Host -ForegroundColor DarkRed "Az module not installed, checking other modules"}
}


# AzureAD
if(!(Get-Module AzureAD)){
    try{
        Import-Module AzureAD -ErrorAction Stop
        Import-Module $PSScriptRoot\AzureAD\MicroBurst-AzureAD.psm1
    }
    catch{Write-Host -ForegroundColor DarkRed "AzureAD module not installed, checking other modules"}
}

<# AzureRm - Uncomment this section if you want to import the functions
if(!(Get-Module AzureRM)){
    try{
        Import-Module AzureRM -ErrorAction Stop
        Import-Module $PSScriptRoot\AzureRM\MicroBurst-AzureRM.psm1
    }
    catch{
        # If Az is already installed, no need to warn on no AzureRM
        if($azStatus -ne "1"){Write-Host -ForegroundColor DarkRed "AzureRM module not installed, checking other modules"}
    }
}#>

# MSOL
if(!(Get-Module msonline)){
    try{
        Import-Module msonline -ErrorAction Stop
        Import-Module $PSScriptRoot\MSOL\MicroBurst-MSOL.psm1
    }
    catch{Write-Host -ForegroundColor DarkRed "MSOnline module not installed, checking other modules"}
}

# Import Additional Functions

Import-Module $PSScriptRoot\Misc\MicroBurst-Misc.psm1
Import-Module $PSScriptRoot\REST\MicroBurst-AzureREST.psm1

$global:WarningPreference = $prefBackup
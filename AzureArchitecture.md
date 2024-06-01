## Directory

- Each tenant has one dedicated Directory, this handles IAM for the resources

## Management Groups

- Multiple subscriptions are managed via a management group. 
- A management group can be placed inside another management group, nested management groups
- The top Management Group would be the root management group.
- Each tenant has a single root management group

## Subscriptions

- Logical unit of services linked to an Azure account
- Is billing but also can be ACCESS BOUNDARY
- One Directory can have multiple subscriptions
- Subscriptions can only TRUST one Directory
- An Azure role at the subscription level applies to all resources inside that subscription

## Resources and Resource Groups

- Everything deployable is a resource contained in a resource group
- A resource can only exist in one group
- Deleting the group deletes all contained resources
- Each group has its own IAM for RBAC
- An Azure role applied to the resource group affects all resources inside

## Managed Identity

- You can give resources a managed identity that let's them use access tokens to access other resources
- It's a special form of service principal
- Can be System-Assigned (tied to a single resource and cannot be shared)
- Can be User-Assigned (independent life-cycle, can be re-used, shared across resources)

## ARM

- Client neutral - many technologies leverage ARM under the hood
- Create, Update, Delete resources and managed Access Control

## Azure vs EntraID vs On-Prem AD

- EntraID is an IAM/identity service product offering within the Azure cloud platform accessed via API
- AD is an on-prem IAM solution that performs directory services over LDAP, NTLM and Kerberos
- EntraID is NOT directory services in the cloud. That is EntraID Domain Services aka "DC-aaS"
- Linking the two is called Hybrid Identity

## Azure RBAC

Role based Access Control

- Owner: Full access to resources, CAN manage access for other Users
    Applies To: All Resource types

- Contributor: Full access to resources, CANNOT manage access for others
    Applies To: All resource types

- Reader: View all resources, nothing else
    Applies To: All resource Types
   
- User Access Administrator: View all resources, CAN manage access for other users
    Applies To: All resource types

- Assignment: An EntraID principal/object HAS <Role Definition> ON <Scope>
    Evaluation: 
      - Transitive for groups, all members of the group inherit the role
      - For multiple role assignments, the effective permissions are the sum of all assignments (they stack)
      - An Explicit Deny takes precedence!!!

## Azure ABAC

Attribute based access control builds on RBAC to provide fine-grained access control based on attributes.

- Ex: Chandra HAS Storage Blob Reader ON RG1 ONLY on blobs with tag "Project=Cascade". She cannot read Project=Alpine files even though they exist in the blob in RG1


## EntraID Roles

- Applicable on EntraID resources like users, groups, domains, licenses.
- Many built-in Administrator roles for different purposes, as well as custom defined roles
- Global Administrator is the EA of the Cloud
- Global Admin can 'elevate' the User Access Administrator Role into the root management group.

## EntraID Editions

- Free: Core Identity and Access Management
  Included with: Azure, Dynamic365, Intune and Power Platform

- Office 365 apps: Free Edition pls features for IAM
  Included with: Office 365 E1, E3, E5, F1 and F5

- Premium P1: All of apps edition plus password and group access, hybrid, conditional acces
  Included With:  Microsoft 365 E3, E5, EMS E3/E5. or separate license

- Premium P2: P1 plus identity protection and governance features
  included with: E5, EMS E5, separate

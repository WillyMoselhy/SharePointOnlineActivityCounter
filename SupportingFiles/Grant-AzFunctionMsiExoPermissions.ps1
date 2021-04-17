# This script helps grant proper permissions to the MSI to access exchange online.
return "Not designed to run using F5"

#Links. https://stackoverflow.com/questions/63953702/access-o365-exchange-online-with-an-azure-managed-identity-or-service-principal

Import-Module -Name AzureAD


Connect-AzureAD

$AzureFunctionAppName = "getdeletefilecount"

# Create Azure function

# Enable Azure MSI for Azure function

# Grant proper permissions for MSI for the Exchange.ManageAsApp API
$O365ExoSP =  Get-AzureADServicePrincipal -Filter "DisplayName eq 'Office 365 Exchange Online'"

$Permission = $O365ExoSP.AppRoles.Where({$_.Value -eq 'Exchange.ManageAsApp'})

$AzureFunctionSP = Get-AzureADServicePrincipal -Filter "DisplayName eq '$AzureFunctionAppName'"

# Confirm this works by going to AAD > Enterprise Application > Office 365 Exchange Online > Users and groups
New-AzureADServiceAppRoleAssignment -ObjectId $AzureFunctionSP.ObjectId -Id $Permission[0].Id -PrincipalId $AzureFunctionSP.ObjectId -ResourceId $O365ExoSP.ObjectId


#Check if role is currently enabled
$roleName = 'Compliance Administrator'
$role = Get-AzureADDirectoryRole  -Filter "DisplayName eq '$roleName'"
if(-not $role){ #Role is not enabled
    $roleTemplate = Get-AzureADDirectoryRoleTemplate | Where-Object DisplayName -eq $roleName
    Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
    $role = Get-AzureADDirectoryRole  -Filter "DisplayName eq '$roleName'"
}

# Assign role to the MSI
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $AzureFunctionSP.ObjectId


# Check status

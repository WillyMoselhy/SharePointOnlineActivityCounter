# Azure Functions profile.ps1
#
# This profile.ps1 will get executed every "cold start" of your Function App.
# "cold start" occurs when:
#
# * A Function App starts up for the very first time
# * A Function App starts up after being de-allocated due to inactivity
#
# You can define helper functions, run commands, or specify environment variables
# NOTE: any variables defined that are not environment variables will get reset after the first execution

Write-Output "Loading PS Profile"

# Authenticate with Azure PowerShell using MSI.
Write-Output "Connecting to Azure using MSI"
Connect-AzAccount -Identity | Out-Null -ErrorAction Stop
Write-Output "Connected to Azure."


# You can also define functions or aliases that can be referenced in any of your PowerShell functions.
Import-Module -Name UtilityFunctions, Az.Storage, Az.Resources, Az.Accounts

if ([int]$env:Switch_ExchangeOnlineInProfile) {
    # Connect to Exchange Online
    Connect-UtilityExchangeOnline

    #$startdate = '2021-04-05T13:10:02.8771587+00:00'
    #$enddate = '2021-04-05T13:15:02.5054510+00:00'
    #(Search-UnifiedAuditLog -StartDate $startdate -EndDate $enddate -RecordType 'SharePointFileOperation' -Verbose -Debug -Operations 'FileDeleted')
}



Write-Output "Profile load complete."

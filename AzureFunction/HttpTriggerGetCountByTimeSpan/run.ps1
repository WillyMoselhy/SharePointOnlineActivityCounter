using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Interact with query parameters or the body of the request.
$name = $Request.Query.BeginTimeStamp
if (-not ($Request.Query.BeginTimeStamp -and $Request.Query.EndTimeStamp) ) {
    $body = "Time stamps are missing."
    throw $body
}

#region: Prepare Time Stamps

$beginTimeStamp = Get-Date -Date $Request.Query.BeginTimeStamp
$endTimeStamp = Get-Date -Date $Request.Query.EndTimeStamp

Write-Output "Begin TimeStamp: $(Get-Date $beginTimeStamp -Format o)"
Write-Output "End Timestamp: $(Get-Date $endTimeStamp -Format o)"

#endregion: Prepare Time Stamps

#region: Get count
try {

    Write-Output "Query Share Point Activity Log"

    if (-not [int]$env:Switch_ExchangeOnlineInProfile) {
        Connect-UtilityExchangeOnline
    }

    $GetSharePointActivityCountParams = @{
        UserId         = $lastTimeStamp.UserId
        Operation      = $lastTimeStamp.Operation
        BeginTimeStamp = $beginTimeStamp
        EndTimeStamp   = $endTimeStamp
    }
    $spActivityCounts = Get-SharePointActivityCount @GetSharePointActivityCountParams -ErrorAction Stop

    Write-Output "SharePoint Activity Counts:"
    $spActivityCounts | Format-Table
    $body = $spActivityCounts | Format-Table | Out-String
}
catch {
    throw
}
finally{
    if (-not [int]$env:Switch_ExchangeOnlineInProfile) {
        Disconnect-ExchangeOnline
    }
}

#endregion: Get Count


# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})

# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

#region: Import JSON File

#Generate SAS to access file
$timeStampFileSAS = Get-AzStorageBlobSasUri -BlobURL $env:TimeStampFileURL
Write-Output "Obtained SAS token for time stamp file."
# Import JSON File
$lastTimeStamp = Invoke-RestMethod -Uri $timeStampFileSAS
# Validate JSON File
if (-not ( Test-LastTimeStamp -LastTimeStamp $lastTimeStamp)) {
    throw 'Time Stamp file is not valid'
}

#endregion: Import JSON File

#region: Prepare Time Stamps
Write-Output "Offset hours is set to: $env:OffsetHours"

if ([string]::IsNullOrEmpty($lastTimeStamp.LastTimeStamp)) {
    $lastTimeStamp.LastTimeStamp = (Get-Date).AddMinutes(-10).AddHours(([int] $env:OffsetHours) * -1)

    Write-Output "Last Time Stamp field missing, setting time stamp to $(Get-Date -Date $lastTimeStamp.LastTimeStamp -Format o)"
}

if ([DateTime] $lastTimeStamp.LastTimeStamp -gt (Get-Date).AddHours(([int] $env:OffsetHours) * -1) ) {
    Write-Output "Last time stamp is less than $env:OffsetHours hour(s) ago. Please try again later. This is configurable from function settings"

    return #If last timestamp is after configured offset hours, do nothing.
}

$beginTimeStamp = Get-Date -Date $lastTimeStamp.LastTimeStamp
$endTimeStamp = (Get-Date).AddHours(([int] $env:OffsetHours) * -1)

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
}
catch {
    throw
}
finally{
    if (-not [int]$env:Switch_ExchangeOnlineInProfile) {
        switch ($env:Switch_ExchangeOnlineMSI){
            '1' {Get-PSSession | Remove-PSSession}
            '0' {Disconnect-ExchangeOnline -Confirm:$false}
        }
    }
}

#endregion: Get Count

#region: Post to LAW
try {
    Write-Output "Posting to Log Analytics Workspace."

    $AddLAWEntryParams = @{
        InputObject  = $spActivityCounts
        LAWId        = $env:LogAnalyticsWorkspaceId
        LawKey       = $env:LogAnalyticsWorkspaceKey
        LAWTableName = $env:LogAnalyticsWorkspaceTableName
    }
    Add-LAWEntry @AddLAWEntryParams -ErrorAction Stop

    Write-Output "Posted to Log Analytics Workspace."
}
catch {
    $errorUpdatingLAW = $true
    Write-Output $_
}
finally {
    if ($errorUpdatingLAW) {
        throw "Failed to update LAW"
    }
}

#endregion: Post to LAW

#region: Export JSON File

$lastTimeStamp.LastTimeStamp = $endTimeStamp

Invoke-RestMethod -Uri $timeStampFileSAS -Method PUT -Body ($lastTimeStamp | ConvertTo-Json) -ContentType 'application/json' -Headers @{'x-ms-blob-type' = 'BlockBlob' }
Write-Output "Updated timestamp file"
#endregion: Export JSON File
